#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdio.h>

#include "proxy_connection.h"
#include "proxy.h"

#include "logging.h"
#include "networking.h"
#include "poll_set.h"


// LOG_MODULE_CREATE(proxy_backend);


#define ERROR_OUT(...) { LOG_ERROR(__VA_ARGS__); goto cleanup; }
#define ERROR_OUT_EX(module, ...) { LOG_ERROR_EX(module, __VA_ARGS__); goto cleanup; }


/* File global variables */
static proxy_connection proxy_connection_pool[MAX_CONNECTIONS_PER_PROXY];

#if defined(__ZEPHYR__)
#define CONNECTION_HANDLER_STACK_SIZE (32*1024)

Z_KERNEL_STACK_ARRAY_DEFINE_IN(connection_handler_stack_pool, MAX_CONNECTIONS_PER_PROXY, \
                CONNECTION_HANDLER_STACK_SIZE, __attribute__((section(CONFIG_RAM_SECTION_STACKS_1))));
#endif


void init_proxy_connection_pool(void)
{
        for (int i = 0; i < MAX_CONNECTIONS_PER_PROXY; i++)
        {
                proxy_connection_pool[i].in_use = false;
                proxy_connection_pool[i].direction = REVERSE_PROXY;
                proxy_connection_pool[i].tunnel_sock = -1;
                proxy_connection_pool[i].asset_sock = -1;
                proxy_connection_pool[i].tls_session = NULL;
                proxy_connection_pool[i].log_module = NULL;
                proxy_connection_pool[i].slot = -1;
                proxy_connection_pool[i].num_of_bytes_in_tun2ass_buffer = 0;
                proxy_connection_pool[i].num_of_bytes_in_ass2tun_buffer = 0;
                pthread_attr_init(&proxy_connection_pool[i].thread_attr);
                pthread_attr_setdetachstate(&proxy_connection_pool[i].thread_attr, PTHREAD_CREATE_DETACHED);
        }
}


proxy_connection* add_new_connection_to_proxy(proxy* proxy, int client_socket,
                                              struct sockaddr* client_addr)
{
        int ret = 0;

        /* Search for a free connection slot in the pool */
        int freeSlotConnectionPool = -1;
        for (int i = 0; i < MAX_CONNECTIONS_PER_PROXY; i++)
        {
                if (proxy_connection_pool[i].in_use == false)
                {
                        freeSlotConnectionPool = i;
                        break;
                }
        }

        int freeSlotProxyConnectionsArray = -1;
        for (int i = 0; i < MAX_CONNECTIONS_PER_PROXY; i++)
        {
                if((proxy->connections[i] == NULL) || (proxy->connections[i]->in_use == false))
                {
                        freeSlotProxyConnectionsArray = i;
                        break;
                }
        }

        if ((freeSlotConnectionPool == -1) || (freeSlotProxyConnectionsArray == -1))
        {
                LOG_ERROR_EX(proxy->log_module, "Cannot accept more connections (no free slot)");
                close(client_socket);
                return NULL;
        }

        proxy_connection* connection = &proxy_connection_pool[freeSlotConnectionPool];

        proxy->num_connections += 1;

        /* Store new client data */
        connection->in_use = true;
        connection->direction = proxy->direction;
        connection->slot = freeSlotConnectionPool;
        connection->log_module = &proxy->log_module;
        connection->proxy = proxy;

        if (connection->direction == FORWARD_PROXY)
        {
                connection->asset_sock = client_socket;

                /* Create the socket for the tunnel  */
                connection->tunnel_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (connection->tunnel_sock == -1)
                        ERROR_OUT_EX(proxy->log_module, "Error creating tunnel socket, errno: %d",
                                     errno);
        }
        else if (connection->direction == REVERSE_PROXY)
        {
                connection->tunnel_sock = client_socket;

                /* Create the socket for the asset connection */
                connection->asset_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (connection->asset_sock == -1)
                        ERROR_OUT_EX(proxy->log_module, "Error creating asset socket, errno: %d",
                                     errno);
        }

        /* Set sockets non-blocking */
        setblocking(connection->tunnel_sock, false);
        setblocking(connection->asset_sock, false);

        if (setsockopt(connection->tunnel_sock, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0)
                ERROR_OUT_EX(proxy->log_module, "setsockopt(TCP_NODELAY) tunnel_sock failed: error %d", errno);

        if (setsockopt(connection->asset_sock, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0)
                ERROR_OUT_EX(proxy->log_module, "setsockopt(TCP_NODELAY) asset_sock failed: error %d", errno);

        /* Connect to the peer */
        if (connection->direction == FORWARD_PROXY)
        {
                ret = connect(connection->tunnel_sock, (struct sockaddr*) &proxy->target_addr, sizeof(proxy->target_addr));
        }
        else if (connection->direction == REVERSE_PROXY)
        {
                ret = connect(connection->asset_sock, (struct sockaddr*) &proxy->target_addr, sizeof(proxy->target_addr));
        }
        if ((ret != 0) && (errno != EINPROGRESS))
                ERROR_OUT_EX(proxy->log_module, "Unable to connect to target peer, errno: %d", errno);

        /* Create a new TLS session on the destined interface depending on the direction */
        connection->tls_session = asl_create_session(proxy->tls_endpoint, connection->tunnel_sock);
        if (connection->tls_session == NULL)
                ERROR_OUT_EX(proxy->log_module, "Error creating TLS session");

        /* Store the new connection within the proxy */
        proxy->connections[freeSlotProxyConnectionsArray] = connection;

#if defined(__ZEPHYR__)
        /* Store the pointer to the related stack for the client handler thread
         * (started after the TLS handshake). */
        pthread_attr_setstack(&connection->thread_attr,
                              connection_handler_stack_pool[freeSlotConnectionPool],
                              K_THREAD_STACK_SIZEOF(connection_handler_stack_pool[freeSlotConnectionPool]));
#endif

        /* Set the priority of the client handler thread to be one higher than the backend thread.
         * This priorizes active connections before handshakes of new ones. */
        // struct sched_param param = {
        // 	.sched_priority = HANDLER_THREAD_PRIORITY,
        // };
        // pthread_attr_setschedparam(&connection->thread_attr, &param);
        // pthread_attr_setschedpolicy(&connection->thread_attr, SCHED_RR);

        /* Print info */
        struct sockaddr_in* client_data = (struct sockaddr_in*) client_addr;
        char peer_ip[20];
        net_addr_ntop(AF_INET, &client_data->sin_addr, peer_ip, sizeof(peer_ip));
        LOG_INFO_EX(proxy->log_module, "New connection from %s:%d, using slot %d/%d",
                peer_ip, ntohs(client_data->sin_port),
                freeSlotConnectionPool+1, MAX_CONNECTIONS_PER_PROXY);

        return connection;

cleanup:
        proxy_connection_cleanup(connection);
        return NULL;
}


proxy_connection* find_proxy_connection_by_fd(int fd)
{
        for (int i = 0; i < MAX_CONNECTIONS_PER_PROXY; i++)
        {
                if ((proxy_connection_pool[i].tunnel_sock == fd) ||
                    (proxy_connection_pool[i].asset_sock == fd))
                {
                        return &proxy_connection_pool[i];
                }
        }

        return NULL;
}


void proxy_connection_cleanup(proxy_connection* connection)
{
        /* Kill the network connections */
        if (connection->tunnel_sock >= 0)
        {
                close(connection->tunnel_sock);
                connection->tunnel_sock = -1;
        }
        if (connection->asset_sock >= 0)
        {
                close(connection->asset_sock);
                connection->asset_sock = -1;
        }

        /* Cleanup the TLS session */
        if (connection->tls_session != NULL)
        {
                asl_free_session(connection->tls_session);
                connection->tls_session = NULL;
        }

        /* Update connection count */
        if (connection->proxy != NULL)
        {
                connection->proxy->num_connections -= 1;
        }

        connection->num_of_bytes_in_tun2ass_buffer = 0;
        connection->num_of_bytes_in_ass2tun_buffer = 0;
        connection->log_module = NULL;
        connection->slot = -1;
        connection->proxy = NULL;

        connection->in_use = false;
}


void* connection_handler_thread(void *ptr)
{
        proxy_connection* connection = (proxy_connection* ) ptr;
        poll_set poll_set;
        bool shutdown = false;

#if defined(__ZEPHYR__)
        pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
#else
        LOG_INFO_EX(*connection->log_module, "TLS proxy connection handler started for slot %d/%d",
                connection->slot+1, MAX_CONNECTIONS_PER_PROXY);
#endif


        poll_set_init(&poll_set);

        poll_set_add_fd(&poll_set, connection->tunnel_sock, POLLIN);
        poll_set_add_fd(&poll_set, connection->asset_sock, POLLOUT | POLLIN);

        while (!shutdown)
        {
                /* Block and wait for incoming events (new connections, received data, ...) */
                int ret = poll(poll_set.fds, poll_set.num_fds, -1);

                if (ret == -1) {
                        LOG_ERROR_EX(*connection->log_module, "Connection %d: poll error %d",
                                   connection->slot+1, errno);
                        continue;
                }

                /* Check which fds created an event */
                for (int i = 0; i < poll_set.num_fds; i++)
                {
                        int fd = poll_set.fds[i].fd;
                        short event = poll_set.fds[i].revents;

                        if(event == 0)
                                continue;

                        if (fd == connection->tunnel_sock)
                        {
                                if (event & POLLIN)
                                {
                                        ret = 1;
                                        while (ret > 0)
                                        {
                                                /* Data received from the tunnel */
                                                ret = asl_receive(connection->tls_session,
                                                                connection->tun2ass_buffer,
                                                                sizeof(connection->tun2ass_buffer));

                                                if (ret > 0)
                                                {
                                                        connection->num_of_bytes_in_tun2ass_buffer = ret;

                                                        /* Send received data to the asset */
                                                        ret = send(connection->asset_sock,
                                                                connection->tun2ass_buffer,
                                                                connection->num_of_bytes_in_tun2ass_buffer,
                                                                0);

                                                        if (ret == -1)
                                                        {
                                                                if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
                                                                {
                                                                        /* We have to wait for the asset socket to be writable. Until we can send
                                                                        * the data, we also mustn't receive more data on the tunnel socket. */
                                                                        poll_set_add_events(&poll_set, connection->asset_sock, POLLOUT);
                                                                        poll_set_remove_events(&poll_set, connection->tunnel_sock, POLLIN);
                                                                        ret = 0;
                                                                }
                                                                else
                                                                {
                                                                        LOG_ERROR_EX(*connection->log_module, "Error sending data to asset: %d (%s)",
                                                                                     errno, strerror(errno));
                                                                        shutdown = true;
                                                                        break;
                                                                }
                                                        }
                                                        else if ((size_t)ret == connection->num_of_bytes_in_tun2ass_buffer)
                                                        {
                                                                if (connection->num_of_bytes_in_tun2ass_buffer < sizeof(connection->tun2ass_buffer))
                                                                {
                                                                        /* We read the maximum amount of data from the tunnel connection. This
                                                                         * could be an indication that there is more data to be read. Hence, we
                                                                         * trigger another read here. */
                                                                        ret = 0;
                                                                }

                                                                connection->num_of_bytes_in_tun2ass_buffer = 0;
                                                        }
                                                        else
                                                        {
                                                                connection->num_of_bytes_in_tun2ass_buffer -= ret;
                                                                memmove(connection->tun2ass_buffer, connection->tun2ass_buffer + ret,
                                                                        connection->num_of_bytes_in_tun2ass_buffer);
                                                                poll_set_update_events(&poll_set, connection->asset_sock, POLLOUT);
                                                                // Do we need have to remove POLLIN from tunnel_sock here?
                                                                // LOG_WARN_EX(*connection->log_module, "Not all data sent to asset");
                                                                ret = 0;
                                                        }

                                                }
                                                else if (ret == ASL_WANT_READ)
                                                {
                                                        /* We have to wait for more data from the peer to read data (not a full record has been
                                                         * received).
                                                         */
                                                        ret = 0;
                                                }
                                                else if (ret < 0)
                                                {
                                                        /* Connection closed */
                                                        ret = -1;
                                                }
                                        }
                                }
                                if (event & POLLOUT)
                                {
                                        /* We can send data on the tunnel connection now. Send remaining
                                         * data from the asset. */
                                        ret = asl_send(connection->tls_session,
                                                           connection->ass2tun_buffer,
                                                           connection->num_of_bytes_in_ass2tun_buffer);

                                        if (ret == 0)
                                        {
                                                /* Wait again for incoming data on the asset socket and remove
                                                 * the writable indication from the tunnel socket. */
                                                poll_set_remove_events(&poll_set, connection->tunnel_sock, POLLOUT);
                                                poll_set_add_events(&poll_set, connection->asset_sock, POLLIN);
                                                connection->num_of_bytes_in_ass2tun_buffer = 0;
                                        }
                                }
                                if (event & POLLERR)
                                {
                                        LOG_ERROR_EX(*connection->log_module, "Error on tunnel connection");
                                        shutdown = true;
                                        break;
                                }

                                if (ret < 0)
                                {
                                        shutdown = true;
                                        break;
                                }

                        }
                        else if (fd == connection->asset_sock)
                        {
                                if (event & POLLIN)
                                {
                                        /* Data received from the asset connection */
                                        ret = read(connection->asset_sock, connection->ass2tun_buffer, sizeof(connection->ass2tun_buffer));

                                        if (ret > 0)
                                        {
                                                connection->num_of_bytes_in_ass2tun_buffer = ret;

                                                /* Send received data to the other socket */
                                                ret = asl_send(connection->tls_session,
                                                                   connection->ass2tun_buffer,
                                                                   connection->num_of_bytes_in_ass2tun_buffer);

                                                if (ret == ASL_WANT_WRITE)
                                                {
                                                        /* We have to wait for the tunnel socket to be writable. Until we can send
                                                         * the data, we also mustn't receive more data on the asset socket. */
                                                        poll_set_add_events(&poll_set, connection->tunnel_sock, POLLOUT);
                                                        poll_set_remove_events(&poll_set, connection->asset_sock, POLLIN);
                                                        ret = 0;
                                                }
                                                else
                                                {
                                                        connection->num_of_bytes_in_ass2tun_buffer = 0;
                                                }

                                        }
                                        else if (ret == 0)
                                        {
                                                /* Connection closed */
                                                ret = -1;
                                        }
                                }
                                if (event & POLLOUT)
                                {
                                        /* We can send data on the asset connection now. Send remaining
                                         * tunnel data. */
                                        ret = send(connection->asset_sock,
                                                   connection->tun2ass_buffer,
                                                   connection->num_of_bytes_in_tun2ass_buffer,
                                                   0);

                                        if (ret == -1)
                                        {
                                                if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
                                                {
                                                        ret = 0;
                                                }
                                                else
                                                {
                                                        LOG_ERROR_EX(*connection->log_module, "Error sending data to asset: %d (%s)",
                                                                     errno, strerror(errno));
                                                        shutdown = true;
                                                        break;
                                                }
                                        }
                                        else if ((size_t)ret == connection->num_of_bytes_in_tun2ass_buffer)
                                        {
                                                /* Wait again for incoming data on the tunnel socket and remove
                                                 * the writable indication from the asset socket. */
                                                poll_set_remove_events(&poll_set, connection->asset_sock, POLLOUT);
                                                poll_set_add_events(&poll_set, connection->tunnel_sock, POLLIN);
                                                connection->num_of_bytes_in_tun2ass_buffer = 0;
                                        }
                                        else
                                        {
                                                connection->num_of_bytes_in_tun2ass_buffer -= ret;
                                                memmove(connection->tun2ass_buffer, connection->tun2ass_buffer + ret,
                                                        connection->num_of_bytes_in_tun2ass_buffer);
                                                // LOG_WARN_EX(*connection->log_module, "Not all data sent to asset");
                                        }

                                }
                                if (event & POLLERR)
                                {
                                        LOG_ERROR_EX(*connection->log_module, "Error on asset connection");
                                        shutdown = true;
                                        break;
                                }

                                if (ret < 0)
                                {
                                        shutdown = true;
                                        break;
                                }
                        }
                }
        }

        LOG_INFO_EX(*connection->log_module, "Connection on slot %d/%d closed",
                   connection->slot+1, MAX_CONNECTIONS_PER_PROXY);

        asl_close_session(connection->tls_session);

        proxy_connection_cleanup(connection);

        return NULL;
}