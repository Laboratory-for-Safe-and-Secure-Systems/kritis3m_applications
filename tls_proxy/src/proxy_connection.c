#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

#include "proxy_backend.h"
#include "proxy_connection.h"
#include "proxy_management.h"

#include "logging.h"
#include "networking.h"
#include "poll_set.h"
#include "threading.h"

// LOG_MODULE_CREATE(proxy_backend);

#define ERROR_OUT(...)                                                                             \
        {                                                                                          \
                LOG_ERROR(__VA_ARGS__);                                                            \
                goto cleanup;                                                                      \
        }
#define ERROR_OUT_EX(module, ...)                                                                  \
        {                                                                                          \
                LOG_ERROR_EX(module, __VA_ARGS__);                                                 \
                goto cleanup;                                                                      \
        }

/* File global variables */
#if defined(__ZEPHYR__)

static proxy_connection proxy_connection_pool[MAX_CONNECTIONS_PER_PROXY]
        __attribute__((section(CONFIG_RAM_SECTION_STACKS_2)));

#define CONNECTION_HANDLER_STACK_SIZE (8 * 1024)
Z_KERNEL_STACK_ARRAY_DEFINE_IN(connection_handler_stack_pool,
                               MAX_CONNECTIONS_PER_PROXY,
                               CONNECTION_HANDLER_STACK_SIZE,
                               __attribute__((section(CONFIG_RAM_SECTION_STACKS_1))));

#else

static proxy_connection proxy_connection_pool[MAX_CONNECTIONS_PER_PROXY];

#endif

/* Internal method declarations */
static int handle_management_message(proxy_connection* connection,
                                     int socket,
                                     proxy_management_message const* msg);
static bool handle_tunnel_to_asset(proxy_connection* connection, short event, poll_set* poll_set);
static bool handle_asset_to_tunnel(proxy_connection* connection, short event, poll_set* poll_set);
static void* connection_handler_thread(void* ptr);

void init_proxy_connection_pool(void)
{
        for (int i = 0; i < MAX_CONNECTIONS_PER_PROXY; i++)
        {
                proxy_connection_pool[i].in_use = false;
                proxy_connection_pool[i].detached = false;
                proxy_connection_pool[i].direction = REVERSE_PROXY;
                proxy_connection_pool[i].tunnel_sock = -1;
                proxy_connection_pool[i].asset_sock = -1;
                proxy_connection_pool[i].target_addr = NULL;
                proxy_connection_pool[i].tls_session = NULL;
                proxy_connection_pool[i].log_module = NULL;
                proxy_connection_pool[i].proxy = NULL;
                proxy_connection_pool[i].slot = -1;
                proxy_connection_pool[i].management_socket_pair[0] = -1;
                proxy_connection_pool[i].management_socket_pair[1] = -1;
                proxy_connection_pool[i].num_of_bytes_in_tun2ass_buffer = 0;
                proxy_connection_pool[i].num_of_bytes_in_ass2tun_buffer = 0;
        }
}

proxy_connection* add_new_connection_to_proxy(proxy* proxy,
                                              int client_socket,
                                              struct sockaddr_in6* client_addr)
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
                if ((proxy->connections[i] == NULL) || (proxy->connections[i]->in_use == false))
                {
                        freeSlotProxyConnectionsArray = i;
                        break;
                }
        }

        if ((freeSlotConnectionPool == -1) || (freeSlotProxyConnectionsArray == -1))
        {
                LOG_ERROR_EX(proxy->log_module, "Cannot accept more connections (no free slot)");
                closesocket(client_socket);
                return NULL;
        }

        proxy_connection* connection = &proxy_connection_pool[freeSlotConnectionPool];

        proxy->num_connections += 1;

        /* Store new client data */
        connection->in_use = true;
        connection->detached = false;
        connection->direction = proxy->direction;
        connection->slot = freeSlotConnectionPool;
        connection->target_addr = proxy->target_addr;
        connection->log_module = &proxy->log_module;
        connection->proxy = proxy;

        /* Configure the client socket */
        if (configure_peer_socket(client_socket) != 0)
                ERROR_OUT_EX(proxy->log_module, "Error configuring peer socket");

        /* Create the client socket to the other peer */
        int target_sock = create_client_socket(connection->target_addr->ai_family);
        if (target_sock == -1)
                ERROR_OUT_EX(proxy->log_module, "Error creating target socket, errno: %d", errno);

        if (connection->direction == FORWARD_PROXY)
        {
                connection->asset_sock = client_socket;
                connection->tunnel_sock = target_sock;
        }
        else if (connection->direction == REVERSE_PROXY)
        {
                connection->asset_sock = target_sock;
                connection->tunnel_sock = client_socket;
        }

        /* Set sockets non-blocking */
        setblocking(connection->tunnel_sock, false);
        setblocking(connection->asset_sock, false);

        /* Connect to the peer */
        ret = connect(target_sock,
                      (struct sockaddr*) connection->target_addr->ai_addr,
                      connection->target_addr->ai_addrlen);

        if ((ret != 0) &&
#if defined(_WIN32)
            (WSAGetLastError() != WSAEWOULDBLOCK))
#else
            (errno != EINPROGRESS))
#endif
                ERROR_OUT_EX(proxy->log_module, "Unable to connect to target peer, errno: %d", errno);

        /* Create a new TLS session on the destined interface depending on the direction */
        connection->tls_session = asl_create_session(proxy->tls_endpoint, connection->tunnel_sock);
        if (connection->tls_session == NULL)
                ERROR_OUT_EX(proxy->log_module, "Error creating TLS session");

        /* Store the new connection within the proxy */
        proxy->connections[freeSlotProxyConnectionsArray] = connection;

        /* Print info */
        char peer_ip[INET6_ADDRSTRLEN];

        if (client_addr->sin6_family == AF_INET)
                net_addr_ntop(AF_INET,
                              &((struct sockaddr_in*) client_addr)->sin_addr,
                              peer_ip,
                              sizeof(peer_ip));
        else if (client_addr->sin6_family == AF_INET6)
                net_addr_ntop(AF_INET6,
                              &((struct sockaddr_in6*) client_addr)->sin6_addr,
                              peer_ip,
                              sizeof(peer_ip));

        LOG_INFO_EX(proxy->log_module,
                    "New connection from %s:%d, using slot %d/%d",
                    peer_ip,
                    ntohs(((struct sockaddr_in*) client_addr)->sin_port),
                    freeSlotConnectionPool + 1,
                    MAX_CONNECTIONS_PER_PROXY);

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

int proxy_connection_try_next_target(proxy_connection* connection)
{
        int ret = 0;
        if (connection->target_addr->ai_next == NULL)
        {
                LOG_DEBUG_EX(*connection->log_module, "No more target addresses to try");
                return -1;
        }

        connection->target_addr = connection->target_addr->ai_next;

        /* Close the current connection depending on the role */
        if (connection->direction == REVERSE_PROXY && connection->asset_sock >= 0)
        {
                /* Close current socket */
                closesocket(connection->asset_sock);

                /* Create the new socket for the asset connection */
                connection->asset_sock = socket(connection->target_addr->ai_family,
                                                SOCK_STREAM,
                                                IPPROTO_TCP);
                if (connection->asset_sock == -1)
                        ERROR_OUT_EX(*connection->log_module,
                                     "Error creating asset socket, errno: %d",
                                     errno);

                setblocking(connection->asset_sock, false);

                /* Set TCP_NODELAY option to disable Nagle algorithm */
                if (setsockopt(connection->asset_sock,
                               IPPROTO_TCP,
                               TCP_NODELAY,
                               (char*) &(int) {1},
                               sizeof(int)) < 0)
                        ERROR_OUT_EX(*connection->log_module,
                                     "setsockopt(TCP_NODELAY) asset_sock failed: error %d",
                                     errno);

#if !defined(__ZEPHYR__) && !defined(_WIN32)
                /* Set retry count to send a total of 3 SYN packets => Timeout ~7s */
                if (setsockopt(connection->asset_sock,
                               IPPROTO_TCP,
                               TCP_SYNCNT,
                               (char*) &(int) {2},
                               sizeof(int)) < 0)
                        ERROR_OUT_EX(*connection->log_module,
                                     "setsockopt(TCP_SYNCNT) asset_sock failed: error %d",
                                     errno);
#endif
                /* Connect to the peer */
                ret = connect(connection->asset_sock,
                              (struct sockaddr*) connection->target_addr->ai_addr,
                              connection->target_addr->ai_addrlen);
        }
        else if (connection->direction == FORWARD_PROXY && connection->tunnel_sock >= 0)
        {
                closesocket(connection->tunnel_sock);

                /* Create the new socket for the tunnel */
                connection->tunnel_sock = socket(connection->target_addr->ai_family,
                                                 SOCK_STREAM,
                                                 IPPROTO_TCP);
                if (connection->tunnel_sock == -1)
                        ERROR_OUT_EX(*connection->log_module,
                                     "Error creating tunnel socket, errno: %d",
                                     errno);

                setblocking(connection->tunnel_sock, false);

                /* Set TCP_NODELAY option to disable Nagle algorithm */
                if (setsockopt(connection->tunnel_sock,
                               IPPROTO_TCP,
                               TCP_NODELAY,
                               (char*) &(int) {1},
                               sizeof(int)) < 0)
                        ERROR_OUT_EX(*connection->log_module,
                                     "setsockopt(TCP_NODELAY) tunnel_sock failed: error %d",
                                     errno);

#if !defined(__ZEPHYR__) && !defined(_WIN32)
                /* Set retry count to send a total of 3 SYN packets => Timeout ~7s */
                if (setsockopt(connection->tunnel_sock,
                               IPPROTO_TCP,
                               TCP_SYNCNT,
                               (char*) &(int) {2},
                               sizeof(int)) < 0)
                        ERROR_OUT_EX(*connection->log_module,
                                     "setsockopt(TCP_SYNCNT) tunnel_sock failed: error %d",
                                     errno);
#endif
                /* Connect to the peer */
                ret = connect(connection->tunnel_sock,
                              (struct sockaddr*) connection->target_addr->ai_addr,
                              connection->target_addr->ai_addrlen);
        }

        if ((ret != 0) &&
#if defined(_WIN32)
            (WSAGetLastError() != WSAEWOULDBLOCK))
#else
            (errno != EINPROGRESS))
#endif
                ERROR_OUT_EX(*connection->log_module,
                             "Unable to connect to target peer, errno: %d",
                             errno);

        return 0;

cleanup:
        proxy_connection_cleanup(connection);
        return -1;
}

int proxy_connection_detach_handling(proxy_connection* connection)
{
        /* Create the socket pair for external management */
        int ret = create_socketpair(connection->management_socket_pair);
        if (ret < 0)
        {
                LOG_ERROR_EX(*connection->log_module,
                             "Error creating management socket pair: %d (%s)",
                             errno,
                             strerror(errno));
                return -1;
        }

        LOG_DEBUG_EX(*connection->log_module,
                     "Created management socket pair (%d, %d)",
                     connection->management_socket_pair[0],
                     connection->management_socket_pair[1]);

        connection->detached = true;

        /* Start the thread */
        thread_attibutes attr = {0};
        attr.function = connection_handler_thread;
        attr.argument = connection;
#if defined(__ZEPHYR__)
        attr.stack_size = K_THREAD_STACK_SIZEOF(connection_handler_stack_pool[connection->slot]);
        attr.stack = connection_handler_stack_pool[connection->slot];
#endif
        ret = start_thread(&connection->thread, &attr);

        return ret;
}

int proxy_connection_stop_handling(proxy_connection* connection)
{
        if ((connection->management_socket_pair[0] > 0) && (connection->management_socket_pair[1] > 0))
        {
                LOG_DEBUG_EX(*connection->log_module,
                             "Stopping connection on slot %d/%d",
                             connection->slot + 1,
                             MAX_CONNECTIONS_PER_PROXY);

                /* Send a stop request to the connection handler thread */
                proxy_management_message msg = {
                        .type = CONNECTION_STOP_REQUEST,
                        .payload.dummy_unused = 0,
                };
                int ret = send_management_message(connection->management_socket_pair[0], &msg);
                if (ret < 0)
                {
                        LOG_ERROR_EX(*connection->log_module,
                                     "Error sending stop request to connection handler thread");
                        return -1;
                }

                /* Wait for response */
                ret = read_management_message(connection->management_socket_pair[0], &msg);
                if (ret < 0)
                {
                        return -1;
                }
                else if (msg.type != RESPONSE)
                {
                        LOG_ERROR_EX(*connection->log_module, "Received invalid response");
                        return -1;
                }
                else if (msg.payload.response_code < 0)
                {
                        LOG_ERROR_EX(*connection->log_module,
                                     "Error stopping proxy backend (error %d)",
                                     msg.payload.response_code);
                        return -1;
                }
        }

        /* Wait for the backend thread to be terminated */
        if (connection->detached)
                wait_for_thread(connection->thread);

        return 0;
}

void proxy_connection_cleanup(proxy_connection* connection)
{
        /* Kill the network connections */
        if (connection->tunnel_sock >= 0)
        {
                closesocket(connection->tunnel_sock);
                connection->tunnel_sock = -1;
        }
        if (connection->asset_sock >= 0)
        {
                closesocket(connection->asset_sock);
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

        /* Close the management socket pair */
        if (connection->management_socket_pair[0] >= 0)
        {
                closesocket(connection->management_socket_pair[0]);
                connection->management_socket_pair[0] = -1;
        }
        if (connection->management_socket_pair[1] >= 0)
        {
                closesocket(connection->management_socket_pair[1]);
                connection->management_socket_pair[1] = -1;
        }

        connection->num_of_bytes_in_tun2ass_buffer = 0;
        connection->num_of_bytes_in_ass2tun_buffer = 0;
        connection->target_addr = NULL;
        connection->slot = -1;
        connection->proxy = NULL;

        connection->in_use = false;
}

/* Handle incoming management messages.
 *
 * Return 0 in case the message has been processed successfully, -1 otherwise. In case the
 * connection thread has to be stopped and the connection has to be cleaned up, +1 in returned.
 */
static int handle_management_message(proxy_connection* connection,
                                     int socket,
                                     proxy_management_message const* msg)
{
        int ret = 0;

        switch (msg->type)
        {
        case CONNECTION_STOP_REQUEST:
                {
                        /* Return 1 to indicate we have to stop the connection thread and cleanup */
                        ret = 1;

                        /* Send response */
                        proxy_management_message response = {
                                .type = RESPONSE,
                                .payload.response_code = 0,
                        };
                        send_management_message(socket, &response);
                        break;
                }
        default:
                LOG_ERROR_EX(*connection->log_module,
                             "Received invalid management message: msg->type=%d",
                             msg->type);
                ret = -1;
                break;
        }

        return ret;
}

static bool handle_tunnel_to_asset(proxy_connection* connection, short event, poll_set* poll_set)
{
        int ret = 0;
        bool shutdown = false;

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
#if defined(_WIN32)
                                        if (WSAGetLastError() == WSAEWOULDBLOCK)
#else
                                        if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
#endif
                                        {
                                                /* We have to wait for the asset socket to be writable.
                                                 * Until we can send the data, we also mustn't receive
                                                 * more data on the tunnel socket. */
                                                poll_set_add_events(poll_set,
                                                                    connection->asset_sock,
                                                                    POLLOUT);
                                                poll_set_remove_events(poll_set,
                                                                       connection->tunnel_sock,
                                                                       POLLIN);
                                                ret = 0;
                                        }
                                        else
                                        {
                                                if ((errno == ECONNRESET) || (errno == EPIPE))
                                                {
                                                        LOG_INFO_EX(*connection->log_module,
                                                                    "Asset connection closed");
                                                }
                                                else
                                                {
                                                        LOG_ERROR_EX(*connection->log_module,
                                                                     "Error sending data to asset: "
                                                                     "%d (%s)",
                                                                     errno,
                                                                     strerror(errno));
                                                }
                                                shutdown = true;
                                                break;
                                        }
                                }
                                else if ((size_t) ret == connection->num_of_bytes_in_tun2ass_buffer)
                                {
                                        if (connection->num_of_bytes_in_tun2ass_buffer <
                                            sizeof(connection->tun2ass_buffer))
                                        {
                                                /* We read the maximum amount of data from the
                                                 * tunnel connection. This could be an indication
                                                 * that there is more data to be read. Hence, we
                                                 * trigger another read here. */
                                                ret = 0;
                                        }

                                        connection->num_of_bytes_in_tun2ass_buffer = 0;
                                }
                                else
                                {
                                        connection->num_of_bytes_in_tun2ass_buffer -= ret;
                                        memmove(connection->tun2ass_buffer,
                                                connection->tun2ass_buffer + ret,
                                                connection->num_of_bytes_in_tun2ass_buffer);
                                        poll_set_update_events(poll_set, connection->asset_sock, POLLOUT);
                                        // Do we need have to remove POLLIN
                                        // from tunnel_sock here?
                                        // LOG_WARN_EX(*connection->log_module, "Not all data sent to asset");
                                        ret = 0;
                                }
                        }
                        else if (ret == ASL_WANT_READ)
                        {
                                /* We have to wait for more data from the
                                 * peer to read data (not a full record has
                                 * been received).
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
                /* We can send data on the tunnel connection now. Send
                 * remaining data from the asset. */
                ret = asl_send(connection->tls_session,
                               connection->ass2tun_buffer,
                               connection->num_of_bytes_in_ass2tun_buffer);

                if (ret == ASL_SUCCESS)
                {
                        /* Wait again for incoming data on the asset socket and remove
                         * the writable indication from the tunnel socket. */
                        poll_set_remove_events(poll_set, connection->tunnel_sock, POLLOUT);
                        poll_set_add_events(poll_set, connection->asset_sock, POLLIN);
                        connection->num_of_bytes_in_ass2tun_buffer = 0;
                }
                else if (ret == ASL_WANT_WRITE)
                {
                        /* We still have to wait until we can send data, just wait. Hence,
                         * we have to clear the error condition */
                        ret = 0;
                }
        }
        if (event & POLLERR)
        {
                LOG_INFO_EX(*connection->log_module, "Tunnel connection closed");
                shutdown = true;
        }

        if (ret < 0)
        {
                shutdown = true;
        }

        return shutdown;
}

static bool handle_asset_to_tunnel(proxy_connection* connection, short event, poll_set* poll_set)
{
        int ret = 0;
        bool shutdown = false;

        if (event & POLLIN)
        {
                /* Data received from the asset connection */
                ret = recv(connection->asset_sock,
                           connection->ass2tun_buffer,
                           sizeof(connection->ass2tun_buffer),
                           0);

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
                                poll_set_add_events(poll_set, connection->tunnel_sock, POLLOUT);
                                poll_set_remove_events(poll_set, connection->asset_sock, POLLIN);
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
                else
                {
                        ret = -1;
                }
        }
        if (event & POLLOUT)
        {
                /* We can send data on the asset connection now. Send
                 * remaining tunnel data. */
                ret = send(connection->asset_sock,
                           connection->tun2ass_buffer,
                           connection->num_of_bytes_in_tun2ass_buffer,
                           0);

                if (ret == -1)
                {
#if defined(_WIN32)
                        if (WSAGetLastError() == WSAEWOULDBLOCK)
#else
                        if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
#endif
                        {
                                ret = 0;
                        }
                        else
                        {
                                if ((errno == ECONNRESET) || (errno == EPIPE))
                                {
                                        LOG_INFO_EX(*connection->log_module, "Asset connection closed");
                                }
                                else
                                {
                                        LOG_ERROR_EX(*connection->log_module,
                                                     "Error sending data to asset: %d (%s)",
                                                     errno,
                                                     strerror(errno));
                                }
                                shutdown = true;
                        }
                }
                else if ((size_t) ret == connection->num_of_bytes_in_tun2ass_buffer)
                {
                        /* Wait again for incoming data on the tunnel socket and remove
                         * the writable indication from the asset socket. */
                        poll_set_remove_events(poll_set, connection->asset_sock, POLLOUT);
                        poll_set_add_events(poll_set, connection->tunnel_sock, POLLIN);
                        connection->num_of_bytes_in_tun2ass_buffer = 0;
                }
                else
                {
                        connection->num_of_bytes_in_tun2ass_buffer -= ret;
                        memmove(connection->tun2ass_buffer,
                                connection->tun2ass_buffer + ret,
                                connection->num_of_bytes_in_tun2ass_buffer);
                        // LOG_WARN_EX(*connection->log_module, "Not all data sent to asset");
                }
        }
        if (event & POLLERR)
        {
                LOG_INFO_EX(*connection->log_module, "Asset connection closed");
                shutdown = true;
        }

        if (ret < 0)
        {
                shutdown = true;
        }

        return shutdown;
}

static void* connection_handler_thread(void* ptr)
{
        proxy_connection* connection = (proxy_connection*) ptr;
        poll_set poll_set;
        bool shutdown = false;

        LOG_INFO_EX(*connection->log_module,
                    "Proxy connection handler started for slot %d/%d",
                    connection->slot + 1,
                    MAX_CONNECTIONS_PER_PROXY);

        poll_set_init(&poll_set);

        poll_set_add_fd(&poll_set, connection->tunnel_sock, POLLIN);
        poll_set_add_fd(&poll_set, connection->asset_sock, POLLOUT | POLLIN);

        /* Set the management socket to non-blocking and add it to the poll_set */
        setblocking(connection->management_socket_pair[1], false);
        poll_set_add_fd(&poll_set, connection->management_socket_pair[1], POLLIN);

        while (!shutdown)
        {
                /* Block and wait for incoming events (new connections, received data, ...) */
                int ret = poll(poll_set.fds, poll_set.num_fds, -1);

                if (ret == -1)
                {
                        LOG_ERROR_EX(*connection->log_module,
                                     "Connection %d: poll error %d",
                                     connection->slot + 1,
                                     errno);
                        continue;
                }

                /* Check which fds created an event */
                for (int i = 0; i < poll_set.num_fds; i++)
                {
                        int fd = poll_set.fds[i].fd;
                        short event = poll_set.fds[i].revents;

                        if (event == 0)
                                continue;

                        if (fd == connection->management_socket_pair[1])
                        {
                                if (event & POLLIN)
                                {
                                        /* management_socket received data */
                                        proxy_management_message msg;
                                        ret = read_management_message(fd, &msg);
                                        if (ret < 0)
                                        {
                                                continue;
                                        }

                                        /* Handle the message */
                                        ret = handle_management_message(connection, fd, &msg);
                                        if (ret == 1)
                                        {
                                                shutdown = true;
                                                break;
                                        }
                                }
                        }
                        else if (fd == connection->tunnel_sock)
                        {
                                shutdown = handle_tunnel_to_asset(connection, event, &poll_set);
                        }
                        else if (fd == connection->asset_sock)
                        {
                                shutdown = handle_asset_to_tunnel(connection, event, &poll_set);
                        }
                }
        }

        LOG_INFO_EX(*connection->log_module,
                    "Connection on slot %d/%d closed",
                    connection->slot + 1,
                    MAX_CONNECTIONS_PER_PROXY);

        asl_close_session(connection->tls_session);

        proxy_connection_cleanup(connection);
        terminate_thread(connection->log_module);
        return NULL;
}
