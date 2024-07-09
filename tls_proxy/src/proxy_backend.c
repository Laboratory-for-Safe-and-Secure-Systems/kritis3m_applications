
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdio.h>

#include "tls_proxy.h"

#include "proxy_management.h"
#include "proxy_connection.h"
#include "proxy.h"

#include "logging.h"
#include "poll_set.h"
#include "networking.h"

#include "asl.h"


LOG_MODULE_CREATE(proxy_backend);


#define ERROR_OUT(...) { LOG_ERROR(__VA_ARGS__); goto cleanup; }
#define ERROR_OUT_EX(module, ...) { LOG_ERROR_EX(module, __VA_ARGS__); goto cleanup; }


#if defined(__ZEPHYR__)

#define BACKEND_THREAD_PRIORITY 8
#define HANDLER_THREAD_PRIORITY 10

#else

#define BACKEND_THREAD_PRIORITY 10
#define HANDLER_THREAD_PRIORITY 12

#endif


typedef struct tls_proxy_backend
{
        int management_socket_pair[2];
        pthread_t thread;
        pthread_attr_t thread_attr;
        poll_set poll_set;
}
tls_proxy_backend;


/* File global variables */
static tls_proxy_backend proxy_backend;



#if defined(__ZEPHYR__)

#define BACKEND_STACK_SIZE (127*1024)
Z_KERNEL_STACK_DEFINE_IN(backend_stack, BACKEND_STACK_SIZE, \
                __attribute__((section(CONFIG_RAM_SECTION_STACKS_2))));
#endif


/* Internal method declarations */
static int handle_management_message(int socket, tls_proxy_management_message const* msg);
static void* tls_proxy_main_thread(void* ptr);


static int handle_management_message(int socket, tls_proxy_management_message const* msg)
{
        switch (msg->type)
        {
                case REVERSE_PROXY_START_REQUEST:
                {
                        /* Add a new reverse proxy */
                        int proxy_id = add_new_proxy(REVERSE_PROXY, &msg->payload.reverse_proxy_config);

                        /* Add proxy to the poll_set */
                        proxy* new_proxy = find_proxy_by_id(proxy_id);
                        int ret = poll_set_add_fd(&proxy_backend.poll_set, new_proxy->incoming_sock, POLLIN);
                        if (ret != 0)
                        {
                                LOG_ERROR("Error adding new proxy to poll_set");
                                kill_proxy(new_proxy);
                                proxy_id = -1;
                        }

                        /* Send response */
                        tls_proxy_management_message response = {
                                .type = PROXY_RESPONSE,
                                .payload.response_code = proxy_id,
                        };
                        send_management_message(socket, &response);
                        break;
                }
                case FORWARD_PROXY_START_REQUEST:
                {
                        /* Add a new forward proxy */
                        int proxy_id = add_new_proxy(FORWARD_PROXY, &msg->payload.forward_proxy_config);

                        /* Add proxy to the poll_set */
                        proxy* new_proxy = find_proxy_by_id(proxy_id);
                        int ret = poll_set_add_fd(&proxy_backend.poll_set, new_proxy->incoming_sock, POLLIN);
                        if (ret != 0)
                        {
                                LOG_ERROR("Error adding new proxy to poll_set");
                                kill_proxy(new_proxy);
                                proxy_id = -1;
                        }

                        /* Send response */
                        tls_proxy_management_message response = {
                                .type = PROXY_RESPONSE,
                                .payload.response_code = proxy_id,
                        };
                        send_management_message(socket, &response);
                        break;
                }
                case PROXY_STATUS_REQUEST:
                {
                        /* Find the proxy */
                        proxy* proxy = find_proxy_by_id(msg->payload.status_req.proxy_id);

                        /* Fill the status object */
                        if (proxy != NULL)
                        {
                                proxy_status* status = msg->payload.status_req.status_obj_ptr;
                                status->is_running = true;
                                status->incoming_port = proxy->incoming_port;
                                status->direction = proxy->direction;
                                status->num_connections = proxy->num_connections;
                        }
                        else
                        {
                                proxy_status* status = msg->payload.status_req.status_obj_ptr;
                                status->is_running = false;
                                status->incoming_port = 0;
                                status->num_connections = 0;
                        }

                        /* Send response */
                        tls_proxy_management_message response = {
                                .type = PROXY_RESPONSE,
                                .payload.response_code = 0,
                        };
                        send_management_message(socket, &response);
                        break;
                }
                case PROXY_STOP_REQUEST:
                {
                        /* Kill the proxy */
                        proxy* proxy_to_be_killed = find_proxy_by_id(msg->payload.proxy_id);
                        if (proxy_to_be_killed != NULL)
                        {
                                poll_set_remove_fd(&proxy_backend.poll_set, proxy_to_be_killed->incoming_sock);
                                kill_proxy(proxy_to_be_killed);
                        }
                        /* Send response */
                        tls_proxy_management_message response = {
                                .type = PROXY_RESPONSE,
                                .payload.response_code = 0,
                        };
                        send_management_message(socket, &response);
                        break;
                }
                default:
                        LOG_ERROR("Received invalid management message");
                        break;
        }

        return 0;
}


/* The actual main thread for the proxy backend */
void* tls_proxy_main_thread(void* ptr)
{
        tls_proxy_backend* backend = (tls_proxy_backend*) ptr;

#if !defined(__ZEPHYR__)
        LOG_INFO("TLS proxy backend started");
#endif

        /* Set the management socket to non-blocking and add it to the poll_set */
        setblocking(backend->management_socket_pair[1], false);
        poll_set_add_fd(&backend->poll_set, backend->management_socket_pair[1], POLLIN);

        while (1)
        {
                struct sockaddr client_addr;
                socklen_t client_addr_len = sizeof(client_addr);

                /* Block and wait for incoming events (new connections, received data, ...) */
                int ret = poll(backend->poll_set.fds, backend->poll_set.num_fds, -1);

                if (ret == -1) {
                        LOG_ERROR("poll error: %d", errno);
                        continue;
                }

                /* Check which fds created an event */
                for (int i = 0; i < backend->poll_set.num_fds; i++)
                {
                        int fd = backend->poll_set.fds[i].fd;
                        short event = backend->poll_set.fds[i].revents;

                        if(event == 0)
                                continue;

                        proxy* proxy = NULL;
                        proxy_connection* proxy_connection = NULL;

                        if (fd == backend->management_socket_pair[1])
                        {
                                if (event & POLLIN)
                                {
                                        /* management_socket received data */
                                        tls_proxy_management_message msg;
                                        ret = read_management_message(fd, &msg);
                                        if (ret < 0)
                                        {
                                                continue;
                                        }

                                        /* Handle the message */
                                        handle_management_message(fd, &msg);
                                }
                        }
                        /* Check all reverse proxies */
                        else if ((proxy = find_proxy_by_fd(fd)) != NULL)
                        {
                                if (event & POLLIN)
                                {
                                        /* New client connection, try to handle it */
                                        int client_socket = accept(proxy->incoming_sock, &client_addr, &client_addr_len);
                                        if (client_socket < 0)
                                        {
                                                int error = errno;
                                                if (error != EAGAIN)
                                                        LOG_ERROR("accept error: %d (fd=%d)", error, proxy->incoming_sock);
                                                continue;
                                        }

                                        /* Handle new client */
                                        proxy_connection = add_new_connection_to_proxy(proxy,
                                                                                       client_socket,
                                                                                       &client_addr);
                                        if (proxy_connection == NULL)
                                        {
                                                LOG_ERROR("Error adding new client");
                                                continue;
                                        }

                                        /* As we perform the TLS handshake from within the main thread, we have to add
                                          * the socket to the poll_set. In case of a reverse proxy, the TCP connection
                                         * is already established, hence we can wait for incoming data. In case of a
                                         * forward proxy, we first have to wait for successful connection establishment.
                                         */
                                        if (proxy_connection->direction == REVERSE_PROXY)
                                        {
                                                ret = poll_set_add_fd(&backend->poll_set, proxy_connection->tunnel_sock,
                                                                      POLLIN);
                                        }
                                        else if (proxy_connection->direction == FORWARD_PROXY)
                                        {
                                                ret = poll_set_add_fd(&backend->poll_set, proxy_connection->tunnel_sock,
                                                                      POLLOUT | POLLERR | POLLHUP);
                                        }
                                        if (ret != 0)
                                        {
                                                LOG_ERROR("Error adding tunnel connection to poll_set");
                                                proxy_connection_cleanup(proxy_connection);
                                                continue;
                                        }
                                        break;
                                }
                        }
                        /* Check all proxy connections (that are in the TLS handshake) */
                        else if ((proxy_connection = find_proxy_connection_by_fd(fd)) != NULL)
                        {
                                if ((event & POLLIN) || (event & POLLOUT))
                                {
                                        /* Continue with the handshake */
                                        ret = asl_handshake(proxy_connection->tls_session);


                                        if (ret == ASL_SUCCESS)
                                        {
                                                /* Handshake done, remove respective socket from the poll_set */
                                                poll_set_remove_fd(&backend->poll_set, fd);

                                                /* Get handshake metrics (only for reverse proxys, as the metrics are not correct
                                                 * on the TLS client endpoint). */
                                                if (proxy_connection->direction == REVERSE_PROXY)
                                                {
                                                        asl_handshake_metrics metrics;
                                                        metrics = asl_get_handshake_metrics(proxy_connection->tls_session);

                                                        LOG_INFO("Handshake done\r\n\tDuration: %.3f milliseconds\r\n\tTx bytes: "\
                                                                "%d\r\n\tRx bytes: %d", metrics.duration_us / 1000.0,
                                                                metrics.tx_bytes, metrics.rx_bytes);
                                                }

                                                /* Start thread for connection handling */
                                                ret = pthread_create(&proxy_connection->thread,
                                                                     &proxy_connection->thread_attr,
                                                                     connection_handler_thread,
                                                                     proxy_connection);
                                                if (ret != 0)
                                                {
                                                        LOG_ERROR("Error starting client handler thread: %d (%s)", errno, strerror(errno));
                                                        proxy_connection_cleanup(proxy_connection);
                                                }
                                        }
                                        else if (ret == ASL_WANT_READ)
                                        {
                                                /* We have to wait for more data from the peer */
                                                poll_set_update_events(&backend->poll_set, fd, POLLIN);
                                        }
                                        else if (ret == ASL_WANT_WRITE)
                                        {
                                                /* We have to wait for the socket to be writable */
                                                poll_set_update_events(&backend->poll_set, fd, POLLOUT);
                                        }
                                        else
                                        {
                                                LOG_ERROR("Error performing TLS handshake: %s", asl_error_message(ret));
                                                poll_set_remove_fd(&backend->poll_set, fd);
                                                proxy_connection_cleanup(proxy_connection);
                                                continue;
                                        }
                                }
                                if ((event & POLLERR) || (event & POLLHUP))
                                {
                                        LOG_ERROR("Socket error");
                                        poll_set_remove_fd(&backend->poll_set, fd);
                                        proxy_connection_cleanup(proxy_connection);
                                        continue;
                                }
                        }
                        else
                        {
                                LOG_ERROR("Received event for unknown fd %d", fd);
                        }
                }
        }

        return NULL;
}



/* Start a new thread and run the main TLS proxy backend with given config.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_backend_run(proxy_backend_config const* config)
{
        /* Init connection pool */
        init_proxy_connection_pool();

        /* Init server pool */
        init_proxy_pool();

        /* Init app config */
        proxy_backend.management_socket_pair[0] = -1;
        proxy_backend.management_socket_pair[1] = -1;

        pthread_attr_init(&proxy_backend.thread_attr);
        pthread_attr_setdetachstate(&proxy_backend.thread_attr, PTHREAD_CREATE_DETACHED);

        poll_set_init(&proxy_backend.poll_set);

#if defined(__ZEPHYR__)
        /* We have to properly set the attributes with the stack to use for Zephyr. */
        pthread_attr_setstack(&proxy_backend.thread_attr, &backend_stack, K_THREAD_STACK_SIZEOF(backend_stack));
#endif

        /* Set the priority of the client handler thread to be one higher than the backend thread.
         * This priorizes active connections before handshakes of new ones. */
        // struct sched_param param = {
        // 	.sched_priority = BACKEND_THREAD_PRIORITY,
        // };
        // pthread_attr_setschedparam(&proxy_backend.thread_attr, &param);
        // pthread_attr_setschedpolicy(&proxy_backend.thread_attr, SCHED_RR);

        /* Set the log level */
        LOG_LVL_SET(config->log_level);

        /* Create the socket pair for external management */
        int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, proxy_backend.management_socket_pair);
        if (ret < 0)
        {
                LOG_ERROR("Error creating socket pair for management: %d (%s)", errno, strerror(errno));
                return -1;
        }

        /* Create the new thread */
        ret = pthread_create(&proxy_backend.thread, &proxy_backend.thread_attr, tls_proxy_main_thread, &proxy_backend);
        if (ret == 0)
        {
                LOG_INFO("TLS proxy main thread started");
        }
        else
        {
                LOG_ERROR("Error starting TLS proxy thread: %d (%s)", errno, strerror(errno));
        }

        return ret;
}


int tls_proxy_start_helper(tls_proxy_management_message const* request)
{
        tls_proxy_management_message response;

        /* Send request */
        int ret = send_management_message(proxy_backend.management_socket_pair[0], request);
        if (ret < 0)
        {
                return -1;
        }

        /* Wait for response */
        ret = read_management_message(proxy_backend.management_socket_pair[0], &response);
        if (ret < 0)
        {
                return -1;
        }
        else if (response.type != PROXY_RESPONSE)
        {
                LOG_ERROR("Received invalid response");
                return -1;
        }
        else if (response.payload.response_code < 0)
        {
                LOG_ERROR("Error starting new TLS proxy (error %d)", response.payload.response_code);
                return -1;
        }

        /* Response code is the id of the new server */
        return response.payload.response_code;
}


/* Start a new reverse proxy with given config.
 *
 * Returns the id of the new proxy instance on success (positive integer) or -1
 * on failure (error message is printed to console).
 */
int tls_reverse_proxy_start(proxy_config const* config)
{
        /* Create a START_REQUEST message */
        tls_proxy_management_message request = {
                .type = REVERSE_PROXY_START_REQUEST,
                .payload.reverse_proxy_config = *config,
        };

        return tls_proxy_start_helper(&request);
}


/* Start a new forward proxy with given config.
 *
 * Returns the id of the new proxy instance on success (positive integer) or -1
 * on failure (error message is printed to console).
 */
int tls_forward_proxy_start(proxy_config const* config)
{
        /* Create a START_REQUEST message */
        tls_proxy_management_message request = {
                .type = FORWARD_PROXY_START_REQUEST,
                .payload.forward_proxy_config = *config,
        };

        return tls_proxy_start_helper(&request);
}


/* Querry status information from the proxy with given id.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_get_status(int id, proxy_status* status)
{
        /* Create a management message */
        tls_proxy_management_message message = {
                .type = PROXY_STATUS_REQUEST,
                .payload.status_req = {
                        .proxy_id = id,
                        .status_obj_ptr = status,
                }
        };

        /* Send request */
        int ret = send_management_message(proxy_backend.management_socket_pair[0], &message);
        if (ret < 0)
        {
                return -1;
        }

        /* Wait for response */
        ret = read_management_message(proxy_backend.management_socket_pair[0], &message);
        if (ret < 0)
        {
                return -1;
        }
        else if (message.type != PROXY_RESPONSE)
        {
                LOG_ERROR("Received invalid response");
                return -1;
        }
        else if (message.payload.response_code < 0)
        {
                LOG_ERROR("Error obtaining proxy status (error %d)", message.payload.response_code);
                return -1;
        }

        return 0;
}


/* Stop the running proxy with given id (returned by tls_forward_proxy_start or
 * tls_forward_proxy_start).
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_stop(int id)
{
        /* Create a STOP_REQUEST message */
        tls_proxy_management_message request = {
                .type = PROXY_STOP_REQUEST,
                .payload.proxy_id = id,
        };
        tls_proxy_management_message response;

        /* Send request */
        int ret = send_management_message(proxy_backend.management_socket_pair[0], &request);
        if (ret < 0)
        {
                return -1;
        }

        /* Wait for response */
        ret = read_management_message(proxy_backend.management_socket_pair[0], &response);
        if (ret < 0)
        {
                return -1;
        }
        else if (response.type != PROXY_RESPONSE)
        {
                LOG_ERROR("Received invalid response");
                return -1;
        }
        else if (response.payload.response_code < 0)
        {
                LOG_ERROR("Error stopping TLS proxy (error %d)", response.payload.response_code);
                return -1;
        }

        return 0;
}


/* Terminate the application backend.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_backend_terminate(void)
{
        /* Stop all running proxies */
        for (int id = 1; id <= MAX_PROXYS; id++)
        {
                proxy* proxy_to_kill = find_proxy_by_id(id);
                if (proxy_to_kill != NULL)
                {
                        poll_set_remove_fd(&proxy_backend.poll_set, proxy_to_kill->incoming_sock);
                        kill_proxy(proxy_to_kill);
                }
        }

        /* Stop the main thread */
        pthread_cancel(proxy_backend.thread);

        /* Close the management socket pair */
        if (proxy_backend.management_socket_pair[0] >= 0)
        {
                close(proxy_backend.management_socket_pair[0]);
                proxy_backend.management_socket_pair[0] = -1;
        }
        if (proxy_backend.management_socket_pair[1] >= 0)
        {
                close(proxy_backend.management_socket_pair[1]);
                proxy_backend.management_socket_pair[1] = -1;
        }

        return 0;
}
