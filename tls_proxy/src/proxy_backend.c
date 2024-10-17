
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#if defined(_WIN32)

#include <winsock2.h>

#else

#include <sys/socket.h>
#include <netinet/tcp.h>

#endif

#include "tls_proxy.h"

#include "proxy_management.h"
#include "proxy_connection.h"
#include "proxy_backend.h"

#include "logging.h"
#include "poll_set.h"
#include "networking.h"

#include "asl.h"


LOG_MODULE_CREATE(proxy_backend);


#define ERROR_OUT(...) { LOG_ERROR(__VA_ARGS__); goto cleanup; }
#define ERROR_OUT_EX(module, ...) { LOG_ERROR_EX(module, __VA_ARGS__); goto cleanup; }



/* File global variables */
static proxy proxy_pool[MAX_PROXYS];



#if defined(__ZEPHYR__)

#define BACKEND_STACK_SIZE (32*1024)
Z_KERNEL_STACK_DEFINE_IN(backend_stack, BACKEND_STACK_SIZE, \
                __attribute__((section(CONFIG_RAM_SECTION_STACKS_2))));

#endif


/* Internal method declarations */
static int add_new_proxy(enum tls_proxy_direction direction, proxy_config const* config);
static proxy* find_proxy_by_fd(int fd);
static proxy* find_proxy_by_id(int id);
static void kill_proxy(proxy* proxy);

static int handle_management_message(proxy_backend* backend, int socket, proxy_management_message const* msg);
static void kill_all_proxies(proxy_backend* backend);
static void asl_log_callback(int32_t level, char const* message);
static void* proxy_backend_thread(void* ptr);


void init_proxy_pool(void)
{
        for (int i = 0; i < MAX_PROXYS; i++)
        {
                proxy_pool[i].in_use = false;
                proxy_pool[i].direction = REVERSE_PROXY;
                proxy_pool[i].incoming_sock = -1;
                proxy_pool[i].incoming_port = 0;
                proxy_pool[i].tls_endpoint = NULL;
                proxy_pool[i].log_module.name = NULL;
                proxy_pool[i].log_module.level = LOG_LVL_WARN;
                proxy_pool[i].num_connections = 0;

                for (int j = 0; j < MAX_CONNECTIONS_PER_PROXY; j++)
                {
                        proxy_pool[i].connections[j] = NULL;
                }
        }
}


int proxy_backend_init(proxy_backend* backend, proxy_backend_config const* config)
{
        /* Init app config */
        backend->running = false;
        backend->management_socket_pair[0] = -1;
        backend->management_socket_pair[1] = -1;

        pthread_attr_init(&backend->thread_attr);
        pthread_attr_setdetachstate(&backend->thread_attr, PTHREAD_CREATE_JOINABLE);

        poll_set_init(&backend->poll_set);

#if defined(__ZEPHYR__)
        /* We have to properly set the attributes with the stack to use for Zephyr. */
        pthread_attr_setstack(&backend->thread_attr, &backend_stack, K_THREAD_STACK_SIZEOF(backend_stack));
#endif

        /* Set the priority of the client handler thread to be one higher than the backend thread.
         * This priorizes active connections before handshakes of new ones. */
        // struct sched_param param = {
        // 	.sched_priority = BACKEND_THREAD_PRIORITY,
        // };
        // pthread_attr_setschedparam(&backend->thread_attr, &param);
        // pthread_attr_setschedpolicy(&backend->thread_attr, SCHED_RR);

        /* Set the log level */
        LOG_LVL_SET(config->log_level);

        /* Create the socket pair for external management */
        int ret = create_socketpair(backend->management_socket_pair);
        if (ret < 0)
        {
                LOG_ERROR("Error creating socket pair for management: %d (%s)", errno, strerror(errno));
                return -1;
        }
        LOG_DEBUG("Created management socket pair (%d, %d)", backend->management_socket_pair[0],
                                                            backend->management_socket_pair[1]);

        /* Create the new thread */
        ret = pthread_create(&backend->thread, &backend->thread_attr, proxy_backend_thread, backend);
        if (ret != 0)
        {
                LOG_ERROR("Error starting TLS proxy thread: %d (%s)", errno, strerror(errno));
                return -1;
        }

        return 0;
}


/* Create a new proxy and add it to the main event loop */
static int add_new_proxy(enum tls_proxy_direction direction, proxy_config const* config)
{
        /* Search for a free server slot */
        int freeSlot = -1;
        for (int i = 0; i < MAX_PROXYS; i++)
        {
                if (proxy_pool[i].in_use == false)
                {
                        freeSlot = i;
                        break;
                }
        }

        if (freeSlot == -1)
        {
                LOG_ERROR("Cannot create more TLS proxies (no free slot)");
                return -1;
        }

        proxy* proxy = &proxy_pool[freeSlot];

        proxy->in_use = true;
        proxy->direction = direction;

        /* Setup the log module for the proxy */
        char* log_module_name = (char*) malloc(32);
        if (log_module_name == NULL)
                ERROR_OUT("Error allocating memory for log module name");
        snprintf(log_module_name, 32, "tls_proxy_%d", freeSlot+1);
        proxy->log_module.name = log_module_name;
        proxy->log_module.level = config->log_level;

        if (direction == REVERSE_PROXY)
        {
                LOG_INFO_EX(proxy->log_module, "Starting new reverse proxy on port %d",
                        config->listening_port);

                /* Create the TLS endpoint */
                proxy->tls_endpoint = asl_setup_server_endpoint(&config->tls_config);
        }
        else if (direction == FORWARD_PROXY)
        {
                LOG_INFO_EX(proxy->log_module, "Starting new forward proxy to %s:%d",
                config->target_ip_address, config->target_port);

                /* Create the TLS endpoint */
                proxy->tls_endpoint = asl_setup_client_endpoint(&config->tls_config);
        }
        if (proxy->tls_endpoint == NULL)
                ERROR_OUT_EX(proxy->log_module, "Error creating TLS endpoint");

        /* Create the TCP socket for the incoming connection */
        proxy->incoming_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (proxy->incoming_sock == -1)
                ERROR_OUT_EX(proxy->log_module, "Error creating incoming TCP socket");

        if (setsockopt(proxy->incoming_sock, SOL_SOCKET, SO_REUSEADDR, &(char){1}, sizeof(int)) < 0)
                ERROR_OUT_EX(proxy->log_module, "setsockopt(SO_REUSEADDR) failed: errer %d", errno);

        /* Configure TCP server */
        struct sockaddr_in bind_addr = {
                        .sin_family = AF_INET,
                        .sin_port = htons(config->listening_port)
        };
        net_addr_pton(bind_addr.sin_family, config->own_ip_address, &bind_addr.sin_addr);
        proxy->incoming_port = config->listening_port;

        /* Bind server socket to its destined IPv4 address */
        if (bind(proxy->incoming_sock, (struct sockaddr*) &bind_addr, sizeof(bind_addr)) == -1)
                ERROR_OUT_EX(proxy->log_module, "Cannot bind socket %d to %s:%d: error %d",
                        proxy->incoming_sock, config->own_ip_address, config->listening_port, errno);

        /* If a random port have been used, obtain the actually selected one */
	if (config->listening_port == 0)
	{
		socklen_t sockaddr_len = sizeof(bind_addr);
		if (getsockname(proxy->incoming_sock, (struct sockaddr*)&bind_addr, &sockaddr_len) < 0)
                        ERROR_OUT_EX(proxy->log_module, "getsockname failed with errno: %d", errno);

		proxy->incoming_port = ntohs(bind_addr.sin_port);
	}

        /* Start listening for incoming connections */
        listen(proxy->incoming_sock, MAX_CONNECTIONS_PER_PROXY);

        /* Set the new socket to non-blocking */
        setblocking(proxy->incoming_sock, false);

        /* Configure TCP client */
        proxy->target_addr.sin_family = AF_INET;
        proxy->target_addr.sin_port = htons(config->target_port);
        net_addr_pton(proxy->target_addr.sin_family, config->target_ip_address, &proxy->target_addr.sin_addr);

        LOG_DEBUG_EX(proxy->log_module, "Waiting for incoming connections on port %d", config->listening_port);

        return freeSlot+1;

cleanup:
        kill_proxy(proxy);

        return -1;
}


static proxy* find_proxy_by_fd(int fd)
{
        for (int i = 0; i < MAX_PROXYS; i++)
        {
                if (proxy_pool[i].incoming_sock == fd)
                {
                        return &proxy_pool[i];
                }
        }

        return NULL;
}


static proxy* find_proxy_by_id(int id)
{
        if (id < 1 || id >= MAX_PROXYS)
                return NULL;

        if (proxy_pool[id-1].in_use == false)
                return NULL;

        return &proxy_pool[id-1];

}


/* Stop a running proxy and cleanup afterwards */
static void kill_proxy(proxy* proxy)
{
        /* Stop the listening socket and clear it from the poll_set */
        if (proxy->incoming_sock >= 0)
        {
                closesocket(proxy->incoming_sock);
                proxy->incoming_sock = -1;
        }

        /* Kill all connections */
        for (int i = 0; i < MAX_CONNECTIONS_PER_PROXY; i++)
        {
                if (proxy->connections[i] != NULL)
                {
                        /* Stop the running thread. */
                        if (proxy->connections[i]->in_use == true)
                        {
                                LOG_DEBUG("Killing proxy connection %d", i);
                                proxy_connection_stop_handling(proxy->connections[i]);
                        }

                        /* Cleanup the client */
                        proxy_connection_cleanup(proxy->connections[i]);

                        proxy->connections[i] = NULL;
                }
        }

        LOG_DEBUG_EX(proxy->log_module, "Killed all connections");

        /* Clear TLS context */
        if (proxy->tls_endpoint != NULL)
        {
                asl_free_endpoint(proxy->tls_endpoint);
                proxy->tls_endpoint = NULL;
        }

        /* Free log module name */
        if (proxy->log_module.name != NULL)
        {
                free((void*) proxy->log_module.name);
                proxy->log_module.name = NULL;
        }

        proxy->incoming_sock = 0;
        proxy->in_use = false;
}


/* Handle incoming management messages.
 *
 * Return 0 in case the message has been processed successfully, -1 otherwise. In case the connection thread has
 * to be stopped and the connection has to be cleaned up, +1 in returned.
 */
static int handle_management_message(proxy_backend* backend, int socket, proxy_management_message const* msg)
{
        int ret = 0;

        switch (msg->type)
        {
                case REVERSE_PROXY_START_REQUEST:
                {
                        /* Add a new reverse proxy */
                        int proxy_id = add_new_proxy(REVERSE_PROXY, &msg->payload.reverse_proxy_config);
                        if (proxy_id > 0)
                        {
                                /* Add proxy to the poll_set */
                                proxy* new_proxy = find_proxy_by_id(proxy_id);
                                int ret = poll_set_add_fd(&backend->poll_set, new_proxy->incoming_sock, POLLIN);
                                if (ret != 0)
                                {
                                        LOG_ERROR("Error adding new proxy to poll_set");
                                        kill_proxy(new_proxy);
                                        proxy_id = -1;
                                }
                        }

                        /* Send response */
                        proxy_management_message response = {
                                .type = RESPONSE,
                                .payload.response_code = proxy_id,
                        };
                        ret = send_management_message(socket, &response);
                        break;
                }
                case FORWARD_PROXY_START_REQUEST:
                {
                        /* Add a new forward proxy */
                        int proxy_id = add_new_proxy(FORWARD_PROXY, &msg->payload.forward_proxy_config);
                        if (proxy_id > 0)
                        {
                                /* Add proxy to the poll_set */
                                proxy* new_proxy = find_proxy_by_id(proxy_id);
                                int ret = poll_set_add_fd(&backend->poll_set, new_proxy->incoming_sock, POLLIN);
                                if (ret != 0)
                                {
                                        LOG_ERROR("Error adding new proxy to poll_set");
                                        kill_proxy(new_proxy);
                                        proxy_id = -1;
                                }
                        }

                        /* Send response */
                        proxy_management_message response = {
                                .type = RESPONSE,
                                .payload.response_code = proxy_id,
                        };
                        ret = send_management_message(socket, &response);
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
                        proxy_management_message response = {
                                .type = RESPONSE,
                                .payload.response_code = 0,
                        };
                        ret = send_management_message(socket, &response);
                        break;
                }
                case PROXY_STOP_REQUEST:
                {
                        /* Kill the proxy */
                        proxy* proxy_to_be_killed = find_proxy_by_id(msg->payload.proxy_id);
                        if (proxy_to_be_killed != NULL)
                        {
                                poll_set_remove_fd(&backend->poll_set, proxy_to_be_killed->incoming_sock);
                                kill_proxy(proxy_to_be_killed);
                        }
                        /* Send response */
                        proxy_management_message response = {
                                .type = RESPONSE,
                                .payload.response_code = 0,
                        };
                        ret = send_management_message(socket, &response);
                        break;
                }
                case BACKEND_STOP_REQUEST:
                {
                        /* Kill all proxies */
                        kill_all_proxies(backend);

                        /* Return 1 to indicate we have to stop the connection thread and cleanup */
                        ret = 1;

                        /* Send response */
                        proxy_management_message response = {
                                .type = RESPONSE,
                                .payload.response_code = 0,
                        };

                        /* Do not update ret here to make sure the thread terminates */
                        send_management_message(socket, &response);
                        break;
                }
                default:
                        LOG_ERROR("Received invalid management message: msg->type=%d", msg->type);
                        ret = -1;
                        break;
        }

        return ret;
}


static void kill_all_proxies(proxy_backend* backend)
{
         /* Stop all running proxies */
        for (int id = 1; id <= MAX_PROXYS; id++)
        {
                proxy* proxy_to_kill = find_proxy_by_id(id);
                if (proxy_to_kill != NULL)
                {
                        LOG_DEBUG("Killing proxy %d", id);
                        poll_set_remove_fd(&backend->poll_set, proxy_to_kill->incoming_sock);
                        kill_proxy(proxy_to_kill);
                }
        }
}


void proxy_backend_cleanup(proxy_backend* backend)
{
        /* Close the management socket pair */
        if (backend->management_socket_pair[0] >= 0)
        {
                closesocket(backend->management_socket_pair[0]);
                backend->management_socket_pair[0] = -1;
        }
        if (backend->management_socket_pair[1] >= 0)
        {
                closesocket(backend->management_socket_pair[1]);
                backend->management_socket_pair[1] = -1;
        }

        backend->running = false;
}


static void asl_log_callback(int32_t level, char const* message)
{
        switch (level)
        {
        case ASL_LOG_LEVEL_ERR:
                LOG_ERROR("%s", message);
                break;
        case ASL_LOG_LEVEL_WRN:
                LOG_WARN("%s", message);
                break;
        case ASL_LOG_LEVEL_INF:
                LOG_INFO("%s", message);
                break;
        case ASL_LOG_LEVEL_DBG:
                LOG_DEBUG("%s", message);
                break;
        default:
                LOG_ERROR("unknown log level %d: %s", level, message);
                break;
        }
}


/* The actual main thread for the proxy backend */
void* proxy_backend_thread(void* ptr)
{
        proxy_backend* backend = (proxy_backend*) ptr;
        bool shutdown = false;
        backend->running = true;

        LOG_INFO("Proxy backend thread started");

        /* Set the management socket to non-blocking and add it to the poll_set */
        setblocking(backend->management_socket_pair[1], false);
        poll_set_add_fd(&backend->poll_set, backend->management_socket_pair[1], POLLIN);

        /* Initialize the Agile Security Library */
        asl_configuration asl_config = asl_default_config();
        asl_config.logging_enabled = true;
        asl_config.log_level = LOG_LVL_GET();
        asl_config.log_callback = asl_log_callback;

	int ret = asl_init(&asl_config);
	if (ret != 0)
        {
                LOG_ERROR("Error initializing ASL: %d", ret);

                /* Immediatelly terminate */
                shutdown = true;
        }

        while (!shutdown)
        {
                struct sockaddr client_addr;
                socklen_t client_addr_len = sizeof(client_addr);

                /* Block and wait for incoming events (new connections, received data, ...) */
                ret = poll(backend->poll_set.fds, backend->poll_set.num_fds, -1);

                if (ret == -1) {
                #if defined(_WIN32)
                        LOG_ERROR("poll error: %d", WSAGetLastError());
                #else
                        LOG_ERROR("poll error: %d", errno);
                #endif
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
                                        proxy_management_message msg;
                                        ret = read_management_message(fd, &msg);
                                        if (ret < 0)
                                        {
                                                continue;
                                        }

                                        /* Handle the message */
                                        ret = handle_management_message(backend, fd, &msg);
                                        if (ret == 1)
                                        {
                                                shutdown = true;
                                                break;
                                        }
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
                                                                      POLLOUT);
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
                                if ((event & POLLERR) || (event & POLLHUP))
                                {
                                        LOG_INFO("Client connection closed");
                                        poll_set_remove_fd(&backend->poll_set, fd);
                                        proxy_connection_cleanup(proxy_connection);
                                        continue;
                                }
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
                                                ret = proxy_connection_detach_handling(proxy_connection);
                                                if (ret != 0)
                                                {
                                                        LOG_ERROR("Error starting client handler thread: %d (%s)", ret, strerror(ret));
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
                        }
                        else
                        {
                                LOG_ERROR("Received event for unknown fd %d", fd);
                        }
                }
        }

        LOG_INFO("Proxy backend thread terminated");

        proxy_backend_cleanup(backend);

        asl_cleanup();

        /* Detach the thread here, as it is terminating by itself. With that,
         * the thread resources are freed immediatelly. */
        pthread_detach(pthread_self());

        pthread_exit(NULL);
}

