
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

#include "tls_proxy.h"

#include "proxy_backend.h"
#include "proxy_connection.h"
#include "proxy_management.h"

#include "logging.h"
#include "networking.h"
#include "poll_set.h"
#include "threading.h"

#include "asl.h"

#ifdef USE_MANAGEMENT

#include "kritis3m_application_manager.h"

#endif

LOG_MODULE_CREATE(proxy_backend);

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

#define IPv4 0
#define IPv6 1

/* File global variables */
static proxy proxy_pool[MAX_PROXYS];

#if defined(__ZEPHYR__)

#define BACKEND_STACK_SIZE (16 * 1024)
Z_KERNEL_STACK_DEFINE_IN(backend_stack,
                         BACKEND_STACK_SIZE,
                         __attribute__((section(CONFIG_RAM_SECTION_STACKS_2))));

#endif

/* Internal method declarations */
static int add_new_proxy(proxy_config* config);
static proxy* find_proxy_by_fd(int fd);
static proxy* find_proxy_by_id(int id);
static void kill_proxy(proxy* proxy);

static int handle_management_message(proxy_backend* backend, int socket, proxy_management_message* msg);
static void kill_all_proxies(proxy_backend* backend);
static void asl_log_callback(int32_t level, char const* message);
static void* proxy_backend_thread(void* ptr);

void init_proxy_pool(void)
{
        for (int i = 0; i < MAX_PROXYS; i++)
        {
                proxy_pool[i].application_id = -1;
                proxy_pool[i].in_use = false;
                proxy_pool[i].incoming_tls = false;
                proxy_pool[i].outgoing_tls = false;
                proxy_pool[i].incoming_sock[IPv4] = -1;
                proxy_pool[i].incoming_sock[IPv6] = -1;
                proxy_pool[i].incoming_port[IPv4] = 0;
                proxy_pool[i].incoming_port[IPv6] = 0;
                proxy_pool[i].outgoing_addr = NULL;
                proxy_pool[i].incoming_tls_endpoint = NULL;
                proxy_pool[i].outgoing_tls_endpoint = NULL;
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

        poll_set_init(&backend->poll_set);

        /* Set the log level */
        LOG_LVL_SET(config->log_level);

        /* Create the socket pair for external management */
        int ret = create_socketpair(backend->management_socket_pair);
        if (ret < 0)
        {
                LOG_ERROR("Error creating socket pair for management: %d (%s)", errno, strerror(errno));
                return -1;
        }
        LOG_DEBUG("Created management socket pair (%d, %d)",
                  backend->management_socket_pair[0],
                  backend->management_socket_pair[1]);

        /* Create the new thread */
        thread_attibutes attr = {0};
        attr.function = proxy_backend_thread;
        attr.argument = backend;
#if defined(__ZEPHYR__)
        attr.stack_size = K_THREAD_STACK_SIZEOF(backend_stack);
        attr.stack = backend_stack;
#endif
        ret = start_thread(&backend->thread, &attr);
        if (ret != 0)
        {
                LOG_ERROR("Error starting TLS proxy thread: %d (%s)", errno, strerror(errno));
                return -1;
        }

        return 0;
}

/* Create a new proxy and add it to the main event loop */
static int add_new_proxy(proxy_config* config)
{
        struct addrinfo* bind_addr = NULL;

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
        proxy->incoming_tls = config->incoming_tls;
        proxy->outgoing_tls = config->outgoing_tls;
        proxy->application_id = config->application_id;

        /* Setup the log module for the proxy */
        char* log_module_name = (char*) malloc(32);
        if (log_module_name == NULL)
                ERROR_OUT("Error allocating memory for log module name");
        snprintf(log_module_name, 32, "tls_proxy_%d", freeSlot + 1);
        proxy->log_module.name = log_module_name;
        proxy->log_module.level = config->log_level;

        /* Create the TCP sockets for the incoming connections (IPv4 and IPv6).
         * Do a DNS lookup to make sure we have an IP address. If we already have an IP, this
         * results in a noop. */
        if (address_lookup_server(config->incoming_ip_address, config->incoming_port, &bind_addr, AF_UNSPEC) <
            0)
                ERROR_OUT_EX(proxy->log_module, "Error looking up bind IP address");

        /* Iterate over the linked-list of results */
        struct addrinfo* tmp_addr = bind_addr;
        while (tmp_addr != NULL)
        {
                int sock = -1;

                /* Create listening socket */
                sock = create_listening_socket(tmp_addr->ai_family,
                                               tmp_addr->ai_addr,
                                               tmp_addr->ai_addrlen);
                if (sock == -1)
                        ERROR_OUT_EX(proxy->log_module, "Error creating incoming TCP socket");

                if (tmp_addr->ai_family == AF_INET)
                {
                        proxy->incoming_sock[IPv4] = sock;
                        proxy->incoming_port[IPv4] = ntohs(
                                ((struct sockaddr_in*) tmp_addr->ai_addr)->sin_port);
                }
                else if (tmp_addr->ai_family == AF_INET6)
                {
                        proxy->incoming_sock[IPv6] = sock;
                        proxy->incoming_port[IPv6] = ntohs(
                                ((struct sockaddr_in6*) tmp_addr->ai_addr)->sin6_port);
                }

                tmp_addr = tmp_addr->ai_next;
        }

        /* Do a DNS lookup to make sure we have an IP address. If we already have an IP, this
         * results in a noop. */
        if (address_lookup_client(config->outgoing_ip_address,
                                  config->outgoing_port,
                                  &proxy->outgoing_addr,
                                  AF_UNSPEC) < 0)
                ERROR_OUT_EX(proxy->log_module, "Error looking up outgoing IP address");

        if (config->incoming_tls)
        {
                /* Create the incoming TLS endpoint */
                proxy->incoming_tls_endpoint = asl_setup_server_endpoint(&config->incoming_tls_config);
                if (proxy->incoming_tls_endpoint == NULL)
                        ERROR_OUT_EX(proxy->log_module, "Error creating incoming TLS endpoint");
        }
        if (config->outgoing_tls)
        {
                config->outgoing_tls_config.server_name = config->outgoing_ip_address;

                /* Create the TLS endpoint */
                proxy->outgoing_tls_endpoint = asl_setup_client_endpoint(&config->outgoing_tls_config);
                if (proxy->outgoing_tls_endpoint == NULL)
                        ERROR_OUT_EX(proxy->log_module, "Error creating outgoing TLS endpoint");
        }

        LOG_DEBUG_EX(proxy->log_module,
                     "Waiting for incoming connections on port %d",
                     config->incoming_port);

        if (bind_addr != NULL)
                freeaddrinfo(bind_addr);

        return freeSlot + 1;

cleanup:
        if (bind_addr != NULL)
                freeaddrinfo(bind_addr);

        kill_proxy(proxy);

        return -1;
}

static proxy* find_proxy_by_fd(int fd)
{
        for (int i = 0; i < MAX_PROXYS; i++)
        {
                if ((fd == proxy_pool[i].incoming_sock[IPv4]) ||
                    (fd == proxy_pool[i].incoming_sock[IPv6]))
                {
                        return &proxy_pool[i];
                }
        }

        return NULL;
}
#ifdef USE_MANAGEMENT
static proxy* find_proxy_by_mgmt_id(int mgmt_id)
{
        if (mgmt_id < 0)
                return NULL;

        for (int i = 0; i < MAX_PROXYS; i++)
        {
                if (proxy_pool[i].application_id == mgmt_id)
                {
                        return &proxy_pool[i];
                }
        }
        return NULL;
}
#endif

static proxy* find_proxy_by_id(int id)
{
        if (id < 1 || id >= MAX_PROXYS)
                return NULL;

        if (proxy_pool[id - 1].in_use == false)
                return NULL;

        return &proxy_pool[id - 1];
}

/* Stop a running proxy and cleanup afterwards */
static void kill_proxy(proxy* proxy)
{
        /* Stop the listening sockets and clear it from the poll_set */
        if (proxy->incoming_sock[IPv4] >= 0)
        {
                closesocket(proxy->incoming_sock[IPv4]);
                proxy->incoming_sock[IPv4] = -1;
        }
        if (proxy->incoming_sock[IPv6] >= 0)
        {
                closesocket(proxy->incoming_sock[IPv6]);
                proxy->incoming_sock[IPv6] = -1;
        }

        /* Kill all connections */
        for (int i = 0; i < MAX_CONNECTIONS_PER_PROXY; i++)
        {
                if (proxy->connections[i] != NULL)
                {
                        LOG_DEBUG("Killing proxy connection %d", i);

                        /* Stop the running thread. */
                        proxy_connection_stop_handling(proxy->connections[i]);

                        /* Cleanup the client */
                        proxy_connection_cleanup(proxy->connections[i]);

                        proxy->connections[i] = NULL;
                }
        }

        LOG_DEBUG_EX(proxy->log_module, "Killed all connections");

        /* Clear TLS contexts */
        if (proxy->incoming_tls_endpoint != NULL)
        {
                asl_free_endpoint(proxy->incoming_tls_endpoint);
                proxy->incoming_tls_endpoint = NULL;
        }
        if (proxy->outgoing_tls_endpoint != NULL)
        {
                asl_free_endpoint(proxy->outgoing_tls_endpoint);
                proxy->outgoing_tls_endpoint = NULL;
        }

        /* Free log module name */
        if (proxy->log_module.name != NULL)
        {
                free((void*) proxy->log_module.name);
                proxy->log_module.name = NULL;
        }

        /* Clear the outgoing address */
        if (proxy->outgoing_addr != NULL)
        {
                freeaddrinfo(proxy->outgoing_addr);
                proxy->outgoing_addr = NULL;
        }

        proxy->incoming_port[IPv4] = 0;
        proxy->incoming_port[IPv6] = 0;
        proxy->in_use = false;
}

/* Handle incoming management messages.
 *
 * Return 0 in case the message has been processed successfully, -1 otherwise. In case the
 * connection thread has to be stopped and the connection has to be cleaned up, +1 in returned.
 */
static int handle_management_message(proxy_backend* backend, int socket, proxy_management_message* msg)
{
        int ret = 0;

        switch (msg->type)
        {
        case PROXY_START_REQUEST:
                {
                        /* Add a new proxy */
                        int proxy_id = add_new_proxy(&msg->payload.proxy_config);
                        if (proxy_id > 0)
                        {
                                /* Add proxy to the poll_set */
                                proxy* new_proxy = find_proxy_by_id(proxy_id);
                                if (new_proxy && new_proxy->incoming_sock[IPv4] >= 0)
                                {
                                        ret = poll_set_add_fd(&backend->poll_set,
                                                              new_proxy->incoming_sock[IPv4],
                                                              POLLIN);
                                        if (ret != 0)
                                        {
                                                LOG_ERROR("Error adding new proxy to "
                                                          "poll_set");
                                                kill_proxy(new_proxy);
                                                proxy_id = -1;
                                        }
                                }
                                if (ret == 0 && new_proxy && new_proxy->incoming_sock[IPv6] >= 0)
                                {
                                        ret = poll_set_add_fd(&backend->poll_set,
                                                              new_proxy->incoming_sock[IPv6],
                                                              POLLIN);
                                        if (ret != 0)
                                        {
                                                LOG_ERROR("Error adding new proxy to "
                                                          "poll_set");
                                                poll_set_remove_fd(&backend->poll_set,
                                                                   new_proxy->incoming_sock[IPv4]);
                                                kill_proxy(new_proxy);
                                                proxy_id = -1;
                                        }
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
                                status->incoming_tls = proxy->incoming_tls;
                                status->outgoing_tls = proxy->outgoing_tls;
                                status->incoming_port_v4 = proxy->incoming_port[IPv4];
                                status->incoming_port_v6 = proxy->incoming_port[IPv6];
                                status->num_connections = proxy->num_connections;
                        }
                        else
                        {
                                proxy_status* status = msg->payload.status_req.status_obj_ptr;
                                status->is_running = false;
                                status->incoming_tls = false;
                                status->outgoing_tls = false;
                                status->incoming_port_v4 = 0;
                                status->incoming_port_v6 = 0;
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
                                poll_set_remove_fd(&backend->poll_set,
                                                   proxy_to_be_killed->incoming_sock[IPv4]);
                                poll_set_remove_fd(&backend->poll_set,
                                                   proxy_to_be_killed->incoming_sock[IPv6]);
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
#ifdef USE_MANAGEMENT
        case PROXY_STOP_REQUEST_MGMT:
                {
                        /* Kill the proxy */
                        proxy* proxy_to_be_killed = find_proxy_by_mgmt_id(msg->payload.mgmt_id);
                        if (proxy_to_be_killed != NULL)
                        {
                                poll_set_remove_fd(&backend->poll_set,
                                                   proxy_to_be_killed->incoming_sock[IPv4]);
                                poll_set_remove_fd(&backend->poll_set,
                                                   proxy_to_be_killed->incoming_sock[IPv6]);
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
#endif
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
                        poll_set_remove_fd(&backend->poll_set, proxy_to_kill->incoming_sock[IPv4]);
                        poll_set_remove_fd(&backend->poll_set, proxy_to_kill->incoming_sock[IPv6]);
                        kill_proxy(proxy_to_kill);
                }
        }
}

void proxy_backend_cleanup(proxy_backend* backend)
{
        /* Close the management socket pair */
        if (backend->management_socket_pair[0] >= 0)
        {
                int sock = backend->management_socket_pair[0];
                backend->management_socket_pair[0] = -1;
                closesocket(sock);
        }
        if (backend->management_socket_pair[1] >= 0)
        {
                int sock = backend->management_socket_pair[1];
                backend->management_socket_pair[1] = -1;
                closesocket(sock);
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
                struct sockaddr_in6 client_addr;
                socklen_t client_addr_len = sizeof(client_addr);

                /* Block and wait for incoming events (new connections, received data, ...) */
                ret = poll(backend->poll_set.fds, backend->poll_set.num_fds, -1);

                if (ret == -1)
                {
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

                        if (event == 0)
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
                                        int client_socket = accept(fd,
                                                                   (struct sockaddr*) &client_addr,
                                                                   &client_addr_len);
                                        if (client_socket < 0)
                                        {
                                                int error = errno;
                                                if (error != EAGAIN)
                                                        LOG_ERROR("accept error: %d (fd=%d)", error, fd);
                                                continue;
                                        }

#ifdef USE_MANAGEMENT
                                        // if (confirm_client(proxy->application_id,
                                        //                    (struct sockaddr*) &client_addr) == false)
                                        //         LOG_WARN("client is not trusted");
#endif

                                        /* Handle new client */
                                        proxy_connection = add_new_connection_to_proxy(proxy,
                                                                                       client_socket,
                                                                                       &client_addr);
                                        if (proxy_connection == NULL)
                                        {
                                                LOG_ERROR("Error adding new client");
                                                continue;
                                        }

                                        /* As we perform the TLS handshake from within the main
                                         * thread, we have to add the sockets to the poll_set. When
                                         * the incoming connection requires TLS, we wait for data to
                                         * be available on the incoming socket. When the outgoing
                                         * connection requires TLS, we wait for the socket to be
                                         * writable (as we have to send data for the TLS handshake).
                                         */
                                        if (proxy_connection->incoming_tls)
                                        {
                                                ret = poll_set_add_fd(&backend->poll_set,
                                                                      proxy_connection->incoming_sock,
                                                                      POLLIN);
                                                if (ret != 0)
                                                {
                                                        LOG_ERROR("Error adding incoming socket to "
                                                                  "poll_set");
                                                        proxy_connection_cleanup(proxy_connection);
                                                        continue;
                                                }
                                        }
                                        else
                                        {
                                                /* Nothing to do in this case, consider TLS handshake done */
                                                proxy_connection->incoming_tls_hs_done = true;
                                        }

                                        ret = poll_set_add_fd(&backend->poll_set,
                                                              proxy_connection->outgoing_sock,
                                                              POLLERR | POLLHUP | POLLOUT);
                                        if (ret != 0)
                                        {
                                                LOG_ERROR("Error adding outgoing socket to "
                                                          "poll_set");
                                                proxy_connection_cleanup(proxy_connection);
                                                continue;
                                        }

                                        // if (proxy_connection->outgoing_tls)
                                        // {
                                        //         poll_set_update_events(&backend->poll_set,
                                        //                                proxy_connection->outgoing_sock,
                                        //                                POLLOUT | POLLERR | POLLHUP);
                                        // }
                                        break;
                                }
                        }
                        /* Check all proxy connections (that are in the TLS handshake) */
                        else if ((proxy_connection = find_proxy_connection_by_fd(fd)) != NULL)
                        {
                                if (((event & POLLERR) || (event & POLLHUP)) &&
                                    fd == proxy_connection->outgoing_sock)
                                {
                                        poll_set_remove_fd(&backend->poll_set, fd);

                                        /* If we have an additional target, try that first */
                                        if (proxy_connection_try_next_target(proxy_connection) < 0)
                                        {
                                                LOG_INFO("Client connection closed");
                                                proxy_connection_cleanup(proxy_connection);
                                                continue;
                                        }

                                        poll_set_add_fd(&backend->poll_set,
                                                        proxy_connection->outgoing_sock,
                                                        POLLERR | POLLHUP | POLLOUT);

                                        continue;
                                }
                                if ((event & POLLIN) || (event & POLLOUT))
                                {
                                        if (fd == proxy_connection->incoming_sock)
                                        {
                                                /* Continue with the handshake */
                                                ret = asl_handshake(
                                                        proxy_connection->incoming_tls_session);

                                                if (ret == ASL_SUCCESS)
                                                {
                                                        /* Handshake done, remove socket from the poll_set */
                                                        poll_set_remove_fd(&backend->poll_set,
                                                                           proxy_connection->incoming_sock);

                                                        proxy_connection->incoming_tls_hs_done = true;

                                                        /* Get handshake metrics (only for reverse
                                                         * proxys, as the metrics are not correct on
                                                         * the TLS client endpoint). */
                                                        asl_handshake_metrics metrics;
                                                        metrics = asl_get_handshake_metrics(
                                                                proxy_connection->incoming_tls_session);
                                                        LOG_INFO("Incoming TLS handshake done "
                                                                 "(took "
                                                                 "%.3f ms)",
                                                                 metrics.duration_us / 1000.0);

                                                        /* Start thread for connection handling */
                                                        if (proxy_connection->outgoing_tls_hs_done)
                                                        {
                                                                ret = proxy_connection_detach_handling(
                                                                        proxy_connection);
                                                                if (ret != 0)
                                                                {
                                                                        LOG_ERROR("Error starting "
                                                                                  "client "
                                                                                  "handler "
                                                                                  "thread: %d (%s)",
                                                                                  ret,
                                                                                  strerror(ret));
                                                                        proxy_connection_cleanup(
                                                                                proxy_connection);
                                                                }
                                                        }
                                                }
                                                else if (ret == ASL_WANT_READ)
                                                {
                                                        /* We have to wait for more data from the peer */
                                                        poll_set_update_events(&backend->poll_set,
                                                                               proxy_connection->incoming_sock,
                                                                               POLLIN);
                                                }
                                                else if (ret == ASL_WANT_WRITE)
                                                {
                                                        /* We have to wait for the socket to be writable */
                                                        poll_set_update_events(&backend->poll_set,
                                                                               proxy_connection->incoming_sock,
                                                                               POLLOUT);
                                                }
                                                else
                                                {
                                                        LOG_ERROR("Error performing incoming TLS "
                                                                  "handshake: "
                                                                  "%s",
                                                                  asl_error_message(ret));
                                                        poll_set_remove_fd(&backend->poll_set,
                                                                           proxy_connection->incoming_sock);
                                                        poll_set_remove_fd(&backend->poll_set,
                                                                           proxy_connection->outgoing_sock);
                                                        proxy_connection_cleanup(proxy_connection);
                                                        continue;
                                                }
                                        }
                                        else if (fd == proxy_connection->outgoing_sock)
                                        {
                                                if (proxy_connection->outgoing_tls == true)
                                                {
                                                        /* Continue with the handshake */
                                                        ret = asl_handshake(
                                                                proxy_connection->outgoing_tls_session);
                                                }
                                                else
                                                {
                                                        /* No TLS, consider handshake successful */
                                                        ret = ASL_SUCCESS;
                                                }

                                                if (ret == ASL_SUCCESS)
                                                {
                                                        /* Handshake done, remove socket from the poll_set */
                                                        poll_set_remove_fd(&backend->poll_set,
                                                                           proxy_connection->outgoing_sock);

                                                        proxy_connection->outgoing_tls_hs_done = true;

                                                        /* Get handshake metrics (only for reverse
                                                         * proxys, as the metrics are not correct on
                                                         * the TLS client endpoint). */
                                                        if (proxy_connection->outgoing_tls)
                                                        {
                                                                asl_handshake_metrics metrics;
                                                                metrics = asl_get_handshake_metrics(
                                                                        proxy_connection->outgoing_tls_session);
                                                                LOG_INFO("Outgoing TLS handshake "
                                                                         "done "
                                                                         "(took "
                                                                         "%.3f ms)",
                                                                         metrics.duration_us / 1000.0);
                                                        }
                                                        /* Start thread for connection handling */
                                                        if (proxy_connection->incoming_tls_hs_done)
                                                        {
                                                                ret = proxy_connection_detach_handling(
                                                                        proxy_connection);
                                                                if (ret != 0)
                                                                {
                                                                        LOG_ERROR("Error starting "
                                                                                  "client "
                                                                                  "handler "
                                                                                  "thread: %d (%s)",
                                                                                  ret,
                                                                                  strerror(ret));
                                                                        proxy_connection_cleanup(
                                                                                proxy_connection);
                                                                }
                                                        }
                                                }
                                                else if (ret == ASL_WANT_READ)
                                                {
                                                        /* We have to wait for more data from the peer */
                                                        poll_set_update_events(&backend->poll_set,
                                                                               proxy_connection->outgoing_sock,
                                                                               POLLIN);
                                                }
                                                else if (ret == ASL_WANT_WRITE)
                                                {
                                                        /* We have to wait for the socket to be writable */
                                                        poll_set_update_events(&backend->poll_set,
                                                                               proxy_connection->outgoing_sock,
                                                                               POLLOUT);
                                                }
                                                else
                                                {
                                                        LOG_ERROR("Error performing outgoing TLS "
                                                                  "handshake: "
                                                                  "%s",
                                                                  asl_error_message(ret));
                                                        poll_set_remove_fd(&backend->poll_set,
                                                                           proxy_connection->outgoing_sock);
                                                        poll_set_remove_fd(&backend->poll_set,
                                                                           proxy_connection->incoming_sock);
                                                        proxy_connection_cleanup(proxy_connection);
                                                        continue;
                                                }
                                        }
                                        else
                                        {
                                                LOG_ERROR("Received event for unknown fd %d", fd);
                                                poll_set_remove_fd(&backend->poll_set, fd);
                                                proxy_connection_cleanup(proxy_connection);
                                                continue;
                                        }
                                }
                        }
                        else
                        {
                                LOG_ERROR("Received event for unknown fd %d", fd);
                                poll_set_remove_fd(&backend->poll_set, fd);
                                continue;
                        }
                }
        }

        proxy_backend_cleanup(backend);
        asl_cleanup();
        terminate_thread(&backend->thread, LOG_MODULE_GET());
        return NULL;
}
