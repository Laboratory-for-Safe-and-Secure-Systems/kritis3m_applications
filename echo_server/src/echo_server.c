#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#if defined(_WIN32)

#include <winsock2.h>

#else

#include <sys/socket.h>
#include <netinet/tcp.h>

#endif

#include "echo_server.h"

#include "logging.h"
#include "poll_set.h"
#include "networking.h"


LOG_MODULE_CREATE(echo_server);


#define ERROR_OUT(...) { LOG_ERROR(__VA_ARGS__); goto cleanup; }

#define IPv4 0
#define IPv6 1

#if defined(__ZEPHYR__)

#define MAX_CLIENTS 5
#define RECV_BUFFER_SIZE 1024

#else

#define MAX_CLIENTS 25
#define RECV_BUFFER_SIZE 16384

#endif


enum echo_server_management_message_type
{
        MANAGEMENT_MSG_START,
        MANAGEMENT_MSG_STATUS_REQUEST,
        MANAGEMENT_MSG_SHUTDOWN,
        MANAGEMENT_RESPONSE
};

typedef struct echo_server_management_message
{
        enum echo_server_management_message_type type;

        union
        {
                echo_server_config config;	/* START */
                echo_server_status* status_ptr; /* STATUS_REQUEST */
                int dummy_unused;               /* SHUTDOWN */
                int response_code;              /* RESPONSE */
        }
        payload;
}
echo_server_management_message;


typedef struct echo_server
{
        bool running;
        bool use_tls;
        int server_socket[2]; // IPv4 and IPv6
        uint16_t listening_port[2]; // IPv4 and IPv6
        uint16_t num_clients;
        asl_endpoint* tls_endpoint;
        int management_socket_pair[2];
        pthread_t thread;
        pthread_attr_t thread_attr;
        struct poll_set poll_set;
}
echo_server;


typedef struct echo_client
{
        bool in_use;
        bool handshake_done;
        int socket;
        int slot;
        asl_session* tls_session;
        size_t num_of_bytes_in_recv_buffer;
        uint8_t recv_buffer[RECV_BUFFER_SIZE];
}
echo_client;


/* File global variables */
static echo_server the_server = {
        .running = false,
        .use_tls = false,
        .server_socket = {-1, -1},
        .listening_port = {0, 0},
        .num_clients = 0,
        .tls_endpoint = NULL,
        .management_socket_pair = {-1, -1},
};


#if defined(__ZEPHYR__)

static echo_client client_pool[MAX_CLIENTS] __attribute__((section(CONFIG_RAM_SECTION_STACKS_1)));

#define STACK_SIZE (32*1024)
Z_KERNEL_STACK_DEFINE_IN(echo_server_stack, STACK_SIZE, \
                __attribute__((section(CONFIG_RAM_SECTION_STACKS_1))));

#else

static echo_client client_pool[MAX_CLIENTS];

#endif


/* Internal method declarations */
static void asl_log_callback(int32_t level, char const* message);
static void* echo_server_main_thread(void* ptr);
static int prepare_server(echo_server* server, echo_server_config const* config);
static echo_client* add_new_client(echo_server* server, int client_socket, struct sockaddr_in6* client_addr);
static echo_client* find_client_by_fd(int fd);
static int do_echo(echo_server* server, echo_client* client, int event);
static void client_cleanup(echo_client* client);
static int send_management_message(int socket, echo_server_management_message const* msg);
static int read_management_message(int socket, echo_server_management_message* msg);
static int handle_management_message(echo_server* server, int socket);
static void echo_server_cleanup(echo_server* server);


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


static void* echo_server_main_thread(void* ptr)
{
        echo_server* server = (echo_server*) ptr;
        echo_server_config* config = NULL;

        bool shutdown = false;
        int ret = 0;

        /* Read the START message with the configuration */
        echo_server_management_message start_msg = {0};
        memset(&start_msg, 0, sizeof(start_msg));
        ret = read_management_message(server->management_socket_pair[1], &start_msg);
        if (ret != 0)
        {
                ERROR_OUT("Error reading start message");
        }
        else if (start_msg.type != MANAGEMENT_MSG_START)
        {
                ERROR_OUT("Received invalid start message");
        }
        config = &start_msg.payload.config;

        /* Start the server */
        ret = prepare_server(server, config);
        if (ret != 0)
        {
                shutdown = true;
                LOG_ERROR("Error preparing server");
        }

        /* Set the management socket to non-blocking and add it to the poll_set */
        setblocking(server->management_socket_pair[1], false);
        poll_set_add_fd(&server->poll_set, server->management_socket_pair[1], POLLIN);

        /* Send response */
        start_msg.type = MANAGEMENT_RESPONSE;
        start_msg.payload.response_code = ret;
        ret = send_management_message(server->management_socket_pair[1], &start_msg);
        if (ret < 0)
        {
                ERROR_OUT("Error sending response");
        }

        while (!shutdown)
        {
                struct sockaddr_in6 client_addr;
                socklen_t client_addr_len = sizeof(client_addr);

                /* Block and wait for incoming events (new connections, received data, ...) */
                int ret = poll(server->poll_set.fds, server->poll_set.num_fds, -1);

                if (ret == -1) {
                        LOG_ERROR("poll error: %d", errno);
                        continue;
                }

                /* Check which fds created an event */
                for (int i = 0; i < server->poll_set.num_fds; i++)
                {
                        int fd = server->poll_set.fds[i].fd;
                        short event = server->poll_set.fds[i].revents;

                        if(event == 0)
                                continue;

                        echo_client* client = NULL;

                        /* Check management socket */
                        if (fd == server->management_socket_pair[1])
                        {
                                if (event & POLLIN)
                                {
                                        /* Handle the message */
                                        ret = handle_management_message(server, fd);
                                        if (ret == 1)
                                        {
                                                shutdown = true;
                                                break;
                                        }
                                }
                        }
                        /* Check server fd */
                        else if ((fd == server->server_socket[IPv4]) || (fd == server->server_socket[IPv6]))
                        {
                                if (event & POLLIN)
                                {
                                        /* New client connection, try to handle it */
                                        int client_socket = accept(fd, (struct sockaddr*)&client_addr, &client_addr_len);
                                        if (client_socket < 0)
                                        {
                                                int error = errno;
                                                if (error != EAGAIN)
                                                        LOG_ERROR("accept error: %d (fd=%d)", error, fd);
                                                continue;
                                        }

                                        /* Handle new client */
                                        client = add_new_client(server, client_socket, &client_addr);
                                        if (client == NULL)
                                        {
                                                LOG_ERROR("Error adding new client");
                                                closesocket(client_socket);
                                                continue;
                                        }

                                        /* Add the socket of the new client to the poll_set. */
                                        ret = poll_set_add_fd(&server->poll_set, client->socket, POLLIN);
                                        if (ret != 0)
                                        {
                                                LOG_ERROR("Error adding new client to poll_set");
                                                client_cleanup(client);
                                                continue;
                                        }
                                        break;
                                }
                        }
                        /* Check all clients */
                        else if ((client = find_client_by_fd(fd)) != NULL)
                        {
                                if (event & POLLERR)
                                {
                                        LOG_INFO("Client connection in slot %d closed", client->slot+1);
                                        poll_set_remove_fd(&server->poll_set, fd);
                                        client_cleanup(client);
                                        continue;
                                }

                                if (client->tls_session != NULL && client->handshake_done == false)
                                {
                                        /* Perform TLS handshake */
                                        ret = asl_handshake(client->tls_session);

                                        if (ret == ASL_SUCCESS)
                                        {
                                                /* Handshake done */
                                                client->handshake_done = true;

                                                /* Print handshake metrics */
                                                asl_handshake_metrics metrics;
                                                metrics = asl_get_handshake_metrics(client->tls_session);
                                                LOG_INFO("Handshake done (took %.3f ms)", metrics.duration_us / 1000.0);
                                        }
                                        else if (ret == ASL_WANT_READ)
                                        {
                                                /* We have to wait for more data from the peer */
                                                poll_set_update_events(&server->poll_set, fd, POLLIN);
                                        }
                                        else if (ret == ASL_WANT_WRITE)
                                        {
                                                /* We have to wait for the socket to be writable */
                                                poll_set_update_events(&server->poll_set, fd, POLLOUT);
                                        }
                                        else
                                        {
                                                LOG_ERROR("Error performing TLS handshake: %s", asl_error_message(ret));
                                                poll_set_remove_fd(&server->poll_set, fd);
                                                client_cleanup(client);
                                                continue;
                                        }
                                }
                                else
                                {
                                        /* Do the echo */
                                        ret = do_echo(server, client, event);
                                        if (ret < 0)
                                        {
                                                /* Error, close session */
                                                client_cleanup(client);
                                                break;
                                        }
                                }
                        }
                        else
                        {
                                LOG_ERROR("Received event for unknown fd %d", fd);
                        }
                }
        }

cleanup:
        /* Cleanup */
        echo_server_cleanup(server);

        LOG_DEBUG("Echo server thread terminated");

        /* Detach the thread here, as it is terminating by itself. With that,
         * the thread resources are freed immediatelly. */
        pthread_detach(pthread_self());

        return NULL;
}


static int prepare_server(echo_server* server, echo_server_config const* config)
{
        int ret = 0;

        server->running = true;
        server->use_tls = config->use_tls;
        server->num_clients = 0;
        server->server_socket[IPv4] = -1;
        server->server_socket[IPv6] = -1;
        server->listening_port[IPv4] = 0;
        server->listening_port[IPv6] = 0;

        /* Init client pool */
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
                client_pool[i].in_use = false;
                client_pool[i].handshake_done = false;
                client_pool[i].socket = -1;
                client_pool[i].slot = -1;
                client_pool[i].tls_session = NULL;
                client_pool[i].num_of_bytes_in_recv_buffer = 0;
        }

        poll_set_init(&server->poll_set);

        /* Create the listening sockets for incoming client connections.
         * Do a DNS lookup to make sure we have an IP address. If we already have an IP, this
         * results in a noop. */
        struct addrinfo* bind_addr = NULL;
        ret = address_lookup_server(config->own_ip_address, config->listening_port, &bind_addr);
        if (ret < 0)
                ERROR_OUT("Error looking up target IP address");

        /* Iterate over the linked-list of results */
        struct addrinfo* tmp_addr = bind_addr;
        while (tmp_addr != NULL)
        {
                int sock = -1;

                /* Create listening socket */
                sock = create_listening_socket(tmp_addr->ai_family, tmp_addr->ai_addr, tmp_addr->ai_addrlen);
                if (sock == -1)
                {
                        ret = -1;
                        ERROR_OUT("Error creating incoming TCP socket");
                }

                /* Add the socket to the poll_set */
                ret = poll_set_add_fd(&server->poll_set, sock, POLLIN);
                if (ret != 0)
                        ERROR_OUT("Error adding socket to poll_set");

                if (tmp_addr->ai_family == AF_INET)
                {
                        server->server_socket[IPv4] = sock;
                        server->listening_port[IPv4] = ntohs(((struct sockaddr_in*)tmp_addr->ai_addr)->sin_port);
                }
                else if (tmp_addr->ai_family == AF_INET6)
                {
                        server->server_socket[IPv6] = sock;
                        server->listening_port[IPv6] = ntohs(((struct sockaddr_in6*)tmp_addr->ai_addr)->sin6_port);
                }

                tmp_addr = tmp_addr->ai_next;
        }

        /* Initialize the Agile Security Library and configure TLS endpoint */
        if (config->use_tls == true)
        {
                LOG_DEBUG("Initializing ASL");

                asl_configuration asl_config = asl_default_config();
                asl_config.logging_enabled = true;
                asl_config.log_level = LOG_LVL_GET();
                asl_config.log_callback = asl_log_callback;

                ret = asl_init(&asl_config);
                if (ret != ASL_SUCCESS)
                        ERROR_OUT("Error initializing ASL: %d (%s)", ret, asl_error_message(ret));

                LOG_DEBUG("Setting up TLS server endpoint");

                server->tls_endpoint = asl_setup_server_endpoint(&config->tls_config);
                if (server->tls_endpoint == NULL)
                {
                        ret = -1;
                        ERROR_OUT("Error creating TLS endpoint");
                }
        }

cleanup:
        if (bind_addr != NULL)
                freeaddrinfo(bind_addr);

        return ret;
}


static echo_client* add_new_client(echo_server* server, int client_socket,
                                   struct sockaddr_in6* client_addr)
{
        /* Search for a free client slot in the pool */
        int freeSlot = -1;
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
                if (client_pool[i].in_use == false)
                {
                        freeSlot = i;
                        break;
                }
        }
        if (freeSlot == -1)
        {
                LOG_ERROR("No free client slots available");
                return NULL;
        }

        echo_client* client = &client_pool[freeSlot];

        server->num_clients += 1;

        /* Store new client data */
        client->in_use = true;
        client->num_of_bytes_in_recv_buffer = 0;
        client->socket = client_socket;
        client->slot = freeSlot;

        setblocking(client->socket, false);

        if (setsockopt(client->socket, IPPROTO_TCP, TCP_NODELAY, (char*)&(int){1}, sizeof(int)) < 0)
        {
                LOG_ERROR("setsockopt(TCP_NODELAY) for client socket failed: error %d", errno);
                client_cleanup(client);
                return NULL;
        }

        /* Create the TLS session */
        if (server->use_tls == true)
        {
                client->tls_session = asl_create_session(server->tls_endpoint, client->socket);
                if (client->tls_session == NULL)
                {
                        LOG_ERROR("Error creating TLS session");
                        client_cleanup(client);
                        return NULL;
                }

                client->handshake_done = false;
        }
        else
                /* No handshake necessary */
                client->handshake_done = true;

        /* Print info */
        char peer_ip[INET6_ADDRSTRLEN];

        if (client_addr->sin6_family == AF_INET)
                net_addr_ntop(AF_INET, &((struct sockaddr_in*)client_addr)->sin_addr, peer_ip, sizeof(peer_ip));
        else if (client_addr->sin6_family == AF_INET6)
                net_addr_ntop(AF_INET6, &((struct sockaddr_in6*)client_addr)->sin6_addr, peer_ip, sizeof(peer_ip));

        LOG_INFO("New client connection from %s:%d, using slot %d/%d",
                peer_ip, ntohs(((struct sockaddr_in*)client_addr)->sin_port),
                freeSlot+1, MAX_CLIENTS);

        return client;
}


static echo_client* find_client_by_fd(int fd)
{
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
                if (client_pool[i].socket == fd)
                {
                        return &client_pool[i];
                }
        }

        return NULL;
}


static int do_echo(echo_server* server, echo_client* client, int event)
{
        int ret = 0;

        if (event & POLLIN)
        {
                ret = 1;
                while (ret > 0)
                {
                        /* Receive data from the peer */
                        if (client->tls_session != NULL)
                        {
                                ret = asl_receive(client->tls_session, client->recv_buffer, sizeof(client->recv_buffer));
                                if (ret == ASL_CONN_CLOSED)
                                        ret = 0;
                        }
                        else
                        {
                                ret = recv(client->socket, client->recv_buffer, sizeof(client->recv_buffer), 0);

                                if ((ret == -1) &&
                        #if defined(_WIN32)
                                        (WSAGetLastError() == WSAEWOULDBLOCK))
                        #else
                                        ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
                        #endif
                                {
                                        ret = ASL_WANT_READ;
                                }
                        }

                        if (ret > 0)
                        {
                                client->num_of_bytes_in_recv_buffer = ret;

                                /* Echo data back */
                                if (client->tls_session != NULL)
                                {
                                        ret = asl_send(client->tls_session, client->recv_buffer,
                                                client->num_of_bytes_in_recv_buffer);

                                        if (ret == ASL_WANT_WRITE)
                                        {
                                                /* We have to wait for the socket to be writable */
                                                poll_set_update_events(&server->poll_set, client->socket, POLLOUT);
                                                ret = 0;
                                        }
                                        else if (ret != ASL_SUCCESS)
                                                ret = -1;
                                        else
                                                ret = client->num_of_bytes_in_recv_buffer;
                                }
                                else
                                {
                                        ret = send(client->socket,
                                                client->recv_buffer,
                                                client->num_of_bytes_in_recv_buffer,
                                                0);

                                        if ((ret == -1) &&
                                        #if defined(_WIN32)
                                                (WSAGetLastError() == WSAEWOULDBLOCK))
                                        #else
                                                ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
                                        #endif
                                        {
                                                /* We have to wait for the socket to be writable */
                                                poll_set_update_events(&server->poll_set, client->socket, POLLOUT);
                                                ret = 0;
                                        }
                                }

                                if ((size_t)ret == sizeof(client->recv_buffer))
                                {
                                        /* We read the maximum amount of data from the socket. This could be
                                         * an indication that there is more data to be read. Hence, we trigger
                                         * another read here. */
                                        ret = 1;
                                }
                                else if (ret  == client->num_of_bytes_in_recv_buffer)
                                {
                                        client->num_of_bytes_in_recv_buffer = 0;
                                        ret = 0;
                                }
                        }
                        else if (ret == ASL_WANT_READ)
                        {
                                /* We have to wait for more data from the peer */
                                ret = 0;

                        }
                        else if (ret == 0)
                        {
                                /* Connection closed */
                                LOG_INFO("TCP connection closed by peer");
                                ret = -1;
                        }
                }
        }
        if (event & POLLOUT)
        {
                /* Echo received data to the other socket */
                if (client->tls_session != NULL)
                {
                        ret = asl_send(client->tls_session, client->recv_buffer,
                                       client->num_of_bytes_in_recv_buffer);
                        if (ret == ASL_SUCCESS)
                        {
                                /* Wait again for incoming data */
                                poll_set_update_events(&server->poll_set, client->socket, POLLIN);
                        }
                        else if (ret != ASL_WANT_WRITE)
                        {
                                ret = -1;
                        }
                }
                else
                {
                        ret = send(client->socket,
                                   client->recv_buffer,
                                   client->num_of_bytes_in_recv_buffer,
                                   0);

                        if (ret >= 0)
                        {
                                /* Wait again for incoming data */
                                poll_set_update_events(&server->poll_set, client->socket, POLLIN);
                        }
                }
        }

        return ret;
}


static void client_cleanup(echo_client* client)
{
        if (client->tls_session != NULL)
        {
                asl_free_session(client->tls_session);
                client->tls_session = NULL;
        }

        if (client->socket > 0)
        {
                poll_set_remove_fd(&the_server.poll_set, client->socket);
                closesocket(client->socket);
                client->socket = -1;
        }

        if (client->in_use == true)
        {
                client->num_of_bytes_in_recv_buffer = 0;
                client->in_use = false;
        }

        if (the_server.num_clients > 0)
                the_server.num_clients -= 1;

        client->slot = -1;
        client->handshake_done = false;
}


static int send_management_message(int socket, echo_server_management_message const* msg)
{
        int ret = 0;
        static const int max_retries = 5;
        int retries = 0;

        while ((ret <= 0) && (retries < max_retries))
        {
                ret = send(socket, (char const*) msg, sizeof(echo_server_management_message), 0);
                if (ret < 0)
                {
                        if (errno != EAGAIN)
                        {
                                LOG_ERROR("Error sending message: %d (%s)", errno, strerror(errno));
                                return -1;
                        }

                        usleep(10 * 1000);
                }
                else if (ret != sizeof(echo_server_management_message))
                {
                        LOG_ERROR("Sent invalid message");
                        return -1;
                }

                retries++;
        }

        if (retries >= max_retries)
        {
                LOG_ERROR("Failed to send message after %d retries", max_retries);
                return -1;
        }

        return 0;
}


static int read_management_message(int socket, echo_server_management_message* msg)
{
        int ret = recv(socket, (char*) msg, sizeof(echo_server_management_message), 0);
        if (ret < 0)
        {
                LOG_ERROR("Error receiving message: %d (%s)", errno, strerror(errno));
                return -1;
        }
        else if (ret != sizeof(echo_server_management_message))
        {
                LOG_ERROR("Received invalid response (ret=%d; expected=%lu)", ret, sizeof(echo_server_management_message));
                return -1;
        }

        return 0;
}


/* Handle incoming management messages.
 *
 * Return 0 in case the message has been processed successfully, -1 otherwise. In case the connection thread has
 * to be stopped and the connection has to be cleaned up, +1 in returned.
 */
static int handle_management_message(echo_server* server, int socket)
{
        /* Read message from the management socket. */
        echo_server_management_message msg = {0};
        int ret = read_management_message(socket, &msg);
        if (ret < 0)
        {
                LOG_ERROR("Error reading management message: %d", ret);
                return -1;
        }

        switch (msg.type)
        {
                case MANAGEMENT_MSG_STATUS_REQUEST:
                {
                        /* Fill status object */
                        echo_server_status* status = msg.payload.status_ptr;
                        status->is_running = server->running;
                        status->listening_port_v4 = server->listening_port[IPv4];
                        status->listening_port_v6 = server->listening_port[IPv6];
                        status->num_connections = server->num_clients;

                        /* Send response */
                        msg.type = MANAGEMENT_RESPONSE;
                        msg.payload.response_code = 0;
                        ret = send_management_message(socket, &msg);
                        break;
                }
                case MANAGEMENT_MSG_SHUTDOWN:
                {
                        /* Return 1 to indicate we have to stop the connection thread and cleanup */
                        ret = 1;

                        /* Send response */
                        msg.type = MANAGEMENT_RESPONSE;
                        msg.payload.response_code = 0;

                        /* Do not update ret here to make sure the thread terminates */
                        send_management_message(socket, &msg);

                        LOG_DEBUG("Received shutdown message, stopping server");
                        break;
                }
                default:
                        LOG_ERROR("Received invalid management message: msg->type=%d", msg.type);
                        ret = -1;
                        break;
        }

        return ret;
}


static void echo_server_cleanup(echo_server* server)
{
        /* Stop all running client connections */
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
                client_cleanup(&client_pool[i]);
        }

        /* Stop the listening sockets */
        if (server->server_socket[IPv4] > 0)
        {
                closesocket(server->server_socket[IPv4]);
                server->server_socket[IPv4] = -1;
        }
        if (server->server_socket[IPv6] > 0)
        {
                closesocket(server->server_socket[IPv6]);
                server->server_socket[IPv6] = -1;
        }

        /* Clean the TLS endpoint */
        if ((server->use_tls == true) && (server->tls_endpoint != NULL))
        {
                asl_free_endpoint(server->tls_endpoint);
                asl_cleanup();
                server->tls_endpoint = NULL;
        }

        /* Close the management socket pair */
        if (server->management_socket_pair[0] != -1)
        {
                int sock = server->management_socket_pair[0];
                server->management_socket_pair[0] = -1;
                closesocket(sock);
        }
        if (server->management_socket_pair[1] != -1)
        {
                int sock = server->management_socket_pair[1];
                server->management_socket_pair[1] = -1;
                closesocket(sock);
        }


        server->running = false;
}


/* Create the default config for the echo server */
echo_server_config echo_server_default_config(void)
{
        echo_server_config default_config = {0};

        default_config.own_ip_address = NULL;
        default_config.listening_port = 0; /* 0 selects random available port */
        default_config.log_level = LOG_LVL_WARN;
        default_config.use_tls = false;
        default_config.tls_config = asl_default_endpoint_config();

        return default_config;
}


/* Start a new thread and run the echo server.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int echo_server_run(echo_server_config const* config)
{
        /* Set the log level */
        LOG_LVL_SET(config->log_level);

        if (the_server.running == true)
        {
                LOG_ERROR("TCP echo server is already running , killing it");
                echo_server_terminate();
        }

        /* Create the socket pair for external management */
        int ret = create_socketpair(the_server.management_socket_pair);
        if (ret < 0)
                ERROR_OUT("Error creating socket pair for management: %d (%s)", errno, strerror(errno));

        LOG_DEBUG("Created management socket pair (%d, %d)", the_server.management_socket_pair[0],
                                                             the_server.management_socket_pair[1]);

        /* Init main backend */
        pthread_attr_init(&the_server.thread_attr);
        pthread_attr_setdetachstate(&the_server.thread_attr, PTHREAD_CREATE_JOINABLE);

#if defined(__ZEPHYR__)
        /* We have to properly set the attributes with the stack to use for Zephyr. */
        pthread_attr_setstack(&the_server.thread_attr, echo_server_stack, K_THREAD_STACK_SIZEOF(echo_server_stack));
#endif

        /* Create the new thread */
        ret = pthread_create(&the_server.thread, &the_server.thread_attr, echo_server_main_thread, &the_server);
        if (ret != 0)
                ERROR_OUT("Error starting TCP echo server thread: %s", strerror(ret));

        /* Create a START message */
        echo_server_management_message msg = {0};
        msg.type = MANAGEMENT_MSG_START;
        msg.payload.config = *config;

        /* Send request */
        ret = send_management_message(the_server.management_socket_pair[0], &msg);
        if (ret < 0)
                ERROR_OUT("Error sending management message");

        /* Wait for response */
        ret = read_management_message(the_server.management_socket_pair[0], &msg);
        if (ret != 0)
        {
                ERROR_OUT("Error reading management response");
        }
        else if (msg.type != MANAGEMENT_RESPONSE)
        {
                ERROR_OUT("Received invalid response");
        }
        else if (msg.payload.response_code < 0)
        {
                ERROR_OUT("Error starting echo server (error %d)", msg.payload.response_code);
        }

        LOG_DEBUG("TCP echo server main thread started");

        return msg.payload.response_code;


cleanup:
        echo_server_cleanup(&the_server);
        return -1;
}


/* Querry status information from the echo server.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int echo_server_get_status(echo_server_status* status)
{
        if ((the_server.management_socket_pair[0] < 0) ||
            (the_server.management_socket_pair[1] < 0))
        {
                LOG_INFO("TCP echo server is not running");
                return 0;
        }

        /* Create the STATUS_REQUEST message. Object is used for the response, too. */
        echo_server_management_message message = {0};
        message.type = MANAGEMENT_MSG_STATUS_REQUEST;
        message.payload.status_ptr = status;

        /* Send request */
        int ret = send_management_message(the_server.management_socket_pair[0], &message);
        if (ret < 0)
        {
                return -1;
        }

        /* Wait for response */
        ret = read_management_message(the_server.management_socket_pair[0], &message);
        if (ret < 0)
        {
                return -1;
        }
        else if (message.type != MANAGEMENT_RESPONSE)
        {
                LOG_ERROR("Received invalid response");
                return -1;
        }
        else if (message.payload.response_code < 0)
        {
                LOG_ERROR("Error obtaining status (error %d)", message.payload.response_code);
                return -1;
        }

        return 0;
}


/* Terminate the echo server.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int echo_server_terminate(void)
{
        if ((the_server.running == false) ||
            (the_server.management_socket_pair[0] < 0) ||
            (the_server.management_socket_pair[1] < 0))
        {
                LOG_DEBUG("TCP echo server is not running");
                return 0;
        }

        /* Send shutdown message to the management socket */
        echo_server_management_message msg = {0};
        msg.type = MANAGEMENT_MSG_SHUTDOWN;
        msg.payload.dummy_unused = 0;

        /* Send request */
        int ret = send_management_message(the_server.management_socket_pair[0], &msg);
        if (ret < 0)
        {
                return -1;
        }

        /* Wait for response */
        ret = read_management_message(the_server.management_socket_pair[0], &msg);
        if (ret < 0)
        {
                return -1;
        }
        else if (msg.type != MANAGEMENT_RESPONSE)
        {
                LOG_ERROR("Received invalid response");
                return -1;
        }
        else if (msg.payload.response_code < 0)
        {
                LOG_ERROR("Error stopping backend (error %d)", msg.payload.response_code);
                return -1;
        }

        /* Wait until the main thread is terminated */
        pthread_join(the_server.thread, NULL);

        return 0;
}
