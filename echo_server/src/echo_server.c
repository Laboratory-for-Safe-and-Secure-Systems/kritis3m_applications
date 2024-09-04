#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "echo_server.h"

#include "logging.h"
#include "poll_set.h"
#include "networking.h"


LOG_MODULE_CREATE(echo_server);


#define ERROR_OUT(...) { LOG_ERROR(__VA_ARGS__); goto cleanup; }


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
        int server_socket;
        uint16_t listening_port;
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
        asl_session* tls_session;
        size_t num_of_bytes_in_recv_buffer;
        uint8_t recv_buffer[RECV_BUFFER_SIZE];
}
echo_client;


/* File global variables */
static echo_server the_server = {
        .running = false,
        .use_tls = false,
        .server_socket = -1,
        .listening_port = 0,
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
static echo_client* add_new_client(echo_server* server, int client_socket, struct sockaddr* client_addr);
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
                ERROR_OUT("Error preparing server");

        /* Set the management socket to non-blocking and add it to the poll_set */
        setblocking(server->management_socket_pair[1], false);
        poll_set_add_fd(&server->poll_set, server->management_socket_pair[1], POLLIN);

        /* Send response */
        start_msg.type = MANAGEMENT_RESPONSE;
        start_msg.payload.response_code = 0;
        ret = send_management_message(server->management_socket_pair[1], &start_msg);
        if (ret < 0)
        {
                ERROR_OUT("Error sending response");
        }

        while (!shutdown)
        {
                struct sockaddr client_addr;
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
                        else if (fd == server->server_socket)
                        {
                                if (event & POLLIN)
                                {
                                        /* New client connection, try to handle it */
                                        int client_socket = accept(server->server_socket, &client_addr, &client_addr_len);
                                        if (client_socket < 0)
                                        {
                                                int error = errno;
                                                if (error != EAGAIN)
                                                        LOG_ERROR("accept error: %d (fd=%d)", error, server->server_socket);
                                                continue;
                                        }

                                        /* Handle new client */
                                        client = add_new_client(server, client_socket,
                                                                &client_addr);
                                        if (client == NULL)
                                        {
                                                LOG_ERROR("Error adding new client");
                                                close(client_socket);
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

                                                LOG_INFO("Handshake done\r\n\tDuration: %.3f milliseconds\r\n\tTx bytes: "\
                                                        "%d\r\n\tRx bytes: %d", metrics.duration_us / 1000.0,
                                                        metrics.tx_bytes, metrics.rx_bytes);
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

        /* Init client pool */
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
                client_pool[i].in_use = false;
                client_pool[i].handshake_done = false;
                client_pool[i].socket = -1;
                client_pool[i].tls_session = NULL;
                client_pool[i].num_of_bytes_in_recv_buffer = 0;
        }

        poll_set_init(&server->poll_set);

        /* Initialize the Agile Security Library */
        if (config->use_tls == true)
        {
                LOG_DEBUG("Initializing ASL");

                asl_configuration asl_config = {
                        .logging_enabled = true,
                        .log_level = LOG_LVL_GET(),
                        .custom_log_callback = asl_log_callback,
                };
                ret = asl_init(&asl_config);
                if (ret != ASL_SUCCESS)
                        ERROR_OUT("Error initializing ASL: %d (%s)", ret, asl_error_message(ret));
        }

        /* Create the TCP socket for the incoming connection */
        server->server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server->server_socket == -1)
                ERROR_OUT("Error creating incoming TCP socket");

        if (setsockopt(server->server_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
                ERROR_OUT("setsockopt(SO_REUSEADDR) failed: error %d\n", errno);

        /* Configure TCP server */
        server->listening_port = config->listening_port;
        struct sockaddr_in bind_addr = {
                        .sin_family = AF_INET,
                        .sin_port = htons(config->listening_port)
        };
        net_addr_pton(bind_addr.sin_family, config->own_ip_address, &bind_addr.sin_addr);

        /* Bind server socket to its destined IPv4 address */
        if (bind(server->server_socket, (struct sockaddr*) &bind_addr, sizeof(bind_addr)) == -1)
                ERROR_OUT("Cannot bind socket %d to %s:%d: error %d\n",
                          server->server_socket, config->own_ip_address, config->listening_port, errno);

        /* If a random port have been used, obtain the actually selected one */
        if (config->listening_port == 0)
        {
                socklen_t sockaddr_len = sizeof(bind_addr);
                if (getsockname(server->server_socket, (struct sockaddr*)&bind_addr, &sockaddr_len) < 0)
                        ERROR_OUT("getsockname failed with errno: %d", errno);

                server->listening_port = ntohs(bind_addr.sin_port);
        }

        /* Configure TLS endpoint */
        if (config->use_tls == true)
        {
                LOG_DEBUG("Setting up TLS server endpoint");

                server->tls_endpoint = asl_setup_server_endpoint(&config->tls_config);
                if (server->tls_endpoint == NULL)
                        ERROR_OUT("Error creating TLS endpoint");
        }

        /* Start listening for incoming connections */
        listen(server->server_socket, MAX_CLIENTS);

        /* Set the new socket to non-blocking */
        setblocking(server->server_socket, false);

        /* Add new server to the poll_set */
        ret = poll_set_add_fd(&server->poll_set, server->server_socket, POLLIN);
        if (ret != 0)
                ERROR_OUT("Error adding socket to poll_set");

cleanup:
        return ret;
}


static echo_client* add_new_client(echo_server* server, int client_socket,
                                   struct sockaddr* client_addr)
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

        setblocking(client->socket, false);

        if (setsockopt(client->socket, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0)
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
        struct sockaddr_in* client_data = (struct sockaddr_in*) client_addr;
        char peer_ip[20];
        net_addr_ntop(AF_INET, &client_data->sin_addr, peer_ip, sizeof(peer_ip));
        LOG_INFO("New client connection from %s:%d, using slot %d/%d",
                peer_ip, ntohs(client_data->sin_port),
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
                                ret = read(client->socket, client->recv_buffer, sizeof(client->recv_buffer));

                                if ((ret == -1) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
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

                                        if ((ret == -1) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
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
                close(client->socket);
                client->socket = -1;
        }

        if (client->in_use == true)
        {
                client->num_of_bytes_in_recv_buffer = 0;
                client->in_use = false;
        }

        if (the_server.num_clients > 0)
                the_server.num_clients -= 1;

        client->handshake_done = false;
}


static int send_management_message(int socket, echo_server_management_message const* msg)
{
        int ret = 0;
        static const int max_retries = 5;
        int retries = 0;

        while ((ret <= 0) && (retries < max_retries))
        {
                ret = send(socket, msg, sizeof(echo_server_management_message), 0);
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
        int ret = recv(socket, msg, sizeof(echo_server_management_message), 0);
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
                        status->listening_port = server->listening_port;
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

        /* Stop the listening socket */
        if (server->server_socket > 0)
        {
                close(server->server_socket);
                server->server_socket = -1;
        }

        /* Clean the TLS endpoint */
        if ((server->use_tls == true) && (server->tls_endpoint != NULL))
        {
                asl_free_endpoint(server->tls_endpoint);
                asl_cleanup();
        }

        /* Close the management socket pair */
        if (server->management_socket_pair[0] != -1)
        {
                close(server->management_socket_pair[0]);
                server->management_socket_pair[0] = -1;
        }
        if (server->management_socket_pair[1] != -1)
        {
                close(server->management_socket_pair[1]);
                server->management_socket_pair[1] = -1;
        }

        server->running = false;
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
                if (config->listening_port != the_server.listening_port)
                {
                        LOG_ERROR("TCP echo server is already running on port %d, killing it", the_server.listening_port);
                        echo_server_terminate();
                }
                else
                {
                        LOG_INFO("TCP echo server is already running on port %d", the_server.listening_port);
                        return 0;
                }
        }

        /* Create the socket pair for external management */
        int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, the_server.management_socket_pair);
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
