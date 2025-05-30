#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

#include "tcp_client_stdin_bridge.h"

#include "logging.h"
#include "networking.h"
#include "poll_set.h"
#include "threading.h"

LOG_MODULE_CREATE(tcp_client_stdin_bridge);

#define ERROR_OUT(...)                                                                             \
        {                                                                                          \
                LOG_ERROR(__VA_ARGS__);                                                            \
                goto cleanup;                                                                      \
        }

#if !defined(__ZEPHYR__) && !defined(_WIN32)

#define RECV_BUFFER_SIZE 1024

enum tcp_client_stdin_bridge_management_message_type
{
        MANAGEMENT_MSG_STATUS_REQUEST,
        MANAGEMENT_MSG_SHUTDOWN,
        MANAGEMENT_RESPONSE
};

typedef struct tcp_client_stdin_bridge_management_message
{
        enum tcp_client_stdin_bridge_management_message_type type;

        union
        {
                tcp_client_stdin_bridge_status* status_ptr; /* STATUS_REQUEST */
                int dummy_unused;                           /* SHUTDOWN */
                int response_code;                          /* RESPONSE */
        } payload;
} tcp_client_stdin_bridge_management_message;

typedef struct tcp_client_stdin_bridge
{
        bool running;
        int tcp_socket;
        struct addrinfo* target_addr;
        thread_info thread;
        poll_set poll_set;
        int management_socket_pair[2];
        size_t num_of_bytes_in_recv_buffer;
        uint8_t recv_buffer[RECV_BUFFER_SIZE];
} tcp_client_stdin_bridge;

/* File global variables */
static tcp_client_stdin_bridge client_stdin_bridge = {
        .running = false,
        .tcp_socket = -1,
        .management_socket_pair = {-1, -1},
        .num_of_bytes_in_recv_buffer = 0,
};

/* Internal method declarations */
static void* tcp_client_stdin_bridge_main_thread(void* ptr);
static int send_management_message(int socket, tcp_client_stdin_bridge_management_message const* msg);
static int read_management_message(int socket, tcp_client_stdin_bridge_management_message* msg);
static int handle_management_message(tcp_client_stdin_bridge* bridge, int socket);
static void bridge_cleanup(tcp_client_stdin_bridge* bridge);

static void* tcp_client_stdin_bridge_main_thread(void* ptr)
{
        tcp_client_stdin_bridge* bridge = (tcp_client_stdin_bridge*) ptr;
        bool shutdown = false;

        bridge->running = true;

        /* Set the management socket to non-blocking and add it to the poll_set */
        setblocking(bridge->management_socket_pair[1], false);
        poll_set_add_fd(&bridge->poll_set, bridge->management_socket_pair[1], POLLIN);

        while (!shutdown)
        {
                /* Block and wait for incoming events (new connections, received data, ...) */
                int ret = poll(bridge->poll_set.fds, bridge->poll_set.num_fds, -1);

                if (ret == -1)
                {
                        LOG_ERROR("poll error: %d", errno);
                        continue;
                }

                /* Check which fds created an event */
                for (int i = 0; i < bridge->poll_set.num_fds; i++)
                {
                        int fd = bridge->poll_set.fds[i].fd;
                        short event = bridge->poll_set.fds[i].revents;

                        if (event == 0)
                                continue;

                        /* Check management socket */
                        if (fd == bridge->management_socket_pair[1])
                        {
                                if (event & POLLIN)
                                {
                                        /* Handle the message */
                                        ret = handle_management_message(bridge, fd);
                                        if (ret == 1)
                                        {
                                                shutdown = true;
                                                break;
                                        }
                                }
                        }
                        /* Check tcp client fd */
                        else if (fd == bridge->tcp_socket)
                        {
                                if (event & POLLIN)
                                {
                                        /* Receive data from the peer */
                                        ret = read(fd, bridge->recv_buffer, sizeof(bridge->recv_buffer));

                                        if (ret > 0)
                                        {
                                                bridge->num_of_bytes_in_recv_buffer = ret;

                                                /* Print data */
                                                ret = write(STDIN_FILENO,
                                                            bridge->recv_buffer,
                                                            bridge->num_of_bytes_in_recv_buffer);
                                        }
                                        else if (ret == 0)
                                        {
                                                /* Connection closed */
                                                LOG_INFO("TCP connection closed by peer");
                                                ret = -1;
                                        }
                                }
                                if (event & POLLOUT)
                                {
                                        /* Echo received data to the other socket */
                                        ret = send(fd,
                                                   bridge->recv_buffer,
                                                   bridge->num_of_bytes_in_recv_buffer,
                                                   0);

                                        if (ret >= 0)
                                        {
                                                /* Wait again for incoming data */
                                                poll_set_update_events(&bridge->poll_set, fd, POLLIN);
                                        }
                                }

                                if (ret < 0)
                                {
                                        /* Error, close session */
                                        shutdown = true;
                                        break;
                                }
                        }
                        /* Check stdin */
                        else if (fd == STDIN_FILENO)
                        {
                                if (event & POLLIN)
                                {
                                        /* Receive data from stdin */
                                        ret = read(fd, bridge->recv_buffer, sizeof(bridge->recv_buffer));

                                        if (ret > 0)
                                        {
                                                bridge->num_of_bytes_in_recv_buffer = ret;

                                                /* Echo data back */
                                                ret = send(bridge->tcp_socket,
                                                           bridge->recv_buffer,
                                                           bridge->num_of_bytes_in_recv_buffer,
                                                           0);

                                                if ((ret == -1) &&
                                                    ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
                                                {
                                                        /* We have to wait for the socket to be writable */
                                                        poll_set_update_events(&bridge->poll_set,
                                                                               bridge->tcp_socket,
                                                                               POLLOUT);
                                                        ret = 0;
                                                }
                                        }
                                        else if (ret < 0)
                                        {
                                                LOG_ERROR("Error reading from stdin: %d (%s)",
                                                          errno,
                                                          strerror(errno));
                                        }
                                }
                        }
                        else
                        {
                                LOG_ERROR("Received event for unknown fd %d", fd);
                        }
                }
        }

        /* Cleanup */
        bridge_cleanup(bridge);
        terminate_thread(&bridge->thread, LOG_MODULE_GET());
}

static int send_management_message(int socket, tcp_client_stdin_bridge_management_message const* msg)
{
        int ret = 0;
        static const int max_retries = 5;
        int retries = 0;

        while ((ret <= 0) && (retries < max_retries))
        {
                ret = send(socket, (char*) msg, sizeof(tcp_client_stdin_bridge_management_message), 0);
                if (ret < 0)
                {
                        if (errno != EAGAIN)
                        {
                                LOG_ERROR("Error sending message: %d (%s)", errno, strerror(errno));
                                return -1;
                        }

                        usleep(10 * 1000);
                }
                else if (ret != sizeof(tcp_client_stdin_bridge_management_message))
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

static int read_management_message(int socket, tcp_client_stdin_bridge_management_message* msg)
{
        int ret = recv(socket, (char*) msg, sizeof(tcp_client_stdin_bridge_management_message), 0);
        if (ret < 0)
        {
                LOG_ERROR("Error receiving message: %d (%s)", errno, strerror(errno));
                return -1;
        }
        else if (ret != sizeof(tcp_client_stdin_bridge_management_message))
        {
                LOG_ERROR("Received invalid response (ret=%d; expected=%lu)",
                          ret,
                          sizeof(tcp_client_stdin_bridge_management_message));
                return -1;
        }

        return 0;
}

/* Handle incoming management messages.
 *
 * Return 0 in case the message has been processed successfully, -1 otherwise. In case the
 * connection thread has to be stopped and the connection has to be cleaned up, +1 in returned.
 */
static int handle_management_message(tcp_client_stdin_bridge* bridge, int socket)
{
        /* Read message from the management socket. */
        tcp_client_stdin_bridge_management_message msg = {0};
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
                        tcp_client_stdin_bridge_status* status = msg.payload.status_ptr;
                        status->is_running = bridge->running;

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

static void bridge_cleanup(tcp_client_stdin_bridge* bridge)
{
        /* Close the TCP socket */
        if (bridge->tcp_socket != -1)
        {
                closesocket(bridge->tcp_socket);
                bridge->tcp_socket = -1;
        }

        /* Close the management socket pair */
        if (bridge->management_socket_pair[0] != -1)
        {
                int sock = bridge->management_socket_pair[0];
                bridge->management_socket_pair[0] = -1;
                closesocket(sock);
        }
        if (bridge->management_socket_pair[1] != -1)
        {
                int sock = bridge->management_socket_pair[1];
                bridge->management_socket_pair[1] = -1;
                closesocket(sock);
        }

        if (bridge->target_addr != NULL)
        {
                freeaddrinfo(bridge->target_addr);
                bridge->target_addr = NULL;
        }

        bridge->running = false;
}

#endif // !defined(__ZEPHYR__)

/* Create the default config for the TCP client stdin bridge */
tcp_client_stdin_bridge_config tcp_client_stdin_bridge_default_config(void)
{
        tcp_client_stdin_bridge_config default_config = {0};

        default_config.target_ip_address = NULL;
        default_config.target_port = 0;
        default_config.log_level = LOG_LVL_WARN;

        return default_config;
}

/* Start a new thread and run the TCP client stdin bridge application.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_client_stdin_bridge_run(tcp_client_stdin_bridge_config const* config)
{
        /* Set the log level */
        LOG_LVL_SET(config->log_level);

#if defined(__ZEPHYR__) || defined(_WIN32)
        LOG_ERROR("TCP client stdin bridge not supported on Zephyr");
        return -1;
#else
        /* Init */
        poll_set_init(&client_stdin_bridge.poll_set);
        client_stdin_bridge.num_of_bytes_in_recv_buffer = 0;
        client_stdin_bridge.target_addr = NULL;

        /* Create the socket pair for external management */
        int ret = create_socketpair(client_stdin_bridge.management_socket_pair);
        if (ret < 0)
                ERROR_OUT("Error creating socket pair for management: %d (%s)", errno, strerror(errno));

        LOG_DEBUG("Created management socket pair (%d, %d)",
                  client_stdin_bridge.management_socket_pair[0],
                  client_stdin_bridge.management_socket_pair[1]);

        LOG_INFO("Connecting to %s:%d", config->target_ip_address, config->target_port);

        /* Do a DNS lookup to make sure we have an IP address. If we already have an IP, this
         * results in a noop. */
        if (address_lookup_client(config->target_ip_address,
                                  config->target_port,
                                  &client_stdin_bridge.target_addr,
                                  AF_UNSPEC) < 0)
                ERROR_OUT("Error looking up target IP address");

        /* Create the TCP socket for the outgoing connection */
        client_stdin_bridge.tcp_socket = create_client_socket(
                client_stdin_bridge.target_addr->ai_family);
        if (client_stdin_bridge.tcp_socket == -1)
                ERROR_OUT("Error creating TCP socket");

        /* Set the new socket to non-blocking */
        setblocking(client_stdin_bridge.tcp_socket, false);

        /* Connect to the peer */
        ret = connect(client_stdin_bridge.tcp_socket,
                      (struct sockaddr*) client_stdin_bridge.target_addr->ai_addr,
                      client_stdin_bridge.target_addr->ai_addrlen);
        if ((ret != 0) &&
#if defined(_WIN32)
            (WSAGetLastError() != WSAEWOULDBLOCK))
#else
            (errno != EINPROGRESS))
#endif
                ERROR_OUT("Unable to connect to target peer, errno: %d", errno);

        /* Add new server to the poll_set */
        ret = poll_set_add_fd(&client_stdin_bridge.poll_set, client_stdin_bridge.tcp_socket, POLLOUT);
        if (ret != 0)
                ERROR_OUT("Error adding TCP client to poll_set");

        /* Add stdin to the poll_set */
        ret = poll_set_add_fd(&client_stdin_bridge.poll_set, STDIN_FILENO, POLLIN);
        if (ret != 0)
                ERROR_OUT("Error adding stdin to poll_set");

        /* Create the new thread */
        thread_attibutes attr = {0};
        attr.function = tcp_client_stdin_bridge_main_thread;
        attr.argument = &client_stdin_bridge;
        ret = start_thread(&client_stdin_bridge.thread, &attr);
        if (ret != 0)
                ERROR_OUT("Error starting TCP client stdin bridge thread: %s", strerror(ret));

        LOG_INFO("TCP client stdin bridge main thread started");

        return ret;

cleanup:
        bridge_cleanup(&client_stdin_bridge);
        return -1;
#endif
}

/* Querry status information from the TCP STDIN bridge.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_client_stdin_bridge_get_status(tcp_client_stdin_bridge_status* status)
{
#if defined(__ZEPHYR__) || defined(_WIN32)
        LOG_ERROR("TCP client stdin bridge not supported on Zephyr");
        return -1;
#else
        if ((client_stdin_bridge.management_socket_pair[0] < 0) ||
            (client_stdin_bridge.management_socket_pair[0] < 0))
        {
                LOG_DEBUG("Bridge thread not running");
                return -1;
        }

        /* Create the STATUS_REQUEST message. Object is used for the response, too. */
        tcp_client_stdin_bridge_management_message message = {0};
        message.type = MANAGEMENT_MSG_STATUS_REQUEST;
        message.payload.status_ptr = status;

        /* Send request */
        int ret = send_management_message(client_stdin_bridge.management_socket_pair[0], &message);
        if (ret < 0)
        {
                return -1;
        }

        /* Wait for response */
        ret = read_management_message(client_stdin_bridge.management_socket_pair[0], &message);
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
#endif
}

/* Terminate the tcp_client_stdin_bridge application.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_client_stdin_bridge_terminate(void)
{
#if defined(__ZEPHYR__) || defined(_WIN32)
        LOG_ERROR("TCP client stdin bridge not supported on Zephyr");
        return -1;
#else
        if ((client_stdin_bridge.management_socket_pair[0] > 0) &&
            (client_stdin_bridge.management_socket_pair[1] > 0))
        {
                /* Send shutdown message to the management socket */
                tcp_client_stdin_bridge_management_message msg = {0};
                msg.type = MANAGEMENT_MSG_SHUTDOWN;
                msg.payload.dummy_unused = 0;

                /* Send request */
                int ret = send_management_message(client_stdin_bridge.management_socket_pair[0], &msg);
                if (ret < 0)
                {
                        return -1;
                }

                /* Wait for response */
                ret = read_management_message(client_stdin_bridge.management_socket_pair[0], &msg);
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
                        LOG_ERROR("Error stopping bridge (error %d)", msg.payload.response_code);
                        return -1;
                }
        }

        /* Wait until the main thread is terminated */
        wait_for_thread(&client_stdin_bridge.thread);

        return 0;
#endif
}
