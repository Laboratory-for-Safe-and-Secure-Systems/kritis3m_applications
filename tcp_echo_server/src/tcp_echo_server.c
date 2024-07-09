#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "tcp_echo_server.h"

#include "logging.h"
#include "poll_set.h"
#include "networking.h"


LOG_MODULE_CREATE(tcp_echo_server);


#define MAX_CLIENTS 5
#define RECV_BUFFER_SIZE 1024


typedef struct tcp_echo_server
{
	bool running;
        int tcp_server_socket;
	uint16_t listening_port;
	pthread_t thread;
	pthread_attr_t thread_attr;
	struct poll_set poll_set;
}
tcp_echo_server;

typedef struct echo_client
{
        bool in_use;
        int socket;
        size_t num_of_bytes_in_recv_buffer;
        uint8_t recv_buffer[RECV_BUFFER_SIZE];
}
echo_client;


/* File global variables */
static tcp_echo_server echo_server = {
	.running = false,
	.tcp_server_socket = -1,
	.listening_port = 0,
};
static echo_client client_pool[MAX_CLIENTS];

#if defined(__ZEPHYR__)
#define STACK_SIZE 8*1024

Z_KERNEL_STACK_DEFINE_IN(echo_server_stack, STACK_SIZE, \
		__attribute__((section(CONFIG_RAM_SECTION_STACKS_1))));
#endif


/* Internal method declarations */
static void* tcp_echo_server_main_thread(void* ptr);
static echo_client* add_new_client(int client_socket, struct sockaddr* client_addr);
static echo_client* find_client_by_fd(int fd);
static void client_cleanup(echo_client* client);


static void* tcp_echo_server_main_thread(void* ptr)
{
	tcp_echo_server* server = (tcp_echo_server*) ptr;

	server->running = true;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	while (1)
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

                        /* Check server fd */
			if (fd == server->tcp_server_socket)
			{
				if (event & POLLIN)
				{
					/* New client connection, try to handle it */
					int client_socket = accept(server->tcp_server_socket, &client_addr, &client_addr_len);
					if (client_socket < 0)
					{
						int error = errno;
						if (error != EAGAIN)
							LOG_ERROR("accept error: %d (fd=%d)", error, server->tcp_server_socket);
						continue;
					}

					/* Handle new client */
					client = add_new_client(client_socket,
								&client_addr);
					if (client == NULL)
					{
						LOG_ERROR("Error adding new client");
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
                                if (event & POLLIN)
				{
					/* Receive data from the peer */
					ret = read(fd, client->recv_buffer, sizeof(client->recv_buffer));

					if (ret > 0)
					{
						client->num_of_bytes_in_recv_buffer = ret;

                                                /* Echo data back */
                                                ret = send(fd,
							   client->recv_buffer,
							   client->num_of_bytes_in_recv_buffer,
							   0);

						if ((ret == -1) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
						{
							/* We have to wait for the socket to be writable */
							poll_set_update_events(&server->poll_set, fd, POLLOUT);
							ret = 0;
						}
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
						   client->recv_buffer,
						   client->num_of_bytes_in_recv_buffer,
						   0);

					if (ret >= 0)
					{
						/* Wait again for incoming data */
						poll_set_update_events(&server->poll_set, fd, POLLIN);
					}
				}

				if (ret < 0)
				{
					/* Error, close session */
					client_cleanup(client);
					break;
				}
			}
			else
			{
				LOG_ERROR("Received event for unknown fd %d", fd);
			}
		}
	}

	server->running = false;

	return NULL;
}

static echo_client* add_new_client(int client_socket,
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

        echo_client* client = &client_pool[freeSlot];

	/* Store new client data */
	client->in_use = true;
        client->num_of_bytes_in_recv_buffer = 0;
        client->socket = client_socket;

	setblocking(client->socket, false);

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

static void client_cleanup(echo_client* client)
{
        if (client->socket > 0)
        {
                poll_set_remove_fd(&echo_server.poll_set, client->socket);
                close(client->socket);
                client->socket = -1;
        }
        if (client->in_use == true)
        {
                client->num_of_bytes_in_recv_buffer = 0;
                client->in_use = false;
        }
}


/* Start a new thread and run the TCP echo server.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_echo_server_run(tcp_echo_server_config const* config)
{
	if (echo_server.running == true)
	{
		if (config->listening_port != echo_server.listening_port)
		{
			LOG_ERROR("TCP echo server is already running on port %d, killing it", echo_server.listening_port);
			tcp_echo_server_terminate();
		}
		else
		{
			LOG_INFO("TCP echo server is already running on port %d", echo_server.listening_port);
			return 0;
		}
	}

        /* Init client pool */
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		client_pool[i].in_use = false;
		client_pool[i].socket = -1;
		client_pool[i].num_of_bytes_in_recv_buffer = 0;
	}

        poll_set_init(&echo_server.poll_set);

        /* Create the TCP socket for the incoming connection */
	echo_server.tcp_server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (echo_server.tcp_server_socket == -1)
	{
		LOG_ERROR("Error creating incoming TCP socket");
		return -1;
	}

        if (setsockopt(echo_server.tcp_server_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
        {
                LOG_ERROR("setsockopt(SO_REUSEADDR) failed: error %d\n", errno);
		close(echo_server.tcp_server_socket);
		return -1;
        }

	/* Configure TCP server */
	echo_server.listening_port = config->listening_port;
	struct sockaddr_in bind_addr = {
			.sin_family = AF_INET,
			.sin_port = htons(config->listening_port)
	};
	net_addr_pton(bind_addr.sin_family, config->own_ip_address, &bind_addr.sin_addr);

	/* Bind server socket to its destined IPv4 address */
	if (bind(echo_server.tcp_server_socket, (struct sockaddr*) &bind_addr, sizeof(bind_addr)) == -1)
	{
		LOG_ERROR("Cannot bind socket %d to %s:%d: error %d\n",
                        echo_server.tcp_server_socket, config->own_ip_address, config->listening_port, errno);
		close(echo_server.tcp_server_socket);
		return -1;
	}

	/* Start listening for incoming connections */
	listen(echo_server.tcp_server_socket, MAX_CLIENTS);

	/* Set the new socket to non-blocking */
	setblocking(echo_server.tcp_server_socket, false);

	/* Add new server to the poll_set */
	int ret = poll_set_add_fd(&echo_server.poll_set, echo_server.tcp_server_socket, POLLIN);
	if (ret != 0)
	{
		LOG_ERROR("Error adding socket to poll_set");
		close(echo_server.tcp_server_socket);
		return -1;
	}

        /* Init main backend */
	pthread_attr_init(&echo_server.thread_attr);
	pthread_attr_setdetachstate(&echo_server.thread_attr, PTHREAD_CREATE_DETACHED);

#if defined(__ZEPHYR__)
	/* We have to properly set the attributes with the stack to use for Zephyr. */
	pthread_attr_setstack(&echo_server.thread_attr, echo_server_stack, K_THREAD_STACK_SIZEOF(echo_server_stack));
#endif

        /* Create the new thread */
	ret = pthread_create(&echo_server.thread, &echo_server.thread_attr, tcp_echo_server_main_thread, &echo_server);
	if (ret == 0)
	{
		LOG_INFO("TCP echo server main thread started");
	}
	else
	{
		LOG_ERROR("Error starting TCP echo server thread: %s", strerror(ret));
	}

	return ret;
}


/* Terminate the echo server.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_echo_server_terminate(void)
{
	if (echo_server.running == false)
	{
		LOG_INFO("TCP echo server is not running");
		return 0;
	}

	/* Stop the main thread */
	pthread_cancel(echo_server.thread);

	/* Stop all running client connections */
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
                client_cleanup(&client_pool[i]);
	}

	/* Stop the listening socket */
	if (echo_server.tcp_server_socket > 0)
	{
		close(echo_server.tcp_server_socket);
		echo_server.tcp_server_socket = -1;
	}

	return 0;
}
