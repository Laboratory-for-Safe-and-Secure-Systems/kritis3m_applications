
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>

#if defined(__ZEPHYR__)

#else

#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

#endif

#include "tls_echo_server.h"

#include "logging.h"
#include "poll_set.h"
#include "networking.h"
#include "wolfssl.h"


LOG_MODULE_REGISTER(tls_echo_server);


#define RECV_BUFFER_SIZE 1024

#define MAX_SERVERS 3
#define MAX_CLIENTS 5


/* Proper declaration of the client structure */
struct tls_client_config_internal
{
	bool in_use;

	int tcp_sock;
	char peer_ip[20];
	uint16_t peer_port;
	WOLFSSL* wolfssl_session;
	pthread_t thread;
	pthread_attr_t thread_attr;
	uint8_t recv_buffer[RECV_BUFFER_SIZE];
};

struct tls_server_config_internal
{
	bool in_use;
	uint16_t listening_port;
	int tcp_sock;
	WOLFSSL_CTX* wolfssl_contex;
	struct tls_client_config_internal* clients[MAX_CLIENTS];
};

struct tls_echo_server_config
{
	int management_socket_pair[2];
	pthread_t thread;
	pthread_attr_t thread_attr;
	struct poll_set poll_set;
};

enum tls_echo_server_management_message_type
{
	TLS_ECHO_SERVER_START_REQUEST,
	TLS_ECHO_SERVER_STOP_REQUEST,
	TLS_ECHO_SERVER_RESPONSE,
};

struct tls_echo_server_message
{
	enum tls_echo_server_management_message_type type;
	
	union tls_echo_server_management_message_payload
	{
		struct tls_server_config server_config;	/* START_REQUEST */
		int server_id; 				/* STOP_REQUEST */
		int response_code; 			/* RESPONSE */
	} 
	payload;
};


/* File global variables */
static struct tls_echo_server_config echo_server;
static struct tls_client_config_internal client_pool[MAX_CLIENTS];
static struct tls_server_config_internal server_pool[MAX_SERVERS];


#if defined(__ZEPHYR__)
#define CLIENT_HANDLER_STACK_SIZE 32*1024
#define SERVER_STACK_SIZE 128*1024

// K_THREAD_STACK_ARRAY_DEFINE(client_stack_pool, MAX_CLIENTS, CLIENT_HANDLER_STACK_SIZE);
// K_THREAD_STACK_DEFINE(server_stack, SERVER_STACK_SIZE);

Z_KERNEL_STACK_ARRAY_DEFINE_IN(client_stack_pool, MAX_CLIENTS, CLIENT_HANDLER_STACK_SIZE, __attribute__((section("SRAM3"))));
Z_KERNEL_STACK_DEFINE_IN(server_stack, SERVER_STACK_SIZE, __attribute__((section("SRAM3"))));
#endif


/* Internal method declarations */
static void* tls_echo_server_main_thread(void* ptr);
static void* tls_client_handler_thread(void *ptr);

static int send_management_message(int socket, struct tls_echo_server_message const* msg);
static int read_management_message(int socket, struct tls_echo_server_message* msg);
static int handle_management_message(int socket, struct tls_echo_server_message const* msg);

static int add_new_server(struct tls_server_config const* server_config);
static void kill_server(struct tls_server_config_internal* server);

static struct tls_client_config_internal* add_new_client_for_server(struct tls_server_config_internal* server,
								    int client_socket,
								    struct sockaddr* client_addr,
								    socklen_t client_addr_len);
static int perform_client_handshake(struct tls_client_config_internal* client);

static struct tls_server_config_internal* find_server_by_fd(int fd);
static struct tls_client_config_internal* find_client_by_fd(int fd);

static void tls_client_cleanup(struct tls_client_config_internal* client);



static int send_management_message(int socket, struct tls_echo_server_message const* msg)
{
	int ret = send(socket, msg, sizeof(struct tls_echo_server_message), 0);
	if (ret < 0)
	{
		LOG_ERR("Error sending message: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int read_management_message(int socket, struct tls_echo_server_message* msg)
{
	int ret = recv(socket, msg, sizeof(struct tls_echo_server_message), 0);
	if (ret < 0)
	{
		LOG_ERR("Error receiving message: %s", strerror(errno));
		return -1;
	}
	else if (ret != sizeof(struct tls_echo_server_message))
	{
		LOG_ERR("Received invalid response");
		return -1;
	}
	
	return 0;
}

static int handle_management_message(int socket, struct tls_echo_server_message const* msg)
{
	switch (msg->type)
	{
		case TLS_ECHO_SERVER_START_REQUEST:
		{
			/* Add a new server */
			int server_id = add_new_server(&msg->payload.server_config);

			/* Send response */
			struct tls_echo_server_message response = {
				.type = TLS_ECHO_SERVER_RESPONSE,
				.payload.response_code = server_id,
			};
			send_management_message(socket, &response);
			break;
		}
		case TLS_ECHO_SERVER_STOP_REQUEST:
		{
			/* Kill the server */
			if (server_pool[msg->payload.server_id-1].in_use == true)
			{
				kill_server(&server_pool[msg->payload.server_id-1]);

			}
			/* Send response */
			struct tls_echo_server_message response = {
				.type = TLS_ECHO_SERVER_RESPONSE,
				.payload.response_code = 0,
			};
			send_management_message(socket, &response);
			break;
		}
		default:
			LOG_ERR("Received invalid management message");
			break;
	}

	return 0;
}


/* Create a new TLS server and add it to the main event loop */
static int add_new_server(struct tls_server_config const* server_config)
{
	/* Search for a free server slot */
	int freeSlot = -1;
	for (int i = 0; i < MAX_SERVERS; i++)
	{
		if (server_pool[i].in_use == false)
		{
			freeSlot = i;
			break;
		}
	}

	if (freeSlot == -1)
	{
		LOG_ERR("Cannot create more TLS echo servers (no free slot)");
		return -1;
	}

	struct tls_server_config_internal* server = &server_pool[freeSlot];

	server->in_use = true;
	server->listening_port = server_config->listening_port;

	LOG_INF("Starting new TLS echo server on port %d using slot %d/%d", 
		server->listening_port, freeSlot+1, MAX_SERVERS);

	/* Create the wolfssl context */
	server->wolfssl_contex = wolfssl_setup_server_context(&server_config->tls_config); 
	if (server->wolfssl_contex == NULL)
	{
		LOG_ERR("Error creating WolfSSL context");
		kill_server(server);
		return -1;
	}
	
	/* Create the TCP socket */
	server->tcp_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (server->tcp_sock == -1)
	{
		LOG_ERR("Error creating TCP socket");
		kill_server(server);
		return -1;
	}

	/* Configure TCP server */
	struct sockaddr_in bind_addr = {
			.sin_family = AF_INET,
			.sin_port = htons(server->listening_port)
	};
	net_addr_pton(bind_addr.sin_family, server_config->ip_address, &bind_addr.sin_addr);

	/* Bind server socket to its destined IPv4 address */
	if (bind(server->tcp_sock, (struct sockaddr*) &bind_addr, sizeof(bind_addr)) == -1) 
	{
		LOG_ERR("Cannot bind socket %d to %s: errer %d\n", server->tcp_sock, server_config->ip_address, errno);
		kill_server(server);
		return -1;
	}

	/* Start listening for incoming connections */
	listen(server->tcp_sock, MAX_CLIENTS);

	/* Set the new socket to non-blocking */
	setblocking(server->tcp_sock, false);

	/* Add new server to the poll_set */
	int ret = poll_set_add_fd(&echo_server.poll_set, server->tcp_sock, POLLIN);
	if (ret != 0)
	{
		LOG_ERR("Error adding new server to poll_set");
		kill_server(server);
		return -1;
	}


	LOG_INF("Waiting for TLS connections on port %d", server->listening_port);

	return freeSlot+1;
}


/* Stop a running server and cleanup afterwards */
static void kill_server(struct tls_server_config_internal* server)
{
	/* Stop the listening socket and clear it from the poll_set */
	if (server->tcp_sock >= 0) 
	{
		poll_set_remove_fd(&echo_server.poll_set, server->tcp_sock);
		close(server->tcp_sock);
		server->tcp_sock = -1;
	}

	/* Kill all client connections */
	for (int i = 0; i < MAX_CLIENTS; i++) 
	{
		if (server->clients[i] != NULL)
		{
			/* Kill the running thread. This is very ungracefully, but necessary here,
			 * as the thread is probably blocked. 
			 */
			if (server->clients[i]->in_use == true) 
			{
				pthread_cancel(server->clients[i]->thread);
			}

			/* Cleanup the client */
			tls_client_cleanup(server->clients[i]);

			server->clients[i] = NULL;
		}
	}

	/* Clear TLS context */
	if (server->wolfssl_contex != NULL)
	{
		wolfSSL_CTX_free(server->wolfssl_contex);
		server->wolfssl_contex = NULL;
	}

	server->listening_port = 0;
	server->in_use = false;
}


static struct tls_server_config_internal* find_server_by_fd(int fd)
{
	for (int i = 0; i < MAX_SERVERS; i++)
	{
		if (server_pool[i].tcp_sock == fd)
		{
			return &server_pool[i];
		}
	}

	return NULL;
}

static struct tls_client_config_internal* find_client_by_fd(int fd)
{
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		if (client_pool[i].tcp_sock == fd)
		{
			return &client_pool[i];
		}
	}

	return NULL;
}

static struct tls_client_config_internal* add_new_client_for_server(struct tls_server_config_internal* server,
								    int client_socket,
								    struct sockaddr* client_addr,
								    socklen_t client_addr_len)
{
	/* Search for a free client slot in the pool */
	int freeSlotClientPool = -1;
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		if (client_pool[i].in_use == false)
		{
			freeSlotClientPool = i;
			break;
		}
	}

	int freeSlotServerClientsArray = -1;
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		if((server->clients[i] == NULL) || (server->clients[i]->in_use == false))
		{
			freeSlotServerClientsArray = i;
			break;
		}
	}

	if ((freeSlotClientPool == -1) || (freeSlotServerClientsArray == -1))
	{
		LOG_ERR("Cannot accept more TLS connections (no free slot)");
		close(client_socket);
		return NULL;
	}


	/* Create a new TLS session */
	WOLFSSL* new_session = wolfSSL_new(server->wolfssl_contex);

	if (new_session == NULL)
	{
		LOG_ERR("Cannot accept more TLS connections (error creating session)");
		close(client_socket);
		return NULL;
	}

	struct tls_client_config_internal* client = &client_pool[freeSlotClientPool];

	/* Store new client data */
	server->clients[freeSlotServerClientsArray] = client;
	client->in_use = true;
	client->wolfssl_session = new_session;
	client->tcp_sock = client_socket;

	struct sockaddr_in* client_data = (struct sockaddr_in*) client_addr;
	net_addr_ntop(AF_INET, &client_data->sin_addr, client->peer_ip, sizeof(client->peer_ip));
	client->peer_port = ntohs(client_data->sin_port);

#if defined(__ZEPHYR__)
	/* Store the pointer to the related stack for the client handler thread
	 * (started after the TLS handshake). */
	pthread_attr_setstack(&client->thread_attr,
			      client_stack_pool[freeSlotClientPool],
			      K_THREAD_STACK_SIZEOF(client_stack_pool[freeSlotClientPool]));
#endif

	wolfSSL_set_fd(client->wolfssl_session, client_socket);

	setblocking(client_socket, false);

	/* Print info */
	LOG_INF("New client connection on port %d from %s:%d, using slot %d/%d", 
		server->listening_port, client->peer_ip, client->peer_port, freeSlotClientPool+1, MAX_CLIENTS);

	return client;
}


static int perform_client_handshake(struct tls_client_config_internal* client)
{
	/* Perform TLS handshake */
	int ret = wolfssl_handshake(client->wolfssl_session);
	if (ret == 0)
	{
		LOG_INF("Handshake with peer %s:%d done", client->peer_ip, client->peer_port);
	}
	
	return ret;
}


static void tls_client_cleanup(struct tls_client_config_internal* client)
{
	/* Kill the network connection */
	if (client->tcp_sock >= 0) 
	{
		close(client->tcp_sock);
	}
	client->tcp_sock = -1;

	client->peer_ip[0] = '\0';
	client->peer_port = 0;

	/* Cleanup the TLS session */
	if (client->wolfssl_session != NULL) 
	{
		wolfSSL_free(client->wolfssl_session);
	}
	client->wolfssl_session = NULL;

	client->in_use = false;
}


/* The actual main thread for the echo server */
void* tls_echo_server_main_thread(void* ptr)
{
	struct tls_echo_server_config* config = (struct tls_echo_server_config*) ptr;

	/* Set the management socket to non-blocking and add it to the poll_set */
	setblocking(config->management_socket_pair[1], false);
	poll_set_add_fd(&config->poll_set, config->management_socket_pair[1], POLLIN);
	
	while (1)
	{
		struct sockaddr client_addr;
		socklen_t client_addr_len = sizeof(client_addr);

		/* Block and wait for incoming events (new connections, received data, ...) */
		int ret = poll(config->poll_set.fds, config->poll_set.num_fds, -1);

		if (ret == -1) {
			LOG_ERR("poll error: %d", errno);
			continue;
		}

		/* Check which fds created an event */
		for (int i = 0; i < config->poll_set.num_fds; i++) 
		{
			int fd = config->poll_set.fds[i].fd;
			short event = config->poll_set.fds[i].revents;

			struct tls_server_config_internal* server = NULL;
			struct tls_client_config_internal* client = NULL;

			if (fd == config->management_socket_pair[1])
			{
				if (event & POLLIN)
				{
					/* management_socket received data */
					struct tls_echo_server_message msg;
					ret = read_management_message(fd, &msg);
					if (ret < 0)
					{
						continue;
					}

					/* Handle the message */
					handle_management_message(fd, &msg);
				}
			}
			/* Check all TLS servers */
			else if ((server = find_server_by_fd(fd)) != NULL)
			{
				if (event & POLLIN)
				{
					/* New client connection, try to handle it */
					int client_socket = accept(server->tcp_sock, &client_addr, &client_addr_len);
					if (client_socket < 0) 
					{
						int error = errno;
						if (error != EAGAIN)
							LOG_ERR("accept error: %d (fd=%d)", error, server->tcp_sock);
						continue;
					}

					/* Handle new client */
					client = add_new_client_for_server(server, client_socket, &client_addr, client_addr_len);
					if (client == NULL)
					{
						LOG_ERR("Error adding new client");
						continue;
					}

					/* As we perform the TLS handshake from within the main thread, we have to add the 
	 				 * client_socket to the poll_set. */
					ret = poll_set_add_fd(&config->poll_set, client_socket, POLLIN);
					if (ret != 0)
					{
						LOG_ERR("Error adding new client to poll_set");
						tls_client_cleanup(client);
						continue;
					}
				}
			}
			/* Check all clients (that are in the TLS handshake) */
			else if ((client = find_client_by_fd(fd)) != NULL)
			{
				if ((event & POLLIN) || (event & POLLOUT))
				{	
					/* Continue with the handshake */
					ret = perform_client_handshake(client);

					if (ret < 0)
					{
						LOG_ERR("Error performing TLS handshake");
						tls_client_cleanup(client);
						continue;
					}
					else if (ret == 0)
					{
						/* Handshake done, start thread for client */
						poll_set_remove_fd(&config->poll_set, fd);

						ret = pthread_create(&client->thread, &client->thread_attr, tls_client_handler_thread, client);
						if (ret == 0)
						{
							LOG_INF("client handler thread for %s:%d started", client->peer_ip, client->peer_port);
						}
						else
						{
							LOG_ERR("Error starting client handler thread: %s", strerror(ret));
							tls_client_cleanup(client);
						}
					}
					else if (ret == WOLFSSL_ERROR_WANT_WRITE)
					{
						/* We have to wait for the socket to be writable */
						poll_set_update_events(&config->poll_set, fd, POLLOUT);
					}
					else
					{
						/* We have to wait for more data from the peer */
						poll_set_update_events(&config->poll_set, fd, POLLIN);
					}
				}
			}
			else
			{
				LOG_ERR("Received event for unknown fd %d", fd);
			}
		}
	}

	return NULL;
}


static void* tls_client_handler_thread(void *ptr)
{
	struct tls_client_config_internal* client = (struct tls_client_config_internal* ) ptr;
	struct poll_set poll_set;
	bool shutdown = false;

	poll_set_init(&poll_set);

	poll_set_add_fd(&poll_set, client->tcp_sock, POLLIN);
	
	while (!shutdown)
	{
		/* Block and wait for incoming events (new connections, received data, ...) */
		int ret = poll(poll_set.fds, poll_set.num_fds, -1);

		if (ret == -1) {
			LOG_ERR("poll error: %d", errno);
			continue;
		}

		/* Check which fds created an event */
		for (int i = 0; i < poll_set.num_fds; i++) 
		{
			int fd = poll_set.fds[i].fd;
			short event = poll_set.fds[i].revents;

			if (fd == client->tcp_sock)
			{
				int ret = 0;

				if (event & POLLIN)
				{
					/* Receive data from the peer */
					ret = wolfssl_receive(client->wolfssl_session,
								  client->recv_buffer,
								  sizeof(client->recv_buffer));

					if (ret > 0)
					{
						/* Echo received data */
						ret = wolfssl_send(client->wolfssl_session, 
								   client->recv_buffer, 
								   ret);

						if (ret == WOLFSSL_ERROR_WANT_WRITE)
						{
							/* We have to wait for the socket to be writable */
							poll_set_update_events(&poll_set, fd, POLLOUT);
						}
					}
				}
				if (event & POLLOUT)
				{
					/* Echo queued data */
					ret = wolfssl_send(client->wolfssl_session, 
							       client->recv_buffer, 
							       ret);
					
					if (ret == 0)
					{
						/* Wait again for incoming data */
						poll_set_update_events(&poll_set, fd, POLLIN);
					}
				}

				if (ret < 0)
				{
					/* Error, close session */
					shutdown = true;
					break;
				}
			}
		}
	}

	wolfSSL_shutdown(client->wolfssl_session);

	LOG_INF("client handler thread for %s:%d stopped", client->peer_ip, client->peer_port);

	tls_client_cleanup(client);

	return NULL;
}


/* Initialize the application backend. Must be called once on startup.
 * 
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_echo_server_init(void)
{
	/* Init client pool */
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		client_pool[i].in_use = false;
		client_pool[i].tcp_sock = -1;
		client_pool[i].peer_ip[0] = '\0';
		client_pool[i].peer_port = 0;
		client_pool[i].wolfssl_session = NULL;
		pthread_attr_init(&client_pool[i].thread_attr);
		pthread_attr_setdetachstate(&client_pool[i].thread_attr, PTHREAD_CREATE_DETACHED);
	}

	/* Init server pool */
	for (int i = 0; i < MAX_SERVERS; i++)
	{
		server_pool[i].in_use = false;
		server_pool[i].listening_port = 0;
		server_pool[i].tcp_sock = -1;
		server_pool[i].wolfssl_contex = NULL;

		for (int j = 0; j < MAX_CLIENTS; j++)
		{
			server_pool[i].clients[j] = NULL;
		}
	}

	/* Init app config */
	echo_server.management_socket_pair[0] = -1;
	echo_server.management_socket_pair[1] = -1;

	pthread_attr_init(&echo_server.thread_attr);
	pthread_attr_setdetachstate(&echo_server.thread_attr, PTHREAD_CREATE_DETACHED);

	poll_set_init(&echo_server.poll_set);

	return 0;
}


/* Start a new thread and run the main TLS echo server backend.
 * 
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_echo_server_run(void)
{
#if defined(__ZEPHYR__)
	/* We have to properly set the attributes with the stack to use for Zephyr. */
	pthread_attr_setstack(&echo_server.thread_attr, server_stack, K_THREAD_STACK_SIZEOF(server_stack));
#endif

	/* Create the socket pair for external management */
	int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, echo_server.management_socket_pair);
	if (ret < 0)
	{
		LOG_ERR("Error creating socket pair for management: %s", strerror(errno));
		return -1;
	}

	/* Create the new thread */
	ret = pthread_create(&echo_server.thread, &echo_server.thread_attr, tls_echo_server_main_thread, &echo_server);
	if (ret == 0)
	{
		LOG_INF("TLS echo server main thread started");
	}
	else
	{
		LOG_ERR("Error starting TLS echo server thread: %s", strerror(ret));
	}

	return ret;
}


/* Start a new echo server with given config.
 * 
 * Returns the id of the new server on success (positive integer) or -1 on failure
 * (error message is printed to console).
 */
int tls_echo_server_start(struct tls_server_config* server)
{
	/* Create a START_REQUEST message */
	struct tls_echo_server_message request = {
		.type = TLS_ECHO_SERVER_START_REQUEST,
		.payload.server_config = *server,
	};
	struct tls_echo_server_message response;

	/* Send request */
	int ret = send_management_message(echo_server.management_socket_pair[0], &request);
	if (ret < 0)
	{
		return -1;
	}

	/* Wait for response */
	ret = read_management_message(echo_server.management_socket_pair[0], &response);
	if (ret < 0)
	{	
		return -1;
	}
	else if (response.type != TLS_ECHO_SERVER_RESPONSE)
	{
		LOG_ERR("Received invalid response");
		return -1;
	}
	else if (response.payload.response_code < 0)
	{
		LOG_ERR("Error starting TLS echo server (error %d)", response.payload.response_code);
		return -1;
	}
	
	/* Response code is the id of the new server */
	return response.payload.response_code;
}


/* Stop the running echo server with given id (returned von tls_echo_server_start).
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_echo_server_stop(int id)
{
	/* Create a STOP_REQUEST message */
	struct tls_echo_server_message request = {
		.type = TLS_ECHO_SERVER_STOP_REQUEST,
		.payload.server_id = id,
	};
	struct tls_echo_server_message response;

	/* Send request */
	int ret = send_management_message(echo_server.management_socket_pair[0], &request);
	if (ret < 0)
	{
		return -1;
	}

	/* Wait for response */
	ret = read_management_message(echo_server.management_socket_pair[0], &response);
	if (ret < 0)
	{	
		return -1;
	}
	else if (response.type != TLS_ECHO_SERVER_RESPONSE)
	{
		LOG_ERR("Received invalid response");
		return -1;
	}
	else if (response.payload.response_code < 0)
	{
		LOG_ERR("Error stopping TLS echo server (error %d)", response.payload.response_code);
		return -1;
	}
	
	return 0;
}
