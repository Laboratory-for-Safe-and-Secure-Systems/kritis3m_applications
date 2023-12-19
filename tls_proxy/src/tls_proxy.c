
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>

#include "tls_proxy.h"

#include "logging.h"
#include "poll_set.h"
#include "networking.h"
#include "wolfssl.h"


LOG_MODULE_REGISTER(tls_proxy);


#define RECV_BUFFER_SIZE 1024

#define MAX_PROXYS 3
#define MAX_CONNECTIONS_PER_PROXY 5


enum tls_proxy_direction
{
	REVERSE_PROXY,
	FORWARD_PROXY,
};

struct proxy_connection
{
	bool in_use;
	enum tls_proxy_direction direction;
	int listening_peer_sock;
	int target_peer_sock;
	WOLFSSL* wolfssl_session;
	pthread_t thread;
	pthread_attr_t thread_attr;
	size_t num_of_bytes_in_recv_buffer;
	uint8_t recv_buffer[RECV_BUFFER_SIZE];
};

struct proxy
{
	bool in_use;
	enum tls_proxy_direction direction;
	int listening_tcp_sock;
	struct sockaddr_in target_addr;
	WOLFSSL_CTX* wolfssl_contex;
	struct proxy_connection* connections[MAX_CONNECTIONS_PER_PROXY];
};

struct tls_proxy_backend_config
{
	int management_socket_pair[2];
	pthread_t thread;
	pthread_attr_t thread_attr;
	struct poll_set poll_set;
};

enum tls_proxy_management_message_type
{
	REVERSE_PROXY_START_REQUEST,
	FORWARD_PROXY_START_REQUEST,
	PROXY_STOP_REQUEST,
	PROXY_RESPONSE,
};

struct tls_proxy_management_message
{
	enum tls_proxy_management_message_type type;
	
	union tls_proxy_management_message_payload
	{
		struct proxy_config reverse_proxy_config;	/* REVERSE_PROXY_START_REQUEST */
		struct proxy_config forward_proxy_config; 	/* FORWARD_PROXY_START_REQUEST */
		int proxy_id;					/* PROXY_STOP_REQUEST */
		int response_code; 				/* RESPONSE */
	} 
	payload;
};


/* File global variables */
static struct tls_proxy_backend_config proxy_backend;
static struct proxy_connection proxy_connection_pool[MAX_CONNECTIONS_PER_PROXY];
static struct proxy proxy_pool[MAX_PROXYS];


#if defined(__ZEPHYR__)
#define CONNECTION_HANDLER_STACK_SIZE 32*1024
#define BACKEND_STACK_SIZE 128*1024

// K_THREAD_STACK_ARRAY_DEFINE(client_stack_pool, MAX_CLIENTS, CLIENT_HANDLER_STACK_SIZE);
// K_THREAD_STACK_DEFINE(server_stack, BACKEND_STACK_SIZE);

Z_KERNEL_STACK_ARRAY_DEFINE_IN(connection_handler_stack_pool, MAX_CONNECTIONS_PER_PROXY, CONNECTION_HANDLER_STACK_SIZE, __attribute__((section("SRAM3"))));
Z_KERNEL_STACK_DEFINE_IN(backend_stack, BACKEND_STACK_SIZE, __attribute__((section("SRAM3"))));
#endif


/* Internal method declarations */
static void* tls_proxy_main_thread(void* ptr);
static void* connection_handler_thread(void *ptr);

static int send_management_message(int socket, struct tls_proxy_management_message const* msg);
static int read_management_message(int socket, struct tls_proxy_management_message* msg);
static int handle_management_message(int socket, struct tls_proxy_management_message const* msg);

static int add_new_proxy(enum tls_proxy_direction direction, struct proxy_config const* config);
static void kill_proxy(struct proxy* proxy);

static struct proxy_connection* add_new_connection_to_proxy(struct proxy* proxy,
							    int client_socket,
							    struct sockaddr* client_addr,
							    socklen_t client_addr_len);
static int perform_handshake(struct proxy_connection* connection);

static struct proxy* find_proxy_by_fd(int fd);
static struct proxy_connection* find_proxy_connection_by_fd(int fd);

static void proxy_connection_cleanup(struct proxy_connection* connection);



static int send_management_message(int socket, struct tls_proxy_management_message const* msg)
{
	int ret = send(socket, msg, sizeof(struct tls_proxy_management_message), 0);
	if (ret < 0)
	{
		LOG_ERR("Error sending message: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int read_management_message(int socket, struct tls_proxy_management_message* msg)
{
	int ret = recv(socket, msg, sizeof(struct tls_proxy_management_message), 0);
	if (ret < 0)
	{
		LOG_ERR("Error receiving message: %s", strerror(errno));
		return -1;
	}
	else if (ret != sizeof(struct tls_proxy_management_message))
	{
		LOG_ERR("Received invalid response");
		return -1;
	}
	
	return 0;
}

static int handle_management_message(int socket, struct tls_proxy_management_message const* msg)
{
	switch (msg->type)
	{
		case REVERSE_PROXY_START_REQUEST:
		{
			/* Add a new reverse proxy */
			int proxy_id = add_new_proxy(REVERSE_PROXY, &msg->payload.reverse_proxy_config);

			/* Send response */
			struct tls_proxy_management_message response = {
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

			/* Send response */
			struct tls_proxy_management_message response = {
				.type = PROXY_RESPONSE,
				.payload.response_code = proxy_id,
			};
			send_management_message(socket, &response);
			break;
		}
		case PROXY_STOP_REQUEST:
		{
			/* Kill the proxy */
			if (proxy_pool[msg->payload.proxy_id-1].in_use == true)
			{
				kill_proxy(&proxy_pool[msg->payload.proxy_id-1]);

			}
			/* Send response */
			struct tls_proxy_management_message response = {
				.type = PROXY_RESPONSE,
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


/* Create a new proxy and add it to the main event loop */
static int add_new_proxy(enum tls_proxy_direction direction, struct proxy_config const* config)
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
		LOG_ERR("Cannot create more TLS proxies (no free slot)");
		return -1;
	}

	struct proxy* proxy = &proxy_pool[freeSlot];

	proxy->in_use = true;
	proxy->direction = direction;

	if (direction == REVERSE_PROXY)
	{
		LOG_INF("Starting new reverse proxy on port %d using slot %d/%d", 
			config->listening_port, freeSlot+1, MAX_PROXYS);

		/* Create the wolfssl context */
		proxy->wolfssl_contex = wolfssl_setup_server_context(&config->tls_config);
	}
	else if (direction == FORWARD_PROXY)
	{
		LOG_INF("Starting new forward proxy to %s:%d using slot %d/%d", 
		config->target_ip_address, config->target_port, freeSlot+1, MAX_PROXYS);

		/* Create the wolfssl context */
		proxy->wolfssl_contex = wolfssl_setup_client_context(&config->tls_config);
	}

	if (proxy->wolfssl_contex == NULL)
	{
		LOG_ERR("Error creating WolfSSL context");
		kill_proxy(proxy);
		return -1;
	}
	
	/* Create the TCP socket for the incoming connection */
	proxy->listening_tcp_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (proxy->listening_tcp_sock == -1)
	{
		LOG_ERR("Error creating incoming TCP socket");
		kill_proxy(proxy);
		return -1;
	}

	if (setsockopt(proxy->listening_tcp_sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
        {
                LOG_ERR("setsockopt(SO_REUSEADDR) failed: errer %d\n", errno);
		close(proxy->listening_tcp_sock);
		return -1;
        }

	/* Configure TCP server */
	struct sockaddr_in bind_addr = {
			.sin_family = AF_INET,
			.sin_port = htons(config->listening_port)
	};
	net_addr_pton(bind_addr.sin_family, config->own_ip_address, &bind_addr.sin_addr);

	/* Bind server socket to its destined IPv4 address */
	if (bind(proxy->listening_tcp_sock, (struct sockaddr*) &bind_addr, sizeof(bind_addr)) == -1) 
	{
		LOG_ERR("Cannot bind socket %d to %s:%d: errer %d\n",
			proxy->listening_tcp_sock, config->own_ip_address, config->listening_port, errno);
		kill_proxy(proxy);
		return -1;
	}

	/* Start listening for incoming connections */
	listen(proxy->listening_tcp_sock, MAX_CONNECTIONS_PER_PROXY);

	/* Set the new socket to non-blocking */
	setblocking(proxy->listening_tcp_sock, false);

	/* Add new server to the poll_set */
	int ret = poll_set_add_fd(&proxy_backend.poll_set, proxy->listening_tcp_sock, POLLIN);
	if (ret != 0)
	{
		LOG_ERR("Error adding new proxy to poll_set");
		kill_proxy(proxy);
		return -1;
	}

	/* Configure TCP client */
	proxy->target_addr.sin_family = AF_INET;
	proxy->target_addr.sin_port = htons(config->target_port);
	net_addr_pton(proxy->target_addr.sin_family, config->target_ip_address, &proxy->target_addr.sin_addr);

	LOG_INF("Waiting for incoming connections on port %d", config->listening_port);

	return freeSlot+1;
}


/* Stop a running proxy and cleanup afterwards */
static void kill_proxy(struct proxy* proxy)
{
	/* Stop the listening socket and clear it from the poll_set */
	if (proxy->listening_tcp_sock >= 0) 
	{
		poll_set_remove_fd(&proxy_backend.poll_set, proxy->listening_tcp_sock);
		close(proxy->listening_tcp_sock);
		proxy->listening_tcp_sock = -1;
	}

	/* Kill all connections */
	for (int i = 0; i < MAX_CONNECTIONS_PER_PROXY; i++) 
	{
		if (proxy->connections[i] != NULL)
		{
			/* Kill the running thread. This is very ungracefully, but necessary here,
			 * as the thread is probably blocked. 
			 */
			if (proxy->connections[i]->in_use == true) 
			{
				pthread_cancel(proxy->connections[i]->thread);
			}

			/* Cleanup the client */
			proxy_connection_cleanup(proxy->connections[i]);

			proxy->connections[i] = NULL;
		}
	}

	/* Clear TLS context */
	if (proxy->wolfssl_contex != NULL)
	{
		wolfSSL_CTX_free(proxy->wolfssl_contex);
		proxy->wolfssl_contex = NULL;
	}

	proxy->in_use = false;
}


static struct proxy* find_proxy_by_fd(int fd)
{
	for (int i = 0; i < MAX_PROXYS; i++)
	{
		if (proxy_pool[i].listening_tcp_sock == fd)
		{
			return &proxy_pool[i];
		}
	}

	return NULL;
}

static struct proxy_connection* find_proxy_connection_by_fd(int fd)
{
	for (int i = 0; i < MAX_CONNECTIONS_PER_PROXY; i++)
	{
		if ((proxy_connection_pool[i].listening_peer_sock == fd) ||
		    (proxy_connection_pool[i].target_peer_sock == fd))
		{
			return &proxy_connection_pool[i];
		}
	}

	return NULL;
}

static struct proxy_connection* add_new_connection_to_proxy(struct proxy* proxy,
							    int client_socket,
							    struct sockaddr* client_addr,
							    socklen_t client_addr_len)
{
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
		LOG_ERR("Cannot accept more connections (no free slot)");
		close(client_socket);
		return NULL;
	}


	/* Create a new TLS session */
	WOLFSSL* new_session = wolfSSL_new(proxy->wolfssl_contex);

	if (new_session == NULL)
	{
		LOG_ERR("Cannot accept more connections (error creating TLS session)");
		close(client_socket);
		return NULL;
	}

	struct proxy_connection* connection = &proxy_connection_pool[freeSlotConnectionPool];

	/* Store new client data */
	connection->in_use = true;
	connection->direction = proxy->direction;
	connection->listening_peer_sock = client_socket;
	connection->wolfssl_session = new_session;

	setblocking(connection->listening_peer_sock, false);

	/* Create the TCP socket for the outgoing connection */
	connection->target_peer_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (connection->target_peer_sock == -1)
	{
		LOG_ERR("Error creating outgoing TCP socket, errno: %d", errno);
		proxy_connection_cleanup(connection);
		return NULL;
	}

	/* Set socket non-blocking */
	setblocking(connection->target_peer_sock, false);

	/* Connect to the peer */
	int ret = connect(connection->target_peer_sock, (struct sockaddr*) &proxy->target_addr, sizeof(proxy->target_addr));
	if ((ret != 0) && (errno != EINPROGRESS))
	{
		LOG_ERR("Unable to connect to target peer, errno: %d", errno);
		proxy_connection_cleanup(connection);
		return NULL;
	}

	/* Map the TLS session to the respective socket depending on the direction */
	if (connection->direction == FORWARD_PROXY)
	{	
		wolfSSL_set_fd(connection->wolfssl_session, connection->target_peer_sock);
	}
	else if (connection->direction == REVERSE_PROXY)
	{
		wolfSSL_set_fd(connection->wolfssl_session, connection->listening_peer_sock);
	}

	/* Store the new connection within the proxy */
	proxy->connections[freeSlotProxyConnectionsArray] = connection;

#if defined(__ZEPHYR__)
	/* Store the pointer to the related stack for the client handler thread
	 * (started after the TLS handshake). */
	pthread_attr_setstack(&connection->thread_attr,
			      connection_handler_stack_pool[freeSlotConnectionPool],
			      K_THREAD_STACK_SIZEOF(connection_handler_stack_pool[freeSlotConnectionPool]));
#endif

	/* Print info */
	struct sockaddr_in* client_data = (struct sockaddr_in*) client_addr;
	char peer_ip[20];
	net_addr_ntop(AF_INET, &client_data->sin_addr, peer_ip, sizeof(peer_ip));
	LOG_INF("New client connection from %s:%d, using slot %d/%d", 
		peer_ip, ntohs(client_data->sin_port),
		freeSlotConnectionPool+1, MAX_CONNECTIONS_PER_PROXY);

	return connection;
}


static int perform_handshake(struct proxy_connection* connection)
{
	/* Perform TLS handshake */
	int ret = wolfssl_handshake(connection->wolfssl_session);
	if (ret == 0)
	{
		LOG_INF("Handshake done");
	}
	
	return ret;
}


static void proxy_connection_cleanup(struct proxy_connection* connection)
{
	/* Kill the network connections */
	if (connection->listening_peer_sock >= 0) 
	{
		close(connection->listening_peer_sock);
		connection->listening_peer_sock = -1;
	}
	if (connection->target_peer_sock >= 0) 
	{
		close(connection->target_peer_sock);
		connection->target_peer_sock = -1;
	}

	/* Cleanup the TLS session */
	if (connection->wolfssl_session != NULL) 
	{
		wolfSSL_free(connection->wolfssl_session);
		connection->wolfssl_session = NULL;
	}

	connection->num_of_bytes_in_recv_buffer = 0;
	
	connection->in_use = false;
}


/* The actual main thread for the proxy backend */
void* tls_proxy_main_thread(void* ptr)
{
	struct tls_proxy_backend_config* config = (struct tls_proxy_backend_config*) ptr;

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

			if(event == 0)
                                continue;

			struct proxy* proxy = NULL;
			struct proxy_connection* proxy_connection = NULL;

			if (fd == config->management_socket_pair[1])
			{
				if (event & POLLIN)
				{
					/* management_socket received data */
					struct tls_proxy_management_message msg;
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
					int client_socket = accept(proxy->listening_tcp_sock, &client_addr, &client_addr_len);
					if (client_socket < 0) 
					{
						int error = errno;
						if (error != EAGAIN)
							LOG_ERR("accept error: %d (fd=%d)", error, proxy->listening_tcp_sock);
						continue;
					}

					/* Handle new client */
					proxy_connection = add_new_connection_to_proxy(proxy,
										       client_socket,
										       &client_addr,
										       client_addr_len);
					if (proxy_connection == NULL)
					{
						LOG_ERR("Error adding new client");
						continue;
					}

					/* As we perform the TLS handshake from within the main thread, we have to add the 
	 				 * respective socket to the poll_set. */
					if (proxy_connection->direction == REVERSE_PROXY)
					{
						ret = poll_set_add_fd(&config->poll_set, proxy_connection->listening_peer_sock, POLLIN);
					}
					else if (proxy_connection->direction == FORWARD_PROXY)
					{
						ret = poll_set_add_fd(&config->poll_set, proxy_connection->target_peer_sock, POLLOUT);
					}
					if (ret != 0)
					{
						LOG_ERR("Error adding new client to poll_set");
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
					ret = perform_handshake(proxy_connection);

					if (ret < 0)
					{
						LOG_ERR("Error performing TLS handshake");
						poll_set_remove_fd(&config->poll_set, fd);
						proxy_connection_cleanup(proxy_connection);
						continue;
					}
					else if (ret == 0)
					{
						/* Handshake done, remove respective socket from the poll_set */
						poll_set_remove_fd(&config->poll_set, fd);

						/* Start thread for connection handling */
						ret = pthread_create(&proxy_connection->thread,
								     &proxy_connection->thread_attr,
								     connection_handler_thread,
								     proxy_connection);
						if (ret == 0)
						{
							LOG_INF("connection handler thread started");
						}
						else
						{
							LOG_ERR("Error starting client handler thread: %s", strerror(ret));
							proxy_connection_cleanup(proxy_connection);
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


static void* connection_handler_thread(void *ptr)
{
	struct proxy_connection* connection = (struct proxy_connection* ) ptr;
	struct poll_set poll_set;
	bool shutdown = false;

	poll_set_init(&poll_set);

	poll_set_add_fd(&poll_set, connection->listening_peer_sock, POLLIN);
	poll_set_add_fd(&poll_set, connection->target_peer_sock, POLLOUT);
	
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

			if(event == 0)
                                continue;

			if (((connection->direction == REVERSE_PROXY) && (fd == connection->listening_peer_sock)) ||
			    ((connection->direction == FORWARD_PROXY) && (fd == connection->target_peer_sock)))
			{
				if (event & POLLIN)
				{
					/* Receive data from the peer */
					ret = wolfssl_receive(connection->wolfssl_session,
							      connection->recv_buffer,
							      sizeof(connection->recv_buffer));

					if (ret > 0)
					{
						connection->num_of_bytes_in_recv_buffer = ret;

						/* Send received data to the other socket */
						int destination_fd = -1;
						if (connection->direction == REVERSE_PROXY)
						{
							destination_fd = connection->target_peer_sock;
						}
						else if (connection->direction == FORWARD_PROXY)
						{
							destination_fd = connection->listening_peer_sock;
						}

						ret = send(destination_fd,
							   connection->recv_buffer,
							   connection->num_of_bytes_in_recv_buffer,
							   0);

						if ((ret == -1) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
						{	
							/* We have to wait for the socket to be writable */
							poll_set_update_events(&poll_set, fd, POLLOUT);
							ret = 0;
						}
					}
				}
				if (event & POLLOUT)
				{
					/* Send received data to the other socket */
					int destination_fd = -1;
					if (connection->direction == REVERSE_PROXY)
					{
						destination_fd = connection->target_peer_sock;
					}
					else if (connection->direction == FORWARD_PROXY)
					{
						destination_fd = connection->listening_peer_sock;
					}

					ret = send(destination_fd,
						   connection->recv_buffer,
						   connection->num_of_bytes_in_recv_buffer,
						   0);

					
					if (ret >= 0)
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
			else if (((connection->direction == REVERSE_PROXY) && (fd == connection->target_peer_sock)) ||
			    	 ((connection->direction == FORWARD_PROXY) && (fd == connection->listening_peer_sock)))
			{
				if (event & POLLIN)
				{
					/* Receive data from the peer */
					ret = read(fd, connection->recv_buffer, sizeof(connection->recv_buffer));

					if (ret > 0)
					{
						connection->num_of_bytes_in_recv_buffer = ret;

						/* Send received data to the other socket */
						ret = wolfssl_send(connection->wolfssl_session,
								   connection->recv_buffer,
								   connection->num_of_bytes_in_recv_buffer);

						if (ret == WOLFSSL_ERROR_WANT_WRITE)
						{
							/* We have to wait for the socket to be writable */
							poll_set_update_events(&poll_set, fd, POLLOUT);
							ret = 0;
						}

					}
					else if (ret == 0)
					{
						/* Connection closed */
						LOG_INF("TCP connection closed by peer");
						ret = -1;
					}
				}
				if (event & POLLOUT)
				{
					/* Send received data to the other socket */
					ret = wolfssl_send(connection->wolfssl_session, 
							   connection->recv_buffer, 
							   connection->num_of_bytes_in_recv_buffer);
					
					if (ret >= 0)
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

	wolfSSL_shutdown(connection->wolfssl_session);

	LOG_INF("connection handler thread stopped");

	proxy_connection_cleanup(connection);

	return NULL;
}


/* Start a new thread and run the main TLS proxy backend.
 * 
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_backend_run(void)
{
	/* Init connection pool */
	for (int i = 0; i < MAX_CONNECTIONS_PER_PROXY; i++)
	{
		proxy_connection_pool[i].in_use = false;
		proxy_connection_pool[i].direction = REVERSE_PROXY;
		proxy_connection_pool[i].listening_peer_sock = -1;
		proxy_connection_pool[i].target_peer_sock = -1;
		proxy_connection_pool[i].wolfssl_session = NULL;
		proxy_connection_pool[i].num_of_bytes_in_recv_buffer;
		pthread_attr_init(&proxy_connection_pool[i].thread_attr);
		pthread_attr_setdetachstate(&proxy_connection_pool[i].thread_attr, PTHREAD_CREATE_DETACHED);
	}

	/* Init server pool */
	for (int i = 0; i < MAX_PROXYS; i++)
	{
		proxy_pool[i].in_use = false;
		proxy_pool[i].direction = REVERSE_PROXY;
		proxy_pool[i].listening_tcp_sock = -1;
		proxy_pool[i].wolfssl_contex = NULL;

		for (int j = 0; j < MAX_CONNECTIONS_PER_PROXY; j++)
		{
			proxy_pool[i].connections[j] = NULL;
		}
	}

	/* Init app config */
	proxy_backend.management_socket_pair[0] = -1;
	proxy_backend.management_socket_pair[1] = -1;

	pthread_attr_init(&proxy_backend.thread_attr);
	pthread_attr_setdetachstate(&proxy_backend.thread_attr, PTHREAD_CREATE_DETACHED);

	poll_set_init(&proxy_backend.poll_set);

#if defined(__ZEPHYR__)
	/* We have to properly set the attributes with the stack to use for Zephyr. */
	pthread_attr_setstack(&proxy_backend.thread_attr, backend_stack, K_THREAD_STACK_SIZEOF(backend_stack));
#endif

	/* Create the socket pair for external management */
	int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, proxy_backend.management_socket_pair);
	if (ret < 0)
	{
		LOG_ERR("Error creating socket pair for management: %s", strerror(errno));
		return -1;
	}

	/* Create the new thread */
	ret = pthread_create(&proxy_backend.thread, &proxy_backend.thread_attr, tls_proxy_main_thread, &proxy_backend);
	if (ret == 0)
	{
		LOG_INF("TLS proxy main thread started");
	}
	else
	{
		LOG_ERR("Error starting TLS proxy thread: %s", strerror(ret));
	}

	return ret;
}


int tls_proxy_start_helper(struct tls_proxy_management_message const* request)
{
	struct tls_proxy_management_message response;

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
		LOG_ERR("Received invalid response");
		return -1;
	}
	else if (response.payload.response_code < 0)
	{
		LOG_ERR("Error starting new TLS proxy (error %d)", response.payload.response_code);
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
int tls_reverse_proxy_start(struct proxy_config const* config)
{
	/* Create a START_REQUEST message */
	struct tls_proxy_management_message request = {
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
int tls_forward_proxy_start(struct proxy_config const* config)
{
	/* Create a START_REQUEST message */
	struct tls_proxy_management_message request = {
		.type = FORWARD_PROXY_START_REQUEST,
		.payload.forward_proxy_config = *config,
	};

	return tls_proxy_start_helper(&request);
}


/* Stop the running proxy with given id (returned by tls_forward_proxy_start or
 * tls_forward_proxy_start).
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_stop(int id)
{
	/* Create a STOP_REQUEST message */
	struct tls_proxy_management_message request = {
		.type = PROXY_STOP_REQUEST,
		.payload.proxy_id = id,
	};
	struct tls_proxy_management_message response;

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
		LOG_ERR("Received invalid response");
		return -1;
	}
	else if (response.payload.response_code < 0)
	{
		LOG_ERR("Error stopping TLS proxy (error %d)", response.payload.response_code);
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
	/* Stop all running reverse proxies */
	for (int i = 0; i < MAX_PROXYS; i++)
	{
		if (proxy_pool[i].in_use == true)
		{
			kill_proxy(&proxy_pool[i]);
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
