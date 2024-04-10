
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/tcp.h>

#include "tls_proxy.h"

#include "logging.h"
#include "poll_set.h"
#include "networking.h"
#include "wolfssl.h"


LOG_MODULE_REGISTER(tls_proxy);

#define MAX_PROXYS 3

#if defined(__ZEPHYR__)

#define RECV_BUFFER_SIZE 1024
#define MAX_CONNECTIONS_PER_PROXY 3

#else

#define RECV_BUFFER_SIZE 32768
#define MAX_CONNECTIONS_PER_PROXY 15

#endif



enum tls_proxy_direction
{
	REVERSE_PROXY,
	FORWARD_PROXY,
};


typedef struct proxy_connection
{
	bool in_use;
	enum tls_proxy_direction direction;
	int tunnel_sock;
	int asset_sock;
	wolfssl_session* tls_session;
	int slot;
	pthread_t thread;
	pthread_attr_t thread_attr;

	uint8_t tun2ass_buffer[RECV_BUFFER_SIZE];
	size_t num_of_bytes_in_tun2ass_buffer;

	uint8_t ass2tun_buffer[RECV_BUFFER_SIZE];
	size_t num_of_bytes_in_ass2tun_buffer;
}
proxy_connection;

typedef struct proxy
{
	bool in_use;
	enum tls_proxy_direction direction;
	int incoming_sock;
	struct sockaddr_in target_addr;
	wolfssl_endpoint* tls_endpoint;
	struct proxy_connection* connections[MAX_CONNECTIONS_PER_PROXY];
}
proxy;

typedef struct tls_proxy_backend_config
{
	int management_socket_pair[2];
	pthread_t thread;
	pthread_attr_t thread_attr;
	struct poll_set poll_set;
}
tls_proxy_backend_config;

enum tls_proxy_management_message_type
{
	REVERSE_PROXY_START_REQUEST,
	FORWARD_PROXY_START_REQUEST,
	PROXY_STOP_REQUEST,
	PROXY_RESPONSE,
};

typedef struct tls_proxy_management_message
{
	enum tls_proxy_management_message_type type;

	union tls_proxy_management_message_payload
	{
		proxy_config reverse_proxy_config;	/* REVERSE_PROXY_START_REQUEST */
		proxy_config forward_proxy_config; 	/* FORWARD_PROXY_START_REQUEST */
		int proxy_id;					/* PROXY_STOP_REQUEST */
		int response_code; 				/* RESPONSE */
	}
	payload;
}
tls_proxy_management_message;


/* File global variables */
static tls_proxy_backend_config proxy_backend;
static proxy_connection proxy_connection_pool[MAX_CONNECTIONS_PER_PROXY];
static proxy proxy_pool[MAX_PROXYS];


#if defined(__ZEPHYR__)
#define CONNECTION_HANDLER_STACK_SIZE (32*1024)
#define BACKEND_STACK_SIZE (127*1024)

Z_KERNEL_STACK_ARRAY_DEFINE_IN(connection_handler_stack_pool, MAX_CONNECTIONS_PER_PROXY, \
		CONNECTION_HANDLER_STACK_SIZE, __attribute__((section(CONFIG_RAM_SECTION_STACKS_1))));

Z_KERNEL_STACK_DEFINE_IN(backend_stack, BACKEND_STACK_SIZE, \
		__attribute__((section(CONFIG_RAM_SECTION_STACKS_2))));
#endif


/* Internal method declarations */
static void* tls_proxy_main_thread(void* ptr);
static void* connection_handler_thread(void *ptr);

static int send_management_message(int socket, tls_proxy_management_message const* msg);
static int read_management_message(int socket, tls_proxy_management_message* msg);
static int handle_management_message(int socket, tls_proxy_management_message const* msg);

static int add_new_proxy(enum tls_proxy_direction direction, proxy_config const* config);
static void kill_proxy(proxy* proxy);

static proxy_connection* add_new_connection_to_proxy(proxy* proxy,
							    int client_socket,
							    struct sockaddr* client_addr);

static proxy* find_proxy_by_fd(int fd);
static proxy_connection* find_proxy_connection_by_fd(int fd);

static void proxy_connection_cleanup(proxy_connection* connection);



static int send_management_message(int socket, tls_proxy_management_message const* msg)
{
	int ret = send(socket, msg, sizeof(tls_proxy_management_message), 0);
	if (ret < 0)
	{
		LOG_ERR("Error sending message: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int read_management_message(int socket, tls_proxy_management_message* msg)
{
	int ret = recv(socket, msg, sizeof(tls_proxy_management_message), 0);
	if (ret < 0)
	{
		LOG_ERR("Error receiving message: %s", strerror(errno));
		return -1;
	}
	else if (ret != sizeof(tls_proxy_management_message))
	{
		LOG_ERR("Received invalid response");
		return -1;
	}

	return 0;
}

static int handle_management_message(int socket, tls_proxy_management_message const* msg)
{
	switch (msg->type)
	{
		case REVERSE_PROXY_START_REQUEST:
		{
			/* Add a new reverse proxy */
			int proxy_id = add_new_proxy(REVERSE_PROXY, &msg->payload.reverse_proxy_config);

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

			/* Send response */
			tls_proxy_management_message response = {
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
			tls_proxy_management_message response = {
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
		LOG_ERR("Cannot create more TLS proxies (no free slot)");
		return -1;
	}

	/* This is only a temporary solution, as we currently not set the log level
	 * on a proxy individual base, but rather on a system wide level. */
	LOG_LEVEL_SET(config->logLevel);

	proxy* proxy = &proxy_pool[freeSlot];

	proxy->in_use = true;
	proxy->direction = direction;

	if (direction == REVERSE_PROXY)
	{
		LOG_INF("Starting new reverse proxy on port %d using slot %d/%d",
			config->listening_port, freeSlot+1, MAX_PROXYS);

		/* Create the TLS endpoint */
		proxy->tls_endpoint = wolfssl_setup_server_endpoint(&config->tls_config);
	}
	else if (direction == FORWARD_PROXY)
	{
		LOG_INF("Starting new forward proxy to %s:%d using slot %d/%d",
		config->target_ip_address, config->target_port, freeSlot+1, MAX_PROXYS);

		/* Create the TLS endpoint */
		proxy->tls_endpoint = wolfssl_setup_client_endpoint(&config->tls_config);
	}

	if (proxy->tls_endpoint == NULL)
	{
		LOG_ERR("Error creating TLS endpoint");
		kill_proxy(proxy);
		return -1;
	}

	/* Create the TCP socket for the incoming connection */
	proxy->incoming_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (proxy->incoming_sock == -1)
	{
		LOG_ERR("Error creating incoming TCP socket");
		kill_proxy(proxy);
		return -1;
	}

	if (setsockopt(proxy->incoming_sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
        {
                LOG_ERR("setsockopt(SO_REUSEADDR) failed: errer %d\n", errno);
		close(proxy->incoming_sock);
		return -1;
        }

	/* Configure TCP server */
	struct sockaddr_in bind_addr = {
			.sin_family = AF_INET,
			.sin_port = htons(config->listening_port)
	};
	net_addr_pton(bind_addr.sin_family, config->own_ip_address, &bind_addr.sin_addr);

	/* Bind server socket to its destined IPv4 address */
	if (bind(proxy->incoming_sock, (struct sockaddr*) &bind_addr, sizeof(bind_addr)) == -1)
	{
		LOG_ERR("Cannot bind socket %d to %s:%d: errer %d\n",
			proxy->incoming_sock, config->own_ip_address, config->listening_port, errno);
		kill_proxy(proxy);
		return -1;
	}

	/* Start listening for incoming connections */
	listen(proxy->incoming_sock, MAX_CONNECTIONS_PER_PROXY);

	/* Set the new socket to non-blocking */
	setblocking(proxy->incoming_sock, false);

	/* Add new server to the poll_set */
	int ret = poll_set_add_fd(&proxy_backend.poll_set, proxy->incoming_sock, POLLIN);
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
static void kill_proxy(proxy* proxy)
{
	/* Stop the listening socket and clear it from the poll_set */
	if (proxy->incoming_sock >= 0)
	{
		poll_set_remove_fd(&proxy_backend.poll_set, proxy->incoming_sock);
		close(proxy->incoming_sock);
		proxy->incoming_sock = -1;
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
	if (proxy->tls_endpoint != NULL)
	{
		wolfssl_free_endpoint(proxy->tls_endpoint);
		proxy->tls_endpoint = NULL;
	}

	proxy->in_use = false;
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

static proxy_connection* find_proxy_connection_by_fd(int fd)
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

static proxy_connection* add_new_connection_to_proxy(proxy* proxy,
							    int client_socket,
							    struct sockaddr* client_addr)
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

	proxy_connection* connection = &proxy_connection_pool[freeSlotConnectionPool];

	/* Store new client data */
	connection->in_use = true;
	connection->direction = proxy->direction;
	connection->slot = freeSlotConnectionPool;

	if (connection->direction == FORWARD_PROXY)
	{
		connection->asset_sock = client_socket;

		/* Create the socket for the tunnel  */
		connection->tunnel_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (connection->tunnel_sock == -1)
		{
			LOG_ERR("Error creating tunnel socket, errno: %d", errno);
			proxy_connection_cleanup(connection);
			return NULL;
		}
	}
	else if (connection->direction == REVERSE_PROXY)
	{
		connection->tunnel_sock = client_socket;

		/* Create the socket for the asset connection */
		connection->asset_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (connection->asset_sock == -1)
		{
			LOG_ERR("Error creating asset socket, errno: %d", errno);
			proxy_connection_cleanup(connection);
			return NULL;
		}
	}

	/* Set sockets non-blocking */
	setblocking(connection->tunnel_sock, false);
	setblocking(connection->asset_sock, false);

	if (setsockopt(connection->tunnel_sock, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0)
        {
                LOG_ERR("setsockopt(TCP_NODELAY) failed: errer %d\n", errno);
		proxy_connection_cleanup(connection);
			return NULL;
        }
	if (setsockopt(connection->asset_sock, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0)
        {
                LOG_ERR("setsockopt(TCP_NODELAY) failed: errer %d\n", errno);
		proxy_connection_cleanup(connection);
			return NULL;
        }

	/* Connect to the peer */
	if (connection->direction == FORWARD_PROXY)
	{
		ret = connect(connection->tunnel_sock, (struct sockaddr*) &proxy->target_addr, sizeof(proxy->target_addr));
	}
	else if (connection->direction == REVERSE_PROXY)
	{
		ret = connect(connection->asset_sock, (struct sockaddr*) &proxy->target_addr, sizeof(proxy->target_addr));
	}
	if ((ret != 0) && (errno != EINPROGRESS))
	{
		LOG_ERR("Unable to connect to target peer, errno: %d", errno);
		proxy_connection_cleanup(connection);
		return NULL;
	}

	/* Create a new TLS session on the destined interface depending on the direction */
	connection->tls_session = wolfssl_create_session(proxy->tls_endpoint, connection->tunnel_sock);
	if (connection->tls_session == NULL)
	{
		LOG_ERR("Cannot accept more connections (error creating TLS session)");
		proxy_connection_cleanup(connection);
		return NULL;
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
	LOG_INF("New connection from %s:%d, using slot %d/%d",
		peer_ip, ntohs(client_data->sin_port),
		freeSlotConnectionPool+1, MAX_CONNECTIONS_PER_PROXY);

	return connection;
}


static void proxy_connection_cleanup(proxy_connection* connection)
{
	/* Kill the network connections */
	if (connection->tunnel_sock >= 0)
	{
		close(connection->tunnel_sock);
		connection->tunnel_sock = -1;
	}
	if (connection->asset_sock >= 0)
	{
		close(connection->asset_sock);
		connection->asset_sock = -1;
	}

	/* Cleanup the TLS session */
	if (connection->tls_session != NULL)
	{
		wolfssl_free_session(connection->tls_session);
		connection->tls_session = NULL;
	}

	connection->num_of_bytes_in_tun2ass_buffer = 0;
	connection->num_of_bytes_in_ass2tun_buffer = 0;
	connection->slot = -1;

	connection->in_use = false;
}


/* The actual main thread for the proxy backend */
void* tls_proxy_main_thread(void* ptr)
{
	tls_proxy_backend_config* config = (tls_proxy_backend_config*) ptr;

#if !defined(__ZEPHYR__)
	LOG_INF("TLS proxy backend started");
#endif

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

			proxy* proxy = NULL;
			proxy_connection* proxy_connection = NULL;

			if (fd == config->management_socket_pair[1])
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
							LOG_ERR("accept error: %d (fd=%d)", error, proxy->incoming_sock);
						continue;
					}

					/* Handle new client */
					proxy_connection = add_new_connection_to_proxy(proxy,
										       client_socket,
										       &client_addr);
					if (proxy_connection == NULL)
					{
						LOG_ERR("Error adding new client");
						continue;
					}

					/* As we perform the TLS handshake from within the main thread, we have to add
	 				 * the socket to the poll_set. In case of a reverse proxy, the TCP connection
					 * is already established, hence we can wait for incoming data. In case of a
					 * forward proxy, we first have to wait for successful connection establishment.
					 */
					if (proxy_connection->direction == REVERSE_PROXY)
					{
						ret = poll_set_add_fd(&config->poll_set, proxy_connection->tunnel_sock,
								      POLLIN);
					}
					else if (proxy_connection->direction == FORWARD_PROXY)
					{
						ret = poll_set_add_fd(&config->poll_set, proxy_connection->tunnel_sock,
								      POLLOUT | POLLERR | POLLHUP);
					}
					if (ret != 0)
					{
						LOG_ERR("Error adding tunnel connection to poll_set");
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
					ret = wolfssl_handshake(proxy_connection->tls_session);

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

						/* Get handshake metrics (only for reverse proxys, as the metrics are not correct
						 * on the TLS client endpoint). */
						if (proxy_connection->direction == REVERSE_PROXY)
						{
							tls_handshake_metrics metrics;
							metrics = wolfssl_get_handshake_metrics(proxy_connection->tls_session);

							LOG_INF("Handshake done\r\n\tDuration: %.3f milliseconds\r\n\tTx bytes: "\
								"%d\r\n\tRx bytes: %d", metrics.duration_us / 1000.0,
								metrics.txBytes, metrics.rxBytes);
						}

						/* Start thread for connection handling */
						ret = pthread_create(&proxy_connection->thread,
								     &proxy_connection->thread_attr,
								     connection_handler_thread,
								     proxy_connection);
						if (ret != 0)
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
				if ((event & POLLERR) || (event & POLLHUP))
				{
					LOG_ERR("Socket error");
					poll_set_remove_fd(&config->poll_set, fd);
					proxy_connection_cleanup(proxy_connection);
					continue;
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
	proxy_connection* connection = (proxy_connection* ) ptr;
	poll_set poll_set;
	bool shutdown = false;

#if defined(__ZEPHYR__)
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
#else
	LOG_INF("TLS proxy connection handler started for slot %d/%d",
		connection->slot+1, MAX_CONNECTIONS_PER_PROXY);
#endif


	poll_set_init(&poll_set);

	poll_set_add_fd(&poll_set, connection->tunnel_sock, POLLIN);
	poll_set_add_fd(&poll_set, connection->asset_sock, POLLOUT | POLLIN);

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

			if (fd == connection->tunnel_sock)
			{
				if (event & POLLIN)
				{
					/* Data received from the tunnel */
					ret = wolfssl_receive(connection->tls_session,
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
							if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
							{
								/* We have to wait for the asset socket to be writable. Until we can send
							 	 * the data, we also mustn't receive more data on the tunnel socket. */
								poll_set_add_events(&poll_set, connection->asset_sock, POLLOUT);
								poll_set_remove_events(&poll_set, connection->tunnel_sock, POLLIN);
								ret = 0;
							}
							else
							{
								// LOG_ERR("Error sending data to asset: %s", strerror(errno));
								shutdown = true;
								break;
							}
						}
						else if ((size_t)ret == connection->num_of_bytes_in_tun2ass_buffer)
						{
							connection->num_of_bytes_in_tun2ass_buffer = 0;
						}
						else
						{
							connection->num_of_bytes_in_tun2ass_buffer -= ret;
							memmove(connection->tun2ass_buffer, connection->tun2ass_buffer + ret,
								connection->num_of_bytes_in_tun2ass_buffer);
							poll_set_update_events(&poll_set, connection->asset_sock, POLLOUT);
							// LOG_WRN("Not all data sent to asset");
						}

					}
					else if (ret < 0)
					{
						/* Connection closed */
						// LOG_INF("Tunnel connection on slot %d/%d closed",
						// 	connection->slot+1, MAX_CONNECTIONS_PER_PROXY);
						ret = -1;
					}
				}
				if (event & POLLOUT)
				{
					/* We can send data on the tunnel connection now. Send remaining
					 * data from the asset. */
					ret = wolfssl_send(connection->tls_session,
							   connection->ass2tun_buffer,
							   connection->num_of_bytes_in_ass2tun_buffer);

					if (ret == 0)
					{
						/* Wait again for incoming data on the asset socket and remove
						 * the writable indication from the tunnel socket. */
						poll_set_remove_events(&poll_set, connection->tunnel_sock, POLLOUT);
						poll_set_add_events(&poll_set, connection->asset_sock, POLLIN);
						connection->num_of_bytes_in_ass2tun_buffer = 0;
					}
				}
				if (event & POLLERR)
				{
					// LOG_ERR("Error on tunnel connection");
					shutdown = true;
					break;
				}

				if (ret < 0)
				{
					shutdown = true;
					break;
				}

			}
			else if (fd == connection->asset_sock)
			{
				if (event & POLLIN)
				{
					/* Data received from the asset connection */
					ret = read(connection->asset_sock, connection->ass2tun_buffer, sizeof(connection->ass2tun_buffer));

					if (ret > 0)
					{
						connection->num_of_bytes_in_ass2tun_buffer = ret;

						/* Send received data to the other socket */
						ret = wolfssl_send(connection->tls_session,
								   connection->ass2tun_buffer,
								   connection->num_of_bytes_in_ass2tun_buffer);

						if (ret == WOLFSSL_ERROR_WANT_WRITE)
						{
							/* We have to wait for the tunnel socket to be writable. Until we can send
							 * the data, we also mustn't receive more data on the asset socket. */
							poll_set_add_events(&poll_set, connection->tunnel_sock, POLLOUT);
							poll_set_remove_events(&poll_set, connection->asset_sock, POLLIN);
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
						// LOG_INF("Asset connection on slot %d/%d closed by peer",
						// 	connection->slot+1, MAX_CONNECTIONS_PER_PROXY);
						ret = -1;
					}
				}
				if (event & POLLOUT)
				{
					/* We can send data on the asset connection now. Send remaining
					 * tunnel data. */
					ret = send(connection->asset_sock,
						   connection->tun2ass_buffer,
						   connection->num_of_bytes_in_tun2ass_buffer,
						   0);

					if (ret == -1)
					{
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
						{
							ret = 0;
						}
						else
						{
							// LOG_ERR("Error sending data to asset: %s", strerror(errno));
							shutdown = true;
							break;
						}
					}
					else if ((size_t)ret == connection->num_of_bytes_in_tun2ass_buffer)
					{
						/* Wait again for incoming data on the tunnel socket and remove
						 * the writable indication from the asset socket. */
						poll_set_remove_events(&poll_set, connection->asset_sock, POLLOUT);
						poll_set_add_events(&poll_set, connection->tunnel_sock, POLLIN);
						connection->num_of_bytes_in_tun2ass_buffer = 0;
					}
					else
					{
						connection->num_of_bytes_in_tun2ass_buffer -= ret;
						memmove(connection->tun2ass_buffer, connection->tun2ass_buffer + ret,
							connection->num_of_bytes_in_tun2ass_buffer);
						// LOG_WRN("Not all data sent to asset");
					}

				}
				if (event & POLLERR)
				{
					// LOG_ERR("Error on asset connection");
					shutdown = true;
					break;
				}

				if (ret < 0)
				{
					shutdown = true;
					break;
				}
			}
		}
	}

	LOG_INF("Connection on slot %d/%d closed", connection->slot+1, MAX_CONNECTIONS_PER_PROXY);

	wolfssl_close_session(connection->tls_session);

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
		proxy_connection_pool[i].tunnel_sock = -1;
		proxy_connection_pool[i].asset_sock = -1;
		proxy_connection_pool[i].tls_session = NULL;
		proxy_connection_pool[i].slot = -1;
		proxy_connection_pool[i].num_of_bytes_in_tun2ass_buffer = 0;
		proxy_connection_pool[i].num_of_bytes_in_ass2tun_buffer = 0;
		pthread_attr_init(&proxy_connection_pool[i].thread_attr);
		pthread_attr_setdetachstate(&proxy_connection_pool[i].thread_attr, PTHREAD_CREATE_DETACHED);
	}

	/* Init server pool */
	for (int i = 0; i < MAX_PROXYS; i++)
	{
		proxy_pool[i].in_use = false;
		proxy_pool[i].direction = REVERSE_PROXY;
		proxy_pool[i].incoming_sock = -1;
		proxy_pool[i].tls_endpoint = NULL;

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
	pthread_attr_setstack(&proxy_backend.thread_attr, &backend_stack, K_THREAD_STACK_SIZEOF(backend_stack));
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
