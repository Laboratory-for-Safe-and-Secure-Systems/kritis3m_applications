#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>

#include "tcp_client_stdin_bridge.h"

#include "logging.h"
#include "poll_set.h"
#include "networking.h"
#include "wolfssl.h"


LOG_MODULE_REGISTER(tcp_client_stdin_bridge);


#define RECV_BUFFER_SIZE 1024


struct tcp_client_stdin_bridge
{
        int tcp_socket;
	pthread_t thread;
	pthread_attr_t thread_attr;
	struct poll_set poll_set;
	size_t num_of_bytes_in_recv_buffer;
        uint8_t recv_buffer[RECV_BUFFER_SIZE];
};


/* File global variables */
static struct tcp_client_stdin_bridge client_stdin_bridge;

#if defined(__ZEPHYR__)
#define STACK_SIZE 8*1024

Z_KERNEL_STACK_DEFINE_IN(client_stdin_bridge_stack, STACK_SIZE, __attribute__((section("SRAM3"))));
#endif


/* Internal method declarations */
static void* tcp_client_stdin_bridge_main_thread(void* ptr);


static void* tcp_client_stdin_bridge_main_thread(void* ptr)
{
	struct tcp_client_stdin_bridge* bridge = (struct tcp_client_stdin_bridge*) ptr;
	
	while (1)
	{
		/* Block and wait for incoming events (new connections, received data, ...) */
		int ret = poll(bridge->poll_set.fds, bridge->poll_set.num_fds, -1);

		if (ret == -1) {
			LOG_ERR("poll error: %d", errno);
			continue;
		}

		/* Check which fds created an event */
		for (int i = 0; i < bridge->poll_set.num_fds; i++) 
		{
			int fd = bridge->poll_set.fds[i].fd;
			short event = bridge->poll_set.fds[i].revents;

                        if(event == 0)
                                continue;

                        /* Check tcp client fd */
			if (fd == bridge->tcp_socket)
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
						LOG_INF("TCP connection closed by peer");
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
					close(bridge->tcp_socket);
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

						if ((ret == -1) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
						{	
							/* We have to wait for the socket to be writable */
							poll_set_update_events(&bridge->poll_set, bridge->tcp_socket, POLLOUT);
							ret = 0;
						}
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


/* Start a new thread and run the TCP client stdin bridge application.
 * 
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_client_stdin_bridge_run(struct tcp_client_stdin_bridge_config const* config)
{
        /* Init */
        poll_set_init(&client_stdin_bridge.poll_set);
	client_stdin_bridge.num_of_bytes_in_recv_buffer = 0;

        /* Create the TCP socket for the outgoing connection */
	client_stdin_bridge.tcp_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (client_stdin_bridge.tcp_socket == -1)
	{
		LOG_ERR("Error creating TCP socket");
		return -1;
	}

	/* Configure TCP server */
	struct sockaddr_in target_addr = {
			.sin_family = AF_INET,
			.sin_port = htons(config->target_port)
	};
	net_addr_pton(target_addr.sin_family, config->target_ip_address, &target_addr.sin_addr);

	/* Set the new socket to non-blocking */
	setblocking(client_stdin_bridge.tcp_socket, false);

	/* Connect to the peer */
	int ret = connect(client_stdin_bridge.tcp_socket, (struct sockaddr*) &target_addr, sizeof(target_addr));
	if ((ret != 0) && (errno != EINPROGRESS))
	{
		LOG_ERR("Unable to connect to target peer, errno: %d", errno);
		close(client_stdin_bridge.tcp_socket);
		return -1;
	}

	/* Add new server to the poll_set */
	ret = poll_set_add_fd(&client_stdin_bridge.poll_set, client_stdin_bridge.tcp_socket, POLLOUT);
	if (ret != 0)
	{
		LOG_ERR("Error adding TCP client to poll_set");
		close(client_stdin_bridge.tcp_socket);
		return -1;
	}

	/* Add stdin to the poll_set */
	ret = poll_set_add_fd(&client_stdin_bridge.poll_set, STDIN_FILENO, POLLIN);
	if (ret != 0)
	{
		LOG_ERR("Error adding stdin to poll_set");
		close(client_stdin_bridge.tcp_socket);
		return -1;
	}

        /* Init main backend */
	pthread_attr_init(&client_stdin_bridge.thread_attr);
	pthread_attr_setdetachstate(&client_stdin_bridge.thread_attr, PTHREAD_CREATE_DETACHED);

#if defined(__ZEPHYR__)
	/* We have to properly set the attributes with the stack to use for Zephyr. */
	pthread_attr_setstack(&client_stdin_bridge.thread_attr, client_stdin_bridge_stack, K_THREAD_STACK_SIZEOF(client_stdin_bridge_stack));
#endif

        /* Create the new thread */
	ret = pthread_create(&client_stdin_bridge.thread, &client_stdin_bridge.thread_attr, tcp_client_stdin_bridge_main_thread, &client_stdin_bridge);
	if (ret == 0)
	{
		LOG_INF("TCP client stdin bridge main thread started");
	}
	else
	{
		LOG_ERR("Error starting TCP client stdin bridge thread: %s", strerror(ret));
		close(client_stdin_bridge.tcp_socket);
	}

	return ret;
}


/* Terminate the tcp_client_stdin_bridge application.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_client_stdin_bridge_terminate(void)
{
	/* Stop the main thread */
	pthread_cancel(client_stdin_bridge.thread);

	return 0;
}
