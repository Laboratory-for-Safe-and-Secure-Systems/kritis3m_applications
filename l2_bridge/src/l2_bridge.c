#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "stdio.h"

#if defined(__ZEPHYR__)

#include <zephyr/net/ethernet.h>

#else

#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#endif

#include "l2_bridge.h"
#include "packet_socket.h"

#include "logging.h"
#include "poll_set.h"
#include "networking.h"

LOG_MODULE_REGISTER(l2_bridge);

typedef struct l2_bridge
{
	poll_set poll_set;
	pthread_t thread;
	pthread_attr_t thread_attr;
	Bridge *asset;
	Bridge *tunnel;
} l2_bridge;

/* File global variables */
static l2_bridge theBridge;
#if defined(__ZEPHYR__)
#define STACK_SIZE 8 * 1024

Z_KERNEL_STACK_DEFINE_IN(bridge_stack, STACK_SIZE,
						 __attribute__((section(CONFIG_RAM_SECTION_STACKS_1))));
#endif

int bridge_send(Bridge *bridge, uint8_t *buffer, int buffer_len, int buffer_start)
{
	sendFunc send = (sendFunc)bridge->vtable[call_send];
	return send(bridge, buffer, buffer_len, buffer_start);
}

int bridge_receive(Bridge *bridge)
{
	receiveOrPipeFunc receive = (receiveOrPipeFunc)bridge->vtable[call_receive];
	return receive(bridge);
}

int bridge_pipe(Bridge *bridge)
{
	receiveOrPipeFunc pipe = (receiveOrPipeFunc)bridge->vtable[call_pipe];
	return pipe(bridge);
}
int bridge_close(Bridge *bridge)
{
	return bridge->vtable[call_close](bridge);
}

/* Internal method declarations */
static void *l2_bridge_main_thread(void *ptr);

Bridge *find_bridge_by_fd(int fd)
{
	if (theBridge.asset->fd == fd)
	{
		return theBridge.asset;
	}
	else if (theBridge.tunnel->fd == fd)
	{
		return theBridge.tunnel;
	}
	else
	{
		return NULL;
	}
}

static void *l2_bridge_main_thread(void *ptr)
{
	l2_bridge *bridge = (l2_bridge *)ptr;

	while (1)
	{
		/* Block and wait for incoming packets */
		int ret = poll(bridge->poll_set.fds, bridge->poll_set.num_fds, -1);

		if (ret == -1)
		{
			LOG_ERR("poll error: %d", errno);
			continue;
		}
		/* Check which fds created an event */
		for (int i = 0; i < bridge->poll_set.num_fds; i++)
		{
			int fd = bridge->poll_set.fds[i].fd;
			short event = bridge->poll_set.fds[i].revents;

			if (event == 0)
				continue;

			Bridge *t_bridge = find_bridge_by_fd(fd);
			if (t_bridge == NULL)
			{
				LOG_ERR("Received event for unknown fd %d", fd);
				continue;
			}
			if (event == POLLIN)
			{
				int ret = bridge_receive(t_bridge);
				if (ret < 0)
				{
					LOG_ERR("Failed to receive data on bridge %d", fd);
				}
				else
				{
					bridge_pipe(t_bridge);
				}
			}
			if (event == POLLOUT)
			{
				LOG_INF("POLLOUT event for fd %d", fd);
			}
			if (event & POLLERR)
			{
				LOG_ERR("Received error event for fd %d", fd);
			}
		}

		/* Check lan fd */
	}

	return NULL;
}

Bridge *init_bridge(const interface_config *interface, connected_channel channel)
{
	// check which interface type is requested
	switch (interface->type)
	{
	case PACKET_SOCKET:
		// dynammic memory allocation for PacketSocket
		PacketSocket *bridge = (PacketSocket *)malloc(sizeof(PacketSocket));
		init_packet_socket_bridge(bridge, interface, channel);

		return (Bridge *)bridge;
	case TUN_INTERFACE:
#if defined(__ZEPHYR__)
		LOG_INF("ZEPHYR does not support TUN interface yet");
#else
		LOG_INF("TUN interface is not implemented yet");
#endif
		return NULL;
	default:
		LOG_ERR("Invalid interface type");
		return NULL;
	}
}
void marry_bridges(Bridge *bridge1, Bridge *bridge2)
{
	bridge1->pipe = bridge2;
	bridge2->pipe = bridge1;
}

/* Start a new thread and run the Layer 2 bridge.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int l2_bridge_run(l2_bridge_config const *config)
{
// handle not implemented interfaces
#if defined(__ZEPHYR__)
	if (config->asset_interface.type == TUN_INTERFACE ||
		config->tunnel_interface.type == TUN_INTERFACE)
	{
		LOG_ERR("TUN interface not supported");
		return -1;
	}
#endif
	Bridge *t_bridge = init_bridge(&config->asset_interface, ASSET);
	if (t_bridge == NULL)
	{
		LOG_ERR("Failed to initialize asset bridge");
		bridge_close(t_bridge);
		return -1;
	}
	theBridge.asset = t_bridge;
	t_bridge = init_bridge(&config->tunnel_interface, TUNNEL);
	if (t_bridge == NULL)
	{
		LOG_ERR("Failed to initialize tunnel bridge");
		bridge_close(t_bridge);
		return -1;
	}
	theBridge.tunnel = t_bridge;

	marry_bridges(theBridge.asset, theBridge.tunnel);

	poll_set_init(&theBridge.poll_set);

	/* Set the new sockets to non-blocking */
	setblocking(theBridge.asset->fd, false);
	setblocking(theBridge.tunnel->fd, false);

	/* Add sockets to the poll_set */
	int ret = poll_set_add_fd(&theBridge.poll_set, theBridge.asset->fd, POLLIN);
	if (ret != 0)
	{
		LOG_ERR("Error adding ASSET socket to poll_set");
		bridge_close(theBridge.asset);
		bridge_close(theBridge.tunnel);
		return -1;
	}
	ret = poll_set_add_fd(&theBridge.poll_set, theBridge.tunnel->fd, POLLIN);
	if (ret != 0)
	{
		LOG_ERR("Error adding TUNNEL socket to poll_set");
		bridge_close(theBridge.asset);
		bridge_close(theBridge.tunnel);
		return -1;
	}

	/* Init main backend */
	pthread_attr_init(&theBridge.thread_attr);
	pthread_attr_setdetachstate(&theBridge.thread_attr, PTHREAD_CREATE_DETACHED);

#if defined(__ZEPHYR__)
	/* We have to properly set the attributes with the stack to use for Zephyr. */
	pthread_attr_setstack(&theBridge.thread_attr, bridge_stack, K_THREAD_STACK_SIZEOF(bridge_stack));
#endif

	/* Create the new thread */
	ret = pthread_create(&theBridge.thread, &theBridge.thread_attr, l2_bridge_main_thread, &theBridge);
	if (ret == 0)
	{
		LOG_INF("L2 bridge main thread started");
	}
	else
	{
		LOG_ERR("Error starting L2 bridge thread: %s", strerror(ret));
	}

	return ret;
}

/* Terminate the Layer 2 bridge.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int l2_bridge_terminate(void)
{
	/* Stop the main thread */
	pthread_cancel(theBridge.thread);

	/* Close the sockets */
	bridge_close(theBridge.asset);

	return 0;
}
