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

#include "logging.h"
#include "poll_set.h"
#include "networking.h"


LOG_MODULE_REGISTER(l2_bridge);


typedef struct l2_bridge
{
	poll_set poll_set;
	pthread_t thread;
	pthread_attr_t thread_attr;

	int asset_socket;
	int tunnel_socket; 

	struct sockaddr_ll asset_interface;
	struct sockaddr_ll tunnel_interface;
}
l2_bridge;

/* File global variables */
static l2_bridge theBridge;
#if defined(__ZEPHYR__)
#define STACK_SIZE 8*1024

Z_KERNEL_STACK_DEFINE_IN(bridge_stack, STACK_SIZE, \
		__attribute__((section(CONFIG_RAM_SECTION_STACKS_1))));
#endif


/* Internal method declarations */
static void* l2_bridge_main_thread(void* ptr);


static void* l2_bridge_main_thread(void* ptr)
{
	l2_bridge* bridge = (l2_bridge*) ptr;
	static uint8_t recv_buffer[2048];
	uint32_t recv_buffer_len = 0;
	struct sockaddr_ll source;
	socklen_t source_len = sizeof(source);
	
	while (1)
	{
		/* Block and wait for incoming packets */
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

                        /* Check lan fd */
			if (fd == bridge->asset_socket)
			{
				if (event & POLLIN)
				{
					recv_buffer_len = recvfrom(bridge->asset_socket, recv_buffer, sizeof(recv_buffer), 0,
								   (struct sockaddr*)&source, &source_len);

					if (recv_buffer_len < 0)
					{
						if (errno == EAGAIN)
						{
							continue;
						}

						LOG_ERR("RAW : recv error %d", errno);
						ret = -errno;
						break;
					}

					// LOG_INF("Received %d bytes on LAN interface", recv_buffer_len);
					// LOG_INF("Protocol: %04x", htons(source.sll_protocol));

					/* Check if we have to forward the packet */
					if ((source.sll_pkttype == PACKET_OTHERHOST) ||
					    (source.sll_pkttype == PACKET_MULTICAST) ||
					    (source.sll_pkttype == PACKET_BROADCAST))
					{
						ret = sendto(bridge->tunnel_socket, recv_buffer, recv_buffer_len, 0,
							(const struct sockaddr *)&bridge->tunnel_interface,
							sizeof(bridge->tunnel_interface));
						if (ret < 0) 
						{
							LOG_ERR("Failed to send to WAN interface, errno %d", errno);
							break;
						}
					}
				}
				if (event & POLLOUT)
				{
					
				}
			}
			/* Check all clients */
			else if (fd == bridge->tunnel_socket)
			{
                                if (event & POLLIN)
				{
					recv_buffer_len = recvfrom(bridge->tunnel_socket, recv_buffer, sizeof(recv_buffer), 0,
								   (struct sockaddr*)&source, &source_len);

					if (recv_buffer_len < 0)
					{
						if (errno == EAGAIN)
						{
							continue;
						}

						LOG_ERR("RAW : recv error %d", errno);
						ret = -errno;
						break;
					}

					// LOG_INF("Received %d bytes on WAN interface", recv_buffer_len);
					// LOG_INF("Protocol: %04x", htons(source.sll_protocol));

					/* Check if we have to forward the packet */
					if ((source.sll_pkttype == PACKET_OTHERHOST) ||
					    (source.sll_pkttype == PACKET_MULTICAST) ||
					    (source.sll_pkttype == PACKET_BROADCAST))
					{
						ret = sendto(bridge->asset_socket, recv_buffer, recv_buffer_len, 0,
			     			     (const struct sockaddr *)&bridge->asset_interface,
			     			     sizeof(bridge->asset_interface));
						if (ret < 0) 
						{
							LOG_ERR("Failed to send to LAN interface, errno %d", errno);
							break;
						}
					}
				}
				if (event & POLLOUT)
				{
					
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


/* Start a new thread and run the Layer 2 bridge.
 * 
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int l2_bridge_run(l2_bridge_config const* config)
{
        poll_set_init(&theBridge.poll_set);

	memset(&theBridge.asset_interface, 0, sizeof(theBridge.asset_interface));
	memset(&theBridge.tunnel_interface, 0, sizeof(theBridge.tunnel_interface));

        /* Create the Packet sockets for the two interfaces */
	int proto = ETH_P_ALL;
#if !defined(__ZEPHYR__)
	proto = htons(ETH_P_ALL);
#endif

	theBridge.asset_socket = socket(AF_PACKET, SOCK_RAW, proto);
	if (theBridge.asset_socket == -1)
	{
		LOG_ERR("Error creating LAN socket: %d", errno);
		return -1;
	}

	theBridge.tunnel_socket = socket(AF_PACKET, SOCK_RAW, proto);
	if (theBridge.tunnel_socket == -1)
	{
		LOG_ERR("Error creating WAN socket: %d", errno);
		return -1;
	}

#if defined(__ZEPHYR__)
	theBridge.asset_interface.sll_ifindex = net_if_get_by_iface(config->asset_interface);
	theBridge.tunnel_interface.sll_ifindex = net_if_get_by_iface(config->tunnel_interface);
#else
	/* We have to get the mapping between interface name and index */
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	strncpy(ifr.ifr_name, (char const*) config->asset_interface, IFNAMSIZ);
	ioctl(theBridge.asset_socket, SIOCGIFINDEX, &ifr);

	theBridge.asset_interface.sll_ifindex = ifr.ifr_ifindex;

	strncpy(ifr.ifr_name, (char const*) config->tunnel_interface, IFNAMSIZ);
	ioctl(theBridge.tunnel_socket, SIOCGIFINDEX, &ifr);

	theBridge.tunnel_interface.sll_ifindex = ifr.ifr_ifindex;
#endif
	theBridge.asset_interface.sll_family = AF_PACKET;
	theBridge.tunnel_interface.sll_family = AF_PACKET;

	/* Bind the packet sockets to their interfaces */
	if (bind(theBridge.asset_socket, (struct sockaddr*) &theBridge.asset_interface, sizeof(theBridge.asset_interface)) < 0)
	{
		LOG_ERR("binding LAN socket to interface failed: error %d\n", errno);
		close(theBridge.asset_socket);
		close(theBridge.tunnel_socket);
		return -1;
	}
	if (bind(theBridge.tunnel_socket, (struct sockaddr*) &theBridge.tunnel_interface, sizeof(theBridge.tunnel_interface)) < 0)
	{
		LOG_ERR("binding WAN socket to interface failed: error %d\n", errno);
		close(theBridge.asset_socket);
		close(theBridge.tunnel_socket);
		return -1;
	}

#if !defined(__ZEPHYR__)
        if (setsockopt(theBridge.asset_socket, SOL_PACKET, PACKET_IGNORE_OUTGOING, &(int){1}, sizeof(int)) < 0)
        {
                LOG_ERR("setsockopt(PACKET_IGNORE_OUTGOING) on LAN socket failed: error %d\n", errno);
		close(theBridge.asset_socket);
		close(theBridge.tunnel_socket);
		return -1;
        }

	if (setsockopt(theBridge.tunnel_socket, SOL_PACKET, PACKET_IGNORE_OUTGOING, &(int){1}, sizeof(int)) < 0)
        {
                LOG_ERR("setsockopt(PACKET_IGNORE_OUTGOING) on WAN socket failed: error %d\n", errno);
		close(theBridge.asset_socket);
		close(theBridge.tunnel_socket);
		return -1;
        }
#endif

	/* Set the new sockets to non-blocking */
	setblocking(theBridge.asset_socket, false);
	setblocking(theBridge.tunnel_socket, false);

	/* Add sockets to the poll_set */
	int ret = poll_set_add_fd(&theBridge.poll_set, theBridge.asset_socket, POLLIN);
	if (ret != 0)
	{
		LOG_ERR("Error adding ASSET socket to poll_set");
		close(theBridge.asset_socket);
		close(theBridge.tunnel_socket);
		return -1;
	}
	ret = poll_set_add_fd(&theBridge.poll_set, theBridge.tunnel_socket, POLLIN);
	if (ret != 0)
	{
		LOG_ERR("Error adding TUNNEL socket to poll_set");
		close(theBridge.asset_socket);
		close(theBridge.tunnel_socket);
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
	close(theBridge.asset_socket);
	close(theBridge.tunnel_socket);

	return 0;
}
