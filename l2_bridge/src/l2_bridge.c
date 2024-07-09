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


LOG_MODULE_CREATE(l2_bridge);


typedef struct l2_bridge
{
	poll_set poll_set;
	pthread_t thread;
	pthread_attr_t thread_attr;

	int lan_socket;
	int wan_socket;

	struct sockaddr_ll lan_interface;
	struct sockaddr_ll wan_interface;
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
	ssize_t recv_buffer_len = 0;
	struct sockaddr_ll source;
	socklen_t source_len = sizeof(source);

	while (1)
	{
		/* Block and wait for incoming packets */
		int ret = poll(bridge->poll_set.fds, bridge->poll_set.num_fds, -1);

		if (ret == -1) {
			LOG_ERROR("poll error: %d", errno);
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
			if (fd == bridge->lan_socket)
			{
				if (event & POLLIN)
				{
					recv_buffer_len = recvfrom(bridge->lan_socket, recv_buffer, sizeof(recv_buffer), 0,
								   (struct sockaddr*)&source, &source_len);

					if (recv_buffer_len < 0)
					{
						if (errno == EAGAIN)
						{
							continue;
						}

						LOG_ERROR("RAW : recv error %d", errno);
						ret = -errno;
						break;
					}

					// LOG_INFO("Received %d bytes on LAN interface", recv_buffer_len);
					// LOG_INFO("Protocol: %04x", htons(source.sll_protocol));

					/* Check if we have to forward the packet */
					if ((source.sll_pkttype == PACKET_OTHERHOST) ||
					    (source.sll_pkttype == PACKET_MULTICAST) ||
					    (source.sll_pkttype == PACKET_BROADCAST))
					{
						ret = sendto(bridge->wan_socket, recv_buffer, recv_buffer_len, 0,
							(const struct sockaddr *)&bridge->wan_interface,
							sizeof(bridge->wan_interface));
						if (ret < 0)
						{
							LOG_ERROR("Failed to send to WAN interface, errno %d", errno);
							break;
						}
					}
				}
				if (event & POLLOUT)
				{

				}
			}
			/* Check all clients */
			else if (fd == bridge->wan_socket)
			{
                                if (event & POLLIN)
				{
					recv_buffer_len = recvfrom(bridge->wan_socket, recv_buffer, sizeof(recv_buffer), 0,
								   (struct sockaddr*)&source, &source_len);

					if (recv_buffer_len < 0)
					{
						if (errno == EAGAIN)
						{
							continue;
						}

						LOG_ERROR("RAW : recv error %d", errno);
						ret = -errno;
						break;
					}

					// LOG_INFO("Received %d bytes on WAN interface", recv_buffer_len);
					// LOG_INFO("Protocol: %04x", htons(source.sll_protocol));

					/* Check if we have to forward the packet */
					if ((source.sll_pkttype == PACKET_OTHERHOST) ||
					    (source.sll_pkttype == PACKET_MULTICAST) ||
					    (source.sll_pkttype == PACKET_BROADCAST))
					{
						ret = sendto(bridge->lan_socket, recv_buffer, recv_buffer_len, 0,
			     			     (const struct sockaddr *)&bridge->lan_interface,
			     			     sizeof(bridge->lan_interface));
						if (ret < 0)
						{
							LOG_ERROR("Failed to send to LAN interface, errno %d", errno);
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
				LOG_ERROR("Received event for unknown fd %d", fd);
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

	memset(&theBridge.lan_interface, 0, sizeof(theBridge.lan_interface));
	memset(&theBridge.wan_interface, 0, sizeof(theBridge.wan_interface));

        /* Create the Packet sockets for the two interfaces */
	int proto = ETH_P_ALL;
#if !defined(__ZEPHYR__)
	proto = htons(ETH_P_ALL);
#endif

	theBridge.lan_socket = socket(AF_PACKET, SOCK_RAW, proto);
	if (theBridge.lan_socket == -1)
	{
		LOG_ERROR("Error creating LAN socket: %d", errno);
		return -1;
	}

	theBridge.wan_socket = socket(AF_PACKET, SOCK_RAW, proto);
	if (theBridge.wan_socket == -1)
	{
		LOG_ERROR("Error creating WAN socket: %d", errno);
		return -1;
	}

#if defined(__ZEPHYR__)
	theBridge.lan_interface.sll_ifindex = net_if_get_by_iface(config->lan_interface);
	theBridge.wan_interface.sll_ifindex = net_if_get_by_iface(config->wan_interface);
#else
	/* We have to get the mapping between interface name and index */
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	strncpy(ifr.ifr_name, (char const*) config->lan_interface, IFNAMSIZ);
	ioctl(theBridge.lan_socket, SIOCGIFINDEX, &ifr);

	theBridge.lan_interface.sll_ifindex = ifr.ifr_ifindex;

	strncpy(ifr.ifr_name, (char const*) config->wan_interface, IFNAMSIZ);
	ioctl(theBridge.wan_socket, SIOCGIFINDEX, &ifr);

	theBridge.wan_interface.sll_ifindex = ifr.ifr_ifindex;
#endif
	theBridge.lan_interface.sll_family = AF_PACKET;
	theBridge.wan_interface.sll_family = AF_PACKET;

	/* Bind the packet sockets to their interfaces */
	if (bind(theBridge.lan_socket, (struct sockaddr*) &theBridge.lan_interface, sizeof(theBridge.lan_interface)) < 0)
	{
		LOG_ERROR("binding LAN socket to interface failed: error %d\n", errno);
		close(theBridge.lan_socket);
		close(theBridge.wan_socket);
		return -1;
	}
	if (bind(theBridge.wan_socket, (struct sockaddr*) &theBridge.wan_interface, sizeof(theBridge.wan_interface)) < 0)
	{
		LOG_ERROR("binding WAN socket to interface failed: error %d\n", errno);
		close(theBridge.lan_socket);
		close(theBridge.wan_socket);
		return -1;
	}

#if !defined(__ZEPHYR__)
        if (setsockopt(theBridge.lan_socket, SOL_PACKET, PACKET_IGNORE_OUTGOING, &(int){1}, sizeof(int)) < 0)
        {
                LOG_ERROR("setsockopt(PACKET_IGNORE_OUTGOING) on LAN socket failed: error %d\n", errno);
		close(theBridge.lan_socket);
		close(theBridge.wan_socket);
		return -1;
        }

	if (setsockopt(theBridge.wan_socket, SOL_PACKET, PACKET_IGNORE_OUTGOING, &(int){1}, sizeof(int)) < 0)
        {
                LOG_ERROR("setsockopt(PACKET_IGNORE_OUTGOING) on WAN socket failed: error %d\n", errno);
		close(theBridge.lan_socket);
		close(theBridge.wan_socket);
		return -1;
        }
#endif

	/* Set the new sockets to non-blocking */
	setblocking(theBridge.lan_socket, false);
	setblocking(theBridge.wan_socket, false);

	/* Add sockets to the poll_set */
	int ret = poll_set_add_fd(&theBridge.poll_set, theBridge.lan_socket, POLLIN);
	if (ret != 0)
	{
		LOG_ERROR("Error adding LAN socket to poll_set");
		close(theBridge.lan_socket);
		close(theBridge.wan_socket);
		return -1;
	}
	ret = poll_set_add_fd(&theBridge.poll_set, theBridge.wan_socket, POLLIN);
	if (ret != 0)
	{
		LOG_ERROR("Error adding WAN socket to poll_set");
		close(theBridge.lan_socket);
		close(theBridge.wan_socket);
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
		LOG_INFO("L2 bridge main thread started");
	}
	else
	{
		LOG_ERROR("Error starting L2 bridge thread: %s", strerror(ret));
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
	close(theBridge.lan_socket);
	close(theBridge.wan_socket);

	return 0;
}
