
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "stdio.h"

#include "wolfssl.h"

#if defined(__ZEPHYR__)

#include <zephyr/net/ethernet.h>
#include <zephyr/kernel.h>

#else

#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#endif
#include "tap_interface.h"
#include "packet_socket.h"
#include "dtls_socket.h"
// #include "udp_socket.h"

#include "logging.h"
#include "poll_set.h"
#include "networking.h"

LOG_MODULE_REGISTER(l2_gateway);

typedef struct l2_gateway
{
	poll_set poll_set;
	pthread_t thread;
	pthread_attr_t thread_attr;
	L2_Gateway *asset;
	L2_Gateway *tunnel;
	l2_gateway_config config;
} l2_gateway;

static l2_gateway theBridge = {
	.asset = NULL,
	.tunnel = NULL,
};

/* Internal method declarations */
static void *l2_gateway_main_thread(void *ptr);
void marry_bridges(L2_Gateway *bridge1, L2_Gateway *bridge2);
/* File global variables */

#if defined(__ZEPHYR__)
#define STACK_SIZE 60 * 1024

Z_KERNEL_STACK_DEFINE_IN(l2_gateway_stack, STACK_SIZE,
						 __attribute__((section(CONFIG_RAM_SECTION_STACKS_2))));
#endif

int l2_gateway_register_fd(int fd, short events)
{
	return poll_set_add_fd(&theBridge.poll_set, fd, events);
}

void l2_gateway_update_events(int fd, short events)
{
	poll_set_update_events(&theBridge.poll_set, fd, events);
}

void l2_gateway_remove_fd(int fd)
{
	poll_set_remove_fd(&theBridge.poll_set, fd);
}

void reset_l2_gateway()
{
	poll_set_init(&theBridge.poll_set);
	if (theBridge.asset != NULL)
	{
		l2_gateway_close(theBridge.asset);
	}
	if (theBridge.tunnel != NULL)
	{
		l2_gateway_close(theBridge.tunnel);
	}
}

int configure_interfaces(l2_gateway_config const *config)
{
	int ret = -1;

	// ***********VLAN TAG AREA***********
#if defined(__ZEPHYR__)

	// set tunnel vlan tag
	if (config->tunnel_vlan_tag > 0)
	{
		net_if_set_promisc(network_interfaces()->tunnel);
		ret = net_eth_vlan_enable(network_interfaces()->tunnel, config->tunnel_vlan_tag);
		if (ret < 0)
		{
			LOG_ERR("Cannot enable VLAN for tag %d: error %d", config->tunnel_vlan_tag, ret);
			return ret;
		}
	}

	// set asset vlan tag
	if (config->asset_vlan_tag > 0)
	{
		ret = net_eth_vlan_enable(network_interfaces()->asset, config->asset_vlan_tag);
		if (ret < 0)
		{
			LOG_ERR("Cannot enable VLAN for tag %d: error %d", config->asset_vlan_tag, ret);
			return ret;
		}
		// net_virtual_set_flags(network_interfaces()->asset, NET_IF_PROMISC);
	}

#else
	if (config->asset_vlan_tag > 0 || config->tunnel_vlan_tag > 0)
	{
		LOG_ERR("VLAN is not supported in LINUX");
		return -1;
	}

	// linux set iface into promiscous mode

#endif

	return ret;
}

int l2_gateway_start(l2_gateway_config const *config)
{
	int ret;
	theBridge.config = *config;
	/* Init main backend */
	pthread_attr_init(&theBridge.thread_attr);
	pthread_attr_setdetachstate(&theBridge.thread_attr, PTHREAD_CREATE_DETACHED);

#if defined(__ZEPHYR__)
	/* We have to properly set the attributes with the stack to use for Zephyr. */
	pthread_attr_setstack(&theBridge.thread_attr, l2_gateway_stack, K_THREAD_STACK_SIZEOF(l2_gateway_stack));
#endif
	/* Create the new thread */
	ret = pthread_create(&theBridge.thread,
						 &theBridge.thread_attr,
						 l2_gateway_main_thread,
						 &theBridge);
	if (ret == 0)
	{
		LOG_INF("L2 bridge main thread started");
		while (1)
		{
			sleep(1);
		}
	}
	else
	{
		LOG_ERR("Error starting L2 bridge thread: %s", strerror(ret));
	}

	return 1;
}

int l2_gateway_send(L2_Gateway *bridge, int fd, uint8_t *buffer, int buffer_len, int buffer_start)
{
	sendFunc send = (sendFunc)bridge->vtable[call_send];
	return send(bridge, fd, buffer, buffer_len, buffer_start);
}

int l2_gateway_receive(L2_Gateway *bridge, int fd)
{
	receiveFunc receive = (receiveFunc)bridge->vtable[call_receive];
	return receive(bridge, fd, NULL);
}

int l2_gateway_pipe(L2_Gateway *bridge)
{
	PipeFunc pipe = (PipeFunc)bridge->vtable[call_pipe];
	return pipe(bridge);
}
int l2_gateway_close(L2_Gateway *l2_gateway)
{
	return l2_gateway->vtable[call_close](l2_gateway);
}

L2_Gateway *find_bridge_by_fd(int fd)
{
	if (theBridge.asset->fd == fd)
	{
		return theBridge.asset;
	}
	return theBridge.tunnel;
}

int standard_transfer(l2_gateway *l2_gw_container)
{

	while (1)
	{
		int ret = poll(l2_gw_container->poll_set.fds, l2_gw_container->poll_set.num_fds, -1);
		if (ret < 0)
		{
			LOG_ERR("poll error: %d", errno);
			continue;
		}
		/* Check which fds created an event */
		for (int i = 0; i < l2_gw_container->poll_set.num_fds; i++)
		{
			int fd = l2_gw_container->poll_set.fds[i].fd;
			short event = l2_gw_container->poll_set.fds[i].revents;

			if (event == 0)
				continue;

			L2_Gateway *t_bridge = find_bridge_by_fd(fd);
			if (t_bridge == NULL)
			{
				LOG_ERR("Received event for unknown fd %d", fd);
				continue;
			}
			if (event & POLLIN)
			{
				int ret = l2_gateway_receive(t_bridge, fd);
				if (ret < 0)
				{
					LOG_ERR("Failed to receive data on bridge %d, errno %d ", fd, errno);
					goto return_standard_transfer;
				}
				if (ret == 0)
				{
					continue;
				}

				ret = l2_gateway_pipe(t_bridge);
				if (ret < 0)
				{
					LOG_ERR("Failed to pipe data on bridge %d", fd);
					// goto return_standard_transfer;
				}
			}

			if (event & POLLOUT)
			{
				LOG_INF("POLLOUT event for fd %d", fd);
			}

			if (event & POLLERR)
			{
				LOG_ERR("Received error event for fd %d", fd);
			}
			if (event & POLLHUP)
			{
				LOG_ERR("Received HUP event for fd %d", fd);
			}
		}
	}

return_standard_transfer:
	LOG_INF("Standard transfer exiting");
	return -1;
}
int init_asset(const l2_gateway_config *config, l2_gateway *gw)
{
	L2_Gateway *asset = NULL;
	int ret = -1;
	switch (config->asset_type)
	{
	case PACKET_SOCKET:
		asset = (L2_Gateway *)((PacketSocket *)malloc(sizeof(PacketSocket)));
		memset(asset, 0, sizeof(PacketSocket));
		memset((uint8_t *)asset->buf, 0, sizeof(asset->buf));
		ret = init_packet_socket_gateway((PacketSocket *)asset, config, ASSET);
		if (ret < 0)
		{
			LOG_ERR("Failed to initialize packet socket gateway");
			return -1;
		}
		break;
	case DTLS_SOCKET:
		asset = (L2_Gateway *)((DtlsSocket *)malloc(sizeof(DtlsSocket)));
		memset((DtlsSocket *)asset, 0, sizeof(DtlsSocket));

		ret = init_dtls_socket_gateway((DtlsSocket *)asset, config, ASSET);
		if (ret < 0)
		{
			LOG_ERR("Failed to initialize dtls server socket gateway");
			return -1;
		}
		break;
	case UDP_SOCKET:
		LOG_INF("Not implemented yet");
		break;
	case TAP_INTERFACE:
		asset = (L2_Gateway *)((TapInterface *)malloc(sizeof(TapInterface)));
		memset((TapInterface *)asset, 0, sizeof(TapInterface));
		memset((uint8_t *)asset->buf, 0, sizeof(asset->buf));
		ret = init_tap_interface_gateway((TapInterface *)asset, config, ASSET);
		break;
	}

	if (ret < 0)
	{
		LOG_ERR("Failed to initialize tunnel");
		asset = asset;
	}
	gw->asset = asset;
	return ret;
}

int init_tunnel(const l2_gateway_config *config, l2_gateway *gw)
{
	L2_Gateway *tunnel = NULL;
	int ret = -1;
	switch (config->tunnel_type)
	{
	case PACKET_SOCKET:
		tunnel = (L2_Gateway *)((PacketSocket *)malloc(sizeof(PacketSocket)));
		memset((PacketSocket *)tunnel, 0, sizeof(PacketSocket));
		memset((uint8_t *)tunnel->buf, 0, sizeof(tunnel->buf));
		ret = init_packet_socket_gateway((PacketSocket *)tunnel, config, TUNNEL);
		break;
	case DTLS_SOCKET:
		tunnel = (L2_Gateway *)((DtlsSocket *)malloc(sizeof(DtlsSocket)));
		memset((DtlsSocket *)tunnel, 0, sizeof(DtlsSocket));
		memset((uint8_t *)tunnel->buf, 0, sizeof(tunnel->buf));
		ret = init_dtls_socket_gateway((DtlsSocket *)tunnel, config, TUNNEL);
		// ret = init_dt((PacketSocket*)tunnel ,config,TUNNEL);

		break;
	case UDP_SOCKET:
		LOG_ERR("UDP_SOCKET not implemented yet");
		break;
	case TAP_INTERFACE:
		tunnel = (L2_Gateway *)((TapInterface *)malloc(sizeof(TapInterface)));
		memset((TapInterface *)tunnel, 0, sizeof(TapInterface));
		memset((uint8_t *)tunnel->buf, 0, sizeof(tunnel->buf));
		ret = init_tap_interface_gateway((TapInterface *)tunnel, config, TUNNEL);
		break;
	}
	if (ret < 0)
	{
		LOG_ERR("Failed to initialize tunnel");
		free(tunnel);
		tunnel = NULL;
	}
	gw->tunnel = tunnel;
	return ret;
}

static void *l2_gateway_main_thread(void *ptr)
{
	l2_gateway *l2_gw_container = (l2_gateway *)ptr;
	const l2_gateway_config *config = &l2_gw_container->config;

	int ret = -1;
	reset_l2_gateway();
	ret = configure_interfaces(config);

	/* Set the new sockets to non-blocking */
	bool connected = false;
	// delay for 20 sec
	while (1)
	{
		if (connected)
		{
			// set asset link up
			ret = standard_transfer(l2_gw_container);
			if (ret < 0)
			{
				connected = false;
				if (l2_gw_container->asset != NULL)
				{
					l2_gateway_close(l2_gw_container->asset);
				}
				if (l2_gw_container->tunnel != NULL)
				{
					l2_gateway_close(l2_gw_container->tunnel);
				}
			}
		}
		else
		{
			ret = init_tunnel(config, l2_gw_container);
			if (ret < 0)
			{
				LOG_ERR("Failed to initialize tunnel");
				return NULL;
			}
			if (ret >= 0)
			{
				ret = init_asset(config, l2_gw_container);
				if (ret < 0)
				{
					LOG_ERR("Failed to initialize tunnel");
					return NULL;
				}
				marry_bridges(theBridge.asset, theBridge.tunnel);
				connected = true;
			}
			else
			{
				l2_gateway_close(l2_gw_container->tunnel);
			}
		}
	}

	return NULL;
	LOG_INF("L2 bridge main thread exiting");
}

void marry_bridges(L2_Gateway *bridge1, L2_Gateway *bridge2)
{
	bridge1->l2_gw_pipe = bridge2;
	bridge2->l2_gw_pipe = bridge1;
}

/* Terminate the Layer 2 bridge.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int l2_gateway_terminate(void)
{
	/* Stop the main thread */
	pthread_cancel(theBridge.thread);

	/* Close the sockets */
	l2_gateway_close(theBridge.asset);
	l2_gateway_close(theBridge.tunnel);

	return 0;
}
