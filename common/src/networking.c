
#include <errno.h>
#include <stdint.h>

#if defined(__ZEPHYR__)

#include <sys/socket.h>
#include <zephyr/posix/fcntl.h>
#include <zephyr/net/net_l2.h>

#elif defined(_WIN32)

#include <winsock2.h>
#include <sys/types.h>

#else

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#endif



#include "networking.h"
#include "logging.h"

LOG_MODULE_CREATE(networking);


static struct network_interfaces ifaces =
{
	.management = NULL,
	.lan = NULL,
	.wan = NULL
};


#if defined (__ZEPHYR__)


/* Callback to obtain the network interfaces */
static void iface_cb(struct net_if* iface, void* user_data)
{
	struct network_interfaces* ifaces = user_data;

	if (net_if_l2(iface) != &NET_L2_GET_NAME(ETHERNET)) {
		return;
	}

	if (iface == ifaces->management) {
		return;
	}

	if (ifaces->lan == NULL)
	{
		ifaces->lan = iface;
	}
	else
	{
		ifaces->wan = iface;
	}
}


/* Callback for ethernet link events */
static void iface_up_handler(struct net_mgmt_event_callback *cb, uint32_t mgmt_event, struct net_if *iface)
{
	const char* status = "err";

	if (iface == ifaces.management)
	{
		if (mgmt_event == NET_EVENT_L4_CONNECTED)
		{
			status = "up";
		}
		else if (mgmt_event == NET_EVENT_L4_DISCONNECTED)
		{
			status = "down";
		}

		LOG_INFO("Ethernet link %s (iface %p)", status, iface);
	}
}



/* Initialize the network interfaces */
int initialize_network_interfaces()
{
	/* Add an event handler to track ethernet link changes */
	static struct net_mgmt_event_callback iface_up_cb;
	net_mgmt_init_event_callback(&iface_up_cb, iface_up_handler, NET_EVENT_L4_CONNECTED | NET_EVENT_L4_DISCONNECTED);
	net_mgmt_add_event_callback(&iface_up_cb);

	/* Initialize the Management VLAN */
	ifaces.management = net_if_get_default();

	#if defined(CONFIG_NET_VLAN)
	int ret = net_eth_vlan_enable(ifaces.management, CONFIG_VLAN_TAG_MANAGEMENT);
	if (ret < 0)
	{
		LOG_ERROR("Cannot enable VLAN for tag %d: error %d", CONFIG_VLAN_TAG_MANAGEMENT, ret);
        	return ret;
	}
	#endif

	net_if_foreach(iface_cb, &ifaces);

	#if defined(CONFIG_NET_VLAN)
	/* Initialize LAN VLAN */
	ret = net_eth_vlan_enable(ifaces.lan, CONFIG_VLAN_TAG_LAN);
	if (ret < 0)
	{
		LOG_ERROR("Cannot enable VLAN for tag %d: error %d", CONFIG_VLAN_TAG_LAN, ret);
        return ret;
	}

	struct in_addr helper_addr;

	/* Set netmask and gateway for lan interface */
	ret = net_addr_pton(AF_INET, CONFIG_NET_PROD_LAN_IPV4_NETMASK, &helper_addr);
	if (ret != 0)
	{
		LOG_ERROR("Invalid netmask %s for the LAN interface: error %d", CONFIG_NET_PROD_LAN_IPV4_NETMASK, ret);
		return ret;
	}

	net_if_ipv4_set_netmask(ifaces.lan, &helper_addr);

	ret = net_addr_pton(AF_INET, CONFIG_NET_PROD_LAN_IPV4_GW, &helper_addr);
	if (ret != 0)
	{
		LOG_ERROR("Invalid gateway address %s for the LAN interface: error %d", CONFIG_NET_PROD_LAN_IPV4_GW, ret);
		return ret;
	}

	net_if_ipv4_set_gw(ifaces.lan, &helper_addr);

	/* Initialize WAN VLAN */
	ret = net_eth_vlan_enable(ifaces.wan, CONFIG_VLAN_TAG_WAN);
	if (ret < 0)
	{
		LOG_ERROR("Cannot enable VLAN for tag %d: error %d", CONFIG_VLAN_TAG_WAN, ret);
        return ret;
	}

	/* Set netmask and gateway for lan interface */
	ret = net_addr_pton(AF_INET, CONFIG_NET_PROD_WAN_IPV4_NETMASK, &helper_addr);
	if (ret != 0)
	{
		LOG_ERROR("Invalid netmask %s for the WAN interface: error %d", CONFIG_NET_PROD_WAN_IPV4_NETMASK, ret);
		return ret;
	}

	net_if_ipv4_set_netmask(ifaces.wan, &helper_addr);

	ret = net_addr_pton(AF_INET, CONFIG_NET_PROD_WAN_IPV4_GW, &helper_addr);
	if (ret != 0)
	{
		LOG_ERROR("Invalid gateway address %s for the WAN interface: error %d", CONFIG_NET_PROD_WAN_IPV4_GW, ret);
		return ret;
	}

	net_if_ipv4_set_gw(ifaces.wan, &helper_addr);
	#endif

	return 0;
}

/* Add an ip address to a network interface */
int add_ipv4_address(void* iface, struct in_addr ipv4_addr)
{
	int ret = -EINVAL;

	if (IS_ENABLED(CONFIG_NET_IPV4) && net_if_flag_is_set((struct net_if*) iface, NET_IF_IPV4))
	{
		struct net_if_addr* ifaddr = net_if_ipv4_addr_add((struct net_if*) iface, &ipv4_addr, NET_ADDR_MANUAL, 0);

		if (ifaddr)
		{
			ret = 0;
		}
	}

	return ret;
}

/* Remove an ip address from a network interface */
int remove_ipv4_address(void* iface, struct in_addr ipv4_addr)
{
	if (IS_ENABLED(CONFIG_NET_IPV4) && net_if_flag_is_set((struct net_if*) iface, NET_IF_IPV4))
	{
		net_if_ipv4_addr_rm((struct net_if*) iface, &ipv4_addr);
	}

	return 0;
}

#elif defined(_WIN32)

#include <stdio.h>

/* Initialize the network interfaces */
int initialize_network_interfaces()
{
	WSADATA wsaData;

	if(WSAStartup(0x202, &wsaData) == 0)
	{
		return 0;
	}
	else
	{
		printf("ERROR: Initialization failure.\n");
		return -1;
	}
}

#else //defined (__ZEPHYR__)

/* Initialize the network interfaces */
int initialize_network_interfaces()
{
    ifaces.management = "eth0";
    ifaces.lan = "vlan400";
    ifaces.wan = "vlan300";

    return 0;
}


int run_ip_shell_cmd(char const* command, char** output)
{
#define MALLOC_SIZE 4096

    *output = (char*) malloc(MALLOC_SIZE);

    if (*output == NULL)
    {
        return -ENOMEM;
    }

    /* Open a pipe to the command and execute it */
    FILE* fp = popen(command, "r");
    if (fp == NULL)
    {
         free(*output);
		 *output = NULL;
         return -errno;
    }

    /* Read the output */
    size_t bytesRead = 0;
    while (!feof(fp))
    {
      /* Read output */
      bytesRead += fread(*output + bytesRead, sizeof(char), MALLOC_SIZE - bytesRead, fp);
    }
    (*output)[bytesRead] = '\0';

    /* Close the pipe and read the return code of the executed command */
    return WEXITSTATUS(pclose(fp));
}


/* Add an ip address to a network interface */
int add_ipv4_address(void* iface, struct in_addr ipv4_addr)
{
	int ret = 0;
    char command[100];
	char* output = NULL;

    /* Create the command */
    snprintf(command, sizeof(command), "ip addr add %s/24 dev %s 2>&1", inet_ntoa(ipv4_addr), (char const*) iface);

    /* Run the command and catch return code and stdout + stderr */
	ret = run_ip_shell_cmd(command, &output);

    if (ret != 0)
    {
		if ((ret == 2) && (strcmp(output, "RTNETLINK answers: File exists\n") == 0))
		{
			/* IP address is already set, we continue silently */
			ret = 0;
		}
		else
		{
			LOG_ERROR("Command %s failed with error code %d (output %s)", ret, output);
		}
    }

    free(output);

	return ret;
}


/* Remove an ip address from a network interface */
int remove_ipv4_address(void* iface, struct in_addr ipv4_addr)
{
	int ret = 0;
    char command[100];
	char* output = NULL;

    /* Create the command */
    snprintf(command, sizeof(command), "ip addr del %s/24 dev %s 2>&1", inet_ntoa(ipv4_addr), (char const*) iface);

    /* Run the command and catch return code and stdout + stderr */
	ret = run_ip_shell_cmd(command, &output);

    if (ret != 0)
    {
		// ToDo: Update error message to the actual error
		if ((ret == 2) && (strcmp(output, "RTNETLINK answers: File exists\n") == 0))
		{
			/* IP address is already set, we continue silently */
			ret = 0;
		}
		else
		{
			LOG_ERROR("Command %s failed with error code %d (output %s)", ret, output);
		}
    }

    free(output);

	return ret;
}

#endif //defined (__ZEPHYR__)


/* Get a const pointer to the initialized structure containing the network interfaces */
struct network_interfaces const* network_interfaces(void)
{
    return &ifaces;
}


/* Helper method to set a socket to (non) blocking */
int setblocking(int fd, bool val)
{
#ifdef _WIN32
	unsigned long arg = 1;
	int ret = ioctlsocket(fd, FIONBIO, &arg);
	if (ret != NO_ERROR)
	{
		LOG_ERROR("ioctlsocket(FIONBIO): %d", ret);
		return ret;
	}
#else
	int fl, res;

	fl = fcntl(fd, F_GETFL, 0);
	if (fl == -1)
	{
		LOG_ERROR("fcntl(F_GETFL): %d", errno);
		return errno;
	}

	if (val)
	{
		fl &= ~O_NONBLOCK;
	}
	else
	{
		fl |= O_NONBLOCK;
	}

	res = fcntl(fd, F_SETFL, fl);
	if (res == -1)
	{
		LOG_ERROR("fcntl(F_SETFL): %d", errno);
		return errno;
	}

	return 0;
#endif
}

#include <stdio.h>

/* Generic method to create a socketpair for inter-thread communication */
int create_socketpair(int socket_pair[2])
{
#if defined(_WIN32)
	/* Implementation taken from:
	 * https://github.com/ncm/selectable-socketpair/blob/master/socketpair.c */
	union {
		struct sockaddr_in inaddr;
		struct sockaddr addr;
	} a;
	SOCKET listener;
	int e;
	socklen_t addrlen = sizeof(a.inaddr);
	DWORD flags = 0;
	int reuse = 1;

	if (socket_pair == 0) {
		WSASetLastError(WSAEINVAL);
		return SOCKET_ERROR;
	}
	socket_pair[0] = socket_pair[1] = -1;

	listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listener == -1) {
		int error = WSAGetLastError();
		printf("socket error: %d\n", error);
		return SOCKET_ERROR;
	}


	memset(&a, 0, sizeof(a));
	a.inaddr.sin_family = AF_INET;
	a.inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	a.inaddr.sin_port = 0;

	for (;;) {
		if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (char*) &reuse, (socklen_t) sizeof(reuse)) == -1)
			break;
		if (bind(listener, &a.addr, sizeof(a.inaddr)) == SOCKET_ERROR)
			break;

		memset(&a, 0, sizeof(a));
		if  (getsockname(listener, &a.addr, &addrlen) == SOCKET_ERROR)
			break;

		// win32 getsockname may only set the port number, p=0.0005.
		// ( http://msdn.microsoft.com/library/ms738543.aspx ):
		a.inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		a.inaddr.sin_family = AF_INET;

		if (listen(listener, 1) == SOCKET_ERROR)
			break;

		socket_pair[0] = WSASocketW(AF_INET, SOCK_STREAM, 0, NULL, 0, flags);
		if (socket_pair[0] == -1)
			break;

		if (connect(socket_pair[0], &a.addr, sizeof(a.inaddr)) == SOCKET_ERROR)
			break;

		socket_pair[1] = accept(listener, NULL, NULL);
		if (socket_pair[1] == -1)
			break;

		closesocket(listener);
		return 0;
	}

	e = WSAGetLastError();
	closesocket(listener);
	closesocket(socket_pair[0]);
	closesocket(socket_pair[1]);
	WSASetLastError(e);
	socket_pair[0] = socket_pair[1] = -1;
	return SOCKET_ERROR;

#else
	int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair);
	if (ret < 0)
		socket_pair[0] = socket_pair[1] = -1;

	return ret;
#endif
}
