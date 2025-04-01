
#include <errno.h>
#include <stdint.h>

#if defined(__ZEPHYR__)

#include <ctype.h>
#include <sys/socket.h>
#include <zephyr/net/net_l2.h>
#include <zephyr/posix/fcntl.h>

#elif defined(_WIN32)

#include <sys/types.h>
#include <winsock2.h>

#else

#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>

#endif

#include "file_io.h"
#include "logging.h"
#include "networking.h"

LOG_MODULE_CREATE(networking);

#define ERROR_OUT(...)                                                                             \
        {                                                                                          \
                LOG_ERROR(__VA_ARGS__);                                                            \
                goto cleanup;                                                                      \
        }

static struct network_interfaces ifaces = {
        .management = NULL,
        .lan = NULL,
        .wan = NULL,
};

static int is_numeric(char const* str)
{
        while (*str)
        {
                if (!isdigit(*str))
                        return 0;
                str++;
        }

        return 1;
}

/**
 * @brief Parses an input string to extract an IP address and port number.
 *
 * @param input The input string containing an IP address and/or port (e.g., "127.0.0.1:4433",
 * "[::1]:4433", "localhost:4433").
 * @param ip Pointer to a string where the extracted IP address will be stored. Memory is allocated
 * dynamically and must be freed by the caller.
 * @param port Pointer to a `uint16_t` where the extracted port number will be stored. If no port is
 * provided, it will be set to 0.
 * @return 0 on success, -1 on failure (error messages are logged).
 *
 * @note The function supports IPv4, IPv6, and URI formats, and checks for invalid port numbers or
 * malformed input.
 */
int parse_ip_address(char* input, char** ip, uint16_t* port)
{
        /* Search for the first colon.
         *
         * 1) If non is found, we have either only an IPv4 address, or only an URI, or
         *    only a port number, e.g. "127.0.0.1", "localhost" or "4433".
         *
         * 2) If we only find a single colon, we have either an IPv4 address or an URI
         *    with a port number, e.g. "127.0.0.1:4433" or "localhost:4433".
         *
         * 3) If we find multiple colons, we have an IPv6 address. In this case, we have
         *    to check whether a port is also provided. If so, the IPv6 address must be
         *    wrapped in square brackets, e.g. "[::1]:4433".
         *    Otherwise, only an address is given, e.g. "::1".
         *
         * Rough code at the momemt, but it works for now...
         * ToDo: Refactor this code to make it more readable and maintainable.
         */
        char* first_colon = strchr(input, ':');

        if (first_colon == NULL)
        {
                /* First case */

                struct in_addr addr;
                if (net_addr_pton(AF_INET, input, &addr) == 1)
                {
                        /* We have an IPv4 address */
                        *ip = duplicate_string(input);
                        if (*ip == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for IP address");
                                return -1;
                        }
                        *port = 0;
                }
                else if (is_numeric(input))
                {
                        /* We have a port number */
                        *ip = NULL;
                        unsigned long new_port = strtoul(input, NULL, 10);
                        if ((new_port == 0) || (new_port > 65535))
                        {
                                LOG_ERROR("invalid port number %lu", new_port);
                                return -1;
                        }
                        *port = (uint16_t) new_port;
                }
                else
                {
                        /* We have an URI */
                        *ip = duplicate_string(input);
                        if (*ip == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for IP address");
                                return -1;
                        }
                        *port = 0;
                }
        }
        else
        {
                char* last_colon = strchr(first_colon + 1, ':');

                if (last_colon == NULL)
                {
                        /* Second case */

                        *first_colon = '\0';
                        *ip = duplicate_string(input);
                        if (*ip == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for IP address");
                                return -1;
                        }
                        unsigned long new_port = strtoul(first_colon + 1, NULL, 10);
                        if ((new_port == 0) || (new_port > 65535))
                        {
                                LOG_ERROR("invalid port number %lu", new_port);
                                return -1;
                        }
                        *port = (uint16_t) new_port;
                }
                else
                {
                        /* Third case */

                        /* Move to the last colon*/
                        char* tmp = last_colon;
                        while ((tmp = strchr(tmp + 1, ':')) != NULL)
                        {
                                last_colon = tmp;
                        }

                        if (*(last_colon - 1) == ']')
                        {
                                if (*input != '[')
                                {
                                        LOG_ERROR("invalid IPv6 address: %s", input);
                                        return -1;
                                }

                                /* Port is given */
                                *(last_colon - 1) = '\0';

                                *ip = duplicate_string(input + 1);
                                if (*ip == NULL)
                                {
                                        LOG_ERROR("unable to allocate memory for IP address");
                                        return -1;
                                }
                                unsigned long new_port = strtoul(last_colon + 1, NULL, 10);
                                if ((new_port == 0) || (new_port > 65535))
                                {
                                        LOG_ERROR("invalid port number %lu", new_port);
                                        return -1;
                                }
                                *port = (uint16_t) new_port;
                        }
                        else
                        {
                                /* Check if the user wrongly provided a port without square brackets */
                                *last_colon = '\0';
                                struct in6_addr addr;
                                if (net_addr_pton(AF_INET6, input, &addr) == 1)
                                {
                                        *last_colon = ':';
                                        LOG_ERROR("missing square brackets around IPv6 address "
                                                  "before port: %s",
                                                  input);
                                        return -1;
                                }
                                *last_colon = ':';

                                /* No port given */
                                *ip = duplicate_string(input);
                                if (*ip == NULL)
                                {
                                        LOG_ERROR("unable to allocate memory for IP address");
                                        return -1;
                                }
                                *port = 0;
                        }
                }
        }

        return 0;
}

/**
 * @brief Parses an IP address and CIDR prefix from a string.
 *
 * Extracts the IP address and CIDR prefix from a `<ip_address>/<cidr>` format.
 * Validates the IP address format using `inet_pton`. Ensures buffers are sufficient.
 *
 * @param[in]  ip_cidr    Input string with IP/CIDR.
 * @param[out] ip_addr    Buffer to store the IP address.
 * @param[in]  ip_len     Length of the IP address buffer.
 * @param[out] cidr       Buffer to store the CIDR prefix.
 * @param[in]  cidr_len   Length of the CIDR buffer.
 *
 * @return int 0 on success, -1 on error (e.g., invalid format, insufficient buffer).
 */
int parse_ip_cidr(const char* ip_cidr, char* ip_addr, size_t ip_len, char* cidr, size_t cidr_len)
{
        if (!ip_cidr || !ip_addr || !cidr || ip_len == 0 || cidr_len == 0)
        {
                return -1; // Invalid parameters
        }

        // Locate the slash separating IP and CIDR
        const char* slash = strchr(ip_cidr, '/');
        if (!slash)
        {
                return -1; // No CIDR part found
        }

        // Calculate the length of the IP address part
        size_t ip_part_len = slash - ip_cidr;
        if (ip_part_len >= ip_len)
        {
                return -1; // IP address buffer is too small
        }

        // Copy and null-terminate the IP address
        strncpy(ip_addr, ip_cidr, ip_part_len);
        ip_addr[ip_part_len] = '\0';

        // Validate the IP address format (IPv4 or IPv6)
        struct in_addr ipv4;
        struct in6_addr ipv6;
        if (inet_pton(AF_INET, ip_addr, &ipv4) != 1 && inet_pton(AF_INET6, ip_addr, &ipv6) != 1)
        {
                return -1; // Invalid IP address
        }

        // Copy and null-terminate the CIDR prefix
        size_t cidr_part_len = strlen(slash + 1);
        if (cidr_part_len >= cidr_len)
        {
                return -1; // CIDR buffer is too small
        }
        strncpy(cidr, slash + 1, cidr_len - 1);
        cidr[cidr_len - 1] = '\0';

        return 0;
}

/**
 * @brief Checks if the given IP address is a valid IPv6 address.
 *
 * Uses `inet_pton` to determine if the provided IP string is a valid IPv6 address.
 *
 * @param[in] ip_str Input string containing the IP address.
 *
 * @return int 1 if the IP is a valid IPv6 address, 0 otherwise.
 */
int is_ipv6(const char* ip_str)
{
        if (!ip_str)
        {
                return 0; // Null input is not a valid IPv6 address
        }

        struct in6_addr ipv6;
        return inet_pton(AF_INET6, ip_str, &ipv6) == 1;
}

#if defined(__ZEPHYR__)

/* Callback to obtain the network interfaces */
static void iface_cb(struct net_if* iface, void* user_data)
{
        struct network_interfaces* ifaces = user_data;

        if (net_if_l2(iface) != &NET_L2_GET_NAME(ETHERNET))
        {
                return;
        }

        if (iface == ifaces->management)
        {
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
static void iface_up_handler(struct net_mgmt_event_callback* cb, uint32_t mgmt_event, struct net_if* iface)
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
int initialize_network_interfaces(int32_t log_level)
{
        /* Add an event handler to track ethernet link changes */
        static struct net_mgmt_event_callback iface_up_cb;
        net_mgmt_init_event_callback(&iface_up_cb,
                                     iface_up_handler,
                                     NET_EVENT_L4_CONNECTED | NET_EVENT_L4_DISCONNECTED);
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
                LOG_ERROR("Invalid netmask %s for the LAN interface: error %d",
                          CONFIG_NET_PROD_LAN_IPV4_NETMASK,
                          ret);
                return ret;
        }

        net_if_ipv4_set_netmask(ifaces.lan, &helper_addr);

        ret = net_addr_pton(AF_INET, CONFIG_NET_PROD_LAN_IPV4_GW, &helper_addr);
        if (ret != 0)
        {
                LOG_ERROR("Invalid gateway address %s for the LAN interface: error %d",
                          CONFIG_NET_PROD_LAN_IPV4_GW,
                          ret);
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
                LOG_ERROR("Invalid netmask %s for the WAN interface: error %d",
                          CONFIG_NET_PROD_WAN_IPV4_NETMASK,
                          ret);
                return ret;
        }

        net_if_ipv4_set_netmask(ifaces.wan, &helper_addr);

        ret = net_addr_pton(AF_INET, CONFIG_NET_PROD_WAN_IPV4_GW, &helper_addr);
        if (ret != 0)
        {
                LOG_ERROR("Invalid gateway address %s for the WAN interface: error %d",
                          CONFIG_NET_PROD_WAN_IPV4_GW,
                          ret);
                return ret;
        }

        net_if_ipv4_set_gw(ifaces.wan, &helper_addr);
#endif

        return 0;
}

#elif defined(_WIN32)

#include <stdio.h>

/* Initialize the network interfaces */
int initialize_network_interfaces(int32_t log_level)
{
        WSADATA wsaData;

        LOG_LVL_SET(log_level);

        if (WSAStartup(0x202, &wsaData) == 0)
        {
                return 0;
        }
        else
        {
                LOG_ERROR("Network initialization failed.\n");
                return -1;
        }
}

#else // Linux

/* Initialize the network interfaces */
int initialize_network_interfaces(int32_t log_level)
{
        ifaces.management = "eth0";
        ifaces.lan = "vlan400";
        ifaces.wan = "vlan300";

        LOG_LVL_SET(log_level);

        return 0;
}

#endif

#ifdef __ZEPHYR__

/* Add an ip address to a network interface */
int add_ip_address(const void* iface, const char* ip_addr, const char* cidr, bool is_ipv6)
{
        int ret = -EINVAL;

        if (is_ipv6 && IS_ENABLED(CONFIG_NET_IPV6) &&
            net_if_flag_is_set((struct net_if*) iface, NET_IF_IPV6))
        {
                struct in6_addr helper_addr;

                /* Convert ip string */
                ret = net_addr_pton(AF_INET6, ip_addr, &helper_addr);
                if (ret != 0)
                {
                        LOG_ERROR("Invalid IP address \"%s\": error %d", ip_addr, ret);
                        return ret;
                }

                struct net_if_addr* ifaddr = net_if_ipv6_addr_add((struct net_if*) iface,
                                                                  &helper_addr,
                                                                  NET_ADDR_MANUAL,
                                                                  0);
                if (ifaddr)
                        ret = 0;

                /* ToDo: Parse CIDR to properly set Netmask */
        }
        else if (IS_ENABLED(CONFIG_NET_IPV4) && net_if_flag_is_set((struct net_if*) iface, NET_IF_IPV4))
        {
                struct in_addr helper_addr;

                /* Convert ip string */
                ret = net_addr_pton(AF_INET, ip_addr, &helper_addr);
                if (ret != 0)
                {
                        LOG_ERROR("Invalid IP address \"%s\": error %d", ip_addr, ret);
                        return ret;
                }

                struct net_if_addr* ifaddr = net_if_ipv4_addr_add((struct net_if*) iface,
                                                                  &helper_addr,
                                                                  NET_ADDR_MANUAL,
                                                                  0);
                if (ifaddr)
                        ret = 0;

                /* ToDo: Parse CIDR to properly set Netmask */
        }

        return ret;
}

/* Remove an ip address from a network interface */
int remove_ipv4_address(const void* iface, const char* ip_addr, const char* cidr, bool is_ipv6)
{
        int ret = -EINVAL;

        if (is_ipv6 && IS_ENABLED(CONFIG_NET_IPV6) &&
            net_if_flag_is_set((struct net_if*) iface, NET_IF_IPV6))
        {
                struct in6_addr helper_addr;

                /* Convert ip string */
                ret = net_addr_pton(AF_INET6, ip_addr, &helper_addr);
                if (ret != 0)
                {
                        LOG_ERROR("Invalid IP address \"%s\": error %d", ip_addr, ret);
                        return ret;
                }

                if (net_if_ipv6_addr_rm((struct net_if*) iface, &helper_addr))
                        ret = 0;
        }
        else if (IS_ENABLED(CONFIG_NET_IPV4) && net_if_flag_is_set((struct net_if*) iface, NET_IF_IPV4))
        {
                struct in_addr helper_addr;

                /* Convert ip string */
                ret = net_addr_pton(AF_INET, ip_addr, &helper_addr);
                if (ret != 0)
                {
                        LOG_ERROR("Invalid IP address \"%s\": error %d", ip_addr, ret);
                        return ret;
                }

                if (net_if_ipv4_addr_rm((struct net_if*) iface, &helper_addr))
                        ret = 0;
        }

        return ret;
}

#else /* _WIN32 and Linux */

int run_shell_cmd(char const* command, char** output)
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
        int status = pclose(fp);

#ifndef _WIN32
        /* ask how the process ended to clean up the exit code. */
        if (WIFEXITED(status))
                status = WEXITSTATUS(status);
        else if (WIFSIGNALED(status))
                status = WTERMSIG(status);
        else if (WIFSTOPPED(status))
                status = WSTOPSIG(status);
#else
        /* Do we have to do something here? */
#endif

        return status;
}

/* Add an ip address to a network interface */
int add_ip_address(const void* iface, const char* ip_addr, const char* cidr, bool is_ipv6)
{
        int ret = 0;
        char command[100];
        char* output = NULL;

        /* Create the command */
#ifdef _WIN32
        snprintf(command,
                 sizeof(command),
                 "netsh interface %s add address \"%s\" %s/%s",
                 is_ipv6 ? "ipv6" : "ipv4",
                 (char const*) iface,
                 ip_addr,
                 cidr);
#else
        snprintf(command,
                 sizeof(command),
                 "ip %s addr add %s/%s dev %s 2>&1",
                 is_ipv6 ? "-6" : "-4",
                 ip_addr,
                 cidr,
                 (char const*) iface);
#endif

        /* Run the command and catch return code and stdout + stderr */
        ret = run_shell_cmd(command, &output);

        if (ret != 0)
        {
#ifndef _WIN32
                if ((ret == 2) && (strcmp(output, "RTNETLINK answers: File exists\n") == 0))
                {
                        /* IP address is already set, we continue silently */
                        ret = 0;
                }
                else
#endif
                {
                        LOG_ERROR("Command %s failed with error code %d (output %s)", ret, output);
                }
        }

        free(output);

        return ret;
}

/* Remove an ip address from a network interface */
int remove_ip_address(const void* iface, const char* ip_addr, const char* cidr, bool is_ipv6)
{
        int ret = 0;
        char command[100];
        char* output = NULL;

        /* Create the command */
#ifdef _WIN32
        snprintf(command,
                 sizeof(command),
                 "netsh interface %s delete address \"%s\" %s/%s",
                 is_ipv6 ? "ipv6" : "ipv4",
                 (char const*) iface,
                 ip_addr,
                 cidr);
#else
        snprintf(command, sizeof(command), "ip addr del %s/%s dev %s 2>&1", ip_addr, cidr, (char const*) iface);
#endif

        /* Run the command and catch return code and stdout + stderr */
        ret = run_shell_cmd(command, &output);

        if (ret != 0)
        {
                // ToDo: Update error message to the actual error
#ifndef _WIN32
                if ((ret == 2) && (strcmp(output, "RTNETLINK answers: File exists\n") == 0))
                {
                        /* IP address is already set, we continue silently */
                        ret = 0;
                }
                else
#endif
                {
                        LOG_ERROR("Command %s failed with error code %d (output %s)", ret, output);
                }
        }

        free(output);

        return ret;
}

#endif /* __ZEPHYR__ */

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

        return 0;
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
        union
        {
                struct sockaddr_in inaddr;
                struct sockaddr addr;
        } a;
        SOCKET listener;
        int e;
        socklen_t addrlen = sizeof(a.inaddr);
        DWORD flags = 0;
        int reuse = 1;

        if (socket_pair == 0)
        {
                WSASetLastError(WSAEINVAL);
                return SOCKET_ERROR;
        }
        socket_pair[0] = socket_pair[1] = -1;

        listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == -1)
        {
                int error = WSAGetLastError();
                printf("socket error: %d\n", error);
                return SOCKET_ERROR;
        }

        memset(&a, 0, sizeof(a));
        a.inaddr.sin_family = AF_INET;
        a.inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.inaddr.sin_port = 0;

        for (;;)
        {
                if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (char*) &reuse, (socklen_t) sizeof(reuse)) ==
                    -1)
                        break;
                if (bind(listener, &a.addr, sizeof(a.inaddr)) == SOCKET_ERROR)
                        break;

                memset(&a, 0, sizeof(a));
                if (getsockname(listener, &a.addr, &addrlen) == SOCKET_ERROR)
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

static int address_lookup_internal(char const* dest,
                                   uint16_t port,
                                   struct addrinfo** addr,
                                   int family,
                                   int flags)
{
        struct addrinfo hints = {.ai_family = family,
                                 .ai_socktype = SOCK_STREAM,
                                 .ai_protocol = IPPROTO_TCP,
                                 .ai_flags = flags};
        char port_str[6];
        char* port_str_ptr = port_str;

#if defined(__ZEPHYR__)
        if (port == 0)
                /* To select a random port in Zephyr, we have to pass NULL as `service` to getaddrinfo()*/
                port_str_ptr = NULL;
        else
#endif
                snprintf(port_str, sizeof(port_str), "%d", port);

        int ret = getaddrinfo(dest, port_str_ptr, &hints, addr);
        if (ret != 0)
        {
                if (dest)
                        LOG_ERROR("getaddrinfo failed for %s:%d: %s", dest, port, gai_strerror(ret));
                else
                        LOG_ERROR("getaddrinfo failed for port %d: %s", port, gai_strerror(ret));
                return -1;
        }

        return 0;
}

/* Lookup the provided outgoing destination and fill the linked-list accordingly. */
int address_lookup_client(char const* dest, uint16_t port, struct addrinfo** addr, int family)
{
        return address_lookup_internal(dest, port, addr, family, AI_NUMERICSERV | AI_ADDRCONFIG);
}

/* Lookup the provided incoming destination and fill the linked-list accordingly. */
int address_lookup_server(char const* dest, uint16_t port, struct addrinfo** addr, int family)
{
        return address_lookup_internal(dest, port, addr, family, AI_PASSIVE | AI_NUMERICSERV | AI_ADDRCONFIG);
}

/* Create a new listening socket for given type and address.
 *
 * Return value is the socket file descriptor or -1 in case of an error.
 */
int create_listening_socket(int type, struct sockaddr* addr, socklen_t addr_len)
{
        int sock = -1;
        char ip_str[INET6_ADDRSTRLEN];

        if (type == AF_INET)
                net_addr_ntop(type, &((struct sockaddr_in*) addr)->sin_addr, ip_str, sizeof(ip_str));
        else if (type == AF_INET6)
                net_addr_ntop(type, &((struct sockaddr_in6*) addr)->sin6_addr, ip_str, sizeof(ip_str));

        /* Prepare the socket */
        sock = socket(type, SOCK_STREAM, IPPROTO_TCP);

        if (sock == -1)
                ERROR_OUT("Error creating incoming TCP socket");

        if (type == AF_INET6)
        {
                if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*) &(int) {1}, sizeof(int)) < 0)
                        ERROR_OUT("setsockopt(IPV6_V6ONLY) failed: error %d\n", errno);
        }

        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*) &(int) {1}, sizeof(int)) < 0)
                ERROR_OUT("setsockopt(SO_REUSEADDR) failed: error %d\n", errno);

        if (bind(sock, addr, addr_len) < 0)
                ERROR_OUT("Cannot bind socket %d to %s:%d: error %d\n",
                          sock,
                          ip_str,
                          ntohs(((struct sockaddr_in*) addr)->sin_port),
                          errno);

        /* If a random port have been used, obtain the actually selected one */
        if (ntohs(((struct sockaddr_in*) addr)->sin_port) == 0)
        {
                if (getsockname(sock, addr, &addr_len) < 0)
                        ERROR_OUT("getsockname failed with errno: %d", errno);
        }

        if (listen(sock, 5) < 0)
                ERROR_OUT("Error listening on socket %d: %d", sock, errno);

        if (setblocking(sock, false) != 0)
                ERROR_OUT("Error setting socket to non-blocking");

        LOG_DEBUG("Listening on %s:%d", ip_str, ntohs(((struct sockaddr_in*) addr)->sin_port));

        return sock;

cleanup:
        if (sock != -1)
                closesocket(sock);

        return -1;
}

/* Create a new client socket for given type and address.
 *
 * Return value is the socket file descriptor or -1 in case of an error
 */
int create_client_socket(int type)
{
        int sock = -1;

        /* Create the socket */
        sock = socket(type, SOCK_STREAM, IPPROTO_TCP);

        if (sock == -1)
                ERROR_OUT("Error creating TCP client socket");

        /* Set TCP_NODELAY option to disable Nagle algorithm */
        if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*) &(int) {1}, sizeof(int)) < 0)
                ERROR_OUT("setsockopt(TCP_NODELAY) failed: error %d", errno);

#if !defined(__ZEPHYR__) && !defined(_WIN32)
        /* Set retry count to send a total of 3 SYN packets => Timeout ~7s */
        if (setsockopt(sock, IPPROTO_TCP, TCP_SYNCNT, (char*) &(int) {2}, sizeof(int)) < 0)
                ERROR_OUT("setsockopt(TCP_SYNCNT) failed: error %d", errno);
#endif

        return sock;

cleanup:
        if (sock != -1)
                closesocket(sock);

        return -1;
}

/* Configure a peer socket obtained from an accept() call to a listening socket.
 *
 * Returns 0 in case of success, -1 otherwise.
 */
int configure_peer_socket(int peer_sock)
{
        /* Set TCP_NODELAY option to disable Nagle algorithm */
        if (setsockopt(peer_sock, IPPROTO_TCP, TCP_NODELAY, (char*) &(int) {1}, sizeof(int)) < 0)
        {
                LOG_ERROR("setsockopt(TCP_NODELAY) failed: error %d", errno);
                return -1;
        }

        return 0;
}
