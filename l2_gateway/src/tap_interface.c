
#include "tap_interface.h"

#if !defined(__ZEPHYR__)
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

#include "networking.h"
#include "logging.h"

LOG_MODULE_REGISTER(tap_interface);

/******************************************************************************************************
 *  Forward Declarations                                                                              *
 ******************************************************************************************************/
int tun_alloc(char *dev, int flags, const char *ip_addr);
int init_tap_interface_gateway(TapInterface *l2_gw, const l2_gateway_config *config, connected_channel channel);
int tap_interface_send(TapInterface *tap_interface, int fd, uint8_t *buffer, int buffer_len, int frame_start);
int tap_interface_receive(TapInterface *tap_interface, int _fd);
int tap_interface_close(TapInterface *tap_interface);
int tap_interface_pipe(TapInterface *tap_interface);


/******************************************************************************************************
 *  FUNCTION DEFINITIONS                                                                              *
 ******************************************************************************************************/

/**
 * Initializes the tap interface for the gateway.
 *
 * @param l2_gw The TapInterface structure to initialize.
 * @param config The l2_gateway_config structure containing the configuration settings.
 * @param channel The connected_channel enum specifying the channel type.
 * @return 0 on success, or a negative error code on failure.
 */
int init_tap_interface_gateway(TapInterface *l2_gw, const l2_gateway_config *config, connected_channel channel)
{
    // local function variables
    char *a_name;
    int tapfd = -1;
    int packet_socket_fd = -1; // packet_socket_fd is not used and remains -1

    memset(l2_gw->tap_name, 0, sizeof(l2_gw->tap_name));
    strcpy(l2_gw->tap_name, "tap-gw");

    /**
     * Create the tap interface
     * IFF_TAP: Request Tap Interface
     * IFF_NO_PI: Do not provide preceding packet information
     * IFF_VNET_HDR: Provide vnet header could be considered for future use
     * If ip addr provided, the ip addr will be assigned to the interface
     */
    tapfd = tun_alloc(l2_gw->tap_name,
                      IFF_TAP | IFF_NO_PI,
                      (channel == ASSET) ? config->asset_ip : config->tunnel_ip);
    if (tapfd < 0)
    {
        LOG_ERR("couldn't create tap interface: %d", errno);
        return tapfd;
    }

    // Get the interface index
    int ifindex = if_nametoindex(l2_gw->tap_name);

    /***
     * In case of using a packet socket on top the tap interface
     * @param send_sockaddr: sockaddr_ll structure to bind the socket to the interface
     */
    struct sockaddr_ll send_sockaddr;
    send_sockaddr.sll_family = AF_PACKET;
    send_sockaddr.sll_halen = ETH_ALEN;
    send_sockaddr.sll_ifindex = ifindex; // The number we just found earlier..
    send_sockaddr.sll_protocol = htons(ETH_P_ALL);
    send_sockaddr.sll_hatype = 0;
    send_sockaddr.sll_pkttype = 0;

    /**
     * @bug binding packet socket to tap interface is not working.
     * The packet is still receiving packets of different interfaces
     *
     * packet_socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
     * ret = bind(packet_socket_fd, (struct sockaddr *)&send_sockaddr, sizeof(send_sockaddr));
     * if (ret < 0)
     * {
     *     LOG_ERR("Error binding packet socket: %s", strerror(errno));
     *     return ret;
     * }
     * setblocking(packet_socket_fd, true);
     * l2_gw->packet_socket_fd = packet_socket_fd;
     */

    l2_gw->tap_iface_addr = send_sockaddr;
    l2_gw->packet_socket_fd = packet_socket_fd; // packet socket fd is not in use
    l2_gw->bridge.fd = tapfd;                   // tap interface file descriptor
    setblocking(tapfd, false);
    l2_gateway_register_fd(tapfd, POLLIN | POLLHUP | POLLERR);

    l2_gw->bridge.channel = channel;
    l2_gw->config = config;

    // register callbacks
    l2_gw->bridge.vtable[call_close] = tap_interface_close;
    l2_gw->bridge.vtable[call_send] = tap_interface_send;
    l2_gw->bridge.vtable[call_receive] = tap_interface_receive;
    l2_gw->bridge.vtable[call_pipe] = tap_interface_pipe;

    return 0;
}

/**
 * Sends data in @param buffer via the tap interface into the kernel space.
 *
 * @param tap_interface The TapInterface structure representing the tap interface.
 * @param fd The file descriptor which must be supplied do tue the interface l2_gateway_send function, but is !!not!! used.
 * @param buffer The buffer containing the data to be sent.
 * @param buffer_len The length of the buffer.
 * @param frame_start The starting index of the frame within the buffer.
 * @return The number of bytes sent, or -1 if an error occurred.
 */
int tap_interface_send(TapInterface *tap_interface, int fd, uint8_t *buffer, int buffer_len, int frame_start)
{
    int ret = -1;
    ret = write(tap_interface->bridge.fd,
                buffer + frame_start,
                buffer_len);
    if (ret < 0)
    {
        LOG_ERR("Error sending to tap interface: %d, %s", errno, strerror(errno));
    }
    else
    {
        LOG_INF("Sent %d bytes to tap interface", ret);
    }
    return ret;
}

/**
 * @brief Receives data from a tap interface and writes the data into the buffer of @param tap_interface.
 *
 * This function reads data from the tap interface associated with the given TapInterface object.
 * The received data is stored in the TapInterface's bridge buffer and the length of the received
 * data is updated accordingly.
 *
 * @param tap_interface The TapInterface object representing the tap interface.
 * @param _fd should be -1. It is not used in this function and just available because of the interface l2_gateway_send.
 * @return The number of bytes received from the tap interface, or -1 if an error occurred.
 */
int tap_interface_receive(TapInterface *tap_interface, int _fd)
{
    int ret = -1;
    ret = read(tap_interface->bridge.fd,
               tap_interface->bridge.buf,
               sizeof(tap_interface->bridge.buf));
    if (ret < 0)
    {
        LOG_ERR("Error reading from tap interface: %s", strerror(errno));
    }
    else if (ret == 0)
    {
        LOG_ERR("tap interface should be closed");
    }
    else
    {
        LOG_INF("Received %d bytes from tap interface", ret);
        tap_interface->bridge.len = ret;
    }
    return ret;
}

/**
 * @brief Sends data from the tap interface to the counterpart interface.
 *
 * This function sends data from the tap interface to the counterpart interface
 * (asset<->tunnel). It uses the l2_gateway_send() function to send the data.
 *
 * @param tap_interface The TapInterface structure representing the tap interface.
 * @return The return value of the l2_gateway_send() function.
 */
int tap_interface_pipe(TapInterface *tap_interface)
{
    int ret = -1;
    if (tap_interface->bridge.l2_gw_pipe == NULL)
    {
        LOG_ERR("Pipe is not connected");
        ret = -1;
        tap_interface->bridge.len = 0;
    }
    else
    {
        if (tap_interface->bridge.len == 0)
        {
            // there is no data to pipe
            ret = -1;
        }
        else
        {
            ret = l2_gateway_send(tap_interface->bridge.l2_gw_pipe,
                                  -1, // tap interface is not associated with a file descriptor
                                  tap_interface->bridge.buf,
                                  tap_interface->bridge.len,
                                  0);
            tap_interface->bridge.len = 0;
        }
    }
    return ret;
}

/**
 * @brief Closes a TapInterface.
 *
 * Since ioctl(tap_fd, TUNSETPERSIST, 1); is not set, the tap interface will be deleted after the file descriptor is clsoed
 * Then, the memmory of @param tap_interface is freed
 *
 * @param tap_interface The TapInterface to be closed.
 * @return 0 on success, -1 on failure.
 */
int tap_interface_close(TapInterface *tap_interface)
{
    close(tap_interface->bridge.fd);
    free(tap_interface);
    return 1;
}
/**
 * @brief Allocates a TUN/TAP interface.
 *
 * This function opens the clone device, prepares the necessary structures,
 * and tries to create the TUN/TAP device. If successful, it writes back the
 * name of the interface to the `dev` variable.
 *
 * @param dev The name of the interface (or '\0'). Must have enough space to
 *            hold the interface name if '\0' is passed.
 * @param flags Interface flags (e.g., IFF_TUN, IFF_TAP, IFF_NO_PI).
 * @param ip_addr The IP address to assign to the interface (optional).
 * @return The file descriptor for the virtual interface if successful,
 *         otherwise a negative value indicating an error.
 *
 * @todo it must be checked, if ip addr add is working with prefix len 24
 */

int tun_alloc(char *dev, int flags, const char *ip_addr)
{

    int ret = -1;
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    /* Arguments taken by the function:
     *
     * char *dev: the name of an interface (or '\0'). MUST have enough
     *   space to hold the interface name if '\0' is passed
     * int flags: interface flags (eg, IFF_TUN etc.)
     */

    /* open the clone device */
    if ((fd = open(clonedev, O_RDWR | O_CLOEXEC)) < 0)
    {
        return fd;
    }

    /* preparation of the struct ifr, of type "struct ifreq" */
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags; /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

    if (*dev)
    {
        /* if a device name was specified, put it in the structure; otherwise,
         * the kernel will try to allocate the "next" device of the
         * specified type */
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    /* try to create the device */
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
    {
        close(fd);
        return err;
    }

    if (flags & IFF_VNET_HDR)
    {
        int len = 12;
        // generate vnet header with 12 bytes len
        ret = ioctl(fd, TUNSETVNETHDRSZ, &(int){len});
        if (ret != 0)
        {
            LOG_ERR("ioctl(TUNSETVNETHDRSZ)");
        }
    }

    /* if the operation was successful, write back the name of the
     * interface to the variable "dev", so the caller can know
     * it. Note that the caller MUST reserve space in *dev (see calling
     * code below) */
    strcpy(dev, ifr.ifr_name);
    uint8_t cmd[200];
    sprintf(cmd, "ip link set dev %s up", dev);
    system(cmd);

    // If ip addr is provided, assign the ip address to the interface
    if (ip_addr != NULL)
    {
        memset(cmd, sizeof(cmd), 0);
        sprintf(cmd, "sudo ip a add %s/24 dev %s", ip_addr, dev);
        system(cmd);
        return fd;
    }

    // Set IFF_UP flag
    /* this is the special file descriptor that the caller will use to talk
     * with the virtual interface */
    return fd;
}
#endif