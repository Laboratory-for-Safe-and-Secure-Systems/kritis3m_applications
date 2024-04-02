
#include "tap_interface.h"

#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include <errno.h>
#include <netinet/in.h>   // IPPROTO_*
#include <net/if.h>       // ifreq
#include <linux/if_tun.h> // IFF_TUN, IFF_NO_PI

#include <sys/ioctl.h>

#include "networking.h"
#include "logging.h"

LOG_MODULE_REGISTER(tap_interface);

int tun_alloc(char *dev, int flags);

int init_tap_interface_gateway(TapInterface *l2_gw, const l2_gateway_config *config, connected_channel channel)
{
    char *a_name;
    int tapfd = -1;

    memset(l2_gw->tap_name, 0, sizeof(l2_gw->tap_name));
    strcpy(l2_gw->tap_name, "tap-gw");

    // switch off additional meta data
    tapfd = tun_alloc(l2_gw->tap_name, IFF_TAP | IFF_NO_PI); /* tap interface */

    if (tapfd < 0)
    {
        LOG_ERR("couldn't create tap interface: %s", strerror(errno));
        return tapfd;
    }

    l2_gw->bridge.fd = tapfd;
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

int tap_interface_send(TapInterface *tap_interface, int fd, uint8_t *buffer, int buffer_len, int frame_start)
{
    return send(tap_interface->bridge.fd,
                buffer + frame_start,
                buffer_len - frame_start,
                0);
}
int tap_interface_receive(TapInterface *tap_interface, int fd, int (*regiser_cb)(int fd))
{
    return read(tap_interface->bridge.fd,
                tap_interface->bridge.buf,
                tap_interface->bridge.len);
}
int tap_interface_pipe(TapInterface *tap_interface)
{
    return l2_gateway_send(tap_interface->bridge.l2_gw_pipe,
                           tap_interface->bridge.fd,
                           tap_interface->bridge.buf,
                           tap_interface->bridge.len,
                           0);
}

int tap_interface_close(TapInterface *tap_interface)
{
    close(tap_interface->bridge.fd);
    char command[64];
    memset(command, 0, 64);
    sprintf(command, "ip link delete %s", tap_interface->tap_name);
    return system(command);
}

int tun_alloc(char *dev, int flags)
{

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

    /* if the operation was successful, write back the name of the
     * interface to the variable "dev", so the caller can know
     * it. Note that the caller MUST reserve space in *dev (see calling
     * code below) */
    strcpy(dev, ifr.ifr_name);

    /* this is the special file descriptor that the caller will use to talk
     * with the virtual interface */
    return fd;
}