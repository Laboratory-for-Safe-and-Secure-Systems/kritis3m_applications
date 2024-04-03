
#ifndef __TAP_INTERFACE_H_
#define __TAP_INTERFACE_H_

#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "l2_gateway.h"

#if !defined(__ZEPHYR__)
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */

typedef struct TapInterface TapInterface;
struct TapInterface
{
    L2_Gateway bridge; // The bridge associated with the packet socket.
    int packet_socket_fd; // The file descriptor for the packet socket, which is not used by now.
    struct sockaddr_ll tap_iface_addr; // the link address of the tap interace
    const l2_gateway_config *config; // the general config
    char tap_name[IFNAMSIZ]; // the name of the tap interface
};

// the function to initialize the tap interface
int init_tap_interface_gateway(TapInterface *l2_gw, const l2_gateway_config *config, connected_channel channel);

#endif

#endif //__PACKET_SOCKET_H__