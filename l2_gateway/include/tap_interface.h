
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
    L2_Gateway bridge; /**< The bridge associated with the packet socket. */
    const l2_gateway_config *config;
    char tap_name[IFNAMSIZ]; /**< The name of the tap interface. */
};

int init_tap_interface_gateway(TapInterface *l2_gw, const l2_gateway_config *config, connected_channel channel);

int tap_interface_send(TapInterface *tap_interface, int fd, uint8_t *buffer, int buffer_len, int frame_start);
int tap_interface_receive(TapInterface *tap_interface, int fd, int (*regiser_cb)(int fd));
int tap_interface_pipe(TapInterface *tap_interface);
int tap_interface_close(TapInterface *tap_interface);

#endif

#endif //__PACKET_SOCKET_H__