

#ifndef __UDP_SOCKET_H__
#define __UDP_SOCKET_H__

#include <zephyr/net/ethernet.h>
#include <zephyr/net/net_ip.h>

#include "l2_gateway.h"

typedef struct UdpSocket UdpSocket;
struct UdpSocket
{
    L2_Gateway bridge;             /**< The bridge associated with the packet socket. */
    struct sockaddr_in addr;   /**< The socket address. */
    struct sockaddr_in source; /**< The source address, which is used by the recieve function. */
};

int init_udp_socket_bridge(UdpSocket *bridge,
                           const interface_config *interface,
                           connected_channel channel);

int udp_socket_send(UdpSocket *bridge, uint8_t *buffer, int buffer_len, int frame_start);

int udp_socket_receive(UdpSocket *bridge);

int udp_socket_pipe(UdpSocket *bridge);

int udp_socket_close(UdpSocket *bridge);

#endif //__UDP_SOCKET_H_
