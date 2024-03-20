#ifndef __PACKET_SOCKET_H__
#define __PACKET_SOCKET_H__

#include "l2_gateway.h"

#if !defined(__ZEPHYR__)
       #include <linux/if_packet.h>
       #include <net/ethernet.h> /* the L2 protocols */
       #endif


typedef struct PacketSocket PacketSocket;
struct PacketSocket
{
    L2_Gateway bridge;         /**< The bridge associated with the packet socket. */
    struct sockaddr_ll addr;   /**< The socket address. */
    struct sockaddr_ll source; /**< The source address, which is used by the recieve function. */
};

int init_packet_socket_gateway(PacketSocket *l2_gw, const l2_gateway_configg *config, connected_channel channel);

int init_packet_socket_bridge(PacketSocket *bridge,
                              const interface_config *interface,
                              connected_channel channel);

int packet_socket_send(PacketSocket *l2_gateway, uint8_t *buffer, int buffer_len, int frame_start);

int packet_socket_receive(PacketSocket *l2_gateway, int fd);

int packet_socket_pipe(PacketSocket *l2_gateway);

int packet_socket_close(PacketSocket *l2_gateway);

#endif //__PACKET_SOCKET_H__