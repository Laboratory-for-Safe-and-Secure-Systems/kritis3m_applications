
#ifndef __PACKET_SOCKET_H__
#define __PACKET_SOCKET_H__


#include <zephyr/net/ethernet.h>
#include "l2_bridge.h"


typedef struct PacketSocket PacketSocket;
struct PacketSocket
{
    Bridge bridge;
    struct sockaddr_ll addr;
};

int init_packet_socket_bridge(PacketSocket* bridge); 
int packet_socket_send(PacketSocket *bridge, uint8_t *data, size_t len);
int packet_socket_receive(PacketSocket *bridge);
int packet_socket_pipe(PacketSocket *bridge, uint8_t *data, size_t len);

#endif //__PACKET_SOCKET_H__