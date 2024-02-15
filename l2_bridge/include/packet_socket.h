
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
int packet_socket_send(PacketSocket *bridge, uint8_t *buffer, int buffer_len, int frame_start);
int packet_socket_receive(PacketSocket *bridge);
int packet_socket_pipe(PacketSocket *bridge);

#endif //__PACKET_SOCKET_H__