
#ifndef __PACKET_SOCKET_H__
#define __PACKET_SOCKET_H__

#include <zephyr/kernel.h>
#include <zephyr/net/sockets>
#include "l2_bridge.h"

typedef struct PacketSocket PacketSocket;
struct PacketSocket
{
    int (*vtable[3])();
    uint8_t buf[2048];
    uint32_t len;
    interface_type type;
    connected_channel channel;
    Bridge *pipe;
    int fd;
};

int packet_socket_send(Bridge *bridge, uint8_t *data, size_t len);
int packet_socket_receive(Bridge *bridge);
int packet_socket_pipe(Bridge *bridge, void *data, size_t len);

#endif //__PACKET_SOCKET_H__