

#ifndef __UDP_SOCKET_H__
#define __UDP_SOCKET_H__

#include <unistd.h> // Include the necessary header file for the 'close' function
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "networking.h"

#if defined(__ZEPHYR__)
#include <zephyr/net/ethernet.h>
#else
#include <errno.h>      //For errno - the error number
#include <netinet/ip.h> //Provides declarations for ip header
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */ // inet_addr
#include <net/if.h>

#include <netinet/in.h>
#endif

#include "l2_gateway.h"

typedef struct UdpSocket UdpSocket;
struct UdpSocket
{
    L2_Gateway bridge;         /**< The bridge associated with the packet socket. */
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
