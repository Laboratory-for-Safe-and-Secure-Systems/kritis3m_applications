#ifndef __PACKET_SOCKET_H__
#define __PACKET_SOCKET_H__

#include <zephyr/net/ethernet.h>
#include "l2_bridge.h"

/**
 * @brief Structure representing a packet socket.
 * 
 * This structure encapsulates the necessary information for a packet socket,
 * including the bridge, socket addresses, and source address.
 */
typedef struct PacketSocket PacketSocket;
struct PacketSocket
{
    Bridge bridge;                  /**< The bridge associated with the packet socket. */
    struct sockaddr_ll addr;        /**< The socket address. */
    struct sockaddr_ll source;      /**< The source address, which is used by the recieve function. */
};

/**
 * @brief Initialize a packet socket bridge.
 * 
 * This function initializes a packet socket bridge with the given interface configuration
 * and connected channel.
 * 
 * @param bridge The packet socket bridge to initialize.
 * @param interface The interface configuration.
 * @param channel The cannel, the bridge is connected to. 
 * @return 0 on success, negative error code on failure.
 */
int init_packet_socket_bridge(PacketSocket *bridge,
                              const interface_config *interface,
                              connected_channel channel);

/**
 * @brief Send a packet over a packet socket bridge.
 * 
 * This function sends a packet over the specified packet socket bridge.
 * If this bridge is connected to a VLAN interface, it must be ensured that frame_start is 4.
 * This function, will shift src and dst mac 4 bytes to the left, to make space for the VLAN tag.
 * So when using this function, the raw_frame should start at buffer+4. 
 * 
 * @param bridge The packet socket bridge.
 * @param buffer The buffer containing the packet data.
 * @param buffer_len The length of the buffer.
 * @param frame_start The starting index of the frame in the buffer.
 * @return 0 on success, negative error code on failure.
 */
int packet_socket_send(PacketSocket *bridge, uint8_t *buffer, int buffer_len, int frame_start);

/**
 * @brief Receive a packet on a packet socket bridge.
 * 
 * This function receives a packet on the specified packet socket bridge.
 * 
 * @param bridge The packet socket bridge.
 * @return 0 on success, negative error code on failure.
 */
int packet_socket_receive(PacketSocket *bridge);

/**
 * @brief Pipe packets between two packet socket bridges.
 * 
 * This function pipes packets between two packet socket bridges.
 * 
 * @param bridge The packet socket bridge.
 * @return 0 on success, negative error code on failure.
 */
int packet_socket_pipe(PacketSocket *bridge);

/**
 * @brief Close a packet socket bridge.
 * 
 * This function closes a packet socket bridge.
 * 
 * @param bridge The packet socket bridge to close.
 * @return 0 on success, negative error code on failure.
 */
int packet_socket_close(PacketSocket *bridge);

#endif //__PACKET_SOCKET_H__