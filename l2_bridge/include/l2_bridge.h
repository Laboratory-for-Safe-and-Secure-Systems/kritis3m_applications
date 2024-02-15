#ifndef L2_BRIDGE_H
#define L2_BRIDGE_H

#include <stdint.h>
#include <stdlib.h>


/**
 * @brief Enumeration for the type of interface.
 */
typedef enum interface_type
{
	TUN_INTERFACE, /**< TUN interface type. */
	PACKET_SOCKET, /**< Packet socket interface type. */
} interface_type;

typedef struct interface_config
{
	interface_type type;
	int vlan_tag;
	void *interface;
} interface_config;

typedef struct l2_bridge_config
{
	interface_config asset_interface;
	interface_config tunnel_interface;
} l2_bridge_config;



/**
 * @brief Enumeration for the connected channel.
 */
typedef enum connected_channel
{
	ASSET, /**< Asset channel. */
	TUNNEL, /**< Tunnel channel. */
} connected_channel;

/**
 * @brief Structure representing a bridge.
 *
 * This structure defines a bridge, which is used to connect two network interfaces.
 * It contains function pointers, a buffer, length information, interface type,
 * connected channel, VLAN tag, a pipe, and a file descriptor.
 */
typedef struct Bridge Bridge;
struct Bridge
{
	int (*vtable[4])();
	uint8_t buf[2048];
	uint32_t len;
	interface_type type;
	connected_channel channel;
	int vlan_tag; // if vlan tag < 0 -> not supported
	Bridge *pipe;
	int fd;
};

/**
 * @brief Define a function pointer type for sending data through the bridge.
 *
 * This function pointer type is used to define the signature of functions that send data
 * through the bridge. It takes a pointer to a Bridge object, a buffer containing the data
 * to be sent, the length of the buffer, and a flag indicating whether the frame is the start
 * of a new frame. The function should return an integer indicating the status of the send operation.
 *
 * @param bridge Pointer to the Bridge object.
 * @param buffer Pointer to the data buffer.
 * @param buffer_len Length of the data buffer.
 * @param frame_start Flag indicating whether the frame is the start of a new frame.
 * @return Integer indicating the status of the send operation.
 */
typedef int (*sendFunc)(Bridge *bridge, uint8_t *buffer, int buffer_len, int frame_start);

/**
 * @brief Define a function pointer type for receiving or piping data through the bridge.
 *
 * This function pointer type is used to define the signature of functions that receive or
 * pipe data through the bridge. It takes a pointer to a Bridge object and should return an
 * integer indicating the status of the receive or pipe operation.
 *
 * @param self Pointer to the Bridge object.
 * @return Integer indicating the status of the receive or pipe operation.
 */
typedef int (*receiveOrPipeFunc)(Bridge *self);


/**
 * @brief Enumeration of call types.
 *
 * This enumeration defines the different types of calls that can be made in the l2_bridge module.
 * - call_send: Represents a send call.
 * - call_receive: Represents a receive call.
 * - call_pipe: Represents a pipe call.
 * - call_close: Represents a close call.
 */
enum
{
	call_send,
	call_receive,
	call_pipe,
	call_close
};

/**
 * @brief Sends data through the bridge.
 *
 * This function sends the specified buffer of data through the bridge.
 *
 * @param bridge The bridge object.
 * @param buffer Pointer to the data buffer.
 * @param buffer_len Length of the data buffer.
 * @param buffer_start Starting index of the data buffer.
 * @return Returns the number of bytes sent, or a negative error code on failure.
 */
int bridge_send(Bridge *bridge, uint8_t *buffer, int buffer_len, int buffer_start);

/**
 * @brief Receives data from the bridge.
 *
 * This function receives data from the bridge and returns the number of received bytes.
 *
 * @param bridge The bridge object.
 * @return Returns the received data, or a negative error code on failure.
 */
int bridge_receive(Bridge *bridge);

/**
 * @brief Sends received data via the conencted pipePipes data through the bridge.
 *
 * This function sends the received data in its buffer through the connected pipe.
 *
 * @param bridge The bridge object.
 * @return Returns negative error code on failure.
 */
int bridge_pipe(Bridge *bridge);

/**
 * @brief Closes the bridge.
 *
 * This function closes the bridge and releases any associated resources.
 *
 * @param bridge The bridge object.
 * @return Returns 0 on success, or a negative error code on failure.
 */
int bridge_close(Bridge *bridge);

/* Start a new thread and run the Layer 2 bridge.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int l2_bridge_run(l2_bridge_config const *config);

/* Terminate the Layer 2 bridge.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int l2_bridge_terminate(void);

#endif // TCP_ECHO_SERVER_H
