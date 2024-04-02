
#ifndef __L2_GATEWAY_H_
#define __L2_GATEWAY_H_

#include <stdint.h>
#include <stdlib.h>

#include "wolfssl.h"
/**
 * @brief Enumeration for the type of interface.
 */
typedef enum interface_type
{
	TAP_INTERFACE, /**< TUN interface type. */
	PACKET_SOCKET, /**< Packet socket interface type. */
	UDP_SOCKET,
	DTLS_SOCKET,
} interface_type;


typedef struct interface_config
{
	interface_type type;
	int vlan_tag;
	void *interface;
} interface_config;


typedef struct l2_gateway_config
{
	interface_type asset_type;
	const char *asset_ip;
	int asset_port;
	const char *asset_target_ip;
	int asset_target_port;
	int asset_vlan_tag;

	interface_type tunnel_type;
	const char *tunnel_ip;
	int tunnel_port;
	const char *tunnel_target_ip;
	int tunnel_target_port;

	int asset_client_port;
	int tunnel_client_port;

	int tunnel_vlan_tag;
	struct wolfssl_endpoint_configuration dtls_config;

} l2_gateway_config;

struct dtls_config
{
	char const *own_ip_address;
	uint16_t listening_port;
	char const *target_ip_address;
	uint16_t target_port;
	struct wolfssl_endpoint_configuration dtls_config;
};

/**
 * @brief Enumeration for the connected channel.
 */
typedef enum connected_channel
{
	ASSET,	/**< Asset channel. */
	TUNNEL, /**< Tunnel channel. */
} connected_channel;

/**
 * @brief Structure representing a l2_gateway.
 *
 * This structure defines a l2_gateway, which is used to connect two network interfaces.
 * It contains function pointers, a buffer, length information, interface type,
 * connected channel, VLAN tag, a l2_gw_pipe, and a file descriptor.
 */
typedef struct L2_Gateway L2_Gateway;
struct L2_Gateway
{
	int (*vtable[5])();
	uint8_t buf[1700];
	uint32_t len;
	interface_type type;
	connected_channel channel;
	int vlan_tag; // if vlan tag < 0 -> not supported
	L2_Gateway *l2_gw_pipe;
	int fd;
};

int l2_gateway_register_fd(int  fd, short events);
void l2_gateway_update_events(int fd, short events);
void l2_gateway_remove_fd(int fd);


/**
 * @brief Define a function pointer type for sending data through the l2_gateway.
 *
 * This function pointer type is used to define the signature of functions that send data
 * through the l2_gateway. It takes a pointer to a L2_Gateway object, a buffer containing the data
 * to be sent, the length of the buffer, and a flag indicating whether the frame is the start
 * of a new frame. The function should return an integer indicating the status of the send operation.
 *
 * @param l2_gateway Pointer to the L2_Gateway object.
 * @param buffer Pointer to the data buffer.
 * @param buffer_len Length of the data buffer.
 * @param frame_start Flag indicating whether the frame is the start of a new frame.
 * @return Integer indicating the status of the send operation.
 */
typedef int (*sendFunc)(L2_Gateway *l2_gateway, int fd,  uint8_t *buffer, int buffer_len, int frame_start);


typedef int (*periodic_callback)(L2_Gateway* l2_gateway);


/**
 * @brief Define a function pointer type for receiving or piping data through the l2_gateway.
 *
 * This function pointer type is used to define the signature of functions that receive or
 * l2_gw_pipe data through the l2_gateway. It takes a pointer to a L2_Gateway object and should return an
 * integer indicating the status of the receive or l2_gw_pipe operation.
 *
 * @param self Pointer to the L2_Gateway object.
 * @return Integer indicating the status of the receive or l2_gw_pipe operation.
 */
typedef int (*receiveFunc)(L2_Gateway *self, int fd, int (*callback)(int fd));


typedef int (*PipeFunc)(L2_Gateway *self);

/**
 * @brief Enumeration of call types.
 *
 * This enumeration defines the different types of calls that can be made in the l2_l2_gateway module.
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
	call_close,
	call_connect
};

/**
 * @brief Sends data through the l2_gateway.
 *
 * This function sends the specified buffer of data through the l2_gateway.
 *
 * @param l2_gateway The l2_gateway object.
 * @param buffer Pointer to the data buffer.
 * @param buffer_len Length of the data buffer.
 * @param buffer_start Starting index of the data buffer.
 * @return Returns the number of bytes sent, or a negative error code on failure.
 */
int l2_gateway_send(L2_Gateway *l2_gateway,int fd, uint8_t *buffer, int buffer_len, int buffer_start);

/**
 * @brief Receives data from the l2_gateway.
 *
 * This function receives data from the l2_gateway and returns the number of received bytes.
 *
 * @param l2_gateway The l2_gateway object.
 * @return Returns the received data, or a negative error code on failure.
 */
int l2_gateway_receive(L2_Gateway *l2_gateway, int fd);

/**
 * @brief Sends received data via the conencted pipePipes data through the l2_gateway.
 *
 * This function sends the received data in its buffer through the connected pipe.
 *
 * @param l2_gateway The l2_gateway object.
 * @return Returns negative error code on failure.
 */
int l2_gateway_pipe(L2_Gateway *l2_gateway);

/**
 * @brief Closes the l2_gateway.
 *
 * This function closes the l2_gateway and releases any associated resources.
 *
 * @param l2_gateway The l2_gateway object.
 * @return Returns 0 on success, or a negative error code on failure.
 */
int l2_gateway_close(L2_Gateway *l2_gateway);

/* Start a new thread and run the Layer 2 l2_gateway.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */


int l2_gateway_start(l2_gateway_config const *config);

/* Terminate the Layer 2 l2_gateway.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int l2_gateway_terminate(void);

#endif // L2_GATEWAY_H_
