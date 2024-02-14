#ifndef L2_BRIDGE_H
#define L2_BRIDGE_H

#include <stdint.h>
#include <stdlib.h>


typedef enum interface_type
{
	TUN_INTERFACE,
	TUN_INTERFACE_VLAN,
	PACKET_SOCKET,
	PACKET_SOCKET_VLAN,
	INVALID
} interface_type;

typedef enum connected_channel
{
	ASSET,
	TUNNEL
} connected_channel;

typedef struct Bridge Bridge;
struct Bridge
{
    int (*vtable[3])();
	uint8_t buf[2048];
	uint32_t len;
	interface_type type;
	connected_channel channel;	
	Bridge* pipe; 
	int fd;
};

// Define a function pointer type for send and pipe functions.
typedef int (*sendOrPipeFunc)(Bridge* bridge, uint8_t* data, size_t len);
// Define a function pointer type for receive function.
typedef int (*receiveFunc)(Bridge* self);


//used to identify function pointer: BaseVtable[call_send] = bridge_send
enum { call_send, call_receive, call_pipe };

static int bridge_send(Bridge* bridge, uint8_t* data, size_t len){
	sendOrPipeFunc send = (sendOrPipeFunc)bridge->vtable[call_send];
	return send(bridge, data, len);
}

static int bridge_receive(Bridge* bridge){
	receiveFunc receive = (receiveFunc)bridge->vtable[call_receive];
	return receive(bridge);

}

static int bridge_pipe(Bridge* bridge, void* data, size_t len){
	sendOrPipeFunc pipe = (sendOrPipeFunc)bridge->vtable[call_pipe];
	return pipe(bridge, data, len);
}


typedef struct interface_config{
	interface_type type;
	void *interface;
} interface_config;

typedef struct l2_bridge_config
{
	interface_config asset_interface;
	interface_config tunnel_interface;
} l2_bridge_config;

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
