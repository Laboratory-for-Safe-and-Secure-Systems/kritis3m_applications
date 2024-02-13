#ifndef L2_BRIDGE_H
#define L2_BRIDGE_H

#include <stdint.h>
#include <stdlib.h>


typedef struct l2_bridge_config 
{
	void* asset_interface;
	void* tunnel_interface;
}
l2_bridge_config;


/* Start a new thread and run the Layer 2 bridge.
 * 
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int l2_bridge_run(l2_bridge_config const* config);


/* Terminate the Layer 2 bridge.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int l2_bridge_terminate(void);


#endif // TCP_ECHO_SERVER_H
