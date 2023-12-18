#ifndef TCP_CLIENT_STDIN_BRIDGE_H
#define TCP_CLIENT_STDIN_BRIDGE_H

#include <stdint.h>
#include <stdlib.h>


struct tcp_client_stdin_bridge_config
{
        char const* target_ip_address;
        uint16_t target_port;
};


/* Start a new thread and run the TCP client stdin bridge application.
 * 
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_client_stdin_bridge_run(struct tcp_client_stdin_bridge_config const* config);


/* Terminate the tcp_client_stdin_bridge application.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_client_stdin_bridge_terminate(void);

#endif // TCP_CLIENT_STDIN_BRIDGE_H
