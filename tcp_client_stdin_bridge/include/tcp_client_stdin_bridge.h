#ifndef TCP_CLIENT_STDIN_BRIDGE_H
#define TCP_CLIENT_STDIN_BRIDGE_H

#include <stdint.h>
#include <stdlib.h>


typedef struct tcp_client_stdin_bridge_config
{
        char const* target_ip_address;
        uint16_t target_port;
}
tcp_client_stdin_bridge_config;


/* Start a new thread and run the TCP client stdin bridge application.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_client_stdin_bridge_run(tcp_client_stdin_bridge_config const* config);


/* Terminate the tcp_client_stdin_bridge application.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_client_stdin_bridge_terminate(void);

#endif // TCP_CLIENT_STDIN_BRIDGE_H
