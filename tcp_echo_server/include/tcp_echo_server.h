#ifndef TCP_ECHO_SERVER_H
#define TCP_ECHO_SERVER_H

#include <stdint.h>
#include <stdlib.h>


struct tcp_echo_server_config
{
        char const* own_ip_address;
        uint16_t listening_port;
};


/* Start a new thread and run the TCP echo server.
 * 
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_echo_server_run(struct tcp_echo_server_config const* config);


/* Terminate the echo server.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_echo_server_terminate(void);

#endif // TCP_ECHO_SERVER_H
