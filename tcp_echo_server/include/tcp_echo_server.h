#ifndef TCP_ECHO_SERVER_H
#define TCP_ECHO_SERVER_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>


typedef struct tcp_echo_server_config
{
        char const* own_ip_address;
        uint16_t listening_port;
        int32_t log_level;
}
tcp_echo_server_config;


typedef struct tcp_echo_server_status
{
        bool is_running;
        uint16_t listening_port;
        uint32_t num_connections;
}
tcp_echo_server_status;


/* Start a new thread and run the TCP echo server.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_echo_server_run(tcp_echo_server_config const* config);


/* Querry status information from the TCP echo server.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_echo_server_get_status(tcp_echo_server_status* status);


/* Terminate the echo server.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_echo_server_terminate(void);

#endif // TCP_ECHO_SERVER_H
