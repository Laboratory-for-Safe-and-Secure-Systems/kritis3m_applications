#ifndef TCP_CLIENT_STDIN_BRIDGE_H
#define TCP_CLIENT_STDIN_BRIDGE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct tcp_client_stdin_bridge_config
{
        char const* target_ip_address;
        uint16_t target_port;
        int32_t log_level;
} tcp_client_stdin_bridge_config;

typedef struct tcp_client_stdin_bridge_status
{
        bool is_running;
} tcp_client_stdin_bridge_status;

/* Create the default config for the TCP client stdin bridge */
tcp_client_stdin_bridge_config tcp_client_stdin_bridge_default_config(void);

/* Start a new thread and run the TCP client stdin bridge application.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_client_stdin_bridge_run(tcp_client_stdin_bridge_config const* config);

/* Querry status information from the TCP STDIN bridge.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_client_stdin_bridge_get_status(tcp_client_stdin_bridge_status* status);

/* Terminate the tcp_client_stdin_bridge application.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tcp_client_stdin_bridge_terminate(void);

#endif // TCP_CLIENT_STDIN_BRIDGE_H
