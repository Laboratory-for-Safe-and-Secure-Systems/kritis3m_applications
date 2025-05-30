#ifndef ECHO_SERVER_H
#define ECHO_SERVER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "asl.h"

typedef struct echo_server_config
{
        char* own_ip_address;
        uint16_t listening_port;
        int32_t log_level;

        bool use_tls;
        asl_endpoint_configuration tls_config;
} echo_server_config;

typedef struct echo_server_status
{
        bool is_running;
        uint16_t listening_port_v4;
        uint16_t listening_port_v6;
        uint32_t num_connections;
} echo_server_status;

/* Create the default config for the echo server */
echo_server_config echo_server_default_config(void);

/* Start a new thread and run the echo server.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int echo_server_run(echo_server_config const* config);

/* Querry status information from the echo server.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int echo_server_get_status(echo_server_status* status);

/* Terminate the echo server.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int echo_server_terminate(void);

#endif // ECHO_SERVER_H
