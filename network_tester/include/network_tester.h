#ifndef NETWORK_TESTER_H
#define NETWORK_TESTER_H

#include <stdint.h>
#include <stdlib.h>

#include "asl.h"


typedef struct network_tester_config
{
        int32_t log_level;

        char* output_path;

        struct handshake_test
        {
                int iterations;
                int delay_ms; /* Delay between handshakes */
        }
        handshake_test;

        struct message_latency_test
        {
                int iterations;
                int delay_us; /* Delay between messages */
                int size;
        }
        message_latency_test;

        char* target_ip;
        uint16_t target_port;

        bool silent_test;

        bool use_tls;
        asl_endpoint_configuration tls_config;
}
network_tester_config;


typedef struct network_tester_status
{
        bool is_running;
        uint32_t progress_percent;
}
network_tester_status;


/* Create the default config for the network_tester */
network_tester_config network_tester_default_config(void);


/* Start a new thread and run the network tester application.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int network_tester_run(network_tester_config const* config);


/* Querry status information from the network tester.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int network_tester_get_status(network_tester_status* status);


/* Terminate the network tester application.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int network_tester_terminate(void);


#endif // NETWORK_TESTER_H
