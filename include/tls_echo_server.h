#ifndef TLS_ECHO_SERVER_H
#define TLS_ECHO_SERVER_H

#include <stdint.h>
#include <stdlib.h>

#include "wolfssl.h"

struct tls_server_config
{
	char const* ip_address;
	uint16_t listening_port;
	struct wolfssl_endpoint_configuration tls_config;
};


/* Initialize the application backend. Must be called once on startup.
 * 
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_echo_server_init(void);


/* Start a new thread and run the main TLS echo server backend.
 * 
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_echo_server_run(void);


/* Start a new echo server with given config.
 * 
 * Returns the id of the new server on success (positive integer) or -1 on failure
 * (error message is printed to console).
 */
int tls_echo_server_start(struct tls_server_config const* server);


/* Stop the running echo server with given id (returned von tls_echo_server_start).
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_echo_server_stop(int id);


#endif