#ifndef TLS_PROXY_H
#define TLS_PROXY_H

#include <stdint.h>
#include <stdlib.h>

#include "wolfssl.h"


struct reverse_proxy_config
{
	char const* own_ip_address;
	uint16_t listening_port;
	char const* target_ip_address;
	uint16_t target_port;
	struct wolfssl_endpoint_configuration tls_config;
};


struct forward_proxy_config
{
	char const* own_ip_address;
	uint16_t listening_port;
	char const* target_ip_address;
	uint16_t target_port;
	struct wolfssl_endpoint_configuration tls_config;
};


/* Initialize the application backend. Must be called once on startup.
 * 
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_init(void);


/* Start a new thread and run the main TLS proxy backend.
 * 
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_run(void);


/* Start a new reverse proxy with given config.
 * 
 * Returns the id of the new proxy instance on success (positive integer) or -1
 * on failure (error message is printed to console).
 */
int tls_reverse_proxy_start(struct reverse_proxy_config const* config);


/* Stop the running reverse proxy with given id (returned von tls_reverse_proxy_start).
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_reverse_proxy_stop(int id);


/* Start a new forward proxy with given config.
 * 
 * Returns the id of the new proxy instance on success (positive integer) or -1
 * on failure (error message is printed to console).
 */
int tls_forward_proxy_start(struct forward_proxy_config const* config);


/* Stop the running forward proxy with given id (returned von tls_forward_proxy_start).
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_forward_proxy_stop(int id);


/* Terminate the application backend.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_terminate(void);


#endif // TLS_PROXY_H