#ifndef TLS_PROXY_H
#define TLS_PROXY_H

#include <stdint.h>
#include <stdlib.h>

#include "asl.h"

#include "kritis3m_application_config.h"

enum tls_proxy_direction
{
        REVERSE_PROXY,
        FORWARD_PROXY,
};

typedef struct proxy_backend_config
{
        int32_t log_level;
} proxy_backend_config;

typedef struct proxy_config
{
        int application_id;
        char* own_ip_address;
        char* target_ip_address;
        uint16_t listening_port;
        uint16_t target_port;
        int32_t log_level;
        asl_endpoint_configuration tls_config;
} proxy_config;

typedef struct proxy_status
{
        bool is_running;
        uint16_t incoming_port_v4;
        uint16_t incoming_port_v6;
        enum tls_proxy_direction direction;
        uint32_t num_connections;
} proxy_status;

/* Create the default config for the TLS proxy backend */
proxy_backend_config tls_proxy_backend_default_config(void);

/* Create the default config for a TLS proxy */
proxy_config tls_proxy_default_config(void);

/* Start a new thread and run the main TLS proxy backend with given config.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_backend_run(proxy_backend_config const* config);

/* Start a new reverse proxy with given config.
 *
 * Returns the id of the new proxy instance on success (positive integer) or -1
 * on failure (error message is printed to console).
 */
int tls_reverse_proxy_start(proxy_config const* config);

/* Start a new forward proxy with given config.
 *
 * Returns the id of the new proxy instance on success (positive integer) or -1
 * on failure (error message is printed to console).
 */
int tls_forward_proxy_start(proxy_config const* config);

/* Querry status information from the proxy with given id.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_get_status(int id, proxy_status* status);

/* Stop the running proxy with given id (returned by tls_forward_proxy_start or
 * tls_forward_proxy_start).
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_stop(int id);

/* Terminate the application backend.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_backend_terminate(void);

#ifdef USE_MANAGEMENT
/* Stop the running proxy with given id (returned by tls_forward_proxy_start or
 * tls_forward_proxy_start).
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_stop_mgmt_id(int id);
#endif

#endif // TLS_PROXY_H
