#ifndef CLI_PARSING_H
#define CLI_PARSING_H

#include <stdint.h>
#include <stdlib.h>

#if defined(__ZEPHYR__)
#include <zephyr/shell/shell.h>
#endif

#include "logging.h"
#include "wolfssl.h"
#include "tls_proxy.h"
#include "l2_bridge.h"
#include "l2_gateway.h"
#include "wolfssl/certs_test.h"

enum application_role
{
    NOT_SET,
    ROLE_REVERSE_PROXY,
    ROLE_FORWARD_PROXY,
    ROLE_ECHO_SERVER,
    ROLE_ECHO_CLIENT,
    ROLE_L2_GATEWAY,
};

/* Parse the provided argv array and store the information in the provided config variables.
 *
 * Returns 0 on success, +1 in case the help was printed and -1 on failure (error is printed
 * on console).
 */
int parse_cli_arguments(enum application_role *role, struct proxy_config *proxy_config,
                        wolfssl_library_configuration *wolfssl_config, l2_bridge_config *bridge_config, l2_gateway_config *l2_gateway_config,
                        struct shell const *sh, size_t argc, char **argv);

#endif // CLI_PARSING_H
