#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "proxy_backend.h"
#include "proxy_connection.h"
#include "proxy_management.h"

#include "logging.h"
#include "threading.h"

LOG_MODULE_CREATE(proxy_api);

/* File global variables */
static proxy_backend the_backend;

/* Create the default config for the TLS proxy backend */
proxy_backend_config tls_proxy_backend_default_config(void)
{
        proxy_backend_config default_config = {0};

        default_config.log_level = LOG_LVL_WARN;

        return default_config;
}

/* Create the default config for a TLS proxy */
proxy_config tls_proxy_default_config(void)
{
        proxy_config default_config = {0};

        default_config.own_ip_address = NULL;
        default_config.listening_port = 0; /* 0 selects random available port */
        default_config.target_ip_address = NULL;
        default_config.target_port = 0;
        default_config.log_level = LOG_LVL_WARN;
        default_config.tls_config = asl_default_endpoint_config();

        return default_config;
}

/* Start a new thread and run the main TLS proxy backend with given config.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_backend_run(proxy_backend_config const* config)
{
        /* Set the log level. We do that before checking if the backend is
         * already running to make sure the log level is updated. */
        LOG_LVL_SET(config->log_level);

        if (the_backend.running)
        {
                LOG_DEBUG("Proxy backend already running");
                return 0;
        }

        /* Init connection pool */
        init_proxy_connection_pool();

        /* Init server pool */
        init_proxy_pool();

        /* Init backend config */
        int ret = proxy_backend_init(&the_backend, config);

        if (ret == 0)
        {
                /* Obtain the status of proxy with id 1 to check if the backend thread
                 * is running properly. */
                proxy_status status;
                ret = tls_proxy_get_status(1, &status);
                if (ret < 0)
                {
                        LOG_ERROR("Failed to obtain status of proxy with id 1");
                        return -1;
                }
        }

        if (ret == 0)
        {
                LOG_INFO("TLS proxy main thread started");
        }

        return ret;
}

int tls_proxy_start_helper(proxy_management_message const* request)
{
        proxy_management_message response = {0};

        /* Send request */
        int ret = send_management_message(the_backend.management_socket_pair[0], request);
        if (ret < 0)
        {
                return -1;
        }

        /* Wait for response */
        ret = read_management_message(the_backend.management_socket_pair[0], &response);
        if (ret < 0)
        {
                return -1;
        }
        else if (response.type != RESPONSE)
        {
                LOG_ERROR("Received invalid response");
                return -1;
        }
        else if (response.payload.response_code < 0)
        {
                LOG_ERROR("Error starting new TLS proxy (error %d)", response.payload.response_code);
                return -1;
        }

        /* Response code is the id of the new server */
        return response.payload.response_code;
}

/* Start a new reverse proxy with given config.
 *
 * Returns the id of the new proxy instance on success (positive integer) or -1
 * on failure (error message is printed to console).
 */
int tls_reverse_proxy_start(proxy_config const* config)
{
        if ((the_backend.management_socket_pair[0] < 0) || (the_backend.management_socket_pair[0] < 0))
        {
                LOG_ERROR("Proxy backend not running");
                return -1;
        }

        /* Create a START_REQUEST message */
        proxy_management_message request = {0};
        request.type = REVERSE_PROXY_START_REQUEST;
        request.payload.reverse_proxy_config = *config;

        return tls_proxy_start_helper(&request);
}

/* Start a new forward proxy with given config.
 *
 * Returns the id of the new proxy instance on success (positive integer) or -1
 * on failure (error message is printed to console).
 */
int tls_forward_proxy_start(proxy_config const* config)
{
        if ((the_backend.management_socket_pair[0] < 0) || (the_backend.management_socket_pair[0] < 0))
        {
                LOG_ERROR("Proxy backend not running");
                return -1;
        }

        /* Create a START_REQUEST message */
        proxy_management_message request = {0};
        memset(&request, 0, sizeof(request));
        request.type = FORWARD_PROXY_START_REQUEST;
        request.payload.forward_proxy_config = *config;

        return tls_proxy_start_helper(&request);
}

/* Querry status information from the proxy with given id.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_get_status(int id, proxy_status* status)
{
        if ((the_backend.management_socket_pair[0] < 0) || (the_backend.management_socket_pair[0] < 0))
        {
                LOG_ERROR("Proxy backend not running");
                return -1;
        }

        /* Create the PROXY_STATUS_REQUEST message. Object is used for the response, too. */
        proxy_management_message message = {.type = PROXY_STATUS_REQUEST,
                                            .payload.status_req = {
                                                    .proxy_id = id,
                                                    .status_obj_ptr = status,
                                            }};

        /* Send request */
        int ret = send_management_message(the_backend.management_socket_pair[0], &message);
        if (ret < 0)
        {
                return -1;
        }

        /* Wait for response */
        ret = read_management_message(the_backend.management_socket_pair[0], &message);
        if (ret < 0)
        {
                return -1;
        }
        else if (message.type != RESPONSE)
        {
                LOG_ERROR("Received invalid response");
                return -1;
        }
        else if (message.payload.response_code < 0)
        {
                LOG_ERROR("Error obtaining proxy status (error %d)", message.payload.response_code);
                return -1;
        }

        return 0;
}

/* Stop the running proxy with given id (returned by tls_forward_proxy_start or
 * tls_forward_proxy_start).
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_stop(int id)
{
        if ((the_backend.management_socket_pair[0] > 0) && (the_backend.management_socket_pair[1] > 0))
        {
                /* Create a PROXY_STOP_REQUEST message */
                proxy_management_message request = {
                        .type = PROXY_STOP_REQUEST,
                        .payload.proxy_id = id,
                };
                proxy_management_message response = {0};

                /* Send request */
                int ret = send_management_message(the_backend.management_socket_pair[0], &request);
                if (ret < 0)
                {
                        return -1;
                }

                /* Wait for response */
                ret = read_management_message(the_backend.management_socket_pair[0], &response);
                if (ret < 0)
                {
                        return -1;
                }
                else if (response.type != RESPONSE)
                {
                        LOG_ERROR("Received invalid response");
                        return -1;
                }
                else if (response.payload.response_code < 0)
                {
                        LOG_ERROR("Error stopping TLS proxy (error %d)",
                                  response.payload.response_code);
                        return -1;
                }
        }

        return 0;
}

/* Terminate the application backend.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_backend_terminate(void)
{
        if ((the_backend.management_socket_pair[0] > 0) && (the_backend.management_socket_pair[1] > 0))
        {
                /* Create a BACKEND_STOP_REQUEST message */
                proxy_management_message request = {
                        .type = BACKEND_STOP_REQUEST,
                        .payload.dummy_unused = 0,
                };
                proxy_management_message response = {0};

                /* Send request */
                int ret = send_management_message(the_backend.management_socket_pair[0], &request);
                if (ret < 0)
                {
                        return -1;
                }

                /* Wait for response */
                ret = read_management_message(the_backend.management_socket_pair[0], &response);
                if (ret < 0)
                {
                        return -1;
                }
                else if (response.type != RESPONSE)
                {
                        LOG_ERROR("Received invalid response");
                        return -1;
                }
                else if (response.payload.response_code < 0)
                {
                        LOG_ERROR("Error stopping proxy backend (error %d)",
                                  response.payload.response_code);
                        return -1;
                }
        }

        /* Wait for the backend thread to be terminated */
        wait_for_thread(&the_backend.thread);

        return 0;
}

#ifdef USE_MANAGEMENT
/* Stop the running proxy with given id (returned by tls_forward_proxy_start or
 * tls_forward_proxy_start).
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int tls_proxy_stop_mgmt_id(int appl_id)
{
        if ((the_backend.management_socket_pair[0] < 0) || (the_backend.management_socket_pair[0] < 0))
        {
                LOG_ERROR("Proxy backend not running");
                return -1;
        }

        /* Create a PROXY_STOP_REQUEST message */
        proxy_management_message request = {
                .type = PROXY_STOP_REQUEST_MGMT,
                .payload.mgmt_id = appl_id,
        };
        proxy_management_message response = {0};

        /* Send request */
        int ret = send_management_message(the_backend.management_socket_pair[0], &request);
        if (ret < 0)
        {
                return -1;
        }

        /* Wait for response */
        ret = read_management_message(the_backend.management_socket_pair[0], &response);
        if (ret < 0)
        {
                return -1;
        }
        else if (response.type != RESPONSE)
        {
                LOG_ERROR("Received invalid response");
                return -1;
        }
        else if (response.payload.response_code < 0)
        {
                LOG_ERROR("Error stopping TLS proxy (error %d)", response.payload.response_code);
                return -1;
        }

        return 0;
}
#endif
