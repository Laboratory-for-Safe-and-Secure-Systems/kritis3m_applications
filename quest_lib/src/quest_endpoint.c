#include "quest.h"
#include "quest_types.h"

#include "file_io.h"
#include "logging.h"
#include "networking.h"

LOG_MODULE_CREATE(quest_endpoint);

/*------------------------------ private functions -------------------------------*/

/// @brief Derives neccessary connection parameter based on the paramter passed in
///        the quest_configuration.
/// @param endpoint reference to the quest_endpoint, which contains the input paramter
///        and the reserved fields for the derivated parameter.
/// @return returns E_OK if working correctly, otherwise returns an error code less than zero.
static enum kritis3m_status_info derive_connection_parameter(quest_endpoint* endpoint)
{
        int status;
        char IP_str[INET6_ADDRSTRLEN];

        /* Look-up IP address from hostname and hostport */
        status = address_lookup_client(endpoint->connection_info.hostname,
                                       endpoint->connection_info.hostport,
                                       &endpoint->connection_info.target_addr,
                                       AF_INET);
        if (status != 0)
        {
                LOG_ERROR("error looking up server IP address, error code %d", status);
                return ADDR_ERR;
        }

        /* Convert the IP from socket_addr_in to string */
        inet_ntop(endpoint->connection_info.target_addr->ai_family,
                  endpoint->connection_info.target_addr,
                  IP_str,
                  sizeof(IP_str));

        LOG_INFO("IP address for %s: %s:%s\n",
                 endpoint->connection_info.hostname,
                 IP_str,
                 endpoint->connection_info.hostport);

        return E_OK;
}

/// @brief Configures quest_endpoint based on the paramter contained in the quest_configuration.
/// @param endpoint reference to the quest_endpoint, which shall be configured.
/// @param config reference to the quest_configuration, which contains the configuration parameter.
/// @return returns E_OK if working correctly, otherwise returns an error code less than zero.
static enum kritis3m_status_info configure_endpoint(quest_endpoint* endpoint, quest_configuration* config)
{
        enum kritis3m_status_info status = E_OK;

        if (config->connection_info.hostname == NULL)
        {
                status = PARAM_ERR;
                goto error_out;
        }

        if (config->connection_info.hostport == 0)
        {
                status = PARAM_ERR;
                goto error_out;
        }

        endpoint->verbose = config->verbose;
        endpoint->security_param.enable_secure_con = config->security_param.enable_secure_con;

        if (endpoint->security_param.enable_secure_con)
        {
                endpoint->security_param.client_endpoint = config->security_param.client_endpoint;
        }

        endpoint->connection_info.hostname = duplicate_string(config->connection_info.hostname);
        if (endpoint->connection_info.hostname == NULL)
        {
                status = ALLOC_ERR;
                goto error_out;
        }
        endpoint->connection_info.hostport = config->connection_info.hostport;

        endpoint->connection_info.sae_ID = duplicate_string(config->connection_info.own_sae_ID);
        if (endpoint->connection_info.sae_ID == NULL)
        {
                status = ALLOC_ERR;
                goto error_out;
        }

        return status;

error_out:
        return status;
}

/*------------------------------- public functions -------------------------------*/
quest_endpoint* quest_setup_endpoint(quest_configuration* config)
{
        enum kritis3m_status_info status;
        quest_endpoint* endpoint;

        endpoint = malloc(sizeof(struct quest_endpoint));
        if (endpoint == NULL)
        {
                LOG_ERROR("error occured during quest endpoint allocation.");
                return NULL;
        }

        status = configure_endpoint(endpoint, config);
        if (status != E_OK)
        {
                LOG_ERROR("error occured during quest endpoint setup.");
                goto ENDPOINT_ERR;
        }

        status = derive_connection_parameter(endpoint);
        if (status != E_OK)
        {
                LOG_ERROR("error occured during connection parameter derivation.");
                goto ENDPOINT_ERR;
        }

        return endpoint;

ENDPOINT_ERR:
        free(endpoint);
        return NULL;
}

enum kritis3m_status_info quest_get_own_sae_id(quest_endpoint* endpoint, char* dst_buf)
{
        if (endpoint->connection_info.sae_ID == NULL)
                return PARAM_ERR;

        /* value copy of the sae_id to the buffer */
        strcpy(dst_buf, endpoint->connection_info.sae_ID);
        return E_OK;
}

enum kritis3m_status_info quest_free_endpoint(quest_endpoint* endpoint)
{
        if (endpoint->connection_info.target_addr != NULL)
        {
                /* free derived IP address */
                freeaddrinfo(endpoint->connection_info.target_addr);
        }

        if (endpoint->security_param.enable_secure_con &&
            (endpoint->security_param.client_endpoint != NULL))
        {
                /* free asl_endpoint for the connection to th QKD line */
                asl_free_endpoint(endpoint->security_param.client_endpoint);
        }

        if (endpoint->connection_info.hostname != NULL)
        {
                free(endpoint->connection_info.hostname);
                endpoint->connection_info.hostname = NULL;
        }

        if (endpoint->connection_info.sae_ID != NULL)
        {
                free(endpoint->connection_info.sae_ID);
                endpoint->connection_info.sae_ID = NULL;
        }

        if (endpoint != NULL)
                free(endpoint);

        return E_OK;
}