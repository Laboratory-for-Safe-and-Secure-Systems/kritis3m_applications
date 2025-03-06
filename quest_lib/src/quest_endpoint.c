#include "quest.h"
#include "quest_types.h"

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

        /* temporary fix to connect to mock-server */
        endpoint->connection_info.hostname = "127.0.0.2";

        /* Look-up IP address from hostname and hostport */
        status = address_lookup_client(endpoint->connection_info.hostname,
                                       (uint16_t) strtol(endpoint->connection_info.hostport, NULL, 10),
                                       &endpoint->connection_info.IP_v4,
                                       AF_INET);
        if (status != 0)
        {
                LOG_ERROR("error looking up server IP address, error code %d", status);
                return ADDR_ERR;
        }

        /* temporary fix to connect to mock-server */
        endpoint->connection_info.hostname = "im-lfd-qkd-bob.othr.de";

        /* Convert the IP from socket_addr_in to string */
        inet_ntop(AF_INET,
                  endpoint->connection_info.IP_v4,
                  endpoint->connection_info.IP_str,
                  sizeof(endpoint->connection_info.IP_str));

        LOG_INFO("IP address for %s: %s:%s\n",
                 endpoint->connection_info.hostname,
                 endpoint->connection_info.IP_str,
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
                goto INVALID_PARAM;

        if (config->connection_info.hostport == NULL)
                goto INVALID_PARAM;

        endpoint->verbose = config->verbose;
        endpoint->security_param.enable_secure_con = config->security_param.enable_secure_con;

        if (endpoint->security_param.enable_secure_con)
        {
                endpoint->security_param.client_endpoint = config->security_param.client_endpoint;
        }

        endpoint->connection_info.hostname = config->connection_info.hostname;
        endpoint->connection_info.hostport = config->connection_info.hostport;

        return status;

INVALID_PARAM:
        status = PARAM_ERR;
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

enum kritis3m_status_info quest_free_endpoint(quest_endpoint* endpoint)
{
        if (endpoint->connection_info.IP_v4 != NULL)
        {
                /* free derived IP address */
                freeaddrinfo(endpoint->connection_info.IP_v4);
        }

        if (endpoint->security_param.enable_secure_con &&
            (endpoint->security_param.client_endpoint != NULL))
        {
                /* free asl_endpoint for the connection to th QKD line */
                asl_free_endpoint(endpoint->security_param.client_endpoint);
        }

        return E_OK;
}