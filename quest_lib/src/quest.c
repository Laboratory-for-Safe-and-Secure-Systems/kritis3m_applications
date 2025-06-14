#include "quest.h"
#include "kritis3m_http.h"

/*------------------------------ private functions -------------------------------*/

/*------------------------------- public functions -------------------------------*/
quest_configuration* quest_default_config(void)
{
        quest_configuration* default_config;
        default_config = malloc(sizeof(struct quest_configuration));

        if (default_config == NULL)
                return NULL;

        default_config->verbose = false;

        default_config->connection_info.own_sae_ID = NULL;
        default_config->connection_info.remote_sae_ID = NULL;

        default_config->connection_info.hostname = NULL;
        default_config->connection_info.hostport = 0;

        default_config->security_param.enable_secure_con = false;
        default_config->security_param.client_endpoint = NULL;

        return default_config;
}

enum kritis3m_status_info quest_config_deinit(quest_configuration* config)
{
        if (config == NULL)
                return E_OK;

        if (config->connection_info.hostname != NULL)
        {
                free(config->connection_info.hostname);
                config->connection_info.hostname = NULL;
        }

        if (config->connection_info.own_sae_ID != NULL)
        {
                free(config->connection_info.own_sae_ID);
                config->connection_info.own_sae_ID = NULL;
        }

        if (config->connection_info.remote_sae_ID != NULL)
        {
                free(config->connection_info.remote_sae_ID);
                config->connection_info.remote_sae_ID = NULL;
        }

        /* free quest configuration */
        free(config);

        return E_OK;
}