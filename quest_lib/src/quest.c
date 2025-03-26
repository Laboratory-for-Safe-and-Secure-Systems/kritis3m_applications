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

        default_config->connection_info.hostname = "im-lfd-qkd-bob.othr.de";
        default_config->connection_info.host_sae_ID = "bob_sae_etsi_1";
        default_config->connection_info.hostport = "9120";

        default_config->security_param.enable_secure_con = false;
        default_config->security_param.client_endpoint = NULL;

        return default_config;
}

enum kritis3m_status_info quest_deinit(quest_configuration* config)
{
        if (config == NULL)
                return E_OK;

        /* free quest configuration */
        free(config);

        return E_OK;
}