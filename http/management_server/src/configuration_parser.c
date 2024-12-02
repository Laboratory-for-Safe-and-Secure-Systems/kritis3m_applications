

#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>

#include "cJSON.h"
#include "logging.h"
#include "utils.h"
#include "errno.h"
#include "string.h"
#include "configuration_parser.h"
LOG_MODULE_CREATE(kritis3m_config_paser);

int parse_whitelist(cJSON *json_obj, Whitelist *whitelist);
int parse_crypo_config(cJSON *json_obj, CryptoProfile *CryptoProfile, char *secure_middleware_path, char *pin);
int parse_crypo_identity(cJSON *json_obj, crypto_identity *crypto_identity, char *crypto_identity_path);
int parse_application(cJSON *json_obj, Kritis3mApplications *application);

int parse_json_to_ManagementConfig(cJSON *json_management_service, Kritis3mManagemntConfiguration *config, char *identity_path)
{
    int ret = 0;

    ret = parse_endpoint_addr(cJSON_GetObjectItem(json_management_service, "server_addr")->valuestring,
                              config->server_endpoint_addr.address, ENDPOINT_LEN, &config->server_endpoint_addr.port);
    if (ret < 0)
        goto error_occured;
    cJSON *js_middleware_path = cJSON_GetObjectItem(json_management_service, "secure_middleware_path");
    if ((js_middleware_path == NULL) ||
        (strcmp(js_middleware_path->valuestring, "") == 0))
    {
        LOG_DEBUG("no middleware path provided");
        config->secure_middleware_path = NULL;
        config->secure_middleware_path_size = 0;
    }
    else
    {
        LOG_DEBUG("no middleware path provided");
        config->secure_middleware_path = string_duplicate(js_middleware_path->valuestring);
        config->secure_middleware_path_size = strlen(config->secure_middleware_path) + 1;
    }
    cJSON *js_pin = cJSON_GetObjectItem(json_management_service, "pin");
    if ((js_pin == NULL) ||
        (strcmp(js_pin->valuestring, "") == 0))
    {
        LOG_DEBUG("no middleware path provided");
        config->pin = NULL;
        config->pin_size = 0;
    }
    else
    {
        LOG_DEBUG("no middleware path provided");
        config->pin = string_duplicate(js_pin->valuestring);
        config->pin_size = strlen(config->pin) + 1;
    }

    char *json_parsed = strncpy(config->serial_number, cJSON_GetObjectItem(json_management_service, "serial_number")->valuestring, SERIAL_NUMBER_SIZE);
    if (json_parsed == NULL)
    {
        goto error_occured;
    }

    cJSON *json_identity = cJSON_GetObjectItem(json_management_service, "management_identity");

    char *identity = cJSON_GetObjectItem(json_identity, "identity")->valuestring;
    if (identity == NULL)
    {
        goto error_occured;
    }
    network_identity nw_identitiy;
    if (strcmp(identity, "management_service") == 0)
    {
        nw_identitiy = MANAGEMENT_SERVICE;
    }
    else if (strcmp(identity, "managment") == 0)
    {
        nw_identitiy = MANAGEMENT;
    }
    else if (strcmp(identity, "remote") == 0)
    {
        nw_identitiy = REMOTE;
    }
    else if (strcmp(identity, "production") == 0)
    {
        nw_identitiy = PRODUCTION;
    }
    else
    {
        LOG_ERROR("unknown identity");
        goto error_occured;
    }
    config->identity.identity = nw_identitiy;

    ret = parse_endpoint_addr(cJSON_GetObjectItem(json_identity, "server_addr")->valuestring,
                              config->identity.server_endpoint_addr.address, ENDPOINT_LEN, &config->identity.server_endpoint_addr.port);
    if (ret < 0)
        goto error_occured;

    config->identity.filepath_size = strlen(identity_path) + 40;
    config->identity.filepath = malloc(config->identity.filepath_size);

    get_identity_folder_path(config->identity.filepath, config->identity.filepath_size,
                             identity_path,
                             config->identity.identity);

    config->identity.revocation_list_url = string_duplicate(cJSON_GetObjectItem(json_identity, "revocation_list_url")->valuestring);
    if (config->identity.revocation_list_url == NULL)
    {
        goto error_occured;
    }
    config->identity.revocation_list_url_size = strlen(config->identity.revocation_list_url) + 1; //'\0'

    config->identity.server_url = string_duplicate(cJSON_GetObjectItem(json_identity, "server_url")->valuestring);
    if (config->identity.server_url == NULL)
    {
        goto error_occured;
    }
    config->identity.server_url_size = strlen(config->identity.server_url) + 1; //'\0'

    return ret;

error_occured:
    ret = -1;
    LOG_ERROR("can't parse management serivce configuation, error occured with errno: %d", errno);
    return ret;
}

int parse_buffer_to_Config(char *json_buffer, int json_buffer_size, Kritis3mNodeConfiguration *config)
{
    int ret = 0;
    int string_len = -1;
    char helper_string[1024];

    /** ---------------------------   Derive Folder Crypto Folder from crypto_path ------------------------- */
    // base crypto path
    cJSON *root = cJSON_ParseWithLength(json_buffer, json_buffer_size);
    config->crypto_path = string_duplicate(cJSON_GetObjectItem(root, "crypto_path")->valuestring);
    if (config->crypto_path == NULL)
    {
        ret = -1;
        goto error_occured;
    }
    config->crypto_path_size = strlen(config->crypto_path) + 1;

    config->config_path = string_duplicate(cJSON_GetObjectItem(root, "config_path")->valuestring);
    if (config->config_path == NULL)
    {
        ret = -1;
        goto error_occured;
    }
    config->config_path_size = strlen(config->config_path) + 1;

    // machine folder
    snprintf(helper_string, sizeof(helper_string), "%s/%s", config->crypto_path, "machine");
    config->machine_crypto_path = string_duplicate(helper_string);
    if (config->machine_crypto_path == NULL)
        goto error_occured;
    config->machine_crypto_path_size = strlen(config->machine_crypto_path) + 1;

    // identity folder
    snprintf(helper_string, sizeof(helper_string), "%s/%s", config->crypto_path, "identity");
    config->pki_cert_path = string_duplicate(helper_string);
    if (config->pki_cert_path == NULL)
        goto error_occured;
    config->pki_cert_path_size = strlen(config->pki_cert_path) + 1;

    // management_service
    snprintf(helper_string, sizeof(helper_string), "%s/%s", config->pki_cert_path, "management_service");
    config->management_service_path = string_duplicate(helper_string);
    if (config->management_service_path == NULL)
        goto error_occured;
    config->management_service_path_size = strlen(config->management_service_path) + 1;

    // management
    snprintf(helper_string, sizeof(helper_string), "%s/%s", config->pki_cert_path, "management");
    config->management_path = string_duplicate(helper_string);
    if (config->management_path == NULL)
        goto error_occured;
    config->management_path_size = strlen(config->management_path) + 1;

    // remote
    snprintf(helper_string, sizeof(helper_string), "%s/%s", config->pki_cert_path, "remote");
    config->remote_path = string_duplicate(helper_string);
    if (config->remote_path == NULL)
        goto error_occured;
    config->remote_path_size = strlen(config->remote_path) + 1;

    // production
    snprintf(helper_string, sizeof(helper_string), "%s/%s", config->pki_cert_path, "production");
    config->production_path = string_duplicate(helper_string);
    if (config->production_path == NULL)
        goto error_occured;
    config->production_path_size = strlen(config->production_path) + 1;

    /**-------------------------- Selected Configuration------------------------------------------ */

    if (cJSON_GetObjectItem(root, "selected_configuration") == NULL)
    {
        config->selected_configuration = CFG_NONE;
    }
    else if (cJSON_IsNumber(cJSON_GetObjectItem(root, "selected_configuration")))
        config->selected_configuration = cJSON_GetObjectItem(root, "selected_configuration")->valueint;
    else
        goto error_occured;

    /** ------------------------------- Application Config--------------------------------------- */
    // primary file path
    snprintf(helper_string, sizeof(helper_string), "%s/%s", config->config_path, "primary.json");
    config->primary_path = string_duplicate(helper_string);
    if (config->primary_path == NULL)
    {
        goto error_occured;
    }
    config->primary_path_size = strlen(config->primary_path) + 1;

    // secondary file path
    snprintf(helper_string, sizeof(helper_string), "%s/%s", config->config_path, "secondary.json");
    config->secondary_path = string_duplicate(helper_string);
    if (config->secondary_path == NULL)
    {
        goto error_occured;
    }
    config->secondary_path_size = strlen(config->secondary_path) + 1;

    /**------------------------------------Management Service ------------------------------------ */
    cJSON *json_management_config = cJSON_GetObjectItem(root, "management_service");
    if (json_management_config == NULL)
        goto error_occured;
    ret = parse_json_to_ManagementConfig(json_management_config, &config->management_identity, config->pki_cert_path);
    if (ret < 0)
        goto error_occured;

    cJSON_Delete(root);
    return ret;
error_occured:
    LOG_ERROR("error occured in parse_buffer_to_config");
    cJSON_Delete(root);
    free_NodeConfig(config);
    return ret;
}

ManagementReturncode parse_buffer_to_SystemConfiguration(char *json_buffer,
                                                         int json_buffer_size,
                                                         SystemConfiguration *config,
                                                         char *crypto_path,
                                                         char *secure_middleware_path, char *pin)
{
    ManagementReturncode retval = MGMT_OK;
    cJSON *root = cJSON_ParseWithLength(json_buffer, json_buffer_size);

    /********************************* NODE PARSING*****************************************/
    // Parse primary configuration
    cJSON *node = cJSON_GetObjectItem(root, "node");
    if (node == NULL)
    {
        goto error_occured;
    }
    cJSON *item = cJSON_GetObjectItem(node, "serial_number");
    if (item == NULL)
        goto error_occured;
    else
        strncpy(config->serial_number, item->valuestring, NAME_LEN);

    item = cJSON_GetObjectItem(node, "network_index");
    if (item == NULL)
        goto error_occured;
    else
        config->node_network_index = item->valueint;
    item = cJSON_GetObjectItem(node, "id");
    if (item == NULL)
        goto error_occured;
    config->node_id = item->valueint;

    item = cJSON_GetObjectItem(node, "locality");
    if (item != NULL)
        strncpy(config->locality, item->valuestring, NAME_LEN);

    /********************************* END NODE PARSING *************************************/

    /********************************* CONFIGURATION PARSING *************************************/
    cJSON *configs = cJSON_GetObjectItem(node, "configs");
    if (configs == NULL)
        goto error_occured;
    int n = cJSON_GetArraySize(configs);
    if (n != 1)
        goto error_occured;
    configs = cJSON_GetArrayItem(configs, 0);

    item = cJSON_GetObjectItem(configs, "id");
    if (item == NULL)
        goto error_occured;
    config->cfg_id = item->valueint;

    item = cJSON_GetObjectItem(configs, "version");
    if (item != NULL)
    {
        config->version = item->valueint;
    }
    else
    {
        goto error_occured;
    }
    item = cJSON_GetObjectItem(configs, "log_level");
    if (item != NULL)
    {
        config->application_config.log_level = item->valueint;
    }
    /********************************** END CONFIGURATION ****************************/

    /*********************************** WHITELIST  **********************************/
    item = cJSON_GetObjectItem(configs, "whitelist");
    if (item == NULL)
        goto error_occured;
    retval = parse_whitelist(item, &config->application_config.whitelist);
    if (retval < MGMT_OK)
        goto error_occured;
    /***********************************END  WHITELIST  **********************************/

    /*********************************** HW_CONFIG      **********************************/

    item = cJSON_GetObjectItem(configs, "hw_config");
    if (item == NULL)
        goto error_occured;

    int number_hw_configs = cJSON_GetArraySize(item);
    if ((number_hw_configs == 0))
        goto error_occured;

    if (number_hw_configs > MAX_NUMBER_HW_CONFIG)
    {
        LOG_WARN("can't take over all ip addr, since store is just designed for %d ip addresses", MAX_NUMBER_HW_CONFIG);
        number_hw_configs = MAX_NUMBER_HW_CONFIG;
    }
    config->application_config.number_hw_config = number_hw_configs;

    for (int i = 0; i < number_hw_configs; i++)
    {
        cJSON *hw_config_item = cJSON_GetArrayItem(item, i);
        if (hw_config_item == NULL)
            goto error_occured;

        cJSON *json_dev = cJSON_GetObjectItem(hw_config_item, "device");
        if (json_dev == NULL)
            goto error_occured;

        strncpy(config->application_config.hw_config[i].device, json_dev->valuestring, IF_NAMESIZE);

        cJSON *json_ip_cidr = cJSON_GetObjectItem(hw_config_item, "cidr");
        if (json_ip_cidr == NULL)
            goto error_occured;
        strncpy(config->application_config.hw_config[i].ip_cidr, json_ip_cidr->valuestring, INET6_ADDRSTRLEN + 4);
    }

    /*********************************** End_HW_Config  **********************************/

    //*******************CRYPTO PROFILES *******************************************/
    cJSON *crypto_profiles = cJSON_GetObjectItem(root, "crypto_config");

    int number_crypto_profiles = cJSON_GetArraySize(crypto_profiles);
    if (number_crypto_profiles == 0)
        LOG_WARN("no crypto profiles provided");
    else if (number_crypto_profiles > MAX_NUMBER_CRYPTOPROFILE)
    {

        LOG_ERROR("too many crypto profiles provided");
        goto error_occured;
    }
    config->application_config.number_crypto_profiles = number_crypto_profiles;

    for (int i = 0; i < number_crypto_profiles; i++)
    {
        cJSON *crypto = cJSON_GetArrayItem(crypto_profiles, i);
        retval = parse_crypo_config(crypto, &config->application_config.crypto_profile[i], secure_middleware_path, pin);
        if (retval < MGMT_OK)
            goto error_occured;
    }
    /*******************CRYPTO IDENTITIES*********************************************/

    cJSON *crypto_identity_json = cJSON_GetObjectItem(root, "identities");
    int number_crypto_identities = cJSON_GetArraySize(crypto_identity_json);
    if ((number_crypto_identities == 0) || (number_crypto_identities > MAX_NUMBER_CRYPTOPROFILE))
    {
        LOG_WARN("no crypto identities provided, or to many ");
        goto error_occured;
    }
    config->application_config.number_crypto_identity = number_crypto_identities;
    for (int i = 0; i < number_crypto_identities; i++)
    {
        cJSON *crypto_identity = cJSON_GetArrayItem(crypto_identity_json, i);
        if (crypto_identity == NULL)
            goto error_occured;

        ManagementReturncode returncode = parse_crypo_identity(crypto_identity, &config->application_config.crypto_identity[i], crypto_path);
        if (returncode < 0)
            goto error_occured;
    }
    //*******************APPLICATION CONFIG*******************************************/
    cJSON *json_applications = cJSON_GetObjectItem(configs, "applications");
    int number_applications = cJSON_GetArraySize(json_applications);

    if (number_applications == 0)
        LOG_WARN("no applications provided");
    if (number_applications > MAX_NUMBER_APPLICATIONS)
    {
        LOG_WARN("Too many appls provided. Can't init %d applications ", MAX_NUMBER_APPLICATIONS - number_applications);
        number_applications = MAX_NUMBER_APPLICATIONS;
    }

    config->application_config.number_applications = number_applications;
    if (number_applications == 0)
        LOG_WARN("no applications available in this configuration");
    else if (number_applications > MAX_NUMBER_APPLICATIONS)
        goto error_occured;
    for (int i = 0; i < number_applications; i++)
    {
        item = cJSON_GetArrayItem(json_applications, i);
        retval = parse_application(item, &config->application_config.applications[i]);
        if (retval < MGMT_OK)
            goto error_occured;
    }
    cJSON_Delete(root);
    return retval;
error_occured:
    if (retval > MGMT_ERR)
        retval = MGMT_ERR;
    cJSON_Delete(root);
    LOG_ERROR("Error occured in getting system configuration, errno: %d", errno);
    return retval;
}

ManagementReturncode parse_whitelist(cJSON *json_obj, Whitelist *whitelist)
{
    ManagementReturncode ret = MGMT_OK;
    int number_trusted_clients = cJSON_GetArraySize(cJSON_GetObjectItem(json_obj, "trusted_clients"));
    whitelist->number_trusted_clients = number_trusted_clients;
    for (int i = 0; i < number_trusted_clients; i++)
    {

        cJSON *trusted_client_json = cJSON_GetArrayItem(cJSON_GetObjectItem(json_obj, "trusted_clients"), i);
        if (trusted_client_json == NULL)
            goto error_occured;

        cJSON *trusted_client_id = cJSON_GetObjectItem(trusted_client_json, "id");
        if ((trusted_client_id == NULL) || (trusted_client_id->valueint < 1))
            goto error_occured;
        whitelist->TrustedClients[i].id = trusted_client_id->valueint;

        cJSON *client_ip = cJSON_GetObjectItem(trusted_client_json, "client_endpoint_addr");
        if ((client_ip == NULL) || (strlen(client_ip->valuestring) < 1))
            goto error_occured;

        int retval = parse_addr_toKritis3maddr(client_ip->valuestring, &whitelist->TrustedClients[i].trusted_client);
        if (retval < 0)
        {
            goto error_occured;
        }

        int number_trusted_applications = cJSON_GetArraySize(cJSON_GetObjectItem(trusted_client_json, "application_ids"));
        whitelist->TrustedClients[i].number_trusted_applications = number_trusted_applications;
        for (int j = 0; j < number_trusted_applications; j++)
        {
            cJSON *trusted_applications = cJSON_GetArrayItem(trusted_client_json, j);
            if (trusted_applications == NULL)
                goto error_occured;
            whitelist->TrustedClients[i].trusted_applications_id[j] = trusted_applications->valueint;
        }
        // Note: trusted_applications_id is not present in the JSON, so it's not parsed here
    }
    return ret;

error_occured:
    ret = MGMT_PARSE_ERROR;
    return ret;
}

ManagementReturncode parse_application(cJSON *json_obj, Kritis3mApplications *application)
{
    ManagementReturncode ret = MGMT_OK;
    cJSON *item;
    item = cJSON_GetObjectItem(json_obj, "id");
    if (item == NULL)
        goto error_occured;
    application->id = item->valueint;

    item = cJSON_GetObjectItem(json_obj, "type");
    if (item == NULL)
        goto error_occured;
    application->type = item->valueint;

    item = cJSON_GetObjectItem(json_obj, "server_endpoint_addr");
    if (item == NULL)
        goto error_occured;
    ret = parse_endpoint_addr(item->valuestring, application->server_endpoint_addr.address, ENDPOINT_LEN, &application->server_endpoint_addr.port);
    if (ret < 0)
    {
        LOG_ERROR("cant parse ip addr from ip:port");
        goto error_occured;
    }

    item = cJSON_GetObjectItem(json_obj, "client_endpoint_addr");
    if (item == NULL)
        goto error_occured;

    ret = parse_endpoint_addr(item->valuestring, application->client_endpoint_addr.address, ENDPOINT_LEN, &application->client_endpoint_addr.port);
    if (ret < 0)
    {
        LOG_ERROR("cant parse ip addr from ip:port");
        goto error_occured;
    }

    item = cJSON_GetObjectItem(json_obj, "ep1_id");
    if (item == NULL)
        goto error_occured;
    application->ep1_id = item->valueint;

    item = cJSON_GetObjectItem(json_obj, "ep2_id");
    application->ep2_id = (item == NULL) ? -1 : item->valueint;

    item = cJSON_GetObjectItem(json_obj, "log_level");
    application->log_level = (item == NULL) ? LOG_LVL_WARN : item->valueint;

    application->state = false;
    return ret;
error_occured:
    ret = MGMT_PARSE_ERROR;
    LOG_ERROR("cannot parse Kritis3m_application");
    return ret;
}
/**
 * parses a crypto idenity
 * @brief at the moment, identity paths are stored twice, once in the identity structure and one in the parent object.
 * @todo make paths more consistent
 */
ManagementReturncode parse_crypo_identity(cJSON *identity_json, crypto_identity *identity, char *crypto_identity_path)
{
    ManagementReturncode ret = MGMT_OK;
    cJSON *item;
    item = cJSON_GetObjectItem(identity_json, "id");
    if ((item == NULL) || (item->valueint < 0))
        goto error_occured;
    identity->id = item->valueint;

    item = cJSON_GetObjectItem(identity_json, "identity");
    if (item == NULL)
        goto error_occured;
    identity->identity = item->valueint;

    identity->filepath_size = strlen(crypto_identity_path) + 50;
    identity->filepath = malloc(identity->filepath_size);

    ret = get_identity_folder_path(identity->filepath, identity->filepath_size, crypto_identity_path, identity->identity);
    if (ret < 0)
        goto error_occured;

    item = cJSON_GetObjectItem(identity_json, "server_endpoint_addr");
    if ((item == NULL) || (strlen(item->valuestring) < 1))
        goto error_occured;

    ret = parse_endpoint_addr(item->valuestring,
                              identity->server_endpoint_addr.address,
                              ENDPOINT_LEN,
                              &identity->server_endpoint_addr.port);
    if (ret < 0)
    {
        LOG_ERROR("cant parse ip addr from ip:port");
        goto error_occured;
    }

    item = cJSON_GetObjectItem(identity_json, "server_url");
    if (item == NULL)
        goto error_occured;
    if (strlen(item->string) < 1)
    {
        identity->server_url = NULL;
        identity->server_url_size = 0;
    }
    else
    {
        identity->server_url = string_duplicate(item->valuestring);
        identity->server_url_size = strlen(identity->server_url) + 1;
    }
    return ret;
error_occured:
    free_CryptoIdentity(identity);
    LOG_ERROR("error in parsing crypto profile");
    ret = MGMT_PARSE_ERROR;
    return ret;
}

ManagementReturncode parse_crypo_config(cJSON *json_obj, CryptoProfile *profile, char *secure_middleware_path, char *pin)
{
    if (json_obj == NULL)
        goto error_occured;
    profile->pin = pin;
    profile->secure_middleware_path = secure_middleware_path;

    ManagementReturncode ret = MGMT_OK;
    cJSON *item;
    item = cJSON_GetObjectItem(json_obj, "id");
    if ((item == NULL) || (item->valueint < 0))
        goto error_occured;
    profile->id = item->valueint;

    item = cJSON_GetObjectItem(json_obj, "name");
    if (item == NULL)
        goto error_occured;
    strncpy(profile->Name, item->valuestring, NAME_LEN);

    item = cJSON_GetObjectItem(json_obj, "mutual_auth");
    if (item == NULL)
        goto error_occured;
    profile->MutualAuthentication = cJSON_IsTrue(item);

    item = cJSON_GetObjectItem(json_obj, "no_encrypt");
    if (item == NULL)
        goto error_occured;
    profile->NoEncryption = cJSON_IsTrue(item);

    item = cJSON_GetObjectItem(json_obj, "kex");
    if (item == NULL)
        goto error_occured;
    profile->ASLKeyExchangeMethod = item->valueint;

    item = cJSON_GetObjectItem(json_obj, "use_secure_elem");
    if (item == NULL)
        goto error_occured;
    profile->UseSecureElement = cJSON_IsTrue(item);

    item = cJSON_GetObjectItem(json_obj, "signature_mode");
    if (item == NULL)
        goto error_occured;
    profile->HybridSignatureMode = item->valueint;

    item = cJSON_GetObjectItem(json_obj, "keylog");
    if (item == NULL)
    {
        profile->Keylog = false;
    }
    else
    {
        profile->Keylog = cJSON_IsTrue(item);
    }

    item = cJSON_GetObjectItem(json_obj, "identity_id");
    if ((item == NULL) || (item->valueint < 0))
        goto error_occured;
    profile->crypto_identity_id = item->valueint;

    return ret;
error_occured:
    LOG_ERROR("error in parsing crypto profile");
    ret = MGMT_PARSE_ERROR;
    return ret;
}