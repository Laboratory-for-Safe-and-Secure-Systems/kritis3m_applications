
#include "cJSON.h"
#include "logging.h"
#include "utils.h"
#include "errno.h"
#include "string.h"
#include <stdio.h>
#include "configuration_parser.h"
LOG_MODULE_CREATE(kritis3m_config_paser);

int parse_whitelist(cJSON *json_obj, Whitelist *whitelist);
int parse_crypo_config(cJSON *json_obj, CryptoProfile *CryptoProfile);
int parse_application(cJSON *json_obj, Kritis3mApplications *application);

int parse_json_to_ManagementConfig(cJSON *json_management_service, Kritis3mManagemntConfiguration *config)
{
    int ret = 0;

    config->management_server_url = duplicate_string(cJSON_GetObjectItem(json_management_service, "management_server_url")->valuestring);
    if (config->management_server_url == NULL)
    {
        goto error_occured;
    }
    config->management_server_url_size = strlen(config->management_server_url) + 1;

    config->management_service_ip = duplicate_string(cJSON_GetObjectItem(json_management_service, "management_service_ip")->valuestring);
    if (config->management_service_ip == NULL)
    {
        goto error_occured;
    }
    char *json_parsed = strncpy(config->serial_number, cJSON_GetObjectItem(json_management_service, "serial_number")->valuestring, SERIAL_NUMBER_SIZE);
    if (json_parsed == NULL)
    {
        goto error_occured;
    }

    cJSON *json_identity = cJSON_GetObjectItem(json_management_service, "management_pki");

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
    config->identity.pki_base_url = duplicate_string(cJSON_GetObjectItem(json_identity, "url")->valuestring);
    if (config->identity.pki_base_url == NULL)
    {
        goto error_occured;
    }
    config->identity.pki_base_url_size = strlen(config->identity.pki_base_url) + 1; //'\0'
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
    cJSON *root = cJSON_ParseWithLength(json_buffer, json_buffer_size);
    config->application_configuration_path = duplicate_string(cJSON_GetObjectItem(root, "application_configuration_path")->valuestring);
    if (config->application_configuration_path == NULL)
    {
        ret = -1;
        goto error_occured;
    }
    config->application_configuration_path_size = strlen(config->application_configuration_path) + 1; // including '\0'
    config->machine_crypto_path = duplicate_string(cJSON_GetObjectItem(root, "machine_crypto_path")->valuestring);
    if (config->machine_crypto_path == NULL)
    {
        ret = -1;
        goto error_occured;
    }
    config->machine_crypto_path_size = strlen(config->machine_crypto_path) + 1; // including '\0'
    config->pki_cert_path = duplicate_string(cJSON_GetObjectItem(root, "pki_cert_path")->valuestring);
    if (config->pki_cert_path == NULL)
    {
        ret = -1;
        goto error_occured;
    }
    config->pki_cert_path_size = strlen(config->pki_cert_path) + 1; // including '\0'
    if (cJSON_GetObjectItem(root, "selected_configuration") == NULL)
    {
        ret = -1;
        goto error_occured;
    }
    if (cJSON_IsNumber(cJSON_GetObjectItem(root, "selected_configuration")))
        config->selected_configuration = cJSON_GetObjectItem(root, "selected_configuration")->valueint;
    else
        goto error_occured;
    // getting network identity
    cJSON *json_management_config = cJSON_GetObjectItem(root, "management_service");
    if (json_management_config == NULL)
        goto error_occured;
    ret = parse_json_to_ManagementConfig(json_management_config, &config->management_identity);
    if (ret < 0)
        goto error_occured;
    cJSON_Delete(root);
    return ret;
error_occured:
    cJSON_Delete(root);
    free_NodeConfig(config);
    return ret;
}

void free_ManagementConfiguration(Kritis3mManagemntConfiguration *config)
{
    free(config->management_server_url);
    free(config->management_service_ip);
    free(config->identity.pki_base_url);
}

void free_NodeConfig(Kritis3mNodeConfiguration *config)
{
    free(config->application_configuration_path);
    free(config->pki_cert_path);
    free(config->machine_crypto_path);
    free_ManagementConfiguration(&config->management_identity);
}

int parse_buffer_to_SystemConfiguration(char *json_buffer, int json_buffer_size, SystemConfiguration *config)
{
    int ret = 0;
    cJSON *root = cJSON_ParseWithLength(json_buffer, json_buffer_size);

    // Parse primary configuration
    cJSON *node = cJSON_GetObjectItem(root, "node");
    if (node == NULL)
    {
    }
    cJSON *item = cJSON_GetObjectItem(node, "serial_number");
    if (item == NULL)
        goto error_occured;
    else
        strcpy(config->serial_number, item->valuestring);

    item = cJSON_GetObjectItem(node, "network_index");
    if (item == NULL)
        goto error_occured;
    else
        config->node_network_index = item->valueint;
    item = cJSON_GetObjectItem(node, "node_id");
    if (item == NULL)
        goto error_occured;
    else
        config->node_id = item->valueint;
    item = cJSON_GetObjectItem(node, "id");
    if (item == NULL)
        goto error_occured;
    else
        config->id = item->valueint;
    item = cJSON_GetObjectItem(node, "hb_interval");
    if (item == NULL)
        goto error_occured;
    else
        // check if valueint can hold uint64_t
        config->heartbeat_interval = cJSON_GetNumberValue(item);
    item = cJSON_GetObjectItem(node, "updated_at");
    if (item == NULL)
        goto error_occured;
    else
        config->updated_at = cJSON_GetNumberValue(item);
    // These parameters are not required but can be usefull for logging purposes
    item = cJSON_GetObjectItem(node, "locality");
    if (item != NULL)
        // change this to strncpy in the future
        strcpy(config->locality, item->valuestring);
    item = cJSON_GetObjectItem(node, "updated_at");
    if (item != NULL)
        config->updated_at = cJSON_GetNumberValue(item);
    item = cJSON_GetObjectItem(node, "version");
    if (item != NULL)
        config->version = item->valueint;
    else
        LOG_WARN("no version provided");
    item = cJSON_GetObjectItem(node, "whitelist");
    if (item == NULL)
        goto error_occured;
    //*******************WHITELIST*******************************************/
    ret = parse_whitelist(item, &config->application_config.whitelist);
    if (ret < 0)
        goto error_occured;
    //*******************CRYPTO PROFILES *******************************************/
    cJSON *crypto_profiles = cJSON_GetObjectItem(node, "crypto_config");
    int number_crypto_profiles = cJSON_GetArraySize(crypto_profiles);
    if (number_crypto_profiles == 0)
        LOG_WARN("no crypto profiles provided");
    else if (number_crypto_profiles > MAX_NUMBER_CRYPTOPROFILE)
        goto error_occured;
    config->application_config.number_crypto_profiles = number_crypto_profiles;
    for (int i = 0; i < number_crypto_profiles; i++)
    {
        cJSON *crypto = cJSON_GetArrayItem(crypto_profiles, i);
        ret = parse_crypo_config(crypto, &config->application_config.crypto_profile[i]);
        if (ret < 0)
            goto error_occured;
    }
    //*******************APPLICATION CONFIG*******************************************/
    cJSON *json_applications = cJSON_GetObjectItem(node, "applications");
    int number_applications = cJSON_GetArraySize(json_applications);

    config->application_config.number_applications = number_applications;
    if (number_applications == 0)
        LOG_WARN("no applications available in this configuration");
    else if (number_applications > MAX_NUMBER_APPLICATIONS)
        goto error_occured;
    for (int i = 0; i < number_applications; i++)
    {
        item = cJSON_GetArrayItem(json_applications, i);
        ret = parse_application(item, &config->application_config.applications[i]);
        if (ret < 0)
            goto error_occured;
    }
    cJSON_Delete(root);
    return ret;
error_occured:
    cJSON_Delete(root);
    ret = -1;
    LOG_ERROR("Error occured in getting system configuration, errno: %d", errno);
    return ret;
}

int parse_whitelist(cJSON *json_obj, Whitelist *whitelist)
{
    int ret = 0;
    int number_trusted_clients = cJSON_GetArraySize(cJSON_GetObjectItem(json_obj, "trusted_clients"));
    whitelist->number_trusted_clients = number_trusted_clients;
    for (int i = 0; i < number_trusted_clients; i++)
    {
        cJSON *trusted_client_json = cJSON_GetArrayItem(cJSON_GetObjectItem(json_obj, "trusted_clients"), i);
        if (trusted_client_json == NULL)
            goto error_occured;
        cJSON *client_ip = cJSON_GetObjectItem(trusted_client_json, "client_ip_port");
        if (client_ip == NULL)
            goto error_occured;
        strcpy(whitelist->TrustedClients[i].client_ip_port, trusted_client_json->valuestring);
        int number_trusted_applications = cJSON_GetArraySize(cJSON_GetObjectItem(trusted_client_json, "trusted_applications_id"));
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
    ret = -1;
    return ret;
}

int parse_application(cJSON *json_obj, Kritis3mApplications *application)
{
    int ret = 0;
    cJSON *item;
    item = cJSON_GetObjectItem(json_obj, "id");
    if (item == NULL)
        goto error_occured;
    application->id = item->valueint;

    item = cJSON_GetObjectItem(json_obj, "type");
    if (item == NULL)
        goto error_occured;
    application->type = item->valueint;

    item = cJSON_GetObjectItem(json_obj, "servier_ip_port");
    if (item == NULL)
        goto error_occured;
    strcpy(application->server_ip_port, item->valuestring);

    item = cJSON_GetObjectItem(json_obj, "client_ip_port");
    if (item == NULL)
        goto error_occured;
    strcpy(application->client_ip_port, item->valuestring);

    item = cJSON_GetObjectItem(json_obj, "ep1_id");
    if (item == NULL)
        goto error_occured;
    application->ep1_id = item->valueint;

    item = cJSON_GetObjectItem(json_obj, "ep2_id");
    if (item == NULL)
        LOG_INFO("Ep2_config not in Application config with application id: %d", application->id);
    application->ep2_id = item->valueint;

    item = cJSON_GetObjectItem(json_obj, "log_level");
    if (item == NULL)
        LOG_WARN("No Log levle included. Default log_level will be selected");
    else
        application->log_level = item->valueint;

    application->state = false;
    return ret;
error_occured:
    LOG_ERROR("cannot parse Kritis3m_application");
    ret = -1;
    return ret;
}

int parse_crypo_config(cJSON *json_obj, CryptoProfile *profile)
{
    int ret = 0;
    cJSON *item;
    item = cJSON_GetObjectItem(json_obj, "id");
    if (item == NULL)
        goto error_occured;
    profile->ID = item->valueint;

    item = cJSON_GetObjectItem(json_obj, "name");
    if (item == NULL)
        goto error_occured;
    strcpy(profile->Name, item->valuestring);

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
        goto error_occured;
    profile->Keylog = cJSON_IsTrue(item);

    item = cJSON_GetObjectItem(json_obj, "identity");
    if (item == NULL)
        goto error_occured;
    profile->Identity.identity = item->valueint;

    return ret;
error_occured:
    LOG_ERROR("error in parsing crypto profile");
    ret = -1;
    return ret;
}

int Kritis3mNodeConfiguration_tojson(Kritis3mNodeConfiguration *config, char **buffer)
{
    int ret = 0;
    if (config == NULL || buffer == NULL)
        return -1;
    cJSON *root = cJSON_CreateObject(); // Create root JSON object

    // Management service object
    cJSON *management_service = cJSON_CreateObject();
    cJSON_AddStringToObject(management_service, "serial_number", config->management_identity.serial_number);
    cJSON_AddStringToObject(management_service, "management_server_url", config->management_identity.management_server_url);
    cJSON_AddStringToObject(management_service, "management_service_ip", config->management_identity.management_service_ip);

    // Management PKI object
    cJSON *management_pki = cJSON_CreateObject();
    switch (config->management_identity.identity.identity)
    {
    case MANAGEMENT_SERVICE:
        cJSON_AddStringToObject(management_pki, "identity", MANAGEMENT_SERVICE_STR);
        break;
    case MANAGEMENT:
        cJSON_AddStringToObject(management_pki, "identity", MANAGEMENT_STR);
        break;
    case REMOTE:
        cJSON_AddStringToObject(management_pki, "identity", REMOTE_STR);
        break;
    case PRODUCTION:
        cJSON_AddStringToObject(management_pki, "identity", PRODUCTION_STR);
        break;
    }
    cJSON_AddStringToObject(management_pki, "url", config->management_identity.identity.pki_base_url);
    cJSON_AddItemToObject(management_service, "management_pki", management_pki);

    // Add management service to root
    cJSON_AddItemToObject(root, "management_service", management_service);

    // Add other paths and configuration
    cJSON_AddStringToObject(root, "application_configuration_path", config->application_configuration_path);
    cJSON_AddStringToObject(root, "machine_crypto_path", config->machine_crypto_path);
    cJSON_AddStringToObject(root, "pki_cert_path", config->pki_cert_path);

    // Add selected configuration
    cJSON_AddNumberToObject(root, "selected_configuration", config->selected_configuration);
    // Convert to string
    char *json_string = cJSON_Print(root);
    // Clean up
    cJSON_Delete(root);
    *buffer = json_string;
    return ret;
}