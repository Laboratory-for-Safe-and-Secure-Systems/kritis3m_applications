
#include "cJSON.h"
#include "logging.h"
#include "utils.h"
#include "errno.h"
#include "string.h"
#include <stdlib.h>
#include <stdio.h>
#include "configuration_parser.h"
LOG_MODULE_CREATE(kritis3m_config_paser);

int parse_whitelist(cJSON *json_obj, Whitelist *whitelist);
int parse_crypo_config(cJSON *json_obj, CryptoProfile *CryptoProfile);
int parse_crypo_identity(cJSON *json_obj, crypto_identity *crypto_identity, char *crypto_identity_path);
int parse_application(cJSON *json_obj, Kritis3mApplications *application);
int set_crypto_filepath(Kritis3mApplications *application, char *crypto_path);

int parseGenericIP(cJSON *json, struct GenericIP *result) {
    // Validate input
    if (!cJSON_IsObject(json)) {
        return 0;
    }

    // Extract IP address
    cJSON *ip_json = cJSON_GetObjectItemCaseSensitive(json, "ip");
    if (!cJSON_IsString(ip_json) || ip_json->valuestring == NULL) {
        return 0;
    }
    strncpy(result->ip, ip_json->valuestring, INET6_ADDRSTRLEN - 1);
    result->ip[INET6_ADDRSTRLEN - 1] = '\0';

    // Extract and validate port
    cJSON *port_json = cJSON_GetObjectItemCaseSensitive(json, "port");
    if (!cJSON_IsNumber(port_json)) {
        return 0;
    }
    int port = port_json->valueint;
    if (port <= 0 || port > 65535) {
        return 0;
    }
    result->port = (uint16_t)port;

    // Validate IP and determine family
    struct in_addr ipv4;
    struct in6_addr ipv6;
    
    if (inet_pton(AF_INET, result->ip, &ipv4) == 1) {
        result->domain = AF_INET;
        return 1;
    }
    
    if (inet_pton(AF_INET6, result->ip, &ipv6) == 1) {
        result->domain = AF_INET6;
        return 1;
    }

    return 0;
}


int parse_json_to_ManagementConfig(cJSON *json_management_service, Kritis3mManagemntConfiguration *config, char *identity_path)
{
    int ret = 0;
    config->server_addr = duplicate_string(cJSON_GetObjectItem(json_management_service, "server_addr")->valuestring);
    if (config->server_addr == NULL)
    {
        goto error_occured;
    }
    config->server_addr_size = strlen(config->server_addr) + 1; //'\0'

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
    config->identity.server_addr = duplicate_string(cJSON_GetObjectItem(json_identity, "server_addr")->valuestring);
    if (config->identity.server_addr == NULL)
    {
        goto error_occured;
    }

    config->identity.filepath_size = strlen(identity_path) + 40;
    config->identity.filepath = malloc(config->identity.filepath_size);

    get_identity_folder_path(config->identity.filepath, config->identity.filepath_size,
                             identity_path,
                             config->identity.identity);

    config->identity.server_addr_size = strlen(config->identity.server_addr) + 1; //'\0'

    config->identity.revocation_list_url = duplicate_string(cJSON_GetObjectItem(json_identity, "revocation_list_url")->valuestring);
    if (config->identity.revocation_list_url == NULL)
    {
        goto error_occured;
    }
    config->identity.revocation_list_url_size = strlen(config->identity.revocation_list_url) + 1; //'\0'

    config->identity.server_url = duplicate_string(cJSON_GetObjectItem(json_identity, "server_url")->valuestring);
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
    cJSON *root = cJSON_ParseWithLength(json_buffer, json_buffer_size);
    config->machine_crypto_path = duplicate_string(cJSON_GetObjectItem(root, "machine_crypto_path")->valuestring);
    if (config->machine_crypto_path == NULL)
    {
        ret = -1;
        goto error_occured;
    }
    config->machine_crypto_path_size = strlen(config->machine_crypto_path) + 1; // including '\0'

    config->crypto_path = duplicate_string(cJSON_GetObjectItem(root, "crypto_path")->valuestring);
    if (config->crypto_path == NULL)
    {
        ret = -1;
        goto error_occured;
    }
    config->crypto_path_size = strlen(config->crypto_path) + 1; // including '\0'
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

    config->primary_path = duplicate_string(cJSON_GetObjectItem(root, "primary_path")->valuestring);
    if (config->primary_path == NULL)
    {
        ret = -1;
        goto error_occured;
    }
    config->primary_path_size = strlen(config->primary_path) + 1; // including '\0'

    config->secondary_path = duplicate_string(cJSON_GetObjectItem(root, "secondary_path")->valuestring);
    if (config->secondary_path == NULL)
    {
        ret = -1;
        goto error_occured;
    }
    config->primary_path_size = strlen(config->secondary_path) + 1; // including '\0'

    if (cJSON_IsNumber(cJSON_GetObjectItem(root, "selected_configuration")))
        config->selected_configuration = cJSON_GetObjectItem(root, "selected_configuration")->valueint;
    else
        goto error_occured;
    // getting network identity
    cJSON *json_management_config = cJSON_GetObjectItem(root, "management_service");
    if (json_management_config == NULL)
        goto error_occured;
    ret = parse_json_to_ManagementConfig(json_management_config, &config->management_identity, config->pki_cert_path);
    if (ret < 0)
        goto error_occured;
    cJSON_Delete(root);
    return ret;
error_occured:
    cJSON_Delete(root);
    free_NodeConfig(config);
    return ret;
}

ManagementReturncode parse_buffer_to_SystemConfiguration(char *json_buffer, int json_buffer_size, SystemConfiguration *config, char *crypto_path)
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

    item = cJSON_GetObjectItem(configs, "hb_interval");
    if (item == NULL)
        goto error_occured;
    config->heartbeat_interval = item->valueint;

    item = cJSON_GetObjectItem(configs, "version");
    // if (item == NULL)
    // goto error_occured;
    // config->version = item->valueint;
    /********************************** END CONFIGURATION ****************************/

    /*********************************** WHITELIST  **********************************/
    item = cJSON_GetObjectItem(configs, "whitelist");
    if (item == NULL)
        goto error_occured;
    retval = parse_whitelist(item, &config->application_config.whitelist);
    if (retval < MGMT_OK)
        goto error_occured;
    /***********************************END  WHITELIST  **********************************/

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
        retval = parse_crypo_config(crypto, &config->application_config.crypto_profile[i]);
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

        cJSON *client_ip = cJSON_GetObjectItem(trusted_client_json, "client_ip_port");
        if ((client_ip == NULL) || (strlen(client_ip->valuestring) < 1))
            goto error_occured;
        strncpy(whitelist->TrustedClients[i].client_ip_port, client_ip->valuestring, IPv4_PORT_LEN);

        ret = parse_ip_port_to_sockaddr_in(whitelist->TrustedClients[i].client_ip_port, &whitelist->TrustedClients[i].addr);
        if (ret < 0)
        {
            LOG_ERROR("can't parse ip addr");
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

    item = cJSON_GetObjectItem(json_obj, "server_ip_port");
    if (item == NULL)
        goto error_occured;
    ret = parse_IPv4_fromIpPort(item->valuestring, application->server_ip);
    if (ret < 0 ){
        LOG_ERROR("cant parse ip addr from ip:port");
        goto error_occured;
    }
    int port  = parse_port_fromIpPort(item->valuestring);
    if (port  < 0){
        LOG_ERROR("no correct port in addr");
        goto error_occured;
    }
    application->server_port = port;


    item = cJSON_GetObjectItem(json_obj, "client_ip_port");
    if (item == NULL)
        goto error_occured;
    ret = parse_IPv4_fromIpPort(item->valuestring, application->client_ip);
    if (ret < 0 ){
        LOG_ERROR("cant parse ip addr from ip:port");
        goto error_occured;
    }
    port  = parse_port_fromIpPort(item->valuestring);
    if (port  < 0){
        LOG_ERROR("no correct port in addr");
        goto error_occured;
    }
    application->client_port= port;

    item = cJSON_GetObjectItem(json_obj, "ep1_id");
    if (item == NULL)
        goto error_occured;
    application->ep1_id = item->valueint;

    item = cJSON_GetObjectItem(json_obj, "ep2_id");
    application->ep2_id = (item == NULL) ? -1 : item->valueint;

    item = cJSON_GetObjectItem(json_obj, "log_level");
    application->log_level = ( item == NULL) ? LOG_LVL_WARN : item->valueint ; 

    application->state = false;
    return ret;
error_occured:
    ret = MGMT_PARSE_ERROR;
    LOG_ERROR("cannot parse Kritis3m_application");
    return ret;
}
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

    item = cJSON_GetObjectItem(identity_json, "server_addr");
    if ((item == NULL) || (strlen(item->valuestring) < 1))
        goto error_occured;
    identity->server_addr = duplicate_string(item->valuestring);
    identity->server_addr_size = strlen(identity->server_addr) + 1;

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
        identity->server_url = duplicate_string(item->valuestring);
        identity->server_url_size = strlen(identity->server_addr) + 1;
    }
    return ret;
error_occured:
    free_CryptoIdentity(identity);
    LOG_ERROR("error in parsing crypto profile");
    ret = MGMT_PARSE_ERROR;
    return ret;
}

ManagementReturncode parse_crypo_config(cJSON *json_obj, CryptoProfile *profile)
{
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
        goto error_occured;
    profile->Keylog = cJSON_IsTrue(item);

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

int Kritis3mNodeConfiguration_tojson(Kritis3mNodeConfiguration *config, char **buffer)
{
    int ret = 0;
    if (config == NULL || buffer == NULL)
        return -1;
    cJSON *root = cJSON_CreateObject(); // Create root JSON object

    // Management service object
    cJSON *management_service = cJSON_CreateObject();
    cJSON_AddStringToObject(management_service, "serial_number", config->management_identity.serial_number);
    cJSON_AddStringToObject(management_service, "server_addr", config->management_identity.server_addr);

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
    cJSON_AddItemToObject(management_service, "management_pki", management_pki);

    // Add management service to root
    cJSON_AddItemToObject(root, "management_service", management_service);

    // Add other paths and configuration
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
