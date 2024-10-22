#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "cJSON.h"
#include "kritis3m_configuration.h" // Assuming this is the header file containing the struct definitions
#include "logging.h"
#include "utils.h"
#include "errno.h"
#include "configuration_parser.h"
LOG_MODULE_CREATE(kritis3m_configuration);

// Function prototypes

const char *identity_folder_names[max_identities] = {
    "management_service",
    "management",
    "remote",
    "production"};

static ConfigurationManager config_manger;

int get_Kritis3mNodeConfiguration(char *filename, Kritis3mNodeConfiguration *config)
{
    int ret = 0;
    uint8_t *json_buffer = NULL;
    int file_size = -1;

    if ((filename == NULL) || (config == NULL))
        goto error_occured;

    ret = read_file(filename, &json_buffer, &file_size);
    if ((ret < 0) || (file_size <= 0))
    {
        goto error_occured;
    }
    ret = parse_buffer_to_Config(json_buffer, file_size, config);
    if (json_buffer != NULL)
        free(json_buffer);
    if (ret < 0)
        goto error_occured;
    return ret;

error_occured:
    LOG_ERROR("Error occured in Read configuration, with error code %d", errno);
    if (json_buffer != NULL)
        free(json_buffer);
    return ret;
}
/**
 * what happens if file has no content:
 * -> new file will be created
 */
ManagementReturncode get_systemconfig(char *filename, SystemConfiguration *systemconfig, char *cryptopath)
{
    int ret = 0;
    ManagementReturncode retval = MGMT_OK;
    uint8_t *json_buffer = NULL;
    int file_size = -1;

    if ((filename == NULL) || (systemconfig == NULL))
        goto error_occured;

    ret = read_file(filename, &json_buffer, &file_size);
    // empty file or no file
    if ((ret < 0))
    {
        retval = MGMT_EMPTY_OBJECT_ERROR;
        // create file for the future
        write_file(filename, "", sizeof(""));
        goto error_occured;
    }
    else if (file_size <= 1)
    {
        retval = MGMT_EMPTY_OBJECT_ERROR;
        goto error_occured;
    }

    retval = parse_buffer_to_SystemConfiguration(json_buffer, file_size, systemconfig, cryptopath);
    if (retval == MGMT_PARSE_ERROR)
    {
        LOG_ERROR("error parsing system configuration");
        goto error_occured;
    }
    else if (retval < MGMT_ERR)
    {
        LOG_ERROR("error occured during parsing configuration");
        goto error_occured;
    }
    return ret;

error_occured:
    if (retval > MGMT_ERR)
        retval = MGMT_ERR;
    LOG_ERROR("Error occured in Read configuration, with error code %d", errno);
    free(json_buffer);
    return retval;
}

SystemConfiguration *get_active_config(ConfigurationManager *manager)
{
    if (manager->active_configuration == CFG_PRIMARY)
    {
        return &manager->primary;
    }
    else if (manager->active_configuration == CFG_SECONDARY)
    {
        return &manager->secondary;
    }
    else
    {
        return NULL;
    }
}
SystemConfiguration *get_inactive_config(ConfigurationManager *manager)
{
    if (manager->active_configuration == CFG_PRIMARY)
    {
        return &manager->secondary;
    }
    else if (manager->active_configuration == CFG_SECONDARY)
    {
        return &manager->primary;
    }
    else
    {
        return NULL;
    }
}

// calls the management server, if no config exists,
// returns the active configuration
ManagementReturncode get_Systemconfig(ConfigurationManager *applconfig, Kritis3mNodeConfiguration *node_config)
{
    /***
     * Three cases must be checked:
     * - No config is available: The Management Server must be instantly called for a configuration
     * - One/Two config/s is/are available: The application can be started. And the next Heartbeat is awaited
     * - Configuration is available, but incomplete
     */
    ManagementReturncode ret = 0;
    SystemConfiguration *sys_config = NULL;
    char *filepath;
    SelectedConfiguration selected_configuration = CFG_NONE;

    if ((applconfig == NULL) || (node_config == NULL))
        goto error_occured;



    switch (applconfig->active_configuration)
    {
    case CFG_PRIMARY:
        applconfig->active_configuration = CFG_PRIMARY;
        sys_config = &applconfig->primary;
        filepath = applconfig->primary_file_path;
        // get primary filepath
        break;
    case CFG_SECONDARY:
        applconfig->active_configuration = CFG_SECONDARY;
        sys_config = &applconfig->secondary;
        filepath = applconfig->secondary_file_path;
        // get secondary filepath
        if (ret < 0)
            goto error_occured;
        break;
    case CFG_NONE:
        applconfig->active_configuration = CFG_PRIMARY;
        LOG_INFO("selected config not provided. Use primary as new selected config");
        return MGMT_EMPTY_OBJECT_ERROR;
        break;
    default:
        LOG_INFO("selected config not provided. Use primary as new selected config");
        return MGMT_EMPTY_OBJECT_ERROR;
        break;
    }
    // reads and parses data from filepath to sys_config object
    ret = get_systemconfig(filepath, sys_config, node_config->pki_cert_path);
    return ret;

error_occured:
    if (ret > MGMT_ERR)
        ret = MGMT_ERR;
    return ret;
}

int write_SystemConfig_toflash(SystemConfiguration *sys_cfg, char *filepath, int filepath_size)
{
    memset(filepath, 0, sizeof(filepath));
    // SystemConfig to json String
    // reads and parses data from filepath to sys_config object
    char *buffer;
    int buffer_size;
    int ret = write_file(filepath, buffer, buffer_size);
    return ret;
error_occured:
    if (ret > -1)
        ret = -1;
}
int write_Kritis3mNodeConfig_toflash(Kritis3mNodeConfiguration *config)

{
    char *buffer = NULL;
    int ret = 0;
    FILE *file = NULL;
    if (config == NULL)
        goto error_occured;
    ret = Kritis3mNodeConfiguration_tojson(config, &buffer);
    file = fopen(config->config_path, "w");
    // Check if the file was opened successfully
    if (file == NULL)
        goto error_occured;
    if (fwrite(buffer, sizeof(char), strlen(buffer), file) != strlen(buffer))
        goto error_occured;
    fclose(file);
    LOG_INFO("File written successfully.\n");
    free(buffer);
    return ret;
error_occured:
    if (file != NULL)
        fclose(file);
    free(buffer);
    ret = -1;
    return ret;
}

int set_SelectedConfiguration(Kritis3mNodeConfiguration *config, int selected_configuration)
{
    LOG_INFO("not implemented");
    return 0;
error_occured:
    int ret = -1;
    LOG_ERROR("Can't set selected configuration");
}

Kritis3mApplications *find_application_by_application_id(Kritis3mApplications *appls, int number_appls, int appl_id)
{
    if (appls == NULL)
        goto error_occured;
    Kritis3mApplications *t_appl = NULL;

    for (int i = 0; i < number_appls; i++)
    {
        t_appl = &appls[i];
        if (t_appl == NULL)
            goto error_occured;
        if (t_appl->id == appl_id)
            return t_appl;
    }
    return NULL;

error_occured:
    LOG_ERROR("No matching applicaiton for application id %d found", appl_id);
    return NULL;
}
// Function to return the path of the identity folder

int get_identity_folder_path(char *out_path, size_t size, const char *base_path, network_identity identity)
{
    if (identity < MANAGEMENT_SERVICE || identity >= max_identities)
    {
        fprintf(stderr, "Invalid identity\n");
        return -1;
    }

    snprintf(out_path, size, "%s/%s", base_path, identity_folder_names[identity]);
    return 0;
}

void free_ManagementConfiguration(Kritis3mManagemntConfiguration *config)
{
    config->server_addr_size = 0;
    if (config->server_addr != NULL)
        free(config->server_addr);
    if (config->identity.revocation_list_url != NULL)
        free(config->identity.revocation_list_url);
    if (config->identity.server_addr != NULL)
        free(config->identity.server_addr);
    if (config->identity.server_url != NULL)
        free(config->identity.server_url);
}

void free_CryptoIdentity(crypto_identity *identity)
{
    identity->filepath_size = 0;
    identity->server_addr_size = 0;
    identity->server_url_size = 0;
    identity->revocation_list_url_size = 0;
    identity->certificates.additional_key_buffer_size = 0;
    identity->certificates.root_buffer_size = 0;
    identity->certificates.key_buffer_size = 0;
    identity->certificates.chain_buffer_size = 0;
    if (identity != NULL)
    {
        if (identity->filepath != NULL)
            free(identity->filepath);

        if (identity->server_addr != NULL)
            free(identity->server_addr);

        if (identity->server_url != NULL)
            free(identity->server_url);

        if (identity->revocation_list_url != NULL)
            free(identity->revocation_list_url);

        if (identity->certificates.additional_key_buffer != NULL)
            free(identity->certificates.additional_key_buffer);

        if (identity->certificates.key_buffer != NULL)
            free(identity->certificates.key_buffer);
        if (identity->certificates.chain_buffer != NULL)
            free(identity->certificates.chain_buffer);
        if (identity->certificates.root_buffer != NULL)
            free(identity->certificates.root_buffer);
    }
}

void free_NodeConfig(Kritis3mNodeConfiguration *config)
{

    if (config != NULL)
    {
        config->config_path_size = 0;
        config->primary_path_size = 0;
        config->secondary_path_size = 0;
        config->pki_cert_path_size = 0;
        config->machine_crypto_path_size = 0;
        if (config->primary_path != NULL)
            free(config->primary_path);
        if (config->secondary_path != NULL)
            free(config->secondary_path);
        if (config->machine_crypto_path != NULL)
            free(config->machine_crypto_path);
        if (config->pki_cert_path != NULL)
            free(config->pki_cert_path);
        if (config->crypto_path != NULL)
            free(config->crypto_path);
    }
    free_CryptoIdentity(&config->management_identity.identity);
}

void cleanup_Systemconfiguration(SystemConfiguration *systemconfiguration)
{

    systemconfiguration->cfg_id = 0;
    systemconfiguration->node_id = 0;
    memset(systemconfiguration->locality, 0, NAME_LEN);
    memset(systemconfiguration->serial_number, 0, NAME_LEN);
    systemconfiguration->node_network_index = 0;
    systemconfiguration->heartbeat_interval = 0;
    systemconfiguration->version = 0;
    Whitelist *whitelist = &systemconfiguration->application_config.whitelist;
    for (int i = 0; i < whitelist->number_trusted_clients; i++)
    {
        memset(&whitelist->TrustedClients[i].addr, 0, sizeof(whitelist->TrustedClients[i].addr));
        memset(&whitelist->TrustedClients[i].client_ip_port, 0, IPv4_PORT_LEN);
        whitelist->TrustedClients[i].id = 0;
        whitelist->TrustedClients[i].number_trusted_applications = 0;
        for (int j = 0; j < whitelist->TrustedClients[i].number_trusted_applications; j++)
            whitelist->TrustedClients[i].trusted_applications_id[j] = 0;
    }

    for (int i = 0; i < MAX_NUMBER_CRYPTOPROFILE; i++)
    {
        CryptoProfile *profile = &systemconfiguration->application_config.crypto_profile[i];
        profile->id = -1;
        profile->ASLKeyExchangeMethod = ASL_KEX_DEFAULT,
        profile->HybridSignatureMode = ASL_HYBRID_SIGNATURE_MODE_DEFAULT;
        profile->crypto_identity_id = 0;
        profile->Keylog = false;
        profile->NoEncryption = false;
        profile->UseSecureElement = false;
        memset(profile->Name, 0, MAX_NAME_SIZE);
    }

    for (int i = 0; i < MAX_NUMBER_APPLICATIONS; i++)
    {
        Kritis3mApplications *appl = &systemconfiguration->application_config.applications[i];
        appl->id = -1;
        appl->ep1_id = -1;
        appl->ep2_id = -1;
        appl->config_id = -1;
        appl->log_level = -1;
        appl->state = 0;
        appl->type = UNDEFINED;
        memset(appl->client_ip_port, 0, IPv4_PORT_LEN);
        memset(appl->server_ip_port, 0, IPv4_PORT_LEN);
    }

    for (int i = 0; i < MAX_NUMBER_CRYPTOPROFILE; i++)
    {
        crypto_identity *cr_identity = &systemconfiguration->application_config.crypto_identity[i];
        cr_identity->identity = MANAGEMENT_SERVICE;
        free_CryptoIdentity(cr_identity);
    }
}