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

int get_Kritis3mNodeConfiguration(char *filename, Kritis3mNodeConfiguration *config)
{
    int ret = 0;
    char *json_buffer = NULL;
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
ManagementReturncode get_systemconfig(char *filename, SystemConfiguration *systemconfig)
{
    int ret = 0;
    ManagementReturncode retval = MGMT_OK;
    char *json_buffer = NULL;
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

    retval = parse_buffer_to_SystemConfiguration(json_buffer, file_size, systemconfig);
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
    char *application_config_path = NULL;
    int application_config_path_size = -1;

    if ((applconfig == NULL) || (node_config == NULL))
        goto error_occured;

    selected_configuration = node_config->selected_configuration;
    application_config_path = node_config->application_configuration_path;
    application_config_path_size = node_config->application_configuration_path_size;

    if (ret < 0)
        goto error_occured;

    switch (selected_configuration)
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
        LOG_INFO("selected config not provided. Use primary as new selected config");
        return MGMT_EMPTY_OBJECT_ERROR;
        break;
    default:
        LOG_INFO("selected config not provided. Use primary as new selected config");
        return MGMT_EMPTY_OBJECT_ERROR;
        break;
    }
    // reads and parses data from filepath to sys_config object
    ret = get_systemconfig(filepath, sys_config);
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
    file = fopen(config->kritis3m_node_configuration_path, "w");
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
    int ret = 0;
    if (config == NULL)
        goto error_occured;
    else if (config->kritis3m_node_configuration_path == NULL)
        goto error_occured;

    return ret;

error_occured:
    ret = -1;
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
    free(config->management_server_url);
    free(config->management_service_ip);
    free(config->identity.pki_base_url);
}

void free_NodeConfig(Kritis3mNodeConfiguration *config)
{
    if (config != NULL)
    {
        if (config->config_path == NULL)
            free(config->config_path);

        if (config->pki_cert_path == NULL)
            free(config->pki_cert_path);

        if (config->machine_crypto_path == NULL)
            free(config->machine_crypto_path);

        if (config->application_configuration_path == NULL)
            free(config->application_configuration_path);
    }
}