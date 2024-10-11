#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cJSON.h"
#include "kritis3m_configuration.h" // Assuming this is the header file containing the struct definitions
#include "logging.h"
#include "utils.h"
#include "errno.h"
#include "configuration_parser.h"
LOG_MODULE_CREATE(kritis3m_configuration);

// Function prototypes

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

error_occured:
    LOG_ERROR("Error occured in Read configuration, with error code %d", errno);
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
    if ((ret < 0) || (file_size <= 1))
    {
        retval = MGMT_EMPTY_OBJECT_ERROR;
        LOG_ERROR("Can't open file: %s, probably file does not exist", filename);
        goto error_occured;
    }
    retval = parse_buffer_to_SystemConfiguration(json_buffer, file_size, systemconfig);
    if (retval == MGMT_PARSE_ERROR)
    {
        LOG_ERROR("error parsing system configuration");
        goto error_occured;
    }
    else if (retval < MGMT_ERROR)
    {
        LOG_ERROR("error occured during parsing configuration");
        goto error_occured;
    }
    return ret;

error_occured:
    if (retval > MGMT_ERROR)
        retval = MGMT_ERROR;
    LOG_ERROR("Error occured in Read configuration, with error code %d", errno);
    free(json_buffer);
    return ret;
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
    char filepath[512];
    SelectedConfiguration selected_configuration = CFG_NONE;
    char *application_config_path = NULL;
    int application_config_path_size = -1;

    if ((applconfig == NULL) || (node_config == NULL))
        goto error_occured;

    selected_configuration = node_config->selected_configuration;
    application_config_path = node_config->application_configuration_path;
    application_config_path_size = node_config->application_configuration_path_size;
    memset(filepath, 0, sizeof(filepath));

    switch (selected_configuration)
    {
    case CFG_PRIMARY:
        applconfig->active_configuration = CFG_PRIMARY;
        sys_config = &applconfig->primary;
        // get primary filepath
        ret = create_file_path(filepath, sizeof(filepath),
                               node_config->application_configuration_path, node_config->application_configuration_path_size,
                               PRIMARY_FILENAME, sizeof(PRIMARY_FILENAME));
        if (ret < 0)
            goto error_occured;
        break;
    case CFG_SECONDARY:
        applconfig->active_configuration = CFG_SECONDARY;
        sys_config = &applconfig->secondary;
        // get secondary filepath
        ret = create_file_path(filepath, sizeof(filepath),
                               node_config->application_configuration_path, node_config->application_configuration_path_size,
                               SECONDARY_FILENAME, sizeof(SECONDARY_FILENAME));
        if (ret < 0)
            goto error_occured;
        break;
    case CFG_NONE:
        LOG_INFO("calling management server");
        applconfig->active_configuration = CFG_PRIMARY;
        sys_config = &applconfig->primary;
        // get primary filepath
        ret = create_file_path(filepath, sizeof(filepath),
                               node_config->application_configuration_path, node_config->application_configuration_path_size,
                               PRIMARY_FILENAME, sizeof(PRIMARY_FILENAME));
        if (ret < 0)
            goto error_occured;
        break;
    default:
        applconfig->active_configuration = CFG_PRIMARY;
        LOG_INFO("selected config not provided. Use primary as new selected config");
        LOG_INFO("calling management server");
        sys_config = &applconfig->primary;
        // get primary filepath
        ret = create_file_path(filepath, sizeof(filepath),
                               node_config->application_configuration_path, node_config->application_configuration_path_size,
                               PRIMARY_FILENAME, sizeof(PRIMARY_FILENAME));
        if (ret < 0)
            goto error_occured;
        LOG_INFO("calling management server");
        break;
    }
    // reads and parses data from filepath to sys_config object
    ret = get_systemconfig(filepath, sys_config);
    return ret;

error_occured:
    if (ret > MGMT_ERROR)
        ret = MGMT_ERROR;
    return ret;
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