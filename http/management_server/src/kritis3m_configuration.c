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

int get_systemconfig(char *filename, SystemConfiguration *systemconfig)
{
    int ret = 0;
    char *json_buffer = NULL;
    int file_size = -1;

    if ((filename == NULL) || (systemconfig == NULL))
        goto error_occured;

    ret = read_file(filename, &json_buffer, &file_size);
    if ((ret < 0) || (file_size <= 0))
    {
        goto error_occured;
    }
    ret = parse_buffer_to_SystemConfiguration(json_buffer, file_size, systemconfig);

error_occured:
    LOG_ERROR("Error occured in Read configuration, with error code %d", errno);
    free(json_buffer);
    return ret;
}

// calls the management server, if no config exists,
// returns the active configuration
int get_Systemconfig(ConfigurationManager *applconfig, Kritis3mNodeConfiguration *node_config)
{
    int ret = 0;
    SystemConfiguration *sys_config = NULL;
    char filepath[512];
    if ((applconfig == NULL) || (node_config == NULL))
        goto error_occured;

    int selected_configuration = node_config->selected_configuration;
    char *application_config_path = node_config->application_configuration_path;
    int application_config_path_size = node_config->application_configuration_path_size;
    memset(filepath, 0, sizeof(filepath));
    if (selected_configuration <= 0)
        LOG_INFO("calling management server");

    if (selected_configuration == 1)
    {
        sys_config = &applconfig->primary;
        // get primary filepath
        ret = create_file_path(filepath, sizeof(filepath),
                               node_config->application_configuration_path, node_config->application_configuration_path_size,
                               PRIMARY_FILENAME, sizeof(PRIMARY_FILENAME));
        if (ret < 0)
            goto error_occured;
    }
    else if (selected_configuration == 2)
    {
        sys_config = &applconfig->secondary;
        // get secondary filepath
        ret = create_file_path(filepath, sizeof(filepath),
                               node_config->application_configuration_path, node_config->application_configuration_path_size,
                               SECONDARY_FILENAME, sizeof(SECONDARY_FILENAME));
        if (ret < 0)
            goto error_occured;
        // get secondary configuration
    }
    get_systemconfig(filepath, sys_config);

error_occured:
    ret = -1;
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
