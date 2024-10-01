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
    ret = read_file(filename, json_buffer, &file_size);
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

int get_Application_config(ConfigurationManager *applconfig, Kritis3mNodeConfiguration *node_config)
{
    int ret = 0;
    int selected_configuration = node_config->selected_configuration;
    char *application_config_path = node_config->application_configuration_path;
    int application_config_path_size = node_config->application_configuration_path_size;
    char filepath[512];
    memset(filepath, 0, sizeof(filepath));

    if (selected_configuration <= 0)
    {
        // call management server
        // initial call to management server
        LOG_INFO("calling management server");
    }
    else if (selected_configuration == 1)
    {
        // get primary filepath 
        ret = create_file_path(filepath, sizeof(filepath),
                               node_config->application_configuration_path, node_config->application_configuration_path_size,
                               PRIMARY_FILENAME, sizeof(PRIMARY_FILENAME));
        if (ret < 0)
            goto error_occured;
    }
    else if (selected_configuration == 2)
    {
        //get secondary filepath
        ret = create_file_path(filepath, sizeof(filepath),
                               node_config->application_configuration_path, node_config->application_configuration_path_size,
                               SECONDARY_FILENAME, sizeof(SECONDARY_FILENAME));
        if (ret < 0)
            goto error_occured;
        // get secondary configuration
    }

    


error_occured:
    ret = -1;
    return ret;
}

SystemConfiguration *get_active_configuration(ConfigurationManager *config)
{
    SystemConfiguration *retval = NULL;
    if (strcmp(config->active_configuration, "primary") == 0)
    {
        retval = &config->primary;
    }
    else if (strcmp(config->active_configuration, "secondary") == 0)
    {
        retval = &config->secondary;
    }
    return retval;
}

SystemConfiguration *get_free_configuration(ConfigurationManager *config)
{
    SystemConfiguration *retval = NULL;
    if (strcmp(config->active_configuration, "primary") == 0)
    {
        retval = &config->secondary;
    }
    else if (strcmp(config->active_configuration, "secondary") == 0)
    {
        retval = &config->primary;
    }
    return retval;
}
// Function prototypes
void free_configuration(ConfigurationManager *config);

// Helper function to parse CryptoProfile
static void parse_crypto_profile(cJSON *crypto_json, CryptoProfile *profile)
{
    profile->ID = cJSON_GetObjectItem(crypto_json, "id")->valueint;
    strncpy(profile->Name, cJSON_GetObjectItem(crypto_json, "name")->valuestring, sizeof(profile->Name) - 1);
    profile->MutualAuthentication = cJSON_IsTrue(cJSON_GetObjectItem(crypto_json, "mutual_auth"));
    profile->NoEncryption = cJSON_IsTrue(cJSON_GetObjectItem(crypto_json, "no_encrypt"));
    profile->ASLKeyExchangeMethod = cJSON_GetObjectItem(crypto_json, "kex")->valueint;
    profile->UseSecureElement = cJSON_IsTrue(cJSON_GetObjectItem(crypto_json, "use_secure_elem"));
    profile->HybridSignatureMode = cJSON_GetObjectItem(crypto_json, "signature_mode")->valueint;
    profile->Keylog = cJSON_IsTrue(cJSON_GetObjectItem(crypto_json, "keylog"));
    profile->Identity = cJSON_GetObjectItem(crypto_json, "identity")->valueint;
}

// Helper function to parse Kritis3mApplications
static void parse_application(cJSON *app_json, Kritis3mApplications *app)
{
    app->id = cJSON_GetObjectItem(app_json, "id")->valueint;
    app->type = cJSON_GetObjectItem(app_json, "type")->valueint;
    app->server_ip_port = strdup(cJSON_GetObjectItem(app_json, "server_ip_port")->valuestring);
    app->client_ip_port = strdup(cJSON_GetObjectItem(app_json, "client_ip_port")->valuestring);
    app->state = true; // Assuming default state is true
    app->ep1_id = cJSON_GetObjectItem(app_json, "ep1_id")->valueint;
    app->ep2_id = cJSON_GetObjectItem(app_json, "ep2_id")->valueint;
}

// Helper function to parse SystemConfiguration
static void parse_system_config(cJSON *node_json, cJSON *crypto_config_json, SystemConfiguration *sys_config)
{
    sys_config->id = cJSON_GetObjectItem(node_json, "id")->valueint;
    sys_config->node_id = cJSON_GetObjectItem(node_json, "node_id")->valueint;
    strncpy(sys_config->locality, cJSON_GetObjectItem(node_json, "locality")->valuestring, sizeof(sys_config->locality) - 1);
    strncpy(sys_config->serial_number, cJSON_GetObjectItem(node_json, "serial_number")->valuestring, sizeof(sys_config->serial_number) - 1);
    sys_config->node_network_index = cJSON_GetObjectItem(node_json, "network_index")->valueint;
    sys_config->heartbeat_interval = cJSON_GetObjectItem(node_json, "hb_interval")->valuedouble;
    sys_config->updated_at = cJSON_GetObjectItem(node_json, "updated_at")->valuedouble;
    sys_config->version = cJSON_GetObjectItem(node_json, "version")->valueint;

    // Parse witelist
    cJSON *whitelist_json = cJSON_GetObjectItem(node_json, "whitelist");
    sys_config->application_config.whitelist.number_trusted_clients = cJSON_GetArraySize(cJSON_GetObjectItem(whitelist_json, "trusted_clients"));
    for (int i = 0; i < sys_config->application_config.whitelist.number_trusted_clients; i++)
    {
        cJSON *client_json = cJSON_GetArrayItem(cJSON_GetObjectItem(whitelist_json, "trusted_clients"), i);
        strncpy(sys_config->application_config.whitelist.TrustedClients[i].client_ip_port,
                cJSON_GetObjectItem(client_json, "client_ip_port")->valuestring,
                IPv4_PORT_LEN - 1);
        // Note: trusted_applications_id is not present in the JSON, so it's not parsed here
    }

    // Parse applications
    cJSON *apps_json = cJSON_GetObjectItem(node_json, "applications");
    sys_config->application_config.number_applications = cJSON_GetArraySize(apps_json);
    for (int i = 0; i < sys_config->application_config.number_applications; i++)
    {
        parse_application(cJSON_GetArrayItem(apps_json, i), &sys_config->application_config.applications[i]);
    }

    // Parse crypto profiles
    sys_config->application_config.number_crypto_profiles = cJSON_GetArraySize(crypto_config_json);
    for (int i = 0; i < sys_config->application_config.number_crypto_profiles; i++)
    {
        parse_crypto_profile(cJSON_GetArrayItem(crypto_config_json, i), &sys_config->application_config.crypto_profile[i]);
    }
}

ConfigurationManager *parse_configuration(char *filename)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        fprintf(stderr, "Error opening file: %s\n", filename);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *json_string = (char *)malloc(file_size + 1);
    if (!json_string)
    {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return NULL;
    }

    fread(json_string, 1, file_size, file);
    json_string[file_size] = '\0';
    fclose(file);

    cJSON *root = cJSON_Parse(json_string);
    free(json_string);

    if (!root)
    {
        fprintf(stderr, "Error parsing JSON\n");
        return NULL;
    }

    ConfigurationManager *config = (ConfigurationManager *)malloc(sizeof(ConfigurationManager));
    if (!config)
    {
        fprintf(stderr, "Memory allocation failed\n");
        cJSON_Delete(root);
        return NULL;
    }

    // Parse primary configuration
    cJSON *primary = cJSON_GetObjectItem(root, "primary");
    parse_system_config(cJSON_GetObjectItem(primary, "node"), cJSON_GetObjectItem(primary, "crypto_config"), &config->primary);

    // Parse secondary configuration
    cJSON *secondary = cJSON_GetObjectItem(root, "secondary");
    parse_system_config(cJSON_GetObjectItem(secondary, "node"), cJSON_GetObjectItem(secondary, "crypto_config"), &config->secondary);

    // Set active configuration
    strncpy(config->active_configuration, cJSON_GetObjectItem(root, "active")->valuestring, sizeof(config->active_configuration) - 1);

    // Initialize mutexes
    pthread_mutex_init(&config->primaryLock, NULL);
    pthread_mutex_init(&config->secondaryLock, NULL);

    cJSON_Delete(root);
    return config;
}

void free_configuration(ConfigurationManager *config)
{
    if (!config)
        return;

    // Free dynamically allocated memory in primary configuration
    for (int i = 0; i < config->primary.application_config.number_applications; i++)
    {
        free(config->primary.application_config.applications[i].server_ip_port);
        free(config->primary.application_config.applications[i].client_ip_port);
    }

    // Free dynamically allocated memory in secondary configuration
    for (int i = 0; i < config->secondary.application_config.number_applications; i++)
    {
        free(config->secondary.application_config.applications[i].server_ip_port);
        free(config->secondary.application_config.applications[i].client_ip_port);
    }

    // Destroy mutexes
    pthread_mutex_destroy(&config->primaryLock);
    pthread_mutex_destroy(&config->secondaryLock);

    // Free the main structure
    free(config);
}
