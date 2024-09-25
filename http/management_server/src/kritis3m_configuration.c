#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cJSON.h"
#include "kritis3m_configuration.h" // Assuming this is the header file containing the struct definitions
#include "logging.h"
LOG_MODULE_CREATE(kritis3m_configuration);

// Function prototypes

int load_configuration(const char *filename, ConfigurationManager *config);
char *read_file(const char *filename);
int parse_json(const char *json_string, ConfigurationManager *config);
void parse_system_configuration(cJSON *json, SystemConfiguration *config);
void parse_whitelist(cJSON *json, Whitelist *whitelist);
void parse_applications(cJSON *json, Kritis3mApplications *applications, int *num_applications);
void parse_crypto_profiles(cJSON *json, CryptoProfile *profiles, int *num_profiles);

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

int load_configuration(const char *filename, ConfigurationManager *config)
{

    char *json_content = read_file(filename);
    if (json_content == NULL)
    {
        return 1;
    }

    parse_json(json_content, config);
    free(json_content);
    return 0;
}

char *read_file(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        printf("Failed to open file\n");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *content = (char *)malloc(file_size + 1);
    if (content == NULL)
    {
        printf("Memory allocation failed\n");
        fclose(file);
        return NULL;
    }

    fread(content, 1, file_size, file);
    content[file_size] = '\0';

    fclose(file);
    return content;
}

int parse_json(const char *json_string, ConfigurationManager *config)
{
    cJSON *json = cJSON_Parse(json_string);
    if (json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            LOG_ERROR("JSON parsing error: %s\n", error_ptr);
        }
        return -1;
    }

    cJSON *active = cJSON_GetObjectItemCaseSensitive(json, "active");
    if (cJSON_IsNumber(active))
    {
        snprintf(config->active_configuration, sizeof(config->active_configuration), "%d", active->valueint);
    }

    cJSON *primary = cJSON_GetObjectItemCaseSensitive(json, "primary");
    if (cJSON_IsObject(primary))
    {
        parse_system_configuration(primary, &config->primary);
    }

    cJSON *secondary = cJSON_GetObjectItemCaseSensitive(json, "secondary");
    if (cJSON_IsObject(secondary))
    {
        parse_system_configuration(secondary, &config->secondary);
    }

    cJSON_Delete(json);
}

void parse_system_configuration(cJSON *json, SystemConfiguration *config)
{
    cJSON *node = cJSON_GetObjectItemCaseSensitive(json, "node");
    if (cJSON_IsObject(node))
    {
        cJSON *id = cJSON_GetObjectItemCaseSensitive(node, "id");
        if (cJSON_IsNumber(id))
        {
            config->id = id->valueint;
        }

        cJSON *node_id = cJSON_GetObjectItemCaseSensitive(node, "node_id");
        if (cJSON_IsNumber(node_id))
        {
            config->node_id = node_id->valueint;
        }

        cJSON *serial_number = cJSON_GetObjectItemCaseSensitive(node, "serial_number");
        if (cJSON_IsString(serial_number) && serial_number->valuestring != NULL)
        {
            strncpy(config->serial_number, serial_number->valuestring, sizeof(config->serial_number) - 1);
        }

        cJSON *network_index = cJSON_GetObjectItemCaseSensitive(node, "network_index");
        if (cJSON_IsNumber(network_index))
        {
            config->node_network_index = network_index->valueint;
        }

        cJSON *locality = cJSON_GetObjectItemCaseSensitive(node, "locality");
        if (cJSON_IsString(locality) && locality->valuestring != NULL)
        {
            strncpy(config->locality, locality->valuestring, sizeof(config->locality) - 1);
        }

        cJSON *updated_at = cJSON_GetObjectItemCaseSensitive(node, "updated_at");
        if (cJSON_IsString(updated_at) && updated_at->valuestring != NULL)
        {
            struct tm tm;
            // strptime(updated_at->valuestring, "%Y-%m-%dT%H:%M:%SZ", &tm);
            config->updated_at = mktime(&tm);
        }

        cJSON *version = cJSON_GetObjectItemCaseSensitive(node, "version");
        if (cJSON_IsNumber(version))
        {
            config->version = version->valueint;
        }

        cJSON *hb_interval = cJSON_GetObjectItemCaseSensitive(node, "hb_interval");
        if (cJSON_IsNumber(hb_interval))
        {
            config->hardbeat_interval = hb_interval->valueint;
        }

        cJSON *whitelist = cJSON_GetObjectItemCaseSensitive(node, "whitelist");
        if (cJSON_IsObject(whitelist))
        {
            parse_whitelist(whitelist, &config->whitelist);
        }

        cJSON *applications = cJSON_GetObjectItemCaseSensitive(node, "applications");
        if (cJSON_IsArray(applications))
        {
            parse_applications(applications, config->applications, &config->number_applications);
        }
    }

    cJSON *crypto_config = cJSON_GetObjectItemCaseSensitive(json, "crypto_config");
    if (cJSON_IsArray(crypto_config))
    {
        parse_crypto_profiles(crypto_config, config->crypto_profile, &config->number_crypto_profiles);
    }
}

void parse_whitelist(cJSON *json, Whitelist *whitelist)
{
    cJSON *trusted_clients = cJSON_GetObjectItemCaseSensitive(json, "trusted_clients");
    if (cJSON_IsArray(trusted_clients))
    {
        whitelist->number_trusted_clients = cJSON_GetArraySize(trusted_clients);
        if (whitelist->number_trusted_clients > MAX_NUMBER_TRUSTED_CLIENTS)
        {
            whitelist->number_trusted_clients = MAX_NUMBER_TRUSTED_CLIENTS;
        }

        for (int i = 0; i < whitelist->number_trusted_clients; i++)
        {
            cJSON *client = cJSON_GetArrayItem(trusted_clients, i);
            if (cJSON_IsObject(client))
            {
                cJSON *client_ip_port = cJSON_GetObjectItemCaseSensitive(client, "client_ip_port");
                if (cJSON_IsString(client_ip_port) && client_ip_port->valuestring != NULL)
                {
                    strncpy(whitelist->TrustedClients[i].client_ip_port, client_ip_port->valuestring, IPv4_PORT_LEN - 1);
                }
                // Note: The 'number_trusted_applications' and 'trusted_applications_id' are not present in the JSON,
                // so they are not parsed here. You may need to add these if they are required.
            }
        }
    }
}

void parse_applications(cJSON *json, Kritis3mApplications *applications, int *num_applications)
{
    *num_applications = cJSON_GetArraySize(json);
    if (*num_applications > NUMBER_PROXIES)
    {
        *num_applications = NUMBER_PROXIES;
    }

    for (int i = 0; i < *num_applications; i++)
    {
        cJSON *app = cJSON_GetArrayItem(json, i);
        if (cJSON_IsObject(app))
        {
            cJSON *id = cJSON_GetObjectItemCaseSensitive(app, "id");
            if (cJSON_IsNumber(id))
            {
                applications[i].id = id->valueint;
            }

            cJSON *type = cJSON_GetObjectItemCaseSensitive(app, "type");
            if (cJSON_IsString(type) && type->valuestring != NULL)
            {
                // You may need to implement a function to convert string to Kritis3mApplicationtype enum
                // For now, we'll just set it to 0
                applications[i].type = 0;
            }

            cJSON *server_ip_port = cJSON_GetObjectItemCaseSensitive(app, "server_ip_port");
            if (cJSON_IsString(server_ip_port) && server_ip_port->valuestring != NULL)
            {
                applications[i].server_ip_port = strdup(server_ip_port->valuestring);
            }

            cJSON *client_ip_port = cJSON_GetObjectItemCaseSensitive(app, "client_ip_port");
            if (cJSON_IsString(client_ip_port) && client_ip_port->valuestring != NULL)
            {
                applications[i].client_ip_port = strdup(client_ip_port->valuestring);
            }

            cJSON *ep1_id = cJSON_GetObjectItemCaseSensitive(app, "ep1_id");
            if (cJSON_IsNumber(ep1_id))
            {
                applications[i].ep1_id = ep1_id->valueint;
            }

            cJSON *ep2_id = cJSON_GetObjectItemCaseSensitive(app, "ep2_id");
            if (cJSON_IsNumber(ep2_id))
            {
                applications[i].ep2_id = ep2_id->valueint;
            }

            // Note: The 'state' field is not present in the JSON, so it's not parsed here
        }
    }
}

void parse_crypto_profiles(cJSON *json, CryptoProfile *profiles, int *num_profiles)
{
    *num_profiles = cJSON_GetArraySize(json);
    if (*num_profiles > NUMBER_CRYPTOPROFILE)
    {
        *num_profiles = NUMBER_CRYPTOPROFILE;
    }

    for (int i = 0; i < *num_profiles; i++)
    {
        cJSON *profile = cJSON_GetArrayItem(json, i);
        if (cJSON_IsObject(profile))
        {
            cJSON *id = cJSON_GetObjectItemCaseSensitive(profile, "id");
            if (cJSON_IsNumber(id))
            {
                profiles[i].ID = id->valueint;
            }

            cJSON *name = cJSON_GetObjectItemCaseSensitive(profile, "name");
            if (cJSON_IsString(name) && name->valuestring != NULL)
            {
                strncpy(profiles[i].Name, name->valuestring, sizeof(profiles[i].Name) - 1);
            }

            cJSON *mutual_auth = cJSON_GetObjectItemCaseSensitive(profile, "mutual_auth");
            if (cJSON_IsBool(mutual_auth))
            {
                profiles[i].MutualAuthentication = cJSON_IsTrue(mutual_auth);
            }

            cJSON *no_encrypt = cJSON_GetObjectItemCaseSensitive(profile, "no_encrypt");
            if (cJSON_IsBool(no_encrypt))
            {
                profiles[i].NoEncryption = cJSON_IsTrue(no_encrypt);
            }

            cJSON *kex = cJSON_GetObjectItemCaseSensitive(profile, "kex");
            if (cJSON_IsNumber(kex))
            {
                profiles[i].ASLKeyExchangeMethod = kex->valueint;
            }

            cJSON *use_secure_elem = cJSON_GetObjectItemCaseSensitive(profile, "use_secure_elem");
            if (cJSON_IsBool(use_secure_elem))
            {
                profiles[i].UseSecureElement = cJSON_IsTrue(use_secure_elem);
            }

            cJSON *signature_mode = cJSON_GetObjectItemCaseSensitive(profile, "signature_mode");
            if (cJSON_IsNumber(signature_mode))
            {
                profiles[i].HybridSignatureMode = signature_mode->valueint;
            }

            cJSON *keylog = cJSON_GetObjectItemCaseSensitive(profile, "keylog");
            if (cJSON_IsBool(keylog))
            {
                profiles[i].Keylog = cJSON_IsTrue(keylog);
            }

            cJSON *identity = cJSON_GetObjectItemCaseSensitive(profile, "identity");
            if (cJSON_IsNumber(identity))
            {
                profiles[i].Identity = identity->valueint;
            }
        }
    }
}