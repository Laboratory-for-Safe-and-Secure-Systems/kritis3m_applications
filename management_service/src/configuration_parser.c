#include <stdio.h>
#include <stdlib.h>

#include "cJSON.h"
#include "configuration_manager.h"
#include "configuration_parser.h"
#include "errno.h"
#include "file_io.h"
#include "logging.h"
#include "networking.h"
#include "string.h"

LOG_MODULE_CREATE(kritis3m_config_paser);

/*--------------------- FORWARD DECLARATION ------------------------------------*/
int parse_whitelist(cJSON* json_obj, Whitelist* whitelist);
int parse_crypo_config(cJSON* json_obj,
                       CryptoProfile* CryptoProfile,
                       char* secure_middleware_path,
                       char* pin);
int parse_application(cJSON* json_obj, Kritis3mApplications* application);

int parse_sysconfig_to_json(struct sysconfig* config, char* json_buffer, int json_buffer_size)
{
        if (!config || !json_buffer || json_buffer_size <= 0)
        {
                LOG_ERROR("Invalid parameters");
                return -1;
        }

        // Format the JSON string directly into the buffer
        int written = 0;
        int remaining = json_buffer_size;

        // Start JSON object
        written = snprintf(json_buffer,
                           remaining,
                           "{\n"
                           "  \"serial_number\": \"%s\",\n"
                           "  \"dataplane_active\": %d,\n"
                           "  \"controlplane_active\": %d,\n"
                           "  \"application_active\": %d,\n",
                           config->serial_number,
                           config->dataplane_active,
                           config->controlplane_active,
                           config->application_active);

        if (written < 0 || written >= remaining)
        {
                LOG_ERROR("Buffer too small for JSON data");
                return -1;
        }

        remaining -= written;

        // Add broker config
        written += snprintf(json_buffer + written,
                            remaining,
                            "  \"broker\": {\n"
                            "    \"host\": \"%s\"\n"
                            "  },\n",
                            config->broker_host);

        if (written < 0 || written >= json_buffer_size)
        {
                LOG_ERROR("Buffer too small for broker config");
                return -1;
        }

        remaining = json_buffer_size - written;

        // Add EST config
        written += snprintf(json_buffer + written,
                            remaining,
                            "  \"est\": {\n"
                            "    \"host\": \"%s\",\n"
                            "    \"port\": %d\n"
                            "  },\n",
                            config->est_host,
                            config->est_port);

        if (written < 0 || written >= json_buffer_size)
        {
                LOG_ERROR("Buffer too small for EST config");
                return -1;
        }

        remaining = json_buffer_size - written;

        // Add endpoint config header
        written += snprintf(json_buffer + written, remaining, "  \"endpoint_config\": {\n");

        if (written < 0 || written >= json_buffer_size)
        {
                LOG_ERROR("Buffer too small for endpoint config header");
                return -1;
        }

        remaining = json_buffer_size - written;

        // Add KEX method
        const char* kex_str;
        switch (config->endpoint_config->key_exchange_method)
        {
        case ASL_KEX_DEFAULT:
                kex_str = "KEX_DEFAULT";
                break;
        case ASL_KEX_CLASSIC_SECP256:
                kex_str = "KEX_CLASSIC_SECP256";
                break;
        case ASL_KEX_CLASSIC_SECP384:
                kex_str = "KEX_CLASSIC_SECP384";
                break;
        case ASL_KEX_CLASSIC_SECP521:
                kex_str = "KEX_CLASSIC_SECP521";
                break;
        case ASL_KEX_CLASSIC_X25519:
                kex_str = "KEX_CLASSIC_X25519";
                break;
        case ASL_KEX_CLASSIC_X448:
                kex_str = "KEX_CLASSIC_X448";
                break;
        case ASL_KEX_PQC_MLKEM512:
                kex_str = "KEX_PQC_MLKEM512";
                break;
        case ASL_KEX_PQC_MLKEM768:
                kex_str = "KEX_PQC_MLKEM768";
                break;
        case ASL_KEX_PQC_MLKEM1024:
                kex_str = "KEX_PQC_MLKEM1024";
                break;
        case ASL_KEX_HYBRID_SECP256_MLKEM512:
                kex_str = "KEX_HYBRID_SECP256_MLKEM512";
                break;
        case ASL_KEX_HYBRID_SECP384_MLKEM768:
                kex_str = "KEX_HYBRID_SECP384_MLKEM768";
                break;
        case ASL_KEX_HYBRID_SECP256_MLKEM768:
                kex_str = "KEX_HYBRID_SECP256_MLKEM768";
                break;
        case ASL_KEX_HYBRID_SECP521_MLKEM1024:
                kex_str = "KEX_HYBRID_SECP521_MLKEM1024";
                break;
        case ASL_KEX_HYBRID_SECP384_MLKEM1024:
                kex_str = "KEX_HYBRID_SECP384_MLKEM1024";
                break;
        case ASL_KEX_HYBRID_X25519_MLKEM512:
                kex_str = "KEX_HYBRID_X25519_MLKEM512";
                break;
        case ASL_KEX_HYBRID_X448_MLKEM768:
                kex_str = "KEX_HYBRID_X448_MLKEM768";
                break;
        case ASL_KEX_HYBRID_X25519_MLKEM768:
                kex_str = "KEX_HYBRID_X25519_MLKEM768";
                break;
        default:
                LOG_ERROR("Unsupported KEX method");
                return -1;
        }

        written += snprintf(json_buffer + written,
                            remaining,
                            "    \"kex\": \"%s\",\n"
                            "    \"mtls\": %s,\n"
                            "    \"cipher_suites\": \"%s\",\n"
                            "    \"keylog_path\":   \"%s\"\n" // no comma
                            "  },\n",
                            kex_str,
                            config->endpoint_config->mutual_authentication ? "true" : "false",
                            config->endpoint_config->ciphersuites,
                            config->endpoint_config->keylog_file ? config->endpoint_config->keylog_file :
                                                                   "");

        if (written < 0 || written >= json_buffer_size)
        {
                LOG_ERROR("Buffer too small for endpoint config details");
                return -1;
        }

        remaining = json_buffer_size - written;

        // Add log level and close JSON object
        written += snprintf(json_buffer + written,
                            remaining,
                            "  \"log_level\": %d\n"
                            "}",
                            config->log_level);

        if (written < 0 || written >= json_buffer_size)
        {
                LOG_ERROR("Buffer too small for closing JSON");
                return -1;
        }

        return 0;
}

int parse_buffer_to_sysconfig(char* json_buffer, int json_buffer_size, struct sysconfig* config)
{
        int ret = 0;
        cJSON* root = cJSON_ParseWithLength(json_buffer, json_buffer_size);
        if (!root)
        {
                LOG_ERROR("Failed to parse JSON buffer");
                return -1;
        }

        // Parse serial number
        cJSON* serial_number = cJSON_GetObjectItem(root, "serial_number");
        if (!serial_number || !cJSON_IsString(serial_number))
        {
                LOG_ERROR("Invalid or missing serial_number");
                goto error;
        }
        config->serial_number = duplicate_string(serial_number->valuestring);

        // Parse active states
        cJSON* dataplane_active = cJSON_GetObjectItem(root, "dataplane_active");
        if (!dataplane_active || !cJSON_IsNumber(dataplane_active))
        {
                LOG_ERROR("Invalid or missing dataplane_active");
                goto error;
        }
        config->dataplane_active = dataplane_active->valueint;

        cJSON* controlplane_active = cJSON_GetObjectItem(root, "controlplane_active");
        if (!controlplane_active || !cJSON_IsNumber(controlplane_active))
        {
                LOG_ERROR("Invalid or missing controlplane_active");
                goto error;
        }
        config->controlplane_active = controlplane_active->valueint;

        cJSON* application_active = cJSON_GetObjectItem(root, "application_active");
        if (!application_active || !cJSON_IsNumber(application_active))
        {
                LOG_ERROR("Invalid or missing application_active");
                goto error;
        }
        config->application_active = application_active->valueint;

        // Parse broker configuration
        cJSON* broker = cJSON_GetObjectItem(root, "broker");
        if (!broker || !cJSON_IsObject(broker))
        {
                LOG_ERROR("Invalid or missing broker configuration");
                goto error;
        }

        cJSON* broker_host = cJSON_GetObjectItem(broker, "host");
        if (!broker_host || !cJSON_IsString(broker_host))
        {
                LOG_ERROR("Invalid or missing broker host");
                goto error;
        }
        config->broker_host = duplicate_string(broker_host->valuestring);

        // Parse EST configuration
        cJSON* est = cJSON_GetObjectItem(root, "est");
        if (!est || !cJSON_IsObject(est))
        {
                LOG_ERROR("Invalid or missing EST configuration");
                goto error;
        }

        cJSON* est_host = cJSON_GetObjectItem(est, "host");
        if (!est_host || !cJSON_IsString(est_host))
        {
                LOG_ERROR("Invalid or missing EST host");
                goto error;
        }
        config->est_host = duplicate_string(est_host->valuestring);

        cJSON* est_port = cJSON_GetObjectItem(est, "port");
        if (!est_port || !cJSON_IsNumber(est_port))
        {
                LOG_ERROR("Invalid or missing EST port");
                goto error;
        }
        config->est_port = est_port->valueint;

        config->endpoint_config = malloc(sizeof(asl_endpoint_configuration));
        if (!config->endpoint_config)
        {
                LOG_ERROR("Failed to allocate memory for endpoint configuration");
                goto error;
        }

        // Parse endpoint configuration
        cJSON* endpoint_config = cJSON_GetObjectItem(root, "endpoint_config");
        if (!endpoint_config || !cJSON_IsObject(endpoint_config))
        {
                LOG_ERROR("Invalid or missing endpoint configuration");
                goto error;
        }

        cJSON* kex = cJSON_GetObjectItem(endpoint_config, "kex");
        if (!kex || !cJSON_IsString(kex))
        {
                LOG_ERROR("Invalid or missing KEX configuration");
                goto error;
        }
        // Map KEX string to enum value
        if (strcmp(kex->valuestring, "KEX_DEFAULT") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_DEFAULT;
        }
        else if (strcmp(kex->valuestring, "KEX_CLASSIC_SECP256") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_CLASSIC_SECP256;
        }
        else if (strcmp(kex->valuestring, "KEX_CLASSIC_SECP384") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_CLASSIC_SECP384;
        }
        else if (strcmp(kex->valuestring, "KEX_CLASSIC_SECP521") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_CLASSIC_SECP521;
        }
        else if (strcmp(kex->valuestring, "KEX_CLASSIC_X25519") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_CLASSIC_X25519;
        }
        else if (strcmp(kex->valuestring, "KEX_CLASSIC_X448") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_CLASSIC_X448;
        }
        else if (strcmp(kex->valuestring, "KEX_PQC_MLKEM512") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_PQC_MLKEM512;
        }
        else if (strcmp(kex->valuestring, "KEX_PQC_MLKEM768") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_PQC_MLKEM768;
        }
        else if (strcmp(kex->valuestring, "KEX_PQC_MLKEM1024") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_PQC_MLKEM1024;
        }
        else if (strcmp(kex->valuestring, "KEX_HYBRID_SECP256_MLKEM512") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_HYBRID_SECP256_MLKEM512;
        }
        else if (strcmp(kex->valuestring, "KEX_HYBRID_SECP384_MLKEM768") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_HYBRID_SECP384_MLKEM768;
        }
        else if (strcmp(kex->valuestring, "KEX_HYBRID_SECP256_MLKEM768") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_HYBRID_SECP256_MLKEM768;
        }
        else if (strcmp(kex->valuestring, "KEX_HYBRID_SECP521_MLKEM1024") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_HYBRID_SECP521_MLKEM1024;
        }
        else if (strcmp(kex->valuestring, "KEX_HYBRID_SECP384_MLKEM1024") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_HYBRID_SECP384_MLKEM1024;
        }
        else if (strcmp(kex->valuestring, "KEX_HYBRID_X25519_MLKEM512") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_HYBRID_X25519_MLKEM512;
        }
        else if (strcmp(kex->valuestring, "KEX_HYBRID_X448_MLKEM768") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_HYBRID_X448_MLKEM768;
        }
        else if (strcmp(kex->valuestring, "KEX_HYBRID_X25519_MLKEM768") == 0)
        {
                config->endpoint_config->key_exchange_method = ASL_KEX_HYBRID_X25519_MLKEM768;
        }
        else
        {
                LOG_ERROR("Unsupported KEX method: %s", kex->valuestring);
                goto error;
        }

        cJSON* mtls = cJSON_GetObjectItem(endpoint_config, "mtls");
        if (!mtls || !cJSON_IsBool(mtls))
        {
                LOG_ERROR("Invalid or missing mTLS configuration");
                goto error;
        }
        config->endpoint_config->mutual_authentication = cJSON_IsTrue(mtls);

        cJSON* keylog_path = cJSON_GetObjectItem(endpoint_config, "keylog_path");
        if (keylog_path && cJSON_IsString(keylog_path))
        {
                config->endpoint_config->keylog_file = duplicate_string(keylog_path->valuestring);
        }
        else
        {
                config->endpoint_config->keylog_file = NULL;
        }

        cJSON* cipher_suites = cJSON_GetObjectItem(endpoint_config, "cipher_suites");
        if (!cipher_suites || !cJSON_IsString(cipher_suites))
        {
                LOG_ERROR("Invalid or missing cipher suites configuration");
                goto error;
        }
        config->endpoint_config->ciphersuites = duplicate_string(cipher_suites->valuestring);

        // Parse log level
        cJSON* log_level = cJSON_GetObjectItem(root, "log_level");
        if (!log_level || !cJSON_IsNumber(log_level))
        {
                LOG_ERROR("Invalid or missing log level");
                goto error;
        }
        config->log_level = log_level->valueint;

        cJSON_Delete(root);
        return ret;

error:
        cJSON_Delete(root);
        return -1;
}

int parse_config(char* buffer,
                 int buffer_len,
                 struct application_manager_config* config,
                 struct hardware_configs* hw_configs)
{
        if (!buffer || buffer_len <= 0 || !config || !hw_configs)
        {
                LOG_ERROR("Invalid parameters for parse_config");
                return -1;
        }

        cJSON* root = cJSON_ParseWithLength(buffer, buffer_len);
        if (!root)
        {
                LOG_ERROR("Failed to parse application configuration JSON");
                return -1;
        }

        // Get the node_update_item object which contains all config data
        cJSON* node_update_item = cJSON_GetObjectItem(root, "node_update_item");
        if (!node_update_item || !cJSON_IsObject(node_update_item))
        {
                LOG_ERROR("Invalid or missing node_update_item object");
                cJSON_Delete(root);
                return -1;
        }

        // Parse hardware configurations
        cJSON* hw_config_json = cJSON_GetObjectItem(node_update_item, "hardware_config");
        if (!hw_config_json || !cJSON_IsArray(hw_config_json))
        {
                LOG_ERROR("Invalid or missing hardware_config array");
                cJSON_Delete(root);
                return -1;
        }

        int hw_count = cJSON_GetArraySize(hw_config_json);
        hw_configs->number_of_hw_configs = hw_count;
        hw_configs->hw_configs = malloc(hw_count * sizeof(HardwareConfiguration));
        if (!hw_configs->hw_configs)
        {
                LOG_ERROR("Failed to allocate memory for hardware configs");
                cJSON_Delete(root);
                return -1;
        }

        for (int i = 0; i < hw_count; i++)
        {
                cJSON* hw_item = cJSON_GetArrayItem(hw_config_json, i);
                if (!hw_item || !cJSON_IsObject(hw_item))
                {
                        LOG_ERROR("Invalid hardware config item at index %d", i);
                        goto error_hw;
                }

                cJSON* ip_cidr = cJSON_GetObjectItem(hw_item, "ip_cidr");
                if (!ip_cidr || !cJSON_IsString(ip_cidr))
                {
                        LOG_ERROR("Invalid or missing ip_cidr in hardware config at index %d", i);
                        goto error_hw;
                }

                // Copy IP CIDR to the hardware configuration
                strncpy(hw_configs->hw_configs[i].ip_cidr, ip_cidr->valuestring, INET6_ADDRSTRLEN + 4);

                cJSON* device = cJSON_GetObjectItem(hw_item, "device");
                if (!device || !cJSON_IsString(device))
                {
                        LOG_ERROR("Invalid or missing device in hardware config at index %d", i);
                        goto error_hw;
                }

                // Copy device name to the hardware configuration
                strncpy(hw_configs->hw_configs[i].device, device->valuestring, IF_NAMESIZE);
        }

        // Parse group configurations from group_proxy_update array
        cJSON* groups_json = cJSON_GetObjectItem(node_update_item, "group_proxy_update");
        if (!groups_json || !cJSON_IsArray(groups_json))
        {
                LOG_ERROR("Invalid or missing group_proxy_update array");
                goto error_hw;
        }

        int group_count = cJSON_GetArraySize(groups_json);
        config->number_of_groups = group_count;
        config->group_config = malloc(group_count * sizeof(struct group_config));
        if (!config->group_config)
        {
                LOG_ERROR("Failed to allocate memory for group configs");
                goto error_hw;
        }

        for (int i = 0; i < group_count; i++)
        {
                cJSON* group_item = cJSON_GetArrayItem(groups_json, i);
                if (!group_item || !cJSON_IsObject(group_item))
                {
                        LOG_ERROR("Invalid group config item at index %d", i);
                        goto error_groups;
                }

                // Allocate and initialize endpoint configuration
                config->group_config[i].endpoint_config = malloc(sizeof(asl_endpoint_configuration));
                if (!config->group_config[i].endpoint_config)
                {
                        LOG_ERROR("Failed to allocate memory for endpoint configuration");
                        goto error_groups;
                }

                // Initialize with default values
                *config->group_config[i].endpoint_config = asl_default_endpoint_config();

                // Parse endpoint configuration
                cJSON* endpoint_json = cJSON_GetObjectItem(group_item, "endpoint_config");
                if (endpoint_json && cJSON_IsObject(endpoint_json))
                {
                        // Parse key exchange method
                        cJSON* kex = cJSON_GetObjectItem(endpoint_json, "asl_key_exchange_method");
                        if (kex && cJSON_IsString(kex))
                        {
                                const char* kex_str = kex->valuestring;

                                if (strcmp(kex_str, "ASL_KEX_DEFAULT") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_DEFAULT;
                                else if (strcmp(kex_str, "ASL_KEX_CLASSIC_SECP256") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_CLASSIC_SECP256;
                                else if (strcmp(kex_str, "ASL_KEX_CLASSIC_SECP384") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_CLASSIC_SECP384;
                                else if (strcmp(kex_str, "ASL_KEX_CLASSIC_SECP521") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_CLASSIC_SECP521;
                                else if (strcmp(kex_str, "ASL_KEX_CLASSIC_X25519") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_CLASSIC_X25519;
                                else if (strcmp(kex_str, "ASL_KEX_CLASSIC_X448") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_CLASSIC_X448;
                                else if (strcmp(kex_str, "ASL_KEX_PQC_MLKEM512") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_PQC_MLKEM512;
                                else if (strcmp(kex_str, "ASL_KEX_PQC_MLKEM768") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_PQC_MLKEM768;
                                else if (strcmp(kex_str, "ASL_KEX_PQC_MLKEM1024") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_PQC_MLKEM1024;
                                else if (strcmp(kex_str, "ASL_KEX_HYBRID_SECP256_MLKEM512") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_HYBRID_SECP256_MLKEM512;
                                else if (strcmp(kex_str, "ASL_KEX_HYBRID_SECP384_MLKEM768") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_HYBRID_SECP384_MLKEM768;
                                else if (strcmp(kex_str, "ASL_KEX_HYBRID_SECP256_MLKEM768") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_HYBRID_SECP256_MLKEM768;
                                else if (strcmp(kex_str, "ASL_KEX_HYBRID_SECP521_MLKEM1024") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_HYBRID_SECP521_MLKEM1024;
                                else if (strcmp(kex_str, "ASL_KEX_HYBRID_SECP384_MLKEM1024") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_HYBRID_SECP384_MLKEM1024;
                                else if (strcmp(kex_str, "ASL_KEX_HYBRID_X25519_MLKEM512") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_HYBRID_X25519_MLKEM512;
                                else if (strcmp(kex_str, "ASL_KEX_HYBRID_X448_MLKEM768") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_HYBRID_X448_MLKEM768;
                                else if (strcmp(kex_str, "ASL_KEX_HYBRID_X25519_MLKEM768") == 0)
                                        config->group_config[i].endpoint_config->key_exchange_method = ASL_KEX_HYBRID_X25519_MLKEM768;
                                else
                                        LOG_WARN("Unsupported KEX method: %s, using default", kex_str);
                        }

                        // Parse mTLS setting
                        cJSON* mutual_auth = cJSON_GetObjectItem(endpoint_json, "mutual_auth");
                        if (mutual_auth && cJSON_IsBool(mutual_auth))
                        {
                                config->group_config[i].endpoint_config->mutual_authentication = cJSON_IsTrue(
                                        mutual_auth);
                        }

                        // Parse cipher suites
                        cJSON* cipher = cJSON_GetObjectItem(endpoint_json, "cipher");
                        if (cipher && cJSON_IsString(cipher))
                        {
                                config->group_config[i].endpoint_config->ciphersuites = duplicate_string(
                                        cipher->valuestring);
                        }
                }

                // Setup proxy configuration
                cJSON* group_log_level = cJSON_GetObjectItem(group_item, "group_log_level");
                if (group_log_level && cJSON_IsNumber(group_log_level))
                {
                        config->group_config[i].proxy_config.log_level = group_log_level->valueint;
                }
                else
                {
                        config->group_config[i].proxy_config.log_level = 1; // Default to 1 if not specified
                }

                // Parse proxies array to get number of proxies
                cJSON* proxies = cJSON_GetObjectItem(group_item, "proxies");
                if (proxies && cJSON_IsArray(proxies))
                {
                        config->group_config[i].number_proxies = cJSON_GetArraySize(proxies);

                        // Find first proxy to set ID and port
                        if (config->group_config[i].number_proxies > 0)
                        {
                                cJSON* first_proxy = cJSON_GetArrayItem(proxies, 0);
                                if (first_proxy && cJSON_IsObject(first_proxy))
                                {
                                        // Get proxy ID
                                        cJSON* proxy_type = cJSON_GetObjectItem(first_proxy,
                                                                                "proxy_type");
                                        if (proxy_type && cJSON_IsNumber(proxy_type))
                                        {
                                                config->group_config[i]
                                                        .proxy_config.application_id = proxy_type->valueint;
                                        }
                                        else
                                        {
                                                config->group_config[i].proxy_config.application_id = 1; // Default ID
                                        }

                                        // Extract port from server_endpoint_addr (format: "ip:port")
                                        cJSON* server_addr = cJSON_GetObjectItem(first_proxy, "server_endpoint_addr");
                                        if (server_addr && cJSON_IsString(server_addr))
                                        {
                                                const char* addr_str = server_addr->valuestring;
                                                char* colon_pos = strrchr(addr_str, ':');
                                                if (colon_pos)
                                                {
                                                        config->group_config[i]
                                                                .proxy_config.listening_port = atoi(
                                                                colon_pos + 1);
                                                }
                                                else
                                                {
                                                        config->group_config[i]
                                                                .proxy_config.listening_port = 0; // Default port
                                                }
                                        }
                                        else
                                        {
                                                config->group_config[i].proxy_config.listening_port = 0; // Default port
                                        }
                                }
                        }
                        else
                        {
                                LOG_WARN("No proxies defined for group %d", i);
                                config->group_config[i].number_proxies = 0;
                                config->group_config[i].proxy_config.application_id = 0;
                                config->group_config[i].proxy_config.listening_port = 0;
                        }
                }
                else
                {
                        LOG_ERROR("Missing proxies array for group %d", i);
                        goto error_groups;
                }
        }

        cJSON_Delete(root);
        return 0;

error_groups:
        for (int i = 0; i < config->number_of_groups; i++)
        {
                if (config->group_config[i].endpoint_config)
                {
                        if (config->group_config[i].endpoint_config->ciphersuites)
                                free((void*) config->group_config[i].endpoint_config->ciphersuites);
                        if (config->group_config[i].endpoint_config->keylog_file)
                                free((void*) config->group_config[i].endpoint_config->keylog_file);
                        free(config->group_config[i].endpoint_config);
                }
        }
        free(config->group_config);

error_hw:
        free(hw_configs->hw_configs);
        cJSON_Delete(root);
        return -1;
}
