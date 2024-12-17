#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "configuration_parser.h"
#include "errno.h"
#include "kritis3m_configuration.h" // Assuming this is the header file containing the struct definitions
#include "logging.h"
#include "networking.h"

LOG_MODULE_CREATE(kritis3m_configuration);

// Function prototypes

const char* identity_folder_names[max_identities] = {"management_service",
                                                     "management",
                                                     "remote",
                                                     "production"};

static ConfigurationManager config_manger;

int get_Kritis3mNodeConfiguration(char* filename, Kritis3mNodeConfiguration* config)
{
        int ret = 0;
        uint8_t* json_buffer = NULL;
        size_t file_size = 0;

        if ((filename == NULL) || (config == NULL))
                goto error_occured;

        ret = read_file(filename, &json_buffer, &file_size);
        if (ret < 0)
        {
                LOG_ERROR("can't read node configuration file");
                goto error_occured;
        }

        ret = parse_buffer_to_Config(json_buffer, file_size, config);
        if (ret < 0)
        {
                LOG_ERROR("couldnt parse configuration file to KRITIS3MNodeConfiguration");
                goto error_occured;
        }
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
ManagementReturncode get_systemconfig(char* filename,
                                      SystemConfiguration* systemconfig,
                                      char* cryptopath,
                                      char* secure_middleware_path,
                                      char* pin)
{
        int ret = 0;
        ManagementReturncode retval = MGMT_OK;
        uint8_t* json_buffer = NULL;
        size_t file_size = 0;

        if ((filename == NULL) || (systemconfig == NULL))
                goto error_occured;

        ret = read_file(filename, &json_buffer, &file_size);
        if ((ret < 0))
        {
                retval = MGMT_ERR;
                LOG_ERROR("can't read systemconfiguration file");
                goto error_occured;
        }

        retval = parse_buffer_to_SystemConfiguration(json_buffer,
                                                     file_size,
                                                     systemconfig,
                                                     cryptopath,
                                                     secure_middleware_path,
                                                     pin);
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
        if (json_buffer != NULL)
                free(json_buffer);

        return ret;

error_occured:
        if (retval > MGMT_ERR)
                retval = MGMT_ERR;
        LOG_ERROR("Error occured in Read configuration, with error code %d", errno);
        if (json_buffer != NULL)
                free(json_buffer);
        return retval;
}

SystemConfiguration* get_active_config(ConfigurationManager* manager)
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
SystemConfiguration* get_inactive_config(ConfigurationManager* manager)
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
ManagementReturncode get_Systemconfig(ConfigurationManager* applconfig,
                                      Kritis3mNodeConfiguration* node_config)
{
        /***
         * Three cases must be checked:
         * - No config is available: The Management Server must be instantly called for a configuration
         * - One/Two config/s is/are available: The application can be started. And the next Heartbeat is awaited
         * - Configuration is available, but incomplete
         */
        ManagementReturncode ret = 0;
        SystemConfiguration* sys_config = NULL;
        char* filepath;
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
        ret = get_systemconfig(filepath,
                               sys_config,
                               node_config->pki_cert_path,
                               node_config->management_identity.secure_middleware_path,
                               node_config->management_identity.pin);
        return ret;

error_occured:
        if (ret > MGMT_ERR)
                ret = MGMT_ERR;
        return ret;
}

Kritis3mApplications* find_application_by_application_id(Kritis3mApplications* appls,
                                                         int number_appls,
                                                         int appl_id)
{
        if (appls == NULL)
                goto error_occured;
        Kritis3mApplications* t_appl = NULL;

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

int get_identity_folder_path(char* out_path, size_t size, const char* base_path, network_identity identity)
{
        if (identity < MANAGEMENT_SERVICE || identity >= max_identities)
        {
                LOG_ERROR("Invalid identity\n");
                return -1;
        }

        snprintf(out_path, size, "%s/%s", base_path, identity_folder_names[identity]);
        return 0;
}

int load_certificates(crypto_identity* identity)
{
        int ret = 0;
        char filepath[MAX_FILEPATH_SIZE];
        if (!identity || !identity->filepath)
                return -1;

        memset(filepath, 0, MAX_FILEPATH_SIZE);
        snprintf(filepath, sizeof(filepath), "%s/cert.pem", identity->filepath);
        identity->certificates.root_path = duplicate_string(filepath);

        memset(filepath, 0, MAX_FILEPATH_SIZE);
        snprintf(filepath, sizeof(filepath), "%s/privateKey.pem", identity->filepath);
        identity->certificates.private_key_path = duplicate_string(filepath);

        memset(filepath, 0, MAX_FILEPATH_SIZE);
        snprintf(filepath, sizeof(filepath), "%s/chain.pem", identity->filepath);
        identity->certificates.certificate_path = duplicate_string(filepath);

        memset(filepath, 0, MAX_FILEPATH_SIZE);
        snprintf(filepath, sizeof(filepath), "%s/additional_key.pem", identity->filepath);
        identity->certificates.chain_buffer = duplicate_string(filepath);

        memset(filepath, 0, MAX_FILEPATH_SIZE);
        snprintf(filepath, sizeof(filepath), "%s/additional_key.pem", identity->filepath);
        if (file_exists(filepath))
        {
                identity->certificates.additional_key_path = duplicate_string(filepath);
        }

        memset(filepath, 0, MAX_FILEPATH_SIZE);
        snprintf(filepath, sizeof(filepath), "%s/intermediate.pem", identity->filepath);
        if (file_exists(filepath))
        {
                identity->certificates.intermediate_path = duplicate_string(filepath);
        }

        if ((ret = read_certificates(&identity->certificates)) < 0)
        {
                LOG_ERROR("can't read certificates");
                cleanup_certificates(&identity->certificates);
                return -1;
        }
        return 0;
}

int create_endpoint_config(crypto_identity* crypto_id,
                           CryptoProfile* crypto_profile,
                           asl_endpoint_configuration* ep_cfg)
{

        int ret = 0;
        if ((crypto_id == NULL) || (crypto_profile == NULL) || (ep_cfg == NULL))
                goto error_occured;

        if (!crypto_id->certificates_available)
        {

                ret = load_certificates(crypto_id);
                if (ret < 0)
                        goto error_occured;
                crypto_id->certificates_available = true;
        }
        ep_cfg->pkcs11.module_path = crypto_profile->secure_middleware_path;
        ep_cfg->pkcs11.module_pin = crypto_profile->pin;

        ep_cfg->hybrid_signature_mode = crypto_profile->HybridSignatureMode;
        ep_cfg->key_exchange_method = crypto_profile->ASLKeyExchangeMethod;
        ep_cfg->mutual_authentication = crypto_profile->MutualAuthentication;
        ep_cfg->no_encryption = crypto_profile->NoEncryption;

        ep_cfg->device_certificate_chain.buffer = crypto_id->certificates.chain_buffer;
        ep_cfg->device_certificate_chain.size = crypto_id->certificates.chain_buffer_size;

        ep_cfg->root_certificate.buffer = crypto_id->certificates.root_buffer;
        ep_cfg->root_certificate.size = crypto_id->certificates.root_buffer_size;

        ep_cfg->private_key.buffer = crypto_id->certificates.key_buffer;
        ep_cfg->private_key.size = crypto_id->certificates.key_buffer_size;

        ep_cfg->private_key.additional_key_buffer = crypto_id->certificates.additional_key_buffer;
        ep_cfg->private_key.additional_key_size = crypto_id->certificates.additional_key_buffer_size;
        ep_cfg->private_key.size = crypto_id->certificates.key_buffer_size;

        return ret;

error_occured:
        if (ret > 0)
                ret = -1;
        LOG_ERROR("can't create asl_endpoint_configuration");

        return ret;
}

void free_ManagementConfiguration(Kritis3mManagemntConfiguration* config)
{
        memset(config->serial_number, 0, SERIAL_NUMBER_SIZE);
        memset(config->server_endpoint_addr.address, 0, ENDPOINT_LEN);
        memset(&config->identity.certificates, 0, sizeof(certificates));
        config->secure_middleware_path_size = 0;
        config->pin_size = 0;

        config->identity.filepath_size = 0;
        if (config->identity.filepath != NULL)
                free(config->identity.filepath);
        if (config->identity.revocation_list_url != NULL)
                free(config->identity.revocation_list_url);
        if (config->identity.server_url != NULL)
                free(config->identity.server_url);
        if (config->secure_middleware_path != NULL)
                free(config->secure_middleware_path);
        if (config->pin != NULL)
                free(config->pin);
}

void free_CryptoIdentity(crypto_identity* identity)
{
        if (identity == NULL)
                return;
        if (identity->filepath != NULL)
                free(identity->filepath);

        if (identity->server_url != NULL)
                free(identity->server_url);

        if (identity->revocation_list_url != NULL)
                free(identity->revocation_list_url);

        cleanup_certificates(&identity->certificates);
}

void free_NodeConfig(Kritis3mNodeConfiguration* config)
{

        if (config != NULL)
        {
                config->config_path_size = 0;
                config->primary_path_size = 0;
                config->secondary_path_size = 0;
                config->pki_cert_path_size = 0;
                config->machine_crypto_path_size = 0;

                config->remote_path_size = 0;
                config->production_path_size = 0;
                config->management_path_size = 0;
                config->management_service_path_size = 0;

                if (config->primary_path != NULL)
                        free(config->primary_path);
                if (config->secondary_path != NULL)
                        free(config->secondary_path);

                if (config->remote_path != NULL)
                        free(config->remote_path);
                if (config->management_path != NULL)
                        free(config->management_path);
                if (config->management_service_path != NULL)
                        free(config->management_service_path);
                if (config->production_path != NULL)
                        free(config->production_path);

                if (config->machine_crypto_path != NULL)
                        free(config->machine_crypto_path);

                if (config->pki_cert_path != NULL)
                        free(config->pki_cert_path);

                if (config->crypto_path != NULL)
                        free(config->crypto_path);
        }
        free_CryptoIdentity(&config->management_identity.identity);
}

void cleanup_Systemconfiguration(SystemConfiguration* systemconfiguration)
{
        if (systemconfiguration == NULL)
                return;

        systemconfiguration->cfg_id = 0;
        systemconfiguration->node_id = 0;
        memset(systemconfiguration->locality, 0, NAME_LEN);
        memset(systemconfiguration->serial_number, 0, NAME_LEN);
        systemconfiguration->node_network_index = 0;
        systemconfiguration->heartbeat_interval = 0;
        systemconfiguration->version = 0;

        /**------------------------------ WHITELIST FREE---------------------------------------- */
        Whitelist* whitelist = &systemconfiguration->application_config.whitelist;
        for (int i = 0; i < whitelist->number_trusted_clients; i++)
        {
                memset(&whitelist->TrustedClients[i].trusted_client, 0, sizeof(Kritis3mSockaddr));
                whitelist->TrustedClients[i].id = 0;
                whitelist->TrustedClients[i].number_trusted_applications = 0;
                for (int j = 0; j < whitelist->TrustedClients[i].number_trusted_applications; j++)
                        whitelist->TrustedClients[i].trusted_applications_id[j] = 0;
        }

        /**------------------------------ CRYPTO FREE---------------------------------------- */
        for (int i = 0; i < MAX_NUMBER_CRYPTOPROFILE; i++)
        {
                CryptoProfile* profile = &systemconfiguration->application_config.crypto_profile[i];
                profile->id = 0;
                profile->ASLKeyExchangeMethod = ASL_KEX_DEFAULT,
                profile->HybridSignatureMode = ASL_HYBRID_SIGNATURE_MODE_DEFAULT;
                profile->crypto_identity_id = 0;
                profile->Keylog = false;
                profile->NoEncryption = false;
                profile->UseSecureElement = false;
                memset(profile->Name, 0, MAX_NAME_SIZE);
        }

        /**------------------------------ APPLICATIONS FREE---------------------------------------- */
        for (int i = 0; i < MAX_NUMBER_APPLICATIONS; i++)
        {
                Kritis3mApplications* appl = &systemconfiguration->application_config.applications[i];
                appl->id = 0;
                appl->ep1_id = 0;
                appl->ep2_id = 0;
                appl->config_id = 0;
                appl->log_level = 0;
                appl->state = false;
                appl->type = UNDEFINED;
                if (appl->client_endpoint_addr.address != NULL)
                {
                        free(appl->client_endpoint_addr.address);
                        appl->client_endpoint_addr.address = NULL;
                }
                appl->client_endpoint_addr.port = 0;

                if (appl->server_endpoint_addr.address != NULL)
                {
                        free(appl->server_endpoint_addr.address);
                        appl->server_endpoint_addr.address = NULL;
                }
                appl->server_endpoint_addr.port = 0;
        }

        /**------------------------------ Identity FREE---------------------------------------- */
        for (int i = 0; i < MAX_NUMBER_CRYPTOPROFILE; i++)
        {
                crypto_identity* cr_identity = &systemconfiguration->application_config.crypto_identity[i];
                cr_identity->identity = MANAGEMENT_SERVICE;

                if (cr_identity->server_endpoint_addr.address != NULL)
                {
                        free(cr_identity->server_endpoint_addr.address);
                        cr_identity->server_endpoint_addr.address = NULL;
                }
                cr_identity->server_endpoint_addr.port = 0;
                free_CryptoIdentity(cr_identity);
        }
        systemconfiguration->application_config.number_applications = 0;
        systemconfiguration->application_config.number_crypto_identity = 0;
        systemconfiguration->application_config.number_crypto_profiles = 0;
        systemconfiguration->application_config.number_hw_config = 0;
}

void cleanup_configuration_manager(ConfigurationManager* configuration_manager)
{
        if (configuration_manager == NULL)
                return;
        cleanup_Systemconfiguration(&configuration_manager->primary);
        cleanup_Systemconfiguration(&configuration_manager->secondary);
        configuration_manager->active_configuration = CFG_NONE;
        memset(configuration_manager->primary_file_path, 0, MAX_FILEPATH_SIZE);
        memset(configuration_manager->secondary_file_path, 0, MAX_FILEPATH_SIZE);
}

char* applicationManagerStatusToJson(const ApplicationManagerStatus* status,
                                     char* json_buffer,
                                     size_t buffer_length)
{
        // Clear the buffer
        memset(json_buffer, 0, buffer_length);

        // Create a cJSON object
        cJSON* json_obj = cJSON_CreateObject();
        if (json_obj == NULL)
        {
                return NULL;
        }

        // Add fields to JSON
        cJSON_AddNumberToObject(json_obj, "status", status->Status);
        cJSON_AddNumberToObject(json_obj, "running_applications", status->running_applications);

        // Convert to string and copy to buffer
        char* json_str = cJSON_Print(json_obj);
        if (json_str == NULL)
        {
                cJSON_Delete(json_obj);
                return NULL;
        }

        // Copy to buffer (with safety check)
        strncpy(json_buffer, json_str, buffer_length - 1);
        json_buffer[buffer_length - 1] = '\0'; // Ensure null-termination

        // Free the dynamically allocated JSON string from cJSON_Print
        free(json_str);

        // Clean up the cJSON object
        cJSON_Delete(json_obj);

        return json_buffer;
}

// !not working with url
int parse_addr_toKritis3maddr(char* ip_port, Kritis3mSockaddr* dst)
{
        uint16_t port = 0;
        char* ip;
        int proto_family = -1;
        int ret = 0;

        // Validate input
        if (ip_port == NULL)
        {
                goto error_occured;
        }

        ret = parse_ip_address(ip_port, &ip, &port);
        if (ret < 0)
                goto error_occured;

        if (inet_pton(AF_INET, ip, &dst->sockaddr_in.sin_addr) == 1)
        {
                dst->sockaddr_in.sin_family = AF_INET;
                dst->sockaddr_in.sin_port = htons(port);
        }
        else if (inet_pton(AF_INET6, ip, &dst->sockaddr_in6.sin6_addr) == 1)
        {
                dst->sockaddr_in6.sin6_family = AF_INET6;
                dst->sockaddr_in6.sin6_port = htons(port);
        }
        else
        {
                goto error_occured;
        }

        if (!ip)
                free(ip);

        return 0;

error_occured:
        if (!ip)
                free(ip);
        LOG_ERROR("can't parse json ip format to KRITIS3MSocket");
        return -1;
}