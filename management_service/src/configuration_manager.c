#include <complex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>

#include "asl.h"
#include "configuration_manager.h"
#include "configuration_parser.h"
#include "file_io.h"
#include "logging.h"
#include "networking.h"
#include "pki_client.h"

LOG_MODULE_CREATE(configuration_manager);

// Global transaction lock
static pthread_mutex_t global_transaction_lock = PTHREAD_MUTEX_INITIALIZER;
static bool transaction_in_progress = false;
static enum CONFIG_TYPE active_transaction_type = 0;

#define SYS_CONFIG_PATH_FORMAT "%s/sys_config.json"

#define CONTROLPLANE_1_CHAIN_PATH_FORMAT "%s/cert/1/controlplane_chain.pem"
#define CONTROLPLANE_1_KEY_PATH_FORMAT "%s/cert/1/controlplane_key.pem"
#define CONTROLPLANE_1_ALTKEY_PATH_FORMAT "%s/cert/1/controlplane_altkey.pem"

#define CONTROLPLANE_2_CHAIN_PATH_FORMAT "%s/cert/2/controlplane_chain.pem"
#define CONTROLPLANE_2_KEY_PATH_FORMAT "%s/cert/2/controlplane_key.pem"
#define CONTROLPLANE_2_ALTKEY_PATH_FORMAT "%s/cert/2/controlplane_altkey.pem"

#define DATAPLANE_1_CHAIN_PATH_FORMAT "%s/cert/1/dataplane_chain.pem"
#define DATAPLANE_1_KEY_PATH_FORMAT "%s/cert/1/dataplane_key.pem"
#define DATAPLANE_1_ALTKEY_PATH_FORMAT "%s/cert/1/dataplane_altkey.pem"

#define DATAPLANE_2_CHAIN_PATH_FORMAT "%s/cert/2/dataplane_chain.pem"
#define DATAPLANE_2_KEY_PATH_FORMAT "%s/cert/2/dataplane_key.pem"
#define DATAPLANE_2_ALTKEY_PATH_FORMAT "%s/cert/2/dataplane_altkey.pem"

#define BOOTSTRAP_CHAIN_PATH_FORMAT "%s/cert/chain.pem"
#define BOOTSTRAP_KEY_PATH_FORMAT "%s/cert/key.pem"
#define BOOTSTRAP_ALTKEY_PATH_FORMAT "%s/cert/altkey.pem"
#define ROOT_PATH_FORMAT "%s/cert/root.pem"

#define APPLICATION_1_PATH_FORMAT "%s/application/1/application.json"
#define APPLICATION_2_PATH_FORMAT "%s/application/2/application.json"

// forward declaration
void cleanup_sysconfig();
void cleanup_configuration_manager(void);
void cleanup_application_config(struct application_manager_config* config);
void cleanup_hardware_configs(struct hardware_configs* hw_configs);

int test_server_conn(char* host, asl_endpoint_configuration* endpoint_config);
int write_sysconfig(void);

void cleanup_endpoint_config(asl_endpoint_configuration* endpoint_config);

int load_endpoint_certificates(asl_endpoint_configuration* endpoint_config,
                               char* chain_path,
                               char* key_path,
                               char* optional_key_path,
                               char* root_path);

struct configuration_manager
{
        char* base_path;

        bool initialized;
        char* sys_config_path;

        struct sysconfig sys_config;

        char* root_cert;

        char* bootstrap_key_path;
        char* bootstrap_altkey_path;
        char* bootstrap_chain_path;

        char* controlplane_1_chain_path;
        char* controlplane_1_key_path;
        char* controlplane_1_altkey_path;

        char* controlplane_2_chain_path;
        char* controlplane_2_key_path;
        char* controlplane_2_altkey_path;

        char* dataplane_1_chain_path;
        char* dataplane_1_key_path;
        char* dataplane_1_altkey_path;

        char* dataplane_2_chain_path;
        char* dataplane_2_key_path;
        char* dataplane_2_altkey_path;

        // application
        char* application_1_path;
        char* application_2_path;
};

static struct configuration_manager configuration_manager = {0};

const struct sysconfig* get_sysconfig()
{
        return (const struct sysconfig*) &configuration_manager.sys_config;
}
const char* strr_transactiontype(enum CONFIG_TYPE cfg_type){
        
        switch(cfg_type){
                case CONFIG_APPLICATION:
                return "dataplane policy transaction";
                case CONFIG_DATAPLANE:
                return "dataplane certificate transaction";
                case CONFIG_CONTROLPLANE:
                return "controlplane certificate transaction";
        }
        return "";
}


int get_application_inactive(struct application_manager_config* config,
                             struct hardware_configs* hw_config)
{
        if (!config || !hw_config || !configuration_manager.initialized)
        {
                LOG_ERROR("Invalid arguments or configuration manager not initialized");
                return -1;
        }

        char* source_path = NULL;

        // Determine which application config to read based on active configuration
        switch (configuration_manager.sys_config.application_active)
        {
        case ACTIVE_ONE:
                // If active is one, use application_2_path (inactive)
                source_path = configuration_manager.application_2_path;
                break;
        case ACTIVE_TWO:
                // If active is two, use application_1_path (inactive)
                source_path = configuration_manager.application_1_path;
                break;
        case ACTIVE_NONE:
                // If none is active, use application_1_path as default
                LOG_INFO("No active application configuration is set, using application_1_path as "
                         "default");
                source_path = configuration_manager.application_1_path;
                break;
        default:
                LOG_ERROR("Invalid application active configuration");
                return -1;
        }

        if (!source_path)
        {
                LOG_ERROR("Failed to determine source path for application configuration");
                return -1;
        }

        // Read the configuration file
        char* buffer = NULL;
        size_t buffer_size = 0;
        int ret = read_file(source_path, (uint8_t**) &buffer, &buffer_size);
        if (ret < 0)
        {
                LOG_ERROR("Failed to read application configuration from %s", source_path);
                return -1;
        }

        // Parse the configuration
        ret = parse_config(buffer, buffer_size, config, hw_config);
        if (ret != 0)
        {
                LOG_ERROR("Failed to parse application configuration");
                free(buffer);
                return -1;
        }
        if (buffer)
        {
                free(buffer);
                buffer = NULL;
        }

        // Now load certificates for each group's endpoint configuration
        for (int i = 0; i < config->number_of_groups; i++)
        {
                if (!config->group_config[i].endpoint_config)
                {
                        LOG_ERROR("Endpoint configuration missing for group %d", i);
                        free(buffer);
                        return -1;
                }

                // Determine which dataplane certificate chain to use based on active configuration
                char* chain_path = NULL;
                switch (configuration_manager.sys_config.dataplane_cert_active)
                {

                case ACTIVE_NONE:
                        LOG_INFO("No active dataplane configuration is set, using "
                                 "dataplane_1_chain_path as default");
                case ACTIVE_ONE:
                        chain_path = configuration_manager.dataplane_1_chain_path;

                        // Load certificates into this endpoint configuration
                        ret = load_endpoint_certificates(config->group_config[i].endpoint_config,
                                                         configuration_manager.dataplane_1_chain_path,
                                                         configuration_manager.dataplane_1_key_path,
                                                         configuration_manager.dataplane_1_altkey_path,
                                                         configuration_manager.root_cert);
                        break;
                case ACTIVE_TWO:
                        ret = load_endpoint_certificates(config->group_config[i].endpoint_config,
                                                         configuration_manager.dataplane_2_chain_path,
                                                         configuration_manager.dataplane_2_key_path,
                                                         configuration_manager.dataplane_2_altkey_path,
                                                         configuration_manager.root_cert);
                        break;
                default:
                        LOG_ERROR("Invalid dataplane active configuration");
                        return -1;
                }

                if (ret != 0)
                {
                        LOG_ERROR("Failed to load certificates for group %d", i);
                        return -1;
                }

                LOG_INFO("Successfully loaded certificates for group %d", i);
        }

        LOG_INFO("Successfully loaded application configuration from %s", source_path);
        return 0;
}

int application_store_inactive(char* buffer, size_t size)
{
        if (!buffer || size == 0 || !configuration_manager.initialized)
        {
                LOG_ERROR("Invalid buffer or size");
                return -1;
        }

        char* destination = NULL;

        switch (configuration_manager.sys_config.application_active)
        {
        case ACTIVE_NONE:
                LOG_INFO("No active controlplane configuration is set, using 1 as default");
                destination = configuration_manager.application_1_path;
                break;
        case ACTIVE_ONE:
                destination = configuration_manager.application_2_path;
                break;
        case ACTIVE_TWO:
                destination = configuration_manager.application_1_path;
                break;
        default:
                LOG_ERROR("Invalid controlplane active configuration");
                return -1;
        }

        if (!destination)
        {
                LOG_ERROR("Failed to determine destination path");
                return -1;
        }

        int ret = write_file(destination, (const uint8_t*) buffer, size, false);
        if (ret != 0)
        {
                LOG_ERROR("Failed to write configuration to %s", destination);
                return -1;
        }

        LOG_INFO("Successfully stored configuration to %s", destination);
        return 0;
}

int init_configuration_manager(char* base_path)
{
        if (!base_path)
        {
                LOG_ERROR("Invalid base path");
                return -1;
        }

        char* buffer = NULL;
        memset(&configuration_manager, 0, sizeof(struct configuration_manager));

        configuration_manager.base_path = duplicate_string(base_path);

        char helper_string[300];
        int ret = 0;

        // sysconfig
        int len = snprintf(helper_string, 300, SYS_CONFIG_PATH_FORMAT, base_path);
        configuration_manager.sys_config_path = duplicate_string(helper_string);

        // controlplane
        len = snprintf(helper_string, 300, ROOT_PATH_FORMAT, base_path);
        configuration_manager.root_cert = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, BOOTSTRAP_KEY_PATH_FORMAT, base_path);
        configuration_manager.bootstrap_key_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, BOOTSTRAP_ALTKEY_PATH_FORMAT, base_path);
        configuration_manager.bootstrap_altkey_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, BOOTSTRAP_CHAIN_PATH_FORMAT, base_path);
        configuration_manager.bootstrap_chain_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, CONTROLPLANE_1_ALTKEY_PATH_FORMAT, base_path);
        configuration_manager.controlplane_1_altkey_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, CONTROLPLANE_1_KEY_PATH_FORMAT, base_path);
        configuration_manager.controlplane_1_key_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, CONTROLPLANE_1_CHAIN_PATH_FORMAT, base_path);
        configuration_manager.controlplane_1_chain_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, CONTROLPLANE_2_ALTKEY_PATH_FORMAT, base_path);
        configuration_manager.controlplane_2_altkey_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, CONTROLPLANE_2_KEY_PATH_FORMAT, base_path);
        configuration_manager.controlplane_2_key_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, CONTROLPLANE_2_CHAIN_PATH_FORMAT, base_path);
        configuration_manager.controlplane_2_chain_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, DATAPLANE_1_ALTKEY_PATH_FORMAT, base_path);
        configuration_manager.dataplane_1_altkey_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, DATAPLANE_1_KEY_PATH_FORMAT, base_path);
        configuration_manager.dataplane_1_key_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, DATAPLANE_1_CHAIN_PATH_FORMAT, base_path);
        configuration_manager.dataplane_1_chain_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, DATAPLANE_2_ALTKEY_PATH_FORMAT, base_path);
        configuration_manager.dataplane_2_altkey_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, DATAPLANE_2_KEY_PATH_FORMAT, base_path);
        configuration_manager.dataplane_2_key_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, DATAPLANE_2_CHAIN_PATH_FORMAT, base_path);
        configuration_manager.dataplane_2_chain_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, APPLICATION_1_PATH_FORMAT, base_path);
        configuration_manager.application_1_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, APPLICATION_2_PATH_FORMAT, base_path);
        configuration_manager.application_2_path = duplicate_string(helper_string);

        size_t buffer_size = 0;
        ret = read_file(configuration_manager.sys_config_path, (uint8_t**) &buffer, &buffer_size);
        if (ret < 0)
        {
                LOG_ERROR("Failed to read sys_config");
                goto error;
        }
        ret = parse_buffer_to_sysconfig(buffer, buffer_size, &configuration_manager.sys_config);
        if (ret != 0)
        {
                LOG_ERROR("Failed to parse sys_config");
                goto error;
        }

        switch (configuration_manager.sys_config.controlplane_cert_active)
        {
        case ACTIVE_ONE:
                ret = load_endpoint_certificates(configuration_manager.sys_config.endpoint_config,
                                                 configuration_manager.controlplane_1_chain_path,
                                                 configuration_manager.controlplane_1_key_path,
                                                 configuration_manager.controlplane_1_altkey_path,
                                                 configuration_manager.root_cert);
                break;
        case ACTIVE_TWO:
                ret = load_endpoint_certificates(configuration_manager.sys_config.endpoint_config,
                                                 configuration_manager.controlplane_2_chain_path,
                                                 configuration_manager.controlplane_2_key_path,
                                                 configuration_manager.controlplane_2_altkey_path,
                                                 configuration_manager.root_cert);
                break;
        case ACTIVE_NONE:
                ret = load_endpoint_certificates(configuration_manager.sys_config.endpoint_config,
                                                 configuration_manager.bootstrap_chain_path,
                                                 configuration_manager.bootstrap_key_path,
                                                 configuration_manager.bootstrap_altkey_path,
                                                 configuration_manager.root_cert);
                break;
        default:
                LOG_ERROR("Invalid controlplane active configuration");
                goto error;
        }

        if (ret < 0)
                goto error;
        configuration_manager.initialized = true;
        return 0;

error:
        if (buffer)
                free(buffer);

        cleanup_configuration_manager();
        return -1;
}

void cfg_manager_log_level_set(int log_level){
        LOG_LVL_SET(log_level);
}

int test_server_conn(char* host, asl_endpoint_configuration* endpoint_config)
{
        if (!host || !endpoint_config)
        {
                LOG_ERROR("Invalid host or endpoint configuration");
                return -1;
        }
        int ret = 0;
        int socket = -1;
        asl_endpoint* endpoint = NULL;
        asl_session* session = NULL;
        struct addrinfo* addr = NULL;

        // Create endpoint with the provided configuration
        endpoint = asl_setup_client_endpoint(endpoint_config);
        if (!endpoint)
        {
                LOG_ERROR("Failed to create endpoint");
                ret = -1;
                goto error;
        }

        // modified for testing purposes
        // modified for testing purposes
        // modified for testing purposes
        // modified for testing purposes
        // modified for testing purposes
        if (address_lookup_client(host, 8080, &addr, AF_UNSPEC) != 0)
        {
                LOG_ERROR("Failed to resolve server address");
                ret = -1;
                goto error;
        }

        // Create socket and connect
        socket = create_client_socket(addr->ai_socktype);
        if (socket == -1)
        {
                LOG_ERROR("Failed to create client socket");
                ret = -1;
                goto error;
        }

        // Connect to the server
        if (connect(socket, addr->ai_addr, addr->ai_addrlen) != 0)
        {
                LOG_ERROR("Failed to connect to server");
                ret = -1;
                goto error;
        }

        // Create TLS session
        session = asl_create_session(endpoint, socket);
        if (!session)
        {
                LOG_ERROR("Failed to create TLS session");
                ret = -1;
                goto error;
        }

        ret = asl_handshake(session);
        if (ret != ASL_SUCCESS)
        {
                LOG_ERROR("TLS handshake failed");
                ret = -1;
                goto error;
        }

        LOG_INFO("TLS handshake successful");
        asl_close_session(session);
        closesocket(socket);
        asl_free_session(session);
        asl_free_endpoint(endpoint);
        freeaddrinfo(addr);
        return 0;
error:
        if (socket != -1)
        {
                closesocket(socket);
                socket = -1;
        }
        if (session)
                asl_free_session(session);
        if (endpoint)
                asl_free_endpoint(endpoint);
        if (addr)
                freeaddrinfo(addr);
        return ret;
}

int load_endpoint_certificates(asl_endpoint_configuration* endpoint_config,
                               char* chain_path,
                               char* key_path,
                               char* optional_key_path,
                               char* root_path)
{
        if (!endpoint_config)
        {
                return -1;
        }
        if (read_file(chain_path,
                      (uint8_t**) &endpoint_config->device_certificate_chain.buffer,
                      &endpoint_config->device_certificate_chain.size) < 0)
        {
                LOG_ERROR("Failed to load controlplane certificate chain");
                return -1;
        }
        if (read_file(key_path,
                      (uint8_t**) &endpoint_config->private_key.buffer,
                      &endpoint_config->private_key.size) < 0)
        {
                LOG_ERROR("Failed to load controlplane private key");
                return -1;
        }
        if (read_file(optional_key_path,
                      (uint8_t**) &endpoint_config->private_key.additional_key_buffer,
                      &endpoint_config->private_key.additional_key_size) < 0)
        {
                LOG_WARN("no additional key buffer. All good");
        }
        if (endpoint_config->private_key.additional_key_size == 0)
        {
                if (endpoint_config->private_key.additional_key_buffer)
                {
                        free((void*) endpoint_config->private_key.additional_key_buffer);
                }
                endpoint_config->private_key.additional_key_buffer = NULL;
        }

        if (read_file(root_path,
                      (uint8_t**) &endpoint_config->root_certificate.buffer,
                      &endpoint_config->root_certificate.size) < 0)
        {
                LOG_ERROR("Failed to load controlplane root certificate");
                return -1;
        }

        return 0;
}

void cleanup_endpoint_config(asl_endpoint_configuration* endpoint_config)
{
        // add if null
        if (endpoint_config == NULL)
                return;

        if (endpoint_config->keylog_file)
                free((void*) endpoint_config->keylog_file);
        if (endpoint_config->ciphersuites)
                free((void*) endpoint_config->ciphersuites);

        if (endpoint_config->pkcs11.module_path)
                free((void*) endpoint_config->pkcs11.module_path);
        if (endpoint_config->pkcs11.module_pin)
                free((void*) endpoint_config->pkcs11.module_pin);

        if (endpoint_config->device_certificate_chain.buffer)
                free((void*) endpoint_config->device_certificate_chain.buffer);

        if (endpoint_config->root_certificate.buffer)
                free((void*) endpoint_config->root_certificate.buffer);

        if (endpoint_config->private_key.buffer)
                free((void*) endpoint_config->private_key.buffer);
        if (endpoint_config->private_key.additional_key_buffer)
                free((void*) endpoint_config->private_key.additional_key_buffer);
}

void cleanup_sysconfig()
{
        if (configuration_manager.sys_config.serial_number)
                free(configuration_manager.sys_config.serial_number);
        if (configuration_manager.sys_config.broker_host)
                free(configuration_manager.sys_config.broker_host);
        if (configuration_manager.sys_config.est_host)
                free(configuration_manager.sys_config.est_host);
        if (configuration_manager.sys_config.endpoint_config)
        {
                cleanup_endpoint_config(configuration_manager.sys_config.endpoint_config);
                free(configuration_manager.sys_config.endpoint_config);
        }
                
        memset(&configuration_manager.sys_config, 0, sizeof(struct sysconfig));
}

char* get_base_path(void)
{
        return configuration_manager.base_path;
}

void cleanup_configuration_manager(void)
{

        // sysconfig
        if (configuration_manager.sys_config_path)
                free(configuration_manager.sys_config_path);

        if (configuration_manager.base_path)
                free(configuration_manager.base_path);

        // controlplane
        if (configuration_manager.controlplane_1_chain_path)
                free(configuration_manager.controlplane_1_chain_path);
        if (configuration_manager.controlplane_1_key_path)
                free(configuration_manager.controlplane_1_key_path);
        if (configuration_manager.controlplane_1_altkey_path)
                free(configuration_manager.controlplane_1_altkey_path);
        if (configuration_manager.controlplane_2_chain_path)
                free(configuration_manager.controlplane_2_chain_path);
        if (configuration_manager.controlplane_2_key_path)
                free(configuration_manager.controlplane_2_key_path);
        if (configuration_manager.controlplane_2_altkey_path)
                free(configuration_manager.controlplane_2_altkey_path);

        // dataplane
        if (configuration_manager.dataplane_1_chain_path)
                free(configuration_manager.dataplane_1_chain_path);
        if (configuration_manager.dataplane_1_key_path)
                free(configuration_manager.dataplane_1_key_path);
        if (configuration_manager.dataplane_1_altkey_path)
                free(configuration_manager.dataplane_1_altkey_path);
        if (configuration_manager.dataplane_2_chain_path)
                free(configuration_manager.dataplane_2_chain_path);
        if (configuration_manager.dataplane_2_key_path)
                free(configuration_manager.dataplane_2_key_path);
        if (configuration_manager.dataplane_2_altkey_path)
                free(configuration_manager.dataplane_2_altkey_path);

        // bootstrap
        if (configuration_manager.bootstrap_chain_path)
                free(configuration_manager.bootstrap_chain_path);
        if (configuration_manager.bootstrap_key_path)
                free(configuration_manager.bootstrap_key_path);
        if (configuration_manager.bootstrap_altkey_path)
                free(configuration_manager.bootstrap_altkey_path);
        if (configuration_manager.root_cert)
                free(configuration_manager.root_cert);

        // applications
        if (configuration_manager.application_1_path)
                free(configuration_manager.application_1_path);
        if (configuration_manager.application_2_path)
                free(configuration_manager.application_2_path);

        cleanup_sysconfig();
}

int write_sysconfig(void)
{
        if (!configuration_manager.sys_config_path || !configuration_manager.initialized)
        {
                LOG_ERROR("Configuration manager not properly initialized");
                return -1;
        }

        char json_buffer[3000];

        int ret = parse_sysconfig_to_json(&configuration_manager.sys_config,
                                          json_buffer,
                                          sizeof(json_buffer));
        if (ret != 0)
        {
                LOG_ERROR("Failed to convert sysconfig to JSON");
                return -1;
        }

        // Write directly to the file in one operation
        ret = write_file(configuration_manager.sys_config_path,
                         (const uint8_t*) json_buffer,
                         strlen(json_buffer),
                         false);
        if (ret != 0)
        {
                LOG_ERROR("Failed to write sys_config to file: %s",
                          configuration_manager.sys_config_path);
                return -1;
        }

        LOG_INFO("Successfully wrote sysconfig to file: %s", configuration_manager.sys_config_path);
        return 0;
}

int get_active_hardware_config(struct application_manager_config* app_config,
                               struct hardware_configs* hw_configs)
{
        if (!app_config || !hw_configs || !configuration_manager.initialized)
        {
                LOG_ERROR("Invalid arguments or configuration manager not initialized");
                return -1;
        }

        // Initialize output structures
        memset(app_config, 0, sizeof(struct application_manager_config));
        memset(hw_configs, 0, sizeof(struct hardware_configs));

        char* source_path = NULL;

        // Determine which application config to read based on active dataplane
        switch (configuration_manager.sys_config.application_active)
        {
        case ACTIVE_ONE:
                source_path = configuration_manager.application_1_path;
                break;
        case ACTIVE_TWO:
                source_path = configuration_manager.application_2_path;
                break;
        case ACTIVE_NONE:
                LOG_INFO("No active dataplane configuration, using application_1_path as "
                         "default");
                source_path = configuration_manager.application_1_path;
                break;
        default:
                LOG_ERROR("Invalid dataplane active configuration");
                return -1;
        }

        if (!source_path)
        {
                LOG_ERROR("Failed to determine source path for application configuration");
                return -1;
        }

        // Read the configuration file
        char* buffer = NULL;
        size_t buffer_size = 0;
        int ret = read_file(source_path, (uint8_t**) &buffer, &buffer_size);
        if (ret < 0)
        {
                LOG_ERROR("Failed to read application configuration from %s", source_path);
                return -1;
        }

        // Parse the configuration
        ret = parse_config(buffer, buffer_size, app_config, hw_configs);
        if (ret != 0)
        {
                LOG_ERROR("Failed to parse application configuration");
                free(buffer);
                return -1;
        }
        if (buffer)
        {
                free(buffer);
                buffer = NULL;
        }

        // Now load certificates for each group's endpoint configuration
        for (int i = 0; i < app_config->number_of_groups; i++)
        {
                if (!app_config->group_config[i].endpoint_config)
                {
                        LOG_ERROR("Endpoint configuration missing for group %d", i);
                        cleanup_application_config(app_config);
                        cleanup_hardware_configs(hw_configs);
                        return -1;
                }

                // Determine which dataplane certificate chain to use
                char* chain_path = NULL;
                switch (configuration_manager.sys_config.dataplane_cert_active)
                {
                case ACTIVE_ONE:

                        // Load certificates into this endpoint configuration
                        ret = load_endpoint_certificates(app_config->group_config[i].endpoint_config,
                                                         configuration_manager.dataplane_1_chain_path,
                                                         configuration_manager.dataplane_1_key_path,
                                                         configuration_manager.dataplane_1_altkey_path,
                                                         configuration_manager.root_cert);
                        break;
                case ACTIVE_TWO:
                        ret = load_endpoint_certificates(app_config->group_config[i].endpoint_config,
                                                         configuration_manager.dataplane_2_chain_path,
                                                         configuration_manager.dataplane_2_key_path,
                                                         configuration_manager.dataplane_2_altkey_path,
                                                         configuration_manager.root_cert);
                        break;
                case ACTIVE_NONE:
                        LOG_INFO("No active dataplane configuration is set, using "
                                 "dataplane_1_chain_path as default");

                        // Load certificates into this endpoint configuration
                        ret = load_endpoint_certificates(app_config->group_config[i].endpoint_config,
                                                         configuration_manager.dataplane_1_chain_path,
                                                         configuration_manager.dataplane_1_key_path,
                                                         configuration_manager.dataplane_1_altkey_path,
                                                         configuration_manager.root_cert);

                        break;
                default:
                        LOG_ERROR("Invalid dataplane active configuration");
                        cleanup_application_config(app_config);
                        cleanup_hardware_configs(hw_configs);
                        return -1;
                }

                if (ret != 0)
                {
                        LOG_ERROR("Failed to load certificates for group %d", i);
                        cleanup_application_config(app_config);
                        cleanup_hardware_configs(hw_configs);
                        return -1;
                }

                LOG_INFO("Successfully loaded certificates for group %d", i);
        }

        LOG_INFO("Successfully loaded active hardware configuration from %s", source_path);
        return 0;
}

// Helper functions to clean up resources
void cleanup_application_config(struct application_manager_config* config)
{
        if (!config)
                return;

        if (config->group_config)
        {
                for (int i = 0; i < config->number_of_groups; i++)
                {
                        if (config->group_config[i].endpoint_config)
                        {
                                cleanup_endpoint_config(config->group_config[i].endpoint_config);
                                if (config->group_config[i].endpoint_config)
                                {
                                        free(config->group_config[i].endpoint_config);
                                        config->group_config[i].endpoint_config = NULL;
                                }
                        }

                        // Free proxy wrappers
                        if (config->group_config[i].proxy_wrapper)
                        {
                                for (int j = 0; j < config->group_config[i].number_proxies; j++)
                                {
                                        if (config->group_config[i].proxy_wrapper[j].proxy_config.own_ip_address)
                                                free(config->group_config[i]
                                                             .proxy_wrapper[j]
                                                             .proxy_config.own_ip_address);
                                        if (config->group_config[i].proxy_wrapper[j].proxy_config.target_ip_address)
                                                free(config->group_config[i]
                                                             .proxy_wrapper[j]
                                                             .proxy_config.target_ip_address);
                                }
                                // deletes the whole array
                                free(config->group_config[i].proxy_wrapper);
                        }
                }
                free(config->group_config);
        }
        config->group_config = NULL;
        config->number_of_groups = 0;
}

void cleanup_hardware_configs(struct hardware_configs* hw_configs)
{
        if (!hw_configs)
                return;

        if (hw_configs->hw_configs)
        {
                free(hw_configs->hw_configs);
                hw_configs->hw_configs = NULL;
        }
        hw_configs->number_of_hw_configs = 0;
}

int store_alt_ctrl_cert(char* cert_buffer, size_t cert_size)
{
        int ret = 0;
        if (!cert_buffer || cert_size == 0)
        {
                LOG_ERROR("Invalid buffer or size");
                return -1;
        }
        //? append yes or no?
        switch (configuration_manager.sys_config.controlplane_cert_active)
        {
        case ACTIVE_ONE:
                ret = write_file(configuration_manager.controlplane_2_chain_path,
                                 (const uint8_t*) cert_buffer,
                                 cert_size,
                                 false);
                ret = 0;
                break;
        case ACTIVE_TWO:
                ret = write_file(configuration_manager.controlplane_1_chain_path,
                                 (const uint8_t*) cert_buffer,
                                 cert_size,
                                 false);
                ret = 0;
                break;
        case ACTIVE_NONE:
                LOG_ERROR("No active controlplane configuration");
                ret = write_file(configuration_manager.controlplane_1_chain_path,
                                 (const uint8_t*) cert_buffer,
                                 cert_size,
                                 false);
                ret = 0;
                break;

        default:
                LOG_ERROR("Invalid controlplane active configuration");
                ret = -1;
                break;
        }
        return ret;
}

int store_transaction(void* context, enum CONFIG_TYPE type, void* to_fetch)
{
        int ret = 0;
        if (to_fetch == NULL)
        {
                LOG_ERROR("No new config to store");
                return -1;
        }
        char* key_path = NULL;
        char* chain_path = NULL;
        char* alt_key_path = NULL;

        char* chain = NULL;
        char* alt_key = NULL;
        char* key = NULL;

        struct est_configuration* est_config = (struct est_configuration*) to_fetch;
        if (est_config == NULL)
        {
                LOG_ERROR("Invalid est config");
                return -1;
        }

        switch (type)
        {
        case CONFIG_CONTROLPLANE:
                {
                        if (configuration_manager.sys_config.controlplane_cert_active == ACTIVE_ONE)
                        {
                                key_path = configuration_manager.controlplane_2_key_path;
                                chain_path = configuration_manager.controlplane_2_chain_path;
                                alt_key_path = configuration_manager.controlplane_2_altkey_path;
                        }
                        else if (configuration_manager.sys_config.controlplane_cert_active == ACTIVE_TWO)
                        {
                                key_path = configuration_manager.controlplane_1_key_path;
                                chain_path = configuration_manager.controlplane_1_chain_path;
                                alt_key_path = configuration_manager.controlplane_1_altkey_path;
                        }
                        else if (configuration_manager.sys_config.controlplane_cert_active == ACTIVE_NONE)
                        {
                                LOG_INFO("no configuration specified, copying "
                                         "controlplane_1_key_path to controlplane_2_key_path");
                                key_path = configuration_manager.controlplane_1_key_path;
                                chain_path = configuration_manager.controlplane_1_chain_path;
                                alt_key_path = configuration_manager.controlplane_1_altkey_path;
                        }
                        break;
                }
        case CONFIG_DATAPLANE:
                {
                        if (configuration_manager.sys_config.dataplane_cert_active == ACTIVE_ONE)
                        {
                                key_path = configuration_manager.dataplane_2_key_path;
                                chain_path = configuration_manager.dataplane_2_chain_path;
                                alt_key_path = configuration_manager.dataplane_2_altkey_path;
                        }
                        else if (configuration_manager.sys_config.dataplane_cert_active == ACTIVE_TWO)
                        {
                                key_path = configuration_manager.dataplane_1_key_path;
                                chain_path = configuration_manager.dataplane_1_chain_path;
                                alt_key_path = configuration_manager.dataplane_1_altkey_path;
                        }
                        else if (configuration_manager.sys_config.dataplane_cert_active == ACTIVE_NONE)
                        {
                                LOG_INFO("no configuration specified, copying dataplane_1_key_path "
                                         "to dataplane_2_key_path");
                                key_path = configuration_manager.dataplane_1_key_path;
                                chain_path = configuration_manager.dataplane_1_chain_path;
                                alt_key_path = configuration_manager.dataplane_1_altkey_path;
                        }
                        else
                        {
                                LOG_ERROR("Invalid dataplane active configuration");
                        }
                        break;
                }
        case CONFIG_APPLICATION:
                {
                        return 0;
                }
        default:
                LOG_ERROR("Invalid config type");
                return -1;
        }

        if (key_path != NULL && chain_path != NULL && alt_key_path != NULL)
        {
                if ((ret = write_file(key_path,
                                      (const uint8_t*) est_config->key,
                                      est_config->key_size,
                                      false)) < 0)
                {
                        LOG_ERROR("Failed to write key to file: %s", key_path);
                        return -1;
                }
                if ((ret = write_file(chain_path,
                                      (const uint8_t*) est_config->chain,
                                      est_config->chain_size,
                                      false)) < 0)
                {
                        LOG_ERROR("Failed to write chain to file: %s", chain_path);
                        return -1;
                }

                if (est_config->alt_key != NULL)
                {
                        if (est_config->alt_key_size == 0)
                        {
                                // reset or create existing file, with size 0
                                if (access(alt_key_path, F_OK) == 0)
                                {
                                        // File exists, delete it
                                        if (unlink(alt_key_path) < 0)
                                        {
                                                LOG_WARN("Failed to delete existing alt key file: %s", alt_key_path);
                                        }
                                        else
                                        {
                                                LOG_INFO("Deleted existing alt key file: %s", alt_key_path);
                                        }
                                }
                                return 0;
                        }
                        else
                        {
                                if ((ret = write_file(alt_key_path,
                                                      (const uint8_t*) est_config->alt_key,
                                                      est_config->alt_key_size,
                                                      false)) < 0)
                                {
                                        LOG_WARN("Failed to write alt_key to file: %s. Fault "
                                                 "tolerant, "
                                                 "node continues without error",
                                                 alt_key_path);
                                        return 0;
                                }
                        }
                }
        }
        else
        {
                LOG_ERROR("Invalid key, chain or alt_key path");
                return -1;
        }
        return ret;
}

int commit_update(void* context, enum CONFIG_TYPE type, void* to_fetch)
{
        int ret = 0;
        enum ACTIVE* cfg_type = NULL;

        switch (type)
        {
        case CONFIG_APPLICATION:
                cfg_type = &configuration_manager.sys_config.application_active;
                break;
        case CONFIG_DATAPLANE:
                cfg_type = &configuration_manager.sys_config.dataplane_cert_active;
                break;
        case CONFIG_CONTROLPLANE:
                cfg_type = &configuration_manager.sys_config.controlplane_cert_active;
                break;
        }
        if (cfg_type == NULL)
        {
                LOG_ERROR("Invalid configuration type");
                return -1;
        }

        if (*cfg_type == ACTIVE_ONE)
        {
                *cfg_type = ACTIVE_TWO;
        }
        else if (*cfg_type == ACTIVE_TWO)
        {
                *cfg_type = ACTIVE_ONE;
        }
        else if (*cfg_type == ACTIVE_NONE)
        {
                *cfg_type = ACTIVE_ONE;
        }
        else
        {
                LOG_ERROR("cfg_type has wrong state");
                return -1;
        }

        if ((ret = write_sysconfig()) < 0)
        {
                LOG_ERROR("rolling back");

                if (*cfg_type == ACTIVE_ONE)
                {
                        *cfg_type = ACTIVE_TWO;
                }
                else if (*cfg_type == ACTIVE_TWO)
                {
                        *cfg_type = ACTIVE_ONE;
                }
                else
                {
                        LOG_ERROR("cfg_type has wrong state");
                        return -1;
                }
        }
        return 0;
}

static void* transaction_worker(void* arg)
{
        struct config_transaction* transaction = (struct config_transaction*) arg;
        char* new_config = NULL;
        size_t config_size = 0;
        int ret = 0;

        // Lock transaction
        pthread_mutex_lock(&transaction->mutex);
        transaction->state = TRANSACTION_PENDING;
        pthread_mutex_unlock(&transaction->mutex);

        // Fetch new configuration
        LOG_DEBUG("Transaction worker: fetch=%p, context=%p, type=%d, to_fetch=%p",
                  transaction->fetch,
                  transaction->context,
                  transaction->type,
                  transaction->to_fetch);

        if (!transaction->fetch)
        {
                LOG_ERROR("Fetch function pointer is NULL");
                goto error;
        }

        ret = transaction->fetch(transaction->context, transaction->type, transaction->to_fetch);
        if (ret != 0)
        {
                LOG_ERROR("Failed to fetch new configuration for transaction, %s", strr_transactiontype(transaction->type));
                
                goto error;
        }

        // Update state to validating
        pthread_mutex_lock(&transaction->mutex);
        transaction->state = TRANSACTION_VALIDATING;
        pthread_mutex_unlock(&transaction->mutex);

        // Validate new configuration
        ret = transaction->validate(transaction->context, transaction->type, transaction->to_fetch);
        if (ret != 0)
        {
                LOG_ERROR("Configuration validation failed, for transaction, %s", strr_transactiontype(transaction->type));
                goto error;
        }
        LOG_INFO("Configuration validation successful");
        // Prepare update
        if (transaction->type == CONFIG_CONTROLPLANE || transaction->type == CONFIG_DATAPLANE)
        {
                ret = store_transaction(transaction->context, transaction->type, transaction->to_fetch);
                if (ret < 0)
                {
                        LOG_ERROR("Failed to store transaction");
                        goto error;
                }
                LOG_INFO("Transaction stored successfully");
        }
        else if (transaction->type == CONFIG_APPLICATION)
        {
                LOG_DEBUG("Application configuration, no need to store");
        }
        else
        {
                LOG_ERROR("Invalid configuration type");
                goto error;
        }
        LOG_INFO("commit update via config.json");
        if ((ret = commit_update(transaction->context, transaction->type, transaction->to_fetch)) < 0)
        {
                LOG_ERROR("Failed to commit update");
                goto error;
        }
        LOG_INFO("Update committed successfully");

        // Update successful
        pthread_mutex_lock(&transaction->mutex);
        transaction->state = TRANSACTION_COMMITTED;
        pthread_mutex_unlock(&transaction->mutex);

        // Call notify callback if available
        if (transaction->notify)
        {
                transaction->notify(TRANSACTION_COMMITTED, transaction->to_fetch);
        }

cleanup:
        if (new_config)
        {
                free(new_config);
        }
        
        // Release the global transaction lock
        pthread_mutex_lock(&global_transaction_lock);
        transaction_in_progress = false;
        pthread_mutex_unlock(&global_transaction_lock);
        
        // Don't free the transaction as it may be allocated on the stack
        return NULL;

error:
        pthread_mutex_lock(&transaction->mutex);
        transaction->state = TRANSACTION_FAILED;
        pthread_mutex_unlock(&transaction->mutex);

        if (transaction->notify)
        {
                transaction->notify(TRANSACTION_FAILED, transaction->to_fetch);
        }

        goto cleanup;
}

int init_config_transaction(
        struct config_transaction* transaction,
        enum CONFIG_TYPE type,
        void* context,                     // defines how to reach out to the server
        void* to_fetch,                    // defines the return value
        config_fetch_callback fetch,       // defines the function to fetch the config
        config_validate_callback validate, // defines the function to validate the config
        config_notify_callback notify // defines the function to notify the caller of the transaction
)
{
        if (!transaction || !fetch || !validate)
        {
                LOG_ERROR("Invalid transaction parameters");
                return -1;
        }

        LOG_DEBUG("Init transaction: fetch=%p, validate=%p, notify=%p", fetch, validate, notify);

        memset(transaction, 0, sizeof(struct config_transaction));
        transaction->type = type;
        transaction->context = context;
        transaction->to_fetch = to_fetch;
        transaction->fetch = fetch;
        transaction->validate = validate;
        transaction->notify = notify;
        transaction->state = TRANSACTION_IDLE;
        transaction->thread_running = false;

        LOG_DEBUG("After init: transaction->fetch=%p", transaction->fetch);

        if (pthread_mutex_init(&transaction->mutex, NULL) != 0)
        {
                LOG_ERROR("Failed to initialize mutex");
                return -1;
        }

        if (pthread_cond_init(&transaction->cond, NULL) != 0)
        {
                LOG_ERROR("Failed to initialize condition variable");
                pthread_mutex_destroy(&transaction->mutex);
                return -1;
        }

        return 0;
}

int start_config_transaction(struct config_transaction* transaction)
{
        if (!transaction)
        {
                LOG_ERROR("Invalid transaction");
                return -1;
        }

        // Try to acquire the global transaction lock
        if (pthread_mutex_lock(&global_transaction_lock) != 0) {
                LOG_ERROR("Failed to lock global transaction mutex");
                return -1;
        }

        // Check if another transaction is already in progress
        if (transaction_in_progress) {
                LOG_WARN("Another transaction (%s) is already in progress. Cannot start new %s",
                         strr_transactiontype(active_transaction_type), 
                         strr_transactiontype(transaction->type));
                pthread_mutex_unlock(&global_transaction_lock);
                return -2; // Special return code for "transaction already in progress"
        }

        // Mark that we now have an active transaction
        transaction_in_progress = true;
        active_transaction_type = transaction->type;
        pthread_mutex_unlock(&global_transaction_lock);

        pthread_mutex_lock(&transaction->mutex);
        if (transaction->thread_running)
        {
                pthread_mutex_unlock(&transaction->mutex);
                // Release the global transaction lock if we can't start
                pthread_mutex_lock(&global_transaction_lock);
                transaction_in_progress = false;
                pthread_mutex_unlock(&global_transaction_lock);
                LOG_ERROR("Transaction already running");
                return -1;
        }

        transaction->thread_running = true;
        pthread_mutex_unlock(&transaction->mutex);

        if (pthread_create(&transaction->worker_thread, NULL, transaction_worker, transaction) != 0)
        {
                LOG_ERROR("Failed to create worker thread");
                pthread_mutex_lock(&transaction->mutex);
                transaction->thread_running = false;
                pthread_mutex_unlock(&transaction->mutex);
                // Release the global transaction lock if we failed to start
                pthread_mutex_lock(&global_transaction_lock);
                transaction_in_progress = false;
                pthread_mutex_unlock(&global_transaction_lock);
                return -1;
        }

        return 0;
}

int cancel_config_transaction(struct config_transaction* transaction)
{
        if (!transaction)
        {
                LOG_ERROR("Invalid transaction");
                return -1;
        }

        pthread_mutex_lock(&transaction->mutex);
        if (!transaction->thread_running)
        {
                pthread_mutex_unlock(&transaction->mutex);
                return 0;
        }

        // Signal the thread to stop
        transaction->thread_running = false;
        pthread_cond_signal(&transaction->cond);
        pthread_mutex_unlock(&transaction->mutex);

        // Wait for thread to finish
        pthread_join(transaction->worker_thread, NULL);

        // Release the global transaction lock
        pthread_mutex_lock(&global_transaction_lock);
        transaction_in_progress = false;
        pthread_mutex_unlock(&global_transaction_lock);

        return 0;
}

void cleanup_config_transaction(struct config_transaction* transaction)
{
        if (!transaction)
        {
                return;
        }

        // Cancel if still running
        cancel_config_transaction(transaction);

        pthread_mutex_destroy(&transaction->mutex);
        pthread_cond_destroy(&transaction->cond);
        if (transaction)
        {
                free(transaction);
        }
}

/**
 * @brief Creates a deep copy of hardware_configs structure
 *
 * @param src The source hardware_configs structure to copy
 * @return struct hardware_configs* A newly allocated deep copy, or NULL on failure
 */
struct hardware_configs* deep_copy_hardware_configs(const struct hardware_configs* src)
{
        if (!src)
        {
                LOG_ERROR("Invalid source hardware_configs");
                return NULL;
        }

        struct hardware_configs* dest = malloc(sizeof(struct hardware_configs));
        if (!dest)
        {
                LOG_ERROR("Failed to allocate memory for hardware_configs");
                return NULL;
        }

        // Initialize with zeros
        memset(dest, 0, sizeof(struct hardware_configs));

        // Copy number of configs
        dest->number_of_hw_configs = src->number_of_hw_configs;

        if (src->number_of_hw_configs > 0 && src->hw_configs)
        {
                // Allocate memory for hw_configs array
                dest->hw_configs = malloc(src->number_of_hw_configs * sizeof(HardwareConfiguration));
                if (!dest->hw_configs)
                {
                        LOG_ERROR("Failed to allocate memory for hw_configs array");
                        free(dest);
                        return NULL;
                }

                // Copy each hardware configuration
                for (int i = 0; i < src->number_of_hw_configs; i++)
                {
                        memcpy(&dest->hw_configs[i], &src->hw_configs[i], sizeof(HardwareConfiguration));
                }
        }

        return dest;
}

/**
 * @brief Creates a deep copy of application_manager_config structure
 *
 * @param src The source application_manager_config structure to copy
 * @return struct application_manager_config* A newly allocated deep copy, or NULL on failure
 */
struct application_manager_config*
        deep_copy_application_config(const struct application_manager_config* src)
{
        if (!src)
        {
                LOG_ERROR("Invalid source application_config");
                return NULL;
        }

        struct application_manager_config* dest = malloc(sizeof(struct application_manager_config));
        if (!dest)
        {
                LOG_ERROR("Failed to allocate memory for application_manager_config");
                return NULL;
        }

        // Initialize with zeros
        memset(dest, 0, sizeof(struct application_manager_config));

        // Copy number of groups
        dest->number_of_groups = src->number_of_groups;

        if (src->number_of_groups > 0 && src->group_config)
        {
                // Allocate memory for group_config array
                dest->group_config = malloc(src->number_of_groups * sizeof(struct group_config));
                if (!dest->group_config)
                {
                        LOG_ERROR("Failed to allocate memory for group_config array");
                        free(dest);
                        return NULL;
                }

                // Initialize group_config array with zeros
                memset(dest->group_config, 0, src->number_of_groups * sizeof(struct group_config));

                // Copy each group configuration
                for (int i = 0; i < src->number_of_groups; i++)
                {
                        // Copy number of proxies
                        dest->group_config[i].number_proxies = src->group_config[i].number_proxies;

                        // Copy endpoint configuration if it exists
                        if (src->group_config[i].endpoint_config)
                        {
                                dest->group_config[i].endpoint_config = malloc(
                                        sizeof(asl_endpoint_configuration));
                                if (!dest->group_config[i].endpoint_config)
                                {
                                        LOG_ERROR("Failed to allocate memory for "
                                                  "endpoint_config");
                                        cleanup_application_config(dest);
                                        free(dest);
                                        return NULL;
                                }

                                // Copy the main endpoint structure
                                memcpy(dest->group_config[i].endpoint_config,
                                       src->group_config[i].endpoint_config,
                                       sizeof(asl_endpoint_configuration));

                                // Now handle the dynamically allocated members of endpoint_config
                                if (src->group_config[i].endpoint_config->ciphersuites)
                                {
                                        dest->group_config[i].endpoint_config->ciphersuites = duplicate_string(
                                                src->group_config[i].endpoint_config->ciphersuites);
                                }

                                if (src->group_config[i].endpoint_config->keylog_file)
                                {
                                        dest->group_config[i].endpoint_config->keylog_file = duplicate_string(
                                                src->group_config[i].endpoint_config->keylog_file);
                                }else{
                                        dest->group_config[i].endpoint_config->keylog_file = NULL;
                                }

                                // Deep copy device certificate chain buffer
                                if (src->group_config[i].endpoint_config->device_certificate_chain.buffer &&
                                    src->group_config[i].endpoint_config->device_certificate_chain.size >
                                            0)
                                {
                                        uint8_t* new_buffer = malloc(
                                                src->group_config[i]
                                                        .endpoint_config->device_certificate_chain.size);
                                        if (!new_buffer)
                                        {
                                                LOG_ERROR("Failed to allocate memory for "
                                                          "device_certificate_chain buffer");
                                                cleanup_application_config(dest);
                                                free(dest);
                                                return NULL;
                                        }

                                        memcpy(new_buffer,
                                               src->group_config[i]
                                                       .endpoint_config->device_certificate_chain.buffer,
                                               src->group_config[i]
                                                       .endpoint_config->device_certificate_chain.size);

                                        dest->group_config[i]
                                                .endpoint_config->device_certificate_chain.buffer = new_buffer;
                                        dest->group_config[i]
                                                .endpoint_config->device_certificate_chain
                                                .size = src->group_config[i]
                                                                .endpoint_config
                                                                ->device_certificate_chain.size;
                                }

                                // Deep copy root certificate buffer
                                if (src->group_config[i].endpoint_config->root_certificate.buffer &&
                                    src->group_config[i].endpoint_config->root_certificate.size > 0)
                                {
                                        uint8_t* new_buffer = malloc(
                                                src->group_config[i]
                                                        .endpoint_config->root_certificate.size);
                                        if (!new_buffer)
                                        {
                                                LOG_ERROR("Failed to allocate memory for "
                                                          "root_certificate buffer");
                                                cleanup_application_config(dest);
                                                free(dest);
                                                return NULL;
                                        }

                                        memcpy(new_buffer,
                                               src->group_config[i]
                                                       .endpoint_config->root_certificate.buffer,
                                               src->group_config[i]
                                                       .endpoint_config->root_certificate.size);

                                        dest->group_config[i].endpoint_config->root_certificate.buffer = new_buffer;
                                        dest->group_config[i]
                                                .endpoint_config->root_certificate
                                                .size = src->group_config[i]
                                                                .endpoint_config->root_certificate.size;
                                }

                                // Deep copy private key buffer
                                if (src->group_config[i].endpoint_config->private_key.buffer &&
                                    src->group_config[i].endpoint_config->private_key.size > 0)
                                {
                                        uint8_t* new_buffer = malloc(
                                                src->group_config[i].endpoint_config->private_key.size);
                                        if (!new_buffer)
                                        {
                                                LOG_ERROR("Failed to allocate memory for "
                                                          "private_key buffer");
                                                cleanup_application_config(dest);
                                                free(dest);
                                                return NULL;
                                        }

                                        memcpy(new_buffer,
                                               src->group_config[i].endpoint_config->private_key.buffer,
                                               src->group_config[i].endpoint_config->private_key.size);

                                        dest->group_config[i].endpoint_config->private_key.buffer = new_buffer;
                                        dest->group_config[i]
                                                .endpoint_config->private_key
                                                .size = src->group_config[i]
                                                                .endpoint_config->private_key.size;
                                }
                                if (src->group_config[i].endpoint_config->private_key.additional_key_buffer){
                                        uint8_t* new_buffer = malloc(
                                                src->group_config[i].endpoint_config->private_key.additional_key_size);
                                        if (!new_buffer)
                                        {
                                                LOG_ERROR("Failed to allocate memory for "
                                                          "private_key_additonal_buffer");
                                                cleanup_application_config(dest);
                                                free(dest);
                                                return NULL;
                                        }

                                        memcpy(new_buffer,
                                               src->group_config[i].endpoint_config->private_key.additional_key_buffer,
                                               src->group_config[i].endpoint_config->private_key.additional_key_size);

                                        dest->group_config[i].endpoint_config->private_key.additional_key_buffer = new_buffer;
                                        dest->group_config[i]
                                                .endpoint_config->private_key
                                                .additional_key_size = src->group_config[i]
                                                                .endpoint_config->private_key.additional_key_size;
                                }
                        }

                        // Copy proxy_wrapper array if it exists
                        if (src->group_config[i].number_proxies > 0 && src->group_config[i].proxy_wrapper)
                        {
                                dest->group_config[i].proxy_wrapper = malloc(
                                        src->group_config[i].number_proxies *
                                        sizeof(struct proxy_wrapper));

                                if (!dest->group_config[i].proxy_wrapper)
                                {
                                        LOG_ERROR("Failed to allocate memory for "
                                                  "proxy_wrapper "
                                                  "array");
                                        cleanup_application_config(dest);
                                        free(dest);
                                        return NULL;
                                }

                                // Copy each proxy wrapper
                                for (int j = 0; j < src->group_config[i].number_proxies; j++)
                                {
                                        // Copy basic fields
                                        dest->group_config[i]
                                                .proxy_wrapper[j]
                                                .proxy_id = src->group_config[i].proxy_wrapper[j].proxy_id;
                                        dest->group_config[i]
                                                .proxy_wrapper[j]
                                                .direction = src->group_config[i].proxy_wrapper[j].direction;

                                        // Copy proxy config
                                        memcpy(&dest->group_config[i].proxy_wrapper[j].proxy_config,
                                               &src->group_config[i].proxy_wrapper[j].proxy_config,
                                               sizeof(proxy_config));

                                        // Deep copy own_ip_address
                                        if (src->group_config[i].proxy_wrapper[j].proxy_config.own_ip_address)
                                        {
                                                dest->group_config[i]
                                                        .proxy_wrapper[j]
                                                        .proxy_config.own_ip_address = duplicate_string(
                                                        src->group_config[i]
                                                                .proxy_wrapper[j]
                                                                .proxy_config.own_ip_address);
                                        }

                                        // Deep copy target_ip_address
                                        if (src->group_config[i].proxy_wrapper[j].proxy_config.target_ip_address)
                                        {
                                                dest->group_config[i]
                                                        .proxy_wrapper[j]
                                                        .proxy_config.target_ip_address = duplicate_string(
                                                        src->group_config[i]
                                                                .proxy_wrapper[j]
                                                                .proxy_config.target_ip_address);
                                        }

                                        // Deep copy name
                                        if (src->group_config[i].proxy_wrapper[j].name)
                                        {
                                                dest->group_config[i].proxy_wrapper[j].name = duplicate_string(
                                                        src->group_config[i].proxy_wrapper[j].name);
                                        }
                                }
                        }
                }
        }

        return dest;
}

char const* get_algorithm(char* algo)
{
        if (strcmp(algo, RSA2048) == 0)
        {
                return RSA2048;
        }
        else if (strcmp(algo, RSA3072) == 0)
        {
                return RSA3072;
        }
        else if (strcmp(algo, RSA4096) == 0)
        {
                return RSA4096;
        }
        else if (strcmp(algo, SECP256) == 0)
        {
                return SECP256;
        }
        else if (strcmp(algo, SECP384) == 0)
        {
                return SECP384;
        }
        else if (strcmp(algo, SECP521) == 0)
        {
                return SECP521;
        }
        else if (strcmp(algo, ED25519) == 0)
        {
                return ED25519;
        }
        else if (strcmp(algo, ED448) == 0)
        {
                return ED448;
        }
        else if (strcmp(algo, MLDSA44) == 0)
        {
                return MLDSA44;
        }
        else if (strcmp(algo, MLDSA65) == 0)
        {
                return MLDSA65;
        }
        else if (strcmp(algo, MLDSA87) == 0)
        {
                return MLDSA87;
        }
        else if (strcmp(algo, FALCON512) == 0)
        {
                return FALCON512;
        }
        else if (strcmp(algo, FALCON102) == 0)
        {
                return FALCON102;
        }
        return NULL;
}

// Add a new function to check if a transaction is in progress
bool is_transaction_in_progress()
{
        bool result;
        pthread_mutex_lock(&global_transaction_lock);
        result = transaction_in_progress;
        pthread_mutex_unlock(&global_transaction_lock);
        return result;
}