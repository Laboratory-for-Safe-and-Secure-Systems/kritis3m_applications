#include "configuration_manager.h"
#include "configuration_parser.h"
#include "file_io.h"
#include "logging.h"
#include "networking.h"
#include <complex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

LOG_MODULE_CREATE(configuration_manager);

#define SYS_CONFIG_PATH_FORMAT "%s/sys_config.json"
#define CONTROLPLANE_KEY_PATH_FORMAT "%s/cert/controlplane_key.pem"
#define CONTROLPLANE_ROOT_CERT_FORMAT "%s/cert/controlplane_root_cert.pem"
#define CONTROLPLANE_1_CHAIN_PATH_FORMAT "%s/cert/1/controlplane_chain.pem"
#define CONTROLPLANE_2_CHAIN_PATH_FORMAT "%s/cert/2/controlplane_chain.pem"

#define DATAPLANE_KEY_PATH_FORMAT CONTROLPLANE_KEY_PATH_FORMAT   //"%s/cert/dataplane_key.pem"
#define DATAPLANE_ROOT_CERT_FORMAT CONTROLPLANE_ROOT_CERT_FORMAT //"%s/cert/dataplane_root_cert.pem"

// for testing purposes
#define DATAPLANE_1_CHAIN_PATH_FORMAT                                                              \
        CONTROLPLANE_1_CHAIN_PATH_FORMAT //"%s/cert/1/dataplane_chain.pem"
#define DATAPLANE_2_CHAIN_PATH_FORMAT                                                              \
        CONTROLPLANE_2_CHAIN_PATH_FORMAT //"%s/cert/2/dataplane_chain.pem"

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
                               char* root_path);

struct configuration_manager
{
        bool initialized;
        char* sys_config_path;

        struct sysconfig sys_config;

        char* controlplane_key_path;
        char* controlplane_root_cert;

        char* controlplane_1_chain_path;
        char* controlplane_2_chain_path;

        // dataplane
        char* dataplane_key_path;
        char* dataplane_root_cert;

        char* dataplane_1_chain_path;
        char* dataplane_2_chain_path;

        // application
        char* application_1_path;
        char* application_2_path;
};

static struct configuration_manager configuration_manager = {0};

const struct sysconfig* get_sysconfig()
{
        return (const struct sysconfig*) &configuration_manager.sys_config;
}

int ack_dataplane_update()
{
        if (!configuration_manager.initialized)
        {
                LOG_ERROR("Configuration manager not initialized");
                return -1;
        }
        switch (configuration_manager.sys_config.application_active)
        {
        case ACTIVE_ONE:
                configuration_manager.sys_config.application_active = ACTIVE_TWO;
                break;
        case ACTIVE_TWO:
                configuration_manager.sys_config.application_active = ACTIVE_ONE;
                break;
        case ACTIVE_NONE:
                LOG_ERROR("No active application configuration");
                return -1;
        }

        write_sysconfig();

        return 0;
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
                case ACTIVE_ONE:
                        chain_path = configuration_manager.dataplane_1_chain_path;
                        break;
                case ACTIVE_TWO:
                        chain_path = configuration_manager.dataplane_2_chain_path;
                        break;
                case ACTIVE_NONE:
                        LOG_INFO("No active dataplane configuration is set, using "
                                 "dataplane_1_chain_path as default");
                        chain_path = configuration_manager.dataplane_1_chain_path;
                        break;
                default:
                        LOG_ERROR("Invalid dataplane active configuration");
                        free(buffer);
                        return -1;
                }

                // Load certificates into this endpoint configuration
                ret = load_endpoint_certificates(config->group_config[i].endpoint_config,
                                                 chain_path,
                                                 configuration_manager.dataplane_key_path,
                                                 configuration_manager.dataplane_root_cert);
                if (ret != 0)
                {
                        LOG_ERROR("Failed to load certificates for group %d", i);
                        free(buffer);
                        return -1;
                }

                LOG_INFO("Successfully loaded certificates for group %d", i);
        }

        LOG_INFO("Successfully loaded application configuration from %s", source_path);
        free(buffer);
        return 0;
}

// store config
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
        char* buffer = NULL;
        memset(&configuration_manager, 0, sizeof(struct configuration_manager));

        char helper_string[300];
        int ret = 0;

        // sysconfig
        int len = snprintf(helper_string, 300, SYS_CONFIG_PATH_FORMAT, base_path);
        configuration_manager.sys_config_path = duplicate_string(helper_string);

        // controlplane
        len = snprintf(helper_string, 300, CONTROLPLANE_KEY_PATH_FORMAT, base_path);
        configuration_manager.controlplane_key_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, CONTROLPLANE_ROOT_CERT_FORMAT, base_path);
        configuration_manager.controlplane_root_cert = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, CONTROLPLANE_1_CHAIN_PATH_FORMAT, base_path);
        configuration_manager.controlplane_1_chain_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, CONTROLPLANE_2_CHAIN_PATH_FORMAT, base_path);
        configuration_manager.controlplane_2_chain_path = duplicate_string(helper_string);

        // dataplane
        len = snprintf(helper_string, 300, DATAPLANE_KEY_PATH_FORMAT, base_path);
        configuration_manager.dataplane_key_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, DATAPLANE_ROOT_CERT_FORMAT, base_path);
        configuration_manager.dataplane_root_cert = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, DATAPLANE_1_CHAIN_PATH_FORMAT, base_path);
        configuration_manager.dataplane_1_chain_path = duplicate_string(helper_string);

        len = snprintf(helper_string, 300, DATAPLANE_2_CHAIN_PATH_FORMAT, base_path);
        configuration_manager.dataplane_2_chain_path = duplicate_string(helper_string);

        // application
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
        // parse
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
                                                 configuration_manager.controlplane_key_path,
                                                 configuration_manager.controlplane_root_cert);
                break;
        case ACTIVE_TWO:
                ret = load_endpoint_certificates(configuration_manager.sys_config.endpoint_config,
                                                 configuration_manager.controlplane_2_chain_path,
                                                 configuration_manager.controlplane_key_path,
                                                 configuration_manager.controlplane_root_cert);
                break;
        case ACTIVE_NONE:
                LOG_INFO("No active controlplane certs");
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

int init_config_update(struct config_update* update, enum CONFIG_TYPE type, char* config, size_t size)
{
        if (!update || !config || size == 0)
        {
                LOG_ERROR("Invalid update parameters");
                return -1;
        }

        update->type = type;
        update->new_config = config;
        update->config_size = size;
        update->validation_callback = NULL;
        update->validation_context = NULL;

        switch (type)
        {
        case CONFIG_APPLICATION:
                update->active_path = &configuration_manager.sys_config.application_active;
                // hacky workaround since application data is sent via a push msg and is not directly requested
                update->path_1 = NULL;
                update->path_2 = NULL;
                break;
        case CONFIG_DATAPLANE:
                update->active_path = &configuration_manager.sys_config.dataplane_cert_active;
                update->path_1 = configuration_manager.dataplane_1_chain_path;
                update->path_2 = configuration_manager.dataplane_2_chain_path;
                break;
        case CONFIG_CONTROLPLANE:
                update->active_path = &configuration_manager.sys_config.controlplane_cert_active;
                update->path_1 = configuration_manager.controlplane_1_chain_path;
                update->path_2 = configuration_manager.controlplane_2_chain_path;
                break;
        default:
                LOG_ERROR("Invalid config type");
                return -1;
        }

        return 0;
}

int prepare_config_update(struct config_update* update)
{
        int ret = 0;
        char* target_path = NULL;
        if (!update || !configuration_manager.initialized)
        {
                LOG_ERROR("Invalid update or configuration manager not initialized");
                return -1;
        }

        if (update->type != CONFIG_APPLICATION)
        {
                switch (*update->active_path)
                {
                case ACTIVE_ONE:
                        target_path = update->path_1;
                        break;
                case ACTIVE_TWO:
                        target_path = update->path_2;
                        break;
                case ACTIVE_NONE:
                        break;
                default:
                        target_path = NULL;
                        LOG_ERROR("Invalid active path");
                        return -1;
                }
                if ((ret = write_file(target_path,
                                      (const uint8_t*) update->new_config,
                                      update->config_size,
                                      false)) < 0)
                {
                        LOG_ERROR("Failed to write configuration to %s", target_path);
                        return -1;
                }
        }

        return 0;
}

int commit_config_update(struct config_update* update)
{
        int ret = 0;
        char* target_path = NULL;
        if (!update || !configuration_manager.initialized)
        {
                LOG_ERROR("Invalid update or configuration manager not initialized");
                return -1;
        }

        switch (*update->active_path)
        {
        case ACTIVE_ONE:
                *update->active_path = ACTIVE_TWO;
                break;
        case ACTIVE_TWO:
                *update->active_path = ACTIVE_ONE;
                break;
        case ACTIVE_NONE:
                *update->active_path = ACTIVE_ONE;
                break;
        default:
                LOG_ERROR("Invalid active path");
                return -1;
        }
        return write_sysconfig();
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

int dataplane_set_certificate(char* buffer, size_t size)
{
        if (!buffer || size == 0 || !configuration_manager.initialized)
        {
                LOG_ERROR("Invalid buffer or size");
                return -1;
        }
        char* destination = NULL;
        asl_endpoint_configuration* endpoint_config = malloc(sizeof(asl_endpoint_configuration));
        if (!endpoint_config)
        {
                LOG_ERROR("Failed to allocate memory for endpoint configuration");
                goto error;
        }
        int ret = 0;

        switch (configuration_manager.sys_config.dataplane_cert_active)
        {
        case ACTIVE_ONE:
                destination = configuration_manager.application_2_path;
                break;
        case ACTIVE_TWO:
                destination = configuration_manager.application_1_path;
                break;
        case ACTIVE_NONE:
                LOG_INFO("No active dataplane configuration is set, using 1 as default");
                destination = configuration_manager.application_1_path;
                break;
        default:
                LOG_ERROR("Invalid dataplane active configuration");
                goto error;
        }
        if (!destination)
        {
                goto error;
        }

        // store certificates in file
        ret = write_file(destination, (const uint8_t*) buffer, size, false);
        if (ret != 0)
        {
                LOG_ERROR("Failed to write controlplane certificate");
                goto error;
        }

        return 0;
error:
        return -1;
}

int controlplane_set_certificate(char* buffer, size_t size)
{
        if (!buffer || size == 0 || !configuration_manager.initialized)
        {
                LOG_ERROR("Invalid buffer or size");
                return -1;
        }
        char* destination = NULL;
        asl_endpoint_configuration* endpoint_config = malloc(sizeof(asl_endpoint_configuration));
        if (!endpoint_config)
        {
                LOG_ERROR("Failed to allocate memory for endpoint configuration");
                goto error;
        }
        int ret = 0;

        switch (configuration_manager.sys_config.controlplane_cert_active)
        {
        case ACTIVE_ONE:
                destination = configuration_manager.controlplane_2_chain_path;
                break;
        case ACTIVE_TWO:
                destination = configuration_manager.controlplane_1_chain_path;
                break;
        case ACTIVE_NONE:
                LOG_INFO("No active controlplane configuration is set, using 1 as default");
                destination = configuration_manager.controlplane_1_chain_path;
                break;
        default:
                LOG_ERROR("Invalid controlplane active configuration");
                goto error;
        }
        if (!destination)
        {
                goto error;
        }

        // store certificates in file
        ret = write_file(destination, (const uint8_t*) buffer, size, false);
        if (ret != 0)
        {
                LOG_ERROR("Failed to write controlplane certificate");
                goto error;
        }

        memcpy(endpoint_config,
               configuration_manager.sys_config.endpoint_config,
               sizeof(asl_endpoint_configuration));

        ret = load_endpoint_certificates(endpoint_config,
                                         destination,
                                         configuration_manager.controlplane_key_path,
                                         configuration_manager.controlplane_root_cert);
        if (ret != 0)
        {
                LOG_ERROR("Failed to load controlplane certificate");
                goto error;
        }

        ret = test_server_conn(configuration_manager.sys_config.broker_host, endpoint_config);
        if (ret != 0)
        {
                LOG_ERROR("Failed to test controlplane certificate");
                goto error;
        }

        // we switchout endpointconfig, to make sure that the buffers are freed later
        asl_endpoint_configuration* old_endpoint_config = configuration_manager.sys_config.endpoint_config;
        configuration_manager.sys_config.endpoint_config = endpoint_config;
        endpoint_config = old_endpoint_config;

        LOG_INFO("Controlplane certificate test successful");
        // switching to new certificate
        switch (configuration_manager.sys_config.controlplane_cert_active)
        {
        case ACTIVE_ONE:
                configuration_manager.sys_config.controlplane_cert_active = ACTIVE_TWO;
                break;
        case ACTIVE_TWO:
                configuration_manager.sys_config.controlplane_cert_active = ACTIVE_ONE;
                break;
        case ACTIVE_NONE:
                configuration_manager.sys_config.controlplane_cert_active = ACTIVE_ONE;
        default:
                LOG_ERROR("Invalid controlplane active configuration");
                goto error;
        }
        ret = write_sysconfig();
        if (ret != 0)
        {
                LOG_ERROR("Failed to write sysconfig");
                goto error;
        }
        // notify kritis3m_scale service restart

        if (endpoint_config->root_certificate.buffer)
                free((void*) endpoint_config->root_certificate.buffer);
        if (endpoint_config->private_key.buffer)
                free((void*) endpoint_config->private_key.buffer);
        if (endpoint_config->device_certificate_chain.buffer)
                free((void*) endpoint_config->device_certificate_chain.buffer);
        free(endpoint_config);
        return 0;
error:
        if (endpoint_config->root_certificate.buffer)
                free((void*) endpoint_config->root_certificate.buffer);
        if (endpoint_config->private_key.buffer)
                free((void*) endpoint_config->private_key.buffer);
        if (endpoint_config->device_certificate_chain.buffer)
                free((void*) endpoint_config->device_certificate_chain.buffer);
        free(endpoint_config);
        return -1;
}
int load_endpoint_certificates(asl_endpoint_configuration* endpoint_config,
                               char* chain_path,
                               char* key_path,
                               char* root_path)
{
        if (!endpoint_config)
        {
                return -1;
        }

        // Check if controlplane is active
        if (configuration_manager.sys_config.controlplane_cert_active == ACTIVE_NONE)
        {
                LOG_ERROR("No active controlplane configuration");
                return -1;
        }

        // Load the certificate chain
        if (read_file(chain_path,
                      (uint8_t**) &endpoint_config->device_certificate_chain.buffer,
                      &endpoint_config->device_certificate_chain.size) < 0)
        {
                LOG_ERROR("Failed to load controlplane certificate chain");
                return -1;
        }

        // Load the private key
        if (read_file(key_path,
                      (uint8_t**) &endpoint_config->private_key.buffer,
                      &endpoint_config->private_key.size) < 0)
        {
                LOG_ERROR("Failed to load controlplane private key");
                return -1;
        }

        // Load the root certificate
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

        free(endpoint_config);
}

void cleanup_sysconfig()
{
        if (configuration_manager.sys_config.broker_host)
                free(configuration_manager.sys_config.broker_host);

        if (configuration_manager.sys_config.est_host)
                free(configuration_manager.sys_config.est_host);

        cleanup_endpoint_config(configuration_manager.sys_config.endpoint_config);
}

void cleanup_configuration_manager(void)
{

        // sysconfig
        if (configuration_manager.sys_config_path)
                free(configuration_manager.sys_config_path);

        // controlplane
        if (configuration_manager.controlplane_key_path)
                free(configuration_manager.controlplane_key_path);
        if (configuration_manager.controlplane_root_cert)
                free(configuration_manager.controlplane_root_cert);
        if (configuration_manager.controlplane_1_chain_path)
                free(configuration_manager.controlplane_1_chain_path);
        if (configuration_manager.controlplane_2_chain_path)
                free(configuration_manager.controlplane_2_chain_path);

        // dataplane
        if (configuration_manager.dataplane_key_path)
                free(configuration_manager.dataplane_key_path);
        if (configuration_manager.dataplane_root_cert)
                free(configuration_manager.dataplane_root_cert);
        if (configuration_manager.dataplane_1_chain_path)
                free(configuration_manager.dataplane_1_chain_path);
        if (configuration_manager.dataplane_2_chain_path)
                free(configuration_manager.dataplane_2_chain_path);

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

        // Now load certificates for each group's endpoint configuration
        for (int i = 0; i < app_config->number_of_groups; i++)
        {
                if (!app_config->group_config[i].endpoint_config)
                {
                        LOG_ERROR("Endpoint configuration missing for group %d", i);
                        free(buffer);
                        cleanup_application_config(app_config);
                        cleanup_hardware_configs(hw_configs);
                        return -1;
                }

                // Determine which dataplane certificate chain to use
                char* chain_path = NULL;
                switch (configuration_manager.sys_config.dataplane_cert_active)
                {
                case ACTIVE_ONE:
                        chain_path = configuration_manager.dataplane_1_chain_path;
                        break;
                case ACTIVE_TWO:
                        chain_path = configuration_manager.dataplane_2_chain_path;
                        break;
                case ACTIVE_NONE:
                        LOG_INFO("No active dataplane configuration is set, using "
                                 "dataplane_1_chain_path as default");
                        chain_path = configuration_manager.dataplane_1_chain_path;
                        break;
                default:
                        LOG_ERROR("Invalid dataplane active configuration");
                        free(buffer);
                        cleanup_application_config(app_config);
                        cleanup_hardware_configs(hw_configs);
                        return -1;
                }

                // Load certificates into this endpoint configuration
                ret = load_endpoint_certificates(app_config->group_config[i].endpoint_config,
                                                 chain_path,
                                                 configuration_manager.dataplane_key_path,
                                                 configuration_manager.dataplane_root_cert);
                if (ret != 0)
                {
                        LOG_ERROR("Failed to load certificates for group %d", i);
                        free(buffer);
                        cleanup_application_config(app_config);
                        cleanup_hardware_configs(hw_configs);
                        return -1;
                }

                LOG_INFO("Successfully loaded certificates for group %d", i);
        }

        LOG_INFO("Successfully loaded active hardware configuration from %s", source_path);
        free(buffer);
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
                                if (config->group_config[i].endpoint_config->ciphersuites)
                                        free((void*) config->group_config[i].endpoint_config->ciphersuites);
                                if (config->group_config[i].endpoint_config->keylog_file)
                                        free((void*) config->group_config[i].endpoint_config->keylog_file);
                                if (config->group_config[i]
                                            .endpoint_config->device_certificate_chain.buffer)
                                        free((void*) config->group_config[i]
                                                     .endpoint_config->device_certificate_chain.buffer);
                                if (config->group_config[i].endpoint_config->private_key.buffer)
                                        free((void*) config->group_config[i]
                                                     .endpoint_config->private_key.buffer);
                                if (config->group_config[i].endpoint_config->root_certificate.buffer)
                                        free((void*) config->group_config[i]
                                                     .endpoint_config->root_certificate.buffer);
                                free(config->group_config[i].endpoint_config);
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

int store_alt_data_cert(char* buffer, size_t size)
{
        if (!buffer || size == 0)
        {
                LOG_ERROR("Invalid buffer or size");
                return -1;
        }

        return 0;
}

// Worker thread function
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
        ret = transaction->fetch(transaction->context, &new_config, &config_size);
        if (ret != 0)
        {
                LOG_ERROR("Failed to fetch new configuration");
                goto error;
        }

        // Update state to validating
        pthread_mutex_lock(&transaction->mutex);
        transaction->state = TRANSACTION_VALIDATING;
        pthread_mutex_unlock(&transaction->mutex);

        // Validate new configuration
        ret = transaction->validate(transaction->context, new_config, config_size);
        if (ret != 0)
        {
                LOG_ERROR("Configuration validation failed");
                goto error;
        }
        LOG_INFO("Configuration validation successful");
        // Prepare update
        struct config_update update = {0};
        /**
         * control plane update is currently bit hacky, since there is no buffer
         * obtained from an http request, but the request is already obtained
         * from the filesystem
         * the current approach is to modify sysconfig accordingly
         * @TODO: fetch_dataplane_config could be modified to return a buffer, so that only validated configs are in mem
         */
        // hacky as well

        if (init_config_update(&update, transaction->type, new_config, config_size) != 0)
        {
                LOG_ERROR("Failed to initialize update");
                goto error;
        }
        if (prepare_config_update(&update) != 0)
        {
                LOG_ERROR("Failed to prepare update");
                goto error;
        }
        // Commit the update
        if (commit_config_update(&update) != 0)
        {
                LOG_ERROR("Failed to commit update");
                goto error;
        }
        // Update successful
        pthread_mutex_lock(&transaction->mutex);
        transaction->state = TRANSACTION_COMMITTED;
        pthread_mutex_unlock(&transaction->mutex);

        // Notify caller
        if (transaction->notify)
        {
                transaction->notify(transaction->context, TRANSACTION_COMMITTED);
        }

cleanup:
        if (new_config)
        {
                free(new_config);
        }
        if (transaction)
        {

                free(transaction);
                transaction = NULL;
        }
        return NULL;

error:
        pthread_mutex_lock(&transaction->mutex);
        transaction->state = TRANSACTION_FAILED;
        pthread_mutex_unlock(&transaction->mutex);

        if (transaction->notify)
        {
                transaction->notify(transaction->context, TRANSACTION_FAILED);
        }
        if (transaction)
        {

                free(transaction);
                transaction = NULL;
        }

        goto cleanup;
}

int init_config_transaction(struct config_transaction* transaction,
                            enum CONFIG_TYPE type,
                            void* context,
                            config_fetch_callback fetch,
                            config_validate_callback validate,
                            config_notify_callback notify)
{
        if (!transaction || !fetch || !validate)
        {
                LOG_ERROR("Invalid transaction parameters");
                return -1;
        }

        memset(transaction, 0, sizeof(struct config_transaction));
        transaction->type = type;
        transaction->context = context;
        transaction->fetch = fetch;
        transaction->validate = validate;
        transaction->notify = notify;
        transaction->state = TRANSACTION_IDLE;
        transaction->thread_running = false;

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

        pthread_mutex_lock(&transaction->mutex);
        if (transaction->thread_running)
        {
                pthread_mutex_unlock(&transaction->mutex);
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
}