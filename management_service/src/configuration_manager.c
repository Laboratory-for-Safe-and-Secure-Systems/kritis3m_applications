#include "configuration_manager.h"
#include "configuration_parser.h"
#include "file_io.h"
#include "stdlib.h"
#include <stdio.h>
#include <string.h>

#define SYS_CONFIG_PATH_FORMAT "%s/sys_config.json"
#define CONTROLPLANE_KEY_PATH_FORMAT "%s/cert/controlplane_key.pem"
#define CONTROLPLANE_ROOT_CERT_FORMAT "%s/cert/controlplane_root_cert.pem"
#define CONTROLPLANE_1_CHAIN_PATH_FORMAT "%s/cert/1/controlplane_chain.pem"
#define CONTROLPLANE_2_CHAIN_PATH_FORMAT "%s/cert/2/controlplane_chain.pem"
#define DATAPLANE_KEY_PATH_FORMAT "%s/cert/dataplane_key.pem"
#define DATAPLANE_ROOT_CERT_FORMAT "%s/cert/dataplane_root_cert.pem"
#define DATAPLANE_1_CHAIN_PATH_FORMAT "%s/cert/1/dataplane_chain.pem"
#define DATAPLANE_2_CHAIN_PATH_FORMAT "%s/cert/2/dataplane_chain.pem"

#define APPLICATION_1_PATH_FORMAT "%s/application/1/application.json"
#define APPLICATION_2_PATH_FORMAT "%s/application/2/application.json"

// forward declaration
void cleanup_sysconfig();
void cleanup_endpoint_config(asl_endpoint_configuration* endpoint_config);

int load_certificates(asl_endpoint_configuration* endpoint_config,
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

int init_configuration_manager(char* base_path)
{
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

        ret = read_file(configuration_manager.sys_config_path,
                        &configuration_manager.sys_config,
                        sizeof(configuration_manager.sys_config));
        if (ret != 0)
        {
                LOG_ERROR("Failed to read sys_config");
                goto error;
        }
        // parse
        ret = parse_buffer_to_sysconfig(configuration_manager.sys_config_path,
                                        sizeof(configuration_manager.sys_config),
                                        &configuration_manager.sys_config);
        if (ret != 0)
        {
                LOG_ERROR("Failed to parse sys_config");
                goto error;
        }

        switch (configuration_manager.sys_config.controlplane_active)
        {
        case ACTIVE_ONE:
                load_certificates(&configuration_manager.sys_config.endpoint_config,
                                  configuration_manager.controlplane_1_chain_path,
                                  configuration_manager.controlplane_key_path,
                                  configuration_manager.controlplane_root_cert);
                break;
        case ACTIVE_TWO:
                load_certificates(&configuration_manager.sys_config.endpoint_config,
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
        return 0;

error:
        cleanup_configuration_manager();
        return -1;
}

int load_certificates(asl_endpoint_configuration* endpoint_config,
                      char* chain_path,
                      char* key_path,
                      char* root_path)
{
        if (!endpoint_config)
        {
                return -1;
        }

        // Check if controlplane is active
        if (configuration_manager.sys_config.controlplane_active == ACTIVE_NONE)
        {
                LOG_ERROR("No active controlplane configuration");
                return -1;
        }

        // Load the certificate chain
        if (read_file(chain_path,
                      &endpoint_config->device_certificate_chain.buffer,
                      &endpoint_config->device_certificate_chain.size) != 0)
        {
                LOG_ERROR("Failed to load controlplane certificate chain");
                return -1;
        }

        // Load the private key
        if (read_file(key_path,
                      &endpoint_config->private_key.buffer,
                      &endpoint_config->private_key.size) != 0)
        {
                LOG_ERROR("Failed to load controlplane private key");
                return -1;
        }

        // Load the root certificate
        if (read_file(root_path,
                      &endpoint_config->root_certificate.buffer,
                      &endpoint_config->root_certificate.size) != 0)
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
