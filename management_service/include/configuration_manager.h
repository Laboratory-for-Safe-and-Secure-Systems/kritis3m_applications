#ifndef CONFIGURATION_MANAGER_H
#define CONFIGURATION_MANAGER_H

#include "asl.h"
#include "kritis3m_configuration.h"
#include "tls_proxy.h"

int init_configuration_manager(char* base_path);

enum ACTIVE
{
        ACTIVE_NONE = 0,
        ACTIVE_ONE,
        ACTIVE_TWO,
};
enum PROXY_TYPE
{
        PROXY_UNSPECIFIC = 0,
        PROXY_FORWARD = 1,
        PROXY_REVERSE = 2,
        PROXY_TLS_TLS = 3,
};

struct sysconfig
{
        // controlplane
        char* serial_number;
        int log_level;

        enum ACTIVE controlplane_active;
        enum ACTIVE dataplane_active;
        enum ACTIVE application_active;

        char* broker_host;

        char* est_host;
        int est_port;
        asl_endpoint_configuration* endpoint_config;
};
struct worker_controlplane_set_certificate_args
{
        char* buffer;
        size_t size;
        void* arg;
};
struct hardware_configs
{
        HardwareConfiguration* hw_configs;
        int number_of_hw_configs;
};

struct proxy_wrapper
{
        char* name;
        proxy_config proxy_config;
        int direction;
};

struct group_config
{
        asl_endpoint_configuration* endpoint_config;
        int number_proxies;
        struct proxy_wrapper* proxy_wrapper;
};

struct application_manager_config
{
        struct group_config* group_config;
        int number_of_groups;
};

const struct sysconfig* get_sysconfig();

int get_application_inactive(struct application_manager_config* config,
                             struct hardware_configs* hw_config);
int ack_dataplane_update();

/**
 * @brief Reads hardware configuration based on the active dataplane configuration
 *
 * This function reads in the hardware configuration from either application_1_path or application_2_path
 * based on which dataplane configuration is active, and populates the provided structures.
 *
 * @param[out] app_config Pointer to application_manager_config structure to be populated
 * @param[out] hw_configs Pointer to hardware_configs structure to be populated
 * @return 0 on success, -1 on failure
 *
 * @note Both structures are allocated by this function and must be freed by the caller.
 *       In case of an error, any allocated memory is freed internally.
 */
int get_active_hardware_config(struct application_manager_config* app_config,
                               struct hardware_configs* hw_configs);

int dataplane_set_certificate(char* buffer, size_t size);
int controlplane_set_certificate(char* buffer, size_t size);
int application_store_inactive(char* buffer, size_t size);

int store_controlplane_certificate(char* buffer, size_t size);
int store_dataplane_certificate(char* buffer, size_t size);

void cleanup_application_config(struct application_manager_config* config);
void cleanup_hardware_configs(struct hardware_configs* hw_configs);

#endif // CONFIGURATION_MANAGER_H
