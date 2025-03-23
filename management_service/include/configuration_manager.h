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

struct group_config
{
        asl_endpoint_configuration* endpoint_config;
        int number_proxies;
        proxy_config proxy_config;
        int number_of_applications;
};

struct application_manager_config
{
        struct group_config* group_config;
        int number_of_groups;
};

const struct sysconfig* get_sysconfig();

int get_dataplane_update(struct application_manager_config* config, struct hardware_configs* hw_config);

int controlplane_set_certificate(char* buffer, size_t size);
int controlplane_store_config(char* buffer, size_t size);

#endif // CONFIGURATION_MANAGER_H