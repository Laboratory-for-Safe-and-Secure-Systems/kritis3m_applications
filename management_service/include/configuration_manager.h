#ifndef CONFIGURATION_MANAGER_H
#define CONFIGURATION_MANAGER_H

#include "asl.h"
#include "kritis3m_configuration.h"

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
        int broker_port;

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
void* worker_controlplane_set_certificate(void*);

#endif // CONFIGURATION_MANAGER_H