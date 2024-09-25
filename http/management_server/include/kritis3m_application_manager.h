#ifndef KRITIS3M_APPLICATION_MANAGER_H
#define KRITIS3M_APPLICATION_MANAGER_H
#include "poll_set.h"

#include "kritis3m_configuration.h"
/***
 * includes threading
 */

typedef struct application_manager_config
{
    int32_t log_level;
} application_manager_config;

int init_application_manager(application_manager_config *config);
int start_application_manager(ApplicationConfiguration *configuration);
int stop_application_manager();
int terminate_application_manager();

#endif // KRITIS3M_APPLICATION_MANAGER_H