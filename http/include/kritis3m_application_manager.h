#ifndef KRITIS3M_APPLICATION_MANAGER_H
#define KRITIS3M_APPLICATION_MANAGER_H
#include "poll_set.h"

#include "kritis3m_configuration.h"

struct application_manager
{
    struct poll_set poll_set;
    int active_applications;

};


void init_application_manager(struct SystemConfiguration* configuration);
void manage(SystemConfiguration* configuration);
#endif  //KRITIS3M_APPLICATION_MANAGER_H