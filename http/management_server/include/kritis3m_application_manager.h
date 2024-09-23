#ifndef KRITIS3M_APPLICATION_MANAGER_H
#define KRITIS3M_APPLICATION_MANAGER_H
#include "poll_set.h"

#include "kritis3m_configuration.h"
/***
 * includes threading
 */

int start_applications(struct SystemConfiguration* configuration);
int stop_applications();


#endif  //KRITIS3M_APPLICATION_MANAGER_H