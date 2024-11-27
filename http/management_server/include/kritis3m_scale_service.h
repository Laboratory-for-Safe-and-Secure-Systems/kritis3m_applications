#ifndef KRITIS3M_SCALE_SERVICE_H
#define KRITIS3M_SCALE_SERVICE_H

#include <netinet/in.h>
#include "kritis3m_configuration.h"
#include <stdio.h>
#include <string.h>

/*********************************************************
 *              MANAGEMENT SERVICE STARTUP
 */


typedef struct kritis3m_service kritis3m_service;
struct kritis3m_service;

int start_kritis3m_service(char *config_file);
int stop_kritis3m_service();



#endif // KRITIS3M_SCALE_SERVICE_H
