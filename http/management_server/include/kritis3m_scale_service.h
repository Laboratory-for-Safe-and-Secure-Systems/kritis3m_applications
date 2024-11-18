#ifndef KRITIS3M_SCALE_SERVICE_H
#define KRITIS3M_SCALE_SERVICE_H

#include <netinet/in.h>
#include "kritis3m_configuration.h"
#include "hb_service.h"
#include <stdio.h>
#include <string.h>

/*********************************************************
 *              MANAGEMENT SERVICE STARTUP
 */

typedef struct kritis3m_service kritis3m_service;
struct kritis3m_service;

int init_kritis3m_service(char *config_file);

/*********************************************************
 *              CONFIGURATION DISTRIBUTION
 */


enum ManagementEvents
{
    MGMT_EV_ERROR,
    MGMT_EV_START,
    MGMT_EV_INIT,
    MGMT_EV_MGM_RESP,
    MGMT_EV_CONFIG_AVAILABLE,
    MGMT_EV_PKI_RESP,
    MGMT_EV_HB_CLOCK_REQ,
    MGMT_EV_HB_RESP,
    MGMT_EV_CONFIG_COMPLETE,
    elems_ManagementEvent, // running application manager, during update process
};

enum request_type

{
    POLICY_GET,
    POLICY_POST,
    ENROLL_GET,
    HEARTBEAT_GET,
};

/**********************************************************
 *                      Hardbeat Service
 */

#endif // KRITIS3M_SCALE_SERVICE_H
