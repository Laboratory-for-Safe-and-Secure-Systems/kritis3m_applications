#ifndef KRITIS3M_APPLICATION_MANAGER_H
#define KRITIS3M_APPLICATION_MANAGER_H

#include "kritis3m_configuration.h"

#include "tls_proxy.h"
#include "tcp_echo_server.h"
// #include "tcp_client_stdin_bridge.h"
#include "poll_set.h"



struct application_manager
{
    struct poll_set poll_set;
    int active_applications;

};


void init_application_manager(struct SystemConfiguration* configuration);
void manage(SystemConfiguration* configuration);
#endif  //KRITIS3M_APPLICATION_MANAGER_H