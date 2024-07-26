#include "kritis3m_application_manager.h"
#include <sys/socket.h>
static struct kritis3m_application_manager = {0};

#include "logging.h"

// kritis3m applications:
#include "proxy.h"
#include "tcp_echo_server.h"
#include "tcp_client_stdin_bridge.h"
#include "l2_bridge.h"
// end kritis3m applications

int start_standard_application(struct SystemConfiguration *configuration)
{
    for (int i = 0; i < configuration->standard_applications; i++)
    {
        switch (configuration->standard_applications[i].application_type)
        {
        case STD_IN_BRIDGE:
         struct tcp_client_stdin_bridge_config config;
         config.target_ip_address = configuration->standard_applications[i].target_ip_port;
         config.target_port = configuration->standard_applications[i].target_port;
{
        char const* target_ip_address;
        uint16_t target_port;
}
            break;
        case ECHO_TCP_SERVER:
            break;
        case ECHO_UDP_SERVER
            LOG_INFO("Not implemented yet");
            break;

            default:
            break;
        }
    }
    return 0;
}

int start_proxy_applications(struct SystemConfiguration *configuration)
{
    return 0;
}

void manage(SystemConfiguration *configuration)
{

    // start standard application

    // start proxyies
}