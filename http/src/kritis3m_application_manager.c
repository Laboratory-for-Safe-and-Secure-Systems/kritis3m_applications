#include "kritis3m_application_manager.h"
#include <sys/socket.h>

#include "utils.h"

// kritis3m applications:
#include "asl.h"
// end kritis3m applications

#include "logging.h"
LOG_MODULE_CREATE(log_manager_svc);

static struct application_manager manager = {0};



/**
 * @brief This service starts the standard applications.
 * Each service which is started is assigned a file descriptor for communication purposes
 * @todo Impolement management service for stdin bridge and echo server
 * @todo Implement managemnt service for the manager
 *
 */
int start_standard_application(struct SystemConfiguration *configuration)
{
    int ret = 0;
    int recv_buffer;
    int pair[2] = {-1};
    for (int i = 0; i < configuration->number_standard_applications; i++)
    {
        switch (configuration->standard_applications[i].application_type)
        {
        // case STD_IN_BRIDGE:
        //     struct tcp_client_stdin_bridge_config config;
        //     ret = parse_IPv4_fromIpPort(configuration->standard_applications[i].listening_ip_port, config.target_ip_address);
        //     if (ret < 0)
        //     {
        //         LOG_ERROR("Failed to parse IP address from listening IP port");
        //         return -1;
        //     }
        //     int port = parse_port_fromIpPort(configuration->standard_applications[i].listening_ip_port);
        //     if (port < 0)
        //     {
        //         LOG_ERROR("Failed to parse port from listening IP port");
        //         return -1;
        //     }

        //     // init management interface
        //     //  int pair[2]={-1};
        //     //  socketpair(AF_INET,SOCK_DGRAM,&pair[0]);
        //     ret = tcp_client_stdin_bridge_run(&config);
        //     if (ret < 0)
        //     {
        //         LOG_ERROR("Failed to start TCP client stdin bridge");
        //         return -1;
        //     }

        //     // recv application OK
        //     if (recv(pair[0], &recv_buffer, sizeof(recv_buffer), 0) > 0 && recv_buffer == APK_OK)
        //     {
        //         LOG_INFO("TCP client stdin bridge started successfully");
        //         // register fd in pollset
        //         //  poll_set_add_fd(&manager.poll_set, pair[0]);
        //     }
        //     else
        //     {
        //         LOG_ERR("start TCP client stdin bridge failed");
        //         return -1;
        //     }

        //     break;
        case ECHO_TCP_SERVER:
            struct tcp_echo_server_config config;
            char ip[IPv4_LEN];
            ret = parse_IPv4_fromIpPort(configuration->standard_applications[i].listening_ip_port, ip);
            if (ret < 0)
            {
                LOG_ERROR("Failed to parse IP address from listening IP port");
                return -1;
            }
            const char* test = ip;
            int port = parse_port_fromIpPort(configuration->standard_applications[i].listening_ip_port);
            if (port < 0)
            {
                LOG_ERROR("Failed to parse port from listening IP port");
                return -1;
            }

            // int pair [2] = {-1};
            // socketpair(AF_INET,SOCK_DGRAM,&pair[0]);

            // recv application OK
            if (recv(pair[0], &recv_buffer, sizeof(recv_buffer), 0) > 0 && recv_buffer == APK_OK)
            {
                // LOG_INFO("TCP client stdin bridge started successfully");
                // register fd in pollset
                //  poll_set_add_fd(&manager.poll_set, pair[0]);
            }
            else
            {
                LOG_ERROR("start TCP client stdin bridge failed");
                return -1;
            }

            break;
        case ECHO_UDP_SERVER:
            // LOG_INFO("Not implemented yet");
            break;

            default:
            break;
        }
    }
    return 0;
}

int start_proxy_applications(struct SystemConfiguration *configuration)
{
    proxy_config proxy_config;

    for (int i = 0; i < configuration->number_proxy_applications; i++)
    {

        char ip[IPv4_LEN];

        // @bug ip address
        int ret = parse_IPv4_fromIpPort(configuration->proxy_applications[i].listening_ip_port, ip);
        if (ret < 0)
        {
            LOG_ERROR("Failed to parse IP address from listening IP port");
            return -1;
        }
        proxy_config.own_ip_address=ip;
        proxy_config.listening_port = parse_port_fromIpPort(configuration->proxy_applications[i].listening_ip_port);
        if (proxy_config.listening_port < 0)
        {
            LOG_ERROR("Failed to parse port from listening IP port");
            return -1;
        }
        char targ_ip[IPv4_LEN];

        ret = parse_IPv4_fromIpPort(configuration->proxy_applications[i].target_ip_port, targ_ip);
        if (ret < 0)
        {
            LOG_ERROR("Failed to parse IP address from target IP port");
            return -1;
        }
        proxy_config.target_ip_address = targ_ip;
        proxy_config.target_port = parse_port_fromIpPort(configuration->proxy_applications[i].target_ip_port);
        if (proxy_config.target_port < 0)
        {
            LOG_ERROR("Failed to parse port from target IP port");
            return -1;
        }

        asl_endpoint_configuration tls_config;
        // @todo: corresponding crypto profile must be selected
        ret = parse_asl_from_crypto_profile(&configuration->crypto_profile[i], &tls_config);

        // start proxy
        ret = tls_forward_proxy_start(&proxy_config);
        if (ret < 0)
        {
            LOG_ERROR("Failed to start proxy");
            return -1;
        }
    }

    return 0;
}

void manage(SystemConfiguration *configuration)
{

    // start standard application

    // start proxyies
}