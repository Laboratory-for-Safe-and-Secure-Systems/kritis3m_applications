#include "kritis3m_application_manager.h"
#include <sys/socket.h>

#include "utils.h"

// kritis3m applications:
#include "asl.h"
#include "tls_proxy.h"
#include "tcp_client_stdin_bridge.h"
#include "echo_server.h"

// end kritis3m applications

#include "logging.h"
LOG_MODULE_CREATE(log_manager_svc);

int get_asl_endpoint(int id, asl_endpoint_configuration *ep);
int get_tcp_client_stdin_bridge_config(tcp_client_stdin_bridge_config *cfg, Kritis3mApplications *appl);
int get_echo_server_config(echo_server_config *cfg, Kritis3mApplications *appl);
int get_tls_proxy_config(proxy_config *cfg, Kritis3mApplications *appl);

static void *application_handler_thread(void *ptr);
struct application_manager
{
    int management_socket_pair[2];
    pthread_t thread;
    pthread_attr_t thread_attr;
    ApplicationConfiguration *config;
    bool running;
};

static struct application_manager manager;

int init_application_manager(application_manager_config *config)
{
    LOG_LVL_SET(config->log_level);
    manager.running = false;
    manager.management_socket_pair[0] = -1;
    manager.management_socket_pair[1] = -1;
    pthread_attr_init(&manager.thread_attr);
}

int start_application_manager(ApplicationConfiguration *configuration)
{
    manager.config = configuration;
    LOG_INFO("starting application thread");
    pthread_create(&manager.thread, &manager.thread_attr, application_handler_thread, &manager);
}
int stop_application_manager()
{
    // send stop request
    return 0;
}
int terminate_application_manager()
{
    // send stop request
    // terminate and free memory
    return 0;
}

static void *application_handler_thread(void *ptr)
{
    struct application_manager *manager = (struct application_manager *)ptr;
    bool proxies_available = false;
    bool echo_server_available = false;
    bool tcp_client_stdin_bridge_available = false;
    bool l2_bridge_available = false;
    int ret = -1;

    // start proxy services

    proxy_backend_config proxy_backend_configuration =
        {
            .log_level = LOG_LVL_INFO,
        };
    ret = tls_proxy_backend_run(&proxy_backend_configuration);
    if (ret < 0)
    {
        LOG_ERROR("cant start proxy backend ");
        goto shutdown;
    }

    for (int i = 0; i < manager->config->number_applications; i++)
    {
        Kritis3mApplications appl = manager->config->applications[i];

        switch (appl.type)
        {
        case TLS_FORWARD_PROXY:
            proxy_config config;
            ret = get_tls_proxy_config(&config, &appl);
            break;
        case TLS_REVERSE_PROXY:
            proxy_config config;
            ret = get_tls_proxy_config(&config, &appl);
            break;
        case TLS_TLS_PROXY:
            LOG_ERROR("TLS TLS PROXY not implmented yet");
            break;
        case ECHO_SERVER:

            echo_server_config config;
            ret = get_echo_server_config(&config, &appl);
            break;
        case TCP_CLIENT_STDIN_BRIDGE:

            tcp_client_stdin_bridge_config config;
            ret = get_tcp_client_stdin_bridge_config(&config, &appl);
            break;
        case L2_BRIDGE:
            LOG_ERROR("L2 bridge management support not implemente yet");

            break;
        default:
            LOG_ERROR("found application with unnknown application identifier: %d", appl.type);
            break;
        }
    }

    while (1)
    {
    }

    return NULL;

shutdown:
    return NULL;
}
int get_port_from_ipport(const char *src)
{
    int ret = -1;
    char *separator = strchr(src, ':');
    char *port_str = NULL;

    if (separator == NULL)
    {
        ret = -1;
    }
    else
    {
        port_str = separator + 1;
        unsigned long new_port = strtoul(port_str, NULL, 10);
        if ((new_port == 0) || (new_port > 65535))
        {
            LOG_ERROR("invalid port number %lu\r\n", new_port);
            ret = -1;
        }
        else
        {

            ret = (int)new_port;
        }
    }
    return ret;
}
char *extract_ipv4(const char *address_with_port)
{
    // Find the colon that separates the IP address and the port
    const char *colon_position = strchr(address_with_port, ':');

    // If no colon is found, return NULL (invalid format)
    if (!colon_position)
    {
        return NULL;
    }

    // Calculate the length of the IP address portion (everything before the colon)
    size_t ip_length = colon_position - address_with_port;

    // Duplicate the IP address portion
    char *ipv4_address = strndup(address_with_port, ip_length);

    return ipv4_address;
}

int get_tcp_client_stdin_bridge_config(tcp_client_stdin_bridge_config *cfg, Kritis3mApplications *appl)
{
    memset(cfg, 0, sizeof(tcp_client_stdin_bridge_config));
    cfg->log_level = appl->log_level;
    cfg->target_ip_address = extract_ipv4(appl->client_ip_port);
    cfg->target_port = get_port_from_ipport(appl->client_ip_port);

    if (cfg->target_ip_address == NULL ||
        (cfg->target_port < -1))
    {
        return -1;
    }
    return 0;
}

int get_echo_server_config(echo_server_config *cfg, Kritis3mApplications *appl)
{
    int ret = -1;
    cfg->own_ip_address = extract_ipv4(appl->server_ip_port);
    cfg->listening_port = get_port_from_ipport(appl->server_ip_port);
    cfg->log_level = appl->log_level;

    // TODO asl endopoint config

    if (cfg->own_ip_address == NULL ||
        (cfg->listening_port < 0))
    {
        return -1;
    }
    return 0;
}
int get_tls_proxy_config(proxy_config *cfg, Kritis3mApplications *appl)
{
    int ret = -1;
    cfg->own_ip_address = extract_ipv4(appl->server_ip_port);
    cfg->listening_port = get_port_from_ipport(appl->server_ip_port);

    if (cfg->own_ip_address == NULL ||
        (cfg->listening_port < 0))
    {
        LOG_ERROR("error parsing own ip address from ip_port");
        ret = -1;
        return ret;
    }

    cfg->target_ip_address = extract_ipv4(appl->server_ip_port);
    cfg->target_port = get_port_from_ipport(appl->client_ip_port);
    if (cfg->target_ip_address == NULL ||
        (cfg->target_port < 0))
    {
        LOG_ERROR("error parsing target ip address from ip_port");
        ret = -1;
        return ret;
    }
    cfg->log_level = appl->log_level;

    return ret;
}