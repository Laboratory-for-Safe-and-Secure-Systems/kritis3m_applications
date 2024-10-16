#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

// kritis3m applications:
#include "kritis3m_application_manager.h"
#include "utils.h"
#include "asl.h"
#include "tls_proxy.h"
#include "tcp_client_stdin_bridge.h"
#include "echo_server.h"

// end kritis3m applications

#include "logging.h"
LOG_MODULE_CREATE(log_manager_svc);

struct application_manager
{
    bool initialized;
    int management_pair[2];
    ApplicationConfiguration *configuration;

    pthread_t thread;
    poll_set notifier;
    pthread_attr_t thread_attr;
};

static struct application_manager manager;

bool uses_tls(int ep_id);

void *application_service_main_thread(void *arg);
enum MSG_RESPONSE_CODE management_request_helper(int socket, application_message *msg);
int get_endpoint_configuration(int ep_1id, asl_endpoint_configuration *ep);
static int read_management_message(int socket, application_message *msg);
static int send_management_message(int socket, application_message *msg);
int create_proxy_config(Kritis3mApplications *appl, proxy_config *config);
int stop_application(Kritis3mApplications *appl);
int stop_application_service(struct application_manager *application_manager);
int respond_with(int socket, enum MSG_RESPONSE_CODE response_code);
int create_echo_config(Kritis3mApplications *appl, echo_server_config *config);
// int create_network_tester_config(Kritis3mApplications *appl, network_tester_config *config);
int create_tcp_stdin_bridge_config(Kritis3mApplications *appl, tcp_client_stdin_bridge_config *config);

int client_matches_trusted_client(TrustedClients *trusted_client, int application_id, struct sockaddr_in *connecting_client)
{
    int ret = -1;
    // 1. check if connecting client matches trusted client
    if ((trusted_client == NULL) ||
        (connecting_client == NULL))
        return ret;

    // ip addr is valid if:
    //  trusted_client  | connecting client | match?
    //  - 0.0.0.0:port  | ANY_IP:port       | true
    //  - ip:0          | ip:ANY_PORT       | true
    //  - 0.0.0.0:0     | ANY_IP:ANY_PORT   | true

    bool family_valid = trusted_client->addr.sin_family == connecting_client->sin_family;
    bool ip_addr_valid = (trusted_client->addr.sin_addr.s_addr == htonl(INADDR_ANY)) || (trusted_client->addr.sin_addr.s_addr == connecting_client->sin_addr.s_addr);
    bool port_valid = (trusted_client->addr.sin_port == htons(0)) || (trusted_client->addr.sin_port == connecting_client->sin_port);

    if (family_valid && ip_addr_valid && port_valid) // comparing ipv4 with ipv4
        ret = 0;
    return ret;
}

bool is_running()
{
    if ((!manager.initialized) ||
        (manager.management_pair[0] < 0) ||
        (manager.management_pair[1] < 0))
    {
        return false;
    }
    return true;
}
bool confirm_client(int application_id, struct sockaddr_in *connecting_client)
{
    application_message request = {0};
    application_message response = {0};
    ApplicationConfiguration *appl_config = manager.configuration;
    bool ret = false;

    if ((!manager.initialized) ||
        (appl_config == NULL) ||
        (manager.management_pair[0] < 0) ||
        (manager.management_pair[1] < 0))
    {
        LOG_ERROR("application manager not initialized");
        return false;
    }
    request.msg_type = APPLICATION_CONNECTION_REQUEST;
    request.payload.client = *connecting_client;

    enum MSG_RESPONSE_CODE return_code = management_request_helper(manager.management_pair[0], &request);
    switch (return_code)
    {
    case MSG_ERROR:
        LOG_ERROR("Service Returned with error");
        goto error_occured;
        break;
    case MSG_OK:
        LOG_INFO("Client accepted");
        ret = true;
        break;
    case MSG_FORBIDDEN:
        LOG_INFO("Client rejected");
        ret = false;
        break;
    case MSG_BUSY:
        LOG_INFO("Try again");
        ret = false;
        break;
    default:
        LOG_ERROR("wrong return code");
        goto error_occured;
        break;
    }
    return ret;
error_occured:
    ret = false;
    LOG_ERROR("confirm client exit with Error");
    return ret;
}

bool is_client_supported(int application_id, struct sockaddr_in *connecting_client)
{
    ApplicationConfiguration *appl_config = manager.configuration;
    bool ret = false;

    if ((!manager.initialized) || (appl_config == NULL))
        return -1;

    for (int i = 0; i < appl_config->whitelist.number_trusted_clients; i++)
    {
        TrustedClients t_client = appl_config->whitelist.TrustedClients[i];
        int client_matches = client_matches_trusted_client(&t_client, application_id, connecting_client);
        if (client_matches == 0)
        {
            // is this connection forseen for application ?
            int number_trusted_application = t_client.number_trusted_applications;
            for (int j = 0; j < number_trusted_application; j++)
            {
                if (t_client.trusted_applications_id[j] == application_id)
                    return true;
            }
        }
    }
    char ip_addr[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &connecting_client->sin_addr, ip_addr, INET_ADDRSTRLEN) != NULL)
    {
        uint16_t port = ntohs(connecting_client->sin_port);
        LOG_WARN("Forbidden Client with IP addr: %s and port: %d tries to establish a connection with application with appl id : % d ", ip_addr, port, application_id);
    }
    return ret;
}
void init_applicaiton_manager(void)
{
    if (!manager.initialized)
    {
        pthread_mutex_init(&manager.configuration->lock, NULL);
        manager.management_pair[0] = -1;
        manager.management_pair[1] = -1;
        poll_set_init(&manager.notifier);
        pthread_attr_init(&manager.thread_attr);
        pthread_attr_setdetachstate(&manager.thread_attr, PTHREAD_CREATE_JOINABLE);
        manager.configuration = NULL;
    }
}

enum MSG_RESPONSE_CODE management_request_helper(int socket, application_message *msg)
{
    int ret;
    enum MSG_RESPONSE_CODE retval = MSG_OK;
    application_message response = {0};

    if (socket < 0)
        goto error_occured;
    ret = send_management_message(socket, msg);
    if (ret < 0)
        goto error_occured;
    ret = read_management_message(socket, &response);
    if (ret < 0)
        goto error_occured;
    if (response.msg_type == MSG_RESPONSE)
        retval = response.payload.return_code;
    else
        goto error_occured;
    return retval;

error_occured:
    retval = MSG_ERROR;
    return retval;
}

int start_application_manager(ApplicationConfiguration *configuration)
{
    int ret = -1;
    bool application_service_initialized = false;
    application_message request = {0};
    application_message response = {0};
    init_applicaiton_manager();
    for (int i = 0; i < configuration->whitelist.number_trusted_clients; i++)
    {
        ret = parse_ip_port_to_sockaddr_in(configuration->whitelist.TrustedClients[i].client_ip_port, &configuration->whitelist.TrustedClients[i].addr);
        if (ret < 0)
            goto error_occured;
    }
    manager.configuration = configuration;
    ret = socketpair(AF_UNIX, SOCK_STREAM, 0, manager.management_pair);
    if (ret < 0)
        LOG_ERROR("Error creating socket pair for management: %d (%s)", errno, strerror(errno));
    LOG_DEBUG("Created management socket pair (%d, %d)", manager.management_pair[0], manager.management_pair[1]);

    /* Init main backend */
    ret = pthread_create(&manager.thread, &manager.thread_attr, application_service_main_thread, &manager);
    if (ret != 0)
        LOG_ERROR("Error starting TCP echo server thread: %s", strerror(ret));
    // wait until service is initialized
    usleep(10 * 1000);
    while (!application_service_initialized)
    {
        // start request
        application_message request = {0};
        enum MSG_RESPONSE_CODE initialized = MSG_BUSY;
        request.msg_type = APPLICATION_SERVICE_START_REQUEST,
        request.payload.config = configuration;
        enum MSG_RESPONSE_CODE initialzed = management_request_helper(manager.management_pair[0], &request);
        if (initialized == MSG_OK)
            application_service_initialized = true;
    }

error_occured:
    LOG_ERROR("cant parse ip port");
    return ret;
}

int start_application(Kritis3mApplications *appl)
{
    int ret = 0;
    int appl_id = -1;
    if (appl == NULL)
        goto error_occured;
    Kritis3mApplicationtype type = appl->type;
    appl_id = appl->id;
    if (appl->state == true)
        LOG_INFO("applicationalready running");
    else
    {
        switch (type)
        {
        UNDEFINED:
        {
            goto error_occured;
            break;
        }
        TLS_FORWARD_PROXY:
        {
            proxy_config config = {0};
            ret = create_proxy_config(appl, &config);
            if (ret < 0)
            {
                LOG_ERROR("can't init proxy config");
                goto error_occured;
            }
            ret = tls_forward_proxy_start(&config);
            if (ret < 0)
            {
                LOG_ERROR("can't start tls forward proxy");
                goto error_occured;
            }
            break;
        }
        TLS_REVERSE_PROXY:
        {
            proxy_config config = {0};
            ret = create_proxy_config(appl, &config);
            if (ret < 0)
            {
                LOG_ERROR("can't init proxy config");
                goto error_occured;
            }
            ret = tls_reverse_proxy_start(&config);
            if (ret < 0)
            {
                LOG_ERROR("can't start tls reverse proxy");
                goto error_occured;
            }
            break;
        }
        TLS_TLS_PROXY:
        {
            LOG_INFO("tls proxy with 2 seperate tls endpoints not implemented yet");
            break;
        }
        ECHO_SERVER:
        {
            echo_server_config config = {0};
            ret = create_echo_config(appl, &config);
            if (ret < 0)
            {
                LOG_ERROR("can't init echo server config");
                goto error_occured;
            }
            ret = echo_server_run(&config);
            if (ret < 0)
            {
                LOG_ERROR("can't start echo server");
                goto error_occured;
            }
            break;
        }
        TCP_CLIENT_STDIN_BRIDGE:
        {

            tcp_client_stdin_bridge_config config = {0};
            ret = create_tcp_stdin_bridge_config(appl, &config);
            if (ret < 0)
            {
                LOG_ERROR("can't init tcp client stdin bridge config");
                goto error_occured;
            }
            ret = tcp_client_stdin_bridge_run(&config);
            if (ret < 0)
            {
                LOG_ERROR("can't start tcp client stdin bridge ");
                goto error_occured;
            }
            break;
        }
        L2_BRIDGE:
        {
            LOG_INFO("l2 bridge support not implemented yet");
            break;
        }
        default:
            goto error_occured;
            break;
        }

        appl->state = true;
    }
    return ret;
error_occured:
    ret = -1;
    LOG_ERROR("error occured starting application");
    return ret;
}
/**************
 * RESPONSES MISSING
 *  @TODO impl response
 */
int handle_management_message(int fd, struct application_manager *appl_manager)
{
    application_message msg = {0};
    int ret = -1;

    enum MSG_RESPONSE_CODE retval = MSG_OK;
    ret = read_management_message(fd, &msg);
    if (ret < 0)
    {
        goto error_occured;
    }
    switch (msg.msg_type)
    {
    /** RETVAL
     * -> OK, on successfull program start
     * -> ERROR, on failure
     */
    case APPLICATION_START_REQUEST:
    {
        Kritis3mApplications *appl = msg.payload.kritis3m_applicaiton;

        if (appl == NULL)
            goto error_occured;
        ret = start_application(appl);
        if (ret < 0)
            goto error_occured;
        retval = MSG_OK;
        break;
    }
    /** RETVAL
     * -> OK, on successfull status Request
     * -> ERROR, on failure
     */
    case APPLICATION_STATUS_REQUEST:
    {
        retval = MSG_ERROR;
        break;
    }
    /** RETVAL
     * -> OK, on successfull Stop Request
     * -> ERROR, on failure
     */
    case APPLICATION_STOP_REQUEST:
    {
        int appl_id = msg.payload.application_id;
        Kritis3mApplications *appl = find_application_by_application_id(appl_manager->configuration->applications,
                                                                        appl_manager->configuration->number_applications,
                                                                        appl_id);
        if (appl == NULL)
        {
            LOG_ERROR("no application found with application_id %d. STOP Request failed", appl_id);
            goto error_occured;
        }
        ret = stop_application(appl);
        if (ret < 0)
        {
            LOG_ERROR("Can't stop application with appl_id %d", appl_id);
            goto error_occured;
        }
        retval = MSG_OK;
        break;
    }
    case APPLICATION_SERVICE_START_REQUEST:
    {
        ApplicationConfiguration *config = msg.payload.config;
        int ret = 0;

        if (config == NULL)
            goto error_occured;
        if (appl_manager->configuration != NULL)
            LOG_WARN("Already existing configuration available. Please terminate application manager before passing new configuration");
        appl_manager->configuration = config;
        // configuration is now aquired from the application manager and can't be modified from outside
        ret = pthread_mutex_lock(&appl_manager->configuration->lock);
        if (ret < 0)
        {
            LOG_ERROR("can't lock config");
        }
        proxy_backend_config backend_config = tls_proxy_backend_default_config();
        ret = tls_proxy_backend_run(&backend_config);
        if (ret < 0)
            goto error_occured;
        for (int i = 0; i < appl_manager->configuration->number_applications; i++)
        {
            Kritis3mApplications *appl = &appl_manager->configuration->applications[i];
            if (appl == NULL)
            {
                LOG_ERROR("appl within applications is NULL, ERROR");
                appl_manager->configuration = NULL;
                ret = pthread_mutex_unlock(&appl_manager->configuration->lock);
                goto error_occured;
            }
            ret = start_application(appl);
            if (ret < 0)
                LOG_ERROR("application with appl_id %d couldnt be started correctly", appl->id);
            else
                appl->state = true;
        }
        retval = MSG_OK;
        break;
    }
    case APPLICATION_SERVICE_STOP_REQUEST:
    {
        // just stops all running appls
        ret = stop_application_service(appl_manager);
        if (ret < 0)
            retval = MSG_ERROR;
        else
            retval = MSG_OK;
        respond_with(fd, retval);
        // not sure about the close process, since the receive socket must still be opened to receive the management message
        close(appl_manager->management_pair[0]);
        close(appl_manager->management_pair[1]);
        return 0;
        // @TODO free mem
        // @TODO RESET application_managerclean application_manager
        appl_manager->initialized = false;
        if (appl_manager != NULL)
            poll_set_init(&appl_manager->notifier);
        break;
    }
    case APPLICATION_SERVICE_STATUS_REQUEST:
    {
        break;
    }

    case APPLICATION_CONNECTION_REQUEST:
    {
        client_connection_request con_req = msg.payload.client_con_request;
        int appl_id = con_req.application_id;
        if ((appl_id < 0))
            goto error_occured;
        bool is_supported = false;
        is_supported = is_client_supported(con_req.application_id, &con_req.client);
        if (is_supported)
            retval = MSG_OK;
        else
            retval = MSG_FORBIDDEN;
        break;
    }
    case MSG_RESPONSE:
    {
        ret = msg.payload.return_code;
        LOG_INFO("response not implemented");
        return 0;
        break;
    }
    default:
    {
        LOG_ERROR("unknown request");
        retval = MSG_ERROR;
        break;
    }
    }
    ret = respond_with(fd, retval);
    return ret;
error_occured:
    retval = MSG_ERROR;
    respond_with(fd, retval);
    ret = -1;
    return ret;
}

void *application_service_main_thread(void *arg)
{
    int ret = -1;
    bool shutodwn = false;
    int management_socket = -1;
    struct application_manager *appl_manager = (struct application_manager *)arg;
    // check if service is correctly initialized:
    if ((appl_manager == NULL) ||
        (appl_manager->configuration == NULL) ||
        (appl_manager->management_pair[1] < 0))
        return NULL;
    poll_set_add_fd(&appl_manager->notifier, appl_manager->management_pair[1], POLLIN | POLLERR | POLLHUP);
    appl_manager->initialized = true;

    while (!shutdown)
    {
        int number_events = poll(appl_manager->notifier.fds, appl_manager->notifier.num_fds, 0);

        if (number_events == -1)
        {
            LOG_ERROR("poll error: %d", errno);
            continue;
        }

        for (int i = 0; i < appl_manager->notifier.num_fds; i++)
        {

            int fd = appl_manager->notifier.fds[i].fd;
            short event = appl_manager->notifier.fds[i].revents;

            if (event == 0)
                continue;

            if (fd == appl_manager->management_pair[1])
            {
                if (event & POLLIN)
                    ret = handle_management_message(fd, appl_manager);
                if ((event & POLLERR) || (event & POLLHUP))
                    LOG_ERROR("Error occured, shut down management service");
                else
                {
                    LOG_ERROR(" unsupported event %d ", event);
                    continue;
                }
            }
        }
    }
error_occured:
    if (appl_manager->initialized)
    {
        stop_application_service(appl_manager);

        close(appl_manager->management_pair[0]);
        close(appl_manager->management_pair[1]);
        appl_manager->initialized = false;
        poll_set_init(&appl_manager->notifier);
    }
    return NULL;
}

static int send_management_message(int socket, application_message *msg)
{
    int ret = 0;
    static const int max_retries = 5;
    int retries = 0;

    while ((ret <= 0) && (retries < max_retries))
    {
        ret = send(socket, msg, sizeof(application_message), 0);
        if (ret < 0)
        {
            if (errno != EAGAIN)
            {
                LOG_ERROR("Error sending message: %d (%s)", errno, strerror(errno));
                return -1;
            }
            usleep(10 * 1000);
        }
        else if (ret != sizeof(application_message))
        {
            LOG_ERROR("Sent invalid message");
            return -1;
        }

        retries++;
    }

    if (retries >= max_retries)
    {
        LOG_ERROR("Failed to send message after %d retries", max_retries);
        return -1;
    }

    return 0;
}

static int read_management_message(int socket, application_message *msg)
{
    int ret = recv(socket, msg, sizeof(application_message), 0);
    if (ret < 0)
    {
        LOG_ERROR("Error receiving message: %d (%s)", errno, strerror(errno));
        return -1;
    }
    else if (ret != sizeof(application_message))
    {
        LOG_ERROR("Received invalid response (ret=%d; expected=%lu)", ret, sizeof(application_message));
        return -1;
    }

    return 0;
}

int create_proxy_config(Kritis3mApplications *appl, proxy_config *config)
{
    if (appl == NULL || config == NULL)
        return -1;
    int ret = 0;
    config->own_ip_address = NULL;
    config->target_ip_address = NULL;
    config->application_id = appl->id;

    config->log_level = appl->log_level;

    config->own_ip_address = (char *)malloc(INET_ADDRSTRLEN);
    config->target_ip_address = (char *)malloc(INET_ADDRSTRLEN);

    ret = parse_IPv4_fromIpPort(appl->server_ip_port, config->own_ip_address);
    if (ret < 0)
    {
        goto error_occured;
    }
    config->listening_port = parse_port_fromIpPort(appl->server_ip_port);
    if (config->listening_port < 0)
    {
        goto error_occured;
    }

    ret = parse_IPv4_fromIpPort(appl->client_ip_port, config->target_ip_address);
    if (ret < 0)
    {
        goto error_occured;
    }
    config->target_port = parse_port_fromIpPort(appl->client_ip_port);
    if (config->target_port < 0)
    {
        goto error_occured;
    }
    ret = get_endpoint_configuration(appl->ep1_id, &config->tls_config);
    if (ret < 0)
        goto error_occured;

    //!! ASL_CONFIG !!
    return ret;

error_occured:
    ret = -1;
    free(config->own_ip_address);
    free(config->target_ip_address);
    return ret;
}

int create_echo_config(Kritis3mApplications *appl, echo_server_config *config)
{
    if ((appl == NULL) ||
        (config == NULL) ||
        (appl->type != ECHO_SERVER))
        return -1;
    int ret = 0;
    config->own_ip_address = NULL;
    config->own_ip_address = (char *)malloc(INET_ADDRSTRLEN);
    config->log_level = appl->log_level;
    config->use_tls = true;
    config->application_id = appl->id;

    ret = parse_IPv4_fromIpPort(appl->server_ip_port, config->own_ip_address);
    if (ret < 0)
    {
        goto error_occured;
    }
    config->listening_port = parse_port_fromIpPort(appl->server_ip_port);
    if (config->listening_port < 0)
    {
        goto error_occured;
    }
    ret = get_endpoint_configuration(appl->ep1_id, &config->tls_config);
    if (ret < 0)
        goto error_occured;
    return ret;
error_occured:
    ret = -1;
    free(config->own_ip_address);
    return ret;
}

int create_tcp_stdin_bridge_config(Kritis3mApplications *appl, tcp_client_stdin_bridge_config *config)
{
    if ((appl == NULL) ||
        (config == NULL) ||
        (appl->type != ECHO_SERVER))
        return -1;
    int ret = 0;
    config->log_level = appl->log_level;
    config->application_id = appl->id;
    config->target_ip_address = NULL;

    config->target_ip_address = (char *)malloc(INET_ADDRSTRLEN);
    ret = parse_IPv4_fromIpPort(appl->client_ip_port, config->target_ip_address);
    if (ret < 0)
        goto error_occured;
    config->target_port = parse_port_fromIpPort(appl->client_ip_port);
    if (config->target_port < 0)
        goto error_occured;

    return ret;
error_occured:
    ret = -1;
    free(config->target_ip_address);
    return ret;
}

int get_endpoint_configuration(int ep_1id, asl_endpoint_configuration *ep)
{
    return -1;
}

int respond_with(int socket, enum MSG_RESPONSE_CODE response_code)
{
    application_message response = {0};
    response.msg_type = MSG_RESPONSE;
    response.payload.return_code = response_code;
    return send_management_message(socket, &response);
}

int stop_application(Kritis3mApplications *appl)
{
    int ret = 0;
    int appl_id = -1;
    if (appl == NULL)
        goto error_occured;

    appl_id = appl->id;

    if (appl->state == false)
    {
        LOG_WARN("application is already offline");
    }
    else
    {
        switch (appl->type)
        {
        case TLS_FORWARD_PROXY:
        {
            ret = tls_proxy_stop_appl_id(appl_id);
            if (ret < 0)
            {
                LOG_ERROR("stop request for tls forward proxy with appl_id %d failed. STOP Request failed", appl_id);
                goto error_occured;
            }
            break;
        }
        case TLS_REVERSE_PROXY:
        {
            ret = tls_proxy_stop_appl_id(appl_id);
            if (ret < 0)
            {
                LOG_ERROR("stop request for tls reverse proxy with appl_id %d failed. STOP Request failed", appl_id);
                goto error_occured;
            }
            break;
        }
        case ECHO_SERVER:
        {
            ret = echo_server_terminate();
            if (ret < 0)
            {
                LOG_ERROR("stop request for echo server with appl_id %d failed. STOP Request failed", appl_id);
                goto error_occured;
            }
            break;
        }
        case TCP_CLIENT_STDIN_BRIDGE:
        {
            ret = tcp_client_stdin_bridge_terminate();
            if (ret < 0)
            {
                LOG_ERROR("stop request for tcp_client_stdin_bridge with appl_id %d failed. STOP Request failed", appl_id);
                goto error_occured;
            }
            break;
        }
        case UNDEFINED:
        {
            LOG_WARN("cant stop application: Unknown application type with appl_id %d ", appl_id);
            goto error_occured;
            break;
        }
        default:
            goto error_occured;
        }
    }
    appl->state = false;
    return ret;
error_occured:
    ret = -1;
    LOG_ERROR("exit stop application with error");
    return ret;
}
int stop_application_service(struct application_manager *application_manager)
{
    int ret = 0;
    int number_applications = -1;
    int appl_id = -1;
    Kritis3mApplications *appls = NULL;
    Kritis3mApplications *appl = NULL;

    if (application_manager == NULL)
        return -1;
    appls = application_manager->configuration->applications;
    number_applications = application_manager->configuration->number_applications;

    for (int i = 0; i < number_applications; i++)
    {
        appl = &appls[i];
        ret = stop_application(appl);
        if (ret < 0)
        {
            LOG_ERROR("can't stop appl with appl id %d", appl_id);
        }
    }

    pthread_mutex_unlock(&application_manager->configuration->lock);
    // free mem
    // mutex unlock config
    // socketpair close

    return ret;
}

int stop_application_manager()
{
    int socket = -1;
    int ret = 0;
    application_message request = {0};
    if (!manager.initialized || (manager.management_pair[0] < 0))
        return -1;

    socket = manager.management_pair[0];
    request.msg_type = APPLICATION_SERVICE_STOP_REQUEST;

    enum MSG_RESPONSE_CODE retval = management_request_helper(socket, &request);
    if (retval != MSG_OK)
    {
        ret = -1;
        LOG_ERROR("error occured in application service");
    }
    else
    {
        LOG_INFO("closed application_manager succesfully");
    }
    close(socket); // closing socket anyway
    return ret;
}