// thread
#include <pthread.h>
#include <semaphore.h>

// std
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "asl.h"
#include "echo_server.h"
#include "kritis3m_application_manager.h"
#include "kritis3m_scale_service.h"
#include "networking.h"
#include "poll_set.h"
#include "tcp_client_stdin_bridge.h"
#include "tls_proxy.h"

#include "logging.h"
LOG_MODULE_CREATE(application_log_module);

typedef struct connection_request
{
        struct sockaddr_in client_addr;
        int application_id;
} connection_request;

typedef struct application_status
{
        bool is_running;
        union concrete_application_status
        {
                proxy_status proxy_status;
                echo_server_status echo_status;
                tcp_client_stdin_bridge_status stdtin_bridge_status;
                // network_tester_status tester_status;

        } concrete_application_status;
} application_status;

typedef struct application_config
{
        int application_id;
        Kritis3mApplicationtype type;
        union concrete_application_config
        {
                echo_server_config echo_config;
                proxy_config proxy_config;
                // network_tester_config network_tester_config;
                tcp_client_stdin_bridge_config stdin_bridge_config;
                ApplicationConfiguration application_configuration;
        } config;
} application_config;

typedef struct client_connection_request
{
        struct sockaddr* client;
        int application_id;
} client_connection_request;

/*--------------------------- IPC ----------------------------------*/
enum application_management_message_type
{
        APPLICATION_START_REQUEST,
        APPLICATION_STATUS_REQUEST,
        APPLICATION_STOP_REQUEST,

        APPLICATION_SERVICE_START_REQUEST,
        APPLICATION_SERVICE_STOP_REQUEST,
        APPLICATION_SERVICE_STATUS_REQUEST,

        APPLICATION_CONNECTION_REQUEST,
        MSG_RESPONSE,
};

typedef struct application_message
{
        enum application_management_message_type msg_type;
        Kritis3mApplicationtype type;
        union application_management_message_payload
        {

                ApplicationConfiguration* config;
                Kritis3mApplications* kritis3m_applicaiton;
                application_config appl_config;
                application_status status_request;
                client_connection_request client_con_request;
                enum MSG_RESPONSE_CODE return_code;
                int application_id;
        } payload;
} application_message;

struct application_manager
{
        bool initialized;
        int management_pair[2];
        ApplicationConfiguration* configuration;
        pthread_t thread;
        pthread_attr_t thread_attr;
        sem_t thread_setup_sem;
        poll_set notifier;
};

// main application manager instance used by the main thread
static struct application_manager manager = {
        .initialized = false,
        .management_pair[THREAD_INT] = -1,
        .management_pair[THREAD_EXT] = -1,
        .configuration = NULL,
        .notifier = {0},
};

/*-------------------------------  FORWARD DECLARATIONS---------------------------------*/
// mainthread
void* application_service_main_thread(void* arg);
// ipc
enum MSG_RESPONSE_CODE management_request_helper(int socket, application_message* msg);
int respond_with(int socket, enum MSG_RESPONSE_CODE response_code);
static int read_management_message(int socket, application_message* msg);
static int send_management_message(int socket, application_message* msg);
enum MSG_RESPONSE_CODE management_request_helper(int socket, application_message* msg);
ManagementReturncode handle_management_message(int fd, struct application_manager* appl_manager);
// services
bool is_client_supported(client_connection_request con_req);
int stop_application(Kritis3mApplications* appl);
int stop_application_service(struct application_manager* application_manager);
int start_application(Kritis3mApplications* appl);
int client_matches_trusted_client(TrustedClients* trusted_client, struct sockaddr* connecting_client);
// helper functions
int create_echo_config(Kritis3mApplications* appl, echo_server_config* config);
int create_tcp_stdin_bridge_config(Kritis3mApplications* appl, tcp_client_stdin_bridge_config* config);
int create_proxy_config(Kritis3mApplications* appl, proxy_config* config);
int get_endpoint_configuration(int ep_1id, asl_endpoint_configuration* ep);

void cleanup_application_manager(void);

// initialize application manager
void init_application_manager(void)
{
        int ret = 0;
        manager.initialized = false;
        if (manager.configuration != NULL)
                manager.configuration = NULL;
        manager.management_pair[THREAD_EXT] = -1;
        manager.management_pair[THREAD_INT] = -1;
        poll_set_init(&manager.notifier);
        pthread_attr_init(&manager.thread_attr);
        pthread_attr_setdetachstate(&manager.thread_attr, PTHREAD_CREATE_JOINABLE);
        sem_init(&manager.thread_setup_sem, 0, 0);
}

// start application manager
int start_application_manager(ApplicationConfiguration* configuration)
{

        int ret = -1;
        bool application_service_initialized = false;
        application_message request = {0};
        application_message response = {0};

        if (configuration == NULL)
                goto error_occured;

        //------------------------ set log level ------------------------------------------//
        LOG_LVL_SET(configuration->log_level);
        LOG_LVL_SET(LOG_LVL_DEBUG);

        //------------------------ init environment --------------------------------------//
        proxy_backend_config backend_config = tls_proxy_backend_default_config();
        ret = tls_proxy_backend_run(&backend_config);
        if (ret < 0)
                goto error_occured;

        ret = create_socketpair(manager.management_pair);
        if (ret < 0)
                LOG_ERROR("Error creating socket pair for management: %d (%s)", errno, strerror(errno));

        /* Init main backend */
        ret = pthread_create(&manager.thread,
                             &manager.thread_attr,
                             application_service_main_thread,
                             &manager);
        if (ret != 0)
                LOG_ERROR("Error starting TCP echo server thread: %s", strerror(ret));
        // wait until service is initialized

        sem_wait(&manager.thread_setup_sem);

        enum MSG_RESPONSE_CODE initialized = MSG_BUSY;
        request.msg_type = APPLICATION_SERVICE_START_REQUEST, request.payload.config = configuration;
        enum MSG_RESPONSE_CODE initialzed = management_request_helper(manager.management_pair[THREAD_EXT],
                                                                      &request);
        if (initialized < 0)
                goto error_occured;
        return 0;

error_occured:
        LOG_ERROR("error initializing application manager");
        return ret;
}

// application manager main thread
void* application_service_main_thread(void* arg)
{
        /*------------------------------------------ INITIALIZATION ------------------------------------------ */
        int ret = -1;
        bool shutdown = true;
        int management_socket = -1;
        struct application_manager* appl_manager = (struct application_manager*) arg;

        // check if service is correctly initialized:
        if ((appl_manager == NULL) || (appl_manager->management_pair[THREAD_INT] < 0))
        {
                LOG_ERROR("application manager can't be started correctly. Either management pair "
                          "or appl_manager is NULL");
                goto cleanup_application_service;
        }

        // signalize application manager is running
        manager.initialized = true;
        LOG_INFO("application manager started");

        // update pollset
        poll_set_add_fd(&appl_manager->notifier,
                        appl_manager->management_pair[THREAD_INT],
                        POLLIN | POLLERR | POLLHUP);

        // signalize caller, that mainthread is started
        sem_post(&manager.thread_setup_sem);

        while (shutdown)
        {
                // await events
                int number_events = poll(appl_manager->notifier.fds, appl_manager->notifier.num_fds, -1);

                if (number_events == -1)
                {
                        LOG_ERROR("poll error: %d", errno);
                        continue;
                }

                for (int i = 0; i < appl_manager->notifier.num_fds; i++)
                {

                        int fd = appl_manager->notifier.fds[i].fd;
                        short event = appl_manager->notifier.fds[i].revents;

                        // no event occured
                        if (event == 0)
                                continue;

                        // Internal thread
                        if (fd == appl_manager->management_pair[THREAD_INT])
                        {
                                // Internal thread, data available
                                if (event & POLLIN)
                                {
                                        ManagementReturncode returncode = handle_management_message(fd,
                                                                                                    appl_manager);
                                        if (returncode == MGMT_THREAD_STOP)
                                        {
                                                goto cleanup_application_service;
                                        }
                                        else if (returncode < 0)
                                        {
                                                LOG_ERROR("error occured");
                                                if (appl_manager->management_pair[THREAD_EXT] > 0)
                                                {
                                                        closesocket(
                                                                appl_manager->management_pair[THREAD_EXT]);
                                                        appl_manager->management_pair[THREAD_EXT] = -1;
                                                }

                                                if (appl_manager->management_pair[THREAD_INT] > 0)
                                                {
                                                        closesocket(
                                                                appl_manager->management_pair[THREAD_INT]);
                                                        appl_manager->management_pair[THREAD_INT] = -1;
                                                }
                                                goto cleanup_application_service;
                                        }
                                }
                                else if ((event & POLLERR) || (event & POLLHUP))
                                {
                                        LOG_ERROR("error occured");

                                        poll_set_remove_fd(&appl_manager->notifier,
                                                           appl_manager->management_pair[THREAD_INT]);
                                        if (appl_manager->management_pair[THREAD_EXT] > 0)
                                        {
                                                closesocket(appl_manager->management_pair[THREAD_EXT]);
                                                appl_manager->management_pair[THREAD_EXT] = -1;
                                        }

                                        if (appl_manager->management_pair[THREAD_INT] > 0)
                                        {
                                                closesocket(appl_manager->management_pair[THREAD_INT]);
                                                appl_manager->management_pair[THREAD_INT] = -1;
                                        }
                                        break;
                                }
                                else
                                {
                                        LOG_ERROR("unsupported event %d ", event);
                                        continue;
                                }
                        }
                }
        }
cleanup_application_service:
        LOG_INFO("exiting kritis3m_applicaiton");
        tls_proxy_backend_terminate();
        cleanup_application_manager();
        pthread_detach(pthread_self());
        return NULL;
}

// returns if application_manager is running
bool is_running()
{
        if ((!manager.initialized) || (manager.management_pair[THREAD_EXT] < 0) ||
            (manager.management_pair[THREAD_INT] < 0))
        {
                return false;
        }
        return true;
}

/*------------------------------------------ IPC functions ------------------------------------------------------*/
// send management message
static int send_management_message(int socket, application_message* msg)
{
        int ret = 0;
        static const int max_retries = 5;
        int retries = 0;

        while ((ret <= 0) && (retries < max_retries))
        {
                ret = send(socket, (char*) msg, sizeof(application_message), 0);
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
// read management message
static int read_management_message(int socket, application_message* msg)
{
        int ret = recv(socket, (char*) msg, sizeof(application_message), 0);
        if (ret < 0)
        {
                LOG_ERROR("Error receiving message: %d (%s)", errno, strerror(errno));
                return -1;
        }
        else if (ret != sizeof(application_message))
        {
                LOG_ERROR("Received invalid response (ret=%d; expected=%lu)",
                          ret,
                          sizeof(application_message));
                return -1;
        }

        return 0;
}

// respond with a MSG_RESPONSE_CODE to a management request
int respond_with(int socket, enum MSG_RESPONSE_CODE response_code)
{
        application_message response = {0};
        response.msg_type = MSG_RESPONSE;
        response.payload.return_code = response_code;
        return send_management_message(socket, &response);
}

// send APPLICATION_CONNECTION_REQUEST to main thread
bool confirm_client(int application_id, struct sockaddr* connecting_client)
{
        application_message request = {0};
        application_message response = {0};
        ApplicationConfiguration* appl_config = manager.configuration;
        bool ret = false;

        if ((!manager.initialized) || (appl_config == NULL) ||
            (manager.management_pair[THREAD_EXT] < 0) || (manager.management_pair[THREAD_INT] < 0))
        {
                LOG_ERROR("application manager not initialized");
                return false;
        }

        request.msg_type = APPLICATION_CONNECTION_REQUEST;
        request.payload.client_con_request.application_id = application_id;
        request.payload.client_con_request.client = connecting_client;

        enum MSG_RESPONSE_CODE return_code = management_request_helper(manager.management_pair[THREAD_EXT],
                                                                       &request);
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

// sends management request and awaits response
enum MSG_RESPONSE_CODE management_request_helper(int socket, application_message* msg)
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

// send APPLICATION_SERVICE_STOP_REQUEST to main thread
int stop_application_manager()
{
        int socket = -1;
        int ret = 0;
        application_message request = {0};
        if (!manager.initialized || (manager.management_pair[THREAD_EXT] < 0))
        {
                LOG_INFO("application manager is already stopped");
                return ret;
        }

        socket = manager.management_pair[THREAD_EXT];
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

        if (manager.management_pair[THREAD_EXT] > 0)
        {
                closesocket(manager.management_pair[THREAD_EXT]);
                manager.management_pair[THREAD_EXT] = -1;
        }

        if (manager.management_pair[THREAD_INT] > 0)
        {
                closesocket(manager.management_pair[THREAD_INT]);
                manager.management_pair[THREAD_INT] = -1;
        }
        pthread_join(manager.thread, NULL);
        return ret;
}

// handle management request
ManagementReturncode handle_management_message(int fd, struct application_manager* appl_manager)
{
        application_message msg = {0};
        int ret = -1;

        enum ManagementReturncode retval = MGMT_OK;
        ret = read_management_message(fd, &msg);
        if (ret < 0)
        {
                retval = MGMT_ERR;
                goto error_occured;
        }
        switch (msg.msg_type)
        {
        // start a single application
        case APPLICATION_START_REQUEST:
                {
                        Kritis3mApplications* appl = msg.payload.kritis3m_applicaiton;

                        if (appl == NULL)
                                goto error_occured;
                        // try to start appl
                        ret = start_application(appl);
                        if (ret < 0)
                                goto error_occured;
                        retval = MGMT_OK;
                        break;
                }
        // not implemented yet
        case APPLICATION_STATUS_REQUEST:
                {
                        retval = MGMT_ERR;
                        LOG_INFO("application status request not implemented yet");

                        break;
                }
        // stops a single application
        case APPLICATION_STOP_REQUEST:
                {
                        int appl_id = msg.payload.application_id;
                        Kritis3mApplications*
                                appl = find_application_by_application_id(appl_manager
                                                                                  ->configuration->applications,
                                                                          appl_manager
                                                                                  ->configuration->number_applications,
                                                                          appl_id);
                        if (appl == NULL)
                        {
                                LOG_ERROR("no application found with application_id %d. STOP "
                                          "Request failed",
                                          appl_id);
                        }
                        ret = stop_application(appl);
                        if (ret < 0)
                        {
                                LOG_ERROR("Can't stop application with appl_id %d", appl_id);
                        }
                        retval = MGMT_OK;
                        break;
                }
        /**
         * Start the Application manager with a ApplicationConfiguration Object
         */
        case APPLICATION_SERVICE_START_REQUEST:
                {
                        ApplicationConfiguration* config = msg.payload.config;
                        ApplicationManagerStatus status = {.running_applications = 0, .Status = APK_OK};
                        int ret = 0;

                        if (appl_manager->configuration != NULL)
                        {
                                LOG_WARN("Already existing configuration available. Please "
                                         "terminate application manager before passing new "
                                         "configuration");
                                goto error_occured;
                        }
                        if (config == NULL)
                                goto error_occured;

                        appl_manager->configuration = config;

                        if (appl_manager->configuration == NULL)
                                goto error_occured;

                        // eraly response
                        respond_with(fd, MSG_OK);

                        for (int i = 0; i < appl_manager->configuration->number_applications; i++)
                        {
                                Kritis3mApplications* appl = &appl_manager->configuration->applications[i];
                                if (appl == NULL)
                                {
                                        LOG_ERROR("appl within applications is NULL, ERROR");
                                        appl_manager->configuration = NULL;
                                        status.Status = APK_ERR;
                                        return MGMT_ERR;
                                }
                                ret = start_application(appl);
                                if (ret < 0)
                                {
                                        LOG_ERROR("couldnt start proxy applciation with id %d",
                                                  appl->id);
                                        status.Status = APK_ERR;
                                        return MGMT_ERR;
                                }
                                else
                                {
                                        appl->state = true;
                                        status.running_applications++;
                                }
                        }
                        // notify kritis3m_service
                        ret = req_send_status_report(status);
                        if (ret < 0)
                        {
                                LOG_ERROR("application_manager: couldnt send status report");
                        }

                        status.Status = APK_OK;
                        return MGMT_OK;
                }
        // shut down application manager
        // cleanup is processed in main thread
        case APPLICATION_SERVICE_STOP_REQUEST:
                {
                        if (appl_manager == NULL)
                        {
                                LOG_ERROR("appl_manager is NULL");
                                return MGMT_ERR;
                        }
                        ret = stop_application_service(appl_manager);
                        if (ret < 0)
                                LOG_ERROR("Can't stop application_service");

                        appl_manager->initialized = false;
                        appl_manager->configuration = NULL;
                        respond_with(fd, retval);

                        retval = MGMT_THREAD_STOP;
                        break;
                }
        case APPLICATION_SERVICE_STATUS_REQUEST:
                {
                        LOG_WARN("applications service status request not implemented yet");
                        retval = MGMT_OK;
                        break;
                }
        // handle connection request
        case APPLICATION_CONNECTION_REQUEST:
                {
                        client_connection_request con_req = msg.payload.client_con_request;
                        int appl_id = con_req.application_id;
                        if ((appl_id < 0))
                                goto error_occured;
                        bool is_supported = is_client_supported(con_req);
                        retval = (is_supported == true) ? MGMT_OK : MGMT_FORBIDDEN;
                        retval = MGMT_OK;
                        break;
                }
        case MSG_RESPONSE:
                {
                        ret = msg.payload.return_code;
                        LOG_INFO("response not implemented");
                        retval = MGMT_OK;
                        break;
                }
        default:
                {
                        LOG_ERROR("unknown request");
                        retval = MGMT_ERR;
                        break;
                }
        }
        //-----------------------------------------  END OF THE HANDLER------------------------------------ //
        ret = respond_with(fd, retval);

        return retval;
error_occured:
        //-----------------------------------------  ERROR HANDLER ------------------------------------ //
        LOG_ERROR("Error occured handling internal management request");
        ret = -1;
        if (retval > 0)
                retval = MGMT_ERR;
        respond_with(fd, retval);
        return retval;
}

/*-------------------------------- Services ------------------------------------------*/

// whitelist lookup if client is supported or not
bool is_client_supported(client_connection_request con_req)
{
        ApplicationConfiguration* appl_config = manager.configuration;
        bool ret = false;

        if ((!manager.initialized) || (appl_config == NULL) || (con_req.client == NULL))
                return false;
        // check each entry in trusted clients
        for (int i = 0; i < appl_config->whitelist.number_trusted_clients; i++)
        {
                TrustedClients t_client = appl_config->whitelist.TrustedClients[i];
                // is this connection forseen for application ?
                int number_trusted_application = t_client.number_trusted_applications;
                for (int j = 0; j < number_trusted_application; j++)
                {
                        if (t_client.trusted_applications_id[j] == con_req.application_id)
                        {
                                int client_matches = client_matches_trusted_client(&t_client,
                                                                                   con_req.client);
                                if (client_matches == 0)
                                {
                                        LOG_INFO("client is trusted");
                                        return true;
                                }
                        }
                }
        }
        return ret;
}

// start application manager
int start_application(Kritis3mApplications* appl)
{
        int ret = 0;
        int appl_id = -1;

        if (appl == NULL)
                goto error_occured;

        Kritis3mApplicationtype type = appl->type;
        appl_id = appl->id;

        switch (type)
        {
        case UNDEFINED:
                {
                        goto error_occured;
                        break;
                }
        case TLS_FORWARD_PROXY:
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
        case TLS_REVERSE_PROXY:
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
        case TLS_TLS_PROXY:
                {
                        LOG_INFO("tls proxy with 2 seperate tls endpoints not implemented yet");
                        break;
                }
        case ECHO_SERVER:
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
        case TCP_CLIENT_STDIN_BRIDGE:
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
        case L2_BRIDGE:
                {
                        LOG_INFO("l2 bridge support not implemented yet");
                        break;
                }
        default:
                LOG_ERROR("unknown application");
                goto error_occured;
                break;
        }

        return ret;
error_occured:
        ret = -1;
        LOG_ERROR("error occured starting application");
        return ret;
}

/*------------------------------ Helper methods ---------------------------------------*/
int create_proxy_config(Kritis3mApplications* appl, proxy_config* config)
{
        if (appl == NULL || config == NULL)
                return -1;
        int ret = 0;

        // config->application_id = appl->id;
        config->log_level = appl->log_level;

        config->own_ip_address = appl->server_endpoint_addr.address;
        config->listening_port = appl->server_endpoint_addr.port;

        config->target_ip_address = appl->client_endpoint_addr.address;
        config->target_port = appl->client_endpoint_addr.port;

        config->application_id = appl->id;

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

int create_echo_config(Kritis3mApplications* appl, echo_server_config* config)
{
        int ret = 0;
        if ((appl == NULL) || (config == NULL) || (appl->type != ECHO_SERVER))
                return -1;

        // config->application_id = appl->id;
        config->log_level = appl->log_level;

        config->own_ip_address = appl->server_endpoint_addr.address;
        config->listening_port = appl->server_endpoint_addr.port;

        config->use_tls = true;

        ret = get_endpoint_configuration(appl->ep1_id, &config->tls_config);
        if (ret < 0)
                goto error_occured;

        LOG_INFO("created echo server config");

        return ret;
error_occured:
        ret = -1;
        free(config->own_ip_address);
        return ret;
}

int create_tcp_stdin_bridge_config(Kritis3mApplications* appl, tcp_client_stdin_bridge_config* config)
{

        int ret = 0;
        if ((appl == NULL) || (config == NULL) || (appl->type != TCP_CLIENT_STDIN_BRIDGE))
                return -1;

        // config->application_id = appl->id;

        config->log_level = appl->log_level;

        config->target_ip_address = appl->client_endpoint_addr.address;
        config->target_port = appl->client_endpoint_addr.port;

        LOG_INFO("tcp client stdin bridge");

        return ret;
error_occured:
        ret = -1;
        return ret;
}

int get_endpoint_configuration(int ep_id, asl_endpoint_configuration* ep)
{
        int ret = 0;
        crypto_identity* identity = NULL;
        CryptoProfile* profile = NULL;

        if ((!manager.initialized) || (manager.configuration == NULL) || (ep == NULL))
        {
                LOG_ERROR("manager is not initialized");
                return -1;
        }

        int number_crypto_profiles = manager.configuration->number_crypto_profiles;
        int number_identitities = manager.configuration->number_crypto_identity;

        if ((number_crypto_profiles <= 0) || (number_crypto_profiles <= 0))
        {

                LOG_ERROR("crypto is not correctly initialized");
                return -1;
        }

        identity = manager.configuration->crypto_identity;
        profile = manager.configuration->crypto_profile;

        // search crypto profiles
        for (int i = 0; i < number_crypto_profiles; i++)
        {
                if (profile[i].id == ep_id)
                {
                        // search matching crypto identity containing the certificates
                        for (int j = 0; j < number_identitities; j++)
                        {
                                if (identity[j].id == profile[i].crypto_identity_id)
                                {
                                        LOG_DEBUG("found crypto configuration for crypto id: %d",
                                                  ep_id);
                                        ret = create_endpoint_config(&identity[j], &profile[i], ep);
                                        if (ret < 0)
                                        {
                                                LOG_DEBUG("can't init endpoint");
                                                return -1;
                                        }
                                        return 0;
                                }
                        }
                }
        }
        return -1;
}

int stop_application(Kritis3mApplications* appl)
{
        int ret = 0;
        int appl_id = -1;
        if (appl == NULL)
                goto error_occured;

        appl_id = appl->id;

        if (appl->state == false)
        {
                LOG_WARN("application with application id %d is already offline", appl_id);
        }
        else
        {
                switch (appl->type)
                {
                case TLS_FORWARD_PROXY:
                        {
                                ret = tls_proxy_stop_mgmt_id(appl_id);
                                if (ret < 0)
                                {
                                        LOG_ERROR("stop request for tls forward proxy with appl_id "
                                                  "%d failed. STOP Request failed",
                                                  appl_id);
                                        goto error_occured;
                                }
                                break;
                        }
                case TLS_REVERSE_PROXY:
                        {
                                ret = tls_proxy_stop_mgmt_id(appl_id);
                                if (ret < 0)
                                {
                                        LOG_ERROR("stop request for tls reverse proxy with appl_id "
                                                  "%d failed. STOP Request failed",
                                                  appl_id);
                                        goto error_occured;
                                }
                                break;
                        }
                case ECHO_SERVER:
                        {
                                ret = echo_server_terminate();
                                if (ret < 0)
                                {
                                        LOG_ERROR("stop request for echo server with appl_id %d "
                                                  "failed. STOP Request failed",
                                                  appl_id);
                                        goto error_occured;
                                }
                                break;
                        }
                case TCP_CLIENT_STDIN_BRIDGE:
                        {
                                ret = tcp_client_stdin_bridge_terminate();
                                if (ret < 0)
                                {
                                        LOG_ERROR("stop request for tcp_client_stdin_bridge with "
                                                  "appl_id %d failed. STOP Request failed",
                                                  appl_id);
                                        goto error_occured;
                                }
                                break;
                        }
                case UNDEFINED:
                        {
                                LOG_WARN("cant stop application: Unknown application type with "
                                         "appl_id %d ",
                                         appl_id);
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

// whitelist lookup if client is trusworthy
int client_matches_trusted_client(TrustedClients* trusted_client, struct sockaddr* connecting_client)
{

        // Check IP address and port
        Kritis3mSockaddr* trusted_addr = &trusted_client->trusted_client;
        struct sockaddr* trusted_sockaddr = &trusted_addr->sockaddr;

        // If trusted IP is INADDR_ANY or IN6ADDR_ANY_INIT, all IPs are allowed
        if (trusted_sockaddr->sa_family == AF_INET)
        {
                struct sockaddr_in* trusted_in = &trusted_addr->sockaddr_in;
                struct sockaddr_in* conn_in = (struct sockaddr_in*) connecting_client;

                if (trusted_in->sin_addr.s_addr == INADDR_ANY)
                {
                        // If port is 0, all ports are allowed
                        if (trusted_in->sin_port == 0 || trusted_in->sin_port == conn_in->sin_port)
                        {
                                return 0;
                        }
                }
                else
                {
                        // Check both IP and port
                        if (trusted_in->sin_addr.s_addr == conn_in->sin_addr.s_addr &&
                            (trusted_in->sin_port == 0 || trusted_in->sin_port == conn_in->sin_port))
                        {
                                return 0;
                        }
                }
        }
        else if (trusted_sockaddr->sa_family == AF_INET6)
        {
                struct sockaddr_in6* trusted_in6 = &trusted_addr->sockaddr_in6;
                struct sockaddr_in6* conn_in6 = (struct sockaddr_in6*) connecting_client;

                // Check for IN6ADDR_ANY_INIT
                if (memcmp(&trusted_in6->sin6_addr, &in6addr_any, sizeof(struct in6_addr)) == 0)
                {
                        // If port is 0, all ports are allowed
                        if (trusted_in6->sin6_port == 0 || trusted_in6->sin6_port == conn_in6->sin6_port)
                        {
                                return 0;
                        }
                }
                else
                {
                        // Check both IP and port
                        if (memcmp(&trusted_in6->sin6_addr,
                                   &conn_in6->sin6_addr,
                                   sizeof(struct in6_addr)) == 0 &&
                            (trusted_in6->sin6_port == 0 ||
                             trusted_in6->sin6_port == conn_in6->sin6_port))
                        {
                                return 0;
                        }
                }
        }
        return -1;
}

int stop_application_service(struct application_manager* application_manager)
{

        int ret = 0;
        int number_applications = -1;
        Kritis3mApplications* appls = NULL;
        Kritis3mApplications* appl = NULL;

        if (application_manager == NULL)
                return 0;

        appls = application_manager->configuration->applications;
        number_applications = application_manager->configuration->number_applications;

        for (int i = 0; i < number_applications; i++)
        {
                appl = &appls[i];
                ret = stop_application(appl);
                if (ret < 0)
                {
                        LOG_ERROR("can't stop appl with appl id %d", appl->id);
                }
        }
        application_manager->initialized = false;
        return ret;
}

// cleanup function
void cleanup_application_manager(void)
{
        int ret = 0;
        manager.initialized = false;
        if (manager.configuration != NULL)
                manager.configuration = NULL;
        manager.management_pair[THREAD_EXT] = -1;
        manager.management_pair[THREAD_INT] = -1;
        poll_set_init(&manager.notifier);
        pthread_attr_destroy(&manager.thread_attr);
}