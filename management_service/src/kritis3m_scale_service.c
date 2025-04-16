#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include "asl.h"
#include "configuration_manager.h"
#include "control_plane_conn.h"
#include "logging.h"
#include "networking.h"
#include "pki_client.h"
#include "poll_set.h"

#include "kritis3m_application_manager.h"
#include "kritis3m_scale_service.h"

LOG_MODULE_CREATE(kritis3m_service);

#define SIMULTANIOUS_REQs 5
#define ENROLL_BUFFER_SIZE 2000
#define REENROLL_BUFFER_SIZE 2000
#define DISTRIBUTION_BUFFER_SIZE 3000
#define POLICY_RESP_BUFFER_SIZE 1000
#define HEARTBEAT_REQ_BUFFER_SIZE 1000
#define HELLO_INTERVAL_SEC 10 // Send hello message every 60 seconds

// main kritis3m_service module type
struct kritis3m_service
{
        bool initialized;
        int management_socket[2];
        pthread_t mainthread;
        pthread_attr_t thread_attr;
        poll_set pollfd;
        asl_endpoint_configuration management_endpoint_config;
        asl_endpoint* client_endpoint;
        int hello_timer_fd; // File descriptor for the hello timer
        bool timer_initialized;
};

struct dataplane_update_coordinator
{
        int management_socket[2];
        int timeout_s;
        bool initialized;
        enum apply_states state;

        struct application_manager_config app_config;
        struct hardware_configs hw_configs;

        // will be deleted
        pthread_t mainthread;
        // will be deleted
        pthread_attr_t thread_attr;
};

// ipc services
enum service_message_type
{
        SVC_MSG_RESPONSE,
        SVC_MSG_KRITIS3M_SERVICE_STOP,
        SVC_MSG_APPLICATION_MANGER_STATUS_REQ,

        SVC_MSG_CTRLPLANE_CERT_GET_REQ, // start controlplane est transaction
        SVC_MSG_DATAPLANE_CERT_GET_REQ, // start dataplane est transaction

        SVC_RELOAD_DATAPLANE,    // new dataplane certificates
        SVC_RELOAD_CONTROLPLANE, // new control plane certificate

        SVC_MSG_DATAPLANE_CONFIG_APPLY_REQ, // new dataplane config, start update coordinator thread
} __attribute__((aligned(4)));

/**
 * @brief Represents a message used for IPC communication between internal threads
 *        of the `kritis3m_scale_service` module.
 */
typedef struct service_message
{
        enum service_message_type msg_type;
        union kritis3m_service_payload
        {
                int32_t return_code;
                struct appl_manager_status
                {
                        ApplicationManagerStatus status;
                } appl_status;
                struct cert_apply_req
                {
                        enum CERT_TYPE cert_type;
                        bool timeout;
                } cert_apply;
        } payload;
} service_message;

/*------------------------ FORWARD DECLARATION --------------------------------*/
int respond_with(int socket, enum MSG_RESPONSE_CODE response_code);
ManagementReturncode handle_svc_message(int socket, service_message* msg, int cfg_id, int version_number);
// init
void* kritis3m_service_main_thread(void* arg);
// http
void cleanup_kritis3m_service();
// timer
static int init_hello_timer(struct kritis3m_service* svc);

// coordinator for dataplane updates
void* handle_dataplane_apply_req(void* arg);

static void cleanup_hello_timer(struct kritis3m_service* svc);
void cleanup_dataplane_update_coordinator(struct dataplane_update_coordinator* update);

// transaction functions:
int fetch_dataplane_certificate(void* context, char** buffer, size_t* buffer_size);
int fetch_controlplane_certificate(void* context, char** buffer, size_t* buffer_size);
int fetch_dataplane_config(void* context, char** buffer, size_t* buffer_size);
int validate_dataplane_config(void* context, char* config, size_t size);
int validate_dataplane_certificate(void* context, char* config, size_t size);
int validate_controlplane_certificate(void* context, char* config, size_t size);

/* ----------------------- MAIN kritis3m_service module -------------------------*/
static struct kritis3m_service svc = {0};
static struct dataplane_update_coordinator coordinator = {0};

// reset svc
void set_kritis3m_serivce_defaults(struct kritis3m_service* svc)
{
        if (svc == NULL)
                return;
        memset(&svc->management_endpoint_config, 0, sizeof(asl_endpoint_configuration));
        create_socketpair(svc->management_socket);
        pthread_attr_init(&svc->thread_attr);
        pthread_attr_setdetachstate(&svc->thread_attr, PTHREAD_CREATE_JOINABLE);
        poll_set_init(&svc->pollfd);
        svc->timer_initialized = false;
}

/**
 * @brief Starts the `kritis3m_service` module.
 *
 * This function initializes and starts the `kritis3m_service` module using the provided configuration file.
 * The config file is then used to obtain the Kritis3mNodeConfiguration, which contains the initial startup configuration
 *
 * @param[in] config_file Path to the configuration file in json format
 * @param[in] log_level The log level to set for the service (e.g., DEBUG, INFO, ERROR).
 *
 * @return Returns 0 if the service is successfully started, otherwise returns a non-zero error code.
 *
 * @note This function assumes that the necessary dependencies and environment are already in place
 * for the service to be initialized and run.
 */
int start_kritis3m_service(char* config_file, int log_level)
{
        // initializations
        int ret = 0;

        /** -------------- set log level ----------------------------- */
        LOG_LVL_SET(log_level);
        set_kritis3m_serivce_defaults(&svc);
        init_control_plane_conn();
        ret = init_configuration_manager(config_file);
        if (ret < 0)
        {
                LOG_ERROR("Failed to initialize configuration manager");
                goto error_occured;
        }
        asl_configuration asl_config = asl_default_config();
        asl_config.log_level = LOG_LVL_INFO;

        asl_init(&asl_config);
        ret = init_hello_timer(&svc);
        if (ret < 0)
        {
                LOG_ERROR("Failed to initialize hello timer");
                goto error_occured;
        }
        const struct sysconfig* sys_config = get_sysconfig();
        struct control_plane_conn_config_t conn_config = {0};
        conn_config.serialnumber = sys_config->serial_number;
        conn_config.endpoint_config = sys_config->endpoint_config;
        conn_config.mqtt_broker_host = sys_config->broker_host;

        struct pki_client_config_t config = {
                .serialnumber = sys_config->serial_number,
                .host = sys_config->est_host,
                .port = sys_config->est_port,
                .endpoint_config = sys_config->endpoint_config,
        };

        uint8_t* cert_buffer;
        size_t cert_buf_size;
        // start example transaction to get new control plane certificate
        // get_blocking_cert(&config, CERT_TYPE_CONTROLPLANE, true, (char**) &cert_buffer, &cert_buf_size);
        // write_file("/tmp/controlplane_cert.pem", cert_buffer, cert_buf_size, false);

        // if (sys_config->controlplane_cert_active == ACTIVE_ONE)
        // {
        //         LOG_INFO("control plane is not bootsrapped yet, we request new certificates");
        //         // ret = cert_request(&config, CERT_TYPE_CONTROLPLANE, true,
        //         // controlplane_set_certificate); if (ret < 0)
        //         // {
        //         //         LOG_ERROR("Failed to bootstrap control plane during initialization, "
        //         //                   "shutting down!");
        //         //         goto error_occured;
        //         // }

        //         ret = get_blocking_cert(&config,
        //                                 CERT_TYPE_CONTROLPLANE,
        //                                 true,
        //                                 (char**) &cert_buffer,
        //                                 &cert_buf_size);
        //         write_file("/tmp/controlplane_cert.pem", cert_buffer, cert_buf_size, false);
        //         free(cert_buffer);
        // }

        // if (sys_config->dataplane_cert_active == ACTIVE_ONE)
        // {
        //         LOG_INFO("dataplane is not bootsrapped yet, we request new certificates");
        //         // ret = cert_request(&config, CERT_TYPE_DATAPLANE, true,
        //         // dataplane_set_certificate); if (ret < 0)
        //         // {
        //         //         LOG_ERROR("Failed to bootstrap dataplane during initialization, "
        //         //                   "shutting down!");
        //         //         goto error_occured;
        //         // }

        //         ret = get_blocking_cert(&config,
        //                                 CERT_TYPE_DATAPLANE,
        //                                 true,
        //                                 (char**) &cert_buffer,
        //                                 &cert_buf_size);
        //         write_file("/tmp/dataplane_cert.pem", cert_buffer, cert_buf_size, false);
        //         free(cert_buffer);
        // }

        start_control_plane_conn(&conn_config);

        // 6. prepare hardware
        svc.initialized = true;

        // 7. start management application
        ret = pthread_create(&svc.mainthread, &svc.thread_attr, kritis3m_service_main_thread, &svc);
        if (ret < 0)
        {
                LOG_ERROR("can't create kritis3m_service thread");
                goto error_occured;
        }

        return 0;
error_occured:
        LOG_INFO("exit kritis3m_service");
        stop_application_manager();
        cleanup_kritis3m_service();
        return ret;
}

void* kritis3m_service_main_thread(void* arg)
{
        start_application_manager();

        enum appl_state
        {
                APPLICATION_MANAGER_OFF,
                APPLICATION_MANAGER_ENABLED,
        };

        LOG_INFO("kritis3m_service started");

        struct kritis3m_service* svc = (struct kritis3m_service*) arg;
        if (svc == NULL)
                goto terminate;

        int hb_interval_sec = 10;
        int ret = 0;
        int cfg_id = -1;
        int version_number = -1;
        ManagementReturncode retval = MGMT_OK;

        asl_endpoint_configuration* ep_cfg = &svc->management_endpoint_config;

        ret = poll_set_add_fd(&svc->pollfd, svc->management_socket[THREAD_INT], POLLIN | POLLERR);
        if (ret < 0)
        {
                LOG_ERROR("cant add fd to to pollset, shutting down management service");
                goto terminate;
        }

        // Add hello timer to poll set
        ret = poll_set_add_fd(&svc->pollfd, svc->hello_timer_fd, POLLIN | POLLERR);
        if (ret < 0)
        {
                LOG_ERROR("Failed to add hello timer to poll set");
                goto terminate;
        }

        while (1)
        {
                ret = poll(svc->pollfd.fds, svc->pollfd.num_fds, -1);

                if (ret == -1)
                {
                        LOG_ERROR("poll error: %d", errno);
                        continue;
                }
                if (ret == 0)
                {
                        continue;
                }
                for (int i = 0; i < svc->pollfd.num_fds; i++)
                {
                        int fd = svc->pollfd.fds[i].fd;
                        short event = svc->pollfd.fds[i].revents;

                        if (event == 0)
                                continue;

                        /* Check management socket */
                        if (fd == svc->management_socket[THREAD_INT])
                        {
                                if (event & POLLIN)
                                {
                                        service_message req = {0};
                                        ManagementReturncode
                                                return_code = handle_svc_message(svc->management_socket[THREAD_INT],
                                                                                 &req,
                                                                                 cfg_id,
                                                                                 version_number);

                                        if (return_code == MGMT_THREAD_STOP)
                                        {
                                                poll_set_remove_fd(&svc->pollfd,
                                                                   svc->management_socket[THREAD_INT]);
                                                goto terminate;
                                        }
                                        else if (return_code < 0)
                                        {
                                                poll_set_remove_fd(&svc->pollfd,
                                                                   svc->management_socket[THREAD_INT]);
                                                closesocket(svc->management_socket[THREAD_INT]);
                                                closesocket(svc->management_socket[THREAD_EXT]);
                                                LOG_ERROR("error occured in handling service "
                                                          "message");
                                                goto terminate;
                                        }
                                }
                        }
                        /* Check hello timer */
                        else if (fd == svc->hello_timer_fd)
                        {
                                if (event & POLLIN)
                                {
                                        uint64_t exp;
                                        ssize_t s = read(svc->hello_timer_fd, &exp, sizeof(uint64_t));
                                        if (s == sizeof(uint64_t))
                                        {
                                                enum MSG_RESPONSE_CODE ret = send_hello_message(true);
                                                if (ret != MSG_OK)
                                                {
                                                        LOG_ERROR("Failed to send hello message: "
                                                                  "%d",
                                                                  ret);
                                                }
                                        }
                                }
                                else if (event & POLLERR)
                                {
                                        LOG_ERROR("hello timer error");
                                }
                        }
                }
        }

terminate:
        LOG_DEBUG("Leaving kritis3m_service main thread");

        stop_application_manager();
        cleanup_kritis3m_service();
        pthread_detach(pthread_self());
        return NULL;
}

enum MSG_RESPONSE_CODE stop_kritis3m_service()
{

        int socket = -1;
        int ret = 0;
        service_message request = {0};

        if ((!svc.initialized) || (svc.management_socket[THREAD_EXT] < 0))
        {
                LOG_ERROR("Kritis3m_service is not initialized");
                ret = -1;
                return ret;
        }

        request.msg_type = SVC_MSG_KRITIS3M_SERVICE_STOP;
        enum MSG_RESPONSE_CODE retval = external_management_request(socket, &request, sizeof(request));

        if (svc.mainthread)
        {
                pthread_join(svc.mainthread, NULL);
                svc.mainthread = 0;
        }

        // ggf. cleanup

        return retval;
}

int svc_respond_with(int socket, enum MSG_RESPONSE_CODE response_code)
{
        service_message response = {0};
        response.msg_type = SVC_MSG_RESPONSE;
        response.payload.return_code = response_code;
        size_t retries = 2;
        return sockpair_write(socket, &response, sizeof(response), &retries);
}

// cfg_id and version number are temporary arguments and will be cleaned up after the testing
ManagementReturncode handle_svc_message(int socket, service_message* msg, int cfg_id, int version_number)
{
        int ret = 0;
        // to internal context
        ManagementReturncode return_code = MGMT_OK;
        // to external context
        enum MSG_RESPONSE_CODE response_code = MSG_OK;
        ret = sockpair_read(socket, msg, sizeof(service_message));
        if (ret < 0)
                goto error_occured;

        switch (msg->msg_type)
        {
        case SVC_MSG_APPLICATION_MANGER_STATUS_REQ:
                {
                        LOG_INFO("Received application manager status request");
                        response_code = MSG_OK;
                        break;
                }
        case SVC_MSG_KRITIS3M_SERVICE_STOP:
                {
                        LOG_INFO("SVC STOP: ");
                        LOG_INFO("Kritis3m service: Received Stop Request");
                        response_code = MSG_OK;
                        return_code = MGMT_THREAD_STOP;
                        break;
                }
        case SVC_MSG_DATAPLANE_CERT_GET_REQ:
                {
                        LOG_INFO("Received data plane certificate get request");
                        response_code = MSG_OK;
                        // cert_request(endpoint_config, config, CERT_TYPE_DATAPLANE, callback);
                        svc_respond_with(socket, response_code);
                        if (ret < 0)
                        {
                                LOG_ERROR("Failed to send dataplane cert get request");
                                return_code = MGMT_ERR;
                        }
                        struct config_transaction transaction = {0};
                        ret = init_config_transaction(&transaction,
                                                      CONFIG_DATAPLANE,
                                                      &coordinator,
                                                      fetch_dataplane_certificate,
                                                      validate_dataplane_certificate,
                                                      NULL);
                        ret = start_config_transaction(&transaction);
                        if (ret < 0)
                        {
                                LOG_ERROR("Failed to start dataplane transaction");
                                goto error_occured;
                        }
                        break;
                }
        case SVC_MSG_CTRLPLANE_CERT_GET_REQ:
                {
                        LOG_INFO("Received control plane certificate apply request");
                        // LOG_INFO("Buffer length: %d", msg->payload.cert_apply.buffer_len);
                        response_code = MSG_OK;
                        svc_respond_with(socket, response_code);
                        // start ctrlplane transaction
                        struct config_transaction transaction = {0};
                        ret = init_config_transaction(&transaction,
                                                      CONFIG_CONTROLPLANE,
                                                      &coordinator,
                                                      fetch_controlplane_certificate,
                                                      validate_controlplane_certificate,
                                                      NULL);
                        ret = start_config_transaction(&transaction);
                        if (ret < 0)
                        {
                                LOG_ERROR("Failed to start controlplane transaction");
                                goto error_occured;
                        }
                        break;
                }
        case SVC_MSG_DATAPLANE_CONFIG_APPLY_REQ:
                {
                        LOG_INFO("Received data plane config apply request");
                        svc_respond_with(socket, MSG_OK);
                        cleanup_dataplane_update_coordinator(&coordinator);

                        struct config_transaction* transaction = malloc(
                                sizeof(struct config_transaction));
                        memset(transaction, 0, sizeof(struct config_transaction));
                        ret = init_config_transaction(transaction,
                                                      CONFIG_DATAPLANE,
                                                      &coordinator,
                                                      fetch_dataplane_config,
                                                      validate_dataplane_config,
                                                      NULL);
                        ret = start_config_transaction(transaction);
                        if (ret < 0)
                        {
                                LOG_ERROR("Failed to start dataplane transaction");
                                goto error_occured;
                        }

                        break;
                }
        case SVC_MSG_RESPONSE:
                {
                        LOG_INFO("received response: %d", msg->payload.return_code);
                        return_code = MGMT_OK;
                        return return_code;
                        break;
                }
        default:
                LOG_WARN("message type %d, not covered", msg->msg_type);
                return_code = MGMT_ERR;
                return return_code;
                break;
        }
        return return_code;

error_occured:
        return_code = MGMT_ERR;
        svc_respond_with(socket, MSG_ERROR);
        LOG_ERROR("handle_svc_message error: %d", ret);
        return ret;
}

void cleanup_kritis3m_service()
{
        svc.initialized = false;
        cleanup_hello_timer(&svc);
}

enum MSG_RESPONSE_CODE dataplane_config_apply_send_status(struct policy_status_t* status)

{
        if (!coordinator.initialized || coordinator.management_socket[THREAD_EXT] < 0)
        {
                LOG_ERROR("coordinator is not initialized");
                return MSG_ERROR;
        }
        LOG_INFO("sending status to coordinator from module: %d", status->module);
        struct policy_status_t msg = {0};
        msg.module = status->module;
        msg.msg = status->msg;
        msg.state = status->state;
        return external_management_request(coordinator.management_socket[THREAD_EXT],
                                           &msg,
                                           sizeof(struct policy_status_t));
}

enum MSG_RESPONSE_CODE ctrlplane_cert_get_req()
{
        if (!svc.initialized || svc.management_socket[THREAD_EXT] < 0)
        {
                LOG_ERROR("Kritis3m_service is not initialized");
                return MSG_ERROR;
        }

        service_message request = {0};
        request.msg_type = SVC_MSG_CTRLPLANE_CERT_GET_REQ;
        return external_management_request(svc.management_socket[THREAD_EXT], &request, sizeof(request));
}

enum MSG_RESPONSE_CODE dataplane_cert_get_req()
{
        if (!svc.initialized || svc.management_socket[THREAD_EXT] < 0)
        {
                LOG_ERROR("Kritis3m_service is not initialized");
                return MSG_ERROR;
        }

        service_message request = {0};
        request.msg_type = SVC_MSG_DATAPLANE_CERT_GET_REQ;
        return external_management_request(svc.management_socket[THREAD_EXT], &request, sizeof(request));
}

enum MSG_RESPONSE_CODE dataplane_config_apply_req()
{
        if (!svc.initialized || svc.management_socket[THREAD_EXT] < 0)
        {
                LOG_ERROR("Kritis3m_service is not initialized");
                return MSG_ERROR;
        }

        service_message request = {0};
        request.msg_type = SVC_MSG_DATAPLANE_CONFIG_APPLY_REQ;
        return external_management_request(svc.management_socket[THREAD_EXT], &request, sizeof(request));
}

static int init_hello_timer(struct kritis3m_service* svc)
{
        struct itimerspec its;
        int ret;

        // Create timer file descriptor
        svc->hello_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (svc->hello_timer_fd == -1)
        {
                LOG_ERROR("Failed to create hello timer: %s", strerror(errno));
                return -1;
        }

        // Set timer interval
        its.it_value.tv_sec = HELLO_INTERVAL_SEC;
        its.it_value.tv_nsec = 0;
        its.it_interval.tv_sec = HELLO_INTERVAL_SEC;
        its.it_interval.tv_nsec = 0;

        // Start timer
        ret = timerfd_settime(svc->hello_timer_fd, 0, &its, NULL);
        if (ret != 0)
        {
                LOG_ERROR("Failed to start hello timer: %s", strerror(errno));
                close(svc->hello_timer_fd);
                return -1;
        }

        svc->timer_initialized = true;
        LOG_INFO("Hello timer initialized successfully");
        return 0;
}

static void cleanup_hello_timer(struct kritis3m_service* svc)
{
        if (svc->timer_initialized)
        {
                close(svc->hello_timer_fd);
                svc->timer_initialized = false;
                LOG_INFO("Hello timer cleaned up");
        }
}

// used by transaction mechanism
int fetch_dataplane_certificate(void* context, char** buffer, size_t* buffer_size)
{
        int ret = 0;
        if (!context || !buffer || !buffer_size)
                goto cleanup;
        struct pki_client_config_t* pki_clinet_config = (struct pki_client_config_t*) context;
        if ((ret = get_blocking_cert(pki_clinet_config, CERT_TYPE_DATAPLANE, true, buffer, buffer_size)) <
            0)
        {
                LOG_ERROR("error occured in fetch dataplane certificate, with ret: %d", ret);
                goto cleanup;
        }
        return ret;

cleanup:
        ret = -1;
        LOG_ERROR("error occured in fetch dataplane certificate");
        if (buffer && !(*buffer))
        {
                free(*buffer);
                *buffer = NULL;
        }
        if (buffer_size)
                *buffer_size = 0;
        return ret;
}

int fetch_controlplane_certificate(void* context, char** buffer, size_t* buffer_size)
{
        int ret = 0;
        if (!context || !buffer || !buffer_size)
                goto cleanup;
        struct pki_client_config_t* pki_clinet_config = (struct pki_client_config_t*) context;
        if ((ret = get_blocking_cert(pki_clinet_config, CERT_TYPE_CONTROLPLANE, true, buffer, buffer_size)) <
            0)
        {
                LOG_ERROR("error occured in fetch controlplane certificate, with ret: %d", ret);
                goto cleanup;
        }
        return ret;

cleanup:
        ret = -1;
        LOG_ERROR("error occured in fetch controlplane certificate");
        if (buffer && !(*buffer))
        {
                free(*buffer);
                *buffer = NULL;
        }
        if (buffer_size)
                *buffer_size = 0;
        return ret;
}
struct dataplane_update_t
{
        struct application_manager_config app_config;
        struct hardware_configs hw_configs;
        enum apply_states state;
        int management_socket[2];
        int timeout_s;
        bool initialized;
};

/**
 * @brief this function is rather hacky, since parsing and storing the config is done in the
 * coordinator, but the transaction mechanism should be kept. addionally, the config is not fetched
 * rather it is obtained via a push message via mqtt and is not directly requested
 * @param buffer: is not used
 * @param buffer_size: is not used
 * @return: 0 on success, -1 on failure
 */
int fetch_dataplane_config(void* context, char** buffer, size_t* buffer_size)
{
        int ret = 0;
        struct dataplane_update_coordinator* update = NULL;
        if (!context)
                goto cleanup;
        update = (struct dataplane_update_coordinator*) context;
        ret = get_application_inactive(&update->app_config, &update->hw_configs);
        if (ret < 0)
        {
                LOG_ERROR("Failed to get dataplane update");
                goto cleanup;
        }
        return ret;

cleanup:
        ret = -1;
        LOG_ERROR("error occured in fetch dataplane config");
        if (buffer && !(*buffer))
        {
                free(*buffer);
                *buffer = NULL;
        }
        // free update
        if (update)
        {
                cleanup_hardware_configs(&update->hw_configs);
                cleanup_application_config(&update->app_config);
                if (update->management_socket[THREAD_INT] != -1)
                        closesocket(update->management_socket[THREAD_INT]);
                if (update->management_socket[THREAD_EXT] != -1)
                        closesocket(update->management_socket[THREAD_EXT]);
                update = NULL;
        }

        if (buffer_size)
                *buffer_size = 0;
        return ret;
}

/**
 * @brief Sends a policy status message to the coordinator
 * @param msg The policy status message to send
 * @return MSG_RESPONSE_CODE indicating success or failure
 */
static enum MSG_RESPONSE_CODE send_policy_status_message(struct policy_status_t* msg)
{
        if (!msg)
        {
                LOG_ERROR("Invalid policy status message");
                return MSG_ERROR;
        }
        return send_policy_status(msg);
}

/**
 * @brief Handles a policy status update from a module
 * @param update The update coordinator context
 * @param msg The received policy status message
 * @return 0 on success, -1 on failure
 */
static int handle_policy_status_update(struct dataplane_update_coordinator* update,
                                       struct policy_status_t* msg)
{
        if (!update || !msg)
        {
                LOG_ERROR("Invalid arguments");
                return -1;
        }

        enum apply_states requested_state = msg->state;
        enum module caller_module = msg->module;
        char* msg_str = (msg->msg) ? msg->msg : "No message";

        switch (requested_state)
        {
        case UPDATE_ERROR:
                LOG_ERROR("Coordinator received error message from %d module: %s", caller_module, msg_str);
                send_policy_status_message(msg);
                return -1;

        case UPDATE_ROLLBACK:
                LOG_INFO("Coordinator: State UPDATE_ROLLBACK");
                if (update->state == UPDATE_APPLIED)
                {
                        application_manager_rollback();
                }
                return 1; // Signal to finish

        case UPDATE_APPLYREQUEST:
                LOG_INFO("Coordinator: State UPDATE_APPLYREQUEST");
                if (change_application_config(&update->app_config, &update->hw_configs) < 0)
                {
                        struct policy_status_t error_msg = {.module = UPDATE_COORDINATOR,
                                                            .state = UPDATE_ERROR,
                                                            .msg = "Internal error"};
                        send_policy_status_message(&error_msg);
                        return -1;
                }
                break;

        case UPDATE_APPLIED:
                LOG_INFO("Coordinator: State UPDATE_APPLIED");
                update->state = UPDATE_APPLIED;
                send_policy_status_message(msg);
                break;

        case UPDATE_ACK:
                LOG_INFO("Coordinator: State UPDATE_ACK");
                ack_dataplane_update();
                return 1; // Signal to finish

        default:
                LOG_ERROR("Coordinator: Invalid module state");
                return -1;
        }
        return 0;
}

/**
 * @brief Validates a dataplane configuration update
 * @param context The update coordinator context
 * @param config Unused parameter (part of interface)
 * @param size Unused parameter (part of interface)
 * @return 0 on success, -1 on failure
 *
 * This function implements the validation process for dataplane configuration updates.
 * It follows a state machine pattern to handle different stages of the update process.
 * The function is part of a transaction interface, hence the unused parameters.
 */
int validate_dataplane_config(void* context, char* config, size_t size)
{
        if (!context)
        {
                LOG_ERROR("Invalid context");
                return -1;
        }

        struct dataplane_update_coordinator* update = (struct dataplane_update_coordinator*) context;
        int ret = 0;

        // Initialize update coordinator
        if ((ret = create_socketpair(update->management_socket)) < 0)
        {
                LOG_ERROR("Failed to create socketpair");
                goto cleanup;
        }

        update->initialized = true;
        update->state = UPDATE_APPLICABLE;
        // set 20 seconds timeout if not set
        update->timeout_s = (update->timeout_s < 0) ? update->timeout_s : 20;

        struct policy_status_t policy_msg = {.module = UPDATE_COORDINATOR,
                                             .state = update->state,
                                             .msg = NULL};

        // Enable sync and send initial status
        if ((ret = enable_sync(true)) < 0)
        {
                LOG_ERROR("Failed to enable sync");
                goto cleanup;
        }

        if (send_policy_status_message(&policy_msg) < 0)
        {
                LOG_ERROR("Failed to send initial policy status");
                goto cleanup;
        }

        // Setup polling
        struct pollfd update_pollfd = {.fd = update->management_socket[THREAD_INT],
                                       .events = POLLIN | POLLERR,
                                       .revents = 0};

        // Main validation loop
        int max_iterations = 3;
        while (max_iterations--)
        {
                ret = poll(&update_pollfd, 1, update->timeout_s * 1000);
                if (ret < 0)
                {
                        LOG_ERROR("Poll error: %d", errno);
                        goto cleanup;
                }

                if (ret == 0)
                {
                        LOG_ERROR("Timeout occurred");
                        policy_msg.state = UPDATE_ERROR;
                        policy_msg.msg = "Timeout occurred";
                        send_policy_status_message(&policy_msg);
                        if (update->state == UPDATE_APPLIED)
                        {
                                application_manager_rollback();
                        }
                        goto cleanup;
                }

                if (update_pollfd.revents & POLLERR)
                {
                        LOG_ERROR("Poll error event: %d", errno);
                        policy_msg.state = UPDATE_ERROR;
                        policy_msg.msg = "Internal error";
                        send_policy_status_message(&policy_msg);
                        if (update->state == UPDATE_APPLIED)
                        {
                                application_manager_rollback();
                        }
                        goto cleanup;
                }

                if (update_pollfd.revents & POLLIN)
                {
                        struct policy_status_t msg = {0};
                        if (sockpair_read(update->management_socket[THREAD_INT],
                                          &msg,
                                          sizeof(struct policy_status_t)) < 0)
                        {
                                LOG_ERROR("Failed to read message: %d", errno);
                                goto cleanup;
                        }

                        respond_with(update->management_socket[THREAD_INT], MSG_OK);
                        ret = handle_policy_status_update(update, &msg);
                        if (ret < 0)
                        {
                                goto cleanup;
                        }
                        else if (ret > 0)
                        {
                                goto finish;
                        }
                }
        }

finish:
        enable_sync(false);
        cleanup_dataplane_update_coordinator(update);
        return 0;

cleanup:
        enable_sync(false);
        cleanup_dataplane_update_coordinator(update);
        return -1;
}

void cleanup_dataplane_update_coordinator(struct dataplane_update_coordinator* update)
{
        if (!update)
                return;
        cleanup_hardware_configs(&update->hw_configs);
        cleanup_application_config(&update->app_config);
        if (update->management_socket[THREAD_INT] != -1)
                closesocket(update->management_socket[THREAD_INT]);
        if (update->management_socket[THREAD_EXT] != -1)
                closesocket(update->management_socket[THREAD_EXT]);
        update->initialized = false;
        update->state = UPDATE_ERROR;
        update->management_socket[THREAD_INT] = -1;
        update->management_socket[THREAD_EXT] = -1;
        update->timeout_s = -1;
}

int validate_controlplane_certificate(void* context, char* config, size_t size)
{
        int ret = 0;
        asl_endpoint* endpoint = NULL;
        asl_session* session = NULL;
        int old_chain_buffer_size = 0;
        if (!context || !config || size <= 0)
                goto cleanup;

        struct pki_client_config_t* pki_clinet_config = (struct pki_client_config_t*) context;

        asl_endpoint_configuration ep_cfg =
                {.device_certificate_chain =
                         {
                                 .buffer = (uint8_t* const) config,
                                 .size = size,
                         },
                 .private_key = pki_clinet_config->endpoint_config->private_key,
                 .root_certificate = pki_clinet_config->endpoint_config->root_certificate,
                 .key_exchange_method = pki_clinet_config->endpoint_config->key_exchange_method,
                 .ciphersuites = pki_clinet_config->endpoint_config->ciphersuites,
                 .mutual_authentication = true,
                 .pkcs11 = pki_clinet_config->endpoint_config->pkcs11,
                 .psk = pki_clinet_config->endpoint_config->psk};
        // create endpoint
        endpoint = asl_setup_client_endpoint(&ep_cfg);
        if (!endpoint)
        {
                LOG_ERROR("failed to create asl endpoint");
                goto cleanup;
        }
        // session = asl_create_session(endpoint, svc->management_socket[THREAD_INT]);
        // if (!session)
        // {
        //         LOG_ERROR("failed to create asl session");
        //         goto cleanup;
        // }
        // ret = asl_handshake(session);
        // if (ret != ASL_SUCCESS)
        // {
        //         LOG_ERROR("failed to handshake with asl session");
        //         goto cleanup;
        // }

        return ret;
cleanup:
        ret = -1;
        if (endpoint)
        {
                asl_free_endpoint(endpoint);
                endpoint = NULL;
        }
        if (session)
        {
                asl_close_session(session);
                session = NULL;
        }
        LOG_ERROR("error occured in validate controlplane certificate");
        return ret;
}

int validate_dataplane_certificate(void* context, char* config, size_t size)
{
        int ret = 0;
        asl_endpoint* endpoint = NULL;
        asl_session* session = NULL;
        int old_chain_buffer_size = 0;
        if (!context || !config || size <= 0)
                goto cleanup;
        struct pki_client_config_t* pki_clinet_config = (struct pki_client_config_t*) context;

        asl_endpoint_configuration ep_cfg =
                {.device_certificate_chain =
                         {
                                 .buffer = (uint8_t* const) config,
                                 .size = size,
                         },
                 .private_key = pki_clinet_config->endpoint_config->private_key,
                 .root_certificate = pki_clinet_config->endpoint_config->root_certificate,
                 .key_exchange_method = pki_clinet_config->endpoint_config->key_exchange_method,
                 .ciphersuites = pki_clinet_config->endpoint_config->ciphersuites,
                 .mutual_authentication = true,
                 .pkcs11 = pki_clinet_config->endpoint_config->pkcs11,
                 .psk = pki_clinet_config->endpoint_config->psk};
        // create endpoint
        endpoint = asl_setup_client_endpoint(&ep_cfg);
        if (!endpoint)
        {
                LOG_ERROR("failed to create asl endpoint");
                goto cleanup;
        }
        // session = asl_create_session(endpoint, svc->management_socket[THREAD_INT]);
        // if (!session)
        // {
        //         LOG_ERROR("failed to create asl session");
        //         goto cleanup;
        // }
        // ret = asl_handshake(session);
        // if (ret != ASL_SUCCESS)
        // {
        //         LOG_ERROR("failed to handshake with asl session");
        //         goto cleanup;
        // }

        return ret;
cleanup:
        ret = -1;
        if (endpoint)
        {
                asl_free_endpoint(endpoint);
                endpoint = NULL;
        }
        if (session)
        {
                asl_close_session(session);
                session = NULL;
        }
        LOG_ERROR("error occured in validate controlplane certificate");
        return ret;
}
