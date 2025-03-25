#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include "configuration_manager.h"
#include "control_plane_conn.h"
#include "logging.h"
#include "networking.h"
#include "pki_client.h"
#include "poll_set.h"

#include "cJSON.h"
#include "http_client.h"

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

struct node_update_coordinator
{
        int update_socket[2];
        pthread_t mainthread;
        pthread_attr_t thread_attr;
        int timeout_s;
        bool initialized;
};

// ipc services
enum service_message_type
{
        SVC_MSG_RESPONSE,
        SVC_MSG_KRITIS3M_SERVICE_STOP,
        SVC_MSG_APPLICATION_MANGER_STATUS_REQ,
        SVC_MSG_CTRLPLANE_CERT_GET_REQ,
        SVC_MSG_DATAPLANE_CERT_GET_REQ,
        SVC_MSG_DATAPLANE_CERT_APPLY_REQ,
        SVC_MSG_CTRLPLANE_CERT_APPLY_REQ,
        SVC_MSG_DATAPLANE_CONFIG_APPLY_REQ,
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
                        char* buffer;
                        int buffer_len;
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

/* ----------------------- MAIN kritis3m_service module -------------------------*/
static struct kritis3m_service svc = {0};
static struct node_update_coordinator coordinator = {0};

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
        case SVC_MSG_CTRLPLANE_CERT_GET_REQ:
                {
                        LOG_INFO("Received control plane certificate get request");
                        response_code = MSG_OK;
                        svc_respond_with(socket, response_code);
                        ret = controlplane_cert_request();
                        if (ret < 0)
                        {
                                LOG_ERROR("Failed to send ctrlplane cert get request");
                                return_code = MGMT_ERR;
                        }
                        break;
                }
        case SVC_MSG_DATAPLANE_CERT_GET_REQ:
                {
                        LOG_INFO("Received data plane certificate get request");
                        response_code = MSG_OK;
                        svc_respond_with(socket, response_code);
                        ret = dataplane_cert_request();
                        if (ret < 0)
                        {
                                LOG_ERROR("Failed to send dataplane cert get request");
                                return_code = MGMT_ERR;
                        }
                        break;
                }
        case SVC_MSG_DATAPLANE_CERT_APPLY_REQ:
                {
                        response_code = MSG_OK;
                        svc_respond_with(socket, response_code);
                        break;
                }
        case SVC_MSG_CTRLPLANE_CERT_APPLY_REQ:
                {
                        LOG_INFO("Received control plane certificate apply request");
                        LOG_INFO("Buffer length: %d", msg->payload.cert_apply.buffer_len);
                        response_code = MSG_OK;
                        svc_respond_with(socket, response_code);
                        break;
                }
        case SVC_MSG_DATAPLANE_CONFIG_APPLY_REQ:
                {
                        LOG_INFO("Received data plane config apply request");
                        svc_respond_with(socket, MSG_OK);
                        coordinator.initialized = false;
                        ret = create_socketpair(coordinator.update_socket);
                        if (ret < 0)
                        {
                                LOG_ERROR("Failed to create socketpair");
                                goto error_occured;
                        }
                        coordinator.timeout_s = 10;
                        pthread_attr_init(&coordinator.thread_attr);
                        pthread_create(&coordinator.mainthread,
                                       &coordinator.thread_attr,
                                       handle_dataplane_apply_req,
                                       &coordinator);
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
        return external_management_request(coordinator.update_socket[THREAD_EXT],
                                           status,
                                           sizeof(struct policy_status_t));
}

void* handle_dataplane_apply_req(void* arg)
{
        ManagementReturncode ret;
        coordinator.initialized = true;
        enable_sync(true);

        struct pollfd update_pollfd;
        update_pollfd.fd = coordinator.update_socket[THREAD_INT];
        update_pollfd.events = POLLIN | POLLERR;

        // control plane sends UPDATE_RECEIVED
        if (ret < 0)
        {
                LOG_ERROR("Failed to send status to server");
                goto error_occured;
        }

        struct application_manager_config* app_config = malloc(
                sizeof(struct application_manager_config));
        struct hardware_configs* hw_configs = malloc(sizeof(struct hardware_configs));

        ret = get_application_inactive(app_config, hw_configs);
        if (ret < 0)
        {
                LOG_ERROR("Failed to get dataplane update");
                goto error_occured;
        }

        enum apply_states current_state = UPDATE_APPLICABLE;
        current_state = UPDATE_APPLICABLE;
        struct policy_status_t policy_msg = {0};
        policy_msg.module = UPDATE_COORDINATOR;
        policy_msg.state = UPDATE_APPLICABLE;
        policy_msg.msg = NULL;
        policy_msg.msg_len = 0;
        ret = send_policy_status(&policy_msg);

        while (1)
        {

                if ((ret = poll(&update_pollfd, 1, coordinator.timeout_s * 1000)) >= 0)
                {
                        if (ret == 0)
                        {
                                memset(&policy_msg, 0, sizeof(struct policy_status_t));
                                policy_msg.module = UPDATE_COORDINATOR;
                                policy_msg.state = UPDATE_ERROR;
                                policy_msg.msg = "Timeout occured";
                                policy_msg.msg_len = strlen("Timeout occured. Rollback initiated");
                                send_policy_status(&policy_msg);
                                if (current_state == UPDATE_APPLIED)
                                {
                                        application_manager_rollback();
                                        // respond error and return
                                }
                                send_policy_status(&policy_msg);
                                goto error_occured;
                        }
                        if (ret < 0)
                        {
                                memset(&policy_msg, 0, sizeof(struct policy_status_t));
                                policy_msg.module = UPDATE_COORDINATOR;
                                policy_msg.state = UPDATE_ERROR;
                                policy_msg.msg = "Internal error";
                                policy_msg.msg_len = strlen("Internal error");
                                send_policy_status(&policy_msg);
                                if (current_state == UPDATE_APPLIED)
                                {
                                        application_manager_rollback();
                                        // respond error and return
                                }
                                send_policy_status(&policy_msg);
                                goto error_occured;
                        }
                        if (update_pollfd.revents & POLLIN)
                        {
                                struct policy_status_t msg = {0};
                                int32_t state = sockpair_read(coordinator.update_socket[THREAD_INT],
                                                              &msg,
                                                              sizeof(struct policy_status_t));
                                respond_with(coordinator.update_socket[THREAD_EXT], MSG_OK);

                                enum apply_states requested_state = msg.state;
                                enum module caller_module = msg.module;

                                switch (requested_state)
                                {
                                case UPDATE_ERROR: // application manager
                                        {
                                                send_policy_status(&msg);
                                                goto error_occured;
                                                break;
                                        }
                                case UPDATE_ROLLBACK: // can be only received from control plane
                                        {
                                                if (current_state == UPDATE_APPLIED)
                                                {
                                                        application_manager_rollback();
                                                }
                                                goto finish_dataplane_apply_req;
                                                break;
                                        }
                                case UPDATE_APPLYREQUEST: // can only be received form control plane
                                        {
                                                ret = change_application_config(app_config, hw_configs);
                                                if (ret < 0)
                                                {
                                                        // message couldnt even be processed -> return error
                                                        memset(&policy_msg,
                                                               0,
                                                               sizeof(struct policy_status_t));
                                                        policy_msg.module = UPDATE_COORDINATOR;
                                                        policy_msg.state = UPDATE_ERROR;
                                                        policy_msg.msg = "Internal error";
                                                        policy_msg.msg_len = strlen(
                                                                "Internal error");
                                                        send_policy_status(&policy_msg);
                                                        goto error_occured;
                                                }
                                                break;
                                        }
                                case UPDATE_APPLIED: // can only be received from application manager
                                        {
                                                current_state = UPDATE_APPLIED;
                                                memset(&policy_msg, 0, sizeof(struct policy_status_t));
                                                policy_msg.module = msg.module;
                                                policy_msg.state = UPDATE_APPLIED;
                                                policy_msg.msg = msg.msg;
                                                policy_msg.msg_len = msg.msg_len;
                                                send_policy_status(&policy_msg);
                                                break;
                                        }
                                case UPDATE_ACK:
                                        {
                                                // on restarting system, new config will be used
                                                ack_dataplane_update();
                                                LOG_INFO("Update applied");
                                                goto finish_dataplane_apply_req;
                                        }
                                default:
                                        LOG_ERROR("Invalid module");
                                        goto error_occured;
                                }
                        }
                }

        finish_dataplane_apply_req:
                enable_sync(false);
                coordinator.initialized = false;
                closesocket(coordinator.update_socket[THREAD_INT]);
                closesocket(coordinator.update_socket[THREAD_EXT]);
                coordinator.update_socket[THREAD_INT] = -1;
                coordinator.update_socket[THREAD_EXT] = -1;
                return NULL;

        error_occured:
                enable_sync(false);
                coordinator.initialized = false;
                closesocket(coordinator.update_socket[THREAD_INT]);
                closesocket(coordinator.update_socket[THREAD_EXT]);
                coordinator.update_socket[THREAD_INT] = -1;
                coordinator.update_socket[THREAD_EXT] = -1;
                return NULL;
        }
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

enum MSG_RESPONSE_CODE dataplane_cert_apply_req(char* buffer, int buffer_len)
{
        if (!svc.initialized || svc.management_socket[THREAD_EXT] < 0)
        {
                LOG_ERROR("Kritis3m_service is not initialized");
                return MSG_ERROR;
        }

        if (!buffer || buffer_len <= 0)
        {
                LOG_ERROR("Invalid buffer parameters");
                return MSG_ERROR;
        }

        service_message request = {0};
        request.msg_type = SVC_MSG_DATAPLANE_CERT_APPLY_REQ;
        request.payload.cert_apply.buffer = buffer;
        request.payload.cert_apply.buffer_len = buffer_len;
        return external_management_request(svc.management_socket[THREAD_EXT], &request, sizeof(request));
}

enum MSG_RESPONSE_CODE ctrlplane_cert_apply_req(char* buffer, int buffer_len)
{
        if (!svc.initialized || svc.management_socket[THREAD_EXT] < 0)
        {
                LOG_ERROR("Kritis3m_service is not initialized");
                return MSG_ERROR;
        }

        if (!buffer || buffer_len <= 0)
        {
                LOG_ERROR("Invalid buffer parameters");
                return MSG_ERROR;
        }

        service_message request = {0};
        request.msg_type = SVC_MSG_CTRLPLANE_CERT_APPLY_REQ;
        request.payload.cert_apply.buffer = buffer;
        request.payload.cert_apply.buffer_len = buffer_len;
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
