#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "asl.h"
#include "asl_helper.h"
#include "configuration_manager.h"
#include "control_plane_conn.h"
#include "kritis3m_application_manager.h"
#include "kritis3m_scale_service.h"
#include "kritis3m_pki_common.h"
#include "logging.h"
#include "networking.h"
#include "pki_client.h"
#include "poll_set.h"

LOG_MODULE_CREATE(kritis3m_service);

#define SIMULTANIOUS_REQs 5
#define ENROLL_BUFFER_SIZE 2000
#define REENROLL_BUFFER_SIZE 2000
#define DISTRIBUTION_BUFFER_SIZE 3000
#define POLICY_RESP_BUFFER_SIZE 1000
#define HEARTBEAT_REQ_BUFFER_SIZE 1000
#define HELLO_INTERVAL_SEC 10 // Send hello message every 60 seconds

static int asl_log_level = 1;

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
        struct pki_client_config_t pki_clinet_config;
        bool proxy_reporting_enabled; // Flag to control proxy state reporting
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

struct appl_manager
{
        struct application_manager_config appl_manager;
        struct hardware_configs hw_configs;
};

// ipc services
enum service_message_type
{
        SVC_MSG_RESPONSE,
        SVC_MSG_KRITIS3M_SERVICE_STOP,
        SVC_MSG_APPLICATION_MANGER_STATUS_REQ,

        SVC_MSG_CERT_GET_REQ, // start dataplane est transaction

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
                struct cert_apply_req
                {
                        enum CERT_TYPE cert_type;
                        bool timeout;
                } cert_apply;
                struct cert_req
                {
                        enum CERT_TYPE cert_type;
                        const char* algo;
                        const char* alt_algo;

                } cert_req;
        } payload;
} service_message;

/*------------------------ FORWARD DECLARATION --------------------------------*/
int respond_with(int socket, enum MSG_RESPONSE_CODE response_code);
ManagementReturncode handle_svc_message(int socket,
                                        service_message* msg,
                                        int cfg_id,
                                        int version_number,
                                        struct est_configuration* est_config,
                                        struct config_transaction* transaction);
// init
void* kritis3m_service_main_thread(void* arg);
// http
void cleanup_kritis3m_service();
// timer
static int init_hello_timer(struct kritis3m_service* svc);

// coordinator for dataplane updates
enum MSG_RESPONSE_CODE initiate_hello_message(bool is_timer);

static void cleanup_hello_timer(struct kritis3m_service* svc);
void cleanup_dataplane_update_coordinator(struct dataplane_update_coordinator* update);

static int fetch_certificate(void* context, enum CONFIG_TYPE type, void* to_fetch);
int fetch_dataplane_config(void* context, enum CONFIG_TYPE type, void* to_fetch);

int validate_dataplane_config(void* context, enum CONFIG_TYPE type, void* to_fetch);
void handle_notify_dataplane_cert(enum TRANSACTION_STATE state, void* to_fetch);
void handle_notify_controlplane_cert(enum TRANSACTION_STATE state, void* to_fetch);

int validate_controlplane_certificate(void* config, enum CONFIG_TYPE type, void* to_fetch);
int validate_dataplane_certificate(void* config, enum CONFIG_TYPE type, void* to_fetch);

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

void scale_log_level_set(int log_level){
        LOG_LVL_SET(log_level);
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
        static int max_retries = 3;
        struct est_configuration est_config = {0};
        int ret = 0;
        asl_log_level = log_level;

        set_kritis3m_serivce_defaults(&svc);
        init_control_plane_conn();
        ret = init_configuration_manager(config_file);
        if (ret < 0)
        {
                LOG_ERROR("Failed to initialize configuration manager");
                goto error_occured;
        }
        asl_configuration asl_config = asl_default_config();

        //logging part
        asl_config.log_level = asl_log_level;
        int lvl = get_sysconfig()->log_level;
        scale_log_level_set(lvl);
        ipc_log_level_set(lvl);
        ctrl_conn_log_level_set(lvl);
        pki_client_log_level_set(lvl);
        appl_manager_log_level_set(lvl);
        asl_helper_log_level_set(lvl);
        cfg_manager_log_level_set(lvl);
        cfg_parser_log_level_set(lvl);


        asl_init(&asl_config);

        //pki init
        kritis3m_pki_configuration kritis3m_config = {
                .log_level = asl_log_level,
                .logging_enabled = true,
        };
        kritis3m_pki_init(&kritis3m_config);



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

        // kritis3m_pki_configuration kritis3m_config = {
        //         .log_level = KRITIS3M_PKI_LOG_LEVEL_DBG,
        //         .logging_enabled= true,
        // };
        // kritis3m_pki_init(&kritis3m_config);

        // hacky, copy due to const member, will be fixed in the future
        struct pki_client_config_t pki_clinet_config = {
                .endpoint_config = sys_config->endpoint_config,
                .serialnumber = sys_config->serial_number,
                .host = sys_config->est_host,
                .port = sys_config->est_port,
        };
        memcpy(&svc.pki_clinet_config, &pki_clinet_config, sizeof(struct pki_client_config_t));

        uint8_t* cert_buffer;
        size_t cert_buf_size;
        bool restart_requested = false;
        if (sys_config->controlplane_cert_active == ACTIVE_NONE)
        {
                struct config_transaction transaction = {0};
                LOG_DEBUG("controlplane: starting with secp384 defaultwise");
                init_est_configuration(&est_config, "secp384", NULL);

                LOG_DEBUG("fetch_certificate=%p", fetch_certificate);
                ret = init_config_transaction(&transaction,
                                              CONFIG_CONTROLPLANE,
                                              &svc.pki_clinet_config,
                                              &est_config,
                                              fetch_certificate,
                                              validate_controlplane_certificate,
                                              NULL);
                ret = start_config_transaction(&transaction);
                // await transaction to finish
                pthread_join(transaction.worker_thread, NULL);
                restart_requested = true;
        }

        if (sys_config->dataplane_cert_active == ACTIVE_NONE)
        {
                struct config_transaction transaction = {0};
                LOG_DEBUG("dataplane: starting with secp384 defaultwise");
                init_est_configuration(&est_config, "secp384", NULL);

                ret = init_config_transaction(&transaction,
                                              CONFIG_DATAPLANE,
                                              &svc.pki_clinet_config,
                                              &est_config,
                                              fetch_certificate,
                                              validate_dataplane_certificate,
                                              NULL);
                ret = start_config_transaction(&transaction);
                // await transaction to finish
                pthread_join(transaction.worker_thread, NULL);
                restart_requested = true;
        }
        if (restart_requested && max_retries > 0)
        {
                max_retries--;
                cleanup_configuration_manager();
                cleanup_kritis3m_service();
                start_kritis3m_service(config_file, asl_log_level);
                return 0;
        }
        else if (restart_requested && max_retries == 0)
        {
                LOG_ERROR("Failed to restart kritis3m_service after 3 retries");
                return -1;
        }

        ret = start_control_plane_conn(&conn_config);
        if (ret < 0)
        {
                LOG_ERROR("Failed to start control plane connection");
                goto error_occured;
        }

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
        cleanup_kritis3m_service();
        return ret;
}

void* kritis3m_service_main_thread(void* arg)
{
        start_application_manager();
        enable_proxy_reporting();
        struct est_configuration est_config = {0};
        struct config_transaction transaction = {0};

        svc.initialized = true;
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
                ret = poll(svc->pollfd.fds, svc->pollfd.num_fds, 10000);

                if (ret == -1)
                {
                        LOG_ERROR("poll error: %d", errno);
                        continue;
                }
                if (ret == 0)
                {
                        LOG_DEBUG("check control plane health");

                        switch (control_plane_status())
                        {
                        case CONTROL_PLANE_NOT_INITIALIZED:
                                LOG_WARN("Control plane not running, restarting connection");
                                const struct sysconfig* sys_config = get_sysconfig();
                                struct control_plane_conn_config_t conn_config = {0};
                                conn_config.serialnumber = sys_config->serial_number;
                                conn_config.endpoint_config = sys_config->endpoint_config;
                                conn_config.mqtt_broker_host = sys_config->broker_host;
                                stop_control_plane_conn();
                                sleep(0.2);
                                start_control_plane_conn(&conn_config);
                                try_reconnect_control_plane();
                                break;
                        case CONTROL_PLANE_DISCON:
                                try_reconnect_control_plane();
                                break;
                        case CONTROL_PLANE_HEALTHY:
                                break;
                        }
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
                                                                                 version_number,
                                                                                 &est_config,
                                                                                 &transaction);

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
                                                enum MSG_RESPONSE_CODE ret = initiate_hello_message(
                                                        true);
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
                switch (control_plane_status())
                {
                case CONTROL_PLANE_NOT_INITIALIZED:
                        LOG_WARN("Control plane not running, restarting connection");
                        const struct sysconfig* sys_config = get_sysconfig();
                        struct control_plane_conn_config_t conn_config = {0};
                        conn_config.serialnumber = sys_config->serial_number;
                        conn_config.endpoint_config = sys_config->endpoint_config;
                        conn_config.mqtt_broker_host = sys_config->broker_host;
                        stop_control_plane_conn();
                        sleep(0.2);
                        start_control_plane_conn(&conn_config);
                        sleep(0.2);
                        try_reconnect_control_plane();
                        break;
                case CONTROL_PLANE_DISCON:
                        try_reconnect_control_plane();
                        break;
                case CONTROL_PLANE_HEALTHY:
                        break;
                }
        }

terminate:
        LOG_DEBUG("Leaving kritis3m_service main thread");

        stop_application_manager();
        cleanup_kritis3m_service();
        stop_control_plane_conn();
        pthread_detach(pthread_self());
        return NULL;
}

enum MSG_RESPONSE_CODE stop_kritis3m_service(void)
{
        int ret = 0;
        service_message request = {0};

        if ((!svc.initialized) || (svc.management_socket[THREAD_EXT] < 0))
        {
                LOG_ERROR("Kritis3m_service is not initialized");
                ret = -1;
                return ret;
        }

        request.msg_type = SVC_MSG_KRITIS3M_SERVICE_STOP;
        enum MSG_RESPONSE_CODE retval = external_management_request(svc.management_socket[THREAD_EXT],
                                                                    &request,
                                                                    sizeof(request));

        if (svc.mainthread)
        {
                pthread_join(svc.mainthread, NULL);
                svc.mainthread = 0;
        }

        return retval;
}

/**
 * @brief Restarts the kritis3m service.
 *
 * This function gets the base path from the configuration manager,
 * stops the current service, and then starts it again with the same configuration.
 *
 * @return Returns MSG_OK if the service is successfully restarted, otherwise returns an error code.
 */
enum MSG_RESPONSE_CODE restart_kritis3m_service(void)
{
        char* base_path = get_base_path();
        if (!base_path)
        {
                LOG_ERROR("Failed to get base path");
                return MSG_ERROR;
        }
        char* base_path_copy = duplicate_string(base_path);
        LOG_INFO("Restarting kritis3m service with base path: %s", base_path_copy);

        // Stop the kritis3m service
        enum MSG_RESPONSE_CODE stop_result = stop_kritis3m_service();
        if (stop_result != MSG_OK)
        {
                LOG_ERROR("Failed to stop kritis3m service");
                return MSG_ERROR;
        }

        // Start the service with the stored config file and log level 4
        int start_result = start_kritis3m_service(base_path_copy,asl_log_level);
        if (start_result < 0)
        {
                LOG_ERROR("Failed to restart kritis3m service");
                return MSG_ERROR;
        }

        return MSG_OK;
}

int svc_respond_with(int socket, enum MSG_RESPONSE_CODE response_code)
{
        service_message response = {0};
        response.msg_type = SVC_MSG_RESPONSE;
        response.payload.return_code = response_code;
        size_t retries = 2;
        return sockpair_write(socket, &response, sizeof(response), &retries);
}

// Modify the handle_svc_message function to check for transaction in progress
ManagementReturncode handle_svc_message(int socket,
                                        service_message* msg,
                                        int cfg_id,
                                        int version_number,
                                        struct est_configuration* est_config,
                                        struct config_transaction* transaction)
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

                        stop_application_manager();
                        stop_control_plane_conn();
                        response_code = MSG_OK;
                        return_code = MGMT_THREAD_STOP;
                        svc_respond_with(socket, response_code);
                        break;
                }
        case SVC_MSG_CERT_GET_REQ:

                {
                        LOG_INFO("Received data plane certificate get request");

                        const char* algo = msg->payload.cert_req.algo;
                        const char* alt_algo = msg->payload.cert_req.alt_algo;
                        enum CERT_TYPE cert_type = msg->payload.cert_req.cert_type;
                        enum CONFIG_TYPE config_type;
                        config_notify_callback notify = NULL;
                        config_validate_callback validate = NULL;
                        response_code = MSG_OK;
                        if (cert_type != CONFIG_DATAPLANE && cert_type != CONFIG_CONTROLPLANE ||
                            est_config == NULL)
                        {
                                svc_respond_with(socket, MSG_ERROR);
                                return_code = MGMT_ERR;
                                goto error_occured;
                        }

                        // Check if a transaction is already in progress
                        if (is_transaction_in_progress())
                        {
                                LOG_WARN("Cannot start certificate transaction - another transaction is already in progress");
                                svc_respond_with(socket, MSG_BUSY);
                                return MGMT_OK;
                        }

                        // cert_request(endpoint_config, config, CERT_TYPE_DATAPLANE, callback);
                        svc_respond_with(socket, response_code);
                        if (ret < 0)
                        {
                                LOG_ERROR("Failed to send dataplane cert get request");
                                return_code = MGMT_ERR;
                                goto error_occured;
                        }

                        init_est_configuration(est_config, algo, alt_algo);
                        if (cert_type == CONFIG_DATAPLANE)
                        {
                                notify = handle_notify_dataplane_cert;
                                config_type = CONFIG_DATAPLANE;
                                validate = validate_dataplane_certificate;
                        }
                        else if (cert_type == CONFIG_CONTROLPLANE)
                        {
                                config_type = CONFIG_CONTROLPLANE;
                                notify = handle_notify_controlplane_cert;
                                validate = validate_controlplane_certificate;
                        }
                        else
                        {
                                LOG_ERROR("Invalid cert type");
                                break;
                        }

                        ret = init_config_transaction(transaction,
                                                      config_type,
                                                      &svc.pki_clinet_config,
                                                      est_config,
                                                      fetch_certificate,
                                                      validate,
                                                      notify);

                        ret = start_config_transaction(transaction);
                        if (ret == -2)
                        {
                                LOG_WARN("Another transaction is already in progress, cannot start %s transaction", 
                                         strr_transactiontype(config_type));
                                return MGMT_OK;
                        }
                        else if (ret < 0)
                        {
                                LOG_ERROR("Failed to start dataplane transaction");
                                goto error_occured;
                        }
                        break;
                }
        case SVC_MSG_DATAPLANE_CONFIG_APPLY_REQ:
                {
                        LOG_INFO("Received data plane config apply request");
                        
                        // Check if a transaction is already in progress
                        if (is_transaction_in_progress())
                        {
                                LOG_WARN("Cannot start dataplane config apply - another transaction is already in progress");
                                svc_respond_with(socket, MSG_BUSY);
                                return MGMT_OK;
                        }
                        
                        svc_respond_with(socket, MSG_OK);
                        ret = init_config_transaction(transaction,
                                                      CONFIG_APPLICATION,
                                                      &coordinator,
                                                      NULL, // to_fetch is 0, transaction mechanism
                                                            // changed to to multple returnvalues in
                                                            // certificate update, which required to_fetch. Cleanup required in the future!
                                                      fetch_dataplane_config,
                                                      // in this case, the testcase tests in production mode
                                                      validate_dataplane_config,
                                                      NULL);
                        ret = start_config_transaction(transaction);
                        if (ret == -2)
                        {
                                LOG_WARN("Another transaction is already in progress, cannot start dataplane config apply transaction");
                                return MGMT_OK;
                        }
                        else if (ret < 0)
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

enum MSG_RESPONSE_CODE dataplane_config_apply_send_status(struct coordinator_status* status)

{
        if (!coordinator.initialized || coordinator.management_socket[THREAD_EXT] < 0)
        {
                LOG_ERROR("coordinator is not initialized");
                return MSG_ERROR;
        }
        LOG_INFO("sending status to coordinator from module: %d", status->module);
        struct coordinator_status msg = {0};
        msg.module = status->module;
        msg.msg = status->msg;
        msg.state = status->state;
        return external_management_request(coordinator.management_socket[THREAD_EXT],
                                           &msg,
                                           sizeof(struct coordinator_status));
}

// if algo && alt_algo is null, extisting keys will be used
enum MSG_RESPONSE_CODE cert_req(enum CERT_TYPE type, char const* algo, char const* alt_algo)
{
        if (!svc.initialized || svc.management_socket[THREAD_EXT] < 0)
        {
                LOG_ERROR("Kritis3m_service is not initialized");
                return MSG_ERROR;
        }

        service_message request = {0};
        request.msg_type = SVC_MSG_CERT_GET_REQ;
        request.payload.cert_req.cert_type = type;
        request.payload.cert_req.algo = algo;
        request.payload.cert_req.alt_algo = alt_algo;

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
static int fetch_certificate(void* context, enum CONFIG_TYPE type, void* to_fetch)
{
        int ret = 0;
        enum CERT_TYPE cert_type;
        if (!context || !to_fetch)
                return -1;

        if (type == CONFIG_APPLICATION)
        {
                return -1;
        }
        else if (type == CONFIG_DATAPLANE)
        {
                cert_type = CERT_TYPE_DATAPLANE;
        }
        else if (type == CONFIG_CONTROLPLANE)
        {
                cert_type = CERT_TYPE_CONTROLPLANE;
        }
        else
        {
                return -1;
        }

        if ((ret = blocking_est_request((struct pki_client_config_t*) context,
                                        cert_type,
                                        true,
                                        (struct est_configuration*) to_fetch)) < 0)
        {
                LOG_ERROR("error occured in fetch dataplane certificate, with ret: %d", ret);
                return -1;
        }
        return ret;
}

void handle_notify_controlplane_cert(enum TRANSACTION_STATE state, void* to_fetch)
{
        LOG_INFO("Control plane certificate transaction state: %d", state);

        switch (state)
        {
        case TRANSACTION_IDLE:
                LOG_INFO("Control plane certificate transaction in IDLE state");
                break;
        case TRANSACTION_PENDING:
                LOG_INFO("Control plane certificate transaction in PENDING state");
                break;
        case TRANSACTION_VALIDATING:
                LOG_INFO("Control plane certificate transaction in VALIDATING state");
                break;
        case TRANSACTION_COMMITTED:
                {
                        restart_kritis3m_service();
                }
                break;
        case TRANSACTION_FAILED:
                LOG_ERROR("Control plane certificate transaction FAILED");
                break;
        }
}

void handle_notify_dataplane_cert(enum TRANSACTION_STATE state, void* to_fetch)
{
        LOG_INFO("Control plane certificate transaction state: %d", state);

        switch (state)
        {
        case TRANSACTION_IDLE:
                LOG_INFO("Control plane certificate transaction in IDLE state");
                break;
        case TRANSACTION_PENDING:
                LOG_INFO("Control plane certificate transaction in PENDING state");
                break;
        case TRANSACTION_VALIDATING:
                LOG_INFO("Control plane certificate transaction in VALIDATING state");
                break;
        case TRANSACTION_COMMITTED:
                {
                        // get hwconfigs and appl config
                        struct hardware_configs hw_configs = {0};
                        struct application_manager_config app_config = {0};
                        get_active_hardware_config(&app_config, &hw_configs);
                        change_application_config(&app_config, &hw_configs, NULL);
                }
                break;
        case TRANSACTION_FAILED:
                LOG_ERROR("Control plane certificate transaction FAILED");
                break;
        }
}

/**
 * @brief this function is rather hacky, since parsing and storing the config is done in the
 * coordinator, but the transaction mechanism should be kept. addionally, the config is not fetched
 * rather it is obtained via a push message via mqtt and is not directly requested
 * @param buffer: is not used
 * @param buffer_size: is not used
 * @return: 0 on success, -1 on failure
 */
int fetch_dataplane_config(void* context, enum CONFIG_TYPE type, void* to_fetch)
{
        int ret = 0;
        if (type != CONFIG_APPLICATION)
        {
                LOG_ERROR("Invalid config type");
                return -1;
        }

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
        return ret;
}

/**
 * @brief Sends a policy status message to the coordinator
 * @param msg The policy status message to send
 * @return MSG_RESPONSE_CODE indicating success or failure
 */
static enum MSG_RESPONSE_CODE send_policy_status_message(struct coordinator_status* msg)
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
                                       struct coordinator_status* msg)
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
                // rollback might be sucessfull, but the transaction responsible for the update process of config.json should fail, to keep the old state
                return -1; // Signal to finish

        case UPDATE_APPLYREQUEST:
                LOG_INFO("Coordinator: State UPDATE_APPLYREQUEST");
                if (change_application_config(&update->app_config,
                                              &update->hw_configs,
                                              send_policy_status_message) < 0)
                {
                        struct coordinator_status error_msg = {.module = UPDATE_COORDINATOR,
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
                LOG_INFO("sucesfully updated new to new configuration");
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
int validate_dataplane_config(void* context, enum CONFIG_TYPE type, void* to_fetch)
{
        if (!context)
        {
                LOG_ERROR("Invalid context");
                return -1;
        }
        LOG_DEBUG("in validate_dataplane config");

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

        struct coordinator_status policy_msg = {.module = UPDATE_COORDINATOR,
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
        int max_iterations = 4;
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
                        // in case of timeout, we rollback
                        LOG_ERROR("coordinator Timeout occurred");
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
                        LOG_DEBUG("coordinator pollerr");

                        if (update->state == UPDATE_APPLIED)
                        {
                                application_manager_rollback();
                        }
                        goto cleanup;
                }

                if (update_pollfd.revents & POLLIN)
                {
                        struct coordinator_status msg = {0};
                        if (sockpair_read(update->management_socket[THREAD_INT],
                                          &msg,
                                          sizeof(struct coordinator_status)) < 0)
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

int validate_controlplane_certificate(void* config, enum CONFIG_TYPE type, void* to_fetch)
{
        int ret = 0;
        int sock_fd = -1;

        if (!config || !to_fetch)
                goto cleanup;

        struct est_configuration* est_config = (struct est_configuration*) to_fetch;

        struct pki_client_config_t* pki_clinet_config = (struct pki_client_config_t*) config;

        asl_endpoint_configuration ep_cfg =
                {.device_certificate_chain =
                         {
                                 .buffer = (uint8_t* const) est_config->chain,
                                 .size = est_config->chain_size,
                         },
                 .private_key =
                         {
                                 .buffer = est_config->key,
                                 .size = est_config->key_size,
                                 .additional_key_buffer = est_config->alt_key_size ? est_config->alt_key :
                                                                                     NULL,
                                 .additional_key_size = est_config->alt_key_size,
                         },
                 .root_certificate = pki_clinet_config->endpoint_config->root_certificate,
                 .key_exchange_method = pki_clinet_config->endpoint_config->key_exchange_method,
                 .ciphersuites = pki_clinet_config->endpoint_config->ciphersuites,
                 .mutual_authentication = true,
                 .pkcs11 = pki_clinet_config->endpoint_config->pkcs11,
                 .psk = pki_clinet_config->endpoint_config->psk};
        // create endpoint

        if ((ret = test_endpoint(pki_clinet_config->host, pki_clinet_config->port, &ep_cfg)) < 0)
        {
                LOG_ERROR("failed to establish connection");
                goto cleanup;
        }

        return ret;
cleanup:
        ret = -1;
        LOG_ERROR("error occured in validate controlplane certificate");
        return ret;
}

// better validation will be done in the future
int validate_dataplane_certificate(void* config, enum CONFIG_TYPE type, void* to_fetch)
{
        LOG_WARN("to be implemented");
        return 0;
}

void enable_proxy_reporting(void)
{
        svc.proxy_reporting_enabled = true;
}

enum MSG_RESPONSE_CODE initiate_hello_message(bool is_timer)
{
        if (!svc.proxy_reporting_enabled)
        {
                LOG_WARN("Proxy reporting is disabled");
                return MSG_OK;
        }
        size_t proxy_status_len = 4096;
        char proxy_status[4096]={0};

        int ret = get_proxy_status(proxy_status, &proxy_status_len);
        if (ret < 0)
        {
                LOG_ERROR("Failed to get proxy status JSON");
                return MSG_ERROR;
        }else{
                LOG_DEBUG("Proxy status: len %d", proxy_status_len);
        }

        return send_hello_message((char const*) proxy_status, proxy_status_len);
}
