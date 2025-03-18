#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "logging.h"
#include "networking.h"
#include "control_plane_conn.h"
#include "poll_set.h"
// #include "sys/timerfd.h"

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

// main kritis3m_service module type
//  Variable static struct kritis3m_service svc = {0}, single instance used by the kritis3m_service module
struct kritis3m_service
{
        bool initialized;
        Kritis3mNodeConfiguration node_configuration;
        ConfigurationManager configuration_manager;
        int management_socket[2];
        pthread_t mainthread;
        pthread_attr_t thread_attr;
        poll_set pollfd;
        asl_endpoint_configuration management_endpoint_config;
        asl_endpoint* client_endpoint;
};

// ipc services
enum service_message_type
{
        SVC_MSG_RESPONSE,
        SVC_MSG_KRITIS3M_SERVICE_STOP,
        SVC_MSG_APPLICATION_MANGER_STATUS_REQ,
}__attribute__((aligned(4)));

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
        } payload;
} service_message;

/*------------------------ FORWARD DECLARATION --------------------------------*/
int respond_with(int socket, enum MSG_RESPONSE_CODE response_code);
ManagementReturncode handle_svc_message(int socket, service_message* msg, int cfg_id, int version_number);
// init
void* kritis3m_service_main_thread(void* arg);
void init_configuration_manager(ConfigurationManager* manager, Kritis3mNodeConfiguration* node_config);
int prepare_all_interfaces(HardwareConfiguration hw_config[], int num_configs);
// http
void cleanup_kritis3m_service();

/* ----------------------- MAIN kritis3m_service module -------------------------*/
static struct kritis3m_service svc = {0};

// reset svc
void set_kritis3m_serivce_defaults(struct kritis3m_service* svc)
{
        if (svc == NULL)
                return;
        memset(&svc->management_endpoint_config, 0, sizeof(asl_endpoint_configuration));
        memset(&svc->configuration_manager, 0, sizeof(ConfigurationManager));
        memset(&svc->node_configuration, 0, sizeof(Kritis3mNodeConfiguration));
        create_socketpair(svc->management_socket);
        pthread_attr_init(&svc->thread_attr);
        pthread_attr_setdetachstate(&svc->thread_attr, PTHREAD_CREATE_JOINABLE);
        poll_set_init(&svc->pollfd);
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

        CryptoProfile default_profile = {
                .ASLKeyExchangeMethod = ASL_KEX_DEFAULT,
                .MutualAuthentication = true,
                .Name = "default",
                .NoEncryption = false,
                .UseSecureElement = false,
                .Keylog = false,
        };
        /** -------------- set log level ----------------------------- */
        LOG_LVL_SET(log_level);

        // get global node config
        set_kritis3m_serivce_defaults(&svc);
        svc.node_configuration.config_path = config_file;
        svc.node_configuration.config_path_size = strlen(config_file);
        init_application_manager();

        // reads and the configfile and parses content to node_configuration
        ret = get_Kritis3mNodeConfiguration(config_file, &svc.node_configuration);
        if (ret < 0)
        {
                LOG_ERROR("can't parse Config, error occured: %d ", errno);
                return ret;
        }
        if ((svc.node_configuration.primary_path == NULL) ||
            (svc.node_configuration.config_path == NULL) ||
            (svc.node_configuration.pki_cert_path == NULL))
        {
                LOG_ERROR("filepaths incorrect");
                return -1;
        }

        // pass middleware and pin from cli to endpoint conf
        svc.management_endpoint_config.pkcs11
                .module_path = svc.node_configuration.management_identity.secure_middleware_path;
        svc.management_endpoint_config.pkcs11.module_pin = svc.node_configuration
                                                                   .management_identity.pin;

        // 2. setsup endpoint configuration, used to communicate with the controller
        ret = create_endpoint_config(&svc.node_configuration.management_identity.identity,
                                     &default_profile,
                                     &svc.management_endpoint_config);
        if (ret < 0)
        {
                LOG_ERROR("endpoint config error");
                goto error_occured;
        }


        // 4. initialization of configuration manager
        /**
         * @brief the configuration manager stores the application data.
         * To ensure a secure update with rollback functionality, two applicationconfigs, primary and secondary are used
         * - In this state only the primary object is used
         */
        init_configuration_manager(&svc.configuration_manager, &svc.node_configuration);

        // set primary application config
        if (svc.configuration_manager.active_configuration == CFG_NONE)
        {
                LOG_INFO("no configuration selected. Starting with primary configuration");
                svc.configuration_manager.active_configuration = CFG_PRIMARY;
        }

        // 5. Read and Parse application config
        ManagementReturncode retval = get_Systemconfig(&svc.configuration_manager,
                                                       &svc.node_configuration);
        if (retval != MGMT_OK)
        {
                LOG_ERROR("reading primary.json failed. Shutdown");
                goto error_occured;
        }

        // 6. prepare hardware
        ret = prepare_all_interfaces(svc.configuration_manager.primary.application_config.hw_config,
                                     svc.configuration_manager.primary.application_config.number_hw_config);
        if (ret < 0)
        {
                LOG_WARN("error occured when initializing net module. Continue");
        }
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
        SystemConfiguration* selected_sys_cfg = NULL;
        ManagementReturncode retval = MGMT_OK;

        asl_endpoint_configuration* ep_cfg = &svc->management_endpoint_config;
        Kritis3mNodeConfiguration node_configuration = svc->node_configuration;
        ConfigurationManager application_configuration_manager = svc->configuration_manager;

        ret = poll_set_add_fd(&svc->pollfd, svc->management_socket[THREAD_INT], POLLIN | POLLERR);
        if (ret < 0)
        {
                LOG_ERROR("cant add fd to to pollset, shutting down management service");
                goto terminate;
        }

        // 8. Start application manager
        ret = start_application_manager(&application_configuration_manager.primary.application_config);
        if (ret < 0)
        {
                LOG_ERROR("can't start application manage");
                goto terminate;
        }

        cfg_id = application_configuration_manager.primary.cfg_id;
        version_number = application_configuration_manager.primary.version;

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
                }
        }

terminate:
        LOG_DEBUG("Leaving kritis3m_service main thread");

        stop_application_manager();
        cleanup_kritis3m_service();
        pthread_detach(pthread_self());
        return NULL;
}

void init_configuration_manager(ConfigurationManager* manager, Kritis3mNodeConfiguration* node_config)
{
        if ((node_config == NULL) || (manager == NULL))
                return;
        manager->active_configuration = node_config->selected_configuration;
        strncpy(manager->primary_file_path, node_config->primary_path, MAX_FILEPATH_SIZE);
        strncpy(manager->secondary_file_path, node_config->secondary_path, MAX_FILEPATH_SIZE);
        cleanup_Systemconfiguration(&manager->primary);
        cleanup_Systemconfiguration(&manager->secondary);
}

//------------------------------------------ HARDWARE INFORMATION --------------------------------------- //

int prepare_all_interfaces(HardwareConfiguration hw_config[], int num_configs)
{
        if (!hw_config || num_configs <= 0 || num_configs > MAX_NUMBER_HW_CONFIG)
        {
                return -1;
        }

        char ip_addr[INET6_ADDRSTRLEN];
        char cidr[4];
        int failures = 0;

        // Process each interface configuration
        for (int i = 0; i < num_configs; i++)
        {
                if (parse_ip_cidr(hw_config[i].ip_cidr, ip_addr, INET6_ADDRSTRLEN, cidr, 4) != 0)
                {
                        failures++;
                        continue;
                }

                bool is_v6 = is_ipv6(ip_addr);

                if (add_ip_address(hw_config[i].device, ip_addr, cidr, is_v6) < 0)
                {
                        failures++;
                }
        }

        return (failures > 0) ? -1 : 0;
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

        //ggf. cleanup

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
        //to internal context
        ManagementReturncode return_code = MGMT_OK;
        //to external context
        enum MSG_RESPONSE_CODE response_code = MSG_OK;
        ret = sockpair_read(socket, msg, sizeof(service_message));
        if (ret < 0)
                goto error_occured;

        switch (msg->msg_type)
        {
        case SVC_MSG_APPLICATION_MANGER_STATUS_REQ:
                {
                }
        case SVC_MSG_KRITIS3M_SERVICE_STOP:
                {
                        LOG_INFO("SVC STOP: ");
                        LOG_INFO("Kritis3m service: Received Stop Request");
                        response_code = MSG_OK;
                        return_code = MGMT_THREAD_STOP;
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
        svc_respond_with(socket, response_code);
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
        free_NodeConfig(&svc.node_configuration);
        cleanup_configuration_manager(&svc.configuration_manager);
}

