// thread
#include <pthread.h>
#include <semaphore.h>

// std
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "control_plane_conn.h"
#include "ipc.h"
#include "kritis3m_application_manager.h"
#include "kritis3m_scale_service.h"
#include "networking.h"
#include "tls_proxy.h"

#include "logging.h"
LOG_MODULE_CREATE(application_log_module);

typedef struct connection_request
{
        struct sockaddr_in client_addr;
        int application_id;
} connection_request;

// typedef struct application_status
// {
//         bool is_running;
//         union concrete_application_status
//         {
//                 proxy_status proxy_status;
//                 echo_server_status echo_status;
//                 tcp_client_stdin_bridge_status stdtin_bridge_status;
//                 // network_tester_status tester_status;

//         } concrete_application_status;
// } application_status;

typedef struct client_connection_request
{
        struct sockaddr* client;
        int application_id;
} client_connection_request;

/*--------------------------- IPC ----------------------------------*/
enum application_management_message_type
{
        MSG_RESPONSE,
        APPLICATION_START_REQUEST,
        CHANGE_APPLICATION_CONFIG_REQUEST,
        STOP_APPLICATION_MANAGER_REQUEST,
        ACKNOWLEDGE_APPLICATION_REQUEST,
        APPLICATION_CONNECTION_REQUEST,
        APPLICATION_ROLLBACK_REQUEST,
};

typedef struct application_management_message
{
        enum application_management_message_type msg_type;
        union application_management_message_payload
        {
                struct
                {

                        struct application_manager_config* application_config;
                        struct hardware_configs* hw_configs;
                } start_config;

                struct
                {
                        struct application_manager_config* application_config;
                        struct hardware_configs* hw_configs;
                        int (*callback)(struct coordinator_status*);
                } change_config;

        } data;
} application_management_message;

struct application_manager
{
        bool initialized;
        int management_pair[2];
        int proxy_ids[20];
        int proxy_id_count;
        struct hardware_configs* hw_configs;
        struct hardware_configs* backup_hw_configs;
        struct application_manager_config* app_config;
        struct application_manager_config* backup_app_config;
        pthread_t thread;
        pthread_attr_t thread_attr;
        sem_t thread_setup_sem;
};

// main application manager instance used by the main thread
static struct application_manager manager = {
        .initialized = false,
        .management_pair[THREAD_INT] = -1,
        .management_pair[THREAD_EXT] = -1,
        .hw_configs = NULL,
        .app_config = NULL,
        .backup_hw_configs = NULL,
        .backup_app_config = NULL,

};

/*-------------------------------  FORWARD DECLARATIONS---------------------------------*/
// mainthread
void* application_service_main_thread(void* arg);
// ipc
int respond_with(int socket, enum MSG_RESPONSE_CODE response_code);

int prepare_all_interfaces(HardwareConfiguration hw_config[], int num_configs);
int restore_interfaces(HardwareConfiguration hw_config[], int num_configs);

void cleanup_application_manager(void);
int handle_management_message(struct application_manager* manager);
int start_application_config(struct application_manager* manager,
                             struct application_manager_config* config,
                             struct hardware_configs* hw_configs);

// initialize application manager
void init_application_manager(void)
{
        int ret = 0;
        manager.initialized = false;
        manager.management_pair[THREAD_EXT] = -1;
        manager.management_pair[THREAD_INT] = -1;
        manager.hw_configs = NULL;
        manager.backup_hw_configs = NULL;
        manager.app_config = NULL;
        manager.backup_app_config = NULL;
        pthread_attr_init(&manager.thread_attr);
        pthread_attr_setdetachstate(&manager.thread_attr, PTHREAD_CREATE_JOINABLE);
        sem_init(&manager.thread_setup_sem, 0, 0);
}

// start application manager
int start_application_manager()
{
        int ret = 0;

        if (manager.initialized)
        {
                LOG_ERROR("Application manager already initialized");
                return -1;
        }

        // Save configuration and hardware configs
        // manager.app_config = app_config;
        // manager.hw_configs = hw_configs;

        // Initialize the application manager resources
        ret = create_socketpair(manager.management_pair);
        if (ret < 0)
        {
                LOG_ERROR("Failed to create socketpair");
                goto error_occured;
        }

        // Start the application manager thread
        ret = pthread_create(&manager.thread,
                             &manager.thread_attr,
                             application_service_main_thread,
                             &manager);
        if (ret != 0)
        {
                LOG_ERROR("Failed to create application manager thread: %s", strerror(ret));
                goto error_occured;
        }

        // Wait for thread to initialize
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5; // 5 second timeout

        if (sem_timedwait(&manager.thread_setup_sem, &ts) != 0)
        {
                LOG_ERROR("Timeout waiting for application manager thread to initialize");
                goto error_occured;
        }

        // Check if initialization was successful
        if (!manager.initialized)
        {
                LOG_ERROR("Application manager thread failed to initialize");
                goto error_occured;
        }

        LOG_INFO("Application manager started successfully");
        return 0;

error_occured:
        LOG_ERROR("Error initializing application manager");

        if (manager.thread)
        {
                pthread_cancel(manager.thread);
                pthread_join(manager.thread, NULL);
                manager.thread = 0;
        }

        if (manager.management_pair[THREAD_EXT] >= 0)
        {
                close(manager.management_pair[THREAD_EXT]);
                manager.management_pair[THREAD_EXT] = -1;
        }

        if (manager.management_pair[THREAD_INT] >= 0)
        {
                close(manager.management_pair[THREAD_INT]);
                manager.management_pair[THREAD_INT] = -1;
        }

        return -1;
}

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

/**
 * @brief Removes all IP addresses from network interfaces specified in the hardware configuration
 *
 * @param hw_config Array of hardware configurations containing interface and IP information
 * @param num_configs Number of configurations in the hw_config array
 * @return 0 on success, -1 if any errors occurred during removal
 */
int restore_interfaces(HardwareConfiguration hw_config[], int num_configs)
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

                if (remove_ip_address(hw_config[i].device, ip_addr, cidr, is_v6) < 0)
                {
                        failures++;
                }
        }

        return (failures > 0) ? -1 : 0;
}

int handle_management_message(struct application_manager* manager)
{
        int ret = 0;
        application_management_message msg = {0};
        ret = sockpair_read(manager->management_pair[THREAD_INT], &msg, sizeof(msg));

        if (ret < 0)
        {
                LOG_ERROR("Failed to read message from socket");
                return ret;
        }
        struct coordinator_status policy_msg = {0};
        policy_msg.module = APPLICATION_MANAGER;

        switch (msg.msg_type)
        {
        case MSG_RESPONSE:
                {
                        LOG_INFO("Received response message");
                        break;
                }
        case APPLICATION_START_REQUEST:

        case CHANGE_APPLICATION_CONFIG_REQUEST:
                {

                        respond_with(manager->management_pair[THREAD_INT], MSG_OK);
                        LOG_INFO("update applied");
                        policy_msg.state = UPDATE_APPLIED;
                        policy_msg.module = APPLICATION_MANAGER;
                        policy_msg.msg = "Update applied";

                        LOG_INFO("Received change application config request");
                        struct application_manager_config* new_config = msg.data.change_config.application_config;
                        struct hardware_configs* new_hw_configs = msg.data.change_config.hw_configs;
                        int (*callback)(struct coordinator_status*) = msg.data.change_config.callback;
                        if (callback)
                                ret = callback(&policy_msg);
                        return 0;

                        if (new_config == NULL || new_hw_configs == NULL)
                        {
                                LOG_ERROR("Invalid application configuration");
                                respond_with(manager->management_pair[THREAD_INT], MSG_ERROR);
                                return -1;
                        }
                        else
                        {
                                respond_with(manager->management_pair[THREAD_INT], MSG_OK);
                        }

                        struct application_manager_config* current_config = manager->app_config;
                        struct application_manager_config* backup_config = manager->backup_app_config;

                        struct hardware_configs* current_hw_configs = manager->hw_configs;
                        struct hardware_configs* backup_hw_configs = manager->backup_hw_configs;

                        // Stop current configuration if running
                        if (current_config != NULL)
                        {
                                tls_proxy_backend_terminate();

                                // Backup the current configuration
                                if (backup_config != NULL)
                                {
                                        // Free previous backup to avoid memory leaks
                                        cleanup_application_config(backup_config);
                                        free(backup_config);
                                }
                                manager->backup_app_config = current_config;
                        }

                        if (current_hw_configs != NULL && current_hw_configs->hw_configs != NULL)
                        {
                                ret = restore_interfaces(current_hw_configs->hw_configs,
                                                         current_hw_configs->number_of_hw_configs);
                                if (ret < 0)
                                {
                                        LOG_ERROR("Failed to restore network "
                                                  "interfaces");
                                        return ret;
                                }
                                // Backup hardware configuration if it exists
                                if (backup_hw_configs != NULL)
                                {
                                        cleanup_hardware_configs(backup_hw_configs);
                                        free(backup_hw_configs);
                                }
                                manager->backup_hw_configs = current_hw_configs;
                        }

                        struct proxy_backend_config config = {0};
                        config.log_level = LOG_LVL_WARN;
                        ret = tls_proxy_backend_run(&config);
                        if (ret < 0)
                        {
                                LOG_ERROR("Failed to start TLS proxy backend");
                                return ret;
                        }

                        ret = start_application_config(manager, new_config, new_hw_configs);
                        if (ret < 0)
                        {
                                LOG_ERROR("Failed to start new application configuration");

                                // Rollback to backup if available
                                if (manager->backup_app_config != NULL &&
                                    manager->backup_hw_configs != NULL)
                                {
                                        LOG_INFO("Rolling back to previous configuration");
                                        // restore current interfaces
                                        ret = restore_interfaces(new_hw_configs->hw_configs,
                                                                 new_hw_configs->number_of_hw_configs);

                                        if (ret < 0)
                                        {
                                                LOG_ERROR("Failed to restore backup network "
                                                          "interfaces");
                                        }

                                        ret = start_application_config(manager,
                                                                       manager->backup_app_config,
                                                                       manager->backup_hw_configs);
                                        if (ret < 0)
                                        {
                                                LOG_ERROR("Failed to rollback to backup"
                                                          "configuration");
                                                // signal update_coordinator error occured
                                                policy_msg.state = UPDATE_ERROR;
                                                policy_msg.module = APPLICATION_MANAGER;
                                                policy_msg.msg = "Failed to rollback to backup "
                                                                 "configuration";
                                                if (callback)
                                                {
                                                        ret = callback(&policy_msg);
                                                }
                                        }
                                        else
                                        {
                                                LOG_INFO("rollback sucesfully");
                                                policy_msg.state = UPDATE_ROLLBACK;
                                                policy_msg.msg = "Rollback to backup "
                                                                 "configuration ";
                                                if (callback)
                                                {
                                                        ret = callback(&policy_msg);
                                                }
                                        }
                                }
                                else
                                {
                                        // no rollback possible
                                        LOG_ERROR("no backup config available application manager "
                                                  "stop");
                                        // send error
                                        // ret = dataplane_config_apply_send_status(UPDATE_ERROR);
                                }
                                cleanup_application_config(new_config);
                                cleanup_hardware_configs(new_hw_configs);
                        }
                        else
                        {
                                policy_msg.state = UPDATE_APPLIED;
                                policy_msg.module = APPLICATION_MANAGER;
                                policy_msg.msg = "Sucesfully applied new configuration";
                                // ret = dataplane_config_apply_send_status(&policy_msg);
                        }
                        break;
                }
        case APPLICATION_ROLLBACK_REQUEST:
                {
                        LOG_INFO("Received application rollback request");
                        respond_with(manager->management_pair[THREAD_INT], MSG_OK);

                        // cleanup current config
                        if (manager->app_config != NULL)
                        {
                                tls_proxy_backend_terminate();
                                cleanup_application_config(manager->app_config);
                                manager->app_config = NULL;
                        }

                        if (manager->hw_configs != NULL)
                        {
                                ret = restore_interfaces(manager->hw_configs->hw_configs,
                                                         manager->hw_configs->number_of_hw_configs);
                                if (ret < 0)
                                {
                                        LOG_ERROR("Failed to restore current network "
                                                  "interfaces during rollback");
                                }
                                cleanup_hardware_configs(manager->hw_configs);
                                manager->hw_configs = NULL;
                        }

                        // Check if backup configuration exists
                        if (manager->backup_app_config != NULL && manager->backup_hw_configs != NULL)
                        {

                                struct proxy_backend_config config = {0};
                                config.log_level = LOG_LVL_WARN;
                                ret = tls_proxy_backend_run(&config);
                                if (ret < 0)
                                {
                                        LOG_ERROR("Failed to restart TLS proxy backend during "
                                                  "rollback");
                                        respond_with(manager->management_pair[THREAD_INT], MSG_ERROR);
                                        return ret;
                                }

                                // Step 5: Apply backup configuration
                                struct application_manager_config* backup_config = manager->backup_app_config;
                                struct hardware_configs* backup_hw_configs = manager->backup_hw_configs;

                                // Start application with backup config
                                ret = start_application_config(manager, backup_config, backup_hw_configs);
                                if (ret < 0)
                                {
                                        LOG_ERROR("Failed to apply backup configuration during "
                                                  "rollback");
                                        cleanup_application_config(backup_config);
                                        cleanup_hardware_configs(backup_hw_configs);
                                        free(backup_config);
                                        free(backup_hw_configs);
                                        backup_config = NULL;
                                        backup_hw_configs = NULL;
                                }
                                else
                                {
                                        manager->backup_app_config = NULL;
                                        manager->backup_hw_configs = NULL;
                                }

                                LOG_INFO("Successfully rolled back to previous configuration");
                        }
                        break;
                }
        case STOP_APPLICATION_MANAGER_REQUEST:
                {
                        respond_with(manager->management_pair[THREAD_INT], MSG_OK);
                        LOG_INFO("Received stop application manager request");
                        ret = tls_proxy_backend_terminate();
                        if (ret < 0)
                        {
                                LOG_ERROR("Failed to stop application configuration");
                                respond_with(manager->management_pair[THREAD_INT], MSG_ERROR);
                                return ret;
                        }

                        return 1; // Signal to exit main loop
                }
        case ACKNOWLEDGE_APPLICATION_REQUEST:
                {
                        LOG_INFO("Received acknowledge application request - not implemented yet");
                        respond_with(manager->management_pair[THREAD_INT], MSG_OK);
                        break;
                }
        case APPLICATION_CONNECTION_REQUEST:
                {
                        LOG_INFO("Received application connection request - not implemented yet");
                        respond_with(manager->management_pair[THREAD_INT], MSG_OK);
                        break;
                }
        default:
                {
                        LOG_ERROR("Unknown message type: %d", msg.msg_type);
                        respond_with(manager->management_pair[THREAD_INT], MSG_ERROR);
                        return -1;
                }
        }

        return 0;
}

/**
 * @brief Start an application configuration
 *
 * @param manager The application manager
 * @param config The application configuration to start
 * @param hw_configs Hardware configurations to apply
 * @return int 0 on success, -1 on failure
 */
int start_application_config(struct application_manager* manager,
                             struct application_manager_config* config,
                             struct hardware_configs* hw_configs)
{

        LOG_LVL_SET(LOG_LVL_DEBUG);
        int ret = 0;
        int* started_proxy_ids = NULL;
        memset(manager->proxy_ids, -1, sizeof(manager->proxy_ids));
        manager->proxy_id_count = 0;

        if (config == NULL || manager == NULL || hw_configs == NULL)
        {
                LOG_ERROR("Invalid parameters");
                return -1;
        }

        LOG_INFO("Starting application configuration with %d groups", config->number_of_groups);

        // Step 1: Prepare hardware interfaces first
        LOG_INFO("Preparing network interfaces");
        if (hw_configs->hw_configs != NULL && hw_configs->number_of_hw_configs > 0)
        {
                // ret = prepare_all_interfaces(hw_configs->hw_configs,
                // hw_configs->number_of_hw_configs); if (ret < 0)
                // {
                //         LOG_ERROR("Failed to prepare network interfaces");
                //         return ret;
                // }
                // LOG_INFO("Successfully prepared %d network interfaces",
                //          hw_configs->number_of_hw_configs);
        }
        else
        {
                LOG_WARN("No hardware configurations available for network interfaces");
        }

        // Start TLS proxies for each group
        for (int i = 0; i < config->number_of_groups; i++)
        {
                struct group_config* group = &config->group_config[i];
                if (!group->proxy_wrapper)
                {
                        LOG_ERROR("No proxy wrapper for group %d", i);
                        ret = -1;
                        goto cleanup;
                }

                LOG_INFO("Starting %d proxies for group %d", group->number_proxies, i);

                // Start proxies for this group
                for (int j = 0; j < group->number_proxies; j++)
                {
                        group->proxy_wrapper[j].proxy_config.tls_config = *group->endpoint_config;

                        LOG_INFO("Starting proxy %d (direction: %d) for group %d",
                                 j,
                                 group->proxy_wrapper[j].direction,
                                 i);

                        int proxy_id = -1;
                        // Start the proxy based on its direction
                        switch (group->proxy_wrapper[j].direction)
                        {
                        case PROXY_FORWARD:
                                proxy_id = tls_forward_proxy_start(
                                        &group->proxy_wrapper[j].proxy_config);
                                break;

                        case PROXY_REVERSE:
                                proxy_id = tls_reverse_proxy_start(
                                        &group->proxy_wrapper[j].proxy_config);
                                break;

                        case PROXY_TLS_TLS:
                                LOG_ERROR("TLS-TLS proxy is not implemented yet");
                                proxy_id = -1;
                                break;

                        default:
                                LOG_ERROR("Unknown proxy type: %d", group->proxy_wrapper[j].direction);
                                // Skip this proxy but continue with others
                                continue;
                        }

                        if (proxy_id < 0)
                        {
                                LOG_ERROR("Failed to start TLS proxy %d in group %d", j, i);
                                ret = -1;
                                goto cleanup;
                        }

                        LOG_INFO("Successfully started proxy %d for group %d (id: %d)", j, i, proxy_id);
                        manager->proxy_ids[manager->proxy_id_count++] = proxy_id;
                }

                LOG_INFO("Successfully started all proxies for group %d", i);
        }

        // Step 3: Set configs as active configs of manager
        LOG_INFO("Setting new configuration as active");
        manager->app_config = config;
        manager->hw_configs = hw_configs;

        LOG_INFO("Application configuration successfully started");

        return 0;

cleanup:
        // Clean up any started proxies
        LOG_WARN("Error occurred. Cleaning up %d started proxies", manager->proxy_id_count);
        for (int i = 0; i < manager->proxy_id_count; i++)
        {
                if (manager->proxy_ids[i] >= 0)
                {
                        LOG_INFO("Stopping proxy with ID %d", manager->proxy_ids[i]);
                        tls_proxy_stop(manager->proxy_ids[i]);
                }
        }
        memset(manager->proxy_ids, -1, sizeof(manager->proxy_ids));
        manager->proxy_id_count = 0;
        return ret;
}

// application manager main thread
void* application_service_main_thread(void* arg)
{
        int ret = 0;
        struct application_manager* manager = (struct application_manager*) arg;
        ret = create_socketpair(manager->management_pair);
        if (ret < 0)
        {
                LOG_ERROR("failed to create socketpair");
                goto cleanup_application_service;
        }

        struct pollfd poll_fd[1];
        poll_fd[THREAD_INT].fd = manager->management_pair[THREAD_INT];
        poll_fd[THREAD_INT].events = POLLIN;

        manager->initialized = true;
        sem_post(&manager->thread_setup_sem);

        while (1)
        {
                ret = poll(poll_fd, 1, -1);
                if (ret < 0)
                {
                        LOG_ERROR("Poll error: %s", strerror(errno));
                        continue;
                }

                if (poll_fd[THREAD_INT].revents & POLLIN)
                {
                        ret = handle_management_message(manager);
                        if (ret > 0)
                        {
                                LOG_INFO("Received signal to exit application manager");
                                break;
                        }
                        else if (ret < 0)
                        {
                                LOG_ERROR("Error handling management message");
                                break;
                        }
                        else if (ret == 1)
                        {
                                LOG_INFO("Received signal to exit application manager");
                                break;
                        }
                }
        }

cleanup_application_service:
        LOG_INFO("exiting kritis3m_application");
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

// respond with a MSG_RESPONSE_CODE to a management request
int respond_with(int socket, enum MSG_RESPONSE_CODE response_code)
{
        common_response_t return_code = response_code;

        return sockpair_write(socket, &return_code, sizeof(common_response_t), NULL);
}

// Implementation of the stop_application_manager function
int stop_application_manager()
{
        int ret = 0;

        if (!is_running())
        {
                LOG_WARN("Application manager is not running");
                return -1;
        }

        application_management_message msg = {0};
        msg.msg_type = STOP_APPLICATION_MANAGER_REQUEST;

        enum MSG_RESPONSE_CODE resp = external_management_request(manager.management_pair[THREAD_EXT],
                                                                  &msg,
                                                                  sizeof(msg));

        if (resp != MSG_OK)
        {
                LOG_ERROR("Failed to stop application manager");
                return -1;
        }

        // Wait for thread to complete
        ret = pthread_join(manager.thread, NULL);
        if (ret != 0)
        {
                LOG_ERROR("Failed to join application manager thread: %s", strerror(ret));
                return -1;
        }

        return 0;
}

// send APPLICATION_CONNECTION_REQUEST to main thread
bool confirm_client(int application_id, struct sockaddr* connecting_client)
{
        if (!is_running())
        {
                LOG_ERROR("Application manager not initialized");
                return false;
        }

        application_management_message request = {0};
        request.msg_type = APPLICATION_CONNECTION_REQUEST;

        // Create and populate client connection request
        client_connection_request con_req = {0};
        con_req.application_id = application_id;
        con_req.client = connecting_client;

        // Send request and get response
        enum MSG_RESPONSE_CODE response = external_management_request(manager.management_pair[THREAD_EXT],
                                                                      &request,
                                                                      sizeof(request));

        switch (response)
        {
        case MSG_OK:
                LOG_INFO("Client connection approved");
                return true;
        case MSG_FORBIDDEN:
                LOG_INFO("Client connection rejected");
                return false;
        case MSG_BUSY:
                LOG_INFO("Application manager busy, try again");
                return false;
        default:
                LOG_ERROR("Unexpected response from application manager");
                return false;
        }
}

/*-------------------------------- Services ------------------------------------------*/

void cleanup_application_manager(void)
{
        int ret = 0;
        manager.initialized = false;
        manager.management_pair[THREAD_EXT] = -1;
        manager.management_pair[THREAD_INT] = -1;

        // Free hardware configs
        if (manager.hw_configs != NULL)
        {
                cleanup_hardware_configs(manager.hw_configs);
                free(manager.hw_configs);
                manager.hw_configs = NULL;
        }

        // Free backup hardware configs
        if (manager.backup_hw_configs != NULL)
        {
                cleanup_hardware_configs(manager.backup_hw_configs);
                free(manager.backup_hw_configs);
                manager.backup_hw_configs = NULL;
        }

        // Free application configs
        if (manager.app_config != NULL)
        {
                cleanup_application_config(manager.app_config);
                free(manager.app_config);
                manager.app_config = NULL;
        }

        // Free backup application configs
        if (manager.backup_app_config != NULL)
        {
                cleanup_application_config(manager.backup_app_config);
                free(manager.backup_app_config);
                manager.backup_app_config = NULL;
        }

        pthread_attr_destroy(&manager.thread_attr);
}

// Application management API implementations
/**
 * @brief Changes the current application configuration.
 *
 * @param new_config Pointer to the new application manager configuration.
 * @return int Returns 0 on success, or an error code on failure.
 */
int change_application_config(struct application_manager_config* new_config,
                              struct hardware_configs* hw_configs,
                              int (*coordinator_callback)(struct coordinator_status*))
{
        int ret = 0;

        if (!is_running())
        {
                LOG_ERROR("Application manager not initialized");
                return -1;
        }

        if (new_config == NULL)
        {
                LOG_ERROR("Invalid application configuration");
                return -1;
        }

        application_management_message msg = {0};
        msg.msg_type = CHANGE_APPLICATION_CONFIG_REQUEST;
        msg.data.change_config.application_config = new_config;
        msg.data.change_config.hw_configs = hw_configs;
        msg.data.change_config.callback = coordinator_callback;
        return external_management_request(manager.management_pair[THREAD_EXT], &msg, sizeof(msg));
}

/**
 * @brief Starts an application with the provided configuration.
 *
 * @param config Pointer to the application manager configuration.
 * @return int Returns 0 on success, or an error code on failure.
 */
int start_application(struct application_manager_config* config, struct hardware_configs* hw_configs)
{
        int ret = 0;

        if (!is_running())
        {
                LOG_ERROR("Application manager not initialized");
                return -1;
        }

        if (config == NULL)
        {
                LOG_ERROR("Invalid application configuration");
                return -1;
        }

        if (hw_configs == NULL)
        {
                LOG_ERROR("Invalid hardware configuration");
                return -1;
        }

        application_management_message msg = {0};
        msg.msg_type = APPLICATION_START_REQUEST;
        msg.data.start_config.application_config = config;
        msg.data.start_config.hw_configs = hw_configs;

        enum MSG_RESPONSE_CODE resp = external_management_request(manager.management_pair[THREAD_EXT],
                                                                  &msg,
                                                                  sizeof(msg));

        if (resp != MSG_OK)
        {
                LOG_ERROR("Failed to start application");
                return -1;
        }

        return 0;
}

int application_manager_rollback()
{
        int ret = 0;

        if (!is_running())
        {
                LOG_ERROR("Application manager not initialized");
                return -1;
        }

        application_management_message msg = {0};
        msg.msg_type = APPLICATION_ROLLBACK_REQUEST;

        return external_management_request(manager.management_pair[THREAD_EXT], &msg, sizeof(msg));
}
