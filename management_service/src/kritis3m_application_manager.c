// thread
#include <pthread.h>
#include <semaphore.h>

// std
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/timerfd.h>

#include "control_plane_conn.h"
#include "ipc.h"
#include "cJSON.h"
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

        struct hardware_configs* hw_configs;
        struct hardware_configs* backup_hw_configs;

        struct application_manager_config* app_config;
        struct application_manager_config* backup_app_config;

        pthread_t thread;
        pthread_attr_t thread_attr;
        sem_t thread_setup_sem;

        cJSON* proxy_status_json; // will be collected every 40 seconds
        int status_timer_fd;  // Timer for status updates

        bool timer_initialized;
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
        .proxy_status_json = NULL,
        .status_timer_fd = -1,
        .timer_initialized = false,
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

static int init_status_timer(struct application_manager* manager);
static void cleanup_status_timer(struct application_manager* manager);
static void update_proxy_status_json(struct application_manager* manager);

static int stop_running_proxies(struct application_manager_config* config);
static int restore_network_interfaces(struct hardware_configs* hw_configs);
static int prepare_network_interfaces(struct hardware_configs* hw_configs);
static int start_proxies(struct application_manager_config* config);
static void cleanup_config_resources(struct application_manager_config* config, struct hardware_configs* hw_configs);
static int start_proxy_backend(void);
static int handle_config_change_request(struct application_manager* manager, struct application_manager_config* new_config, 
                                      struct hardware_configs* new_hw_configs, 
                                      int (*callback)(struct coordinator_status*));

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
        ts.tv_sec += 10; // 10 second timeout

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
        #ifndef HW_CONFIG
           return 0;
        #endif
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
        #ifndef HW_CONFIG
        return 0;
        #endif
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
                        LOG_DEBUG("Received change application config request");

                        struct application_manager_config* new_config = msg.data.change_config.application_config;
                        struct hardware_configs* new_hw_configs = msg.data.change_config.hw_configs;
                        int (*callback)(struct coordinator_status*) = msg.data.change_config.callback;

                        if (!callback || new_config == NULL) {
                                respond_with(manager->management_pair[THREAD_INT], MSG_ERROR);
                                LOG_ERROR("No callback function provided or invalid configuration");
                                return 0;
                        } else {
                                // Only notifies that we successfully received the request
                                respond_with(manager->management_pair[THREAD_INT], MSG_OK);
                        }

                        ret = handle_config_change_request(manager, new_config, new_hw_configs, callback);
                        return ret;
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
 * @brief Handles the configuration change request with proper error handling and rollback
 * 
 * @param manager The application manager instance
 * @param new_config The new application config to apply
 * @param new_hw_configs The new hardware configs to apply
 * @param callback Callback function to notify about the result
 * @return int 0 on success, -1 on failure
 */
static int handle_config_change_request(struct application_manager* manager, 
                                      struct application_manager_config* new_config, 
                                      struct hardware_configs* new_hw_configs, 
                                      int (*callback)(struct coordinator_status*))
{
        int ret = 0;
        struct coordinator_status policy_msg = {0};
        policy_msg.module = APPLICATION_MANAGER;
        
        // Backup variables
        struct application_manager_config* backup_config = NULL;
        struct hardware_configs* backup_hw_configs = NULL;
        
        // Track resource initialization status
        bool new_hw_configs_applied = false;
        bool new_config_applied = false;
        bool proxy_backend_started = false;
        
        // Step 1: Save current configuration as backup if it exists
        if (manager->app_config != NULL) {
                backup_config = manager->app_config;
                manager->app_config = NULL;
                ret = stop_running_proxies(backup_config);
                if (ret < 0) {
                        LOG_WARN("Failed to stop some proxies, continuing with configuration change");
                }
                tls_proxy_backend_terminate();
        }
        
        // Step 2: Save current hardware configuration as backup if it exists
        if (manager->hw_configs != NULL) {
                backup_hw_configs = manager->hw_configs;
                manager->hw_configs = NULL;
                
                // Restore previous network configuration
                ret = restore_network_interfaces(backup_hw_configs);
                if (ret < 0) {
                        LOG_WARN("Failed to restore network interfaces, continuing with configuration change");
                }
        }
        
        // Step 3: Apply new hardware configuration if provided
        if (new_hw_configs != NULL && new_hw_configs->hw_configs != NULL) {
                ret = prepare_network_interfaces(new_hw_configs);
                if (ret < 0) {
                        LOG_ERROR("Failed to prepare network interfaces");
                        // Continue anyway, not critical for proxy setup
                }
                new_hw_configs_applied = true;
        }
        
        // Step 4: Start TLS proxy backend
        ret = start_proxy_backend();
        if (ret < 0) {
                LOG_ERROR("Failed to start proxy backend");
                goto rollback;
        }
        proxy_backend_started = true;
        
        // Step 5: Start proxies from new configuration
        ret = start_proxies(new_config);
        if (ret < 0) {
                LOG_ERROR("Failed to start proxies");
                goto rollback;
        }
        new_config_applied = true;
        
        // Step 6: Update manager with new configurations
        manager->app_config = new_config;
        manager->hw_configs = new_hw_configs;
        
        // Step 7: Notify coordinator about successful update
        policy_msg.state = UPDATE_APPLIED;
        policy_msg.msg = "Successfully applied new configuration";
        if ((ret = callback(&policy_msg)) < 0) {
                LOG_ERROR("Failed to notify coordinator about new configuration.");
        }
        
        // Step 8: Clean up old backup configurations and update backups
        if (manager->backup_app_config != NULL) {
                cleanup_application_config(manager->backup_app_config);
                manager->backup_app_config = backup_config;
        }
        
        if (manager->backup_hw_configs != NULL) {
                cleanup_hardware_configs(manager->backup_hw_configs);
                manager->backup_hw_configs = backup_hw_configs;
        }
        
        return 0;
        
rollback:
        // Rollback procedure if something went wrong
        manager->app_config = backup_config; 
        manager->hw_configs = backup_hw_configs;
        
        // Notify coordinator about failure
        policy_msg.state = UPDATE_ERROR;
        policy_msg.msg = "Failed to apply new configuration";
        LOG_WARN("notifying controller about failed configuration change");
        callback(&policy_msg);
        
        // Clean up resources based on what was initialized
        if (proxy_backend_started) {
                tls_proxy_backend_terminate();
        }
        
        if (new_config_applied) {
                cleanup_application_config(new_config);
                new_config = NULL;
        }
        
        if (new_hw_configs_applied) {
                restore_interfaces(new_hw_configs->hw_configs, new_hw_configs->number_of_hw_configs);
                cleanup_hardware_configs(new_hw_configs);
                new_hw_configs = NULL;
        }
        
        // Attempt to restore backup configuration
        if (backup_hw_configs != NULL) {
                prepare_network_interfaces(backup_hw_configs);
                manager->app_config = backup_config;
        }
        
        if (backup_config != NULL) {
                manager->app_config = backup_config;
                // Start the proxy backend again
                start_proxy_backend();
                
                // Start the proxies from backup config
                ret = start_proxies(backup_config);
                if (ret < 0) {
                        LOG_ERROR("Failed to start backup proxies, shutting down application manager");
                        tls_proxy_backend_terminate();
                        cleanup_application_config(backup_config);
                        cleanup_hardware_configs(backup_hw_configs);
                        manager->backup_app_config = NULL;
                        manager->backup_hw_configs = NULL;
                        return -1;
                }
        }
        
        return 0;
}

/**
 * @brief Stops all running proxies in the given configuration
 * 
 * @param config The application configuration containing proxies to stop
 * @return int 0 on success, -1 if any proxy failed to stop
 */
static int stop_running_proxies(struct application_manager_config* config)
{
        if (!config) return 0;
        
        int ret = 0;
        int result = 0;
        
        for (int i = 0; i < config->number_of_groups; i++) {
                for (int j = 0; j < config->group_config[i].number_proxies; j++) {
                        ret = tls_proxy_stop(config->group_config[i].proxy_wrapper[j].proxy_id);
                        if (ret < 0) {
                                LOG_ERROR("Failed to stop proxy %d", config->group_config[i].proxy_wrapper[j].proxy_id);
                                result = -1;
                        } else {
                                LOG_DEBUG("Successfully stopped proxy %d", config->group_config[i].proxy_wrapper[j].proxy_id);
                        }
                }
        }
        
        return result;
}

/**
 * @brief Restores network interfaces from the hardware configuration
 * 
 * @param hw_configs The hardware configuration containing interface details
 * @return int 0 on success, -1 on failure
 */
static int restore_network_interfaces(struct hardware_configs* hw_configs)
{
        if (!hw_configs) return 0;
        
        int ret = restore_interfaces(hw_configs->hw_configs, hw_configs->number_of_hw_configs);
        if (ret < 0) {
                LOG_ERROR("Failed to restore network interfaces");
                return -1;
        }
        
        LOG_DEBUG("Successfully restored network interfaces");
        return 0;
}

/**
 * @brief Prepares network interfaces according to the hardware configuration
 * 
 * @param hw_configs The hardware configuration containing interface details
 * @return int 0 on success, -1 on failure
 */
static int prepare_network_interfaces(struct hardware_configs* hw_configs)
{
        if (!hw_configs || !hw_configs->hw_configs) return 0;
        
        int ret = prepare_all_interfaces(hw_configs->hw_configs, hw_configs->number_of_hw_configs);
        if (ret < 0) {
                LOG_ERROR("Failed to prepare network interfaces");
                return -1;
        }
        
        LOG_DEBUG("Successfully prepared network interfaces");
        return 0;
}

/**
 * @brief Starts the TLS proxy backend with default configuration
 * 
 * @return int 0 on success, -1 on failure
 */
static int start_proxy_backend(void)
{
        proxy_backend_config backend_config = tls_proxy_backend_default_config();
        int ret = tls_proxy_backend_run(&backend_config);
        
        if (ret < 0) {
                LOG_ERROR("Failed to start TLS proxy backend");
                return -1;
        }
        
        return 0;
}

/**
 * @brief Starts all proxies defined in the application configuration
 * 
 * @param config The application configuration containing proxies to start
 * @return int 0 on success, proxy_id (<0) on failure
 */
static int start_proxies(struct application_manager_config* config)
{
        if (!config) return -1;
        
        int proxy_id = 0;
        
        for (int i = 0; i < config->number_of_groups; i++) {
                asl_endpoint_configuration* endpoint_config = config->group_config[i].endpoint_config;
                for (int j = 0; j < config->group_config[i].number_proxies; j++) {
                        config->group_config[i].proxy_wrapper[j].proxy_config.tls_config = *endpoint_config;
                        if (config->group_config[i].proxy_wrapper[j].direction == PROXY_FORWARD) {
                                proxy_id = tls_forward_proxy_start(&config->group_config[i].proxy_wrapper[j].proxy_config);
                        } else if (config->group_config[i].proxy_wrapper[j].direction == PROXY_REVERSE) {
                                proxy_id = tls_reverse_proxy_start(&config->group_config[i].proxy_wrapper[j].proxy_config);
                        }
                        
                        if (proxy_id < 0) {
                                LOG_ERROR("Failed to start proxy %d", config->group_config[i].proxy_wrapper[j].proxy_id);
                                return proxy_id;
                        } else {
                                config->group_config[i].proxy_wrapper[j].proxy_id = proxy_id;
                                LOG_DEBUG("Successfully started proxy %d", proxy_id);
                        }
                }
        }
        
        return 0;
}

/**
 * @brief Cleans up resources associated with configuration structures
 * 
 * @param config The application configuration to clean up
 * @param hw_configs The hardware configuration to clean up
 */
static void cleanup_config_resources(struct application_manager_config* config, struct hardware_configs* hw_configs)
{
        if (config) {
                cleanup_application_config(config);
        }
        
        if (hw_configs) {
                cleanup_hardware_configs(hw_configs);
        }
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

        // Initialize the status timer
        ret = init_status_timer(manager);
        if (ret < 0)
        {
                LOG_ERROR("Failed to initialize status timer");
                goto cleanup_application_service;
        }

        struct pollfd poll_fd[2];
        poll_fd[THREAD_INT].fd = manager->management_pair[THREAD_INT];
        poll_fd[THREAD_INT].events = POLLIN;
        poll_fd[1].fd = manager->status_timer_fd;
        poll_fd[1].events = POLLIN;

        manager->initialized = true;
        sem_post(&manager->thread_setup_sem);

        // Initial status update
        update_proxy_status_json(manager);

        while (1)
        {
                ret = poll(poll_fd, 2, -1);
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
                }

                if (poll_fd[1].revents & POLLIN)
                {
                        uint64_t exp;
                        ssize_t s = read(manager->status_timer_fd, &exp, sizeof(uint64_t));
                        if (s == sizeof(uint64_t))
                        {
                                update_proxy_status_json(manager);
                        }
                }
        }

cleanup_application_service:
        LOG_INFO("exiting kritis3m_application");
        tls_proxy_backend_terminate();
        cleanup_application_manager();
        cleanup_status_timer(manager);
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
                manager.hw_configs = NULL;
        }

        // Free backup hardware configs
        if (manager.backup_hw_configs != NULL)
        {
                cleanup_hardware_configs(manager.backup_hw_configs);
                manager.backup_hw_configs = NULL;
        }

        // Free application configs
        if (manager.app_config != NULL)
        {
                cleanup_application_config(manager.app_config);
                manager.app_config = NULL;
        }

        // Free backup application configs
        if (manager.backup_app_config != NULL)
        {
                cleanup_application_config(manager.backup_app_config);
                manager.backup_app_config = NULL;
        }

        // Free proxy status JSON
        if (manager.proxy_status_json != NULL)
        {
                cJSON_Delete(manager.proxy_status_json);
                manager.proxy_status_json = NULL;
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

static int init_status_timer(struct application_manager* manager)
{
        struct itimerspec its;
        int ret;

        // Create timer file descriptor
        manager->status_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (manager->status_timer_fd == -1)
        {
                LOG_ERROR("Failed to create status timer: %s", strerror(errno));
                return -1;
        }

        // Set timer interval to 40 seconds as mentioned in the code comment
        its.it_value.tv_sec = 40;
        its.it_value.tv_nsec = 0;
        its.it_interval.tv_sec = 40;
        its.it_interval.tv_nsec = 0;

        // Start timer
        ret = timerfd_settime(manager->status_timer_fd, 0, &its, NULL);
        if (ret != 0)
        {
                LOG_ERROR("Failed to start status timer: %s", strerror(errno));
                close(manager->status_timer_fd);
                return -1;
        }

        manager->timer_initialized = true;
        LOG_INFO("Status timer initialized successfully");
        return 0;
}

static void cleanup_status_timer(struct application_manager* manager)
{
        if (manager->timer_initialized)
        {
                close(manager->status_timer_fd);
                manager->timer_initialized = false;
                LOG_INFO("Status timer cleaned up");
        }
}

static void update_proxy_status_json(struct application_manager* manager)
{
        if (manager == NULL) {
                LOG_ERROR("Invalid manager pointer");
                return;
        }

        // Free existing JSON if it exists
        if (manager->proxy_status_json != NULL) {
                cJSON_Delete(manager->proxy_status_json);
                manager->proxy_status_json = NULL;
        }

        // Create new JSON object
        manager->proxy_status_json = cJSON_CreateObject();
        if (manager->proxy_status_json == NULL) {
                LOG_ERROR("Failed to create JSON object");
                return;
        }

        // Check if application manager is running
        if (!is_running() || manager->app_config == NULL) {
                cJSON_AddStringToObject(manager->proxy_status_json, "status", "not_running");
                cJSON_AddStringToObject(manager->proxy_status_json, "message", "Application manager not initialized");
                return;
        }

        // Add overall status
        cJSON_AddStringToObject(manager->proxy_status_json, "status", "running");

        // Create array for proxy statuses
        cJSON* proxy_statuses = cJSON_CreateArray();
        if (proxy_statuses == NULL) {
                LOG_ERROR("Failed to create proxy statuses array");
                cJSON_Delete(manager->proxy_status_json);
                manager->proxy_status_json = NULL;
                return;
        }
        cJSON_AddItemToObject(manager->proxy_status_json, "proxies", proxy_statuses);

        // Iterate through all proxy groups
        for (int i = 0; i < manager->app_config->number_of_groups; i++) {
                struct group_config* group = &manager->app_config->group_config[i];
                
                for (int j = 0; j < group->number_proxies; j++) {
                        struct proxy_wrapper* proxy = &group->proxy_wrapper[j];
                        
                        if (proxy->proxy_id >= 0) {
                                // Get proxy status
                                proxy_status status = {0};
                                int ret = tls_proxy_get_status(proxy->proxy_id, &status);
                                
                                if (ret < 0) {
                                        LOG_ERROR("Failed to get status for proxy %s (ID: %d)", 
                                                proxy->name, proxy->proxy_id);
                                        continue;
                                }

                                // Create status object for this proxy
                                cJSON* proxy_status_obj = cJSON_CreateObject();
                                if (proxy_status_obj == NULL) {
                                        LOG_ERROR("Failed to create proxy status object");
                                        continue;
                                }

                                // Add proxy information
                                cJSON_AddStringToObject(proxy_status_obj, "name", proxy->name);
                                cJSON_AddNumberToObject(proxy_status_obj, "id", proxy->proxy_id);
                                cJSON_AddStringToObject(proxy_status_obj, "state", 
                                        status.is_running ? "running" : "not_running");
                                
                                // Add to array
                                cJSON_AddItemToArray(proxy_statuses, proxy_status_obj);
                        }
                }
        }
}

uint8_t* get_proxy_status(void) {
        if (!is_running() || manager.app_config == NULL || manager.proxy_status_json == NULL) {
                // Create a simple not running status JSON
                cJSON* not_running_json = cJSON_CreateObject();
                if (!not_running_json) {
                        LOG_ERROR("Failed to create not running status JSON");
                        return NULL;
                }
                
                cJSON_AddStringToObject(not_running_json, "status", "not_running");
                cJSON_AddStringToObject(not_running_json, "message", "Application manager not initialized");
                
                uint8_t* result = (uint8_t*)cJSON_PrintUnformatted(not_running_json);
                cJSON_Delete(not_running_json);
                return result;
        }

        // Return formatted JSON for running status
        return (uint8_t*)cJSON_PrintUnformatted((const cJSON*)manager.proxy_status_json);
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
        int ret = 0;

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
                ret = prepare_network_interfaces(hw_configs);
                if (ret < 0)
                {
                        LOG_WARN("Failed to prepare network interfaces, continuing anyway");
                }
                LOG_INFO("Network interfaces prepared");
        }
        else
        {
                LOG_WARN("No hardware configurations available for network interfaces");
        }
        
        // Step 2: Start the TLS proxy backend if not already running
        ret = start_proxy_backend();
        if (ret < 0)
        {
                LOG_ERROR("Failed to start TLS proxy backend");
                return -1;
        }

        // Step 3: Start proxies
        ret = start_proxies(config);
        if (ret < 0)
        {
                LOG_ERROR("Failed to start proxies");
                tls_proxy_backend_terminate();
                return -1;
        }

        // Step 4: Set configs as active configs of manager
        LOG_INFO("Setting new configuration as active");
        manager->app_config = config;
        manager->hw_configs = hw_configs;

        LOG_INFO("Application configuration successfully started");
        return 0;
}
