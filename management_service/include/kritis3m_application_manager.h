#ifndef KRITIS3M_APPLICATION_MANAGER_H
#define KRITIS3M_APPLICATION_MANAGER_H
#include "configuration_manager.h"
#include "kritis3m_scale_service.h"
#include "tls_proxy.h"
#include "kritis3m_configuration.h"

/**
 * @brief Set up the application manager.
 *
 * Initializes resources required for the application manager.
 */
void init_application_manager(void);


void appl_manager_log_level_set(int log_level);

/**
 * @brief Start the application manager main thread.
 *
 * This function starts the application manager by sending the provided
 * ApplicationConfiguration, which contains the configurations of the kritis3m applications
 *
 * @param app_config Pointer to the application_manager_config structure.
 * @param hw_configs Pointer to the hardware_configs structure.
 * @return int Returns 0 on success, or an error code on failure.
 */
int start_application_manager();

/**
 * @brief Stop the application manager thread.
 *
 * This function sends a stop request to the application manager thread,
 * which will clean up any running applications and exit.
 *
 * @return int Returns 0 on success, or an error code on failure.
 */
int stop_application_manager();

/**
 * @brief Check if the application manager is running.
 *
 * @return bool Returns true if the application manager is running, false otherwise.
 */
bool is_running(void);

/**
 * @brief Perform whitelist lookup for a connecting client.
 *
 * This function can be used by data plane applications (e.g., reverse/forward proxies)
 * to verify if a client is allowed to connect to the KRITIS3M Network.
 *
 * @param application_id The ID of the application requesting confirmation.
 * @param connecting_client Pointer to the sockaddr structure of the client attempting to connect.
 * @return bool Returns true if the client is allowed, false otherwise.
 */
bool confirm_client(int application_id, struct sockaddr* connecting_client);

/**
 * @brief Changes the current application configuration.
 *
 * This function sends a request to change the current application configuration
 * with a new one. The previous configuration will be stored as a backup.
 *
 * @param new_config Pointer to the new application manager configuration.
 * @return int Returns 0 on success, or an error code on failure.
 */
int change_application_config(struct application_manager_config* new_config,
                              struct hardware_configs* hw_config,
                              int (*coordinator_callback)(struct coordinator_status*));

/**
 * @brief Starts an application with the provided configuration.
 *
 * This function sends a request to start an application with the given configuration.
 *
 * @param config Pointer to the application manager configuration.
 * @return int Returns 0 on success, or an error code on failure.
 */
int start_application(struct application_manager_config* config, struct hardware_configs* hw_configs);

/**
 * @brief Rolls back the application configuration.
 *
 * This function rolls back the application configuration to the previous one.
 */
int application_manager_rollback();

int get_proxy_status(char* result, size_t* result_size);



#endif // KRITIS3M_APPLICATION_MANAGER_H