#ifndef KRITIS3M_APPLICATION_MANAGER_H
#define KRITIS3M_APPLICATION_MANAGER_H
#include "kritis3m_configuration.h"

/**
 * @brief Set up the application manager.
 *
 * Initializes resources required for the application manager.
 */
void init_application_manager(void);

/**
 * @brief Start the application manager main thread.
 *
 * This function starts the application manager by sending the provided
 * ApplicationConfiguration, which contains the configurations of the kritis3m applications
 *
 * @param configuration Pointer to the ApplicationConfiguration structure.
 * @return int Returns 0 on success, or an error code on failure.
 */
int start_application_manager(ApplicationConfiguration* configuration);

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
 * @brief Stop the application manager main thread.
 */
int stop_application_manager();

#endif // KRITIS3M_APPLICATION_MANAGER_H