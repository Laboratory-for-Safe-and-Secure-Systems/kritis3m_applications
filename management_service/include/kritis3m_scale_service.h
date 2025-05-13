#ifndef KRITIS3M_SCALE_SERVICE_H
#define KRITIS3M_SCALE_SERVICE_H

#include "configuration_manager.h"
#include "ipc.h"
#include "kritis3m_configuration.h"
#include "tls_proxy.h"
#include "kritis3m_application_manager.h"
#include "pki_client.h"

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
int start_kritis3m_service(char* config_file, int log_level);


// stops kritis3m_scale service
enum MSG_RESPONSE_CODE stop_kritis3m_service(void);

/**
 * @brief Restarts the kritis3m service.
 *
 * This function gets the base path from the configuration manager,
 * stops the current service, and then starts it again with the same configuration.
 *
 * @return Returns MSG_OK if the service is successfully restarted, otherwise returns an error code.
 */
enum MSG_RESPONSE_CODE restart_kritis3m_service(void);

//algo and alt_algo is optional. If provided, new keypairs will be generated 
enum MSG_RESPONSE_CODE cert_req(enum CERT_TYPE type ,char* algo, char* alt_algo);

// returns callback which is used by control plane conn to await signal for synchronous update
// cb: callback function
// arg: argument to pass to the callback
typedef ManagementReturncode config_status_cb(int32_t);

enum MSG_RESPONSE_CODE dataplane_config_apply_req(void);
enum MSG_RESPONSE_CODE dataplane_config_apply_send_status(struct coordinator_status* status);

// Enable proxy state reporting in hello messages
void enable_proxy_reporting(void);

#endif // KRITIS3M_SCALE_SERVICE_H
