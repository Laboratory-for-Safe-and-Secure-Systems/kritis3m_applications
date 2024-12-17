#ifndef KRITIS3M_SCALE_SERVICE_H
#define KRITIS3M_SCALE_SERVICE_H

#include "kritis3m_configuration.h"


int req_send_status_report(ApplicationManagerStatus manager_status);

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

//stops kritis3m_scale service
int stop_kritis3m_service();

#endif // KRITIS3M_SCALE_SERVICE_H
