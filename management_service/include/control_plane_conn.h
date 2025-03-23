#ifndef CONTROL_PLANE_CONN_H
#define CONTROL_PLANE_CONN_H

#include "asl.h"
#include "ipc.h"
#include "kritis3m_configuration.h"
#include <stdbool.h>

// service functions init, start, stop, cleanup
struct control_plane_conn_config_t
{
        char* serialnumber;
        char* mqtt_broker_host;
        asl_endpoint_configuration* endpoint_config;
        int hello_period_min;
};

/* Initialize the control plane core
 * Preperation of internal data structures
 *
 * @return Returns 0 if the control plane core is successfully initialized, otherwise returns a non-zero error code.
 */
int init_control_plane_conn();

/**
 * Start the control plane connection with the given configuration
 * @param conn Configuration for the control plane connection
 * @return Returns 0 on success, non-zero error code otherwise
 */
int start_control_plane_conn(struct control_plane_conn_config_t* conn);

/**
 * Clean up resources used by the control plane connection
 */
void cleanup_control_plane_conn();

/**
 * Send a hello message to the control plane
 * @param value The hello value to send (true/false)
 * @return Returns a ManagementReturncode indicating the result
 */
enum MSG_RESPONSE_CODE send_hello_message(bool value);

/**
 * Send a log message to the control plane
 * @param message The log message to send
 * @return Returns a ManagementReturncode indicating the result
 */
enum MSG_RESPONSE_CODE send_log_message(const char* message);

/**
 * Stop the control plane connection
 * @return Returns 0 on success, non-zero error code otherwise
 */
enum MSG_RESPONSE_CODE stop_control_plane_conn();

enum policy_status
{
        CERT_REQ_RECEIVED,
        CERT_RECEIVED,
        CERT_APPLIED,

        CONFIG_RECEIVED,
        CONFIG_USABLE,
        CONFIG_APPLIED,

};
/**
 * Send a policy status to the control plane
 * @param status The policy status to send
 * @return Returns a MSG_RESPONSE_CODE indicating the result
 */
enum MSG_RESPONSE_CODE send_policy_status(const char* status);

#endif // CONTROL_PLANE_CONN_H