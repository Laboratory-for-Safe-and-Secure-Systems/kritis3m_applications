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

enum apply_states
{
        UPDATE_ERROR = 0,
        UPDATE_ROLLBACK = 1, // node sends to server -> causing other nodes to rollback, server sends to node
        UPDATE_APPLICABLE = 2, // node sends to server // we could check capabilities of the hardware
        UPDATE_APPLYREQUEST = 3, // server sends to node
        UPDATE_APPLIED = 4,      // node sends to server
        UPDATE_ACK = 5,          // server sends to node
};

enum module
{
        CONTROL_PLANE_CONNECTION,
        APPLICATION_MANAGER,
        SCALE_SERVICE,
        UPDATE_COORDINATOR,
};
struct policy_status_t
{
        int32_t module;
        int32_t state;
        char* msg;
};

/**
 * Send a policy status to the control plane
 * @param status The policy status to send
 * @return Returns a MSG_RESPONSE_CODE indicating the result
 */
enum MSG_RESPONSE_CODE send_policy_status(struct policy_status_t* status);

enum MSG_RESPONSE_CODE enable_sync(bool value);

#endif // CONTROL_PLANE_CONN_H