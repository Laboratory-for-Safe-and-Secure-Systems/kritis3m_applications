#ifndef CONTROL_PLANE_CONN_H
#define CONTROL_PLANE_CONN_H

#include "asl.h"
#include "configuration_manager.h"
#include "ipc.h"
#include <stdbool.h>

// service functions init, start, stop, cleanup
struct control_plane_conn_config_t
{
        char* serialnumber;
        char* mqtt_broker_host;
        asl_endpoint_configuration* endpoint_config;
        int hello_period_min;
};

enum CONTROLPLANE_STATUS
{
        CONTROL_PLANE_NOT_INITIALIZED = -2,//full restart
        CONTROL_PLANE_DISCON = -1,//try to reconnect
        CONTROL_PLANE_HEALTHY = 0,
};

void ctrl_conn_log_level_set(int log_level);
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
enum MSG_RESPONSE_CODE send_hello_message(const char* msg, size_t len);

/**
 * Attempts to reconnect to the MQTT broker if the connection is lost
 * 
 * This function checks if the control plane is initialized but disconnected from
 * the MQTT broker. If so, it attempts to reconnect using the existing configuration.
 * 
 * @return true if reconnection was attempted or not needed, false if reconnection failed
 */
bool try_reconnect_control_plane();

enum CONTROLPLANE_STATUS control_plane_status();

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

/**
 * Check if the control plane connection is currently running
 * @return Returns true if the connection is running, false otherwise
 */
bool control_plane_running();

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

/**
 * Send a policy status to the control plane
 * @param status The policy status to send
 * @return Returns a MSG_RESPONSE_CODE indicating the result
 */
enum MSG_RESPONSE_CODE send_policy_status(struct coordinator_status* status);

enum MSG_RESPONSE_CODE enable_sync(bool value);

#endif // CONTROL_PLANE_CONN_H