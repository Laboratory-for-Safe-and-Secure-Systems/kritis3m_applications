#include "control_plane_conn.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "MQTTAsync.h"
#include "cJSON.h"
#include "configuration_manager.h"
#include "file_io.h"
#include "ipc.h"
#include "kritis3m_configuration.h"
#include "kritis3m_scale_service.h"
#include "logging.h"
#include "networking.h"
#include "log_buffer.h"

LOG_MODULE_CREATE("CONTROL_PLANE_CONN");

#if !defined(_WIN32)
#include <unistd.h>
#else
#include <windows.h>
#endif

#if defined(_WRS_KERNEL)
#include <OsWrapper.h>
#endif

struct control_plane_conn_t
{
        int running;
        MQTTAsync_connectOptions conn_opts;
        MQTTAsync_responseOptions opts;
        MQTTAsync client;

        char* serialnumber;
        asl_endpoint_configuration* endpoint_config;
        char* mqtt_broker_host;

        int socket_pair[2];
        int hello_period_min;
        char* topic_log;
        char* topic_hello;
        char* topic_policy;
        char* topic_config;
        char* topic_cert_req;
        char* topic_sync;
        pthread_t conn_thread;
        pthread_attr_t conn_attr;
};

static struct control_plane_conn_t conn;

#define TIMEOUT 10000L
#define QOS 2

#define TOPIC_FORMAT_LOG "%s/log"
#define TOPIC_FORMAT_HELLO "%s/control/hello"
#define TOPIC_FORMAT_POLICY "%s/control/qos"
#define TOPIC_FORMAT_SYNC "%s/control/sync"
#define TOPIC_FORMAT_CONFIG "%s/config"
#define TOPIC_FORMAT_CERT_REQ "%s/control/cert_req"

int disc_finished = 0;
int subscribed = 0;
int finished = 0;

// forward declarations
void* control_plane_conn_thread(void* arg);
void onConnect(void* context, MQTTAsync_successData* response);
void onConnectFailure(void* context, MQTTAsync_failureData* response);
void onDisconnect(void* context, MQTTAsync_successData* response);
void onDisconnectFailure(void* context, MQTTAsync_failureData* response);
void onSubscribe(void* context, MQTTAsync_successData* response);
void onSubscribeFailure(void* context, MQTTAsync_failureData* response);
int msgarrvd(void* context, char* topicName, int topicLen, MQTTAsync_message* message);
bool control_plane_running();

void handle_enable_sync(bool value);

// Forward declarations for the new functions
static int subscribe_to_topics(struct control_plane_conn_t* conn);
static int handle_management_message(struct control_plane_conn_t* conn);
static int handle_hello_request(struct control_plane_conn_t* conn, char* msg);
static int handle_log_request(struct control_plane_conn_t* conn, const char* message);
static int handle_policy_status(struct control_plane_conn_t* conn, struct coordinator_status* status);
static int publish_message(struct control_plane_conn_t* conn,
                           const char* topic_format,
                           const void* payload,
                           int payloadlen,
                           int qos,
                           int retained);

enum control_plane_conn_message_type
{
        CONTROL_PLANE_RETURN = 0,
        CONTROL_PLANE_CONN_STOP,
        CONTROL_PLANE_SEND_HELLO,
        CONTROL_PLANE_SEND_POLICY_STATUS,
        CONTROL_PLANE_SEND_LOG,
        CONTROL_PLANE_ENABLE_SYNC,
};

struct control_plane_conn_message
{
        enum control_plane_conn_message_type type;
        union
        {

                int32_t return_code;
                struct
                {
                        char* message;
                } log;
                struct
                {
                        char* msg;
                } hello;
                struct
                {
                        struct coordinator_status status;
                } policy;
                bool enable_sync;
        } data;
};

static char* create_topic(const char* format, const char* serialnumber)
{
        // Calculate the required length for the topic string
        int required_length = snprintf(NULL, 0, format, serialnumber) + 1; // +1 for null terminator

        // Allocate only the memory needed
        char* topic = malloc(required_length);
        if (topic == NULL)
        {
                return NULL;
        }
        snprintf(topic, required_length, format, serialnumber);
        return topic;
}

void connlost(void* context, char* cause)
{
        MQTTAsync client = (MQTTAsync) context;
        MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
        int rc;

        printf("\nConnection lost\n");
        if (cause)
                printf("     cause: %s\n", cause);

        printf("Reconnecting\n");
        conn_opts.keepAliveInterval = 60;
        conn_opts.cleansession = 1;
        conn_opts.onSuccess = onConnect;
        conn_opts.onFailure = onConnectFailure;
        if ((rc = MQTTAsync_connect(client, &conn_opts)) != MQTTASYNC_SUCCESS)
        {
                printf("Failed to start connect, return code %d\n", rc);
                finished = 1;
        }
}

int msgarrvd(void* context, char* topicName, int topicLen, MQTTAsync_message* message)
{
        cJSON* json = NULL;
        struct control_plane_conn_t* conn = (struct control_plane_conn_t*) context;
        char* payload = (char*) message->payload;

        // Create comparison topics

        if (conn->topic_config == NULL || conn->topic_cert_req == NULL)
        {
                LOG_ERROR("Failed to create comparison topics");
                goto cleanup;
        }

        if (strcmp(topicName, conn->topic_config) == 0)
        {
                LOG_INFO("Received new configuration: %.*s", message->payloadlen, payload);
                int ret = application_store_inactive(payload, message->payloadlen);
                if (ret != 0)
                {
                        LOG_ERROR("Failed to store configuration");
                        goto cleanup;
                }
                dataplane_config_apply_req();
        }

        else if (strcmp(topicName, conn->topic_cert_req) == 0)
        {
                int plane_type = -1;
                int ret = 0;
                bool value = (strncmp(payload, "true", message->payloadlen) == 0);
                LOG_INFO("Received cert request status: %s", value ? "true" : "false");
                cJSON* json = cJSON_ParseWithLength(payload, message->payloadlen);
                if (json == NULL)
                {
                        LOG_ERROR("Failed to parse certificate request");
                        goto cleanup;
                }
                cJSON* json_cert_type = cJSON_GetObjectItem(json, "cert_type");
                if (json_cert_type == NULL)
                {
                        LOG_ERROR("Failed to get cert type from certificate request");
                        goto cleanup;
                }
                plane_type = json_cert_type->valueint;

                LOG_DEBUG("Received cert type for plane: %s",
                          plane_type == 1 ? "dataplane" : "controlplane");
                cJSON* json_cert_req = cJSON_GetObjectItem(json, "cert_req");
                if (plane_type == 1)
                {

                        if ((ret = dataplane_cert_get_req()) < 0)
                        {
                                LOG_ERROR("Failed to send dataplane cert request");
                                goto cleanup;
                        }
                }
                else if (plane_type == 2)
                {
                        if ((ret = ctrlplane_cert_get_req()) < 0)
                        {
                                LOG_ERROR("Failed to send controlplane cert request");
                                goto cleanup;
                        }
                }

                // type
        }
        else if ((strcmp(topicName, conn->topic_sync) == 0))
        {
                LOG_INFO("Received policy status: %s", payload);
                cJSON* json = cJSON_ParseWithLength(message->payload, message->payloadlen);
                if (json == NULL)
                {
                        LOG_ERROR("Failed to parse policy status");
                        goto cleanup;
                }
                cJSON* status = cJSON_GetObjectItem(json, "status");
                if (status == NULL)
                {
                        LOG_ERROR("Failed to get status from policy status");
                        goto cleanup;
                }
                enum apply_states status_value = status->valueint;
                LOG_DEBUG("Received policy status: %d", status_value);
                struct coordinator_status policy_msg = {0};
                policy_msg.module = CONTROL_PLANE_CONNECTION;
                policy_msg.state = status_value;
                policy_msg.msg = "Policy status received";
                dataplane_config_apply_send_status(&policy_msg);
        }

cleanup:
        if (json)
        {
                free(json);
                json = NULL;
        }
        MQTTAsync_freeMessage(&message);
        MQTTAsync_free(topicName);
        return 1;
}

void onDisconnectFailure(void* context, MQTTAsync_failureData* response)
{
        LOG_ERROR("Disconnect failed, rc %d\n", response->code);
        disc_finished = 1;
}

void onDisconnect(void* context, MQTTAsync_successData* response)
{
        LOG_INFO("Successful disconnection");
        disc_finished = 1;
}

void onSubscribe(void* context, MQTTAsync_successData* response)
{
        LOG_INFO("Subscribe succeeded");
        subscribed = 1;
}

void onSubscribeFailure(void* context, MQTTAsync_failureData* response)
{
        LOG_ERROR("Subscribe failed, rc %d\n", response->code);
        finished = 1;
}

void onConnectFailure(void* context, MQTTAsync_failureData* response)
{
        LOG_ERROR("Connect failed, rc %d\n", response->code);
        finished = 1;
}

void onConnect(void* context, MQTTAsync_successData* response)
{
        LOG_INFO("Successfully connected to MQTT broker");
        struct control_plane_conn_t* conn_ptr = (struct control_plane_conn_t*) context;

        // Subscribe to all required topics
        int rc = subscribe_to_topics(conn_ptr);
        if (rc != MQTTASYNC_SUCCESS)
        {
                LOG_ERROR("Failed to subscribe to topics, rc=%d", rc);
                finished = 1;
        }
        else
        {
                LOG_INFO("Successfully subscribed to all topics");
        }
}

// Subscribe to all required topics
static int subscribe_to_topics(struct control_plane_conn_t* conn)
{
        int rc = MQTTASYNC_SUCCESS;
        MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
        opts.onSuccess = onSubscribe;
        opts.onFailure = onSubscribeFailure;
        opts.context = conn;

        // Subscribe to config topic
        rc = MQTTAsync_subscribe(conn->client, conn->topic_config, QOS, &opts);
        if (rc != MQTTASYNC_SUCCESS)
        {
                LOG_ERROR("Failed to subscribe to topic %s, rc=%d", conn->topic_config, rc);
                goto cleanup;
        }

        rc = MQTTAsync_subscribe(conn->client, conn->topic_sync, QOS, &opts);
        if (rc != MQTTASYNC_SUCCESS)
        {
                LOG_ERROR("Failed to subscribe to topic %s, rc=%d", conn->topic_sync, rc);
                goto cleanup;
        }

        // Subscribe to cert management topic
        rc = MQTTAsync_subscribe(conn->client, conn->topic_cert_req, QOS, &opts);
        if (rc != MQTTASYNC_SUCCESS)
        {
                LOG_ERROR("Failed to subscribe to topic %s, rc=%d", conn->topic_cert_req, rc);
                goto cleanup;
        }

        // Subscribe to cert production topic

cleanup:
        return rc;
}

/* Initialize the control plane core
 * Preperation of internal data structures
 *
 * @return Returns 0 if the control plane core is successfully initialized, otherwise returns a non-zero error code.
 */
int init_control_plane_conn()
{
        conn.serialnumber = NULL;
        conn.endpoint_config = NULL;
        conn.hello_period_min = 0;
        conn.conn_thread = 0;
        pthread_attr_init(&conn.conn_attr);
        conn.client = NULL;
        return 0;
}
void close_mqtt_client()
{
        // disconnect from broker
        MQTTAsync_disconnectOptions opts = MQTTAsync_disconnectOptions_initializer;
        MQTTAsync_disconnect(&conn.client, &opts);
        MQTTAsync_destroy(&conn.client);
}

// Add this new function before control_plane_conn_thread
static void cleanup_thread_resources(struct control_plane_conn_t* conn, bool is_error) 
{
    // In error case, close both sockets immediately
    if (is_error) {
        if (conn->socket_pair[THREAD_INT] != -1) {
            closesocket(conn->socket_pair[THREAD_INT]);
            conn->socket_pair[THREAD_INT] = -1;
        }
        if (conn->socket_pair[THREAD_EXT] != -1) {
            closesocket(conn->socket_pair[THREAD_EXT]);
            conn->socket_pair[THREAD_EXT] = -1;
        }
    }

    // Always cleanup MQTT resources
    if (conn->client && MQTTAsync_isConnected(conn->client)) {
        LOG_INFO("Disconnecting from MQTT broker");
        MQTTAsync_disconnectOptions disc_opts = MQTTAsync_disconnectOptions_initializer;
        disc_opts.timeout = 1000; // 1 second timeout
        MQTTAsync_disconnect(conn->client, &disc_opts);
    }
    MQTTAsync_destroy(&conn->client);

    // For non-error case, only close internal socket
    // External socket will be closed by the main thread
    if (!is_error && conn->socket_pair[THREAD_INT] != -1) {
        closesocket(conn->socket_pair[THREAD_INT]);
        conn->socket_pair[THREAD_INT] = -1;
    }
}

void* control_plane_conn_thread(void* arg)
{
        int ret = 0;
        int rc;
        conn.running = 1;

        LOG_INFO("Starting control plane connection thread");

        // Set up connection options
        conn.conn_opts.onSuccess = onConnect;
        conn.conn_opts.onFailure = onConnectFailure;
        conn.conn_opts.context = &conn; // Pass the conn structure as context

        // Connect to the MQTT broker
        if ((ret = MQTTAsync_connect(conn.client, &conn.conn_opts)) != MQTTASYNC_SUCCESS)
        {
                LOG_ERROR("Failed to connect to MQTT broker: %d", ret);
                conn.running = 0;
                cleanup_thread_resources(&conn, true);
                return NULL;
        }

        struct pollfd fds[1];
        fds[THREAD_INT].fd = conn.socket_pair[THREAD_INT];
        fds[THREAD_INT].events = POLLIN | POLLERR | POLLHUP;

        // Main loop
        while (conn.running)
        {
                // Poll with a timeout (1 second) to allow for periodic checks
                ret = poll(fds, 1, -1);
                if (ret < 0)
                {
                        if (errno == EINTR)
                        {
                                // Interrupted by signal, just continue
                                continue;
                        }
                        LOG_ERROR("Failed to poll socket pair: %s", strerror(errno));
                        cleanup_thread_resources(&conn, true);
                        goto exit;
                }

                // Check for socket events
                if (fds[THREAD_INT].revents & POLLIN)
                {
                        LOG_DEBUG("Received message on socket pair");
                        rc = handle_management_message(&conn);
                        if (rc < 0)
                        {
                                LOG_ERROR("Error handling management message: %d", rc);
                                cleanup_thread_resources(&conn, true);
                                goto exit;
                        }
                }
                if (fds[THREAD_INT].revents & POLLERR)
                {
                        LOG_ERROR("Socket pair has error");
                        cleanup_thread_resources(&conn, true);
                        goto exit;
                }
                if (fds[THREAD_INT].revents & POLLHUP)
                {
                        LOG_INFO("Socket pair has hung up");
                        cleanup_thread_resources(&conn, true);
                        goto exit;
                }
        }

        // Graceful shutdown - cleanup resources but keep external socket open
        cleanup_thread_resources(&conn, false);

exit:
        cleanup_control_plane_conn();

        return NULL;
}

// Helper function to send return code back to the caller
static int send_return_code(struct control_plane_conn_t* conn, enum MSG_RESPONSE_CODE code)
{
        common_response_t response = code;

        int rc = sockpair_write(conn->socket_pair[THREAD_INT], &response, sizeof(common_response_t), NULL);
        if (rc < 0)
        {
                LOG_ERROR("Failed to send return code: %s", strerror(errno));
        }
        return rc;
}

// Handle messages received from other modules
static int handle_management_message(struct control_plane_conn_t* conn)
{
        struct control_plane_conn_message message;
        int rc = sockpair_read(conn->socket_pair[THREAD_INT], &message, sizeof(message));
        if (rc < 0)
        {
                LOG_ERROR("Failed to read from socket pair: %s", strerror(errno));
                return rc;
        }

        // Check if we're connected before trying to publish
        if (message.type != CONTROL_PLANE_CONN_STOP && !MQTTAsync_isConnected(conn->client))
        {
                LOG_WARN("Cannot process message, MQTT client not connected");

                send_return_code(conn, MGMT_CONNECT_ERROR);
                return -1;
        }

        enum MSG_RESPONSE_CODE return_code = MSG_OK;

        switch (message.type)
        {
        case CONTROL_PLANE_CONN_STOP:
                LOG_INFO("Received stop request");
                conn->running = 0;
                return_code = MSG_OK;
                break;

        case CONTROL_PLANE_SEND_HELLO:
                {
                        rc = handle_hello_request(conn, message.data.hello.msg);
                        if (rc != MQTTASYNC_SUCCESS) {
                                LOG_ERROR("Failed to send hello message: %d", rc);
                                return_code = MSG_ERROR;
                        }
                        // Always free the message after handling
                        if (message.data.hello.msg) {
                                free(message.data.hello.msg);
                                message.data.hello.msg = NULL;
                        }
                        break;
                }

        case CONTROL_PLANE_SEND_LOG:
                if (message.data.log.message)
                {
                        LOG_DEBUG("Sending log message: %s", message.data.log.message);
                        rc = handle_log_request(conn, message.data.log.message);
                        if (rc != MQTTASYNC_SUCCESS)
                        {
                                LOG_ERROR("Failed to send log message: %d", rc);
                                return_code = MSG_ERROR;
                        }else{
                                return_code = MSG_OK;
                        }
                        if (message.data.log.message)
                        {
                                free(message.data.log.message);
                                message.data.log.message = NULL;

                        }
                }
                else
                {
                        LOG_WARN("Received log message with NULL content");
                        return_code = MSG_ERROR;
                }
                break;

        case CONTROL_PLANE_SEND_POLICY_STATUS:
                LOG_DEBUG("Sending policy status: ");
                rc = handle_policy_status(conn, &message.data.policy.status);
                if (rc != MQTTASYNC_SUCCESS)
                {
                        LOG_ERROR("Failed to send policy status: %d", rc);
                        return_code = MSG_ERROR;
                }
                else
                {

                        return_code = MSG_OK;
                }
                break;
        case CONTROL_PLANE_ENABLE_SYNC:
                {
                        handle_enable_sync(message.data.enable_sync);
                        return_code = MSG_OK;
                        break;
                }

        default:
                LOG_ERROR("Unknown message type: %d", message.type);
                return_code = MSG_ERROR;
        }

        // Send return code back to caller
        send_return_code(conn, return_code);

        return rc;
}

int start_control_plane_conn(struct control_plane_conn_config_t* conn_config)
{
        int ret = 0;

        LOG_LVL_SET(LOG_LVL_DEBUG);

        // Initialize log buffer
        ret = log_buffer_init();
        if (ret != 0) {
                LOG_ERROR("Failed to initialize log buffer");
                goto exit;
        }

        // Validate configuration
        if (conn_config->serialnumber == NULL || conn_config->endpoint_config == NULL ||
            conn_config->mqtt_broker_host == NULL)
        {
                LOG_ERROR("Invalid control plane connection configuration");
                goto exit;
        }
        conn.mqtt_broker_host = duplicate_string(conn_config->mqtt_broker_host);
        if (conn.mqtt_broker_host == NULL)
        {
                LOG_ERROR("Failed to allocate memory for MQTT broker host");
                ret = -1;
                goto exit;
        }

        // Copy configuration
        conn.serialnumber = duplicate_string(conn_config->serialnumber);
        if (conn.serialnumber == NULL)
        {
                LOG_ERROR("Failed to allocate memory for serial number");
                ret = -1;
                goto exit;
        }

        // Allocate and copy endpoint configuration, cleanup by mqtt library
        conn.endpoint_config = malloc(sizeof(asl_endpoint_configuration));
        if (conn.endpoint_config == NULL)
        {
                LOG_ERROR("Failed to allocate memory for endpoint configuration");
                ret = -1;
                goto exit;
        }

        conn.topic_log = create_topic(TOPIC_FORMAT_LOG, conn.serialnumber);
        conn.topic_hello = create_topic(TOPIC_FORMAT_HELLO, conn.serialnumber);
        conn.topic_policy = create_topic(TOPIC_FORMAT_POLICY, conn.serialnumber);
        conn.topic_config = create_topic(TOPIC_FORMAT_CONFIG, conn.serialnumber);
        conn.topic_cert_req = create_topic(TOPIC_FORMAT_CERT_REQ, conn.serialnumber);
        conn.topic_sync = create_topic(TOPIC_FORMAT_SYNC, conn.serialnumber);

        memcpy(conn.endpoint_config, conn_config->endpoint_config, sizeof(asl_endpoint_configuration));

        conn.hello_period_min = conn_config->hello_period_min;

        // Create socket pair for communication with the thread
        ret = create_socketpair(conn.socket_pair);
        if (ret != 0)
        {
                LOG_ERROR("Failed to create socket pair: %s", strerror(errno));
                goto exit;
        }

        // Create MQTT client
        ret = MQTTAsync_create(&conn.client,
                               conn_config->mqtt_broker_host,
                               conn.serialnumber,
                               MQTTCLIENT_PERSISTENCE_NONE,
                               NULL);
        if (ret != MQTTASYNC_SUCCESS)
        {
                LOG_ERROR("Failed to create MQTT client: %d", ret);
                goto exit;
        }

        // Set up MQTT callbacks
        ret = MQTTAsync_setCallbacks(conn.client, &conn, connlost, msgarrvd, NULL);
        if (ret != MQTTASYNC_SUCCESS)
        {
                LOG_ERROR("Failed to set MQTT callbacks: %d", ret);
                goto exit;
        }

        // Set up connection options
        MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
        conn.conn_opts = conn_opts;
        conn.conn_opts.ep_config = conn.endpoint_config;
        conn.conn_opts.keepAliveInterval = 60;
        conn.conn_opts.cleansession = 1;
        conn.conn_opts.onSuccess = onConnect;
        conn.conn_opts.onFailure = onConnectFailure;
        conn.conn_opts.context = &conn;

        // Create thread to handle MQTT connection
        ret = pthread_create(&conn.conn_thread, &conn.conn_attr, control_plane_conn_thread, NULL);
        if (ret != 0)
        {
                LOG_ERROR("Error starting control plane thread: %d (%s)", errno, strerror(errno));
                goto exit;
        }

        // Enable remote logging after successful connection
        log_buffer_set_remote_enabled(true);

        LOG_INFO("Control plane connection started successfully");
        return 0;

exit:
        LOG_ERROR("Failed to start control plane connection");
        cleanup_control_plane_conn();
        return ret;
}

void cleanup_control_plane_conn()
{
        // Disable remote logging and cleanup log buffer
        log_buffer_set_remote_enabled(false);
        log_buffer_cleanup();

        if (conn.serialnumber)
        {
                free(conn.serialnumber);
                conn.serialnumber = NULL;
        }
        if (conn.mqtt_broker_host)
        {
                free(conn.mqtt_broker_host);
                conn.mqtt_broker_host = NULL;
        }
        if (conn.endpoint_config)
        {
                free(conn.endpoint_config);
                conn.endpoint_config = NULL;
        }
        if (conn.client)
        {
                MQTTAsync_destroy(&conn.client);
                conn.client = NULL;
        }
        if (conn.topic_log)
        {
                free(conn.topic_log);
                conn.topic_log = NULL;
        }
        if (conn.topic_hello)
        {
                free(conn.topic_hello);
                conn.topic_hello = NULL;
        }
        if (conn.topic_policy)
        {
                free(conn.topic_policy);
                conn.topic_policy = NULL;
        }
        if (conn.topic_config)
        {
                free(conn.topic_config);
                conn.topic_config = NULL;
        }
        if (conn.topic_cert_req)
        {
                free(conn.topic_cert_req);
                conn.topic_cert_req = NULL;
        }

        return;
}

static int publish_message(struct control_plane_conn_t* conn,
                           const char* topic_format,
                           const void* payload,
                           int payloadlen,
                           int qos,
                           int retained)
{
        int rc = MQTTASYNC_SUCCESS;
        char* topic = create_topic(topic_format, conn->serialnumber);
        if (topic == NULL) {
                LOG_ERROR("Failed to create topic");
                return -1;
        }

        MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
        rc = MQTTAsync_send(conn->client, topic, payloadlen, payload, qos, retained, &opts);
        if (rc != MQTTASYNC_SUCCESS) {
                LOG_ERROR("Failed to publish message to topic %s, rc=%d", topic, rc);
        }

        free(topic);
        return rc;
}

static int handle_hello_request(struct control_plane_conn_t* conn, char* msg)
{
        if (!msg) {
                LOG_ERROR("Invalid hello message");
                return -1;
        }

        int rc = publish_message(conn, conn->topic_hello, msg, strlen(msg), QOS, 0);
        if (rc != MQTTASYNC_SUCCESS) {
                LOG_ERROR("Failed to publish hello message: %d", rc);
        }
        return rc;
}

static int handle_log_request(struct control_plane_conn_t* conn, const char* message)
{
        return publish_message(conn, conn->topic_log, message, strlen(message), QOS, 0);
}

static int handle_policy_status(struct control_plane_conn_t* conn, struct coordinator_status* status)
{
        char* module_name = NULL;
        if (!status || !conn)
        {
                LOG_ERROR("Invalid policy status or control plane connection");
                return -1;
        }
        switch (status->module)
        {
        case CONTROL_PLANE_CONNECTION:
                {
                        module_name = "control plane";
                        break;
                }
        case APPLICATION_MANAGER:
                {
                        module_name = "application manager";
                        break;
                }
        case UPDATE_COORDINATOR:
                {
                        module_name = "update coordinator";
                        break;
                }
        default:
                {
                        module_name = "";
                        break;
                }
        }

        char ret_val[900];
        int ret = snprintf(ret_val,
                           sizeof(ret_val),
                           "{\"status\": %d,\n \"serial-number\": \"%s\",\n \"module\": "
                           "\"%s\",\n "
                           "\"msg\": \"%s\"}",
                           status->state,
                           conn->serialnumber,
                           module_name,
                           status->msg);
        if (ret < 0 || ret >= sizeof(ret_val))
        {
                LOG_ERROR("Failed to format dataplane status - buffer too small or "
                          "encoding error");
                return -1;
        }

        return publish_message(conn, conn->topic_policy, ret_val, ret, QOS, 0);
}

enum MSG_RESPONSE_CODE send_hello_message(char* msg)
{
        if (!control_plane_running()) {
                if (msg) {
                        free(msg);
                }
                return MSG_ERROR;
        }

        struct control_plane_conn_message message;
        message.type = CONTROL_PLANE_SEND_HELLO;
        message.data.hello.msg = msg;
        
        int ret = external_management_request(conn.socket_pair[THREAD_EXT], &message, sizeof(message));
        if (ret < 0) {
                // If the request failed, we need to free the message
                if (message.data.hello.msg) {
                        free(message.data.hello.msg);
                        message.data.hello.msg = NULL;
                }
                LOG_ERROR("Failed to send hello message");
                return MSG_ERROR;
        }
        return MSG_OK;
}

// #todo not sure about mem management, dyn or static
enum MSG_RESPONSE_CODE send_log_message(const char* message)
{
        if (!control_plane_running())
                return MSG_ERROR;
        if (message == NULL)
        {
                LOG_WARN("Cannot send NULL log message");
                return MSG_ERROR;
        }

        struct control_plane_conn_message msg;
        msg.type = CONTROL_PLANE_SEND_LOG;
        msg.data.log.message = strdup(message);
        if (msg.data.log.message == NULL)
        {
                LOG_ERROR("Failed to allocate memory for log message");
                if (msg.data.log.message)
                {
                        free(msg.data.log.message);
                        msg.data.log.message = NULL;
                }
                return MSG_ERROR;
        }

        int ret=  external_management_request(conn.socket_pair[THREAD_EXT], &msg, sizeof(msg));
        if (ret < 0)
        {
                LOG_ERROR("Failed to send log message");
                if (msg.data.log.message)
                {
                        free(msg.data.log.message);
                        msg.data.log.message = NULL;
                }
                return MSG_ERROR;
        }
        return MSG_OK;
}

enum MSG_RESPONSE_CODE send_policy_status(struct coordinator_status* status)
{

        if (!control_plane_running())
                return MSG_ERROR;

        struct control_plane_conn_message msg;
        msg.type = CONTROL_PLANE_SEND_POLICY_STATUS;
        msg.data.policy.status = *status;
        return external_management_request(conn.socket_pair[THREAD_EXT], &msg, sizeof(msg));
}

enum MSG_RESPONSE_CODE stop_control_plane_conn()
{
        if (!control_plane_running())
                return MSG_ERROR;

        LOG_DEBUG("Stopping control plane connection");

        // Create stop message
        struct control_plane_conn_message message;
        message.type = CONTROL_PLANE_CONN_STOP;

        // Send stop message to thread
        int ret = external_management_request(conn.socket_pair[THREAD_EXT], &message, sizeof(message));
        if (ret < 0)
        {
                LOG_ERROR("Failed to stop control plane connection");
                return MSG_ERROR;
        }
        
        // Wait for thread to finish
        pthread_join(conn.conn_thread, NULL);
        
        // Now it's safe to close the external socket
        if (conn.socket_pair[THREAD_EXT] != -1) {
            closesocket(conn.socket_pair[THREAD_EXT]);
            conn.socket_pair[THREAD_EXT] = -1;
        }
        
        return MSG_OK;
}

enum MSG_RESPONSE_CODE enable_sync(bool value)
{
        if (!control_plane_running())
                return MSG_ERROR;
        struct control_plane_conn_message message;
        message.type = CONTROL_PLANE_ENABLE_SYNC;
        message.data.enable_sync = value;
        return external_management_request(conn.socket_pair[THREAD_EXT], &message, sizeof(message));
}

void handle_enable_sync(bool enable_sync)
{
        if (enable_sync)
        {
                MQTTAsync_subscribe(conn.client, conn.topic_sync, QOS, &conn.opts);
        }
        else
        {
                MQTTAsync_unsubscribe(conn.client, conn.topic_sync, &conn.opts);
        }
}

bool control_plane_running()
{
        return conn.client != NULL && conn.socket_pair[THREAD_INT] != -1 &&
               conn.socket_pair[THREAD_EXT] != -1;
}