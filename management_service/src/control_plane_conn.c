#include "control_plane_conn.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "MQTTAsync.h"
#include "file_io.h"
#include "ipc.h"
#include "kritis3m_configuration.h"
#include "logging.h"
#include "networking.h"
#include "poll_set.h"

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
        char* topic_cert_mgmt;
        char* topic_cert_prod;
        pthread_t conn_thread;
        pthread_attr_t conn_attr;
};

static struct control_plane_conn_t conn;

#define TIMEOUT 10000L
#define QOS 2

#define TOPIC_FORMAT_LOG "%s/log"
#define TOPIC_FORMAT_HELLO "%s/control/hello"
#define TOPIC_FORMAT_POLICY "%s/control/ks_qos"
#define TOPIC_FORMAT_CONFIG "%s/config"
#define TOPIC_FORMAT_CERT_MGMT "%s/cert/management"
#define TOPIC_FORMAT_CERT_PROD "%s/cert/production"

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

// Forward declarations for the new functions
static int subscribe_to_topics(struct control_plane_conn_t* conn);
static int handle_management_message(struct control_plane_conn_t* conn);
static int handle_hello_request(struct control_plane_conn_t* conn, bool value);
static int handle_log_request(struct control_plane_conn_t* conn, const char* message);
static int handle_policy_status(struct control_plane_conn_t* conn, const char* status);
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
                        bool value;
                } hello;
                struct
                {
                        char* status;
                } policy;
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
        struct control_plane_conn_t* conn = (struct control_plane_conn_t*) context;
        char* payload = (char*) message->payload;

        // Create comparison topics

        if (conn->topic_config == NULL || conn->topic_cert_mgmt == NULL || conn->topic_cert_prod == NULL)
        {
                LOG_ERROR("Failed to create comparison topics");
                goto cleanup;
        }

        if (strcmp(topicName, conn->topic_config) == 0)
        {
                LOG_INFO("Received new configuration: %.*s", message->payloadlen, payload);
                write_file("./config.json", payload, message->payloadlen, false);
        }
        else if (strcmp(topicName, conn->topic_cert_mgmt) == 0)
        {
                bool value = (strncmp(payload, "true", message->payloadlen) == 0);
                LOG_INFO("Received cert management status: %s", value ? "true" : "false");
        }
        else if (strcmp(topicName, conn->topic_cert_prod) == 0)
        {
                bool value = (strncmp(payload, "true", message->payloadlen) == 0);
                LOG_INFO("Received cert production status: %s", value ? "true" : "false");
        }

cleanup:
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

        // Subscribe to cert management topic
        rc = MQTTAsync_subscribe(conn->client, conn->topic_cert_mgmt, QOS, &opts);
        if (rc != MQTTASYNC_SUCCESS)
        {
                LOG_ERROR("Failed to subscribe to topic %s, rc=%d", conn->topic_cert_mgmt, rc);
                goto cleanup;
        }

        // Subscribe to cert production topic
        rc = MQTTAsync_subscribe(conn->client, conn->topic_cert_prod, QOS, &opts);
        if (rc != MQTTASYNC_SUCCESS)
        {
                LOG_ERROR("Failed to subscribe to topic %s, rc=%d", conn->topic_cert_prod, rc);
                goto cleanup;
        }

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
                goto exit;
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
                        }
                }
                if (fds[THREAD_INT].revents & POLLERR)
                {
                        LOG_ERROR("Socket pair has error");
                        goto exit;
                }
                if (fds[THREAD_INT].revents & POLLHUP)
                {

                        LOG_INFO("Socket pair has hung up");
                        goto exit;
                }
        }

exit:
        LOG_INFO("Exiting control plane connection thread");
        closesocket(conn.socket_pair[THREAD_INT]);
        closesocket(conn.socket_pair[THREAD_EXT]);

        // Ensure MQTT client is properly closed
        if (conn.client && MQTTAsync_isConnected(conn.client))
        {
                LOG_INFO("Disconnecting from MQTT broker");
                MQTTAsync_disconnectOptions disc_opts = MQTTAsync_disconnectOptions_initializer;
                disc_opts.timeout = 1000; // 1 second timeout
                MQTTAsync_disconnect(conn.client, &disc_opts);
        }

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

                // Free any allocated memory to prevent leaks
                if (message.type == CONTROL_PLANE_SEND_LOG && message.data.log.message)
                {
                        free(message.data.log.message);
                }
                else if (message.type == CONTROL_PLANE_SEND_POLICY_STATUS && message.data.policy.status)
                {
                        free(message.data.policy.status);
                }

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
                LOG_DEBUG("Sending hello message, value: %s",
                          message.data.return_code ? "true" : "false");
                rc = handle_hello_request(conn, message.data.hello.value);
                if (rc != MQTTASYNC_SUCCESS)
                {
                        LOG_ERROR("Failed to send hello message: %d", rc);
                        return_code = MSG_ERROR;
                }
                break;

        case CONTROL_PLANE_SEND_LOG:
                if (message.data.log.message)
                {
                        LOG_DEBUG("Sending log message: %s", message.data.log.message);
                        rc = handle_log_request(conn, message.data.log.message);
                        if (rc != MQTTASYNC_SUCCESS)
                        {
                                LOG_ERROR("Failed to send log message: %d", rc);
                                return_code = MSG_ERROR;
                        }
                }
                else
                {
                        LOG_WARN("Received log message with NULL content");
                        return_code = MSG_ERROR;
                }
                break;

        case CONTROL_PLANE_SEND_POLICY_STATUS:
                if (message.data.policy.status)
                {
                        LOG_DEBUG("Sending policy status: %s", message.data.policy.status);
                        rc = handle_policy_status(conn, message.data.policy.status);
                        if (rc != MQTTASYNC_SUCCESS)
                        {
                                LOG_ERROR("Failed to send policy status: %d", rc);
                                return_code = MSG_ERROR;
                        }
                }
                else
                {
                        LOG_WARN("Received policy status with NULL content");
                        return_code = MSG_ERROR;
                }
                break;

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

        // Allocate and copy endpoint configuration
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
        conn.topic_cert_mgmt = create_topic(TOPIC_FORMAT_CERT_MGMT, conn.serialnumber);
        conn.topic_cert_prod = create_topic(TOPIC_FORMAT_CERT_PROD, conn.serialnumber);

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

        LOG_INFO("Control plane connection started successfully");
        return 0;

exit:
        LOG_ERROR("Failed to start control plane connection");
        cleanup_control_plane_conn();
        return ret;
}

void cleanup_control_plane_conn()
{
        if (conn.serialnumber)
        {
                free(conn.serialnumber);
        }
        if (conn.mqtt_broker_host)
        {
                free(conn.mqtt_broker_host);
        }
        if (conn.endpoint_config)
        {
                free(conn.endpoint_config);
        }
        if (conn.conn_thread)
        {
                pthread_join(conn.conn_thread, NULL);
        }
        if (conn.client)
        {
                MQTTAsync_destroy(&conn.client);
        }
        if (conn.topic_log)
        {
                free(conn.topic_log);
        }
        if (conn.topic_hello)
        {
                free(conn.topic_hello);
        }
        if (conn.topic_policy)
        {
                free(conn.topic_policy);
        }
        if (conn.topic_config)
        {
                free(conn.topic_config);
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
        if (topic == NULL)
        {
                return -1;
        }

        MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
        rc = MQTTAsync_send(conn->client, topic, payloadlen, payload, qos, retained, &opts);
        if (rc != MQTTASYNC_SUCCESS)
        {
                LOG_ERROR("Failed to publish message to topic %s, rc=%d", topic, rc);
        }

        free(topic);
        return rc;
}

static int handle_hello_request(struct control_plane_conn_t* conn, bool value)
{
        const char* payload = value ? "true" : "false";
        return publish_message(conn, conn->topic_hello, payload, strlen(payload), QOS, 0);
}

static int handle_log_request(struct control_plane_conn_t* conn, const char* message)
{
        return publish_message(conn, conn->topic_log, message, strlen(message), QOS, 0);
}

static int handle_policy_status(struct control_plane_conn_t* conn, const char* status)
{
        return publish_message(conn, conn->topic_policy, status, strlen(status), QOS, 0);
}

enum MSG_RESPONSE_CODE send_hello_message(bool value)
{
        if (!conn.client)
        {
                LOG_WARN("Control plane connection not started");
                return MSG_ERROR;
        }

        struct control_plane_conn_message message;
        message.type = CONTROL_PLANE_SEND_HELLO;
        message.data.hello.value = value;

        int rc = external_management_request(conn.socket_pair[THREAD_EXT], &message, sizeof(message));
        if (rc != MSG_OK)
        {
                LOG_ERROR("Failed to send hello message: %d", rc);
        }

        return rc;
}

enum MSG_RESPONSE_CODE send_log_message(const char* message)
{
        if (!conn.client)
        {
                LOG_WARN("Control plane connection not started");
                return MSG_ERROR;
        }

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
                return MSG_ERROR;
        }

        enum MSG_RESPONSE_CODE rc = external_management_request(conn.socket_pair[THREAD_EXT],
                                                                &msg,
                                                                sizeof(msg));
        if (rc != MSG_OK)
        {
                LOG_ERROR("Failed to send log message: %s", strerror(errno));
                if (msg.data.log.message)
                {
                        free(msg.data.log.message);
                }
        }
        return rc;
}

enum MSG_RESPONSE_CODE send_policy_status(const char* status)
{
        if (!conn.client)
        {
                LOG_WARN("Control plane connection not started");
                return MSG_ERROR;
        }

        if (status == NULL)
        {
                LOG_WARN("Cannot send NULL policy status");
                return MSG_ERROR;
        }

        struct control_plane_conn_message msg;
        msg.type = CONTROL_PLANE_SEND_POLICY_STATUS;
        msg.data.policy.status = strdup(status);
        if (msg.data.policy.status == NULL)
        {
                LOG_ERROR("Failed to allocate memory for policy status");
                return MGMT_ERR;
        }

        enum MSG_RESPONSE_CODE rc = external_management_request(conn.socket_pair[THREAD_EXT],
                                                                &msg,
                                                                sizeof(msg));
        if (rc != MSG_OK)
        {
                LOG_ERROR("Failed to send policy status: %s", strerror(errno));
                if (msg.data.policy.status)
                {
                        free(msg.data.policy.status);
                }
                return rc;
        }

        return rc;
}

enum MSG_RESPONSE_CODE stop_control_plane_conn()
{
        if (!conn.client)
        {
                LOG_WARN("Control plane connection not started");
                return MSG_ERROR;
        }

        LOG_INFO("Stopping control plane connection");

        // Create stop message
        struct control_plane_conn_message message;
        message.type = CONTROL_PLANE_CONN_STOP;

        // Send stop message to thread
        enum MSG_RESPONSE_CODE rc = external_management_request(conn.socket_pair[THREAD_EXT],
                                                                &message,
                                                                sizeof(message));
        if (rc != MSG_OK)
        {
                LOG_ERROR("Failed to send stop message: %s", strerror(errno));
                return rc;
        }

        // Wait for thread to exit
        if (conn.conn_thread)
        {
                pthread_join(conn.conn_thread, NULL);
                conn.conn_thread = 0;
        }

        LOG_INFO("Control plane connection stopped");
        return rc;
}