#ifndef KRITIS3M_APPLICATION_MANAGER_H
#define KRITIS3M_APPLICATION_MANAGER_H
#include "poll_set.h"
#include "kritis3m_configuration.h"
#include "echo_server.h"
#include "tls_proxy.h"
#include "tcp_client_stdin_bridge.h"

/***
 * includes threading
 */

typedef struct application_manager_config
{
    int32_t log_level;
} application_manager_config;

enum application_management_message_type
{
    APPLICATION_START_REQUEST,
    APPLICATION_STATUS_REQUEST,
    APPLICATION_STOP_REQUEST,

    APPLICATION_SERVICE_START_REQUEST,
    APPLICATION_SERVICE_STOP_REQUEST,
    APPLICATION_SERVICE_STATUS_REQUEST,

    APPLICATION_CONNECTION_REQUEST,
    MSG_RESPONSE,
};
enum MSG_RESPONSE_CODE
{
    MSG_ERROR = -1,
    MSG_OK = 0,
    MSG_FORBIDDEN = 1,
    MSG_BUSY = 2,
};

typedef struct connection_request
{
    struct sockaddr_in client_addr;
    int application_id;
} connection_request;

typedef struct application_status
{
    bool is_running;
    union concrete_application_status
    {
        proxy_status proxy_status;
        echo_server_status echo_status;
        tcp_client_stdin_bridge_status stdtin_bridge_status;
        // network_tester_status tester_status;

    } concrete_application_status;
} application_status;

typedef struct application_config
{
    int application_id;
    Kritis3mApplicationtype type;
    union concrete_application_config
    {
        echo_server_config echo_config;
        proxy_config proxy_config;
        // network_tester_config network_tester_config;
        tcp_client_stdin_bridge_config stdin_bridge_config;
        ApplicationConfiguration application_configuration;
    } config;
} application_config;

typedef struct client_connection_request
{
    struct sockaddr_in client;
    int application_id;
} client_connection_request;

typedef struct application_message
{
    enum application_management_message_type msg_type;
    Kritis3mApplicationtype type;
    union application_management_message_payload
    {

        ApplicationConfiguration *config;
        Kritis3mApplications *kritis3m_applicaiton;
        application_config appl_config;
        application_status status_request;
        client_connection_request client_con_request;
        int application_id;
        struct sockaddr_in client;
        enum MSG_RESPONSE_CODE return_code;
    } payload;
} application_message;

int init_application_manager(ApplicationConfiguration *configuration);
int start_application_manager(ApplicationConfiguration *configuration);
bool is_running();
bool confirm_client(int application_id, struct sockaddr_in *connecting_client);

int stop_application_manager();

#endif // KRITIS3M_APPLICATION_MANAGER_H