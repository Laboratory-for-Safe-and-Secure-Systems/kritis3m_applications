#ifndef KRITIS3M_APPLICATION_MANAGER_H
#define KRITIS3M_APPLICATION_MANAGER_H
#include "poll_set.h"

#include "kritis3m_configuration.h"
#include "tls_proxy.h"
#include "echo_server.h"
#include "tcp_client_stdin_bridge.h"
#include "network_tester.h"

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
    RESPONSE,
};

typedef struct connection_request
{
    struct sockaddr_in client_addr;
    int application_id;
} connection_request;

typedef struct application_status
{
    int application_id;
    Kritis3mApplicationtype type;
    bool is_running;
    union concrete_application_status
    {
        proxy_status proxy_status;
        echo_server_status echo_status;
        tcp_client_stdin_bridge_status stdtin_bridge_status;
        network_tester_status tester_status;

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
        network_tester_config network_tester_config;
        tcp_client_stdin_bridge_config stdin_bridge_config;
    } config;
} application_config;

typedef struct application_message
{
    enum application_management_message_type msg_type;
    union application_management_message_payload
    {
        application_config config;
        application_status status_request;
        int application_id;
    } payload;
    Kritis3mApplicationtype appl_type;
} application_message;

int init_application_manager(application_manager_config *config);
int start_application_manager(ApplicationConfiguration *configuration);
int stop_application_manager();
int terminate_application_manager();

#endif // KRITIS3M_APPLICATION_MANAGER_H