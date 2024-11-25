#ifndef KRITIS3M_APPLICATION_MANAGER_H
#define KRITIS3M_APPLICATION_MANAGER_H
#include "poll_set.h"
#include "kritis3m_configuration.h"

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

void init_application_manager(void);
int start_application_manager(ApplicationConfiguration *configuration);
bool is_running();
bool confirm_client(int application_id, struct sockaddr *connecting_client);

int stop_application_manager();

#endif // KRITIS3M_APPLICATION_MANAGER_H