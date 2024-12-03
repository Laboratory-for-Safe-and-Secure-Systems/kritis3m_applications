#ifndef PROXY_MANAGEMENT_H
#define PROXY_MANAGEMENT_H

#include <stdint.h>

#include "tls_proxy.h"

enum proxy_management_message_type
{
        REVERSE_PROXY_START_REQUEST,
        FORWARD_PROXY_START_REQUEST,

        PROXY_STATUS_REQUEST,

        CONNECTION_STOP_REQUEST,
        PROXY_STOP_REQUEST,
        BACKEND_STOP_REQUEST,

        PROXY_STOP_REQUEST_MGMT,

        RESPONSE,
};

typedef struct proxy_status_request
{
        int proxy_id;
        proxy_status *status_obj_ptr;
} proxy_status_request;

typedef struct proxy_management_message
{
        enum proxy_management_message_type type;

        union proxy_management_message_payload
        {
                proxy_config reverse_proxy_config; /* REVERSE_PROXY_START_REQUEST */
                proxy_config forward_proxy_config; /* FORWARD_PROXY_START_REQUEST */
                proxy_status_request status_req;   /* PROXY_STATUS_REQUEST */
                int proxy_id;                      /* PROXY_STOP_REQUEST */
                int dummy_unused;  /* CONNECTION_STOP_REQUEST, BACKEND_STOP_REQUEST */
                int response_code; /* RESPONSE */
#ifdef USE_MANAGEMENT
                int mgmt_id; /* PROXY_STOP_REQUEST */
#endif
        } payload;
} proxy_management_message;

int send_management_message(int socket, proxy_management_message const *msg);

int read_management_message(int socket, proxy_management_message *msg);

#endif /* PROXY_MANAGEMENT_H */
