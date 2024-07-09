#ifndef PROXY_MANAGEMENT_H
#define PROXY_MANAGEMENT_H

#include <stdint.h>

#include "tls_proxy.h"

enum tls_proxy_management_message_type
{
        REVERSE_PROXY_START_REQUEST,
        FORWARD_PROXY_START_REQUEST,
        PROXY_STATUS_REQUEST,
        PROXY_STOP_REQUEST,
        PROXY_RESPONSE,
};


typedef struct proxy_status_request
{
        int proxy_id;
        proxy_status* status_obj_ptr;
}
proxy_status_request;


typedef struct tls_proxy_management_message
{
        enum tls_proxy_management_message_type type;

        union tls_proxy_management_message_payload
        {
                proxy_config reverse_proxy_config;      /* REVERSE_PROXY_START_REQUEST */
                proxy_config forward_proxy_config;      /* FORWARD_PROXY_START_REQUEST */
                proxy_status_request status_req;        /* PROXY_STATUS_REQUEST */
                int proxy_id;	                        /* PROXY_STOP_REQUEST */
                int response_code;                      /* RESPONSE */
        }
        payload;
}
tls_proxy_management_message;


int send_management_message(int socket, tls_proxy_management_message const* msg);

int read_management_message(int socket, tls_proxy_management_message* msg);


#endif /* PROXY_MANAGEMENT_H */
