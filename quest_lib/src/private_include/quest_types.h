#ifndef QUEST_TYPES_H
#define QUEST_TYPES_H

#include "asl.h"
#include "kritis3m_http.h"
#include "quest.h"

#define KEY_ID_LEN 64

/*------------------------------ private structures ------------------------------*/
typedef struct quest_transaction
{
        /* quest endpoint containing connection parameter */
        quest_endpoint* endpoint;

        struct
        {
                /* Use HTTPS connection instead of HTTP */
                bool enable_secure_con;

                /* OPTIONAL parameter for HTTPS communication */
                asl_session* tls_session;

        } security_param;

        struct
        {
                /* Remote SAE ID */
                char* remote_sae_ID;

                /* OPTIONAL parameter for HTTP-GET WITH KEY ID */
                char key_ID[KEY_ID_LEN];

        } url_param;

        /* Specify which type of HTTP-GET message shall be sent */
        enum http_get_request_type request_type;

        /* HTTP-GET Request struct reference */
        struct http_request* request;

        /* HTTP-GET Response struct reference */
        struct http_get_response* response;

} quest_transaction;

typedef struct quest_endpoint
{
        /* Verbose flag to configure runtime information */
        bool verbose;

        struct
        {
                /* File-descriptor for the socket connection */
                int socket_fd;

                /* Our own SAE ID*/
                char* sae_ID;

                /* Hostname of the QKD Server REST-API */
                char* hostname;

                /* Hostport of the QKD Server */
                uint16_t hostport;

                /* Target address used for host connection */
                struct addrinfo* target_addr;

        } connection_info;

        struct
        {
                /* Use HTTPS connection instead of HTTP */
                bool enable_secure_con;

                /* OPTIONAL parameter for asl client endpoint */
                asl_endpoint* client_endpoint;

        } security_param;

} quest_endpoint;

#endif