#ifndef QUEST_LIB_H
#define QUEST_LIB_H

/******************************************************************************************/
/*     This file repesents the Quantum-Key Exchange Server Transaction (QUEST) library    */
/******************************************************************************************/

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asl.h"
#include "http_client.h"
#include "http_method.h"
#include "kritis3m_http_request.h"
#include "networking.h"

enum kritis3m_status_info
{
        /* generic return status info */
        E_OK = 0,
        E_NOT_OK = -1,

        /* specific error codes */
        ALLOC_ERR = -2,
        SOCKET_ERR = -3,
        QUEST_ERR = -4,
        WOLFSSL_ERR = -5,
        ADDR_ERR = -6,
        CON_ERR = -7,
        ASL_ERR = -8,
};

struct quest_configuration
{
        /* Verbose flag to configure runtime information */
        bool verbose;

        struct
        {
                /* File-descriptor for the socket connection*/
                int socket_fd;

                /* Hostname of the QKD Server REST-API */
                char* hostname;

                /* Hostport of the QKD Server */
                char* hostport;

                /* IP_v4 address used for host connection*/
                struct addrinfo* IP_v4;

                /* IP_v4 string for readability */
                char IP_str[INET6_ADDRSTRLEN];

        } connection_info;

        struct
        {
                /* Use HTTPS connection instead of HTTP */
                bool enable_secure_con;

                /* OPTIONAL parameter for asl client endpoint */
                asl_endpoint* client_endpoint;

                /* OPTIONAL parameter for HTTPS communication */
                asl_session* tls_session;

        } security_param;

        /* Specify which type of HTTP-GET message shall be sent */
        enum http_get_request_type request_type;

        /* HTTP-GET Request struct reference */
        struct http_request* request;

        /* HTTP-GET Response struct reference */
        struct http_get_response* response;

        /* OPTIONAL parameter for HTTP-GET WITH KEY ID */
        char key_ID[33];
};

/// @brief generates a config for the quest library usage and populates it with default values.
/// @return returns a refernce to the config struct object.
struct quest_configuration* quest_default_config(void);

/// @brief after the exchange of http messages, the config musst be deallocated again. This function
///        frees allocated memeory in the quest_configuration struct.
/// @param config reference to the config used for the http-get key requests.
/// @return returns E_OK if the intialization executed successful. Otherwise returns a negative
///         error-code and generates a report in the log.
enum kritis3m_status_info quest_deinit(struct quest_configuration* config);

/// @brief initializes the http connection to the QKD server and populates the associated
///        http-get request and response objects.
/// @param config requires a quest_config reference parameter, as derived from the quest_default_config()
///               function. The parameters of the config can be adapted according to the use-case.
/// @return returns E_OK if the intialization executed successful. Otherwise returns a negative
///         error-code and generates a report in the log.
enum kritis3m_status_info quest_init(struct quest_configuration* config);

/// @brief sends the http-get request to the QKD server.
/// @param config requires a quest_config referemce parameter, as derived from the quest_default_config()
///               function. The parameters of the config can be adapted according to the use-case.
/// @return returns E_OK if the intialization executed successful. Otherwise returns a negative
///         error-code and generates a report in the log.
enum kritis3m_status_info quest_send_request(struct quest_configuration* config);

#endif /* QUEST_LIB_H */
