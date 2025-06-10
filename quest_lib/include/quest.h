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

#include "http_client.h"
#include "http_method.h"
#include "kritis3m_http.h"
#include "networking.h"

typedef struct quest_transaction quest_transaction;
typedef struct quest_endpoint quest_endpoint;

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
        PARAM_ERR = -9,
};

typedef struct quest_configuration
{
        /* Verbose flag to configure runtime information */
        bool verbose;

        struct
        {
                /* Our own SAE ID */
                char* own_sae_ID;

                /* Remote peer SAE ID */
                char* remote_sae_ID;

                /* Hostname of the QKD Server REST-API */
                char* hostname;

                /* Hostport of the QKD Server */
                uint16_t hostport;

        } connection_info;

        struct
        {
                /* Use HTTPS connection instead of HTTP */
                bool enable_secure_con;

                /* ASL Endpoint used for secure communiction with the QKD line */
                asl_endpoint* client_endpoint;

        } security_param;

} quest_configuration;

typedef struct quest_connection
{
        quest_endpoint* local_endpoint;

        char const* remote_sae_ID;

} quest_connection;

/*------------------------------ quest configuration ------------------------------*/

/// @brief Starting point of the QUEST lib usage. Returns the initial object of the
///        quest_configuration struct with the default values set.
/// @return returns a refernce to the allocated quest_configuration object or NULL, if an error occured.
quest_configuration* quest_default_config(void);

/// @brief Frees the allocated quest_configuration.
/// @param config reference to the configuration, which shall be freed.
/// @return returns E_OK if working correctly, otherwise returns an error code less than zero.
enum kritis3m_status_info quest_config_deinit(quest_configuration* config);

/*--------------------------------- quest endpoint --------------------------------*/

/// @brief Derives a QUEST libary endpoint based on the quest_confiquration parameter.
/// @param config reference to the quest_configuration, which specifies the hostname,
///               port and security state.
/// @return returns reference to the allocated quest_endpoint object or NULL, if an error occured.
quest_endpoint* quest_setup_endpoint(quest_configuration* config);

/// @brief Get the secure application entity identifier for the quest endpoint.
/// @param endpoint reference to the quest_endpoint containing the connection and security
///                 information.
/// @return returns the sae_ID as a const char reference.
enum kritis3m_status_info quest_get_own_sae_id(quest_endpoint* endpoint, char* dst_buf);

/// @brief Frees the allocates quest_endpoint.
/// @param endpoint reference to the endpoint, which shall be freed.
/// @return returns E_OK if working correctly, otherwise returns an error code less than zero.
enum kritis3m_status_info quest_free_endpoint(quest_endpoint* endpoint);

/*------------------------------- quest transaction -------------------------------*/

/// @brief Derives a transaction based on the quest_endpoint parameters and the additional
///        function paramters.
/// @param endpoint reference to the quest_endpoint containing the connection and security
///                 information.
/// @param req_type specifies the request type. Currently supported: HTTP_KEY_NO_ID,
///                 HTTP_KEY_WITH_ID and HTTP_STATUS.
/// @param sae_ID   remote secure application entity identifier used in the request url.
/// @param identity if HTTP_KEY_WITH_ID is requested, the key identifier must be referenced here.
/// @return returns a refernce to the allocated quest_transaction object or NULL, if an error occured.
quest_transaction* quest_setup_transaction(quest_endpoint* endpoint,
                                           enum http_get_request_type req_type,
                                           char* remote_sae_ID,
                                           char* identity);

/// @brief Executes the configured transaction by establishing a connection to the QKD KMS and
///        sending the HTTP(S)-GET request. The response is then written to the internal response
///        parameter.
/// @param qkd_transaction reference to the quest_transaction, which shall be executed.
/// @return returns E_OK if working correctly, otherwise returns an error code less than zero.
enum kritis3m_status_info quest_execute_transaction(quest_transaction* qkd_transaction);

/// @brief Following the execution of a quest_transaction, the HTTP(S) response is written to
///        the response field of the quest_transaction. This function returns the field to the
///        user.
/// @param transaction reference to the executed quest_transaction.
/// @return returns reference to the http_get_response received from the QKD KMS.
struct http_get_response* quest_get_transaction_response(quest_transaction* transaction);

/// @brief Closes the connection to the QKD line, but does not clear the endpoint parameters.
/// @param transaction reference to the quest_transaction, which contains the connection parameter
///                    of the active connection to the QKD line.
/// @return returns E_OK if working correctly, otherwise returns an error code less than zero.
enum kritis3m_status_info quest_close_transaction(quest_transaction* transaction);

/// @brief Frees the allocated quest_transaction.
/// @param transaction reference to the quest_transaction, which should be freed.
/// @return returns E_OK if working correctly, otherwise returns an error code less than zero.
enum kritis3m_status_info quest_free_transaction(quest_transaction* transaction);

#endif /* QUEST_LIB_H */
