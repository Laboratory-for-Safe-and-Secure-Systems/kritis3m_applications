#include "quest.h"
#include "quest_types.h"

#include "asl.h"
#include "file_io.h"
#include "logging.h"
#include "networking.h"

LOG_MODULE_CREATE(quest_transaction);

#define TIMEOUT_DURATION 5000

/*------------------------------ private functions -------------------------------*/

/// @brief establishes the TCP connection to the QKD KMS based on the derivated con-
///        nection information from the quest_endpoint.
/// @param qkd_transaction reference to the transaction, which contains the 
///        quest_endpoint reference, as well as the associated connection information.
/// @return returns E_OK if working correctly, otherwise returns an error code less than zero.
static enum kritis3m_status_info establish_host_connection(quest_transaction* qkd_transaction)
{
        int status = E_OK;

        qkd_transaction->endpoint->connection_info.socket_fd = create_client_socket(AF_INET);
        if (qkd_transaction->endpoint->connection_info.socket_fd < 0)
        {
                LOG_ERROR("connection failed, error code: %d\n", errno);
                status = SOCKET_ERR;
                goto SOCKET_CON_ERR;
        }

        if (connect(qkd_transaction->endpoint->connection_info.socket_fd,
                    (struct sockaddr*) qkd_transaction->endpoint->connection_info.IP_v4->ai_addr,
                    qkd_transaction->endpoint->connection_info.IP_v4->ai_addrlen) < 0)
        {
                LOG_ERROR("connection failed, error code: %d\n", errno);
                status = SOCKET_ERR;
                goto SOCKET_CON_ERR;
        }

        /* if enable_secure_con is true we need to perform a TLS handshake */
        if (qkd_transaction->security_param.enable_secure_con)
        {
                qkd_transaction->security_param
                        .tls_session = asl_create_session(qkd_transaction->endpoint->security_param.client_endpoint,
                                                          qkd_transaction->endpoint->connection_info.socket_fd);

                if (qkd_transaction->security_param.tls_session == NULL)
                {
                        LOG_ERROR("failed to establish tls session.\n");
                        status = ASL_ERR;
                        goto SOCKET_CON_ERR;
                }

                if (asl_handshake(qkd_transaction->security_param.tls_session) < 0)
                {
                        LOG_ERROR("tls handshake unsuccessful.\n");
                        status = ASL_ERR;
                        goto SOCKET_CON_ERR;
                }
        }

SOCKET_CON_ERR:
        return status;
}

/// @brief Configures the quest_transaction based on the paramters in the quest_endpoint
///        and additional the function parameters.
/// @param qkd_transaction reference to the quest_transaction, which shall be configured.
/// @param endpoint reference to the quest_endpoint, which contains the configuration parameter.
/// @param req_type specifies the type of HTTP(S) request which shall be sent.
/// @param sae_ID secure application entity identifier used in the request url.
/// @param identity OPTIONAL parameter, which must be set, if a key with a specific key identifier 
///                 shall be requested (req_type must then be HTTP_KEY_WITH_ID).
/// @return returns E_OK if working correctly, otherwise returns an error code less than zero. 
static enum kritis3m_status_info configure_transaction(quest_transaction* qkd_transaction,
                                                       quest_endpoint* endpoint,
                                                       enum http_get_request_type req_type,
                                                       char* sae_ID,
                                                       char* identity)
{
        /* sanity check: required parameter */
        if ((qkd_transaction == NULL) || (endpoint == NULL) || (sae_ID == NULL))
                return PARAM_ERR;

        /* sanity check: if a key should be requested with a
         * specific ID, we need to make sure the ID is passed
         * to the function. */
        if ((req_type == HTTP_KEY_WITH_ID) && (identity == NULL))
        {
                LOG_ERROR("invalid parameter configuration. key identity was NULL.");
                return PARAM_ERR;
        }

        /* set endpoint reference and security mode */
        qkd_transaction->endpoint = endpoint;
        qkd_transaction->security_param.enable_secure_con = endpoint->security_param.enable_secure_con;

        /* set sae_ID in the transaction url parameter */
        qkd_transaction->url_param.sae_ID = sae_ID;

        /* set request type and key identity, if identity is passed to the function. */
        qkd_transaction->request_type = req_type;
        if (identity != NULL)
        {
                memcpy(qkd_transaction->url_param.key_ID, identity, strlen(identity));
        }

        return E_OK;
}

/*------------------------------- public functions -------------------------------*/
quest_transaction* quest_setup_transaction(quest_endpoint* endpoint,
                                           enum http_get_request_type req_type,
                                           char* sae_ID,
                                           char* identity)
{
        enum kritis3m_status_info status = E_OK;
        quest_transaction* qkd_transaction;

        if (endpoint == NULL)
        {
                LOG_ERROR("invalid endpoint parameter.");
                return NULL;
        }

        qkd_transaction = malloc(sizeof(struct quest_transaction));
        if (qkd_transaction == NULL)
        {
                LOG_ERROR("error occured during quest transaction allocation.");
                return NULL;
        }

        /* Ensure all buffers of the transaction are zero */
        memset(qkd_transaction, 0, sizeof(struct quest_transaction));

        status = configure_transaction(qkd_transaction, endpoint, req_type, sae_ID, identity);
        if (status != E_OK)
        {
                free(qkd_transaction);
                goto TRANSACTION_ERR;
        }

        qkd_transaction->request = allocate_http_request();

        qkd_transaction->response = allocate_http_response();

        if (qkd_transaction->request == NULL)
                goto TRANSACTION_ERR;

        if (qkd_transaction->response == NULL)
        {
                /* if response is NULL here, we know, that the request
                 * allocation was successful, but the response allocation
                 * was not. Therfore, we only need to free the request and
                 * exit gracefully. */

                free(qkd_transaction->request);
                goto TRANSACTION_ERR;
        }

        populate_http_response(qkd_transaction->response, qkd_transaction->request_type);

        populate_http_request(qkd_transaction->request,
                              qkd_transaction->response,
                              qkd_transaction->endpoint->connection_info.hostname,
                              qkd_transaction->endpoint->connection_info.hostport,
                              qkd_transaction->url_param.sae_ID,
                              qkd_transaction->url_param.key_ID);

        return qkd_transaction;

TRANSACTION_ERR:
        LOG_ERROR("error occured during quest transaction configuration");
        return NULL;
}

struct http_get_response* quest_get_transaction_response(quest_transaction* transaction)
{
        if (transaction->response == NULL)
                LOG_WARN("transaction response is currently NULL");

        return transaction->response;
}

enum kritis3m_status_info quest_execute_transaction(quest_transaction* qkd_transaction)
{
        enum kritis3m_status_info status = E_OK;
        duration timeout = ms_to_duration(TIMEOUT_DURATION);

        /* open socket and connect to the QKD line */
        status = establish_host_connection(qkd_transaction);
        if (status < E_OK)
        {
                LOG_ERROR("establishing host connection was unsuccessful, error code %d\n", errno);
                goto QKD_CON_ERR;
        }

        /* if enable_secure_con is true, we use HTTPS */
        if (qkd_transaction->security_param.enable_secure_con)
        {
                status = https_client_req(qkd_transaction->endpoint->connection_info.socket_fd,
                                          qkd_transaction->security_param.tls_session,
                                          qkd_transaction->request,
                                          timeout,
                                          qkd_transaction->response);
        }
        else /* otherwise we use standard HTTP */
        {
                status = http_client_req(qkd_transaction->endpoint->connection_info.socket_fd,
                                         qkd_transaction->request,
                                         timeout,
                                         qkd_transaction->response);
        }

        if (status < 0)
        {
                LOG_ERROR("failed to send HTTP-GET request, error code: %d\n", status);
                status = CON_ERR;
        }
        else
        {
                status = E_OK;
        }

QKD_CON_ERR:
        return status;
}

enum kritis3m_status_info quest_close_transaction(quest_transaction* qkd_transaction)
{
        if (qkd_transaction->endpoint->connection_info.socket_fd > 0)
        {
                close(qkd_transaction->endpoint->connection_info.socket_fd);
                qkd_transaction->endpoint->connection_info.socket_fd = -1;
        }

        return E_OK;
}

enum kritis3m_status_info quest_free_transaction(quest_transaction* qkd_transaction)
{

        if (qkd_transaction->security_param.enable_secure_con &&
            (qkd_transaction->security_param.tls_session != NULL))
        {
                /* close and free the asl_session */
                asl_close_session(qkd_transaction->security_param.tls_session);
                asl_free_session(qkd_transaction->security_param.tls_session);
        }

        if (qkd_transaction->request != NULL)
        {
                /* free http-get resquest */
                deinit_http_request(qkd_transaction->request, qkd_transaction->response->msg_type);
        }

        if (qkd_transaction->response != NULL)
        {
                /* free http-get response */
                deinit_http_response(qkd_transaction->response);
        }

        if (qkd_transaction != NULL)
                free(qkd_transaction);

        return E_OK;
}