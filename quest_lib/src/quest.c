#include "quest.h"
#include "file_io.h"
#include "logging.h"
#include "networking.h"

#define TIMEOUT_DURATION 5000

LOG_MODULE_CREATE(quest_lib);

/*------------------------------ private functions -------------------------------*/

/// @brief Using the conection parameter, this function establishes the connection to the 
///        host and creates the tls session and handshake, if enable_secure_con is true.
/// @param config quest configuration containing the connection_info and security_params.
/// @return returns E_OK if working correctly, otherwise returns an error code less than zero.
static enum kritis3m_status_info establish_host_connection(struct quest_configuration* config)
{
        int status = E_OK;

        config->connection_info.socket_fd = create_client_socket(AF_INET);
        if (config->connection_info.socket_fd < 0)
        {
                LOG_ERROR("connection failed, error code: %d\n", errno);
                status = SOCKET_ERR;
                goto SOCKET_CON_ERR;
        }

        if (connect(config->connection_info.socket_fd,(struct sockaddr*) config->connection_info.IP_v4->ai_addr, 
                config->connection_info.IP_v4->ai_addrlen) < 0)
        {
                LOG_ERROR("connection failed, error code: %d\n", errno);
                status = SOCKET_ERR;
                goto SOCKET_CON_ERR;
        }

        /* if enable_secure_con is true we need to perform a TLS handshake */
        if(config->security_param.enable_secure_con)
        {
                config->security_param.tls_session = asl_create_session(config->security_param.client_endpoint, config->connection_info.socket_fd);
                if(config->security_param.tls_session == NULL)
                {
                        LOG_ERROR("failed to establish tls session.\n");
                        status = ASL_ERR;
                        goto SOCKET_CON_ERR;
                }

                if(asl_handshake(config->security_param.tls_session) < 0)
                {
                        LOG_ERROR("tls handshake unsuccessful.\n");
                        status = ASL_ERR;
                        goto SOCKET_CON_ERR;
                }
        }

SOCKET_CON_ERR:
        return status;
}

/// @brief To establish a connection to the QKD line we need a DNS resolve call to get the IP 
///        address of the QKD key management server and subsequent port socket preparation.
/// @param config quest_configuration containing the connection_info parameters.
/// @return returns E_OK if working correctly, otherwise returns an error code less than zero.
static enum kritis3m_status_info derive_connection_parameter(struct quest_configuration* config)
{
        int status;

        /* temporary fix to connect to mock-server */
        config->connection_info.hostname = "127.0.0.2";

        /* Look-up IP address from hostname and hostport */
        status = address_lookup_client(config->connection_info.hostname,
                                       (uint16_t) strtol(config->connection_info.hostport, NULL, 10),
                                       &config->connection_info.IP_v4, AF_INET);
        if (status != 0)
        {
                LOG_ERROR("error looking up server IP address, error code %d", status);
                return ADDR_ERR;
        }

        /* temporary fix to connect to mock-server */
        config->connection_info.hostname = "im-lfd-qkd-bob.othr.de";
       
        /* Convert the IP from socket_addr_in to string */
        inet_ntop(AF_INET, config->connection_info.IP_v4, config->connection_info.IP_str,
                  sizeof(config->connection_info.IP_str));

        LOG_INFO("IP address for %s: %s:%s\n",
                 config->connection_info.hostname,
                 config->connection_info.IP_str,
                 config->connection_info.hostport);

        return E_OK;
}

/*------------------------------- public functions -------------------------------*/
struct quest_configuration* quest_default_config(void)
{
        struct quest_configuration* default_config;

        default_config = malloc(sizeof(struct quest_configuration));

        default_config->verbose = false;

        default_config->security_param.enable_secure_con = true;
        default_config->security_param.client_endpoint = NULL;
        default_config->security_param.tls_session = NULL;

        default_config->connection_info.hostname = "im-lfd-qkd-bob.othr.de";
        default_config->connection_info.hostport = "9120";
        default_config->connection_info.socket_fd = -1;

        default_config->request_type = HTTP_KEY_NO_ID;
        default_config->request = NULL;
        default_config->response = NULL;

        return default_config;
}

enum kritis3m_status_info quest_deinit(struct quest_configuration* config)
{
        if (config == NULL)
                return E_OK;

        if(config->security_param.enable_secure_con)
        {
                asl_close_session(config->security_param.tls_session);
                asl_free_endpoint(config->security_param.client_endpoint);
                asl_cleanup();
        }

        if (config->request != NULL)
        {
                /* free http-get resquest */
                deinit_http_request(config->request, config->response->msg_type);
        }

        if (config->response != NULL)
        {
                /* free http-get response */
                deinit_http_response(config->response);
        }

        /* free quest configuration */
        free(config);

        return E_OK;
}

enum kritis3m_status_info quest_init(struct quest_configuration* config)
{
        enum kritis3m_status_info status = E_OK;

        status = derive_connection_parameter(config);
        if (status < E_OK)
                goto HOST_CON_ERR;

        status = establish_host_connection(config);
        if(status < E_OK)
                goto HOST_CON_ERR;

        config->request = allocate_http_request();

        config->response = allocate_http_response();

        populate_http_response(config->response, config->request_type);

        populate_http_request(config->request,
                              config->response,
                              config->connection_info.hostname,
                              config->connection_info.hostport,
                              config->key_ID);
        return status;

HOST_CON_ERR:
        LOG_ERROR("error occured during execution, error code: %d\n", errno);
        return QUEST_ERR;
}

enum kritis3m_status_info quest_send_request(struct quest_configuration* config)
{
        enum kritis3m_status_info status = E_OK;
        duration timeout = ms_to_duration(TIMEOUT_DURATION);
        
        /* if enable_secure_con is true, we use HTTPS */
        if(config->security_param.enable_secure_con)
        {
                status = https_client_req(config->connection_info.socket_fd, config->security_param.tls_session, 
                        config->request, timeout, config->response);
        }
        else /* otherwise we use standard HTTP */
        {
                status = http_client_req(config->connection_info.socket_fd,
                        config->request, timeout, config->response);
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

        return status;
}
