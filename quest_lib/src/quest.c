#include "quest.h"
#include "logging.h"
#include "networking.h"

#define TIMEOUT_DURATION 5000

LOG_MODULE_CREATE(quest_lib);

/*------------------------------ private functions -------------------------------*/
static enum kritis3m_status_info establish_host_connection(struct quest_configuration* config)
{
        int status;
        struct addrinfo* bind_addr = NULL;

        /* Look-up IP address from hostname and hostport */
        if ((status = address_lookup_client(config->connection_info.hostname,
                                            (uint16_t) strtol(config->connection_info.hostport, NULL, 10),
                                            &bind_addr)) != 0)
        {
                LOG_ERROR("error looking up server IP address, error code %d", status);
                return ADDR_ERR;
        }

        /* Convert the IP from socket_addr_in to string */
        memcpy(&config->connection_info.IP_v4, bind_addr->ai_addr, sizeof(bind_addr->ai_addr));
        void* addr = &(config->connection_info.IP_v4.sin_addr);
        inet_ntop(bind_addr->ai_family,
                  addr,
                  config->connection_info.IP_str,
                  sizeof(config->connection_info.IP_str));

        LOG_INFO("IP address for %s: %s\n",
                 config->connection_info.hostname,
                 config->connection_info.IP_str);

        /* Convert host port from string to unsigned integer */
        config->connection_info.IP_v4.sin_port = htons(
                strtoul(config->connection_info.hostport, NULL, 10));

        return E_OK;
}

/*------------------------------- public functions -------------------------------*/
struct quest_configuration* quest_default_config(void)
{
        struct quest_configuration* default_config;

        default_config = malloc(sizeof(struct quest_configuration));

        default_config->verbose = false;

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

        status = establish_host_connection(config);
        if (status < E_OK)
        {
                goto HOST_CON_ERR;
        }

        config->connection_info.socket_fd = create_client_socket(AF_INET);
        if (config->connection_info.socket_fd < 0)
        {
                LOG_ERROR("connection failed, error code: %d\n", errno);
                status = SOCKET_ERR;
                goto SOCKET_CON_ERR;
        }

        if (connect(config->connection_info.socket_fd,
                    (struct sockaddr*) &config->connection_info.IP_v4,
                    sizeof(config->connection_info.IP_v4)) < 0)
        {

                LOG_ERROR("connection failed, error code: %d\n", errno);
                status = SOCKET_ERR;
                goto SOCKET_CON_ERR;
        }

        config->request = allocate_http_request();

        config->response = allocate_http_response();

        populate_http_response(config->response, config->request_type);

        populate_http_request(config->request,
                              config->response,
                              config->connection_info.hostname,
                              config->connection_info.hostport,
                              config->key_ID);

SOCKET_CON_ERR:
        return status;

HOST_CON_ERR:
        LOG_ERROR("error occured during execution, error code: %d\n", errno);
        return QUEST_ERR;
}

enum kritis3m_status_info quest_send_request(struct quest_configuration* config)
{
        enum kritis3m_status_info status = E_OK;
        duration timeout = ms_toduration(TIMEOUT_DURATION);

        status = http_client_req(config->connection_info.socket_fd,
                                 config->request,
                                 timeout,
                                 config->response);
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
