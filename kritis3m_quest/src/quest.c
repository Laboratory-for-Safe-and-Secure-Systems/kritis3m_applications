#include "quest.h"

#define TIMEOUT_DURATION 5000

/*------------------------------ private functions -------------------------------*/
static enum kritis3m_status_info establish_host_connection(struct quest_configuration* config)
{
        int sock = -1;
        struct addrinfo hints;
        struct addrinfo* res;

        // Initialize the hints struct
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET; // Use AF_INET for IPv4 or AF_INET6 for IPv6
        hints.ai_socktype = SOCK_STREAM;

        // Get address information
        int status;
        if ((status = getaddrinfo(config->connection_info.hostname, NULL, &hints, &res)) != 0)
        {
                printf("[ QUEST ][ FATAL ERROR ] getaddrinfo error: %s\n", gai_strerror(status));
                return ADDR_ERR;
        }

        // Convert the IP to a string and print it
        memcpy(&config->connection_info.IP_v4, res->ai_addr, sizeof(res->ai_addr));
        void* addr = &(config->connection_info.IP_v4.sin_addr);

        inet_ntop(res->ai_family,
                  addr,
                  config->connection_info.IP_str,
                  sizeof(config->connection_info.IP_str));

#ifdef VERBOSE
        printf("[ QUEST ][ INFO ] IP address for %s: %s\n",
               config->connection_info.hostname,
               config->connection_info.IP_str);
#endif

        config->connection_info.IP_v4.sin_port = htons(
                strtoul(config->connection_info.hostport, NULL, 10));

        free(res);
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

        config->connection_info.socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (config->connection_info.socket_fd < 0)
        {
                status = SOCKET_ERR;
                goto SOCKET_CON_ERR;
        }

        status = connect(config->connection_info.socket_fd,
                         (struct sockaddr*) &config->connection_info.IP_v4,
                         sizeof(config->connection_info.IP_v4));
        if (status < 0)
        {
                printf("connection failed, error code: %d\n", errno);
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
        printf("[ QUEST ][ ERROR ] error occured during execution, error code: %d\n", errno);
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
                printf("[ QUEST ][ ERROR ]failed to send HTTP-GET request, error code: %d\n", status);
                status = CON_ERR;
        }
        else
        {
                status = E_OK;
        }

        return status;
}