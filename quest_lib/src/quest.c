#include "quest.h"
#include "logging.h"
#include "networking.h"

#define TIMEOUT_DURATION 5000

LOG_MODULE_CREATE(quest_lib);

/*------------------------------ private functions -------------------------------*/

#if defined(__ZEPHYR__)
/// @brief As zephyr operates with it's own type of address information (zsock_addrinfo),
///        we need to convert the address variable derived from the getaddressinfo()
///        call into a variable of type sockaddr_in, to ensure correct behaviour later on.
/// @param zaddr_info zephyr socket address info struct previously passed to the
///                   getaddressinfo() function.
/// @param addr pointer to the destination sockaddr_in variable used later on.
/// @return returns E_OK if working correctly, otherwise returns an error code less than zero.
static enum kritis3m_status_info convert_addrinfo_to_sockaddr_in(struct zsock_addrinfo* zaddr_info,
                                                                 struct sockaddr_in* addr)
{
        if (zaddr_info == NULL || addr == NULL)
        {
                LOG_ERROR("passed argument was NULL!");
                return E_NOT_OK;
        }

        // We expect the resolved address to be of type IPv4.
        // TODO: integrate IPv6 support here.
        if (zaddr_info->ai_family == AF_INET)
        {
                struct sockaddr_in* addr_in = (struct sockaddr_in*) zaddr_info->ai_addr;
                *addr = *addr_in;
        }
        else
        {
                LOG_WARN("resolved IP address was not of type IPv4.");
                return ADDR_ERR;
        }

        return E_OK;
}
#endif

/// @brief To initialize the quest lib we establish a connection to the QKD line. This
///        requires a DNS resolve call to get the IP address of the QKD server and subsequent
///        socket preparation and connection establishment.
/// @param config quest_configuration containing the connection_info parameters.
/// @return returns E_OK if working correctly, otherwise returns an error code less than zero.
static enum kritis3m_status_info establish_host_connection(struct quest_configuration* config)
{
        int status;

#if defined(__ZEPHYR__)
        /* zephyr's socket addrinfo variable to store resolved IP address */
        struct zsock_addrinfo* bind_addr = NULL;
#else
        /* addrinfo* variable to store resolved IP address */
        struct addrinfo* bind_addr = NULL;
#endif
        /* Look-up IP address from hostname and hostport */
        status = address_lookup_client(config->connection_info.hostname,
                                       (uint16_t) strtol(config->connection_info.hostport, NULL, 10),
                                       &bind_addr, AF_INET);
        if (status != 0)
        {
                LOG_ERROR("error looking up server IP address, error code %d", status);
                return ADDR_ERR;
        }

#if defined(__ZEPHYR__)
        /* Convert zephyr's socket address info to socket address_in */
        status = convert_addrinfo_to_sockaddr_in(bind_addr, &config->connection_info.IP_v4);
        if (status != E_OK)
        {
                LOG_ERROR("error occured during address conversion.");
                return ADDR_ERR;
        }
#else
        /* Copy binary version of the IP address */
        memcpy(&config->connection_info.IP_v4, &bind_addr->ai_addr, sizeof(&bind_addr->ai_addr));
#endif

        /* Convert the IP from socket_addr_in to string */
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
        duration timeout = ms_to_duration(TIMEOUT_DURATION);

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
