#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "asl.h"
#include "http_client.h"
#include "http_method.h"
#include "http_service.h"
#include "linux_comp.h"
#include "logging.h"
#include "networking.h"
#include "utils.h"
LOG_MODULE_CREATE(http_service);

#define DISTRIBUTION_BUFFER_SIZE 5000
#define STATUS_BUFFER_SIZE 1000

//------------------------------------ DEFINTIONS------------------------------------------//

enum request_type
{
        REQ_UNDIFINED,
        REQ_DISTRIBUTION
} request_type;

// makes no sense
struct distribution_request
{
        int version_number;
        char* updated_at;
};

typedef struct
{
        int sock;
        asl_session* session;
        enum request_type request_type;
        union req
        {
                struct distribution_request dist_req;
                char* some_other_req;
        } req;
} request_object;

struct conn
{
        struct addrinfo* mgmt_sockaddr;
        asl_endpoint* mgmt_endpoint;
        request_object mgmt_req;
};

typedef struct
{
        char serial_number[SERIAL_NUMBER_SIZE];
        /**
         * used for the connection to the server
         */
        struct conn con;

#ifdef PKI_READY
        struct management_pki
        {
                struct addrinfo* mgmt_sockaddr;
                asl_endpoint* pki_endpoint;
        } mgmt_pki;
#endif

} Http_service_module;

static Http_service_module http_service = {0};

/*-----------------------------  FORWARD DECLARATIONS -------------------------------------*/

int create_send_status_url(char* url, int url_size, int cfg_id, int version_number);
void set_http_service_defaults(Http_service_module* service);
void cleanup_request_object(request_object* con);
int startup_connection(struct conn* con);
int create_inital_controller_url(char* url, int url_size);
int create_periodic_controller_url(char* url, int url_size, int version_number);
/*-----------------------------  END FORWARD DECLARATIONS -------------------------------------*/

static void http_status_cb(struct http_response* rsp, enum http_final_call final_data, void* user_data);

/**
 * Initialize the HTTP service module with the provided configuration
 * Returns 0 on success, -1 on failure
 */
int init_http_service(Kritis3mManagemntConfiguration* config,
                      asl_endpoint_configuration* mgmt_endpoint_config
#ifdef PKI_READY
                      ,
                      asl_endpoint_configuration* pki_endpoint_config
#endif
)
{
        // Initialize with default values
        set_http_service_defaults(&http_service);

        strncpy(http_service.serial_number, config->serial_number, SERIAL_NUMBER_SIZE);

        // Perform address lookup for management endpoint
        if (address_lookup_client(config->server_endpoint_addr.address,
                                  config->server_endpoint_addr.port,
                                  (struct addrinfo**) &http_service.con.mgmt_sockaddr) != 0)
        {
                goto cleanup;
        }

        // Setup management endpoint
        http_service.con.mgmt_endpoint = asl_setup_client_endpoint(mgmt_endpoint_config);
        if (!http_service.con.mgmt_endpoint)
                goto cleanup;

// Perform address lookup for PKI endpoint
#ifdef PKI_READY
        if (address_lookup_client(config->identity.server_endpoint_addr.address,
                                  config->identity.server_endpoint_addr.port,
                                  (struct addrinfo**) &http_service.mgmt_pki.mgmt_sockaddr) != 0)
        {
                goto cleanup;
        }

        // Setup PKI endpoint
        http_service.mgmt_pki.pki_endpoint = asl_setup_client_endpoint(pki_endpoint_config);
        if (!http_service.mgmt_pki.pki_endpoint)
        {
                goto cleanup;
        }
#endif

        return 0;

cleanup:
        cleanup_http_service();
        return -1;
}

/**
 * Set default values for the HTTP service module
 */
void set_http_service_defaults(Http_service_module* service)
{
        memset(http_service.serial_number, 0, SERIAL_NUMBER_SIZE);
        http_service.con.mgmt_endpoint = NULL;
        http_service.con.mgmt_sockaddr = NULL;

        // set req defaults
        http_service.con.mgmt_req.session = NULL;
        http_service.con.mgmt_req.sock = -1;
        http_service.con.mgmt_req.request_type = REQ_UNDIFINED;
        memset(&http_service.con.mgmt_req.req, 0, sizeof(http_service.con.mgmt_req.req));

        // clear union

#ifdef PKI_READY
        service->mgmt_pki.mgmt_sockaddr = NULL;
        service->mgmt_pki.pki_endpoint = NULL;
#endif
}

/**
 * Clean up resources associated with the HTTP service module
 */
void cleanup_http_service(void)
{

        if (http_service.con.mgmt_req.session != NULL)
        {
                asl_close_session(http_service.con.mgmt_req.session);
                asl_free_session(http_service.con.mgmt_req.session);
        }
        if (http_service.con.mgmt_req.sock > 0)
                closesocket(http_service.con.mgmt_req.sock);

        // Clean up management connection
        if (http_service.con.mgmt_endpoint)
                asl_free_endpoint(http_service.con.mgmt_endpoint);

        if (http_service.con.mgmt_sockaddr)
                freeaddrinfo(http_service.con.mgmt_sockaddr);

#ifdef PKI_READY
        if (http_service.mgmt_pki.mgmt_sockaddr)
                freeaddrinfo(http_service.mgmt_pki.mgmt_sockaddr);

        // Clean up PKI connection
        if (http_service.mgmt_pki.pki_endpoint)
                asl_free_endpoint(http_service.mgmt_pki.pki_endpoint);
#endif

        // Reset all pointers to NULL
        set_http_service_defaults(&http_service);
}
/**
 * Terminate the HTTP service module
 * @todo probably close cons
 * @todo con objects for requests
 */
int terminate_http_service(void)
{
        cleanup_http_service();

        return 0;
}

/********   FORWARD DECLARATION ***************/
static void http_status_cb(struct http_response* rsp, enum http_final_call final_data, void* user_data)
{
        struct response* http_request_status = (struct response*) user_data;
        if (http_request_status == NULL)
                return;

        if (final_data == HTTP_DATA_FINAL)
        {
                switch (rsp->http_status_code)
                {
                case HTTP_OK:
                        LOG_INFO("SUCCESFULL REQUEST");
                        http_request_status->bytes_received = rsp->body_frag_len;
                        http_request_status->buffer_frag_start = rsp->body_frag_start;
                        http_request_status->ret = MGMT_OK;
                        break;
                case HTTP_BAD_REQUEST:
                        LOG_ERROR("bad request");
                        http_request_status->ret = MGMT_BAD_PARAMS;
                        goto error_occured;
                        break;
                case HTTP_SERVICE_UNAVAILABLE:
                        http_request_status->ret = MGMT_BAD_REQUEST;
                        goto error_occured;
                        break;
                case HTTP_TOO_MANY_REQUESTS:
                        LOG_DEBUG("Retry later");
                        http_request_status->ret = MGMT_BUSY;
                        goto error_occured;
                        break;
                default:
                        LOG_ERROR("responded http code is not handled, http response code: %d",
                                  rsp->http_status_code);
                        break;
                }

                http_request_status->http_status_code = HTTP_OK;
        }
        else
        {
                LOG_DEBUG("Partial data received (%zd bytes)", rsp->data_len);
        }

        return;
error_occured:
        http_request_status->http_status_code = rsp->http_status_code;
        http_request_status->bytes_received = 0;
        http_request_status->buffer_frag_start = NULL;
        return;
}

int startup_connection(struct conn* con)
{
        int ret = 0;

        if ((con == NULL) || (con->mgmt_endpoint == NULL) || (con->mgmt_sockaddr == NULL))
                return -1;

        con->mgmt_req.sock = socket(con->mgmt_sockaddr->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (con->mgmt_req.sock < 0)
                goto error_occured;

        ret = connect(con->mgmt_req.sock,
                      (struct sockaddr*) con->mgmt_sockaddr->ai_addr,
                      con->mgmt_sockaddr->ai_addrlen);
        if (ret < 0)
                goto error_occured;

        con->mgmt_req.session = asl_create_session(con->mgmt_endpoint, con->mgmt_req.sock);
        if (con->mgmt_req.session == NULL)
                goto error_occured;
        ret = asl_handshake(con->mgmt_req.session);
        if (ret < 0)
        {
                LOG_ERROR("handshake with controller failed");
                goto error_occured;
        }
        return ret;

error_occured:
        LOG_ERROR("error occured in startup_connectioN");

        ret = -1;
        return ret;
}

int send_statusto_server(t_http_get_cb response_callback,
                         int version_number,
                         int cfg_id,
                         char* payload,
                         int payload_size)
{
        //---------------------------------initialization ---------------------------------//
        char url[520];
        char host[NI_MAXHOST];
        char port[NI_MAXSERV];
        char ip_type[10];
        int ret = 0;
        int fd = -1;
        struct http_request req = {0};
        char response_buffer[STATUS_BUFFER_SIZE];
        struct response response = {.buffer = response_buffer,
                                    .buffer_frag_start = NULL,
                                    .buffer_size = STATUS_BUFFER_SIZE,
                                    .http_status_code = -1,
                                    .ret = -1,
                                    .service_used = MGMT_SEND_STATUS_REQ};

        memset(host, 0, NI_MAXHOST);
        memset(port, 0, NI_MAXSERV);
        memset(ip_type, 0, 10);
        //---------------------------------initialization ---------------------------------//

        // get host
        ret = getnameinfo(http_service.con.mgmt_sockaddr->ai_addr,
                          http_service.con.mgmt_sockaddr->ai_addrlen,
                          host,
                          sizeof(host),
                          NULL,
                          0,
                          NI_NUMERICHOST);
        if (ret < 0)
                goto error_occured;
        // get port from addr info
        ret = getnameinfo(http_service.con.mgmt_sockaddr->ai_addr,
                          http_service.con.mgmt_sockaddr->ai_addrlen,
                          NULL,
                          0,
                          port,
                          sizeof(port),
                          NI_NUMERICSERV);
        if (ret < 0)
                goto error_occured;

        // Determine IP type
        if (http_service.con.mgmt_sockaddr->ai_addr->sa_family == AF_INET)
        {
                strcpy(ip_type, "IPv4");
        }
        else if (http_service.con.mgmt_sockaddr->ai_addr->sa_family == AF_INET6)
        {
                strcpy(ip_type, "IPv6");
        }
        else
        {
                strcpy(ip_type, "Unknown");
        }

        ret = create_send_status_url(url, 520, cfg_id, version_number);
        if (ret < 0)
                goto error_occured;

        req.url = url;
        req.method = HTTP_POST;
        req.protocol = "HTTP/1.1";
        req.response = http_status_cb;
        req.host = host;
        req.port = port;
        req.recv_buf = response_buffer;
        req.recv_buf_len = sizeof(response_buffer);
        req.content_type_value = "application/json";
        req.payload = payload;
        req.payload_len = payload_size;

        duration timeout = ms_toduration(14 * 1000);

        ret = startup_connection(&http_service.con);
        if (ret < 0)
                goto error_occured;

        ret = https_client_req(http_service.con.mgmt_req.sock,
                               http_service.con.mgmt_req.session,
                               &req,
                               timeout,
                               &response);
        if (ret < 0)
        {
                LOG_ERROR("error occured calling distribution server %d", ret);
                response.ret = MGMT_ERR;
        }
        else
        {
                LOG_DEBUG("succesfull http request to management server");
                response.ret = MGMT_OK;
        }

        // Print detailed connection information
        LOG_INFO("Connection Details:\n"
                 "  IP Type:   %s\n"
                 "  Host/IP:   %s\n"
                 "  Port:      %s\n",
                 ip_type,
                 host,
                 port);

        if (response_callback)
                ret = response_callback(response);

        cleanup_request_object(&http_service.con.mgmt_req);

        return ret;
error_occured:
        ret = -1;
        cleanup_request_object(&http_service.con.mgmt_req);
        return ret;
}
int initial_call_controller(t_http_get_cb response_callback)
{
        //---------------------------------initialization ---------------------------------//
        char url[520];
        char host[NI_MAXHOST];
        char port[NI_MAXSERV];
        char ip_type[10];
        int ret = 0;
        int fd = -1;
        struct http_request req = {0};
        char response_buffer[DISTRIBUTION_BUFFER_SIZE];
        struct response response = {.buffer = response_buffer,
                                    .buffer_frag_start = NULL,
                                    .buffer_size = DISTRIBUTION_BUFFER_SIZE,
                                    .http_status_code = -1,
                                    .ret = -1,
                                    .service_used = MGMT_POLICY_REQ};

        memset(host, 0, NI_MAXHOST);
        memset(port, 0, NI_MAXSERV);
        memset(ip_type, 0, 10);
        //---------------------------------initialization ---------------------------------//

        if ((response_callback == NULL))
                goto error_occured;

        // get host
        ret = getnameinfo(http_service.con.mgmt_sockaddr->ai_addr,
                          http_service.con.mgmt_sockaddr->ai_addrlen,
                          host,
                          sizeof(host),
                          NULL,
                          0,
                          NI_NUMERICHOST);
        if (ret < 0)
                goto error_occured;
        // get port from addr info
        ret = getnameinfo(http_service.con.mgmt_sockaddr->ai_addr,
                          http_service.con.mgmt_sockaddr->ai_addrlen,
                          NULL,
                          0,
                          port,
                          sizeof(port),
                          NI_NUMERICSERV);
        if (ret < 0)
                goto error_occured;

        // Determine IP type
        if (http_service.con.mgmt_sockaddr->ai_addr->sa_family == AF_INET)
        {
                strcpy(ip_type, "IPv4");
        }
        else if (http_service.con.mgmt_sockaddr->ai_addr->sa_family == AF_INET6)
        {
                strcpy(ip_type, "IPv6");
        }
        else
        {
                strcpy(ip_type, "Unknown");
        }

        // Print detailed connection information
        LOG_INFO("Connection Details:\n"
                 "  IP Type:   %s\n"
                 "  Host/IP:   %s\n"
                 "  Port:      %s\n",
                 ip_type,
                 host,
                 port);

        ret = create_inital_controller_url(url, 520);
        if (ret < 0)
                goto error_occured;

        req.url = url;
        req.method = HTTP_GET;
        req.protocol = "HTTP/1.1";
        req.response = http_status_cb;
        req.host = host;
        req.port = port;
        req.recv_buf = response_buffer;
        req.recv_buf_len = sizeof(response_buffer);
        duration timeout = ms_toduration(14 * 1000);

        ret = startup_connection(&http_service.con);
        if (ret < 0)
                goto error_occured;

        ret = https_client_req(http_service.con.mgmt_req.sock,
                               http_service.con.mgmt_req.session,
                               &req,
                               timeout,
                               &response);
        if (ret < 0)
        {
                LOG_ERROR("error occured calling distribution server %d", ret);
                response.ret = MGMT_ERR;
        }
        else
        {
                LOG_DEBUG("succesfull http request to management server");
                response.ret = MGMT_OK;
        }
        ret = response_callback(response);
        cleanup_request_object(&http_service.con.mgmt_req);
        return ret;
error_occured:
        ret = -1;
        cleanup_request_object(&http_service.con.mgmt_req);
        return ret;
}

void cleanup_request_object(request_object* req)
{
        if (req == NULL)
                return;
        if (req->session != NULL)
        {
                asl_close_session(req->session);
                asl_free_session(req->session);
        }

        if (req->sock > 0)
        {
                closesocket(req->sock);
                req->sock = -1;
        }
}

//----------------------------------------------  CREATE URL ------------------------------------------------//

int create_inital_controller_url(char* url, int url_size)
{
        if (url == NULL)
                return -1;
        return snprintf(url, url_size, "/api/node/%s/initial/register", http_service.serial_number);
}

int create_send_status_url(char* url, int url_size, int cfg_id, int version_number)
{
        if (url == NULL)
                return -1;
        return snprintf(url,
                        url_size,
                        "/api/node/%s/config/%d/version/%d",
                        http_service.serial_number,
                        cfg_id,
                        version_number);
}

int create_periodic_controller_url(char* url, int url_size, int version_number)
{
        int ret = -1;
        if (url == NULL)
                return -1;

        ret = snprintf(url,
                       url_size,
                       "/api/node/%s/operation/version/%d/heartbeat",
                       http_service.serial_number,
                       version_number);
        return ret;
}
