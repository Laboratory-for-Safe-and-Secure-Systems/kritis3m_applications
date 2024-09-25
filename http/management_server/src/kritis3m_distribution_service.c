
#include "kritis3m_distribution_service.h"

#include "logging.h"
#include "mgmt_certs.h"
#include "cJSON.h"
#include "http_client.h"

#include <arpa/inet.h>
LOG_MODULE_CREATE(policy_distribution_service);

#define POLICY_SERVERADDR "192.168.3.3"
#define POLICY_SERVERPORT "1231"
#define POLICY_RESPONSE_SIZE 4000

/***
 * @todo link the correct URL
 */
#define POLICY_URL (POLICY_SERVERADDR ":" POLICY_SERVERPORT "/hb_service/moin/")

struct http_policy_distribution_user_data
{
    bool is_finished;
    bool error_occured;
    kritis3m_service *response;
    char *error_msg;
};

/********   FORWARD DECLARATION ***************/

static void policy_response_cb(struct http_response *rsp,
                               enum http_final_call final_data,
                               void *user_data)
{
    struct http_policy_distribution_user_data *user_data_ref = (struct http_policy_distribution_user_data *)user_data;
    if (final_data == HTTP_DATA_MORE)
    {
        LOG_INFO("Partial data received (%zd bytes)", rsp->data_len);
        user_data_ref->is_finished = false;
    }
    else if (final_data == HTTP_DATA_FINAL)
    {
        user_data_ref->is_finished = true;
        switch (rsp->http_status_code)
        {
        case HTTP_OK:
            LOG_INFO("SUCCESFULL REQUEST");
            user_data_ref->error_msg = HTTP_OK_MSG;
            // int ret = parse_system_config(rsp->body_frag_start, rsp->body_frag_len, user_data_ref->response);
            // if (ret < 0)
            // {
            //     user_data_ref->error_occured = true;
            //     user_data_ref->error_msg = HTTP_DEFAULT_MSG;
            //     LOG_ERROR("parser error");
            // }

            break;
        case HTTP_BAD_REQUEST:
            user_data_ref->error_occured = true;
            user_data_ref->error_msg = HTTP_BAD_REQUEST_MSG;
            LOG_ERROR("bad request");
            break;
        case HTTP_SERVICE_UNAVAILABLE:
            user_data_ref->error_occured = true;
            user_data_ref->error_msg = HTTP_SERVICE_UNAVAILABLE_MSG;
            LOG_INFO("Hardbeat service is not supported from the server");
            int ret = -1;
            break;
        case HTTP_TOO_MANY_REQUESTS:
            user_data_ref->error_occured = true;
            user_data_ref->error_msg = HTTP_TOO_MANY_REQUESTS_MSG;
            LOG_INFO("Retry later");
            break;
        default:
            user_data_ref->error_occured = true;
            user_data_ref->error_msg = HTTP_DEFAULT_MSG;
            LOG_ERROR("responded http code is not handled, http response code: %d", rsp->http_status_code);
            break;
        }
    }
}

int call_policy_distribution_server(asl_endpoint *ep, PolicyResponse *rsp)
{
    int ret = -1;
    asl_session *policy_rq_session = NULL;

    int req_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (req_fd < 0)
    {
        LOG_ERROR("error obtaining fd, errno: ", errno);
    }
    /********** TCP CONNECTION ************/
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    int server_port = atoi(POLICY_SERVERPORT);
    if (server_port < 0)
    {
        LOG_ERROR("cant convert port to integer");
        goto shutdown;
    }
    server_addr.sin_port = htons(server_port);
    ret = inet_pton(AF_INET, POLICY_SERVERADDR, (struct sockaddr *)&server_addr);
    if (ret < 0)
    {
        LOG_ERROR("cant parse ipv 4 addr, errno: ", errno);
        goto shutdown;
    }
    ret = connect(req_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in));
    if (ret < 0)
    {
        LOG_ERROR("cant connect to client: errno %d", errno);
        return -1;
    }
    policy_rq_session = asl_create_session(ep, req_fd);

    struct http_request req;
    memset(&req, 0, sizeof(req));

    struct http_policy_distribution_user_data user_response_data = {
        .is_finished = false,
        .error_msg = NULL,
        .error_occured = false,
        .response = &rsp->system_configuration};

    uint8_t response_buffer[POLICY_RESPONSE_SIZE] = {0};

    req.method = HTTP_GET;
    req.url = POLICY_URL;
    req.host = POLICY_SERVERADDR;
    req.protocol = "HTTP/1.1";
    /**
     * @todo evaluate if response handling in callback or
     * response handling after request is superior
     */
    req.response = policy_response_cb;
    req.recv_buf = response_buffer;
    req.recv_buf_len = sizeof(response_buffer);

    int32_t timeout = 3 * MSEC_PER_SEC;
    ret = https_client_req(req_fd, policy_rq_session, &req, timeout, &user_response_data);
    if (ret < 0)
    {
        LOG_ERROR("error on client req. need to implment error handler");
        goto shutdown;
    }

    asl_close_session(policy_rq_session);
    asl_free_session(policy_rq_session);
    return 0;
shutdown:
    // its ok to call these functions withh nullptr. no checks required
    asl_close_session(policy_rq_session);
    asl_free_session(policy_rq_session);

    return -1;
}
