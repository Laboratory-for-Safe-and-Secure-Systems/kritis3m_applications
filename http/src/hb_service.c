#include "hb_service.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "logging.h"
#include "mgmt_certs.h"
#include "cJSON.h"
LOG_MODULE_CREATE(hb_service);

#define HB_SERVERADDR "192.168.3.3"
#define HB_SERVERPORT "1231"
#define HB_RESPONSE_SIZE 400
#define HB_URL (HB_SERVERADDR ":" HB_SERVERPORT "/hb_service/moin/")

/*********** FORWARD DECLARATIONS ******************/
int call_hb_server(asl_endpoint *ep, HardbeatResponse *rsp);

int parse_hb_response(uint8_t *hb_response, int size)
{
    int ret = -1;
    cJSON *json = cJSON_ParseWithLength(hb_response, size);
    if (json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            fprintf(stderr, "Error before: %s\n", error_ptr);
        }
        return -1;
    }
    /**********
     * @todo implementing hardbeat parser!!
     */

    return 0;
}

struct http_user_data
{
    bool is_finished;
    bool error_occured;
    HardbeatResponse response;
    char *error_msg;
};

static void hb_response_cb(struct http_response *rsp,
                           enum http_final_call final_data,
                           void *user_data)
{

    struct http_user_data *user_status = (struct http_user_data *)user_status;
    if (final_data == HTTP_DATA_MORE)
    {
        LOG_INFO("Partial data received (%zd bytes)", rsp->data_len);
        user_status->is_finished = false;
    }
    else if (final_data == HTTP_DATA_FINAL)
    {
        user_status->is_finished = true;
        switch (rsp->http_status_code)
        {
        case HTTP_OK:
            LOG_INFO("SUCCESFULL REQUEST");
            user_status->error_msg = HTTP_OK_MSG;
            cJSON *json = cJSON_ParseWithLength(rsp->body_frag_start, rsp->body_frag_len);
            if (json == NULL)
            {
                const char *error_ptr = cJSON_GetErrorPtr();
                if (error_ptr != NULL)
                {
                    LOG_ERROR("Error before: %s\n", error_ptr);
                }
                user_status->error_occured = true;
                return;

                cJSON *js_hardbeat_rsp = cJSON_GetObjectItemCaseSensitive(json, "HB_response");
                if (cJSON_IsObject(js_hardbeat_rsp))
                {
                    /****************** GET Hardbeat Instruction ************************/
                    cJSON *js_item = cJSON_GetObjectItemCaseSensitive(js_hardbeat_rsp, "HB_instruction");
                    if (cJSON_IsNumber(js_item))
                    {
                        int t_hb_instruction = js_item->valueint;
                        if ((t_hb_instruction <= HB_SET_DEBUG_LEVEL) && (t_hb_instruction >= HB_ERROR))
                        {
                            user_status->response.HardbeatInstruction = js_item->valueint;
                        }
                        else
                        {
                            user_status->error_occured = true;
                            return;
                        }
                    }
                    /****************** GET HB Interval************************/
                    js_item = cJSON_GetObjectItemCaseSensitive(js_hardbeat_rsp, "HB_interval_s");
                    if (cJSON_IsNumber(js_item))
                    {
                        uint64_t t_hb_interval = js_item->valueint;
                        /*********
                         * @todo check if parsing works for large integer values
                         *
                         */
                        if (t_hb_interval > 0)
                        {
                            user_status->response.HardbeatInterval_s = js_item->valueint;
                        }
                        else
                        {
                            user_status->error_occured = true;
                            return;
                        }
                    }
                    user_status->error_occured = false;
                }
                break;
            case HTTP_BAD_REQUEST:
                user_status->error_occured = true;
                user_status->error_msg = HTTP_BAD_REQUEST_MSG;
                LOG_ERROR("bad request");
                break;
            case HTTP_SERVICE_UNAVAILABLE:
                user_status->error_occured = true;
                user_status->error_msg = HTTP_SERVICE_UNAVAILABLE_MSG;
                LOG_INFO("Hardbeat service is not supported from the server");
                break;
            case HTTP_TOO_MANY_REQUESTS:
                user_status->error_occured = true;
                user_status->error_msg = HTTP_TOO_MANY_REQUESTS_MSG;
                LOG_INFO("Retry later");
                break;
            default:
                user_status->error_occured = true;
                user_status->error_msg = HTTP_DEFAULT_MSG;
                LOG_ERROR("responded http code is not handled, http response code: %d", rsp->http_status_code);
                break;
            }
        }
    }
}

int handle_hb_event(struct pollfd *pfd, asl_endpoint *ep, HardbeatResponse *rsp)
{
    switch (pfd->revents)
    {
    case POLLIN:
        return call_hb_server(ep, rsp);
        break;
    case POLLERR:
        return -1;
        break;
    default:
        return -1;
        break;
    }
    return HB_NOTHING;
}

int call_hb_server(asl_endpoint *ep, HardbeatResponse *rsp)
{
    int ret = -1;
    /**************** OPEN SOCKET *************/

    int req_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (req_fd < 0)
    {
        LOG_ERROR("error obtaining fd, errno: ", errno);
    }
    /********** TCP CONNECTION ************/
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    int server_port = atoi(HB_SERVERPORT);
    if (server_port < 0)
    {
        LOG_ERROR("cant convert port to integer");
        return -1;
    }
    server_addr.sin_port = htons(server_port);
    ret = inet_pton(AF_INET, HB_SERVERADDR, (struct sockaddr *)&server_addr);
    if (ret < 0)
    {
        LOG_ERROR("cant parse ipv 4 addr, errno: ", errno);
        return -1;
    }
    ret = connect(req_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in));
    if (ret < 0)
    {
        LOG_ERROR("cant connect to client: errno %d", errno);
        return -1;
    }
    asl_session *hb_rq_session = asl_create_session(ep, req_fd);

    struct http_request req;
    memset(&req, 0, sizeof(req));
    struct http_user_data user_response_data = {0};
    uint8_t response_buffer[HB_RESPONSE_SIZE] = {0};

    req.method = HTTP_GET;
    req.url = HB_URL;
    req.host = HB_SERVERADDR;
    req.protocol = "HTTP/1.1";
    /**
     * @todo evaluate if response handling in callback or
     * response handling after request is superior
     */
    req.response = hb_response_cb;
    req.recv_buf = response_buffer;
    req.recv_buf_len = sizeof(response_buffer);

    int32_t timeout = 3 * MSEC_PER_SEC;
    ret = https_client_req(req_fd, hb_rq_session, &req, timeout, &user_response_data);
    if (ret < 0)
    {
        LOG_ERROR("error on client req. need to implment error handler");
        return -1;
    }

    if (user_response_data.is_finished)
    {
        memcpy(rsp,
               &user_response_data.response,
               sizeof(user_response_data.response));
    }

    return 0;
}