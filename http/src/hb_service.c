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
HardbeatInstructions call_hb_server();

int parse_hb_response(uint8_t *hb_response, int size)
{
    return 0;
}

static void hb_response_cb(struct http_response *rsp,
                        enum http_final_call final_data,
                        void *user_data)
{

    if (final_data == HTTP_DATA_MORE)
    {
        LOG_INFO("Partial data received (%zd bytes)", rsp->data_len);
    }
    else if (final_data == HTTP_DATA_FINAL)
    {

        LOG_INFO("All the data received (%zd bytes)", rsp->data_len);
        // print received content
        // check if application type is json
        parse_hb_response(rsp->body_frag_start, (int)rsp->body_frag_len);

        printf("\n");
    }
}

HardbeatInstructions handle_hb_event(struct pollfd *pfd, asl_endpoint *ep)
{
    switch (pfd->revents)
    {
    case POLLIN:
        return call_hb_server(ep);
        break;
    case POLLERR:
        return HB_ERROR;
        break;
    default:
        return HB_NOTHING;
        break;
    }
    return HB_NOTHING;
}

HardbeatInstructions call_hb_server(asl_endpoint *ep)
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
    if (server_port<0){
        LOG_ERROR("cant convert port to integer"); 
        return HB_ERROR;
    }
    server_addr.sin_port = htons(server_port);
    ret = inet_pton(AF_INET, HB_SERVERADDR, (struct sockaddr *)&server_addr);
    if (ret < 0)
    {
        LOG_ERROR("cant parse ipv 4 addr, errno: ", errno);
        return;
    }
    ret = connect(req_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in));
    if (ret < 0)
    {
        LOG_ERROR("cant connect to client: errno %d", errno);
        return HB_ERROR;
    }
    asl_session *hb_rq_session = asl_create_session(ep, req_fd);


    struct http_request req;
    memset(&req, 0, sizeof(req));
    struct http_status
    {
        bool is_finished;
        uint8_t *response_start;
        int response_size;
    };
    struct http_status user_status = {
        .is_finished = false,
        .response_start = NULL,
        .response_size = 0
        };
    uint8_t response_buffer[HB_RESPONSE_SIZE] ={0}; 

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
     https_client_req(req_fd,hb_rq_session,&req,timeout,&user_status);

    return HB_NOTHING; 
}