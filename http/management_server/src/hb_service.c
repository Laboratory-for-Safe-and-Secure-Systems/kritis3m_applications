#include "hb_service.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "logging.h"
#include "mgmt_certs.h"
#include "cJSON.h"
#include "http_client.h"

LOG_MODULE_CREATE(hb_service);

int handle_hb_event(struct pollfd *pfd, asl_endpoint *ep, HardbeatResponse *rsp);

void handle_hb_server_response_cb(struct http_response *rsp,
                                  enum http_final_call final_data,
                                  void *user_data);

/*********** FORWARD DECLARATIONS ******************/
int call_hb_server(asl_endpoint *ep, HardbeatResponse *rsp);

struct http_user_data
{
    bool is_finished;
    bool error_occured;
    HardbeatResponse response;
    char *error_msg;
};
struct TimerPipe
{
    int pipe_fds[2];
    timer_t timerid;
};

int get_clock_signal_fd(TimerPipe *pipe)
{
    int ret = pipe->pipe_fds[0];
    if (ret < 0)
    {
        LOG_ERROR("Error: Invalid file descriptor");
        return -1;
    }
    return ret;
}

static void timer_handler(union sigval arg)
{
    TimerPipe *tp = (TimerPipe *)arg.sival_ptr;
    uint8_t signal = 1;
    write(tp->pipe_fds[1], &signal, sizeof(signal)); // Notify the pipe on timer expiration
}

// Function to start the timer with the given interval
int timer_start(TimerPipe *pipe, uint32_t interval_sec)
{
    int ret = 0;
    struct itimerspec its;
    its.it_value.tv_sec = interval_sec;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = interval_sec; // Repeat at the same interval
    its.it_interval.tv_nsec = 0;

    if (timer_settime(pipe->timerid, 0, &its, NULL) == -1)
    {
        ret = -1;
        LOG_ERROR("timer_settime failed\n");
        return ret;
    }
    LOG_INFO("Timer started with interval %d seconds\n", interval_sec);
    return ret;
}

// Function to stop the timer
int timer_stop(TimerPipe *pipe)
{
    int ret = 0;
    struct itimerspec its;
    memset(&its, 0, sizeof(struct itimerspec)); // Set both interval and value to
                                                // zero to stop the timer

    if (timer_settime(pipe->timerid, 0, &its, NULL) == -1)
    {
        LOG_ERROR("timer_stop failed");
        ret = -1;
        return ret;
    }

    LOG_INFO("Timer stopped");
    return ret;
}

// Function to change the timer interval while it is running
int timer_change_interval(TimerPipe *pipe, int new_interval_sec)
{
    int ret = 0;
    struct itimerspec its;
    its.it_value.tv_sec = new_interval_sec;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = new_interval_sec;
    its.it_interval.tv_nsec = 0;

    if (timer_settime(pipe->timerid, 0, &its, NULL) == -1)
    {
        ret = -1;
        LOG_ERROR("timer_change_interval failed");
        return ret;
    }
    LOG_INFO("Timer interval changed to %d seconds", new_interval_sec);
    return ret;
}

// Initialize the POSIX timer and pipe for communication
int init_posix_timer(TimerPipe *timer_pipe)
{
    int ret = 0;
    struct sigevent sev;

    // Set up the pipe for communication
    if (pipe(timer_pipe->pipe_fds) == -1)
    {
        ret = -1;
        LOG_ERROR("pipe failed");
        return ret;
    }

    // Set pipe to non-blocking mode
    fcntl(timer_pipe->pipe_fds[0], F_SETFL, O_NONBLOCK);

    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_value.sival_ptr = timer_pipe;
    sev.sigev_notify_function = timer_handler;
    sev.sigev_notify_attributes = NULL; // Use default thread attributes

    if (timer_create(CLOCK_REALTIME, &sev, &timer_pipe->timerid) == -1)
    {
        ret = -1;
        LOG_ERROR("timer_create failed\n");
        return ret;
    }
    return ret;
}

// Function to terminate the timer and clean up resources
int timer_terminate(TimerPipe *timer_pipe)
{
    int ret = 0;

    // Stop the timer before deleting
    ret = timer_stop(timer_pipe);
    if (ret < 0)
    {
        LOG_ERROR("couldn't stop timer");
        ret = -1;
    }

    // Delete the timer
    if (timer_delete(timer_pipe->timerid) == -1)
    {
        LOG_ERROR("failed timer delete");
        ret = -1;
        return ret;
    }

    // Close the communication pipes
    close(timer_pipe->pipe_fds[0]);
    close(timer_pipe->pipe_fds[1]);

    LOG_INFO("Timer terminated");
    return ret;
}

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
                cJSON_Delete(json);
                return;

                cJSON *js_hardbeat_rsp = cJSON_GetObjectItemCaseSensitive(json, "HB_response");
                if (cJSON_IsObject(js_hardbeat_rsp))
                {
                    /****************** GET Hardbeat Instruction ************************/
                    cJSON *hb_instructions = cJSON_GetObjectItemCaseSensitive(js_hardbeat_rsp, "HB_instructions");
                    if (cJSON_IsArray(hb_instructions))
                    {

                        int hb_instructions_count = cJSON_GetArraySize(hb_instructions);
                        user_status->response.hb_instructions_count = hb_instructions_count;
                        for (int i = 0; i < hb_instructions_count; i++)
                        {

                            cJSON *hb_instruction = cJSON_GetArrayItem(hb_instructions, i);
                            if (cJSON_IsNumber(hb_instruction))
                            {
                                int t_hb_instruction = hb_instruction->valueint;
                                if ((t_hb_instruction <= HB_SET_DEBUG_LEVEL) && (t_hb_instruction >= HB_ERROR))
                                {
                                    user_status->response.HardbeatInstruction[i] = t_hb_instruction;
                                }
                                else
                                {
                                    user_status->error_occured = true;
                                    cJSON_Delete(json);
                                    return;
                                }
                            }
                        }
                    }

                    /****************** GET HB Interval************************/
                    cJSON *js_iv = cJSON_GetObjectItemCaseSensitive(js_hardbeat_rsp, "HB_interval_s");
                    if (cJSON_IsNumber(js_iv))
                    {
                        uint64_t t_hb_interval = js_iv->valueint;
                        /*********
                         * @todo check if parsing works for large integer values
                         *
                         */
                        if (t_hb_interval > 0)
                        {
                            user_status->response.HardbeatInterval_s = t_hb_interval;
                        }
                        else
                        {
                            user_status->error_occured = true;
                            cJSON_Delete(json);
                            return;
                        }
                    }
                    cJSON_Delete(json);
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
    asl_session *hb_rq_session = NULL;
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
        goto shutdown;
    }
    server_addr.sin_port = htons(server_port);
    ret = inet_pton(AF_INET, HB_SERVERADDR, (struct sockaddr *)&server_addr);
    if (ret < 0)
    {
        LOG_ERROR("cant parse ipv 4 addr, errno: ", errno);
        goto shutdown;
    }
    ret = connect(req_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in));
    if (ret < 0)
    {
        LOG_ERROR("cant connect to client: errno %d", errno);
        goto shutdown;
    }
    hb_rq_session = asl_create_session(ep, req_fd);

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
        goto shutdown;
    }

    if (user_response_data.is_finished)
    {
        memcpy(rsp,
               &user_response_data.response,
               sizeof(user_response_data.response));
    }

    asl_close_session(hb_rq_session);
    asl_free_session(hb_rq_session);
    return 0;

shutdown:
    asl_close_session(hb_rq_session);
    asl_free_session(hb_rq_session);
    return -1;
}