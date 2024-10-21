#include "http_service.h"
#include "asl.h"
#include "utils.h"
#include "http_client.h"
#include "http_method.h"
#include "netinet/in.h"
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "logging.h"
#include "linux_comp.h"
LOG_MODULE_CREATE(http_service);

#define MAX_NUMBER_THREADS 6
#define DISTRIBUTION_BUFFER_SIZE 10000
#define HEARTBEAT_BUFFER_SIZE 1000
#define PKI_BUFFER_SIZE 4000

typedef struct
{
    pthread_t threads[MAX_NUMBER_THREADS];
    pthread_attr_t thread_attr;
    int available[MAX_NUMBER_THREADS]; // 1 = available, 0 = in use
    pthread_mutex_t lock;
    pthread_cond_t cond;
} ThreadPool;

typedef struct
{
    char *serial_number;
    struct management
    {
        struct sockaddr_in mgmt_sockaddr;
        struct sockaddr_in mgmt_pkiaddr;
    } management;

    int number_pkis;
    struct
    {
        network_identity
            network_identity;
        struct sockaddr_in pki_server;
    } pki[max_identities];

    asl_endpoint *client_enpoint;
    ThreadPool pool;
} Http_service_module; // Corrected spelling of 'module'

typedef struct
{
    char *url;
    int thread_id;
    int fd;
    asl_session *session;
    struct response response;
    struct sockaddr_in server_addr;
    t_http_get_cb get_cb;
} http_get;

static Http_service_module http_service = {0};

/**declarations */
char *get_pki_url();
char *get_init_policy_url();
char *get_policy_url();
char *get_heartbeat_url();
char *get_pki_url();
void destroy_thread_pool(ThreadPool *pool);
void init_thread_pool(ThreadPool *pool);
int get_free_thread_id();
void signal_thread_finished(int thread_id);
void http_service_module_defaults();
static void http_get_cb(struct http_response *rsp,
                        enum http_final_call final_data,
                        void *user_data);
/**declarations end*/

void http_service_module_defaults()
{
    http_service.client_enpoint = NULL;
    http_service.serial_number = NULL;
    init_thread_pool(&http_service.pool);
    for (int i = 0; i < max_identities; i++)
        memset(&http_service.pki[i], 0, sizeof(struct sockaddr_in));
    return;
}

int init_http_service(Kritis3mManagemntConfiguration *management_config, asl_endpoint_configuration *endpoint_config)
{
    int ret = 0;
    http_service_module_defaults();
    http_service.serial_number = management_config->serial_number;
    http_service.client_enpoint = asl_setup_client_endpoint(endpoint_config);

    ret = parse_ip_port_to_sockaddr_in(management_config->server_addr, &http_service.management.mgmt_sockaddr);
    if (ret < 0)
        return -1;
    // ret = extract_addr_from_url(management_config->identity.pki_base_url, &http_service.management.mgmt_pkiaddr);
    if (ret < 0)
        return -1;
    return 0;
}

int get_free_thread_id()
{
    ThreadPool *pool = &http_service.pool;

    int thread_id = -1;

    pthread_mutex_lock(&pool->lock);

    // Wait until a thread becomes available
    while (thread_id == -1)
    {
        for (int i = 0; i < MAX_NUMBER_THREADS; i++)
        {
            if (pool->available[i] == 1)
            {
                thread_id = i;
                pool->available[i] = 0; // Mark the thread as in use
                break;
            }
        }
        if (thread_id == -1)
        {
            // No threads are available, wait for one to finish
            pthread_cond_wait(&pool->cond, &pool->lock);
        }
    }
    return thread_id;
}
void signal_thread_finished(int thread_id)
{
    ThreadPool *pool = &http_service.pool;
    pthread_mutex_lock(&pool->lock);
    pool->available[thread_id] = 1;   // Mark the thread as available
    pthread_cond_signal(&pool->cond); // Signal the condition variable
    pthread_mutex_unlock(&pool->lock);
}

/********   FORWARD DECLARATION ***************/
static void http_get_cb(struct http_response *rsp,
                        enum http_final_call final_data,
                        void *user_data)
{
    struct response *http_request_status = (struct response *)user_data;
    if (http_request_status == NULL)
        return;
    if (final_data == HTTP_DATA_MORE)
    {
        LOG_INFO("Partial data received (%zd bytes)", rsp->data_len);
    }
    else if (final_data == HTTP_DATA_FINAL)
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
            LOG_INFO("Hardbeat service is not supported from the server");
            http_request_status->ret = MGMT_BAD_REQUEST;
            goto error_occured;
            break;
        case HTTP_TOO_MANY_REQUESTS:
            LOG_INFO("Retry later");
            http_request_status->ret = MGMT_BUSY;
            goto error_occured;
            break;
        default:
            LOG_ERROR("responded http code is not handled, http response code: %d", rsp->http_status_code);

            break;
        }
    }else{
        LOG_ERROR("bla");
    }
    return;
error_occured:
    http_request_status->bytes_received = 0;
    http_request_status->buffer_frag_start = NULL;
    return;
}

void *http_get_request(void *http_get_data)
{
    http_get *http_req_data = (http_get *)http_get_data;
    t_http_get_cb cb = http_req_data->get_cb;

    char ip_str[INET_ADDRSTRLEN]; // INET_ADDRSTRLEN is 16 for IPv4 addresses
    char port[6];
    struct http_request req = {0};
    int fd = http_req_data->fd;
    int thread_id = http_req_data->thread_id;
    char *url = http_req_data->url;
    asl_session *session = http_req_data->session;
    struct response *response = &http_req_data->response;
    int ret = 0;

    if (http_req_data == NULL)
        return NULL;

    if (cb == NULL ||
        session == NULL ||
        url == NULL)
    {
        LOG_INFO("bad initialisation");
        goto shutdown;
    }

    // Convert the IP address from network byte order to string
    if (inet_ntop(AF_INET, &(http_req_data->server_addr.sin_addr), ip_str, INET_ADDRSTRLEN) == NULL)
    {
        LOG_ERROR("inet_ntop failed");
        goto shutdown;
    }
    int port_num = ntohs(http_req_data->server_addr.sin_port);
    if (port_num > 0)
        snprintf(port, 6, "%d", port_num);
    else
        goto shutdown;

    req.url = http_req_data->url;
    req.host = ip_str;
    req.port = port;
    req.method = HTTP_GET;
    req.protocol = "HTTP/1.1";
    req.response = http_get_cb;

    if (http_req_data->response.buffer == NULL)
        goto shutdown;
    req.recv_buf = http_req_data->response.buffer;
    req.recv_buf_len = http_req_data->response.buffer_size;

    duration timeout = ms_toduration(5 *1000);

    ret = https_client_req(fd, session, &req, timeout, response);
    if (ret < 0)
    {
        LOG_ERROR("error on client req. need to implment error handler");
        goto shutdown;
    }
    cb(*response);
    signal_thread_finished(thread_id);
    if (session != NULL)
        asl_free_session(session);
    if (fd > 0)
        close(fd);
    signal_thread_finished(thread_id);
    pthread_exit(NULL);
shutdown:
    LOG_ERROR("shutting down http get");
    response->ret = MGMT_ERR;
    if (response->buffer != NULL)
        free(response->buffer);
    signal_thread_finished(thread_id);
    if (session != NULL)
        asl_free_session(session);
    if (fd > 0)
        close(fd);
    pthread_exit(NULL);
}

int call_distribution_service(t_http_get_cb response_callback, char *destination_path)
{
    struct response response = {0};
    http_get http_get = {0};
    static char *url[520];
    int ret = 0;
    int fd = -1;

    if ((destination_path == NULL) || (response_callback == NULL))
        goto error_occured;

    http_get.response.service_used = MGMT_POLICY_REQ;
    http_get.response.buffer = (char *)malloc(DISTRIBUTION_BUFFER_SIZE);
    http_get.response.buffer_size = DISTRIBUTION_BUFFER_SIZE;
    http_get.response.buffer_frag_start = 0;
    http_get.response.meta.policy_req.destination_path = destination_path;

    http_get.server_addr = http_service.management.mgmt_sockaddr;
    http_get.get_cb = response_callback;
    http_get.url = get_init_policy_url();

    int thread_id = get_free_thread_id(&http_service.pool);
    if (thread_id < 0)
        goto error_occured;
    http_get.thread_id = thread_id;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    http_get.fd = fd;
    ret = connect(fd, (struct sockaddr *)&http_get.server_addr, sizeof(http_get.server_addr));
    if (ret < 0)
    {
        LOG_ERROR("can't conenct");
        goto error_occured;
    }
    http_get.session = asl_create_session(http_service.client_enpoint, fd);
    if (http_get.session == NULL)
        goto error_occured;
    ret = asl_handshake(http_get.session);
    if (ret < 0)
    {
        LOG_ERROR("failed in the handshake");
        goto error_occured;
    }

    // ret = asl_send(http_get.session, "moin", sizeof("moin"));
    // LOG_INFO("ret is : %d",ret);
    // ret = asl_send(http_get.session, "moin", sizeof("moin"));
    // LOG_INFO("ret is : %d",ret);
    // ret =asl_send(http_get.session, "moin", sizeof("moin"));
    // LOG_INFO("ret : %d", ret);
void * result = http_get_request(&http_get);

    // pthread_create(&http_service.pool.threads[thread_id], &http_service.pool.thread_attr, , &http_get);
    return ret;
    /**
     *  Service Initialisation
     */

error_occured:
    if (http_get.session != NULL)
        free(http_get.session);
    if (fd > 0)
        close(fd);
    if (http_get.response.buffer != NULL)
        free(http_get.response.buffer);
}

// Function to initialize the ThreadPool
void init_thread_pool(ThreadPool *pool)
{
    // Initialize the mutex
    if (pthread_mutex_init(&pool->lock, NULL) != 0)
    {
        perror("Failed to initialize mutex");
        exit(EXIT_FAILURE);
    }

    // Initialize the condition variable
    if (pthread_cond_init(&pool->cond, NULL) != 0)
    {
        perror("Failed to initialize condition variable");
        exit(EXIT_FAILURE);
    }

    // Mark all threads as available
    for (int i = 0; i < MAX_NUMBER_THREADS; i++)
    {
        pool->available[i] = 1; // 1 means the thread is available
    }

    printf("ThreadPool initialized with %d threads.\n", MAX_NUMBER_THREADS);
}

// Function to destroy the ThreadPool (optional cleanup)
void destroy_thread_pool(ThreadPool *pool)
{
    pthread_mutex_destroy(&pool->lock); // Destroy the mutex
    pthread_cond_destroy(&pool->cond);  // Destroy the condition variable
    printf("ThreadPool destroyed.\n");
}

char *get_init_policy_url()
{
    int ret = -1;
    static char policy_url[500];
    ret = snprintf(policy_url, 500, "/api/node/%s/initial/register", http_service.serial_number);
    if (ret < 0)
        return NULL;
    return policy_url;
}