#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>

#include "http_service.h"
#include "asl.h"
#include "utils.h"
#include "http_client.h"
#include "http_method.h"
#include "linux_comp.h"
#include "logging.h"
#include "networking.h"
LOG_MODULE_CREATE(http_service);

#define MAX_NUMBER_THREADS 6
#define DISTRIBUTION_BUFFER_SIZE 10000
#define HEARTBEAT_BUFFER_SIZE 1000
#define PKI_BUFFER_SIZE 4000

//------------------------------------ DEFINTIONS------------------------------------------//
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
    char serial_number[SERIAL_NUMBER_SIZE];
    /**
     * used for the connection to the server
     */
    struct management
    {
        struct addrinfo *mgmt_sockaddr;
        asl_endpoint *mgmt_endpoint;
    } mgmt;

#ifdef PKI_READY
    struct management_pki
    {
        struct addrinfo *mgmt_sockaddr;
        asl_endpoint *pki_endpoint;
    } mgmt_pki;
#endif

    ThreadPool pool;
} Http_service_module;

// will be changed
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

/*-----------------------------  FORWARD DECLARATIONS -------------------------------------*/

void set_http_service_defaults(Http_service_module *service);
void destroy_thread_pool(ThreadPool *pool);
void init_thread_pool(ThreadPool *pool);
int get_free_thread_id();
void signal_thread_finished(int thread_id);
void cleanup_http_service(void);
/*-----------------------------  END FORWARD DECLARATIONS -------------------------------------*/

static void http_get_cb(struct http_response *rsp,
                        enum http_final_call final_data,
                        void *user_data);

/**
 * Initialize the HTTP service module with the provided configuration
 * Returns 0 on success, -1 on failure
 */
int init_http_service(Kritis3mManagemntConfiguration *config,
                      asl_endpoint_configuration *mgmt_endpoint_config
#ifdef PKI_READY
                      ,
                      asl_endpoint_configuration *pki_endpoint_config
#endif
)
{
    // Initialize with default values
    set_http_service_defaults(&http_service);

    strncpy(http_service.serial_number, config->serial_number, SERIAL_NUMBER_SIZE);

    // Perform address lookup for management endpoint
    if (address_lookup_client(config->server_endpoint_addr.address,
                              config->server_endpoint_addr.port,
                              (struct addrinfo **)&http_service.mgmt.mgmt_sockaddr) != 0)
    {
        goto cleanup;
    }

    // Setup management endpoint
    http_service.mgmt.mgmt_endpoint = asl_setup_client_endpoint(mgmt_endpoint_config);
    if (!http_service.mgmt.mgmt_endpoint)
    {
        goto cleanup;
    }

// Perform address lookup for PKI endpoint
#ifdef PKI_READY
    if (address_lookup_client(config->identity.server_endpoint_addr.address,
                              config->identity.server_endpoint_addr.port,
                              (struct addrinfo **)&http_service.mgmt_pki.mgmt_sockaddr) != 0)
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

    // Initialize thread pool
    init_thread_pool(&http_service.pool);

    return 0;

cleanup:
    cleanup_http_service();
    return -1;
}

/**
 * Set default values for the HTTP service module
 */
void set_http_service_defaults(Http_service_module *service)
{
    memset(http_service.serial_number, 0, SERIAL_NUMBER_SIZE);

    http_service.mgmt.mgmt_endpoint = NULL;
    http_service.mgmt.mgmt_sockaddr = NULL;

#ifdef PKI_READY
    service->mgmt_pki.mgmt_sockaddr = NULL;
    service->mgmt_pki.pki_endpoint = NULL;
#endif

    init_thread_pool(&http_service.pool);
}

/**
 * Clean up resources associated with the HTTP service module
 */
void cleanup_http_service(void)
{
    // Clean up management connection
    if (http_service.mgmt.mgmt_endpoint)
        asl_free_endpoint(http_service.mgmt.mgmt_endpoint);

    if (http_service.mgmt.mgmt_sockaddr)
        freeaddrinfo(http_service.mgmt.mgmt_sockaddr);

#ifdef PKI_READY
    if (http_service.mgmt_pki.mgmt_sockaddr)
        freeaddrinfo(http_service.mgmt_pki.mgmt_sockaddr);

    // Clean up PKI connection
    if (http_service.mgmt_pki.pki_endpoint)
        asl_free_endpoint(http_service.mgmt_pki.pki_endpoint);
#endif

    // Cleanup thread pool
    // Function to destroy the ThreadPool (optional cleanup)
    destroy_thread_pool(&http_service.pool);

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
    }
    else
    {
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

    duration timeout = ms_toduration(5 * 1000);

    ret = https_client_req(fd, session, &req, timeout, response);
    if (ret < 0)
    {
        LOG_ERROR("error on client req. need to implment error handler");
        goto shutdown;
    }
    cb(*response);
    // signal_thread_finished(thread_id);
    if (session != NULL)
        asl_free_session(session);
    if (fd > 0)
        close(fd);
    // signal_thread_finished(thread_id);
    // pthread_exit(NULL);
    return 0;
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
    void *result = http_get_request(&http_get);

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

char *get_init_policy_url()
{
    int ret = -1;
    static char policy_url[500];
    ret = snprintf(policy_url, 500, "/api/node/%s/initial/register", http_service.serial_number);
    if (ret < 0)
        return NULL;
    return policy_url;
}

char *get_heartbeat_url(char *version)
{
    int ret = -1;
    static char heartbeat_url[500];
    ret = snprintf(heartbeat_url, 500, "/api/node/%s/operation/version/%s", http_service.serial_number, version);
    if (ret < 0)
        return NULL;
    return heartbeat_url;
}

//----------------------------------------------   THREAD POOL -----------------------------------------//
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

//----------------------------------------------   END THREAD POOL -----------------------------------------//