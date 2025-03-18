#include "pki_client.h"
#include "cJSON.h"
#include "http_client.h"
#include "ipc.h"
#include "kritis3m_scale_service.h"
#include "logging.h"
#include "networking.h"
#include "poll_set.h"
#include "pthread.h"
#include <stdlib.h>
#include <string.h>

LOG_MODULE_CREATE("pki_client");

#define MAX_JOBS 5
#define HTTP_BUFFER_SIZE 4096
#define HTTP_TIMEOUT_MS 5000
#define MAX_WORKER_THREADS 2

enum job_type
{
        JOB_DATAPLANE_CERT_REQUEST,
        JOB_CTRLPLANE_CERT_REQUEST,
        JOB_DATAPLANE_ENROLL_REQUEST,
        JOB_CTRLPLANE_ENROLL_REQUEST
};

enum job_status
{
        JOB_PENDING,
        JOB_RUNNING,
        JOB_COMPLETED,
        JOB_FAILED
};

struct pki_job
{
        int id;
        enum job_type type;
        enum job_status status;
        struct http_request* request;
        struct http_response* response;
        void* user_data;
};

struct pki_job_queue
{
        struct pki_job jobs[MAX_JOBS];
        int head;
        int tail;
        int count;
        pthread_mutex_t mutex;
        pthread_cond_t cond;
        pthread_t worker_threads[MAX_WORKER_THREADS];
        bool workers_running;
};

struct pki_client
{
        asl_endpoint* endpoint;
        struct addrinfo* server_addr;
        char* host;
        char* port;
        int sock;

        pthread_t mainthread;
        pthread_attr_t thread_attr;
        int sockpair[2];
        bool running;

        struct pki_job_queue job_queue;
};

static struct pki_client client = {.endpoint = NULL,
                                   .server_addr = NULL,
                                   .host = NULL,
                                   .port = NULL,
                                   .mainthread = 0,
                                   .thread_attr = {0},
                                   .sockpair = {0},
                                   .running = false,
                                   .job_queue = {.head = 0,
                                                 .tail = 0,
                                                 .count = 0,
                                                 .mutex = PTHREAD_MUTEX_INITIALIZER,
                                                 .cond = PTHREAD_COND_INITIALIZER,
                                                 .workers_running = true}};

// Forward declarations
static void http_response_callback(struct http_response* rsp,
                                   enum http_final_call final_data,
                                   void* user_data);
static int process_job(struct pki_job* job, int socket, asl_session* session);
static void cleanup_job(struct pki_job* job);

static void* worker_thread(void* arg)
{
        struct pki_job_queue* queue = (struct pki_job_queue*) arg;

        while (queue->workers_running)
        {
                pthread_mutex_lock(&queue->mutex);

                // Wait for jobs while queue is empty and workers should keep running
                while (queue->count == 0 && queue->workers_running)
                {
                        pthread_cond_wait(&queue->cond, &queue->mutex);
                }

                if (!queue->workers_running)
                {
                        pthread_mutex_unlock(&queue->mutex);
                        break;
                }

                // Find a pending job
                struct pki_job* job = NULL;
                for (int i = 0; i < queue->count; i++)
                {
                        if (queue->jobs[i].status == JOB_PENDING)
                        {
                                job = &queue->jobs[i];
                                job->status = JOB_RUNNING;
                                break;
                        }
                }

                pthread_mutex_unlock(&queue->mutex);

                if (job)
                {
                        int socket = -1;
                        socket = create_client_socket(SOCK_STREAM);
                        if (socket < 0)
                        {
                                LOG_ERROR("Failed to create socket");
                                cleanup_job(job);
                                continue;
                        }
                        int ret = connect(socket,
                                          client.server_addr->ai_addr,
                                          client.server_addr->ai_addrlen);
                        if (ret != 0)
                        {
                                LOG_ERROR("Failed to connect to server");
                                cleanup_job(job);
                                close(socket);
                                continue;
                        }
                        asl_session* session = asl_create_session(client.endpoint, socket);
                        if (!session)
                        {
                                LOG_ERROR("Failed to setup session");
                                cleanup_job(job);
                                close(socket);
                                continue;
                        }
                        ret = asl_handshake(session);
                        if (ret != ASL_SUCCESS)
                        {
                                LOG_ERROR("Failed to handshake");
                                cleanup_job(job);
                                asl_close_session(session);
                                asl_free_session(session);
                                close(socket);
                                continue;
                        }
                        ret = process_job(job, socket, session);
                        if (ret < 0)
                        {
                                LOG_ERROR("Failed to process job");
                        }

                        asl_close_session(session);
                        asl_free_session(session);
                        close(socket);
                }
        }

        return NULL;
}

static int init_job_queue(struct pki_job_queue* queue)
{
        pthread_mutex_init(&queue->mutex, NULL);
        pthread_cond_init(&queue->cond, NULL);
        queue->workers_running = true;

        // Create worker threads
        for (int i = 0; i < MAX_WORKER_THREADS; i++)
        {
                int ret = pthread_create(&queue->worker_threads[i], NULL, worker_thread, queue);
                if (ret != 0)
                {
                        LOG_ERROR("Failed to create worker thread %d", i);
                        queue->workers_running = false;
                        pthread_cond_broadcast(&queue->cond);
                        for (int j = 0; j < i; j++)
                        {
                                pthread_join(queue->worker_threads[j], NULL);
                        }
                        pthread_mutex_destroy(&queue->mutex);
                        pthread_cond_destroy(&queue->cond);
                        return -1;
                }
        }

        return 0;
}

static void cleanup_job_queue(struct pki_job_queue* queue)
{
        queue->workers_running = false;
        pthread_cond_broadcast(&queue->cond);

        for (int i = 0; i < MAX_WORKER_THREADS; i++)
        {
                pthread_join(queue->worker_threads[i], NULL);
        }

        pthread_mutex_destroy(&queue->mutex);
        pthread_cond_destroy(&queue->cond);
}

static int add_job(struct pki_job_queue* queue, enum job_type type, void* user_data)
{
        pthread_mutex_lock(&queue->mutex);

        if (queue->count >= MAX_JOBS)
        {
                pthread_mutex_unlock(&queue->mutex);
                return -1;
        }

        struct pki_job* job = &queue->jobs[queue->tail];
        job->id = queue->tail;
        job->type = type;
        job->status = JOB_PENDING;
        job->user_data = user_data;

        // Allocate HTTP request and response
        job->request = malloc(sizeof(struct http_request));
        job->response = malloc(sizeof(struct http_response));
        if (!job->request || !job->response)
        {
                cleanup_job(job);
                pthread_mutex_unlock(&queue->mutex);
                return -1;
        }

        memset(job->request, 0, sizeof(struct http_request));
        memset(job->response, 0, sizeof(struct http_response));

        // Configure HTTP request
        job->request->method = HTTP_GET;
        job->request->protocol = "HTTP/1.1";
        job->request->response = http_response_callback;
        job->request->recv_buf = malloc(HTTP_BUFFER_SIZE);
        job->request->recv_buf_len = HTTP_BUFFER_SIZE;

        if (!job->request->recv_buf)
        {
                cleanup_job(job);
                pthread_mutex_unlock(&queue->mutex);
                return -1;
        }

        queue->tail = (queue->tail + 1) % MAX_JOBS;
        queue->count++;

        pthread_cond_signal(&queue->cond);
        pthread_mutex_unlock(&queue->mutex);
        return job->id;
}

static void cleanup_job(struct pki_job* job)
{
        if (job->request)
        {
                if (job->request->recv_buf)
                {
                        free(job->request->recv_buf);
                }
                free(job->request);
        }
        if (job->response)
        {
                if (job->response->recv_buf)
                {
                        free(job->response->recv_buf);
                }
                free(job->response);
        }
        memset(job, 0, sizeof(struct pki_job));
}

static void http_response_callback(struct http_response* rsp,
                                   enum http_final_call final_data,
                                   void* user_data)
{
        struct pki_job* job = (struct pki_job*) user_data;
        enum MSG_RESPONSE_CODE ret = MSG_ERROR;
        if (!job)
                return;

        if (final_data == HTTP_DATA_FINAL)
        {
                // check if response is valid
                if (job->response->http_status_code != 200)
                {
                        LOG_ERROR("Failed to get valid response");
                        job->status = JOB_FAILED;
                        return;
                }

                job->status = JOB_COMPLETED;
                switch (job->type)
                {
                case JOB_DATAPLANE_CERT_REQUEST:
                        ret = dataplane_cert_apply_req(job->response->body_frag_start,
                                                       job->response->body_frag_len);
                        break;
                case JOB_CTRLPLANE_CERT_REQUEST:
                        ret = ctrlplane_cert_apply_req(job->response->body_frag_start,
                                                       job->response->body_frag_len);
                        break;
                case JOB_DATAPLANE_ENROLL_REQUEST:
                        ret = dataplane_cert_apply_req(job->response->body_frag_start,
                                                       job->response->body_frag_len);
                        break;
                case JOB_CTRLPLANE_ENROLL_REQUEST:
                        ret = ctrlplane_cert_apply_req(job->response->body_frag_start,
                                                       job->response->body_frag_len);
                        break;
                default:
                        LOG_ERROR("Invalid job type: %d", job->type);
                        break;
                }

                // Clean up the job after processing
                cleanup_job(job);
        }
}

static int process_job(struct pki_job* job, int socket, asl_session* session)
{
        int ret;

        // Configure request based on job type
        switch (job->type)
        {
        case JOB_DATAPLANE_CERT_REQUEST:
                job->request->url = "/api/v1/certificates/dataplane";
                break;
        case JOB_CTRLPLANE_CERT_REQUEST:
                job->request->url = "/api/v1/certificates/controlplane";
                break;
        case JOB_DATAPLANE_ENROLL_REQUEST:
                job->request->method = HTTP_POST;
                job->request->url = "/api/v1/certificates/dataplane/enroll";
                break;
        case JOB_CTRLPLANE_ENROLL_REQUEST:
                job->request->method = HTTP_POST;
                job->request->url = "/api/v1/certificates/controlplane/enroll";
                break;
        }

        job->request->host = client.host;
        job->request->port = client.port;

        // Send HTTP request with timeout
        duration timeout = ms_to_duration(HTTP_TIMEOUT_MS);
        ret = https_client_req(socket, session, job->request, timeout, job);
        if (ret < 0)
        {
                job->status = JOB_FAILED;
                cleanup_job(job);
                return ret;
        }

        return 0;
}

enum pki_msg_type
{
        PKI_RESPONSE,
        PKI_CLIENT_STOP,
        PKI_CLIENT_DATAPLANE_CERT_REQUEST,
        PKI_CLIENT_CTRLPLANE_CERT_REQUEST,
        PKI_CLIENT_DATAPLANE_ENROLL_REQUEST,
        PKI_CLIENT_CTRLPLANE_ENROLL_REQUEST
} __attribute__((aligned(4)));

struct pki_msg_t
{
        enum pki_msg_type msg_type;
        union pki_msg_payload
        {
                int32_t return_code;
        } payload;
};

static int handle_management_message()
{
        int ret;
        struct pki_msg_t response = {0};

        struct pki_msg_t msg;
        ret = sockpair_read(client.sockpair[THREAD_INT], &msg, sizeof(msg));
        if (ret < 0)
        {
                LOG_ERROR("Failed to read message");
                goto exit;
        }

        switch (msg.msg_type)
        {
        case PKI_CLIENT_STOP:
                client.running = false;
                return 0;

        case PKI_CLIENT_DATAPLANE_CERT_REQUEST:
                ret = add_job(&client.job_queue, JOB_DATAPLANE_CERT_REQUEST, NULL);
                break;

        case PKI_CLIENT_CTRLPLANE_CERT_REQUEST:
                ret = add_job(&client.job_queue, JOB_CTRLPLANE_CERT_REQUEST, NULL);
                break;
        case PKI_CLIENT_DATAPLANE_ENROLL_REQUEST:
                ret = add_job(&client.job_queue, JOB_DATAPLANE_ENROLL_REQUEST, NULL);
                break;
        case PKI_CLIENT_CTRLPLANE_ENROLL_REQUEST:
                ret = add_job(&client.job_queue, JOB_CTRLPLANE_ENROLL_REQUEST, NULL);
                break;

        default:
                LOG_ERROR("Invalid message type: %d", msg.msg_type);
                goto exit;
        }

        response.msg_type = PKI_RESPONSE;
        response.payload.return_code = MSG_OK;
        sockpair_write(client.sockpair[THREAD_INT], &response, sizeof(response), NULL);
        return ret;

exit:
        response.msg_type = PKI_RESPONSE;
        response.payload.return_code = MSG_ERROR;
        sockpair_write(client.sockpair[THREAD_INT], &response, sizeof(response), NULL);
        return -1;
}

void* pki_client_main_thread(void* arg)
{
        struct pki_client* client = (struct pki_client*) arg;
        if (!client)
        {
                LOG_ERROR("Invalid client");
                return NULL;
        }

        client->running = true;
        struct pollfd fds[1];
        fds[0].fd = client->sockpair[THREAD_INT];
        fds[0].events = POLLIN | POLLERR;

        while (client->running)
        {
                int ret = poll(fds, 1, -1);
                if (ret < 0)
                {
                        LOG_ERROR("Poll failed");
                        break;
                }

                if (fds[0].revents & POLLIN)
                {
                        ret = handle_management_message();
                        if (ret < 0)
                        {
                                LOG_ERROR("Failed to handle message");
                        }
                }
        }

        cleanup_pki_client();

        return NULL;
}

int start_pki_client(struct pki_client_config_t* config)
{
        if (!config || !config->endpoint_config || !config->serialnumber || !config->host)
        {
                LOG_ERROR("Invalid config");
                return -1;
        }

        // Initialize job queue
        if (init_job_queue(&client.job_queue) != 0)
        {
                LOG_ERROR("Failed to initialize job queue");
                return -1;
        }

        // Setup endpoint
        client.endpoint = asl_setup_client_endpoint(config->endpoint_config);
        if (!client.endpoint)
        {
                LOG_ERROR("Failed to setup endpoint");
                return -1;
        }

        // Store host and port
        client.host = strdup(config->host);
        client.port = strdup(config->port ? config->port : "443");

        // Resolve server address
        int ret = address_lookup_client(client.host, atoi(client.port), &client.server_addr, AF_INET);
        if (ret != 0)
        {
                LOG_ERROR("Failed to resolve server address");
                goto error;
        }

        // Create socket
        int sock = -1;
        sock = create_client_socket(SOCK_STREAM);
        if (sock < 0)
        {
                LOG_ERROR("Failed to create socket");
                goto error;
        }

        // Connect to server
        ret = connect(sock, client.server_addr->ai_addr, client.server_addr->ai_addrlen);
        if (ret != 0)
        {
                LOG_ERROR("Failed to connect to server");
                goto error;
        }
        closesocket(sock);

        // Create socket pair for IPC
        ret = create_socketpair(client.sockpair);
        if (ret != 0)
        {
                LOG_ERROR("Failed to create socket pair");
                goto error;
        }

        // Start main thread
        ret = pthread_create(&client.mainthread, &client.thread_attr, pki_client_main_thread, &client);
        if (ret != 0)
        {
                LOG_ERROR("Failed to create main thread");
                goto error;
        }

        return 0;

error:
        cleanup_pki_client();
        return -1;
}

void cleanup_pki_client()
{
        if (client.endpoint)
        {
                asl_free_endpoint(client.endpoint);
                client.endpoint = NULL;
        }
        if (client.host)
        {
                free(client.host);
                client.host = NULL;
        }
        if (client.port)
        {
                free(client.port);
                client.port = NULL;
        }
        if (client.server_addr)
        {
                freeaddrinfo(client.server_addr);
                client.server_addr = NULL;
        }
        if (client.sock != -1)
        {
                close(client.sock);
                client.sock = -1;
        }
        if (client.sockpair[THREAD_EXT] != -1)
        {
                closesocket(client.sockpair[THREAD_EXT]);
                client.sockpair[THREAD_EXT] = -1;
        }
        if (client.sockpair[THREAD_INT] != -1)
        {
                closesocket(client.sockpair[THREAD_INT]);
                client.sockpair[THREAD_INT] = -1;
        }
        cleanup_job_queue(&client.job_queue);
}

enum MSG_RESPONSE_CODE stop_pki_client()
{
        if (!client.running)
        {
                return MSG_ERROR;
        }

        struct pki_msg_t msg = {0};
        msg.msg_type = PKI_CLIENT_STOP;
        enum MSG_RESPONSE_CODE ret = external_management_request(client.sockpair[THREAD_EXT],
                                                                 &msg,
                                                                 sizeof(msg));

        if (client.mainthread)
        {
                pthread_join(client.mainthread, NULL);
                client.mainthread = 0;
        }
        cleanup_pki_client();
        return ret;
}
enum MSG_RESPONSE_CODE dataplane_cert_request()
{
        if (!client.running)
        {
                return MSG_ERROR;
        }

        struct pki_msg_t msg = {0};
        msg.msg_type = PKI_CLIENT_DATAPLANE_CERT_REQUEST;
        return external_management_request(client.sockpair[THREAD_EXT], &msg, sizeof(msg));
}

enum MSG_RESPONSE_CODE controlplane_cert_request()
{
        if (!client.running)
        {
                return MSG_ERROR;
        }

        struct pki_msg_t msg = {0};
        msg.msg_type = PKI_CLIENT_CTRLPLANE_CERT_REQUEST;
        return external_management_request(client.sockpair[THREAD_EXT], &msg, sizeof(msg));
}

enum MSG_RESPONSE_CODE dataplane_enroll_request()
{
        if (!client.running)
        {
                return MSG_ERROR;
        }
}

enum MSG_RESPONSE_CODE controlplane_enroll_request()
{
        if (!client.running)
        {
                return MSG_ERROR;
        }

        struct pki_msg_t msg = {0};
        msg.msg_type = PKI_CLIENT_CTRLPLANE_ENROLL_REQUEST;
        return external_management_request(client.sockpair[THREAD_EXT], &msg, sizeof(msg));
}