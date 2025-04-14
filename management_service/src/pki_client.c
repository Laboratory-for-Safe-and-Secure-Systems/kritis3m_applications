#include "pki_client.h"
#include "asl.h"
#include "http_client.h"
#include "http_method.h"
#include "kritis3m_pki_client.h"
#include "kritis3m_pki_common.h"
#include "logging.h"
#include "networking.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

LOG_MODULE_CREATE("pki_client");

#define HTTP_BUFFER_SIZE 16096
#define HTTP_TIMEOUT_MS 50000

// Forward declarations
static void cleanup_request_context(pki_request_context_t* ctx);
static int fetch_ca_certificates(pki_request_context_t* ctx, bool use_callback);
static void* cert_request_thread(void* arg);
static void* ca_chain_thread(void* arg);
static void http_response_callback(struct http_response* rsp,
                                   enum http_final_call final_data,
                                   void* user_data);
static void http_ca_chain_callback(struct http_response* rsp,
                                   enum http_final_call final_data,
                                   void* user_data);

// List of active threads for cleanup
#define MAX_ACTIVE_THREADS 2
static pki_request_context_t* active_threads[MAX_ACTIVE_THREADS] = {NULL};
static pthread_mutex_t active_threads_mutex = PTHREAD_MUTEX_INITIALIZER;

// Helper function to establish connection
static int pki_establish_connection(pki_request_context_t* ctx,
                                    asl_endpoint** endpoint,
                                    asl_session** session,
                                    int* sock_fd)
{
        int ret = 0;
        struct addrinfo* addr_info = NULL;
        const char* hostname = ctx->config->host;
        uint16_t port = ctx->config->port;

        // Resolve the hostname
        if (address_lookup_client(hostname, port, &addr_info, AF_UNSPEC) < 0)
        {
                LOG_ERROR("Failed to resolve server hostname: %s", hostname);
                return ASL_ARGUMENT_ERROR;
        }

        // Create client socket
        *sock_fd = create_client_socket(addr_info->ai_family == AF_INET6 ? AF_INET6 : AF_INET);
        if (*sock_fd < 0)
        {
                LOG_ERROR("Failed to create client socket");
                freeaddrinfo(addr_info);
                return ASL_INTERNAL_ERROR;
        }

        // Connect to the server
        if (ret = connect(*sock_fd, addr_info->ai_addr, addr_info->ai_addrlen), ret < 0)
        {
                LOG_ERROR("Failed to connect to server %d, with errno %d", ret, errno);
                closesocket(*sock_fd);
                freeaddrinfo(addr_info);
                return ASL_INTERNAL_ERROR;
        }

        // Setup TLS session
        *endpoint = asl_setup_client_endpoint(ctx->config->endpoint_config);
        if (*endpoint == NULL)
        {
                LOG_ERROR("Failed to setup ASL client endpoint");
                closesocket(*sock_fd);
                freeaddrinfo(addr_info);
                return ASL_INTERNAL_ERROR;
        }

        // Create ASL session
        *session = asl_create_session(*endpoint, *sock_fd);
        if (*session == NULL)
        {
                LOG_ERROR("Failed to create ASL session");
                asl_free_endpoint(*endpoint);
                closesocket(*sock_fd);
                freeaddrinfo(addr_info);
                return ASL_INTERNAL_ERROR;
        }

        // Perform TLS handshake
        ret = asl_handshake(*session);
        if (ret != ASL_SUCCESS)
        {
                LOG_ERROR("TLS handshake failed: %s", asl_error_message(ret));
                asl_close_session(*session);
                asl_free_session(*session);
                asl_free_endpoint(*endpoint);
                closesocket(*sock_fd);
                freeaddrinfo(addr_info);
                return ret;
        }

        freeaddrinfo(addr_info);
        return ASL_SUCCESS;
}

// Helper function to cleanup connection resources
static void pki_cleanup_connection(asl_endpoint* endpoint,
                                   asl_session* session,
                                   int sock_fd,
                                   struct addrinfo* addr_info)
{
        if (sock_fd >= 0)
        {
                closesocket(sock_fd);
        }

        if (addr_info != NULL)
        {
                freeaddrinfo(addr_info);
        }

        if (session != NULL)
        {
                asl_close_session(session);
                asl_free_session(session);
        }

        if (endpoint != NULL)
        {
                asl_free_endpoint(endpoint);
        }
}

// Helper function to send HTTP requests
static int pki_send_http_request(pki_request_context_t* ctx,
                                 const char* url,
                                 enum http_method method,
                                 const char* content_type,
                                 const uint8_t* payload,
                                 size_t payload_size,
                                 void (*response_callback)(struct http_response*,
                                                           enum http_final_call,
                                                           void*))
{
        int ret = 0;
        asl_endpoint* endpoint = NULL;
        asl_session* session = NULL;
        int sock_fd = -1;
        char port_str[16];
        uint8_t rsp_buffer[HTTP_BUFFER_SIZE];
        memset(rsp_buffer, 0, sizeof(rsp_buffer));

        // Establish connection
        ret = pki_establish_connection(ctx, &endpoint, &session, &sock_fd);
        if (ret != ASL_SUCCESS)
        {
                return ret;
        }

        // Format port as string
        snprintf(port_str, sizeof(port_str), "%hu", ctx->config->port);

        // Setup HTTP request
        struct http_request req = {0};
        req.method = method;
        req.url = url;
        req.protocol = "HTTP/1.1";
        req.host = ctx->config->host;
        req.port = port_str;
        req.content_type_value = content_type;
        req.payload = (char*) payload;
        req.payload_len = payload_size;
        req.recv_buf = rsp_buffer;
        req.recv_buf_len = sizeof(rsp_buffer);
        req.response = response_callback;

        // Set headers based on request type
        const char* headers[] = {"Accept: application/pkcs7-mime\r\n",
                                 "Content-Transfer-Encoding: base64\r\n",
                                 "Connection: close\r\n",
                                 NULL};
        req.header_fields = headers;

        // Send request with timeout
        struct duration timeout = ms_to_duration(HTTP_TIMEOUT_MS);
        ret = https_client_req(sock_fd, session, &req, timeout, ctx);
        if (ret < 0)
        {
                LOG_ERROR("Failed to send HTTP request: %d", ret);
                pki_cleanup_connection(endpoint, session, sock_fd, NULL);
        }

        pki_cleanup_connection(endpoint, session, sock_fd, NULL);
        return ret;
}

// Helper function to create and initialize request context
static pki_request_context_t* create_request_context(struct pki_client_config_t* config,
                                                     enum CERT_TYPE cert_type,
                                                     bool include_ca_certs,
                                                     pki_callback_t callback,
                                                     bool is_blocking)
{
        pki_request_context_t* ctx = malloc(sizeof(pki_request_context_t));
        if (!ctx)
        {
                LOG_ERROR("Failed to allocate request context");
                return NULL;
        }
        memset(ctx, 0, sizeof(pki_request_context_t));

        // Initialize mutex
        if (pthread_mutex_init(&ctx->mutex, NULL) != 0)
        {
                LOG_ERROR("Failed to initialize mutex");
                free(ctx);
                return NULL;
        }

        // Initialize context
        ctx->config = config;
        ctx->cert_type = cert_type;
        ctx->include_ca_certs = include_ca_certs;
        ctx->callback = callback;
        ctx->is_blocking = is_blocking;
        ctx->cert_buffer = NULL;
        ctx->cert_buffer_size = 0;

        ctx->ca_chain_buffer = NULL;
        ctx->ca_chain_buffer_size = 0;
        return ctx;
}

// Helper function to cleanup request context
static void cleanup_request_context(pki_request_context_t* ctx)
{
        if (ctx)
        {
                if (ctx->cert_buffer)
                {
                        free(ctx->cert_buffer);
                }
                if (ctx->ca_chain_buffer)
                {
                        free(ctx->ca_chain_buffer);
                }
                pthread_mutex_destroy(&ctx->mutex);
                free(ctx);
                ctx = NULL;
        }
}

// Helper function to fetch CA certificates
static int fetch_ca_certificates(pki_request_context_t* ctx, bool use_callback)
{
        const char* url = (ctx->cert_type == CERT_TYPE_DATAPLANE) ?
                                  "/.well-known/est/dataplane/cacerts" :
                                  "/.well-known/est/controlplane/cacerts";

        int ret = pki_send_http_request(ctx,
                                        url,
                                        HTTP_GET,
                                        "application/pkcs7-mime",
                                        NULL,
                                        0,
                                        http_ca_chain_callback);
        if (ret != 200)
        {
                LOG_ERROR("Failed to fetch CA certificates");
                if (ctx->callback)
                {
                        ctx->callback(NULL, 0);
                }
                return ret;
        }

        if (ctx->callback && use_callback)
        {
                ctx->callback((char*) ctx->ca_chain_buffer, ctx->ca_chain_size);
        }

        return ASL_SUCCESS;
}

static void register_thread(pki_request_context_t* thread_data)
{
        pthread_mutex_lock(&active_threads_mutex);
        for (int i = 0; i < MAX_ACTIVE_THREADS; i++)
        {
                if (active_threads[i] == NULL)
                {
                        active_threads[i] = thread_data;
                        break;
                }
        }
        pthread_mutex_unlock(&active_threads_mutex);
}

// Remove thread from active threads list
static void unregister_thread(pki_request_context_t* thread_data)
{
        pthread_mutex_lock(&active_threads_mutex);
        for (int i = 0; i < MAX_ACTIVE_THREADS; i++)
        {
                if (active_threads[i] == thread_data)
                {
                        active_threads[i] = NULL;
                        break;
                }
        }
        pthread_mutex_unlock(&active_threads_mutex);
}

// HTTP response callback for certificate requests
static void http_response_callback(struct http_response* rsp,
                                   enum http_final_call final_data,
                                   void* user_data)
{
        pki_request_context_t* ctx = (pki_request_context_t*) user_data;

        pthread_mutex_lock(&ctx->mutex);
        bool is_active = !ctx->cleanup_requested;
        pthread_mutex_unlock(&ctx->mutex);

        if (!is_active)
        {
                LOG_WARN("Certificate request was cleaned up before response was received");
                return;
        }

        if (rsp->http_status_code == 200 && rsp->body_frag_len > 0)
        {
                if (final_data == HTTP_DATA_FINAL)
                {
                        uint8_t* temp_buffer = NULL;
                        int temp_buffer_size = 0;

                        int ret = parseESTResponse(rsp->body_frag_start,
                                                   rsp->body_frag_len,
                                                   &temp_buffer,
                                                   &temp_buffer_size);
                        if (ret == 0 && temp_buffer && temp_buffer_size > 0)
                        {
                                pthread_mutex_lock(&ctx->mutex);
                                ctx->cert_size = temp_buffer_size;
                                ctx->cert_buffer = temp_buffer;
                                pthread_mutex_unlock(&ctx->mutex);
                        }
                        else
                        {
                                LOG_ERROR("Failed to parse EST response");
                                goto error_occurred;
                        }
                }
        }
        else
        {
                LOG_ERROR("HTTP error when fetching certificate: %d %s",
                          rsp->http_status_code,
                          rsp->http_status);
                goto error_occurred;
        }
        return;

error_occurred:
        if (final_data == HTTP_DATA_FINAL && ctx->callback)
        {
                ctx->callback(NULL, 0);
                pthread_mutex_lock(&ctx->mutex);
                ctx->callback = NULL;
                ctx->completed = true;
                if (ctx->cert_buffer)
                {
                        free(ctx->cert_buffer);
                        ctx->cert_buffer = NULL;
                }
                ctx->cert_size = 0;
                pthread_mutex_unlock(&ctx->mutex);
        }
}

// HTTP response callback for CA chain requests
static void http_ca_chain_callback(struct http_response* rsp,
                                   enum http_final_call final_data,
                                   void* user_data)
{
        pki_request_context_t* ctx = (pki_request_context_t*) user_data;

        pthread_mutex_lock(&ctx->mutex);
        bool is_active = !ctx->cleanup_requested;
        pthread_mutex_unlock(&ctx->mutex);

        if (!is_active)
        {
                LOG_WARN("CA chain request was cleaned up before response was received");
                return;
        }

        if (rsp->http_status_code == 200 && rsp->body_frag_len > 0)
        {
                if (final_data == HTTP_DATA_FINAL)
                {
                        uint8_t* temp_buffer = NULL;
                        int temp_buffer_size = 0;

                        int ret = parseESTResponse(rsp->body_frag_start,
                                                   rsp->body_frag_len,
                                                   &temp_buffer,
                                                   &temp_buffer_size);
                        if (ret == 0 && temp_buffer && temp_buffer_size > 0)
                        {
                                pthread_mutex_lock(&ctx->mutex);
                                ctx->ca_chain_size = temp_buffer_size;
                                ctx->ca_chain_buffer = temp_buffer;
                                ctx->has_ca_chain = true;
                                pthread_mutex_unlock(&ctx->mutex);
                        }
                        else
                        {
                                LOG_ERROR("Failed to parse PKCS7 response");
                                goto error_occurred;
                        }
                }
        }
        else
        {
                LOG_ERROR("HTTP error when fetching CA chain: %d %s",
                          rsp->http_status_code,
                          rsp->http_status);
                goto error_occurred;
        }
        return;

error_occurred:
        pthread_mutex_lock(&ctx->mutex);
        if (ctx->ca_chain_buffer)
        {
                free(ctx->ca_chain_buffer);
                ctx->ca_chain_buffer = NULL;
        }
        ctx->ca_chain_size = 0;
        ctx->has_ca_chain = false;
        ctx->ca_chain_buffer_size = 0;
        ctx->completed = true;
        pthread_mutex_unlock(&ctx->mutex);
}

// Check if the server is reachable with a simple ping
static bool ping_server(int socket_fd)
{
        uint8_t ping_data[] = "PING";
        uint8_t response[16];

        // Set socket to non-blocking for timeout handling
        setblocking(socket_fd, false);

        // Send ping
        ssize_t sent = send(socket_fd, ping_data, sizeof(ping_data), 0);
        if (sent <= 0)
        {
                return false;
        }

        // Wait for response with timeout
        struct pollfd pfd = {.fd = socket_fd, .events = POLLIN};

        if (poll(&pfd, 1, 3000) <= 0)
        { // 3 second timeout
                return false;
        }

        // Try to read response
        if (recv(socket_fd, response, sizeof(response), MSG_PEEK) <= 0)
        {
                return false;
        }

        // Set socket back to blocking
        setblocking(socket_fd, true);
        return true;
}

// Clean up thread data
static void cleanup_thread_data(pki_request_context_t* thread_data)
{
        if (thread_data)
        {
                if (thread_data->cert_buffer)
                {
                        free(thread_data->cert_buffer);
                }
                if (thread_data->ca_chain_buffer)
                {
                        free(thread_data->ca_chain_buffer);
                }
                pthread_mutex_destroy(&thread_data->mutex);
                unregister_thread(thread_data);
                free(thread_data);
        }
}

// Worker thread function for certificate request
static void* cert_request_thread(void* arg)
{
        pki_request_context_t* ctx = (pki_request_context_t*) arg;
        int ret = 0;
        struct addrinfo* addr_info = NULL;
        int sock_fd = -1;
        asl_endpoint* endpoint = NULL;
        asl_session* session = NULL;

        // Check if cleanup was requested
        pthread_mutex_lock(&ctx->mutex);
        bool cleanup_requested = ctx->cleanup_requested;
        pthread_mutex_unlock(&ctx->mutex);

        if (cleanup_requested)
        {
                LOG_WARN("Cleanup requested before thread started work");
                return NULL;
        }

        // First, try to fetch the CA certificate chain if requested
        if (ctx->include_ca_certs)
        {
                LOG_INFO("Fetching CA certificate chain from EST server");
                ret = fetch_ca_certificates(ctx, false);
                if (ret != ASL_SUCCESS)
                {
                        LOG_ERROR("Failed to fetch CA certificates");
                        goto cleanup;
                }
        }

        // Create private key structure
        PrivateKey* private_key = privateKey_new();
        if (!private_key)
        {
                LOG_ERROR("Failed to create private key structure");
                ret = ASL_MEMORY_ERROR;
                goto cleanup;
        }

        // Load private key from endpoint configuration
        if (ctx->config && ctx->config->endpoint_config)
        {
                ret = privateKey_loadKeyFromBuffer(private_key,
                                                   ctx->config->endpoint_config->private_key.buffer,
                                                   ctx->config->endpoint_config->private_key.size);
                if (ret != KRITIS3M_PKI_SUCCESS)
                {
                        LOG_ERROR("Failed to load private key: %d", ret);
                        ret = ASL_CERTIFICATE_ERROR;
                        goto cleanup;
                }
        }
        else
        {
                LOG_ERROR("No endpoint configuration available");
                ret = ASL_ARGUMENT_ERROR;
                goto cleanup;
        }

        // Create signing request
        SigningRequest* request = signingRequest_new();
        if (!request)
        {
                LOG_ERROR("Failed to create signing request");
                ret = ASL_MEMORY_ERROR;
                goto cleanup;
        }

        // Check if config is valid
        if (!ctx->config)
        {
                LOG_ERROR("No configuration available");
                ret = ASL_ARGUMENT_ERROR;
                goto cleanup;
        }

        // Prepare metadata for CSR
        SigningRequestMetadata metadata = {.commonName = ctx->config->serialnumber,
                                           .org = "OTH Regensburg",
                                           .country = "DE",
                                           .unit = "LaS3",
                                           .email = NULL,
                                           .altNamesDNS = ctx->config->host,
                                           .altNamesURI = NULL,
                                           .altNamesIP = "127.0.0.1",
                                           .altNamesEmail = NULL};

        // Initialize CSR with metadata
        int init_ret = signingRequest_init(request, &metadata);
        if (init_ret != KRITIS3M_PKI_SUCCESS)
        {
                LOG_ERROR("Failed to initialize signing request: %d", init_ret);
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        // Allocate buffer for CSR
        uint8_t csr_buffer[4096] = {0};
        size_t csr_size = sizeof(csr_buffer);

        // Finalize CSR
        init_ret = signingRequest_finalize(request, private_key, csr_buffer, &csr_size, true);
        if (init_ret != KRITIS3M_PKI_SUCCESS)
        {
                LOG_ERROR("Failed to finalize signing request: %d", init_ret);
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        // Send CSR to EST server
        const char* url = ctx->cert_type == CERT_TYPE_DATAPLANE ?
                                  "/.well-known/est/dataplane/simpleenroll" :
                                  "/.well-known/est/controlplane/simpleenroll";

        ret = pki_send_http_request(ctx,
                                    url,
                                    HTTP_POST,
                                    "application/pkcs10",
                                    csr_buffer,
                                    csr_size,
                                    http_response_callback);
        if (ret != ASL_SUCCESS)
        {
                LOG_ERROR("Failed to send CSR to EST server");
                goto cleanup;
        }

        // Handle response
        pthread_mutex_lock(&ctx->mutex);
        if (ctx->has_ca_chain && ctx->cert_size > 0 && ctx->ca_chain_buffer)
        {
                // Combine certificates
                size_t combined_size = ctx->cert_size + ctx->ca_chain_size;
                uint8_t* combined_buffer = malloc(combined_size);
                if (combined_buffer)
                {
                        memcpy(combined_buffer, ctx->cert_buffer, ctx->cert_size);
                        memcpy(combined_buffer + ctx->cert_size, ctx->ca_chain_buffer, ctx->ca_chain_size);
                        ctx->callback((char*) combined_buffer, combined_size);
                        free(combined_buffer);
                }
                else
                {
                        LOG_ERROR("Failed to allocate buffer for combined certificates");
                        ctx->callback((char*) ctx->cert_buffer, ctx->cert_size);
                }
        }
        else
        {
                ctx->callback((char*) ctx->cert_buffer, ctx->cert_size);
        }
        ctx->completed = true;
        pthread_mutex_unlock(&ctx->mutex);

cleanup:
        if (request)
        {
                signingRequest_free(request);
        }
        if (private_key)
        {
                privateKey_free(private_key);
        }

        // Check if thread should clean itself up
        pthread_mutex_lock(&ctx->mutex);
        bool should_cleanup = ctx->cleanup_requested;
        pthread_mutex_unlock(&ctx->mutex);

        if (should_cleanup)
        {
                cleanup_request_context(ctx);
        }

        return NULL;
}

// Worker thread function for CA chain fetch
static void* ca_chain_thread(void* arg)
{
        pki_request_context_t* ctx = (pki_request_context_t*) arg;
        int ret = 0;
        struct addrinfo* addr_info = NULL;
        int sock_fd = -1;
        asl_endpoint* endpoint = NULL;
        asl_session* session = NULL;

        // Check if cleanup was requested
        pthread_mutex_lock(&ctx->mutex);
        bool cleanup_requested = ctx->cleanup_requested;
        pthread_mutex_unlock(&ctx->mutex);

        if (cleanup_requested)
        {
                LOG_WARN("Cleanup requested before thread started work");
                return NULL;
        }

        // First, try to fetch the CA certificate chain if requested
        if (ctx->include_ca_certs)
        {
                LOG_INFO("Fetching CA certificate chain from EST server");
                ret = fetch_ca_certificates(ctx, false);
                if (ret != ASL_SUCCESS)
                {
                        LOG_ERROR("Failed to fetch CA certificates");
                        goto cleanup;
                }
        }

        // Create private key structure
        PrivateKey* private_key = privateKey_new();
        if (!private_key)
        {
                LOG_ERROR("Failed to create private key structure");
                ret = ASL_MEMORY_ERROR;
                goto cleanup;
        }

        // Load private key from endpoint configuration
        if (ctx->config && ctx->config->endpoint_config)
        {
                ret = privateKey_loadKeyFromBuffer(private_key,
                                                   ctx->config->endpoint_config->private_key.buffer,
                                                   ctx->config->endpoint_config->private_key.size);
                if (ret != KRITIS3M_PKI_SUCCESS)
                {
                        LOG_ERROR("Failed to load private key: %d", ret);
                        ret = ASL_CERTIFICATE_ERROR;
                        goto cleanup;
                }
        }
        else
        {
                LOG_ERROR("No endpoint configuration available");
                ret = ASL_ARGUMENT_ERROR;
                goto cleanup;
        }

        // Create signing request
        SigningRequest* request = signingRequest_new();
        if (!request)
        {
                LOG_ERROR("Failed to create signing request");
                ret = ASL_MEMORY_ERROR;
                goto cleanup;
        }

        // Check if config is valid
        if (!ctx->config)
        {
                LOG_ERROR("No configuration available");
                ret = ASL_ARGUMENT_ERROR;
                goto cleanup;
        }

        // Prepare metadata for CSR
        SigningRequestMetadata metadata = {.commonName = ctx->config->serialnumber,
                                           .org = "OTH Regensburg",
                                           .country = "DE",
                                           .unit = "LaS3",
                                           .email = NULL,
                                           .altNamesDNS = ctx->config->host,
                                           .altNamesURI = NULL,
                                           .altNamesIP = "127.0.0.1",
                                           .altNamesEmail = NULL};

        // Initialize CSR with metadata
        int init_ret = signingRequest_init(request, &metadata);
        if (init_ret != KRITIS3M_PKI_SUCCESS)
        {
                LOG_ERROR("Failed to initialize signing request: %d", init_ret);
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        // Allocate buffer for CSR
        uint8_t csr_buffer[4096] = {0};
        size_t csr_size = sizeof(csr_buffer);

        // Finalize CSR
        init_ret = signingRequest_finalize(request, private_key, csr_buffer, &csr_size, true);
        if (init_ret != KRITIS3M_PKI_SUCCESS)
        {
                LOG_ERROR("Failed to finalize signing request: %d", init_ret);
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        // Send CSR to EST server
        const char* url = ctx->cert_type == CERT_TYPE_DATAPLANE ?
                                  "/.well-known/est/dataplane/simpleenroll" :
                                  "/.well-known/est/controlplane/simpleenroll";

        ret = pki_send_http_request(ctx,
                                    url,
                                    HTTP_POST,
                                    "application/pkcs10",
                                    csr_buffer,
                                    csr_size,
                                    http_response_callback);
        if (ret != ASL_SUCCESS)
        {
                LOG_ERROR("Failed to send CSR to EST server");
                goto cleanup;
        }

        // Handle response
        pthread_mutex_lock(&ctx->mutex);
        if (ctx->has_ca_chain && ctx->cert_size > 0 && ctx->ca_chain_buffer)
        {
                // Combine certificates
                size_t combined_size = ctx->cert_size + ctx->ca_chain_size;
                uint8_t* combined_buffer = malloc(combined_size);
                if (combined_buffer)
                {
                        memcpy(combined_buffer, ctx->cert_buffer, ctx->cert_size);
                        memcpy(combined_buffer + ctx->cert_size, ctx->ca_chain_buffer, ctx->ca_chain_size);
                        ctx->callback((char*) combined_buffer, combined_size);
                        free(combined_buffer);
                }
                else
                {
                        LOG_ERROR("Failed to allocate buffer for combined certificates");
                        ctx->callback((char*) ctx->cert_buffer, ctx->cert_size);
                }
        }
        else
        {
                ctx->callback((char*) ctx->cert_buffer, ctx->cert_size);
        }
        ctx->completed = true;
        pthread_mutex_unlock(&ctx->mutex);

cleanup:
        if (request)
        {
                signingRequest_free(request);
        }
        if (private_key)
        {
                privateKey_free(private_key);
        }

        // Check if thread should clean itself up
        pthread_mutex_lock(&ctx->mutex);
        bool should_cleanup = ctx->cleanup_requested;
        pthread_mutex_unlock(&ctx->mutex);

        if (should_cleanup)
        {
                cleanup_request_context(ctx);
        }

        return NULL;
}

// Public API functions
int cert_request(struct pki_client_config_t* config,
                 enum CERT_TYPE cert_type,
                 bool include_ca_certs,
                 pki_callback_t callback)
{
        if (!config || !config->endpoint_config || !config->serialnumber || !callback)
        {
                LOG_ERROR("Invalid arguments");
                return -1;
        }

        // Create request context
        pki_request_context_t* ctx = create_request_context(config,
                                                            cert_type,
                                                            include_ca_certs,
                                                            callback,
                                                            false);
        if (!ctx)
        {
                return -1;
        }

        // Create worker thread
        if (pthread_create(&ctx->thread_id, NULL, cert_request_thread, ctx) != 0)
        {
                LOG_ERROR("Failed to create worker thread");
                cleanup_request_context(ctx);
                return -1;
        }

        LOG_INFO("Certificate request thread started for %s", config->serialnumber);
        return 0;
}

static int fetch_device_certificates(pki_request_context_t* ctx, bool use_callback)
{
        int ret = 0;
        PrivateKey* private_key = NULL;
        SigningRequest* request = NULL;

        /// check arguments
        if (!ctx || !ctx->config || !ctx->config->endpoint_config || !ctx->config->serialnumber)
        {
                LOG_ERROR("No configuration available");
                ret = ASL_ARGUMENT_ERROR;
                goto cleanup;
        }

        private_key = privateKey_new();
        if (!private_key)
        {
                LOG_ERROR("Failed to create private key structure");
                ret = ASL_MEMORY_ERROR;
                goto cleanup;
        }

        // Load private key from endpoint configuration
        if (ctx->config && ctx->config->endpoint_config)
        {
                ret = privateKey_loadKeyFromBuffer(private_key,
                                                   ctx->config->endpoint_config->private_key.buffer,
                                                   ctx->config->endpoint_config->private_key.size);
                if (ret != KRITIS3M_PKI_SUCCESS)
                {
                        LOG_ERROR("Failed to load private key: %d", ret);
                        ret = ASL_CERTIFICATE_ERROR;
                        goto cleanup;
                }
        }
        else
        {
                LOG_ERROR("No endpoint configuration available");
                ret = ASL_ARGUMENT_ERROR;
                goto cleanup;
        }

        // Create signing request
        request = signingRequest_new();
        if (!request)
        {
                LOG_ERROR("Failed to create signing request");
                ret = ASL_MEMORY_ERROR;
                goto cleanup;
        }

        // Check if config is valid

        // Prepare metadata for CSR
        SigningRequestMetadata metadata = {.commonName = ctx->config->serialnumber,
                                           .org = "OTH Regensburg",
                                           .country = "DE",
                                           .unit = "LaS3",
                                           .email = NULL,
                                           .altNamesDNS = ctx->config->host,
                                           .altNamesURI = NULL,
                                           .altNamesIP = "127.0.0.1",
                                           .altNamesEmail = NULL};

        // Initialize CSR with metadata
        int init_ret = signingRequest_init(request, &metadata);
        if (init_ret != KRITIS3M_PKI_SUCCESS)
        {
                LOG_ERROR("Failed to initialize signing request: %d", init_ret);
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        // Allocate buffer for CSR
        uint8_t csr_buffer[4096] = {0};
        size_t csr_size = sizeof(csr_buffer);

        // Finalize CSR
        init_ret = signingRequest_finalize(request, private_key, csr_buffer, &csr_size, true);
        if (init_ret != KRITIS3M_PKI_SUCCESS)
        {
                LOG_ERROR("Failed to finalize signing request: %d", init_ret);
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        const char* url = (ctx->cert_type == CERT_TYPE_DATAPLANE) ?
                                  "/.well-known/est/dataplane/simpleenroll" :
                                  "/.well-known/est/controlplane/simpleenroll";

        ret = pki_send_http_request(ctx,
                                    url,
                                    HTTP_POST,
                                    "application/pkcs10",
                                    csr_buffer,
                                    csr_size,
                                    http_response_callback);
        if (ret < 0)
        {
                LOG_ERROR("Failed to fetch CA certificates");
                if (ctx->callback && use_callback)
                {
                        ctx->callback(NULL, 0);
                }
                goto cleanup;
        }

        if (ctx->callback && use_callback && ctx->cert_size > 0 && ctx->cert_buffer)
        {
                ctx->callback((char*) ctx->cert_buffer, ctx->cert_size);
        }

cleanup:
        if (request)
        {
                signingRequest_free(request);
        }
        if (private_key)
        {
                privateKey_free(private_key);
        }

        pthread_mutex_lock(&ctx->mutex);
        bool should_cleanup = ctx->cleanup_requested;
        pthread_mutex_unlock(&ctx->mutex);

        if (should_cleanup)
        {
                cleanup_request_context(ctx);
        }

        return ret;
}

int get_blocking_cert(struct pki_client_config_t* config,
                      enum CERT_TYPE cert_type,
                      bool include_ca_certs,
                      char** response_buffer,
                      size_t* response_buffer_size)
{
        int ret = 0;

        if (!config || !response_buffer || !response_buffer_size)
        {
                LOG_ERROR("Invalid arguments");
                return -1;
        }

        // Create request context
        pki_request_context_t* ctx = create_request_context(config, cert_type, include_ca_certs, NULL, true);
        if (!ctx)
        {
                return -1;
        }

        // Set response buffer pointers
        ctx->response_buffer = response_buffer;
        ctx->response_buffer_size = response_buffer_size;

        if (include_ca_certs)
        {
                int ret = fetch_ca_certificates(ctx, false);
                if (ret < 0)
                {
                        cleanup_request_context(ctx);
                        return ret;
                }
        }

        ret = fetch_device_certificates(ctx, false);
        if (ret < 0)
        {
                cleanup_request_context(ctx);
                return ret;
        }

        // chain chain_buffer and cert_buffer, if ....
        pthread_mutex_lock(&ctx->mutex);

        if (include_ca_certs)
        {
                if (ctx->has_ca_chain && ctx->ca_chain_buffer && ctx->cert_size > 0 && ctx->cert_buffer)
                {
                        // Combine certificates
                        size_t combined_size = ctx->cert_size + ctx->ca_chain_size;
                        uint8_t* combined_buffer = malloc(combined_size);
                        if (combined_buffer)
                        {
                                memcpy(combined_buffer, ctx->cert_buffer, ctx->cert_size);
                                memcpy(combined_buffer + ctx->cert_size,
                                       ctx->ca_chain_buffer,
                                       ctx->ca_chain_size);
                                *response_buffer = (char*) combined_buffer;
                                *response_buffer_size = combined_size;
                        }
                        else
                        {
                                LOG_ERROR("Failed to allocate buffer for combined certificates");
                                *response_buffer = (char*) ctx->cert_buffer;
                                *response_buffer_size = ctx->cert_size;
                        }
                }
                else
                {
                        *response_buffer = (char*) ctx->cert_buffer;
                        *response_buffer_size = ctx->cert_size;
                }
        }
        else
        {
                *response_buffer = (char*) ctx->cert_buffer;
                *response_buffer_size = ctx->cert_size;
        }
        ctx->completed = true;
        pthread_mutex_unlock(&ctx->mutex);

        pthread_mutex_destroy(&ctx->mutex);
        free(ctx);

        return 0;
}

// Cleanup all active threads
void cert_request_cleanup_all(void)
{
        pthread_mutex_lock(&active_threads_mutex);
        for (int i = 0; i < MAX_ACTIVE_THREADS; i++)
        {
                if (active_threads[i] != NULL)
                {
                        pki_request_context_t* ctx = active_threads[i];

                        // Mark thread for cleanup
                        pthread_mutex_lock(&ctx->mutex);
                        ctx->cleanup_requested = true;
                        pthread_mutex_unlock(&ctx->mutex);

                        // Cancel thread if it's still running
                        pthread_cancel(ctx->thread_id);
                        pthread_join(ctx->thread_id, NULL);

                        // Clean up resources
                        cleanup_request_context(ctx);
                        active_threads[i] = NULL;
                }
        }
        pthread_mutex_unlock(&active_threads_mutex);
}

// Forward declarations