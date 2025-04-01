#include "pki_client.h"
#include "asl.h"
#include "cJSON.h"
#include "file_io.h"
#include "http_client.h"
#include "ipc.h"
#include "kritis3m_pki_client.h"
#include "kritis3m_scale_service.h"
#include "logging.h"
#include "networking.h"
#include "poll_set.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

LOG_MODULE_CREATE("pki_client");

#define HTTP_BUFFER_SIZE 16096
#define HTTP_TIMEOUT_MS 50000

// Thread data structure for certificate request
typedef struct
{
        asl_endpoint_configuration* endpoint_config;
        char* host;
        int16_t port;
        char* serial_number;
        bool is_controlplane;
        uint8_t* cert_buffer;
        size_t cert_buffer_size;
        size_t cert_size;
        pki_callback_t callback;
        pthread_t thread_id;
        bool completed;
        bool cleanup_requested;
        pthread_mutex_t mutex;
        // Add flag to track if we have a CA chain
        bool has_ca_chain;
        uint8_t* ca_chain_buffer;
        size_t ca_chain_size;
        bool message_complete; // Flag to track if HTTP message is complete
} cert_thread_data_t;

// List of active threads for cleanup
#define MAX_ACTIVE_THREADS 2
static cert_thread_data_t* active_threads[MAX_ACTIVE_THREADS] = {NULL};
static pthread_mutex_t active_threads_mutex = PTHREAD_MUTEX_INITIALIZER;

// HTTP response callback data structure
typedef struct
{
        uint8_t* cert_buffer;
        size_t cert_buffer_size;
        size_t* cert_size;
        pki_callback_t callback;
        cert_thread_data_t* thread_data;
        bool is_ca_chain; // Flag to indicate if this is a CA chain request
} http_callback_data_t;

static int fetch_ca_certificates(cert_thread_data_t* thread_data,
                                 uint8_t* response_buffer,
                                 bool direct_request);

// Add thread to active threads list
static void register_thread(cert_thread_data_t* thread_data)
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
static void unregister_thread(cert_thread_data_t* thread_data)
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

// HTTP response callback
static void http_response_callback(struct http_response* rsp,
                                   enum http_final_call final_data,
                                   void* user_data)
{
        http_callback_data_t* callback_data = (http_callback_data_t*) user_data;
        cert_thread_data_t* thread_data = callback_data->thread_data;

        // Check if thread is still active (not cleanup requested)
        pthread_mutex_lock(&thread_data->mutex);
        bool is_active = !thread_data->cleanup_requested;
        pthread_mutex_unlock(&thread_data->mutex);

        if (!is_active)
        {
                LOG_WARN("Certificate request thread was cleaned up before response was received");
                return;
        }

        if (rsp->http_status_code == 200)
        {
                // Copy certificate data from body fragment
                if (rsp->body_frag_len > 0 && callback_data->cert_buffer != NULL)
                {
                        size_t copy_size = AT_LEAST(callback_data->cert_buffer_size,
                                                    rsp->body_frag_len);
                        memcpy(callback_data->cert_buffer, rsp->body_frag_start, copy_size);
                        *callback_data->cert_size = copy_size;

                        if (final_data == HTTP_DATA_FINAL && callback_data->callback)
                        {
                                // Call the user's callback function with the certificate data only if callback is set
                                // This lets us handle concatenation ourselves in the cert_request_thread
                                callback_data->callback((char*) callback_data->cert_buffer,
                                                        *callback_data->cert_size);

                                // Mark thread as completed only if callback was directly called
                                pthread_mutex_lock(&thread_data->mutex);
                                thread_data->completed = true;
                                pthread_mutex_unlock(&thread_data->mutex);
                        }

                        // Mark message as complete
                        if (final_data == HTTP_DATA_FINAL)
                        {
                                pthread_mutex_lock(&thread_data->mutex);
                                thread_data->message_complete = true;
                                pthread_mutex_unlock(&thread_data->mutex);
                        }
                }
        }
        else
        {
                LOG_ERROR("HTTP error: %d %s", rsp->http_status_code, rsp->http_status);
                if (final_data == HTTP_DATA_FINAL && callback_data->callback)
                {
                        // Call the callback with NULL to indicate failure, only if callback is set
                        callback_data->callback(NULL, 0);

                        // Mark thread as completed
                        pthread_mutex_lock(&thread_data->mutex);
                        thread_data->completed = true;
                        pthread_mutex_unlock(&thread_data->mutex);
                }

                // Mark message as complete regardless of callback
                if (final_data == HTTP_DATA_FINAL)
                {
                        pthread_mutex_lock(&thread_data->mutex);
                        thread_data->message_complete = true;
                        pthread_mutex_unlock(&thread_data->mutex);
                }
        }
}

// HTTP response callback for CA certificate chain
static void http_ca_chain_callback(struct http_response* rsp,
                                   enum http_final_call final_data,
                                   void* user_data)
{
        http_callback_data_t* callback_data = (http_callback_data_t*) user_data;
        cert_thread_data_t* thread_data = callback_data->thread_data;

        // Check if thread is still active (not cleanup requested)
        pthread_mutex_lock(&thread_data->mutex);
        bool is_active = !thread_data->cleanup_requested;
        pthread_mutex_unlock(&thread_data->mutex);

        if (!is_active)
        {
                LOG_WARN("Certificate chain request thread was cleaned up before response was "
                         "received");
                return;
        }

        if (rsp->http_status_code == 200)
        {
                // Copy certificate chain data from body fragment
                if (rsp->body_frag_len > 0 && callback_data->cert_buffer != NULL)
                {
                        size_t copy_size = AT_LEAST(callback_data->cert_buffer_size,
                                                    rsp->body_frag_len);
                        memcpy(callback_data->cert_buffer, rsp->body_frag_start, copy_size);
                        *callback_data->cert_size = copy_size;

                        if (final_data == HTTP_DATA_FINAL)
                        {
                                // Store CA chain in thread data
                                pthread_mutex_lock(&thread_data->mutex);
                                thread_data->has_ca_chain = true;
                                thread_data->ca_chain_buffer = malloc(*callback_data->cert_size);
                                if (thread_data->ca_chain_buffer)
                                {
                                        memcpy(thread_data->ca_chain_buffer,
                                               callback_data->cert_buffer,
                                               *callback_data->cert_size);
                                        thread_data->ca_chain_size = *callback_data->cert_size;
                                        LOG_INFO("CA chain received, size: %zu bytes",
                                                 thread_data->ca_chain_size);
                                }
                                else
                                {
                                        LOG_ERROR("Failed to allocate memory for CA chain");
                                        thread_data->has_ca_chain = false;
                                }
                                pthread_mutex_unlock(&thread_data->mutex);

                                // If this was a direct request for CA chain, call the callback
                                if (callback_data->is_ca_chain && callback_data->callback)
                                {
                                        callback_data->callback(callback_data->cert_buffer,
                                                                *callback_data->cert_size);

                                        // Mark thread as completed if this was a direct CA chain request
                                        pthread_mutex_lock(&thread_data->mutex);
                                        thread_data->completed = true;
                                        pthread_mutex_unlock(&thread_data->mutex);
                                }
                        }
                }
        }
        else
        {
                LOG_ERROR("HTTP error when fetching CA chain: %d %s",
                          rsp->http_status_code,
                          rsp->http_status);

                // Mark that we don't have the CA chain
                pthread_mutex_lock(&thread_data->mutex);
                thread_data->has_ca_chain = false;
                pthread_mutex_unlock(&thread_data->mutex);

                // If this was a direct request for CA chain, call the callback with failure
                if (final_data == HTTP_DATA_FINAL && callback_data->is_ca_chain &&
                    callback_data->callback)
                {
                        callback_data->callback(NULL, 0);

                        // Mark thread as completed
                        pthread_mutex_lock(&thread_data->mutex);
                        thread_data->completed = true;
                        pthread_mutex_unlock(&thread_data->mutex);
                }
        }
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
static void cleanup_thread_data(cert_thread_data_t* thread_data)
{
        if (thread_data)
        {
                if (thread_data->host)
                {
                        free(thread_data->host);
                }
                if (thread_data->serial_number)
                {
                        free(thread_data->serial_number);
                }
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

// Helper function for CA certificate chain fetch thread
static void* ca_chain_thread(void* arg)
{
        cert_thread_data_t* data = (cert_thread_data_t*) arg;
        uint8_t* response_buffer = malloc(HTTP_BUFFER_SIZE);
        if (!response_buffer)
        {
                LOG_ERROR("Failed to allocate response buffer for CA chain");
                pthread_mutex_lock(&data->mutex);
                data->completed = true;
                pthread_mutex_unlock(&data->mutex);
                return NULL;
        }

        // Fetch CA certificates directly
        int ret = fetch_ca_certificates(data, response_buffer, true);

        free(response_buffer);

        // If fetch failed, call callback with error
        if (ret != ASL_SUCCESS && !data->completed)
        {
                data->callback(NULL, 0);
                pthread_mutex_lock(&data->mutex);
                data->completed = true;
                pthread_mutex_unlock(&data->mutex);
        }

        return NULL;
}

// Worker thread function for certificate request
void* cert_request_thread(void* arg)
{
        cert_thread_data_t* thread_data = (cert_thread_data_t*) arg;
        int ret = 0;
        char* hostname = NULL;
        uint16_t port = 0; // Default HTTPS port
        struct addrinfo* addr_info = NULL;
        int sock_fd = -1;
        asl_endpoint* endpoint = NULL;
        asl_session* session = NULL;
        SigningRequest* request = NULL;
        uint8_t* csr_buffer = NULL;
        size_t csr_buffer_size = 4096;
        size_t csr_size = 0;
        PrivateKey* private_key = NULL;
        uint8_t* response_buffer = NULL;
        http_callback_data_t callback_data = {0};
        char* port_str = NULL;
        bool include_ca_certs = false;

        // Check if cleanup was requested
        pthread_mutex_lock(&thread_data->mutex);
        bool cleanup_requested = thread_data->cleanup_requested;
        include_ca_certs = thread_data->has_ca_chain; // Not using ca_chain buffer yet, using this flag to indicate if we should fetch CA certs
        hostname = strdup(thread_data->host);
        port = thread_data->port;
        pthread_mutex_unlock(&thread_data->mutex);

        if (cleanup_requested)
        {
                LOG_WARN("Cleanup requested before thread started work");
                return NULL;
        }

        // Allocate response buffer
        response_buffer = (uint8_t*) malloc(HTTP_BUFFER_SIZE);
        if (!response_buffer)
        {
                LOG_ERROR("Failed to allocate response buffer");
                goto cleanup;
        }
        // null response buffer
        memset(response_buffer, 0, HTTP_BUFFER_SIZE);

        // First, try to fetch the CA certificate chain if requested
        if (include_ca_certs)
        {
                LOG_INFO("Fetching CA certificate chain from EST server");
                ret = fetch_ca_certificates(thread_data, response_buffer, false);
                if (ret != ASL_SUCCESS)
                {
                        LOG_WARN("Failed to fetch CA certificate chain, continuing with CSR");
                        // We continue even if CA chain fetch fails
                }
        }

        // Connect to the server
        // Check if server is reachable
        // if (!ping_server(sock_fd))
        // {
        //         LOG_ERROR("EST server is not reachable");
        //         ret = ASL_CONN_CLOSED;
        //         goto cleanup;
        // }

        kritis3m_pki_configuration pki_config = {0};
        pki_config.log_callback = NULL;
        pki_config.log_level = KRITIS3M_PKI_LOG_LEVEL_DBG;
        pki_config.logging_enabled = true;
        // Initialize PKI library if not already done
        int init_ret = kritis3m_pki_init(&pki_config);
        if (init_ret != KRITIS3M_PKI_SUCCESS)
        {
                LOG_ERROR("Failed to initialize PKI library: %d", init_ret);
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        // Create a new private key structure
        private_key = privateKey_new();
        if (private_key == NULL)
        {
                LOG_ERROR("Failed to create private key structure");
                ret = ASL_MEMORY_ERROR;
                goto cleanup;
        }

        // Load private key from endpoint configuration
        if (thread_data->endpoint_config->private_key.buffer != NULL &&
            thread_data->endpoint_config->private_key.size > 0)
        {
                init_ret = privateKey_loadKeyFromBuffer(private_key,
                                                        thread_data->endpoint_config->private_key.buffer,
                                                        thread_data->endpoint_config->private_key.size);
                if (init_ret != KRITIS3M_PKI_SUCCESS)
                {
                        LOG_ERROR("Failed to load private key: %d", init_ret);
                        ret = ASL_CERTIFICATE_ERROR;
                        goto cleanup;
                }
        }
        else
        {
                LOG_ERROR("No private key available in endpoint configuration");
                ret = ASL_ARGUMENT_ERROR;
                goto cleanup;
        }

        // Create a new signing request
        request = signingRequest_new();
        if (request == NULL)
        {
                LOG_ERROR("Failed to create signing request");
                ret = ASL_MEMORY_ERROR;
                goto cleanup;
        }

        // Prepare metadata for CSR
        SigningRequestMetadata metadata = {.commonName = "KRITIS3M Test Entity", // thread_data->serial_number,
                                           .org = "OTH Regensburg",
                                           .country = "DE",
                                           .unit = "LaS3",
                                           .email = NULL,
                                           .altNamesDNS = "localhost",
                                           .altNamesURI = NULL,
                                           .altNamesIP = "127.0.0.1",
                                           .altNamesEmail = NULL};

        // Initialize CSR with metadata
        init_ret = signingRequest_init(request, &metadata);
        if (init_ret != KRITIS3M_PKI_SUCCESS)
        {
                LOG_ERROR("Failed to initialize signing request: %d", init_ret);
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        // Allocate buffer for CSR
        csr_buffer = (uint8_t*) malloc(csr_buffer_size);
        if (csr_buffer == NULL)
        {
                LOG_ERROR("Failed to allocate CSR buffer");
                ret = ASL_MEMORY_ERROR;
                goto cleanup;
        }
        // cleanup csr buffer
        memset(csr_buffer, 0, csr_buffer_size);

        // Finalize CSR
        init_ret = signingRequest_finalize(request, private_key, csr_buffer, &csr_buffer_size, true);
        if (init_ret != KRITIS3M_PKI_SUCCESS)
        {
                LOG_ERROR("Failed to finalize signing request: %d", init_ret);
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }
        csr_size = csr_buffer_size;
        write_file("/home/philipp/development/kritis3m_workspace/certificates/test_certs/secp384/"
                   "csr.txt",
                   csr_buffer,
                   csr_size,
                   false);

        if (address_lookup_client(hostname, port, &addr_info, AF_UNSPEC) < 0)
        {
                LOG_ERROR("Failed to resolve EST server hostname: %s", hostname);
                ret = ASL_ARGUMENT_ERROR;
                goto cleanup;
        }

        // Create client socket
        sock_fd = create_client_socket(addr_info->ai_family == AF_INET6 ? AF_INET6 : AF_INET);
        if (sock_fd < 0)
        {
                LOG_ERROR("Failed to create client socket");
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        // Setup TLS session to EST server
        endpoint = asl_setup_client_endpoint(thread_data->endpoint_config);
        if (endpoint == NULL)
        {
                LOG_ERROR("Failed to setup ASL client endpoint");
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        // Create ASL session
        if (connect(sock_fd, addr_info->ai_addr, addr_info->ai_addrlen) < 0)
        {
                LOG_ERROR("Failed to connect to EST server");
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }
        session = asl_create_session(endpoint, sock_fd);
        if (session == NULL)
        {
                LOG_ERROR("Failed to create ASL session");
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        // Perform TLS handshake
        ret = asl_handshake(session);
        if (ret != ASL_SUCCESS)
        {
                LOG_ERROR("TLS handshake failed: %s", asl_error_message(ret));
                goto cleanup;
        }

        // Allocate port string
        port_str = malloc(16);
        if (!port_str)
        {
                LOG_ERROR("Failed to allocate port string");
                ret = ASL_MEMORY_ERROR;
                goto cleanup;
        }

        // Format port as string
        snprintf(port_str, 16, "%hu", port);
        // Setup HTTP request for EST
        struct http_request req = {0};

        req.method = HTTP_POST;
        req.url = "/.well-known/est/simplereenroll";
        req.protocol = "HTTP/1.1";
        req.host = hostname;
        req.port = port_str;
        req.content_type_value = "application/pkcs10";

        req.payload = (char*) csr_buffer;
        req.payload_len = csr_buffer_size;

        req.recv_buf = response_buffer;
        req.recv_buf_len = HTTP_BUFFER_SIZE;
        const char* headers[] = {"Accept: application/pkcs7-mime\r\n",
                                 "Content-Transfer-Encoding: base64\r\n",
                                 "Connection: close\r\n",
                                 NULL};
        req.header_fields = headers;

        // Setup response callback for device certificate
        callback_data.cert_buffer = thread_data->cert_buffer;
        callback_data.cert_buffer_size = thread_data->cert_buffer_size;
        callback_data.cert_size = &thread_data->cert_size;
        callback_data.callback = NULL; // We'll handle callback ourselves after combining certs
        callback_data.thread_data = thread_data;
        callback_data.is_ca_chain = false;
        req.response = http_response_callback;

        // Send HTTP request with proper timeout struct
        struct duration timeout = ms_to_duration(HTTP_TIMEOUT_MS);
        ret = https_client_req(sock_fd, session, &req, timeout, &callback_data);
        if (ret < 0)
        {
                LOG_ERROR("HTTP request failed: %d", ret);
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        bool request_completed = false;
        pthread_mutex_lock(&thread_data->mutex);
        request_completed = thread_data->message_complete;
        pthread_mutex_unlock(&thread_data->mutex);
        if (!request_completed)
        {
                LOG_ERROR("it isnt ready yet\n");
        }

        pthread_mutex_lock(&thread_data->mutex);
        if (thread_data->has_ca_chain && thread_data->cert_size > 0 && thread_data->ca_chain_buffer)
        {
                // Allocate buffer for combined certificates
                size_t combined_size = thread_data->cert_size + thread_data->ca_chain_size;
                uint8_t* combined_buffer = malloc(combined_size);

                if (combined_buffer)
                {
                        // Copy device certificate
                        memcpy(combined_buffer, thread_data->cert_buffer, thread_data->cert_size);

                        // Append CA chain
                        memcpy(combined_buffer + thread_data->cert_size,
                               thread_data->ca_chain_buffer,
                               thread_data->ca_chain_size);

                        LOG_INFO("Combined certificate chain created, total size: %zu bytes",
                                 combined_size);

                        // Call the callback with combined chain
                        if (thread_data->callback)
                        {
                                thread_data->callback((char*) combined_buffer, combined_size);
                        }

                        free(combined_buffer);
                }
                else
                {
                        LOG_ERROR("Failed to allocate buffer for combined certificate chain");
                        // Just use device cert if combining fails
                        if (thread_data->callback)
                        {
                                thread_data->callback((char*) thread_data->cert_buffer,
                                                      thread_data->cert_size);
                        }
                }
        }
        else
        {
                // Just use device cert if CA chain not available
                if (thread_data->callback)
                {
                        thread_data->callback((char*) thread_data->cert_buffer, thread_data->cert_size);
                }
        }
        thread_data->completed = true;
        pthread_mutex_unlock(&thread_data->mutex);

        ret = ASL_SUCCESS;

cleanup:
        // Check if we need to call the callback with error
        if (ret != ASL_SUCCESS && thread_data->callback)
        {
                // Error occurred, call the callback with NULL
                thread_data->callback(NULL, 0);

                // Mark thread as completed
                pthread_mutex_lock(&thread_data->mutex);
                thread_data->completed = true;
                pthread_mutex_unlock(&thread_data->mutex);
        }

        // Clean up resources
        if (sock_fd >= 0)
        {
                closesocket(sock_fd);
        }

        if (addr_info != NULL)
        {
                freeaddrinfo(addr_info);
        }

        if (hostname != NULL)
        {
                free(hostname);
        }

        if (port_str != NULL)
        {
                free(port_str);
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

        if (request != NULL)
        {
                signingRequest_free(request);
        }

        if (csr_buffer != NULL)
        {
                free(csr_buffer);
        }

        if (private_key != NULL)
        {
                privateKey_free(private_key);
        }

        if (response_buffer != NULL)
        {
                free(response_buffer);
        }

        // Check if thread should clean itself up
        pthread_mutex_lock(&thread_data->mutex);
        bool should_cleanup = thread_data->cleanup_requested;
        pthread_mutex_unlock(&thread_data->mutex);

        if (should_cleanup)
        {
                cleanup_thread_data(thread_data);
        }

        return NULL;
}

// Cleanup all active threads
void cert_request_cleanup_all(void)
{
        pthread_mutex_lock(&active_threads_mutex);
        for (int i = 0; i < MAX_ACTIVE_THREADS; i++)
        {
                if (active_threads[i] != NULL)
                {
                        cert_thread_data_t* thread_data = active_threads[i];

                        // Mark thread for cleanup
                        pthread_mutex_lock(&thread_data->mutex);
                        thread_data->cleanup_requested = true;
                        pthread_mutex_unlock(&thread_data->mutex);

                        // Cancel thread if it's still running
                        pthread_cancel(thread_data->thread_id);
                        pthread_join(thread_data->thread_id, NULL);

                        // Clean up resources
                        cleanup_thread_data(thread_data);
                        active_threads[i] = NULL;
                }
        }
        pthread_mutex_unlock(&active_threads_mutex);
}

/**
 * Request a certificate from the PKI server
 *
 * @param endpoint_config ASL endpoint configuration containing private key
 * @param config PKI client configuration
 * @param cert_type Type of certificate (CERT_TYPE_DATAPLANE or CERT_TYPE_CONTROLPLANE)
 * @param include_ca_certs Whether to include CA certificates in the response
 * @param callback Function to call when certificate is received
 *
 * @return 0 on success, negative error code on failure
 */
int cert_request(struct pki_client_config_t* config,
                 enum CERT_TYPE cert_type,
                 bool include_ca_certs,
                 pki_callback_t callback)
{
        if (!config->endpoint_config || !config || !config->serialnumber || !callback)
        {
                LOG_ERROR("Invalid arguments");
                return -1;
        }

        // Create thread data structure
        cert_thread_data_t* thread_data = malloc(sizeof(cert_thread_data_t));
        if (!thread_data)
        {
                LOG_ERROR("Failed to allocate thread data");
                return -1;
        }
        memset(thread_data, 0, sizeof(cert_thread_data_t));

        // Initialize mutex
        if (pthread_mutex_init(&thread_data->mutex, NULL) != 0)
        {
                LOG_ERROR("Failed to initialize mutex");
                free(thread_data);
                return -1;
        }

        // Construct EST server URL
        char est_server_url[128];
        snprintf(est_server_url, sizeof(est_server_url), "%s:%d", config->host, config->port);

        // Initialize thread data
        thread_data->endpoint_config = config->endpoint_config;
        thread_data->host = strdup(config->host);
        thread_data->port = config->port;
        thread_data->serial_number = strdup(config->serialnumber);
        thread_data->is_controlplane = (cert_type == CERT_TYPE_CONTROLPLANE);
        thread_data->cert_buffer = malloc(HTTP_BUFFER_SIZE);
        thread_data->cert_buffer_size = HTTP_BUFFER_SIZE;
        thread_data->cert_size = 0;
        thread_data->callback = callback;
        thread_data->completed = false;
        thread_data->cleanup_requested = false;
        thread_data->has_ca_chain = include_ca_certs; // Set flag based on parameter
        thread_data->ca_chain_buffer = NULL;
        thread_data->ca_chain_size = 0;
        thread_data->message_complete = false;

        // Check for allocation failures
        if (!thread_data->host || !thread_data->serial_number || !thread_data->cert_buffer)
        {
                LOG_ERROR("Failed to allocate memory for thread data");
                cleanup_thread_data(thread_data);
                return -1;
        }

        // Register thread in active threads list
        register_thread(thread_data);

        // Create worker thread
        if (pthread_create(&thread_data->thread_id, NULL, cert_request_thread, thread_data) != 0)
        {
                LOG_ERROR("Failed to create worker thread");
                cleanup_thread_data(thread_data);
                return -1;
        }

        // Thread is started, return immediately
        LOG_INFO("Certificate request thread started for %s", config->serialnumber);
        return 0;
}

// Helper function to fetch CA certificate chain
static int fetch_ca_certificates(cert_thread_data_t* thread_data,
                                 uint8_t* response_buffer,
                                 bool direct_request)
{
        int ret = 0;
        char* hostname = NULL;
        uint16_t port = 8443; // Default HTTPS port
        struct addrinfo* addr_info = NULL;
        int sock_fd = -1;
        asl_endpoint* endpoint = NULL;
        asl_session* session = NULL;
        char* port_str = NULL;
        http_callback_data_t callback_data = {0};

        // mutex
        pthread_mutex_lock(&thread_data->mutex);
        hostname = thread_data->host;
        port = thread_data->port;
        pthread_mutex_unlock(&thread_data->mutex);

        // Resolve the hostname
        if (address_lookup_client(hostname, port, &addr_info, AF_UNSPEC) < 0)
        {
                LOG_ERROR("Failed to resolve EST server hostname: %s", hostname);
                ret = ASL_ARGUMENT_ERROR;
                goto cleanup;
        }

        // Create client socket
        sock_fd = create_client_socket(addr_info->ai_family == AF_INET6 ? AF_INET6 : AF_INET);
        if (sock_fd < 0)
        {
                LOG_ERROR("Failed to create client socket for CA chain request");
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        // Connect to the server
        if (connect(sock_fd, addr_info->ai_addr, addr_info->ai_addrlen) < 0)
        {
                LOG_ERROR("Failed to connect to EST server for CA chain");
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        // Setup TLS session to EST server
        endpoint = asl_setup_client_endpoint(thread_data->endpoint_config);
        if (endpoint == NULL)
        {
                LOG_ERROR("Failed to setup ASL client endpoint for CA chain");
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        // Create ASL session
        session = asl_create_session(endpoint, sock_fd);
        if (session == NULL)
        {
                LOG_ERROR("Failed to create ASL session for CA chain");
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        // Perform TLS handshake
        ret = asl_handshake(session);
        if (ret != ASL_SUCCESS)
        {
                LOG_ERROR("TLS handshake failed for CA chain: %s", asl_error_message(ret));
                goto cleanup;
        }

        // Allocate port string
        port_str = malloc(16);
        if (!port_str)
        {
                LOG_ERROR("Failed to allocate port string for CA chain");
                ret = ASL_MEMORY_ERROR;
                goto cleanup;
        }

        // Format port as string
        snprintf(port_str, 16, "%hu", port);

        // Setup HTTP request for EST cacerts
        struct http_request req = {0};
        req.method = HTTP_GET;
        req.url = "/.well-known/est/cacerts";
        req.protocol = "HTTP/1.1";
        req.host = hostname;
        req.port = port_str;
        req.content_type_value = NULL; // No content type for GET request

        req.payload = NULL;
        req.payload_len = 0;

        req.recv_buf = response_buffer;
        req.recv_buf_len = HTTP_BUFFER_SIZE;
        const char* headers[] = {"Accept: application/pkcs7-mime\r\n", "Connection: close\r\n", NULL};
        req.header_fields = headers;

        // Setup response callback
        callback_data.cert_buffer = thread_data->cert_buffer;
        callback_data.cert_buffer_size = thread_data->cert_buffer_size;
        callback_data.cert_size = &thread_data->cert_size;
        callback_data.callback = thread_data->callback;
        callback_data.thread_data = thread_data;
        callback_data.is_ca_chain = direct_request; // Flag if this is a direct CA chain request
        req.response = http_ca_chain_callback;

        // Send HTTP request with proper timeout struct
        struct duration timeout = ms_to_duration(HTTP_TIMEOUT_MS);
        ret = https_client_req(sock_fd, session, &req, timeout, &callback_data);
        if (ret < 0)
        {
                LOG_ERROR("HTTP request for CA chain failed: %d", ret);
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        LOG_INFO("CA certificate chain request sent successfully");
        ret = ASL_SUCCESS;

cleanup:
        // Clean up resources
        if (sock_fd >= 0)
        {
                closesocket(sock_fd);
        }

        if (addr_info != NULL)
        {
                freeaddrinfo(addr_info);
        }

        if (hostname != NULL)
        {
                free(hostname);
        }

        if (port_str != NULL)
        {
                free(port_str);
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

        return ret;
}

/**
 * Fetch the CA certificate chain from the PKI server
 *
 * @param config PKI client configuration
 * @param callback Function to call when certificate chain is received
 *
 * @return 0 on success, negative error code on failure
 */
int fetch_ca_cert_chain(struct pki_client_config_t* config, pki_callback_t callback)
{
        if (!config->endpoint_config || !config || !config->serialnumber || !callback)
        {
                LOG_ERROR("Invalid arguments for fetch_ca_cert_chain");
                return -1;
        }

        // Create thread data structure
        cert_thread_data_t* thread_data = malloc(sizeof(cert_thread_data_t));
        if (!thread_data)
        {
                LOG_ERROR("Failed to allocate thread data");
                return -1;
        }
        memset(thread_data, 0, sizeof(cert_thread_data_t));

        // Initialize mutex
        if (pthread_mutex_init(&thread_data->mutex, NULL) != 0)
        {
                LOG_ERROR("Failed to initialize mutex");
                free(thread_data);
                return -1;
        }

        // Construct EST server URL
        char est_server_url[128];
        snprintf(est_server_url, sizeof(est_server_url), "%s:%d", config->host, config->port);

        // Initialize thread data
        thread_data->endpoint_config = config->endpoint_config;
        thread_data->host = strdup(config->host);
        thread_data->port = config->port;
        thread_data->serial_number = strdup(config->serialnumber);
        thread_data->cert_buffer = malloc(HTTP_BUFFER_SIZE);
        thread_data->cert_buffer_size = HTTP_BUFFER_SIZE;
        thread_data->cert_size = 0;
        thread_data->callback = callback;
        thread_data->completed = false;
        thread_data->cleanup_requested = false;
        thread_data->has_ca_chain = false;

        // Check for allocation failures
        if (!thread_data->host || !thread_data->serial_number || !thread_data->cert_buffer)
        {
                LOG_ERROR("Failed to allocate memory for thread data");
                cleanup_thread_data(thread_data);
                return -1;
        }

        // Register thread in active threads list
        register_thread(thread_data);

        // Create worker thread specifically for CA chain fetch
        if (pthread_create(&thread_data->thread_id, NULL, ca_chain_thread, thread_data) != 0)
        {
                LOG_ERROR("Failed to create worker thread for CA chain fetch");
                cleanup_thread_data(thread_data);
                return -1;
        }

        // Thread is started, return immediately
        LOG_INFO("CA certificate chain request thread started");
        return 0;
}
