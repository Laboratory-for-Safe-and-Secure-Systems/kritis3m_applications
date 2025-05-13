#include "pki_client.h"
#include "asl.h"
#include "asl_helper.h"
#include "file_io.h"
#include "http_client.h"
#include "http_method.h"
#include "kritis3m_pki_client.h"
#include "kritis3m_pki_common.h"
#include "logging.h"
#include "networking.h"
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

LOG_MODULE_CREATE("pki_client");

#define HTTP_BUFFER_SIZE 40000
#define HTTP_TIMEOUT_MS 50000

// Forward declarations
static void pki_cleanup_connection(asl_endpoint* endpoint,
                                   asl_session* session,
                                   int sock_fd,
                                   struct addrinfo* addr_info);
static bool ping_server(int socket_fd);
static void http_response_callback(struct http_response* rsp,
                                   enum http_final_call final_data,
                                   void* user_data);

// Helper function to cleanup connection resources
static void pki_cleanup_connection(asl_endpoint* endpoint,
                                   asl_session* session,
                                   int sock_fd,
                                   struct addrinfo* addr_info)
{
        if (session != NULL)
        {
                asl_close_session(session);
                asl_free_session(session);
        }
        if (sock_fd >= 0)
        {
                closesocket(sock_fd);
        }

        if (addr_info != NULL)
        {
                freeaddrinfo(addr_info);
        }

        if (endpoint != NULL)
        {
                asl_free_endpoint(endpoint);
        }
}

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

void init_est_configuration(struct est_configuration* config, const char* algo, const char* alt_algo)
{
        if (!algo && alt_algo)
        {
                LOG_WARN("only alternative algorithm specified, using existing keys instead");
                config->algorithm = NULL;
                config->alt_algoithm = NULL;
        }
        else
        {
                config->algorithm = algo;
                config->alt_algoithm = (alt_algo && algo) ? alt_algo : NULL;
        }

        memset(config->chain, 0, MAX_CHAIN_SIZE);
        config->chain_buffer_size = MAX_CHAIN_SIZE;
        memset(config->key, 0, MAX_KEY_SIZE);
        config->key_buffer_size = MAX_KEY_SIZE;
        memset(config->alt_key, 0, MAX_KEY_SIZE);
        config->alt_key_buffer_size = MAX_KEY_SIZE;
}

int blocking_est_request(struct pki_client_config_t* config,
                         enum CERT_TYPE cert_type,
                         bool include_ca_certs,
                         struct est_configuration* est_config)
{
        int ret = 0;
        PrivateKey* private_key = NULL;
        SigningRequest* request = NULL;
        uint8_t* ca_chain_buffer = NULL;
        int ca_chain_size = 0;
        uint8_t* cert_buffer = NULL;
        int cert_size = 0;

        if (!config || !est_config)
        {
                LOG_ERROR("Invalid arguments");
                return -1;
        }

        // Generate or use existing keys
        private_key = privateKey_new();
        if (!private_key)
        {
                LOG_ERROR("Failed to create private key structure");
                ret = ASL_MEMORY_ERROR;
                goto cleanup;
        }

        if (est_config->algorithm)
        {
                {

                        LOG_DEBUG("generate keys is enabled. new keys are generated");
                        ret = privateKey_generateKey(private_key, est_config->algorithm);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                        {
                                LOG_ERROR("Failed to generate primary key: %d", ret);
                                ret = ASL_CERTIFICATE_ERROR;
                                goto cleanup;
                        }

                        if (est_config->key && est_config->key_buffer_size > 0)
                        {
                                size_t key_size = est_config->key_buffer_size;
                                memset(est_config->key, 0, est_config->key_buffer_size);
                                ret = privateKey_writeKeyToBuffer(private_key,
                                                                  (uint8_t*) est_config->key,
                                                                  &key_size);
                                if (ret != KRITIS3M_PKI_SUCCESS)
                                {
                                        LOG_ERROR("Failed to export primary key: %d", ret);
                                        ret = ASL_CERTIFICATE_ERROR;
                                        goto cleanup;
                                }
                                est_config->key_size = key_size;
                        }
                }

                // Generate alternative key if requested
                if (est_config->alt_algoithm)
                {

                        LOG_DEBUG("alternative key requested, generating alt key");
                        ret = privateKey_generateAltKey(private_key, est_config->alt_algoithm);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                        {
                                LOG_ERROR("Failed to generate alternative key: %d", ret);
                                ret = ASL_CERTIFICATE_ERROR;
                                goto cleanup;
                        }

                        if (est_config->alt_key && est_config->alt_key_buffer_size > 0)
                        {
                                size_t alt_key_size = est_config->alt_key_buffer_size;
                                memset(est_config->alt_key, 0, est_config->alt_key_buffer_size);
                                ret = privateKey_writeAltKeyToBuffer(private_key,
                                                                     (uint8_t*) est_config->alt_key,
                                                                     &alt_key_size);
                                if (ret != KRITIS3M_PKI_SUCCESS)
                                {
                                        LOG_ERROR("Failed to export alternative key: %d", ret);
                                        ret = ASL_CERTIFICATE_ERROR;
                                        goto cleanup;
                                }
                                est_config->alt_key_size = alt_key_size;
                        }
                }
        }
        else
        {
                LOG_DEBUG("we dont generate new keys, we use existing keys from "
                          "endpoint_configuration");
                // Load existing key
                if (config->endpoint_config->private_key.buffer &&
                    config->endpoint_config->private_key.size > 0)
                {
                        if (est_config->key && est_config->key_buffer_size > 0)
                        {

                                memset(est_config->key, 0, est_config->key_buffer_size);
                                memcpy(est_config->key,
                                       config->endpoint_config->private_key.buffer,
                                       config->endpoint_config->private_key.size);
                                est_config->key_size = config->endpoint_config->private_key.size;
                        }

                        ret = privateKey_loadKeyFromBuffer(private_key,
                                                           (uint8_t*) est_config->key,
                                                           est_config->key_size);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                        {
                                LOG_ERROR("Failed to load private key: %d", ret);
                                ret = ASL_CERTIFICATE_ERROR;
                                goto cleanup;
                        }

                        if (config->endpoint_config->private_key.additional_key_buffer &&
                            config->endpoint_config->private_key.additional_key_size > 0)
                        {

                                if (est_config->alt_key && est_config->alt_key_buffer_size > 0)
                                {

                                        memset(est_config->alt_key, 0, est_config->alt_key_buffer_size);
                                        memcpy(est_config->alt_key,
                                               config->endpoint_config->private_key.additional_key_buffer,
                                               config->endpoint_config->private_key.additional_key_size);
                                        est_config->alt_key_size = config->endpoint_config
                                                                           ->private_key.additional_key_size;

                                        ret = privateKey_loadAltKeyFromBuffer(private_key,
                                                                              (uint8_t*) est_config->alt_key,
                                                                              est_config->alt_key_size);
                                        if (ret != KRITIS3M_PKI_SUCCESS)
                                        {
                                                LOG_ERROR("Failed to load alternative key: %d", ret);
                                                ret = ASL_CERTIFICATE_ERROR;
                                                goto cleanup;
                                        }
                                }
                        }
                }
                else
                {
                        LOG_ERROR("No private key available");
                        ret = ASL_ARGUMENT_ERROR;
                        goto cleanup;
                }
        }

        // Create signing request
        request = signingRequest_new();
        if (!request)
        {
                LOG_ERROR("Failed to create signing request");
                ret = ASL_MEMORY_ERROR;
                goto cleanup;
        }

        // Prepare metadata for CSR
        SigningRequestMetadata metadata = {.commonName = config->serialnumber,
                                           .org = "OTH Regensburg",
                                           .country = "DE",
                                           .unit = "LaS3",
                                           .email = NULL,
                                           .altNamesDNS = config->host,
                                           .altNamesURI = NULL,
                                           .altNamesIP = NULL,
                                           .altNamesEmail = NULL};

        // Initialize CSR with metadata
        ret = signingRequest_init(request, &metadata);
        if (ret != KRITIS3M_PKI_SUCCESS)
        {
                LOG_ERROR("Failed to initialize signing request: %d", ret);
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        // Allocate buffer for CSR
        uint8_t csr_buffer[MAX_KEY_SIZE] = {0};
        size_t csr_size = sizeof(csr_buffer);

        // Finalize CSR
        ret = signingRequest_finalize(request, private_key, csr_buffer, &csr_size, true);
        if (ret != KRITIS3M_PKI_SUCCESS)
        {
                LOG_ERROR("Failed to finalize signing request: %d", ret);
                ret = ASL_INTERNAL_ERROR;
                goto cleanup;
        }

        // Fetch CA certificates if requested
        if (include_ca_certs)
        {
                // Create connection for CA certificates
                asl_endpoint* endpoint = NULL;
                asl_session* session = NULL;
                int sock_fd = -1;

                ret = establish_connection(config->host,
                                           config->port,
                                           config->endpoint_config,
                                           &endpoint,
                                           &session,
                                           &sock_fd);
                if (ret != ASL_SUCCESS)
                {
                        LOG_ERROR("Failed to establish connection for CA certificates: %d", ret);
                        goto cleanup;
                }

                // Format port as string
                char port_str[16];
                snprintf(port_str, sizeof(port_str), "%hu", config->port);

                // Setup HTTP request for CA certificates
                const char* ca_url = (cert_type == CERT_TYPE_DATAPLANE) ?
                                             "/.well-known/est/dataplane/cacerts" :
                                             "/.well-known/est/controlplane/cacerts";

                struct http_request ca_req = {0};
                ca_req.method = HTTP_GET;
                ca_req.url = ca_url;
                ca_req.protocol = "HTTP/1.1";
                ca_req.host = config->host;
                ca_req.port = port_str;
                ca_req.content_type_value = "application/pkcs7-mime";

                const char* cert_headers[] = {"Accept: application/pkcs7-mime\r\n",
                                              "Content-Transfer-Encoding: base64\r\n",
                                              "Connection: close\r\n",
                                              NULL};
                ca_req.header_fields = cert_headers;
                ca_req.response = http_response_callback;

                // Set headers
                const char* ca_headers[] = {"Accept: application/pkcs7-mime\r\n",
                                            "Content-Transfer-Encoding: base64\r\n",
                                            "Connection: close\r\n",
                                            NULL};
                ca_req.header_fields = ca_headers;

                // Allocate buffer for response
                uint8_t ca_rsp_buffer[HTTP_BUFFER_SIZE];
                memset(ca_rsp_buffer, 0, sizeof(ca_rsp_buffer));
                ca_req.recv_buf = ca_rsp_buffer;
                ca_req.recv_buf_len = sizeof(ca_rsp_buffer);

                // Response handler
                struct http_response ca_response = {0};
                // We'll still need direct access to the response for parsing

                // Send request with timeout
                struct duration timeout = ms_to_duration(HTTP_TIMEOUT_MS);
                ret = https_client_req(sock_fd, session, &ca_req, timeout, &ca_response);
                if (ret < 0 || ca_response.http_status_code != 200)
                {
                        LOG_ERROR("Failed to fetch CA certificates: %d, status: %d",
                                  ret,
                                  ca_response.http_status_code);
                        pki_cleanup_connection(endpoint, session, sock_fd, NULL);
                        ret = ASL_CERTIFICATE_ERROR;
                        goto cleanup;
                }

                // Parse the EST response to get CA certificates
                ret = parseESTResponse(ca_response.body_frag_start,
                                       ca_response.body_frag_len,
                                       &ca_chain_buffer,
                                       &ca_chain_size);
                if (ret != KRITIS3M_PKI_SUCCESS || !ca_chain_buffer || ca_chain_size <= 0)
                {
                        LOG_ERROR("Failed to parse CA certificates response: %d", ret);
                        pki_cleanup_connection(endpoint, session, sock_fd, NULL);
                        ret = ASL_CERTIFICATE_ERROR;
                        goto cleanup;
                }

                pki_cleanup_connection(endpoint, session, sock_fd, NULL);
        }

        // Send certificate request
        {
                // Create connection for certificate request
                asl_endpoint* endpoint = NULL;
                asl_session* session = NULL;
                int sock_fd = -1;

                ret = establish_connection(config->host,
                                           config->port,
                                           config->endpoint_config,
                                           &endpoint,
                                           &session,
                                           &sock_fd);
                if (ret != ASL_SUCCESS)
                {
                        LOG_ERROR("Failed to establish connection for certificate request: %d", ret);
                        goto cleanup;
                }

                // Format port as string
                char port_str[16];
                snprintf(port_str, sizeof(port_str), "%hu", config->port);

                // Setup HTTP request for certificate
                const char* cert_url = (cert_type == CERT_TYPE_DATAPLANE) ?
                                               "/.well-known/est/dataplane/simpleenroll" :
                                               "/.well-known/est/controlplane/simpleenroll";

                struct http_request cert_req = {0};
                cert_req.method = HTTP_POST;
                cert_req.url = cert_url;
                cert_req.protocol = "HTTP/1.1";
                cert_req.host = config->host;
                cert_req.port = port_str;
                cert_req.content_type_value = "application/pkcs10";
                const char* headers[] = {"Accept: application/pkcs7-mime\r\n",
                                         "Content-Transfer-Encoding: base64\r\n",
                                         "Connection: close\r\n",
                                         NULL};
                cert_req.header_fields = headers;
                cert_req.payload = (char*) csr_buffer;
                cert_req.payload_len = csr_size;
                cert_req.response = http_response_callback;


                // Allocate buffer for response
                uint8_t cert_rsp_buffer[MAX_KEY_SIZE];
                memset(cert_rsp_buffer, 0, sizeof(cert_rsp_buffer));
                cert_req.recv_buf = cert_rsp_buffer;
                cert_req.recv_buf_len = sizeof(cert_rsp_buffer);

                // Response handler
                struct http_response cert_response = {0};

                // Send request with timeout
                struct duration timeout = ms_to_duration(HTTP_TIMEOUT_MS);
                ret = https_client_req(sock_fd, session, &cert_req, timeout, &cert_response);
                if (ret < 0 || cert_response.http_status_code != 200)
                {
                        LOG_ERROR("Failed to fetch certificate: %d, status: %d",
                                  ret,
                                  cert_response.http_status_code);
                        pki_cleanup_connection(endpoint, session, sock_fd, NULL);
                        ret = ASL_CERTIFICATE_ERROR;
                        goto cleanup;
                }

                // Parse the EST response to get device certificate
                ret = parseESTResponse(cert_response.body_frag_start,
                                       cert_response.body_frag_len,
                                       &cert_buffer,
                                       &cert_size);
                if (ret != KRITIS3M_PKI_SUCCESS || !cert_buffer || cert_size <= 0)
                {
                        LOG_ERROR("Failed to parse certificate response: %d", ret);
                        pki_cleanup_connection(endpoint, session, sock_fd, NULL);
                        ret = ASL_CERTIFICATE_ERROR;
                        goto cleanup;
                }

                pki_cleanup_connection(endpoint, session, sock_fd, NULL);
        }

        // Combine certificates if requested and copy to output buffer
        if (est_config->chain && est_config->chain_buffer_size > 0)
        {
                if (include_ca_certs && ca_chain_buffer && ca_chain_size > 0)
                {
                        // Combine device certificate and CA chain
                        size_t combined_size = cert_size + ca_chain_size;

                        if (combined_size <= est_config->chain_buffer_size)
                        {
                                memset(est_config->chain, 0, est_config->chain_buffer_size);
                                // Copy device certificate
                                memcpy(est_config->chain, cert_buffer, cert_size);

                                // Append CA chain
                                memcpy(est_config->chain + cert_size, ca_chain_buffer, ca_chain_size);

                                est_config->chain_size = combined_size;
                        }
                        else
                        {
                                LOG_ERROR("Buffer too small for combined certificates");
                                ret = ASL_MEMORY_ERROR;
                                goto cleanup;
                        }
                }
                else if (cert_size <= est_config->chain_buffer_size)
                {

                        memset(est_config->chain, 0, est_config->chain_buffer_size);
                        // Just copy the device certificate
                        memcpy(est_config->chain, cert_buffer, cert_size);
                        est_config->chain_size = cert_size;
                }
                else
                {
                        LOG_ERROR("Buffer too small for certificate");
                        ret = ASL_MEMORY_ERROR;
                        goto cleanup;
                }
        }

        ret = ASL_SUCCESS;

cleanup:
        if (private_key)
        {
                privateKey_free(private_key);
        }
        if (request)
        {
                signingRequest_free(request);
        }
        if (ca_chain_buffer)
        {
                free(ca_chain_buffer);
        }
        if (cert_buffer)
        {
                free(cert_buffer);
        }

        return ret;
}

// Response callback function to handle HTTP responses
static void http_response_callback(struct http_response* rsp,
                                   enum http_final_call final_data,
                                   void* user_data)
{
        struct http_response* rsp_ptr = (struct http_response*) user_data;
        if (!rsp)
        {
                LOG_ERROR("Received null HTTP response");
                return;
        }

        // Check HTTP status code
        if (rsp->http_status_code < 200 || rsp->http_status_code >= 300)
        {
                LOG_ERROR("HTTP request failed with status code: %d, status: %s",
                          rsp->http_status_code,
                          rsp->http_status);
                return;
        }

        // Process content-length and data progress
        if (rsp->cl_present)
        {
                LOG_DEBUG("Received HTTP response data: %zu of %zu bytes (%d%%)",
                          rsp->processed,
                          rsp->content_length,
                          (int) (rsp->processed * 100 /
                                 (rsp->content_length ? rsp->content_length : 1)));
        }
        else
        {
                LOG_DEBUG("Received HTTP response data: %zu bytes", rsp->processed);
        }

        // Log successful response on completion
        if (final_data == HTTP_DATA_FINAL)
        {
                LOG_DEBUG("HTTP request completed successfully with status code: %d",
                          rsp->http_status_code);

                rsp_ptr->body_frag_start = rsp->body_frag_start;
                rsp_ptr->body_frag_len = rsp->body_frag_len;
                rsp_ptr->http_status_code = rsp->http_status_code;
                rsp_ptr->cl_present = rsp->cl_present;
                rsp_ptr->content_length = rsp->content_length;
                rsp_ptr->processed = rsp->processed;
                rsp_ptr->message_complete = rsp->message_complete;

                // Log the message completion status
                if (rsp->message_complete)
                {
                        LOG_DEBUG("HTTP message completely received");
                        rsp_ptr->message_complete = rsp->message_complete;
                }
                else
                {
                        LOG_WARN("HTTP message not completely received despite final data "
                                 "flag");
                }
        }
}
