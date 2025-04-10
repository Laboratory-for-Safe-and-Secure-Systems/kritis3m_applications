#ifndef PKI_CLIENT_H_
#define PKI_CLIENT_H_

#include "asl.h"
#include <pthread.h>

// Public types and API
struct pki_client_config_t
{
        const asl_endpoint_configuration* endpoint_config;
        const char* serialnumber;
        const char* host;
        const int16_t port;
};

enum CERT_TYPE
{
        CERT_TYPE_DATAPLANE,
        CERT_TYPE_CONTROLPLANE,
};

typedef int (*pki_callback_t)(char* buffer, size_t size);

// Public API functions
int cert_request(struct pki_client_config_t* config,
                 enum CERT_TYPE cert_type,
                 bool include_ca_certs,
                 pki_callback_t callback);

int get_blocking_cert(struct pki_client_config_t* config,
                      enum CERT_TYPE cert_type,
                      bool include_ca_certs,
                      char** response_buffer,
                      size_t* response_buffer_size);

// Internal types
typedef struct
{
        struct pki_client_config_t* config;
        enum CERT_TYPE cert_type;
        bool include_ca_certs;
        pki_callback_t callback;
        bool is_blocking;
        char** response_buffer;
        size_t* response_buffer_size;
        bool completed;
        bool cleanup_requested;
        pthread_mutex_t mutex;
        pthread_t thread_id;
        uint8_t* cert_buffer;
        size_t cert_buffer_size;
        size_t cert_size;
        bool has_ca_chain;
        uint8_t* ca_chain_buffer;
        size_t ca_chain_buffer_size;
        size_t ca_chain_size;
        bool message_complete; // Flag to track if HTTP message is complete
} pki_request_context_t;

#endif /* PKI_CLIENT_H_ */