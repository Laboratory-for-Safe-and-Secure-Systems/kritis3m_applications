#ifndef PKI_CLIENT_H_
#define PKI_CLIENT_H_

#include "asl.h"

struct pki_client_config_t
{
        asl_endpoint_configuration* endpoint_config;
        char* serialnumber;
        char* host;
        int16_t port;
};
enum CERT_TYPE
{
        CERT_TYPE_DATAPLANE,
        CERT_TYPE_CONTROLPLANE,
};
// define callback function
typedef int (*pki_callback_t)(char* buffer, size_t size);

int cert_request(struct pki_client_config_t* config,
                 enum CERT_TYPE cert_type,
                 bool include_ca_certs,
                 pki_callback_t callback);

// New function to fetch the certificate chain
int fetch_ca_cert_chain(struct pki_client_config_t* config, pki_callback_t callback);

#endif /* PKI_CLIENT_H_ */