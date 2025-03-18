
#ifndef PKI_CLIENT_H_
#define PKI_CLIENT_H_

#include "asl.h"
#include "ipc.h"
#include "kritis3m_configuration.h"

struct pki_client_config_t
{
        asl_endpoint_configuration* endpoint_config;
        char* serialnumber;
        char* host;
        char* port;
};

int start_pki_client(struct pki_client_config_t* config);
void cleanup_pki_client();

enum MSG_RESPONSE_CODE stop_pki_client();
enum MSG_RESPONSE_CODE dataplane_cert_request();
enum MSG_RESPONSE_CODE controlplane_cert_request();

enum MSG_RESPONSE_CODE dataplane_enroll_request();
enum MSG_RESPONSE_CODE controlplane_enroll_request();

#endif /* PKI_CLIENT_H_ */