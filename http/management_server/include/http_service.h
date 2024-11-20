
#ifndef HTTP_SERIVCE_H
#define HTTP_SERIVCE_H

#include "kritis3m_configuration.h"

struct response
{
    enum used_service service_used;
    ManagementReturncode ret;
    uint8_t *buffer;
    uint8_t *buffer_frag_start; // start of body
    uint32_t buffer_size;
    uint32_t bytes_received;
    union response_meta
    {
        struct
        {
            network_identity identity;    // in case of pki
            const char *destination_path; // in case of pki
        } pki;
        struct
        {
            const char *destination_path; // path to store response
        } policy_req;
    } meta;
};

typedef int (*t_http_get_cb)(struct response response);

int call_distribution_service(t_http_get_cb response_callback, char *destination_path);
int init_http_service(Kritis3mManagemntConfiguration *config,
                      asl_endpoint_configuration *mgmt_endpoint_config
#ifdef PKI_READY
                      ,
                      asl_endpoint_configuration *pki_endpoint_config
#endif
);

#endif
