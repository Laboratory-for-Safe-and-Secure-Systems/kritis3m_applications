
#ifndef HTTP_SERIVCE_H
#define HTTP_SERIVCE_H

#include "kritis3m_configuration.h"

// enum {
//     INITIAL_CALL_DISTRIBUTION_SERVER,
//     UPDATE_CALL_DISTRIBUTION_SERVER,

// }services;

struct response
{
    ManagementReturncode ret;
    int http_status_code;

    enum used_service service_used;
    uint8_t *buffer;
    uint8_t *buffer_frag_start; // start of body
    uint32_t buffer_size;
    uint32_t bytes_received;
};

typedef int (*t_http_get_cb)(struct response response);

//http put
//payload as json
int initial_call_controller(t_http_get_cb response_callback);
//http_get
int send_statusto_server(t_http_get_cb response_callback, int version_number, int cfg_id ,char* payload, int payload_size);

int init_http_service(Kritis3mManagemntConfiguration *config,
                      asl_endpoint_configuration *mgmt_endpoint_config
#ifdef PKI_READY
                      ,
                      asl_endpoint_configuration *pki_endpoint_config
#endif
);
void cleanup_http_service(void);

#endif
