#ifndef _PKI_CLIENT_H_
#define _PKI_CLIENT_H_
#include "asl.h"
#include <pthread.h>

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
#define MAX_KEY_SIZE 32*1024
#define MAX_CHAIN_SIZE (4*MAX_KEY_SIZE)



struct est_configuration{
        const char* algorithm; //if specified, keys are generated
        const char* alt_algoithm; //if specified, keys are generated
        
       char key[MAX_KEY_SIZE];
       size_t key_buffer_size;
       size_t key_size;

       char alt_key[MAX_KEY_SIZE];
       size_t alt_key_buffer_size;
       size_t alt_key_size;

       char chain[MAX_CHAIN_SIZE]; 
       size_t chain_buffer_size;
       size_t chain_size;
};
void pki_client_log_level_set(int log_level);

void init_est_configuration(struct est_configuration* est_config,const char* algo, const char* alt_algo);

int blocking_est_request(struct pki_client_config_t* config,
                      enum CERT_TYPE cert_type,
                      bool include_ca_certs,
                      struct est_configuration* est_config);


#endif /* PKI_CLIENT_H_ */