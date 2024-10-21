
#ifndef CRYPTO_PARSER_H
#define CRYPTO_PARSER_H
#include <stdlib.h>
#include <sys/stat.h>
#include <inttypes.h>
#include "kritis3m_configuration.h"

#include "asl.h"
#include "utils.h"


static int readFile(const char *filePath, uint8_t **buffer, size_t bufferSize);

static void set_defaults(certificates *certs)
{
    /* Certificates */
    certs->chain_buffer = NULL;
    certs->chain_buffer_size = 0;
    certs->key_buffer = NULL;
    certs->key_buffer_size = 0;
    certs->additional_key_buffer = NULL;
    certs->additional_key_buffer_size = 0;
    certs->root_buffer = NULL;
    certs->root_buffer_size = 0;
}

// initially
// reenroll
enum PkiRequestType
{
    InitialRequest,
    Reenroll
};

int read_certificates(crypto_identity*identity);
int create_endpoint_config(crypto_identity *crypto_id, CryptoProfile *crypto_profile, asl_endpoint_configuration *ep_cfg);

#endif // CRYPTO_PARSER_H