
#ifndef CRYPTO_PARSER_H
#define CRYPTO_PARSER_H
#include <stdlib.h>
#include <sys/stat.h>
#include <inttypes.h>
#include "kritis3m_configuration.h"

#include "asl.h"
#include "utils.h"

typedef struct certificates
{
    char const *certificate_path;
    char const *private_key_path;
    char const *additional_key_path;
    char const *intermediate_path;
    char const *root_path;

    uint8_t *chain_buffer; /* Entity and intermediate certificates */
    size_t chain_buffer_size;

    uint8_t *key_buffer;
    size_t key_buffer_size;

    uint8_t *additional_key_buffer;
    size_t additional_key_buffer_size;

    uint8_t *root_buffer;
    size_t root_buffer_size;
} certificates;

static int readFile(const char *filePath, uint8_t **buffer, size_t bufferSize);

static void set_defaults(certificates *certs)
{
    /* Certificates */
    certs->certificate_path = NULL;
    certs->private_key_path = NULL;
    certs->additional_key_path = NULL;
    certs->intermediate_path = NULL;
    certs->root_path = NULL;
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

int certificates_to_endpoint(char *cryptopath, int cryptopath_len, crypto_identity *identity, asl_endpoint_configuration *endpointconfig);
int initialize_crypto_endpoint(char *cryptopath, int cryptopath_len, CryptoProfile *crypto_profile);
int crypto_to_endpoint(char *cryptopath, int cryptopath_len, CryptoProfile *profile);
int request_certificates(enum PkiRequestType request_type, const char *machine_crypto_path, const char *pki_path, crypto_identity *identity);

#endif // CRYPTO_PARSER_H