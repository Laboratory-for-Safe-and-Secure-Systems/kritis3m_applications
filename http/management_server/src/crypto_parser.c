
#include "crypto_parser.h"
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include "logging.h"

LOG_MODULE_CREATE(crypto_parser);

int request_certificates(enum PkiRequestType request_type, const char *machine_crypto_path, const char *pki_path, crypto_identity *identity)
{
    int ret = 0;
    switch (request_type)
    {
    case InitialRequest:
        LOG_INFO("pki request will be implemented with cmd tool, but is not available at the moment");
        // check if folder path exists
        struct stat sb;
        if (stat(machine_crypto_path, &sb) != 0 || !S_ISDIR(sb.st_mode))
        {
            LOG_ERROR("machine folder path does not exist, errno: %d", errno);
            goto error_occured;
        }
        char private_key_path[512];
        char ca_cert_path[512];

        snprintf(private_key_path, sizeof(private_key_path), "%s/privateKey.pem", machine_crypto_path);
        snprintf(ca_cert_path, sizeof(ca_cert_path), "%s/ca_cert.pem", machine_crypto_path);
        LOG_INFO("NOT_IMPLEMENTED, but pki: %s will url: %s be called with private key and ca_cert", identity->identity, identity->pki_base_url);
        break;
    case Reenroll:

        LOG_INFO("pki reenroll will be implemented with cmd tool, but is not available at the moment");
        return 0;
        break;
    default:
        LOG_ERROR("wrong requesttype provided");
        return -1;
        break;
    }

error_occured:
    ret = -1;
}

int initialize_crypto_endpoint(char *cryptopath, int cryptopath_len, CryptoProfile *crypto_profile)
{
    asl_endpoint_configuration *ep_cfg = &crypto_profile->endpoint_cfg;

    ep_cfg->hybrid_signature_mode = crypto_profile->HybridSignatureMode;
    ep_cfg->key_exchange_method = crypto_profile->ASLKeyExchangeMethod;
    ep_cfg->mutual_authentication = crypto_profile->MutualAuthentication;
    ep_cfg->no_encryption = crypto_profile->NoEncryption;
    if (crypto_profile->Keylog)
        ep_cfg->keylog_file = NULL;

    int ret = certificates_to_endpoint(cryptopath, cryptopath_len, &crypto_profile->Identity, &crypto_profile->endpoint_cfg);
    return ret;
}

int certificates_to_endpoint(char *cryptopath, int cryptopath_len,
                             crypto_identity *identity,
                             asl_endpoint_configuration *endpointconfig)
{
    int ret = 0;
    char private_key_path[600];
    char cert_chain_path[600];
    char root_cert_path[600];

    char *private_key_buffer = NULL;
    int private_key_buffer_size = 0;
    char *certificate_chain_buffer = NULL;
    int certificate_chain_buffer_size = 0;
    char *root_certificate_buffer = NULL;
    int root_certificate_buffer_size = 0;
    // Check if folder exists

    char *privateKey = "privateKey.pem";
    char *chain = "chain.pem";
    char *cert = "cert.pem";

    ret = create_file_path(private_key_path, sizeof(private_key_path), cryptopath, cryptopath_len, privateKey, sizeof(privateKey));
    if (ret < 0)
        goto error_occured;
    ret = create_file_path(cert_chain_path, sizeof(cert_chain_path), cryptopath, cryptopath_len, chain, sizeof(chain));
    if (ret < 0)
        goto error_occured;
    ret = create_file_path(root_cert_path, sizeof(root_cert_path), cryptopath, cryptopath_len, cert, sizeof(cert));
    if (ret < 0)
        goto error_occured;

    if (access(private_key_path, F_OK) != 0)
        goto error_occured;
    if (access(cert_chain_path, F_OK) != 0)
        goto error_occured;
    if (access(root_cert_path, F_OK) != 0)
        goto error_occured;

    ret = read_file(private_key_path, &private_key_buffer, &private_key_buffer_size);
    if (ret < 0)
        goto error_occured;
    ret = read_file(cert_chain_path, &certificate_chain_buffer, &certificate_chain_buffer_size);
    if (ret < 0)
        goto error_occured;
    ret = read_file(root_cert_path, &root_certificate_buffer, &root_certificate_buffer_size);
    if (ret < 0)
        goto error_occured;

    endpointconfig->device_certificate_chain.buffer = certificate_chain_buffer;
    endpointconfig->device_certificate_chain.size = certificate_chain_buffer_size;

    endpointconfig->private_key.buffer = private_key_buffer;
    endpointconfig->private_key.size = private_key_buffer_size;

    endpointconfig->root_certificate.buffer = root_certificate_buffer;
    endpointconfig->root_certificate.size = root_certificate_buffer_size;

    return ret;
error_occured:
    ret = -1;
    free(certificate_chain_buffer);
    free(private_key_buffer);
    free(certificate_chain_buffer);
    return ret;
}
