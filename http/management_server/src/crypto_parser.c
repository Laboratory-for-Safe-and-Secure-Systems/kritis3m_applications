
#include "crypto_parser.h"
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include "logging.h"

LOG_MODULE_CREATE(crypto_parser);

int read_certificates(crypto_identity *identity)
{
    int ret = 0;
    char filepath[MAX_FILEPATH_SIZE];
    if (identity == NULL)
        return -1;

    // Read root certificate
    ret = create_file_path(filepath, MAX_FILEPATH_SIZE, identity->filepath, identity->filepath_size, "cert.pem", sizeof("cert.pem"));
    if ((ret >=0) &&read_file(filepath, &identity->certificates.root_buffer, (int *)&identity->certificates.root_buffer_size) != 0)
    {
        return -1;
    }

    // Read private key
    snprintf(filepath, sizeof(filepath), "%s/privateKey.pem", identity->filepath);
    if (read_file(filepath, &identity->certificates.key_buffer, (int *)&identity->certificates.key_buffer_size) != 0)
    {
        free(identity->certificates.root_buffer);
        return -1;
    }

    // Read certificate chain
    snprintf(filepath, sizeof(filepath), "%s/chain.pem", identity->filepath);
    if (read_file(filepath, &identity->certificates.chain_buffer, (int *)&identity->certificates.chain_buffer_size) != 0)
    {
        free(identity->certificates.root_buffer);
        free(identity->certificates.key_buffer);
        return -1;
    }
    // Read certificate chain
    snprintf(filepath, sizeof(filepath), "%s/additional_key.pem", identity->filepath);
    if (read_file(filepath, &identity->certificates.additional_key_buffer, (int *)&identity->certificates.additional_key_buffer_size) != 0)
    {
        LOG_INFO("no additional key");
    }
    return 0;
}

int create_endpoint_config(crypto_identity *crypto_id, CryptoProfile *crypto_profile, asl_endpoint_configuration *ep_cfg)
{

    int ret = 0;
    if ((crypto_id == NULL) || (crypto_profile == NULL) || (ep_cfg == NULL))
        goto error_occured;

    if (!crypto_id->certificates_available)
    {

        ret = read_certificates(crypto_id);
        if (ret < 0)
            goto error_occured;
        crypto_id->certificates_available = true;
    }

    ep_cfg->hybrid_signature_mode = crypto_profile->HybridSignatureMode;
    ep_cfg->key_exchange_method = crypto_profile->ASLKeyExchangeMethod;
    ep_cfg->keylog_file = "/home/philipp/kritis/linux_development/kritis3m_workspace/repositories/kritis3m_tls_linux/keylog.txt";
    ep_cfg->mutual_authentication = crypto_profile->MutualAuthentication;
    ep_cfg->no_encryption = crypto_profile->NoEncryption;

    ep_cfg->device_certificate_chain.buffer = crypto_id->certificates.chain_buffer;
    ep_cfg->device_certificate_chain.size = crypto_id->certificates.chain_buffer_size;

    ep_cfg->root_certificate.buffer = crypto_id->certificates.root_buffer;
    ep_cfg->root_certificate.size = crypto_id->certificates.root_buffer_size;

    ep_cfg->private_key.buffer = crypto_id->certificates.key_buffer;
    ep_cfg->private_key.size = crypto_id->certificates.key_buffer_size;

    ep_cfg->private_key.additional_key_buffer = crypto_id->certificates.additional_key_buffer;
    ep_cfg->private_key.additional_key_size = crypto_id->certificates.additional_key_buffer_size;
    ep_cfg->private_key.size = crypto_id->certificates.key_buffer_size;


    return ret;

error_occured:
    if (ret > 0)
        ret = -1;
    LOG_ERROR("can't create asl_endpoint_configuration");

    return ret;
}