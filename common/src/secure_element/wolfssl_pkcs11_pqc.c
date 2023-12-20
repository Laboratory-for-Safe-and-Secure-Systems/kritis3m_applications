
#include "secure_element/wolfssl_pkcs11_pqc.h"
#include "secure_element/secure_element.h"

#include "logging.h"

LOG_MODULE_REGISTER(wolfssl_pkcs11);


#define DEVICE_ID_SECURE_ELEMENT 1

static char secure_element_private_key_id[] = "SERVER_KEY";
static size_t secure_element_private_key_id_size = sizeof("SERVER_KEY") - 1;

static char secure_element_temp_key_kem_id[] = "TEMP_KEY_KEM";
static size_t secure_element_temp_key_kem_id_size = sizeof("TEMP_KEY_KEM") - 1;

static char secure_element_temp_key_sig_id[] = "TEMP_KEY_SIG";
static size_t secure_element_temp_key_sig_id_size = sizeof("TEMP_KEY_SIG") - 1;


/* Internal method declarations */
static int wolfssl_crypto_callback_secure_element(int devId, wc_CryptoInfo* info, void* ctx);
static int wolfssl_extract_dilithium_keys(int key_format, uint8_t const* der_buffer, uint32_t der_size,
				          uint8_t** private_key_buffer, uint32_t* private_key_size,
				          uint8_t** public_key_buffer, uint32_t* public_key_size);
static int wolfssl_extract_falcon_keys(int key_format, uint8_t const* der_buffer, uint32_t der_size,
				       uint8_t** private_key_buffer, uint32_t* private_key_size,
				       uint8_t** public_key_buffer, uint32_t* public_key_size);

static int wolfssl_pkcs11_kyber_keygen(KyberKey* key, uint32_t keySize);
static int wolfssl_pkcs11_kyber_encapsulate(KyberKey* key, uint8_t* ciphertext, uint32_t ciphertextLen,
    					    uint8_t* sharedSecret, uint32_t sharedSecretLen);
static int wolfssl_pkcs11_kyber_decapsulate(KyberKey* key, uint8_t const* ciphertext, uint32_t ciphertextLen,
    					    uint8_t* sharedSecret, uint32_t sharedSecretLen);

static int wolfssl_pkcs11_dilithium_sign(dilithium_key* key, uint8_t const* message, uint32_t message_size,
                                         uint8_t* signature, uint32_t* signature_size);
static int wolfssl_pkcs11_falcon_sign(falcon_key* key, uint8_t const* message, uint32_t message_size,
                                      uint8_t* signature, uint32_t* signature_size);

static int wolfssl_pkcs11_dilithium_verify(dilithium_key* key, uint8_t const* message, uint32_t message_size,
                                           uint8_t const* signature, uint32_t signature_size);
static int wolfssl_pkcs11_falcon_verify(falcon_key* key, uint8_t const* message, uint32_t message_size,
                                        uint8_t const* signature, uint32_t signature_size);

static int wolfssl_pkcs11_dilithium_check_key(dilithium_key* key, uint8_t const* public_key, uint32_t public_key_size);
static int wolfssl_pkcs11_falcon_check_key(falcon_key* key, uint8_t const* public_key, uint32_t public_key_size);



/* Get the id of the static private key */
uint8_t const* wolfssl_get_secure_element_private_key_id(void)
{
        return (uint8_t const*) secure_element_private_key_id;
}


/* Get the size of the id of the static private key */
uint32_t wolfssl_get_secure_element_private_key_id_size(void)
{
        return secure_element_private_key_id_size;
}


/* Get the device id of the secure element */
int wolfssl_get_secure_element_device_id(void)
{
        return DEVICE_ID_SECURE_ELEMENT;
}


/* Import the public/private key pair in the given PEM file into the secure element.
 *
 * Returns 0 on success, -1 in case of an error (error message is logged to the console).
 */
int wolfssl_import_key_pair_into_secure_element(uint8_t const* pem_buffer, uint32_t pem_size)
{
        DerBuffer* der = NULL;
	EncryptedInfo info;
	int  keyFormat = 0;

	/* Delete all currently stored objects on the card */
	int ret = pkcs11_destroy_objects(secure_element_private_key_id, secure_element_private_key_id_size);

	/* Convert key to DER (binary) */
	ret = PemToDer(pem_buffer, pem_size, PRIVATEKEY_TYPE, &der, NULL,
			   &info, &keyFormat);
	if (ret < 0)
	{
		FreeDer(&der);
		LOG_ERR("Error converting private key to DER");
		return -1;
	}

	uint8_t* raw_private_key_buffer = NULL;
	uint32_t raw_private_key_size = 0;
	uint8_t* raw_public_key_buffer = NULL;
	uint32_t raw_public_key_size = 0;

	/* Check which key type we have */
	if ((keyFormat == FALCON_LEVEL1k) || (keyFormat == FALCON_LEVEL5k)) 
	{
		/* Extract the raw public and private keys */
		ret = wolfssl_extract_falcon_keys(keyFormat, der->buffer, der->length,
						  &raw_private_key_buffer, &raw_private_key_size,
						  &raw_public_key_buffer, &raw_public_key_size);
	}
    	else if ((keyFormat == DILITHIUM_LEVEL2k) || (keyFormat == DILITHIUM_LEVEL3k) ||
        	 (keyFormat == DILITHIUM_LEVEL5k)) 
	{
		/* Extract the raw public and private keys */
		ret = wolfssl_extract_dilithium_keys(keyFormat, der->buffer, der->length,
						     &raw_private_key_buffer, &raw_private_key_size,
						     &raw_public_key_buffer, &raw_public_key_size);
        }

	if (ret == 0)
	{
		/* Import private key into secure element */
		ret = pkcs11_create_object_private_key_dilithium2(secure_element_private_key_id,
								  secure_element_private_key_id_size,
								  raw_private_key_buffer,
								  raw_private_key_size);
		if (ret != CKR_OK)
		{
			LOG_ERR("Error importing private key into secure element: %d", ret);
		}
		else
		{
			/* Import public key into secure element */
			ret = pkcs11_create_object_public_key_dilithium2(secure_element_private_key_id,
										secure_element_private_key_id_size,
										raw_public_key_buffer,
										raw_public_key_size);
			if (ret != CKR_OK)
			{
				LOG_ERR("Error importing private key into secure element: %d", ret);
			}
		}
	}

	if (raw_private_key_buffer != NULL)
	{
		free(raw_private_key_buffer);
	}
	if (raw_public_key_buffer != NULL)
	{
		free(raw_public_key_buffer);
	}

	return ret;
}


/* Extract public and private keys from the provided DER buffer. The dilithium level is encoded
 * in the key_format parameter. private_key_buffer and public_key_buffer are allocated with an
 * appropriately sized buffer and must be freed by the caller. 
 * 
 * Returns 0 on success, -1 in case of an error (error message is logged to the console).
 */
int wolfssl_extract_dilithium_keys(int key_format, uint8_t const* der_buffer, uint32_t der_size,
				   uint8_t** private_key_buffer, uint32_t* private_key_size,
				   uint8_t** public_key_buffer, uint32_t* public_key_size)
{
       /* Allocate new key */
	dilithium_key* key = (dilithium_key* ) malloc(sizeof(dilithium_key));
	if (key == NULL) 
	{
		LOG_ERR("Error allocating temporary private key");
		return -1;
	}

	wc_dilithium_init(key);

	/* Set level and allocate memory for raw key */
	if (key_format == DILITHIUM_LEVEL2k) 
	{
		wc_dilithium_set_level(key, 2);

		*private_key_buffer = (uint8_t* ) malloc(DILITHIUM_LEVEL2_KEY_SIZE);
		*private_key_size = DILITHIUM_LEVEL2_KEY_SIZE;

		*public_key_buffer = (uint8_t* ) malloc(DILITHIUM_LEVEL2_PUB_KEY_SIZE);
		*public_key_size = DILITHIUM_LEVEL2_PUB_KEY_SIZE;
	}
	else if (key_format == DILITHIUM_LEVEL3k) 
	{
		wc_dilithium_set_level(key, 3);

		*private_key_buffer = (uint8_t* ) malloc(DILITHIUM_LEVEL3_KEY_SIZE);
		*private_key_size = DILITHIUM_LEVEL3_KEY_SIZE;

		*public_key_buffer = (uint8_t* ) malloc(DILITHIUM_LEVEL3_PUB_KEY_SIZE);
		*public_key_size = DILITHIUM_LEVEL3_PUB_KEY_SIZE;
	}
	else if (key_format == DILITHIUM_LEVEL5k)
	{
		wc_dilithium_set_level(key, 5);

		*private_key_buffer = (uint8_t* ) malloc(DILITHIUM_LEVEL5_KEY_SIZE);
		*private_key_size = DILITHIUM_LEVEL5_KEY_SIZE;

		*public_key_buffer = (uint8_t* ) malloc(DILITHIUM_LEVEL5_PUB_KEY_SIZE);
		*public_key_size = DILITHIUM_LEVEL5_PUB_KEY_SIZE;
	}

	if ((*private_key_buffer == NULL) || (*public_key_buffer == NULL))
	{
		LOG_ERR("Error allocating temporary key buffers");
		wc_dilithium_free(key);
		free(key);
		return -1;
	}
	
	/* Import the actual private key from the DER buffer */
	int ret = wc_dilithium_import_private_key(der_buffer, der_size, NULL, 0, key);
	if (ret != 0) 
	{
		LOG_ERR("Error parsing the DER key: %d", ret);
		wc_dilithium_free(key);
		free(key);
		return -1;
	}

	/* Write the raw keys to the buffers */
	memcpy(*private_key_buffer, key->k, *private_key_size);
	memcpy(*public_key_buffer, key->p, *public_key_size);

	wc_dilithium_free(key);
	free(key);

	return 0;
}


/* Extract public and private keys from the provided DER buffer. The falcon level is encoded
 * in the key_format parameter. private_key_buffer and public_key_buffer are allocated with an
 * appropriately sized buffer and must be freed by the caller.
 * 
 * Returns 0 on success, -1 in case of an error (error message is logged to the console).
 */
int wolfssl_extract_falcon_keys(int key_format, uint8_t const* der_buffer, uint32_t der_size,
				uint8_t** private_key_buffer, uint32_t* private_key_size,
				uint8_t** public_key_buffer, uint32_t* public_key_size)
{
        /* Allocate new key */
	falcon_key* key = (falcon_key* ) malloc(sizeof(falcon_key));
	if (key == NULL) 
	{
		LOG_ERR("Error allocating temporary private key");
		return -1;
	}

	wc_falcon_init(key);

	/* Set level and allocate memory for raw key */
	if (key_format == FALCON_LEVEL1k) 
	{
		wc_falcon_set_level(key, 1);

		*private_key_buffer = (uint8_t* ) malloc(FALCON_LEVEL1_KEY_SIZE);
		*private_key_size = FALCON_LEVEL1_KEY_SIZE;

		*public_key_buffer = (uint8_t* ) malloc(FALCON_LEVEL1_PUB_KEY_SIZE);
		*public_key_size = FALCON_LEVEL1_PUB_KEY_SIZE;
	}
	else if (key_format == FALCON_LEVEL5k) 
	{
		wc_falcon_set_level(key, 5);

		*private_key_buffer = (uint8_t* ) malloc(FALCON_LEVEL5_KEY_SIZE);
		*private_key_size = FALCON_LEVEL5_KEY_SIZE;

		*public_key_buffer = (uint8_t* ) malloc(FALCON_LEVEL5_PUB_KEY_SIZE);
		*public_key_size = FALCON_LEVEL5_PUB_KEY_SIZE;
	}
	
	if ((*private_key_buffer == NULL) || (*public_key_buffer == NULL))
	{
		LOG_ERR("Error allocating temporary key buffers");
		wc_falcon_free(key);
		free(key);
		return -1;
	}
	
	/* Import the actual private key from the DER buffer */
	int ret = wc_falcon_import_private_key(der_buffer, der_size, NULL, 0, key);
	if (ret != 0) 
	{
		LOG_ERR("Error parsing the DER key: %d", ret);
		wc_falcon_free(key);
		free(key);
		return -1;
	}

	/* Write the raw keys to the buffers */
	memcpy(*private_key_buffer, key->k, *private_key_size);
	memcpy(*public_key_buffer, key->p, *public_key_size);

	wc_falcon_free(key);
	free(key);

	return 0;
}


/* Install the central callback for post-quantum operations using the secure element.
 * The argument is an optional ctx pointer parameter that is forwarded to the callback.
 * Set to NULL if not needed.
 * 
 * Returns 0 on success, -1 in case of an error (error message is logged to the console).
 */
int wolfssl_install_crypto_callback_secure_element(void* ctx)
{
        int ret = wc_CryptoCb_RegisterDevice(wolfssl_get_secure_element_device_id(),
					     wolfssl_crypto_callback_secure_element,
					     ctx);
	if (ret != 0)
	{
		LOG_ERR("error: unable to register crypto callback, error %d", ret);
		return -1;
	}

        return 0;
}


static int wolfssl_crypto_callback_secure_element(int devId, wc_CryptoInfo* info, void* ctx)
{
	if (devId != DEVICE_ID_SECURE_ELEMENT)
		return CRYPTOCB_UNAVAILABLE;
	
	int ret = CRYPTOCB_UNAVAILABLE;

	if (info->algo_type == WC_ALGO_TYPE_PK)
	{
		switch (info->pk.type)
		{
		case WC_PK_TYPE_KYBER_KEYGEN:
			ret = wolfssl_pkcs11_kyber_keygen(info->pk.kyber_kg.key,
							  info->pk.kyber_kg.size);
			break;
		case WC_PK_TYPE_KYBER_ENCAPS:
			ret = wolfssl_pkcs11_kyber_encapsulate(info->pk.kyber_encaps.key,
							       info->pk.kyber_encaps.ciphertext,
							       info->pk.kyber_encaps.ciphertextLen,
							       info->pk.kyber_encaps.sharedSecret,
							       info->pk.kyber_encaps.sharedSecretLen);
			break;
		case WC_PK_TYPE_KYBER_DECAPS:
			ret = wolfssl_pkcs11_kyber_decapsulate(info->pk.kyber_decaps.key,
							       info->pk.kyber_decaps.ciphertext,
							       info->pk.kyber_decaps.ciphertextLen,
							       info->pk.kyber_decaps.sharedSecret,
							       info->pk.kyber_decaps.sharedSecretLen);
			break;
		case WC_PK_TYPE_DILITHIUM_KEYGEN:
			/* ToDo */
			break;
		case WC_PK_TYPE_DILITHIUM_SIGN:
			ret = wolfssl_pkcs11_dilithium_sign(info->pk.dilithium_sign.key,
							     info->pk.dilithium_sign.in,
							     info->pk.dilithium_sign.inlen,
							     info->pk.dilithium_sign.out,
							     info->pk.dilithium_sign.outlen);
			break;
		case WC_PK_TYPE_DILITHIUM_VERIFY:
			ret = wolfssl_pkcs11_dilithium_verify(info->pk.dilithium_verify.key,
							      info->pk.dilithium_verify.msg,
							      info->pk.dilithium_verify.msglen,
							      info->pk.dilithium_verify.sig,
							      info->pk.dilithium_verify.siglen);
			if (ret == 0)
				*(info->pk.dilithium_verify.res) = 1;
			break;
		case WC_PK_TYPE_DILITHIUM_CHECK_PRIV_KEY:
			ret = wolfssl_pkcs11_dilithium_check_key(info->pk.dilithium_check.key,
								 info->pk.dilithium_check.pubKey,
								 info->pk.dilithium_check.pubKeySz);
			break;
		case WC_PK_TYPE_FALCON_KEYGEN:
			/* ToDo */
			break;
		case WC_PK_TYPE_FALCON_SIGN:
			ret = wolfssl_pkcs11_falcon_sign(info->pk.falcon_sign.key,
							 info->pk.falcon_sign.in,
							 info->pk.falcon_sign.inlen,
							 info->pk.falcon_sign.out,
							 info->pk.falcon_sign.outlen);
			break;
		case WC_PK_TYPE_FALCON_VERIFY:
			ret = wolfssl_pkcs11_falcon_verify(info->pk.falcon_verify.key,
							   info->pk.falcon_verify.msg,
							   info->pk.falcon_verify.msglen,
							   info->pk.falcon_verify.sig,
							   info->pk.falcon_verify.siglen);
			if (ret == 0)
				*(info->pk.falcon_verify.res) = 1;
			break;
		case WC_PK_TYPE_FALCON_CHECK_PRIV_KEY:
			ret = wolfssl_pkcs11_falcon_check_key(info->pk.falcon_check.key,
							      info->pk.falcon_check.pubKey,
							      info->pk.falcon_check.pubKeySz);
			break;
		default:
			break;
		}
	}

	return ret;
}


int wolfssl_pkcs11_kyber_keygen(KyberKey* key, uint32_t keySize)
{
	int ret = CRYPTOCB_UNAVAILABLE;

	/* Check which key type we have to generate */
	if (key->type == KYBER768)
	{
		/* Delete any exisiting (old) objects */
		pkcs11_destroy_objects(secure_element_temp_key_sig_id, secure_element_temp_key_sig_id_size);

		/* Generate the key */
		ret = pkcs11_generate_key_pair_kyber768(secure_element_temp_key_sig_id,
                                                        secure_element_temp_key_sig_id_size);

		if (ret != CKR_OK) 
		{
			ret = WC_HW_E;
		}
		else
		{
			/* Read public key */
			unsigned long external_public_key_size = EXT_KYBER_MAX_PUB_SZ;
			ret = pkcs11_read_public_key(secure_element_temp_key_sig_id,
						     secure_element_temp_key_sig_id_size,
						     key->pub,
						     &external_public_key_size);

			if ((ret != CKR_OK) || (external_public_key_size != KYBER768_PUBLIC_KEY_SIZE))
			{
				ret = WC_HW_E;
			}
			else
			{
				/* We store the id of the generated key in the private key buffer */
				memcpy(key->priv, secure_element_temp_key_sig_id, secure_element_temp_key_sig_id_size);
			}
		}
	}

	return ret;
}

int wolfssl_pkcs11_kyber_encapsulate(KyberKey* key, uint8_t* ciphertext, uint32_t ciphertextLen,
				     uint8_t* sharedSecret, uint32_t sharedSecretLen)
{
	int ret = CRYPTOCB_UNAVAILABLE;

	/* Helper variables as the pkcs11 lib wants 64 bit integers here */
        unsigned long shared_secret_size_tmp = sharedSecretLen;
	unsigned long ciphertext_size_tmp = ciphertextLen;

	if (key->type == KYBER768)
	{
		ret = pkcs11_encapsulate_kyber768_with_external_public_key(key->pub,
									   KYBER768_PUBLIC_KEY_SIZE,
									   ciphertext,
									   &ciphertext_size_tmp,
									   sharedSecret,
									   &shared_secret_size_tmp);

		if ((ret != CKR_OK) || (shared_secret_size_tmp != sharedSecretLen) ||
		    (ciphertext_size_tmp != ciphertextLen))
		{
			ret = WC_HW_E;
		}
	}

	return ret;
}

int wolfssl_pkcs11_kyber_decapsulate(KyberKey* key, uint8_t const* ciphertext, uint32_t ciphertextLen,
				     uint8_t* sharedSecret, uint32_t sharedSecretLen)
{
	int ret = CRYPTOCB_UNAVAILABLE;

	/* Helper variable as the pkcs11 lib wants a 64 bit integer here */
        unsigned long shared_secret_size_tmp = sharedSecretLen;

	if (key->type == KYBER768)
	{
		ret = pkcs11_decapsulate_kyber768(key->priv,
						  secure_element_temp_key_sig_id_size,
						  (CK_BYTE*) ciphertext,
						  ciphertextLen,
						  sharedSecret,
						  &shared_secret_size_tmp);

		if ((ret != CKR_OK) || (shared_secret_size_tmp != sharedSecretLen))
		{
			ret = WC_HW_E;
		}
	}

	return ret;
}


/* Sign given message with the provided external dilithium key and store the signature in given buffer.
 *
 * Returns 0 on success and a negative error code in case of an error
 */
int wolfssl_pkcs11_dilithium_sign(dilithium_key* key, uint8_t const* message, uint32_t message_size,
                                  uint8_t* signature, uint32_t* signature_size)
{
        /* Helper variable as the pkcs11 lib wants a 64 bit integer here */
        unsigned long signature_size_tmp = 0;

        /* Create the signature */
        int ret = pkcs11_sign_dilithium2(key->id,
                                        key->idLen,
                                        (CK_BYTE*) message, message_size,
                                        signature, &signature_size_tmp);
        if (ret != CKR_OK) 
        {
                ret = WC_HW_E;
        }

        *signature_size = signature_size_tmp;

        return ret;
}


/* Sign given message with the provided external falcon key and store the signature in given buffer.
 *
 * Returns 0 on success and a negative error code in case of an error
 */
int wolfssl_pkcs11_falcon_sign(falcon_key* key, uint8_t const* message, uint32_t message_size,
                        uint8_t* signature, uint32_t* signature_size)
{
        return CRYPTOCB_UNAVAILABLE; // Temporary workaround until the secure element supports Falcon
}


/* Verify given signature for given message with the provided external dilithium key.
 * 
 * Returns 0 on success and a negative error code in case of an error
 */
int wolfssl_pkcs11_dilithium_verify(dilithium_key* key, uint8_t const* message, uint32_t message_size,
                                    uint8_t const* signature, uint32_t signature_size)
{
        int ret = 0;
        unsigned long external_public_key_size = 0;
        
        if (key->level == 2)
        {
                external_public_key_size = DILITHIUM_LEVEL2_PUB_KEY_SIZE;
        }
        else if (key->level == 3)
        {
                external_public_key_size = DILITHIUM_LEVEL3_PUB_KEY_SIZE;
                return CRYPTOCB_UNAVAILABLE; // Temporary workaround until the secure element supports Dilithium 3
        }
        else if (key->level == 5)
        {
                external_public_key_size = DILITHIUM_LEVEL5_PUB_KEY_SIZE;
                return CRYPTOCB_UNAVAILABLE; // Temporary workaround until the secure element supports Dilithium 5
        }
        else
        {
                return BAD_FUNC_ARG;
        }
                
        /* Import the provided public key into the secure element */
        ret = pkcs11_create_object_public_key_dilithium2(secure_element_temp_key_sig_id,
                                                         secure_element_temp_key_sig_id_size,
                                                         key->p,
                                                         external_public_key_size);
        if (ret != CKR_OK) 
        {
                ret = WC_HW_E;
        }
        else
        {
                /* Verify the signature */
                ret = pkcs11_verify_dilithium2(secure_element_temp_key_sig_id,
                                               secure_element_temp_key_sig_id_size,
                                               (CK_BYTE*) message,
                                               message_size,
                                               (CK_BYTE*) signature,
                                               signature_size);
                if (ret != CKR_OK) 
                {
                        ret = SIG_VERIFY_E;
                }

                pkcs11_destroy_objects(secure_element_temp_key_sig_id, secure_element_temp_key_sig_id_size);
        }
        
}


/* Verify given signature for given message with the provided external falcon key.
 * 
 * Returns 0 on success and a negative error code in case of an error
 */
int wolfssl_pkcs11_falcon_verify(falcon_key* key, uint8_t const* message, uint32_t message_size,
                                 uint8_t const* signature, uint32_t signature_size)
{
        return CRYPTOCB_UNAVAILABLE; // Temporary workaround until the secure element supports Falcon
}


/* Compare the given external dilithium key with the provided public key to check if they match.
 *
 * Returns 0 on success and a negative error code in case of an error.
 */
int wolfssl_pkcs11_dilithium_check_key(dilithium_key* key, uint8_t const* public_key, uint32_t public_key_size)
{
        unsigned long external_public_key_size = DILITHIUM_MAX_PUB_KEY_SIZE;
        uint8_t* external_public_key_buffer = malloc(DILITHIUM_MAX_PUB_KEY_SIZE);
        if (external_public_key_buffer == NULL)
        {
                return MEMORY_E;
        }

        /* Read the public key from the secure element */
        int ret = pkcs11_read_public_key(key->id,
                                         key->idLen,
                                         external_public_key_buffer,
                                         &external_public_key_size);
        if (ret != CKR_OK) 
        {
                ret = WC_HW_E;
        }

        /* Compare the read key from the secure element with the provided public key 
         * from the certificate */
        if (ret == 0)
        {
                if (external_public_key_size == public_key_size)
                {
                        ret = memcmp(external_public_key_buffer, public_key, public_key_size);

                        if (ret != 0)
                        {
                                ret = MP_CMP_E;
                        }
                }
                else
                {
                        ret = WC_KEY_SIZE_E;
                }
        }

        free(external_public_key_buffer);

        return ret;
}


/* Compare the given external falcon key with the provided public key to check if they match.
 *
 * Returns 0 on success and a negative error code in case of an error.
 */
int wolfssl_pkcs11_falcon_check_key(falcon_key* key, uint8_t const* public_key, uint32_t public_key_size)
{
        unsigned long external_public_key_size = FALCON_MAX_PUB_KEY_SIZE;
        uint8_t* external_public_key_buffer = malloc(FALCON_MAX_PUB_KEY_SIZE);
        if (external_public_key_buffer == NULL)
        {
                return MEMORY_E;
        }

        /* Read the public key from the secure element */
        int ret = pkcs11_read_public_key(key->id,
                                         key->idLen,
                                         external_public_key_buffer,
                                         &external_public_key_size);
        if (ret != CKR_OK) 
        {
                ret = WC_HW_E;
        }

        /* Compare the read key from the secure element with the provided public key 
         * from the certificate */
        if (ret == 0)
        {
                if (external_public_key_size == public_key_size)
                {
                        ret = memcmp(external_public_key_buffer, public_key, public_key_size);

                        if (ret != 0)
                        {
                                ret = MP_CMP_E;
                        }
                }
                else
                {
                        ret = WC_KEY_SIZE_E;
                }
        }

        free(external_public_key_buffer);

        return ret;
}
