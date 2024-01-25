
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

/* KEMs */
static int pkcs11_pqc_kem_keygen(void* key, int type, uint32_t keySize);
static int pkcs11_pqc_kem_encapsulate(void* key, int type, uint8_t* ciphertext, uint32_t ciphertextLen,
    				      uint8_t* sharedSecret, uint32_t sharedSecretLen);
static int pkcs11_pqc_kem_decapsulate(void* key, int type, uint8_t const* ciphertext, uint32_t ciphertextLen,
    				      uint8_t* sharedSecret, uint32_t sharedSecretLen);


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



/* Fill a new dilithium key with data from the provided DER buffer. The dilithium level is
 * encoded in the key_format parameter. The memory for the key is allocated by this method
 * and must be freed by the caller.
 * 
 * Returns a pointer to the new key on success, NULL in case of an error (error message is
 * logged to the console).
 */
dilithium_key* create_dilithium_key_from_buffer(int key_format, uint8_t const* der_buffer,
						uint32_t der_size, uint8_t const* id, int len)
{
       /* Allocate new key */
	dilithium_key* key = (dilithium_key*) malloc(sizeof(dilithium_key));
	if (key == NULL) 
	{
		LOG_ERR("Error allocating temporary private key");
		return NULL;
	}

	wc_dilithium_init_id(key, id, len, NULL, INVALID_DEVID);

	/* Set level and allocate memory for raw key */
	if (key_format == DILITHIUM_LEVEL2k) 
	{
		wc_dilithium_set_level(key, 2);
	}
	else if (key_format == DILITHIUM_LEVEL3k) 
	{
		wc_dilithium_set_level(key, 3);
	}
	else if (key_format == DILITHIUM_LEVEL5k)
	{
		wc_dilithium_set_level(key, 5);
	}
	
	/* Import the actual private key from the DER buffer */
	int ret = wc_dilithium_import_private_key(der_buffer, der_size, NULL, 0, key);
	if (ret != 0) 
	{
		LOG_ERR("Error parsing the DER key: %d", ret);
		wc_dilithium_free(key);
		free(key);
		return NULL;
	}

	return key;
}


/* Fill a new falcon key with data from the provided DER buffer. The dilithium level is
 * encoded in the key_format parameter. The memory for the key is allocated by this method
 * and must be freed by the caller.
 * 
 * Returns a pointer to the new key on success, NULL in case of an error (error message is
 * logged to the console).
 */
falcon_key* create_falcon_key_from_buffer(int key_format, uint8_t const* der_buffer,
					  uint32_t der_size, uint8_t const* id, int len)
{
        /* Allocate new key */
	falcon_key* key = (falcon_key* ) malloc(sizeof(falcon_key));
	if (key == NULL) 
	{
		LOG_ERR("Error allocating temporary private key");
		return NULL;
	}

	wc_falcon_init_id(key, id, len, NULL, INVALID_DEVID);

	/* Set level and allocate memory for raw key */
	if (key_format == FALCON_LEVEL1k) 
	{
		wc_falcon_set_level(key, 1);
	}
	else if (key_format == FALCON_LEVEL5k) 
	{
		wc_falcon_set_level(key, 5);
	}
	
	/* Import the actual private key from the DER buffer */
	int ret = wc_falcon_import_private_key(der_buffer, der_size, NULL, 0, key);
	if (ret != 0) 
	{
		LOG_ERR("Error parsing the DER key: %d", ret);
		wc_falcon_free(key);
		free(key);
		return NULL;
	}

	return key;
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
		case WC_PK_TYPE_PQC_KEM_KEYGEN:
			ret = pkcs11_pqc_kem_keygen(info->pk.pqc_kem_kg.key,
						    info->pk.pqc_kem_kg.type,
						    info->pk.pqc_kem_kg.size);
			break;
		case WC_PK_TYPE_PQC_KEM_ENCAPS:
			ret = pkcs11_pqc_kem_encapsulate(info->pk.pqc_encaps.key,
							 info->pk.pqc_encaps.type,
							 info->pk.pqc_encaps.ciphertext,
							 info->pk.pqc_encaps.ciphertextLen,
							 info->pk.pqc_encaps.sharedSecret,
							 info->pk.pqc_encaps.sharedSecretLen);
			break;
		case WC_PK_TYPE_PQC_KEM_DECAPS:
			ret = pkcs11_pqc_kem_decapsulate(info->pk.pqc_decaps.key,
							 info->pk.pqc_decaps.type,
							 info->pk.pqc_decaps.ciphertext,
							 info->pk.pqc_decaps.ciphertextLen,
							 info->pk.pqc_decaps.sharedSecret,
							 info->pk.pqc_decaps.sharedSecretLen);
			break;
		default:
			break;
		}
	}

	return ret;
}


int pkcs11_pqc_kem_keygen(void* key, int type, uint32_t keySize)
{
	int ret = CRYPTOCB_UNAVAILABLE;

	/* Check which key type we have to generate */
	// if (key->type == KYBER768)
	// {
	// 	/* Delete any exisiting (old) objects */
	// 	pkcs11_destroy_objects(secure_element_temp_key_sig_id, secure_element_temp_key_sig_id_size);

	// 	/* Generate the key */
	// 	ret = pkcs11_generate_key_pair_kyber768(secure_element_temp_key_sig_id,
        //                                                 secure_element_temp_key_sig_id_size);

	// 	if (ret != CKR_OK) 
	// 	{
	// 		ret = WC_HW_E;
	// 	}
	// 	else
	// 	{
	// 		/* Read public key */
	// 		unsigned long external_public_key_size = EXT_KYBER_MAX_PUB_SZ;
	// 		ret = pkcs11_read_public_key(secure_element_temp_key_sig_id,
	// 					     secure_element_temp_key_sig_id_size,
	// 					     key->pub,
	// 					     &external_public_key_size);

	// 		if ((ret != CKR_OK) || (external_public_key_size != KYBER768_PUBLIC_KEY_SIZE))
	// 		{
	// 			ret = WC_HW_E;
	// 		}
	// 		else
	// 		{
	// 			/* We store the id of the generated key in the private key buffer */
	// 			memcpy(key->priv, secure_element_temp_key_sig_id, secure_element_temp_key_sig_id_size);
	// 		}
	// 	}
	// }

	return ret;
}

int pkcs11_pqc_kem_encapsulate(void* key, int type, uint8_t* ciphertext, uint32_t ciphertextLen,
			       uint8_t* sharedSecret, uint32_t sharedSecretLen)
{
	int ret = CRYPTOCB_UNAVAILABLE;

	/* Helper variables as the pkcs11 lib wants 64 bit integers here */
        unsigned long shared_secret_size_tmp = sharedSecretLen;
	unsigned long ciphertext_size_tmp = ciphertextLen;

	// if (key->type == KYBER768)
	// {
	// 	ret = pkcs11_encapsulate_kyber768_with_external_public_key(key->pub,
	// 								   KYBER768_PUBLIC_KEY_SIZE,
	// 								   ciphertext,
	// 								   &ciphertext_size_tmp,
	// 								   sharedSecret,
	// 								   &shared_secret_size_tmp);

	// 	if ((ret != CKR_OK) || (shared_secret_size_tmp != sharedSecretLen) ||
	// 	    (ciphertext_size_tmp != ciphertextLen))
	// 	{
	// 		ret = WC_HW_E;
	// 	}
	// }

	return ret;
}

int pkcs11_pqc_kem_decapsulate(void* key, int type, uint8_t const* ciphertext, uint32_t ciphertextLen,
			       uint8_t* sharedSecret, uint32_t sharedSecretLen)
{
	int ret = CRYPTOCB_UNAVAILABLE;

	/* Helper variable as the pkcs11 lib wants a 64 bit integer here */
        unsigned long shared_secret_size_tmp = sharedSecretLen;

	// if (key->type == KYBER768)
	// {
	// 	ret = pkcs11_decapsulate_kyber768(key->priv,
	// 					  secure_element_temp_key_sig_id_size,
	// 					  (CK_BYTE*) ciphertext,
	// 					  ciphertextLen,
	// 					  sharedSecret,
	// 					  &shared_secret_size_tmp);

	// 	if ((ret != CKR_OK) || (shared_secret_size_tmp != sharedSecretLen))
	// 	{
	// 		ret = WC_HW_E;
	// 	}
	// }

	return ret;
}



