
#include "secure_element/wolfssl_pkcs11_pqc.h"


#include "logging.h"

LOG_MODULE_REGISTER(wolfssl_pkcs11);


#define DEVICE_ID_SECURE_ELEMENT 1

static char secure_element_private_key_id[] = "SERVER_KEY";
static size_t secure_element_private_key_id_size = sizeof("SERVER_KEY") - 1;



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

