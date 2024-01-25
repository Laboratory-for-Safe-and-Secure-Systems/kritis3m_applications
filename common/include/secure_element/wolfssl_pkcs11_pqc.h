#ifndef WOLFSSSL_PKCS11_PQC_H
#define WOLFSSSL_PKCS11_PQC_H

#include <stdint.h>

#include "wolfssl.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/asn.h"



/* Get the id of the static private key */
uint8_t const* wolfssl_get_secure_element_private_key_id(void);


/* Get the size of the id of the static private key */
uint32_t wolfssl_get_secure_element_private_key_id_size(void);


/* Get the device id of the secure element */
int wolfssl_get_secure_element_device_id(void);


/* Fill a new dilithium key with data from the provided DER buffer. The dilithium level is
 * encoded in the key_format parameter. The memory for the key is allocated by this method
 * and must be freed by the caller.
 * 
 * Returns a pointer to the new key on success, NULL in case of an error (error message is
 * logged to the console).
 */
dilithium_key* create_dilithium_key_from_buffer(int key_format, uint8_t const* der_buffer,
						uint32_t der_size, uint8_t const* id, int len);


/* Fill a new falcon key with data from the provided DER buffer. The dilithium level is
 * encoded in the key_format parameter. The memory for the key is allocated by this method
 * and must be freed by the caller.
 * 
 * Returns a pointer to the new key on success, NULL in case of an error (error message is
 * logged to the console).
 */
falcon_key* create_falcon_key_from_buffer(int key_format, uint8_t const* der_buffer,
					  uint32_t der_size, uint8_t const* id, int len);



#endif /* WOLFSSSL_PKCS11_PQC_H */
