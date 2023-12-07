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


/* Import the public/private key pair in the given PEM file into the secure element.
 *
 * Returns 0 on success, -1 in case of an error (error message is logged to the console).
 */
int wolfssl_import_key_pair_into_secure_element(uint8_t const* pem_buffer, uint32_t pem_size);


/* Install the central callback for post-quantum operations using the secure element.
 * The argument is an optional ctx pointer parameter that is forwarded to the callback.
 * Set to NULL if not needed.
 * 
 * Returns 0 on success, -1 in case of an error (error message is logged to the console).
 */
int wolfssl_install_crypto_callback_secure_element(void* ctx);



#endif /* WOLFSSSL_PKCS11_PQC_H */
