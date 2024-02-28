#ifndef WOLFSSSL_PKCS11_PQC_H
#define WOLFSSSL_PKCS11_PQC_H

#include <stdint.h>

#include "wolfssl.h"

/* Get the id of the static private key */
uint8_t const* secure_element_private_key_id(void);


/* Get the size of the id of the static private key */
uint32_t secure_element_private_key_id_size(void);


/* Get the id of the additional static private key */
uint8_t const* secure_element_additional_private_key_id(void);


/* Get the size of the id of the additional static private key */
uint32_t secure_element_additional_private_key_id_size(void);


/* Get the device id of the secure element */
int secure_element_device_id(void);


/* Import the public/private key pair in the given PEM file into the secure element.
 *
 * Returns 0 on success, -1 in case of an error (error message is logged to the console).
 */
int pkcs11_import_pem_key(pkcs11_module* module, uint8_t const* pem_buffer, uint32_t pem_size,
			  uint8_t const* id, int len);


#endif /* WOLFSSSL_PKCS11_PQC_H */
