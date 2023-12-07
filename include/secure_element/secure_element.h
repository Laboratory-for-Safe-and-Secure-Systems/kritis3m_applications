#ifndef SECURE_ELEMENT_H
#define SECURE_ELEMENT_H

#include <stdint.h>
#include <stdbool.h>

#include "secure_element/atos_pkcs11.h"


#define TEMPLATE_COUNT(t) sizeof((t)) / sizeof(CK_ATTRIBUTE)

#define MAX_OBJECTS 20

#define SE_DEFAULT_PIN "12345678"

#define DEBUG_MAX_OUTPUT 20000

void dumpMemory(const char *description, void *memory, uint32_t memory_size);

CK_RV pkcs11_setLibraryPath(char const* pLibraryPath);

/*! \fn CK_RV pkcs11_get_session(CK_SESSION_HANDLE * phSession)
    \brief Create or reuse PKCS11 session.
    \param phSession session handle
*/
CK_RV pkcs11_get_session(CK_SESSION_HANDLE *phSession);

/*! \fn CK_RV pkcs11_close_session(CK_SESSION_HANDLE * phSession)
    \brief Close PKCS11 session.
    \param phSession session handle
*/
CK_RV pkcs11_close_session();


/*! \fn CK_RV pkcs11_generate_random(CK_BYTE *random, CK_ULONG randomLen)
    \brief Create or reuse PKCS11 session.
    \param random buffer for random number
    \param randomLen random number len
*/
CK_RV pkcs11_generate_random(CK_BYTE *pRandom, CK_ULONG ulRandomLen);

/*! \fn CK_RV pkcs11_create_object(CK_ATTRIBUTE_PTR attributes, CK_ULONG numAttributes)
    \brief Create or reuse PKCS11 session.
    \param pTemplate template
    \param ulTemplateLen template length
*/
CK_RV pkcs11_create_object(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulTemplateLen);

/*! \fn CK_RV pkcs11_create_object_public_key_dilithium2(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pPublicValue, CK_ULONG ulPublicValueLen)
    \brief Create public key dilithium 2
    \param pId object id
    \param ulIdLen object id length
    \param pPublicValue pPublicValue
    \param ulPublicValueLen ulPublicValueLen
*/
CK_RV pkcs11_create_object_public_key_dilithium2(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pPublicValue, CK_ULONG ulPublicValueLen);

/*! \fn CK_RV pkcs11_create_object_private_key_dilithium2(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pPrivateValue, CK_ULONG ulPrivateValueLen)
    \brief Create private key dilithium 2
    \param pId object id
    \param ulIdLen object id length
    \param pPrivateValue pPublicValue
    \param ulPrivateValueLen ulPublicValueLen
*/
CK_RV pkcs11_create_object_private_key_dilithium2(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pPrivateValue, CK_ULONG ulPrivateValueLen);


/*! \fn CK_RV pkcs11_create_object_public_key_kyber768(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pPublicValue, CK_ULONG ulPublicValueLen)
    \brief Create public key kyber 768
    \param pId object id
    \param ulIdLen object id length
    \param pPublicValue pPublicValue
    \param ulPublicValueLen ulPublicValueLen
*/
CK_RV pkcs11_create_object_public_key_kyber768(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pPublicValue, CK_ULONG ulPublicValueLen);

/*! \fn CK_RV pkcs11_create_object_private_key_kyber768(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pPrivateValue, CK_ULONG ulPrivateValueLen)
    \brief Create private key kyber 768
    \param pId object id
    \param ulIdLen object id length
    \param pPrivateValue pPublicValue
    \param ulPrivateValueLen ulPublicValueLen
*/
CK_RV pkcs11_create_object_private_key_kyber768(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pPrivateValue, CK_ULONG ulPrivateValueLen);

/*! \fn CK_RV pkcs11_read_public_key(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pOutput, CK_ULONG *pulOutputLen)
    \brief Read public key object with id.
    \param pId object id
    \param ulIdLen object id length
    \param pOutput publicKey
    \param pulOutputLen publicKey length
*/
CK_RV pkcs11_read_public_key(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pOutput, CK_ULONG *pulOutputLen);

/*! \fn CK_RV pkcs11_destroy_objects(CK_BYTE *pId, CK_ULONG ulIdLen)
    \brief Destroy all objects with id.
    \param pId object id
    \param ulIdLen object id length
*/
CK_RV pkcs11_destroy_objects(CK_BYTE *pId, CK_ULONG ulIdLen);

/*! \fn CK_RV pkcs11_sign_dilithium2(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pInput, CK_ULONG ulInputLen, CK_BYTE *pOutput, CK_ULONG *pulOutputLen)
    \brief Sign with Dilithium 2
    \param pId key id
    \param ulIdLen key id length
    \param pInput data to sign
    \param ulInputLen data to sign length
    \param pOutput signature
    \param pulOutputLen signature length
*/
CK_RV pkcs11_sign_dilithium2(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pInput, CK_ULONG ulInputLen, CK_BYTE *pOutput, CK_ULONG *pulOutputLen);

/*! \fn CK_RV pkcs11_verify_dilithium2(CK_BYTE *id, CK_ULONG idLen, CK_BYTE *input, CK_ULONG inputLen, CK_BYTE *signature, CK_ULONG signatureLen)
    \brief Verify with Dilithium 2
    \param pId key id
    \param ulIdLen key id length
    \param pInput data to sign
    \param ulInputLen data to sign length
    \param pSignature signature
    \param ulSignatureLen signature length
*/
CK_RV pkcs11_verify_dilithium2(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pInput, CK_ULONG ulInputLen, CK_BYTE *pSignature, CK_ULONG ulSignatureLen);

/*! \fn CK_RV pkcs11_encapsulate_kyber768(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pCipherText, CK_ULONG *pulCipherTextLen, CK_BYTE *pSharedSecret, CK_ULONG *pulSharedSecretLen)
    \brief Sign with Dilithium 2
    \param pId key id
    \param ulIdLen key id length
    \param pCipherText buffer for cipher text
    \param ulCipherTextLen  cipher text buffer length
    \param pSharedSecret buffer for shared secret
    \param pulSharedSecretLen shared secret buffer length
*/
CK_RV pkcs11_encapsulate_kyber768(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pCipherText, CK_ULONG *pulCipherTextLen, CK_BYTE *pSharedSecret, CK_ULONG *pulSharedSecretLen);

/*! \fn CK_RV pkcs11_encapsulate_kyber768_with_external_public_key(CK_BYTE *pPublicValue, CK_ULONG ulPublicValueLen, CK_BYTE *pCipherText, CK_ULONG *pulCipherTextLen, CK_BYTE *pSharedSecret, CK_ULONG *pulSharedSecretLen)
    \brief Sign with Dilithium 2
    \param pPublicValue public key value
    \param ulPublicValueLen public key value length
    \param pCipherText buffer for cipher text
    \param ulCipherTextLen  cipher text buffer length
    \param pSharedSecret buffer for shared secret
    \param pulSharedSecretLen shared secret buffer length
*/
CK_RV pkcs11_encapsulate_kyber768_with_external_public_key(CK_BYTE *pPublicValue, CK_ULONG ulPublicValueLen, CK_BYTE *pCipherText, CK_ULONG *pulCipherTextLen, CK_BYTE *pSharedSecret, CK_ULONG *pulSharedSecretLen);

/*! \fn CK_RV pkcs11_decapsulate_kyber768(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pCipherText, CK_ULONG ulCipherTextLen, CK_BYTE *pSharedSecret, CK_ULONG *pulSharedSecretLen)
    \brief Verify with Dilithium 2
    \param pId key id
    \param ulIdLen key id length
    \param pCipherText cipher text
    \param ulCipherTextLen  cipher text length
    \param pSharedSecret buffer for shared secret
    \param pulSharedSecretLen shared secret buffer length
*/
CK_RV pkcs11_decapsulate_kyber768(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pCipherText, CK_ULONG ulCipherTextLen, CK_BYTE *pSharedSecret, CK_ULONG *pulSharedSecretLen);

/*! \fn CK_RV pkcs11_generate_key_pair(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pAttributesPublicKey, CK_ULONG ulAttributesPublicKeyLen, CK_ATTRIBUTE_PTR pAttributesPrivateKey, CK_ULONG ulAttributesPrivateKeyLen)
    \brief Create key pair with given template
    \param pMechanism mechanism
    \param pPublicKeyTemplate template public key
    \param ulPublicKeyTemplateLen template public length
    \param pPrivateKeyTemplate template private key
    \param ulPrivateKeyTemplateLen template private length
*/
CK_RV pkcs11_generate_key_pair(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKey, CK_ULONG ulPublicKeyLen, CK_ATTRIBUTE_PTR pPrivateKey, CK_ULONG ulPrivateKeyLen);


/*! \fn CK_RV pkcs11_generate_key_pair_dilithium2(CK_BYTE *pId, CK_ULONG ulIdLen)
    \brief Create key pair with given template
    \param pId key id
    \param ulIdLen key id length
*/
CK_RV pkcs11_generate_key_pair_dilithium2(CK_BYTE *pId, CK_ULONG ulIdLen);

/*! \fn CK_RV pkcs11_generate_key_pair_kyber768(CK_BYTE *pId, CK_ULONG ulIdLen)
    \brief Create key pair with given template
    \param pId key id
    \param ulIdLen key id length
*/
CK_RV pkcs11_generate_key_pair_kyber768(CK_BYTE *pId, CK_ULONG ulIdLen);


#endif // SECURE_ELEMENT_H