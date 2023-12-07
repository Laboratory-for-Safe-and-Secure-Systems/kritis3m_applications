
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdint.h>
#include <string.h>

#include "secure_element/secure_element.h"

#if defined(_WIN32)

#define DLL_CRYPTOKI_MODULE_PKCS11 "libcardos11-iot-pcsc.dll"

#else /* not WINDOWS */

#define DLL_CRYPTOKI_MODULE_PKCS11 "/usr/local/lib/libcardos11-iot-pcsc.so"

#include <dlfcn.h>
#define HINSTANCE void *
#define LoadLibrary(filename) dlopen((filename), RTLD_NOW)
#define FreeLibrary(handle) dlclose((handle))
#define GetProcAddress(handle, symbol) dlsym((handle), (symbol))
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif
#endif

static CK_C_GetFunctionList pf_pkcs11_GetFunctionList = NULL;
static CK_SESSION_HANDLE ghSession = CK_INVALID_HANDLE;
static CK_FUNCTION_LIST_PTR pCkf = NULL_PTR;

HINSTANCE ghModule = NULL;
char const* gLibraryPath = DLL_CRYPTOKI_MODULE_PKCS11;

void dumpMemory(const char *description, void *memory, uint32_t memory_size)
{
  char str[256] = {0};
  char txt[17] = {0};
  uint32_t i = 0, idx = 0;

  snprintf(str + idx, sizeof(str) - idx, "dumping '%s' (%u bytes)\n", description, memory_size);
  printf("%s", str);

  if (memory == NULL)
  {
    printf("NULL\n");
    return;
  }

  idx = 0;
  memset(txt, 0, sizeof(txt));
  for (i = 0; i < memory_size; i++)
  {
    if (i > DEBUG_MAX_OUTPUT)
    {
      printf("Stop dumping after %d bytes.\n", DEBUG_MAX_OUTPUT);
      break;
    }

    if (i % 16 == 0)
    {
      if (i > 0)
      {
        snprintf(str + idx, sizeof(str) - idx, "  %s\n", txt);
        printf("%s", str);

        idx = 0;
        memset(txt, 0, sizeof(txt));
      }

      idx += snprintf(str + idx, sizeof(str) - idx, "%06x: ", i);
    }

    idx += snprintf(str + idx, sizeof(str) - idx, " %02x", ((uint8_t *)memory)[i]);
    txt[i % 16] = (((uint8_t *)memory)[i] > 31 && ((uint8_t *)memory)[i] < 127) ? ((uint8_t *)memory)[i] : '.';
  }

  if (memory_size > 0)
  {
    for (/* i = i */; i % 16 != 0; i++)
      idx += snprintf(str + idx, sizeof(str) - idx, "   ");

    snprintf(str + idx, sizeof(str) - idx, "  %s\n", txt);
    printf("%s", str);
  }
}

CK_RV pkcs11_setLibraryPath(char const*pLibraryPath)
{
  gLibraryPath = pLibraryPath;
  return CKR_OK;
}

CK_RV pkcs11_get_session(CK_SESSION_HANDLE *phSession)
{

  CK_RV rv = CKR_OK;
  CK_SLOT_ID slotID = 0;
  CK_SLOT_ID slots[10] = {0};
  CK_ULONG slotsCount = 10;

  if (pCkf == NULL_PTR)
  {
    // load
    gLibraryPath = (gLibraryPath == NULL) ? DLL_CRYPTOKI_MODULE_PKCS11 : gLibraryPath;

    ghModule = LoadLibrary(gLibraryPath);
    if (!ghModule)
      return CKR_GENERAL_ERROR;

    pf_pkcs11_GetFunctionList = (CK_C_GetFunctionList)(GetProcAddress(ghModule, "C_GetFunctionList"));

    if (pf_pkcs11_GetFunctionList == NULL)
      return CKR_GENERAL_ERROR;

    rv = (*pf_pkcs11_GetFunctionList)(&pCkf);
    if (rv != CKR_OK)
      return rv;

    // initialize
    rv = pCkf->C_Initialize(NULL_PTR);
    if (rv != CKR_OK)
      return rv;

    // slots
    rv = pCkf->C_GetSlotList(TRUE, slots, &slotsCount);
    if (rv != CKR_OK)
      return rv;

    /* For IoT Devices we assume just one reader (either card or secure element) */
    /* In case of more than one reader connected add “select reader” */
    slotID = slots[0];
  }
  if (ghSession == CK_INVALID_HANDLE)
  {
    rv = pCkf->C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &ghSession);
    if (rv != CKR_OK)
      return rv;
  }

  if (phSession)
    *phSession = ghSession;
  return rv;
}

CK_RV pkcs11_close_session()
{
  if (pCkf)
  {
    pCkf->C_CloseSession(ghSession);
    ghSession = CK_INVALID_HANDLE;
    pCkf->C_Finalize(NULL_PTR);
    pCkf = NULL;
  }
  return CKR_OK;
}

CK_RV pkcs11_generate_random(CK_BYTE *pRandom, CK_ULONG ulRandomLen)
{

  /* Declaration of variables */
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;

  /* Initialization of PKCS#11 session */
  rv = pkcs11_get_session(&hSession);
  if (rv != CKR_OK)
    return rv;

  /* Generate random bytes */
  rv = pCkf->C_GenerateRandom(hSession, pRandom, ulRandomLen);
  if (rv != CKR_OK)
    return rv;

  return rv;
}

CK_RV pkcs11_create_object(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulTemplateLen)
{
  /* Declaration of variables */
  CK_RV rv = CKR_GENERAL_ERROR;

  CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
  CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;

  /* Initialization of PKCS#11 session */
  rv = pkcs11_get_session(&hSession);
  if (rv != CKR_OK)
    return rv;

  /* Create object with given template */
  rv = pCkf->C_CreateObject(hSession, pTemplate, ulTemplateLen, &hObject);
  if (rv != CKR_OK)
    return rv;

  return rv;
}

CK_RV pkcs11_read_public_key(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pOutput, CK_ULONG *pulOutputLen)
{
  /* Declaration of variables */
  CK_RV rv = CKR_GENERAL_ERROR;

  CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;

  CK_OBJECT_HANDLE hObjects[MAX_OBJECTS] = {0};
  CK_ULONG hObjectsCount = sizeof(hObjects) / sizeof(CK_OBJECT_HANDLE);

  CK_OBJECT_CLASS cko_public_key = CKO_PUBLIC_KEY;
  CK_BBOOL ck_token = TRUE;

  CK_ATTRIBUTE searchTemplate[] = {
      {CKA_CLASS, &cko_public_key, sizeof(CK_OBJECT_CLASS)},
      {CKA_TOKEN, &ck_token, sizeof(CK_BBOOL)},
      {CKA_ID, pId, ulIdLen}
  };

  CK_ATTRIBUTE readTemplate[] = {
      {CKA_VALUE, NULL, 0}
  };

  /* Initialization of PKCS#11 session */
  rv = pkcs11_get_session(&hSession);
  if (rv != CKR_OK)
    return rv;

  /* find object with given template */
  /* find all objects with given template */
  rv = pCkf->C_FindObjectsInit(hSession, searchTemplate, TEMPLATE_COUNT(searchTemplate));
  if (rv != CKR_OK)
    return rv;

  rv = pCkf->C_FindObjects(hSession, hObjects, MAX_OBJECTS, &hObjectsCount);
  if (rv != CKR_OK)
    return rv;

  rv = pCkf->C_FindObjectsFinal(hSession);
  if (rv != CKR_OK)
    return rv;

  if (hObjectsCount == 0)
    return CKR_ARGUMENTS_BAD;

  /* We just read the first found object for now */
  /* Read the size of the key first */
  rv = pCkf->C_GetAttributeValue(hSession, hObjects[0], readTemplate, TEMPLATE_COUNT(readTemplate));

  if ((rv == CKR_OK) && (readTemplate[0].ulValueLen != CK_UNAVAILABLE_INFORMATION) && (readTemplate[0].ulValueLen <= *pulOutputLen))
  {
        /* Read the key */
        readTemplate[0].pValue = pOutput;
        rv = pCkf->C_GetAttributeValue(hSession, hObjects[0], readTemplate, TEMPLATE_COUNT(readTemplate));
        if (rv == CKR_OK)
          *pulOutputLen = readTemplate[0].ulValueLen;
  }

  return rv;
}

CK_RV pkcs11_destroy_objects(CK_BYTE *pId, CK_ULONG ulIdLen)
{
  /* Declaration of variables */
  CK_RV rv = CKR_GENERAL_ERROR;

  CK_ULONG i = 0;

  CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;

  CK_OBJECT_HANDLE hObjects[MAX_OBJECTS] = {0};
  CK_ULONG hObjectsCount = sizeof(hObjects) / sizeof(CK_OBJECT_HANDLE);

  CK_BBOOL ck_token = TRUE;

  CK_ATTRIBUTE searchTemplate[] = {
      {CKA_TOKEN, &ck_token, sizeof(CK_BBOOL)},
      {CKA_ID, pId, ulIdLen}};

  /* Initialization of PKCS#11 session */
  rv = pkcs11_get_session(&hSession);
  if (rv != CKR_OK)
    return rv;

  /* find all objects with given template */
  rv = pCkf->C_FindObjectsInit(hSession, searchTemplate, TEMPLATE_COUNT(searchTemplate));
  if (rv != CKR_OK)
    return rv;

  rv = pCkf->C_FindObjects(hSession, hObjects, MAX_OBJECTS, &hObjectsCount);
  if (rv != CKR_OK)
    return rv;

  rv = pCkf->C_FindObjectsFinal(hSession);
  if (rv != CKR_OK)
    return rv;

  /* delete all found objects */
  for (i = 0; i < hObjectsCount; i++)
  {
    rv = pCkf->C_DestroyObject(hSession, hObjects[i]);
    if (rv != CKR_OK)
      return rv;
  }

  return rv;
}

CK_RV pkcs11_create_object_public_key_dilithium2(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pPublicValue, CK_ULONG ulPublicValueLen)
{

  /* Declaration of variables */
  CK_RV rv = CKR_GENERAL_ERROR;

  CK_OBJECT_CLASS cko_public_key = CKO_PUBLIC_KEY;

  CK_KEY_TYPE ck_keyType = CKK_ML_DSA;
  CK_BBOOL ck_token = TRUE;
  CK_BBOOL ck_verify = TRUE;

  CK_ML_DSA_PARAMETER_SET_TYPE param_set = CKP_ML_DSA_65;

  CK_ATTRIBUTE publicKeyTemplate[] = {
      {CKA_CLASS, &cko_public_key, sizeof(CK_OBJECT_CLASS)},
      {CKA_TOKEN, &ck_token, sizeof(CK_BBOOL)},
      {CKA_ID, pId, ulIdLen},
      {CKA_VERIFY, &ck_verify, sizeof(CK_BBOOL)},
      {CKA_VALUE, pPublicValue, ulPublicValueLen},
      {CKA_KEY_TYPE, &ck_keyType, sizeof(CK_KEY_TYPE)},
      {CKA_PARAMETER_SET, &param_set, sizeof(param_set)}};

  /* Create object with given template */
  rv = pkcs11_create_object(publicKeyTemplate, TEMPLATE_COUNT(publicKeyTemplate));
  if (rv != CKR_OK)
    return rv;

  return rv;
}

CK_RV pkcs11_create_object_private_key_dilithium2(CK_BYTE* pId, CK_ULONG ulIdLen, CK_BYTE *pPrivateValue, CK_ULONG ulPrivateValueLen)
{
  /* Declaration of variables */
  CK_RV rv = CKR_GENERAL_ERROR;

  CK_OBJECT_CLASS cko_private_key = CKO_PRIVATE_KEY;

  CK_KEY_TYPE ck_keyType = CKK_ML_DSA;
  CK_BBOOL ck_token = TRUE;
  CK_BBOOL ck_sign = TRUE;

  CK_ML_DSA_PARAMETER_SET_TYPE param_set = CKP_ML_DSA_65;

  CK_ATTRIBUTE privateKeyTemplate[] = {
      {CKA_CLASS, &cko_private_key, sizeof(CK_OBJECT_CLASS)},
      {CKA_TOKEN, &ck_token, sizeof(CK_BBOOL)},
      {CKA_ID, pId, ulIdLen},
      {CKA_SIGN, &ck_sign, sizeof(CK_BBOOL)},
      {CKA_VALUE, pPrivateValue, ulPrivateValueLen},
      {CKA_KEY_TYPE, &ck_keyType, sizeof(CK_KEY_TYPE)},
      {CKA_PARAMETER_SET, &param_set, sizeof(param_set)}};

  /* Create object with given template */
  rv = pkcs11_create_object(privateKeyTemplate, TEMPLATE_COUNT(privateKeyTemplate));
  if (rv != CKR_OK)
    return rv;

  return rv;
}

CK_RV pkcs11_create_object_public_key_kyber768(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pPublicValue, CK_ULONG ulPublicValueLen)
{
  /* Declaration of variables */
  CK_RV rv = CKR_GENERAL_ERROR;

  CK_OBJECT_CLASS cko_public_key = CKO_PUBLIC_KEY;

  CK_ML_KEM_PARAMETER_SET_TYPE param_set = CKP_ML_KEM_768;

  CK_KEY_TYPE ck_keyType = CKK_ML_KEM;
  CK_BBOOL ck_token = TRUE;
  CK_BBOOL ck_encapsulate = TRUE;

  CK_ATTRIBUTE publicKeyTemplate[] = {
      {CKA_CLASS, &cko_public_key, sizeof(CK_OBJECT_CLASS)},
      {CKA_TOKEN, &ck_token, sizeof(CK_BBOOL)},
      {CKA_ID, pId, ulIdLen},
      {CKA_ENCAPSULATE, &ck_encapsulate, sizeof(CK_BBOOL)},
      {CKA_VALUE, pPublicValue, ulPublicValueLen},
      {CKA_KEY_TYPE, &ck_keyType, sizeof(CK_KEY_TYPE)},
      {CKA_PARAMETER_SET, &param_set, sizeof(param_set)}};

  /* Create object with given template */
  rv = pkcs11_create_object(publicKeyTemplate, TEMPLATE_COUNT(publicKeyTemplate));
  if (rv != CKR_OK)
    return rv;

  return rv;
}

CK_RV pkcs11_create_object_private_key_kyber768(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pPrivateValue, CK_ULONG ulPrivateValueLen)
{
  /* Declaration of variables */
  CK_RV rv = CKR_GENERAL_ERROR;

  CK_OBJECT_CLASS cko_private_key = CKO_PRIVATE_KEY;

  CK_ML_KEM_PARAMETER_SET_TYPE param_set = CKP_ML_KEM_768;

  CK_KEY_TYPE ck_keyType = CKK_ML_KEM;
  CK_BBOOL ck_token = TRUE;
  CK_BBOOL ck_decapsulate = TRUE;

  CK_ATTRIBUTE privateKeyTemplate[] = {
      {CKA_CLASS, &cko_private_key, sizeof(CK_OBJECT_CLASS)},
      {CKA_TOKEN, &ck_token, sizeof(CK_BBOOL)},
      {CKA_ID, pId, ulIdLen},
      {CKA_DECAPSULATE, &ck_decapsulate, sizeof(CK_BBOOL)},
      {CKA_VALUE, pPrivateValue, ulPrivateValueLen},
      {CKA_KEY_TYPE, &ck_keyType, sizeof(CK_KEY_TYPE)},
      {CKA_PARAMETER_SET, &param_set, sizeof(param_set)}};

  /* Create object with given template */
  rv = pkcs11_create_object(privateKeyTemplate, TEMPLATE_COUNT(privateKeyTemplate));
  if (rv != CKR_OK)
    return rv;

  return rv;
}

CK_RV pkcs11_sign_dilithium2(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pInput, CK_ULONG ulInputLen, CK_BYTE *pOutput, CK_ULONG *pulOutputLen) 
{
    /* Declaration of variables */
    CK_RV rv = CKR_OK;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_UTF8CHAR_PTR pin = (CK_UTF8CHAR_PTR) SE_DEFAULT_PIN;
    CK_ULONG pinLength = 8;
    CK_ULONG signatureLength = 0;
    CK_OBJECT_CLASS cko_private_key = CKO_PRIVATE_KEY;
    CK_BBOOL ck_token = TRUE;
    CK_KEY_TYPE ck_keyType = CKK_ML_DSA;
    CK_ATTRIBUTE privateKeyTemplate[] = {
      {CKA_CLASS, &cko_private_key, sizeof(CK_OBJECT_CLASS)},
      {CKA_TOKEN, &ck_token, sizeof(CK_BBOOL)},
      {CKA_ID, pId, ulIdLen},
      {CKA_KEY_TYPE, &ck_keyType, sizeof(CK_KEY_TYPE)}
    };
    CK_MECHANISM mechanism = {0};
    CK_OBJECT_HANDLE privateKeys[10] = {0};
    CK_ULONG privateKeysCount = 0;

    /* Initialization of PKCS#11 session */
    if (pulOutputLen) signatureLength = *pulOutputLen;
    rv = pkcs11_get_session(&hSession);
    if (rv != CKR_OK) return rv;
    rv = pCkf->C_Login(hSession, CKU_USER, pin, pinLength);
    rv = pCkf->C_FindObjectsInit(hSession, privateKeyTemplate, TEMPLATE_COUNT(privateKeyTemplate));
    rv = pCkf->C_FindObjects(hSession, privateKeys, 10, &privateKeysCount);
    rv = pCkf->C_FindObjectsFinal(hSession);

    /* Execution of sign function */
    if (privateKeysCount > 0) {
        mechanism.mechanism = CKM_ML_DSA;
        mechanism.pParameter = NULL_PTR;
        mechanism.ulParameterLen = 0;
        rv = pCkf->C_SignInit(hSession, &mechanism, privateKeys[0]);
        rv = pCkf->C_Sign(hSession, pInput, ulInputLen, pOutput, &signatureLength);
        if (pulOutputLen) *pulOutputLen = signatureLength;
    }
    else {
        rv = CKR_OBJECT_HANDLE_INVALID;
    }
    pCkf->C_Logout(hSession);
    return rv;
}

CK_RV pkcs11_verify_dilithium2(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pInput, CK_ULONG ulInputLen, CK_BYTE *pSignature, CK_ULONG ulSignatureLen) 
{
    /* Declaration of variables */
    CK_RV rv = CKR_OK;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_UTF8CHAR_PTR pin = (CK_UTF8CHAR_PTR) SE_DEFAULT_PIN;
    CK_ULONG pinLength = 8;
    CK_OBJECT_CLASS cko_public_key = CKO_PUBLIC_KEY;
    CK_BBOOL ck_token = TRUE;
    CK_KEY_TYPE ck_keyType = CKK_ML_DSA;
    CK_ATTRIBUTE publicKeyTemplate[] = {
      {CKA_CLASS, &cko_public_key, sizeof(CK_OBJECT_CLASS)},
      {CKA_TOKEN, &ck_token, sizeof(CK_BBOOL)},
      {CKA_ID, pId, ulIdLen},
      {CKA_KEY_TYPE, &ck_keyType, sizeof(CK_KEY_TYPE)}
    };
    CK_MECHANISM mechanism = {0};
    CK_OBJECT_HANDLE publicKeys[10] = {0};
    CK_ULONG publicKeysCount = 0;

    /* Initialization of PKCS#11 session */
    rv = pkcs11_get_session(&hSession);
    if (rv != CKR_OK) return rv;
    rv = pCkf->C_Login(hSession, CKU_USER, pin, pinLength);
    rv = pCkf->C_FindObjectsInit(hSession, publicKeyTemplate, TEMPLATE_COUNT(publicKeyTemplate));
    rv = pCkf->C_FindObjects(hSession, publicKeys, 10, &publicKeysCount);
    rv = pCkf->C_FindObjectsFinal(hSession);

    /* Execution of verify function */
    if (publicKeysCount > 0) {
        mechanism.mechanism = CKM_ML_DSA;
        mechanism.pParameter = NULL_PTR;
        mechanism.ulParameterLen = 0;
        rv = pCkf->C_VerifyInit(hSession, &mechanism, publicKeys[0]);
        rv = pCkf->C_Verify(hSession, pInput, ulInputLen, pSignature, ulSignatureLen);
    }
    else {
        rv = CKR_OBJECT_HANDLE_INVALID;
    }

    pCkf->C_Logout(hSession);
    return rv;
}

CK_RV pkcs11_encapsulate_kyber768(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pCipherText, CK_ULONG *pulCipherTextLen, CK_BYTE *pSharedSecret, CK_ULONG *pulSharedSecretLen)
{
    /* Declaration of variables */
    CK_RV rv = CKR_OK;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_UTF8CHAR_PTR pin = (CK_UTF8CHAR_PTR) SE_DEFAULT_PIN;
    CK_ULONG pinLength = 8;
    CK_OBJECT_CLASS cko_public_key = CKO_PUBLIC_KEY;
    CK_BBOOL ck_token = TRUE;
    CK_KEY_TYPE ck_keyType = CKK_ML_KEM;
    CK_ATTRIBUTE publicKeyTemplate[] = {
      {CKA_CLASS, &cko_public_key, sizeof(CK_OBJECT_CLASS)},
      {CKA_TOKEN, &ck_token, sizeof(CK_BBOOL)},
      {CKA_ID, pId, ulIdLen},
      {CKA_KEY_TYPE, &ck_keyType, sizeof(CK_KEY_TYPE)}
    };
    CK_MECHANISM mechanism = {0};
    CK_OBJECT_HANDLE publicKeys[10] = {0};
    CK_ULONG publicKeysCount = 0;

    /* Initialization of PKCS#11 session */
    rv = pkcs11_get_session(&hSession);
    if (rv != CKR_OK) return rv;
    rv = pCkf->C_Login(hSession, CKU_USER, pin, pinLength);
    rv = pCkf->C_FindObjectsInit(hSession, publicKeyTemplate, TEMPLATE_COUNT(publicKeyTemplate));
    rv = pCkf->C_FindObjects(hSession, publicKeys, 10, &publicKeysCount);
    rv = pCkf->C_FindObjectsFinal(hSession);

    /* Execution of encapsulate function */
    if (publicKeysCount > 0) {
        mechanism.mechanism = CKM_ML_KEM;
        mechanism.pParameter = NULL_PTR;
        mechanism.ulParameterLen = 0;
        rv = pCkf->C_EncapsulateInit(hSession, &mechanism, publicKeys[0]);
        rv = pCkf->C_Encapsulate(hSession, pCipherText, pulCipherTextLen, pSharedSecret, pulSharedSecretLen);
    }
    else {
        rv = CKR_OBJECT_HANDLE_INVALID;
    }

    pCkf->C_Logout(hSession);
    return rv;
}

CK_RV pkcs11_encapsulate_kyber768_with_external_public_key(CK_BYTE *pPublicValue, CK_ULONG ulPublicValueLen, CK_BYTE *pCipherText, CK_ULONG *pulCipherTextLen, CK_BYTE *pSharedSecret, CK_ULONG *pulSharedSecretLen)
{
    /* Declaration of variables */
    CK_RV rv = CKR_OK;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_UTF8CHAR_PTR pin = (CK_UTF8CHAR_PTR) SE_DEFAULT_PIN;
    CK_ULONG pinLength = 8;
    CK_OBJECT_CLASS cko_public_key = CKO_PUBLIC_KEY;
    CK_BBOOL ck_token = TRUE;
    CK_KEY_TYPE ck_keyType = CKK_ML_KEM;
    /* CKM_ML_KEM */
    CK_BYTE_PTR kem_pPublicKey = pPublicValue;
    CK_ULONG kem_ulPublicKeyLen = ulPublicValueLen;
    CK_ML_KEM_PARAMS kemParams = { kem_pPublicKey, kem_ulPublicKeyLen };
    CK_MECHANISM mechanism = {0};
    CK_OBJECT_HANDLE publicKeys[10] = {0};
    CK_ULONG publicKeysCount = 0;

    /* Initialization of PKCS#11 session */
    rv = pkcs11_get_session(&hSession);
    if (rv != CKR_OK) return rv;

    /* Execution of encapsulate function */
    mechanism.mechanism = CKM_ML_KEM;
    mechanism.pParameter = &kemParams;
    mechanism.ulParameterLen = sizeof(kemParams);
    rv = pCkf->C_EncapsulateInit(hSession, &mechanism, CK_INVALID_HANDLE);
    rv = pCkf->C_Encapsulate(hSession, pCipherText, pulCipherTextLen, pSharedSecret, pulSharedSecretLen);

    return rv;
}


CK_RV pkcs11_decapsulate_kyber768(CK_BYTE *pId, CK_ULONG ulIdLen, CK_BYTE *pCipherText, CK_ULONG ulCipherTextLen, CK_BYTE *pSharedSecret, CK_ULONG *pulSharedSecretLen)
{
    /* Declaration of variables */
    CK_RV rv = CKR_OK;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_UTF8CHAR_PTR pin = (CK_UTF8CHAR_PTR) SE_DEFAULT_PIN;
    CK_ULONG pinLength = 8;
    CK_OBJECT_CLASS cko_private_key = CKO_PRIVATE_KEY;
    CK_BBOOL ck_token = TRUE;
    CK_KEY_TYPE ck_keyType = CKK_ML_KEM;
    CK_ATTRIBUTE privateKeyTemplate[] = {
      {CKA_CLASS, &cko_private_key, sizeof(CK_OBJECT_CLASS)},
      {CKA_TOKEN, &ck_token, sizeof(CK_BBOOL)},
      {CKA_ID, pId, ulIdLen},
      {CKA_KEY_TYPE, &ck_keyType, sizeof(CK_KEY_TYPE)}
    };
    CK_MECHANISM mechanism = {0};
    CK_OBJECT_HANDLE privateKeys[10] = {0};
    CK_ULONG privateKeysCount = 0;

    /* Initialization of PKCS#11 session */
    rv = pkcs11_get_session(&hSession);
    if (rv != CKR_OK) return rv;
    rv = pCkf->C_Login(hSession, CKU_USER, pin, pinLength);
    rv = pCkf->C_FindObjectsInit(hSession, privateKeyTemplate, TEMPLATE_COUNT(privateKeyTemplate));
    rv = pCkf->C_FindObjects(hSession, privateKeys, 10, &privateKeysCount);
    rv = pCkf->C_FindObjectsFinal(hSession);

    /* Execution of decapsulate function */
    if (privateKeysCount > 0) {
        mechanism.mechanism = CKM_ML_KEM;
        mechanism.pParameter = NULL_PTR;
        mechanism.ulParameterLen = 0;
        rv = pCkf->C_DecapsulateInit(hSession, &mechanism, privateKeys[0]);
        rv = pCkf->C_Decapsulate(hSession, pCipherText, ulCipherTextLen, pSharedSecret, pulSharedSecretLen);
    }
    else {
        rv = CKR_OBJECT_HANDLE_INVALID;
    }
    pCkf->C_Logout(hSession);
    return rv;
}

CK_RV pkcs11_generate_key_pair(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyTemplateLen, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyTemplateLen)
{
  /* Declaration of variables */
  CK_RV rv = CKR_GENERAL_ERROR;

  CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
  CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
  CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;

  /* Initialization of PKCS#11 session */
  rv = pkcs11_get_session(&hSession);
  if (rv != CKR_OK)
    return rv;

  /* Generate key pair with given template */
  rv = pCkf->C_GenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyTemplateLen, pPrivateKeyTemplate, ulPrivateKeyTemplateLen, &hPublicKey, &hPrivateKey);
  if (rv != CKR_OK)
    return rv;

  return rv;
}

CK_RV pkcs11_generate_key_pair_dilithium2(CK_BYTE *pId, CK_ULONG ulIdLen)
{
  /* Declaration of variables */
  CK_RV rv = CKR_GENERAL_ERROR;

  CK_OBJECT_CLASS cko_public_key = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS cko_private_key = CKO_PRIVATE_KEY;

  CK_MECHANISM mechanism = {0};

  CK_KEY_TYPE ck_keyType = CKK_ML_DSA;
  CK_BBOOL ck_token = TRUE;
  CK_BBOOL ck_verify = TRUE;
  CK_BBOOL ck_sign = TRUE;

  CK_ML_DSA_PARAMETER_SET_TYPE param_set = CKP_ML_DSA_65;

  CK_ATTRIBUTE publicKeyTemplate[] = {
      {CKA_CLASS, &cko_public_key, sizeof(CK_OBJECT_CLASS)},
      {CKA_TOKEN, &ck_token, sizeof(CK_BBOOL)},
      {CKA_ID, pId, ulIdLen},
      {CKA_VERIFY, &ck_verify, sizeof(CK_BBOOL)},
      {CKA_KEY_TYPE, &ck_keyType, sizeof(CK_KEY_TYPE)},
      {CKA_PARAMETER_SET, &param_set, sizeof(param_set)}};

  CK_ATTRIBUTE privateKeyTemplate[] = {
      {CKA_CLASS, &cko_private_key, sizeof(CK_OBJECT_CLASS)},
      {CKA_TOKEN, &ck_token, sizeof(CK_BBOOL)},
      {CKA_ID, pId, ulIdLen},
      {CKA_SIGN, &ck_sign, sizeof(CK_BBOOL)},
      {CKA_KEY_TYPE, &ck_keyType, sizeof(CK_KEY_TYPE)},
      {CKA_PARAMETER_SET, &param_set, sizeof(param_set)}};

    mechanism.mechanism = CKM_ML_DSA_KEY_PAIR_GEN;
    mechanism.pParameter = NULL;
    mechanism.ulParameterLen = 0;

  rv = pkcs11_generate_key_pair(&mechanism, publicKeyTemplate, TEMPLATE_COUNT(publicKeyTemplate), privateKeyTemplate, TEMPLATE_COUNT(privateKeyTemplate));
  if (rv != CKR_OK)
    return rv;

  return rv;
}

CK_RV pkcs11_generate_key_pair_kyber768(CK_BYTE *pId, CK_ULONG ulIdLen)
{
  /* Declaration of variables */
  CK_RV rv = CKR_GENERAL_ERROR;

  CK_OBJECT_CLASS cko_public_key = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS cko_private_key = CKO_PRIVATE_KEY;

  CK_MECHANISM mechanism = {0};

  CK_KEY_TYPE ck_keyType = CKK_ML_KEM;
  CK_BBOOL ck_token = TRUE;
  CK_BBOOL ck_encapsulate = TRUE;
  CK_BBOOL ck_decapsulate = TRUE;

  CK_ML_KEM_PARAMETER_SET_TYPE param_set = CKP_ML_KEM_768;

  CK_ATTRIBUTE publicKeyTemplate[] = {
      {CKA_CLASS, &cko_public_key, sizeof(CK_OBJECT_CLASS)},
      {CKA_TOKEN, &ck_token, sizeof(CK_BBOOL)},
      {CKA_ID, pId, ulIdLen},
      {CKA_ENCAPSULATE, &ck_encapsulate, sizeof(CK_BBOOL)},
      {CKA_KEY_TYPE, &ck_keyType, sizeof(CK_KEY_TYPE)},
      {CKA_PARAMETER_SET, &param_set, sizeof(param_set)}};

  CK_ATTRIBUTE privateKeyTemplate[] = {
      {CKA_CLASS, &cko_private_key, sizeof(CK_OBJECT_CLASS)},
      {CKA_TOKEN, &ck_token, sizeof(CK_BBOOL)},
      {CKA_ID, pId, ulIdLen},
      {CKA_DECAPSULATE, &ck_decapsulate, sizeof(CK_BBOOL)},
      {CKA_KEY_TYPE, &ck_keyType, sizeof(CK_KEY_TYPE)},
      {CKA_PARAMETER_SET, &param_set, sizeof(param_set)}};

    mechanism.mechanism = CKM_ML_KEM_KEY_PAIR_GEN;
    mechanism.pParameter = NULL;
    mechanism.ulParameterLen = 0;

  rv = pkcs11_generate_key_pair(&mechanism, publicKeyTemplate, TEMPLATE_COUNT(publicKeyTemplate), privateKeyTemplate, TEMPLATE_COUNT(privateKeyTemplate));
  if (rv != CKR_OK)
    return rv;

  return rv;
}

