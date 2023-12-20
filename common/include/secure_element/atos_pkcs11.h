#ifndef _ATOS_PKCS11_H_
#define _ATOS_PKCS11_H_ 1


/*
 * Copyright (C) 2023 Atos Information Technology GmbH. All Rights Reserved.
 * 
 * This source file contains modifications.
 * 
 * The sources provide the option to use hardware based security via 
 * PKCS#11 function calls.
 * 
 * This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
 * either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

/* Some defines are needed, this defines may be platform specific, 
*  see pkcs11.h for details
*/
#if defined(WINDOWS) || defined (_WINDOWS) || defined (WIN32) || defined (_WIN32)
#pragma pack(push, cryptoki, 1)
#endif

#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType name

#if defined(WINDOWS) || defined (_WINDOWS) || defined (WIN32) || defined (_WIN32)
# define PKCS11_CINTERFACE_CALLSPEC __cdecl
# if defined(PKCS11_LIB) || defined(PKCS11_CINTERFACE_STATIC) /* static library */
#   define PKCS11_CINTERFACE_DLLIMPORT
#   define PKCS11_CINTERFACE_DLLEXPORT
# else
#   define PKCS11_CINTERFACE_DLLIMPORT __declspec(dllimport)
#   define PKCS11_CINTERFACE_DLLEXPORT __declspec(dllexport)
# endif

#elif defined(MAC_OS)
# define PKCS11_CINTERFACE_CALLSPEC
# if defined(PKCS11_LIB) || defined(PKCS11_CINTERFACE_STATIC) /* static library */
#   define PKCS11_CINTERFACE_DLLIMPORT
#   define PKCS11_CINTERFACE_DLLEXPORT
# else
#   define PKCS11_CINTERFACE_DLLIMPORT
#   define PKCS11_CINTERFACE_DLLEXPORT __attribute__((visibility("default")))
# endif

#else  /* not WINDOWS */
# define PKCS11_CINTERFACE_CALLSPEC
# define PKCS11_CINTERFACE_DLLIMPORT
# define PKCS11_CINTERFACE_DLLEXPORT

#endif /* WINDOWS */


#ifdef PKCS11_CINTERFACE_EXPORTS
# define CK_DECLARE_FUNCTION(returnType, name) PKCS11_CINTERFACE_DLLEXPORT returnType PKCS11_CINTERFACE_CALLSPEC name
#else /* Link library to application. */
# define CK_DECLARE_FUNCTION(returnType, name) PKCS11_CINTERFACE_DLLIMPORT returnType PKCS11_CINTERFACE_CALLSPEC name
#endif
//#define PKCS11_CINTERFACE_DECL_FUNC_PTR(returnType, name) typedef returnType (PKCS11_CINTERFACE_CALLSPEC * name)

//#define CK_DECLARE_FUNCTION(returnType, name) \
//  returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType(*name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType(*name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

#if defined(WINDOWS) || defined (_WINDOWS) || defined (WIN32) || defined (_WIN32)
#pragma pack(pop, cryptoki)
#endif

/* Vendor defines */

/* vendor defined objects */
#define CKO_CARDOS_CARDCOMMAND (CKO_VENDOR_DEFINED | 0x00000001UL)

/* all vendor defined uses as CK_BYTE arrays, if not mentioned */

/* vendor defined attributes */
#define CKA_CARDOS_PKCS15_PATH (CKA_VENDOR_DEFINED | 0x00000001UL)
#define CKA_CARDOS_EXTERNAL_DATA_LENGTH (CKA_VENDOR_DEFINED | 0x00000002UL) //CK_ULONG

#define CKA_CARDOS_MSE_SET_DATA (CKA_VENDOR_DEFINED | 0x00000010UL)
#define CKA_CARDOS_MSE_SET_P1 (CKA_VENDOR_DEFINED | 0x00000011UL)     //CK_BYTE
#define CKA_CARDOS_MSE_SET_P2 (CKA_VENDOR_DEFINED | 0x00000012UL)     //CK_BYTE
#define CKA_CARDOS_MSE_RESTORE_P2 (CKA_VENDOR_DEFINED | 0x00000013UL) //CK_BYTE

#define CKA_CARDOS_PAIRED_KEY (CKA_VENDOR_DEFINED | 0x00000020UL) //CK_ULONG

#define CKA_PARAMETER_MGF_TYPE (CKA_VENDOR_DEFINED | 0x00000101UL)

#define CKA_CARDOS_APDU (CKA_VENDOR_DEFINED | 0x00000201UL)
#define CKA_CARDOS_RETURN_DATA (CKA_VENDOR_DEFINED | 0x00000202UL)
#define CKA_CARDOS_RETURN_CODE (CKA_VENDOR_DEFINED | 0x00000203UL)
#define CKA_CARDOS_TRANSACTION (CKA_VENDOR_DEFINED | 0x00000204UL) //CK_BBOOL

#define CKA_CARDOS_DYNAMIC_KEY (CKA_VENDOR_DEFINED | 0x00001050UL)

#define CKA_CARDOS_MARKER (CKA_VENDOR_DEFINED | 0x00010001UL)

#define CKA_CRYPTO_OBJECT (CKA_VENDOR_DEFINED | 0x00020001UL)

#define CKA_PKCS11_MECHANISM_INFO_MIN_LENGTH (CKA_VENDOR_DEFINED | 0x0000F701UL) //CK_ULONG
#define CKA_PKCS11_MECHANISM_INFO_MAX_LENGTH (CKA_VENDOR_DEFINED | 0x0000F702UL) //CK_ULONG
#define CKA_PKCS11_MECHANISM_INFO_FLAGS (CKA_VENDOR_DEFINED | 0x0000F703UL) //CK_ULONG

/* PQC - posty quantum crypto extensions */
/* TODO: needs to be checked if pkcs#11 is pqc ready */

/* vendor defined attributes */

#define CKA_ENCAPSULATE (CKA_VENDOR_DEFINED | 0x00000401UL)
#define CKA_DECAPSULATE (CKA_VENDOR_DEFINED | 0x00000402UL)

#define CKA_PARAMETER_SET (CKA_VENDOR_DEFINED | 0x00000501UL)

/* vendor defined mechanisms */
#define CKM_ML_KEM_KEY_PAIR_GEN (CKM_VENDOR_DEFINED | 0x0008001UL)
#define CKM_ML_DSA_KEY_PAIR_GEN (CKM_VENDOR_DEFINED | 0x0008002UL)

#define CKM_ML_KEM (CKM_VENDOR_DEFINED | 0x0008003UL)
#define CKM_ML_DSA (CKM_VENDOR_DEFINED | 0x0008004UL)

/* vendor defined keytypes*/
#define CKK_ML_DSA (CKK_VENDOR_DEFINED | 0x0004001UL)
#define CKK_ML_KEM (CKK_VENDOR_DEFINED | 0x0004002UL)

/* parameter set types */

typedef CK_ULONG CK_ML_DSA_PARAMETER_SET_TYPE;

typedef CK_ML_DSA_PARAMETER_SET_TYPE CK_PTR CK_ML_DSA_PARAMETER_SET_TYPE_PTR;

#define CKP_ML_DSA_44          0x00000001UL
#define CKP_ML_DSA_65          0x00000002UL


typedef CK_ULONG CK_ML_KEM_PARAMETER_SET_TYPE;

typedef CK_ML_KEM_PARAMETER_SET_TYPE CK_PTR CK_ML_KEM_PARAMETER_SET_TYPE_PTR;

#define CKP_ML_KEM_512          0x00000021UL
#define CKP_ML_KEM_768          0x00000022UL
#define CKP_ML_KEM_1024         0x00000023UL

/*
 * CK_ML_KEM_PARAMS provides the parameters to the
 * CKM_ML_KEM mechanisms, where each party contributes one key pair.
 */
typedef struct CK_ML_KEM_PARAMS {
  CK_BYTE_PTR pPublicKey;
  CK_ULONG ulPublicKeyLen;
} CK_ML_KEM_PARAMS;

typedef CK_ML_KEM_PARAMS CK_PTR CK_ML_KEM_PARAMS_PTR;

#define CKF_ENCAPSULATE            (CKF_EXTENSION | 0x00000001UL)
#define CKF_DECAPSULATE            (CKF_EXTENSION | 0x00000002UL)

#endif /* _ATOS_PKCS11_H_ */

