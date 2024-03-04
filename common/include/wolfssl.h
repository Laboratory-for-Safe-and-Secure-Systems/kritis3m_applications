#ifndef WOLFSSL_H
#define WOLFSSL_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/wc_pkcs11.h"


/* Data structure for the library configuration */
typedef struct wolfssl_library_configuration
{
        bool loggingEnabled;

        bool secure_element_support;
        char const* secure_element_middleware_path;

#ifdef WOLFSSL_STATIC_MEMORY
        struct 
        {
                uint8_t* buffer;
                size_t size;
        }
        staticMemoryBuffer;
#endif
}
wolfssl_library_configuration;


/* Enum for the different modes during the handshake
 * regarding hybrid signatures. */
enum hybrid_signature_mode
{
        HYBRID_SIGNATURE_MODE_NATIVE = 1,
        HYBRID_SIGNATURE_MODE_ALTERNATIVE = 2,
        HYBRID_SIGNATURE_MODE_BOTH = 3
};


/* Data structure for the endpoint configuration */
typedef struct wolfssl_endpoint_configuration
{
        bool mutual_authentication;
        bool no_encryption;
        bool use_secure_element;
        bool secure_element_import_keys;
        
        enum hybrid_signature_mode hybrid_signature_mode;

        struct
        {
                uint8_t const* buffer;
                size_t size;
        }
        device_certificate_chain;

        struct
        {
                uint8_t const* buffer;
                size_t size;

                /* Additional key in case of hybrid signatures */
                uint8_t const* additional_key_buffer;
                size_t additional_key_size;
        }
        private_key;

        struct
        {
                uint8_t const* buffer;
                size_t size;
        }
        root_certificate;

#if defined(HAVE_SECRET_CALLBACK)
        char const* keylog_file;
#endif
}
wolfssl_endpoint_configuration;


/* Data structure for an endpoint (definition is hidden in source file) */
typedef struct wolfssl_endpoint wolfssl_endpoint;


/* Data structure for an active session (definition is hidden in source file) */
typedef struct wolfssl_session wolfssl_session;


/* Data structure for TLS handshake metics */
typedef struct tls_handshake_metrics
{
        uint32_t duration_us;
        uint32_t txBytes;
        uint32_t rxBytes;
}
tls_handshake_metrics;


/* Data structure for a PKCS#11 module */
typedef struct pkcs11_module
{
#ifdef HAVE_PKCS11
	Pkcs11Dev device;
	Pkcs11Token token;
#endif
	bool initialized;
}
pkcs11_module;


/* Initialize WolfSSL library.
 *
 * Parameter is a pointer to a filled library_configuration structure.
 *
 * Returns 0 on success, -1 in case of an error (error message is logged to the console).
 */
int wolfssl_init(wolfssl_library_configuration const* config);


/* Setup a TLS server endpoint.
 *
 * Parameter is a pointer to a filled endpoint_configuration structure.
 *
 * Return value is a pointer to the newly created endpoint or NULL in case of an error
 * (error message is logged to the console).
 */
wolfssl_endpoint* wolfssl_setup_server_endpoint(wolfssl_endpoint_configuration const* config);


/* Setup a TLS client endpoint.
 *
 * Parameter is a pointer to a filled endpoint_configuration structure.
 *
 * Return value is a pointer to the newly created endpoint or NULL in case of an error
 * (error message is logged to the console).
 */
wolfssl_endpoint* wolfssl_setup_client_endpoint(wolfssl_endpoint_configuration const* config);


/* Create a new session for the endpoint.
 *
 * Parameters are a pointer to a configured endpoint and the socket fd of the underlying
 * network connection.
 * 
 * Return value is a pointer to the newly created session or NULL in case of an error
 * (error message is logged to the console).
 */
wolfssl_session* wolfssl_create_session(wolfssl_endpoint* endpoint, int socket_fd);


/* Perform the TLS handshake for a newly created session.
 *
 * Returns 0 on success, -1 on failure (error message is logged to the console) and a positive
 * integer in case the handshake is not done yet (and you have to call the method again when new
 * data from the peer is present). The return code is then either WOLFSSL_ERROR_WANT_READ or
 * WOLFSSL_ERROR_WANT_WRITE.
 */
int wolfssl_handshake(wolfssl_session* session);


/* Receive new data from the TLS peer.
 *
 * Returns the number of received bytes on success, -1 on failure (error message is logged
 * to the console).
 */
int wolfssl_receive(wolfssl_session* session, uint8_t* buffer, int max_size);


/* Send data to the TLS remote peer.
 *
 * Returns 0 on success, -1 on failure (error message is logged to the console). In case 
 * we cannot write the data in one call, WOLFSSL_ERROR_WANT_WRITE is returned, indicating
 * that you have to call the method again (with the same data!) once the socket is writable.
 */
int wolfssl_send(wolfssl_session* session, uint8_t const* buffer, int size);


/* Get metics of the handshake. */
tls_handshake_metrics wolfssl_get_handshake_metrics(wolfssl_session* session);


/* Close the connection of the active session */
void wolfssl_close_session(wolfssl_session* session);


/* Free ressources of a session. */
void wolfssl_free_session(wolfssl_session* session);


/* Free ressources of an endpoint. */
void wolfssl_free_endpoint(wolfssl_endpoint* endpoint);


#endif
