#ifndef WOLFSSL_H
#define WOLFSSL_H

#include <stdint.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"  


/* Data structure for the library configuration */
struct wolfssl_library_configuration
{
        bool loggingEnabled;

#ifdef WOLFSSL_STATIC_MEMORY
        struct 
        {
                uint8_t* buffer;
                size_t size;
        }
        staticMemoryBuffer;
#endif
};


/* Data structure for the endpoint configuration */
struct wolfssl_endpoint_configuration
{
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
        } 
        private_key;

        struct 
        {
                uint8_t const* buffer;
                size_t size;
        } 
        root_certificate;
};


/* Initialize WolfSSL library.
 *
 * Parameter is a pointer to a filled library_configuration structure.
 *
 * Returns 0 on success, -1 in case of an error (error message is logged to the console).
 */
int wolfssl_init(struct wolfssl_library_configuration* config);


/* Setup a TLS server context.
 *
 * Parameter is a pointer to a filled endpoint_configuration structure.
 *
 * Return value is a pointer to the newly created context or NULl in case of an error
 * (error message is logged to the console).
 */
WOLFSSL_CTX* wolfssl_setup_server_context(struct wolfssl_endpoint_configuration* config);


/* Setup a TLS client context.
 *
 * Parameter is a pointer to a filled endpoint_configuration structure.
 *
 * Return value is a pointer to the newly created context or NULl in case of an error
 * (error message is logged to the console).
 */
WOLFSSL_CTX* wolfssl_setup_client_context(struct wolfssl_endpoint_configuration* config);


/* Perform the TLS handshake for a newly created session.
 *
 * Returns 0 on success, -1 on failure (error message is logged to the console) and a positive
 * integer in case the handshake is not done yet (and you have to call the method again when new
 * data from the peer is present). The return code is then either WOLFSSL_ERROR_WANT_READ or
 * WOLFSSL_ERROR_WANT_WRITE.
 */
int wolfssl_handshake(WOLFSSL* session);


/* Receive new data from the TLS peer (blocking read).
 *
 * Returns the number of received bytes on success, -1 on failure (error message is logged
 * to the console).
 */
int wolfssl_receive(WOLFSSL* session, uint8_t* buffer, int max_size);


/* Send data to the TLS remote peer.
 *
 * Returns 0 on success, -1 on failure (error message is logged to the console). In case 
 * we cannot write the data in one call, WOLFSSL_ERROR_WANT_WRITE is returned, indicating
 * that you have to call the method again (with the same data!) once the socket is writable.
 */
int wolfssl_send(WOLFSSL* session, uint8_t* buffer, int size);


#endif
