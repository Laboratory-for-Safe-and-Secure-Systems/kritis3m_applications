/**
 * @file dtls_socket.h
 * @brief This file contains the declaration of the DtlsSocket interface.
 * 
 * To use the DTLS interface, it must be initialized with the function init_dtls_socket_gateway.
 * 
 * @bug In the handshake in dtls_socket_connect it is required both the server and the client to handshake. 
 * @bug But if the counterpart server is not ready, the client will not be able to handshake.
 * @bug As a consequence, the client handshake is reinitiated after a timeout. Which leads to longer connection times.

*/
#ifndef _DTLS_SOCKET_H_
#define _DTLS_SOCKET_H_

#include "l2_gateway.h"
#include "wolfssl.h"

enum dtls_type
{
    DTLS_SERVER,
    DTLS_CLIENT
};

/**
 * @brief Structure representing a DTLS session.
 * 
 * @todo in the future, the complete specific code should be moved to the wolfssl module
 */
typedef struct dtls_session
{
    wolfssl_session *session; /**< Pointer to the wolfSSL session object */
    enum dtls_type type; /** indicates if the session is a server or a client session */
    int fd; /**< The file descriptor associated with the session */
} dtls_session;

/**
 * @brief Structure representing the DTLS Interface structure, which is used as a concrete implementation for l2_gateway.
 * 
 * @todo At the moment the one client and one server is used. In the future, the number of sessions should be configurable.
 */
typedef struct DtlsSocket
{
    L2_Gateway bridge; 

    char const *own_ip_address;
    uint16_t client_port;
    uint16_t server_port;
    l2_gateway_config const *config;

    char const *target_ip_address;
    uint16_t target_port;
    wolfssl_endpoint *dtls_server_endpoint;
    wolfssl_endpoint *dtls_client_endpoint;
    dtls_session dtls_sessions[5];


} DtlsSocket;

int init_dtls_socket_gateway(DtlsSocket *gateway, const l2_gateway_config *config, connected_channel channel);

#endif // _DTLS_SOCKET_H_
