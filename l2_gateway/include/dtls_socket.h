
#ifndef _DTLS_SOCKET_H_
#define _DTLS_SOCKET_H_

#include "l2_gateway.h"
#include "wolfssl.h"


typedef struct DtlsSocket
{
    L2_Gateway bridge; /**< The bridge associated with the packet socket. */

    char const *own_ip_address;
    uint16_t client_port;
    uint16_t server_port;
    l2_gateway_configg *config;

    char const *target_ip_address;
    uint16_t target_port;
    wolfssl_endpoint *dtls_server_endpoint;
    wolfssl_endpoint *dtls_client_endpoint;
    wolfssl_session *dtls_server_session;
    wolfssl_session *dtls_client_session; // holds its own file descripor since it is handled blocking

    wolfssl_session* connection_session[5];

}DtlsSocket;

int init_dtls_socket_gateway(DtlsSocket* gateway, const l2_gateway_configg* config, connected_channel channel);

#endif // _DTLS_SOCKET_H_
