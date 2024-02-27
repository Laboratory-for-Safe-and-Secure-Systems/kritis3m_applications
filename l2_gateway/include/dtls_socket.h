
#ifndef _DTLS_SOCKET_H_
#define _DTLS_SOCKET_H_

#include "l2_gateway.h"
#include "wolfssl.h"

enum connection_state
{
    NOT_CONNECTED,
    DISCONNECTED,
    DTLS_CONNECTING,
    DTLS_CONNECTED,
};
typedef struct DtlsSocket DtlsSocket;
struct DtlsSocket
{
    L2_Gateway bridge; /**< The bridge associated with the packet socket. */

    char const *own_ip_address;
    uint16_t listening_port;
    char const *target_ip_address;
    uint16_t target_port;
    wolfssl_endpoint *dtls_endpoint;
    wolfssl_session *dtls_session;
};

int init_dtls_socket_bridge(DtlsSocket *bridge,
                            struct dtls_config const *config, dtls_type type);

int dtls_socket_send(DtlsSocket *bridge, uint8_t *buffer, int buffer_len, int frame_start);

int dtls_socket_receive(DtlsSocket *bridge);

int dtls_socket_pipe(DtlsSocket *bridge);

int dtls_socket_close(DtlsSocket *bridge);

#endif // _DTLS_SOCKET_H_
