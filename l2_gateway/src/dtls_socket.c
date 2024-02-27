#include "dtls_socket.h"

#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>

#include "logging.h"
#include "poll_set.h"
#include "networking.h"
#include "wolfssl.h"

#define RECV_BUFFER_SIZE 2048
LOG_MODULE_REGISTER(dtls_socket);

int init_dtls_socket_bridge(DtlsSocket *bridge,
                            struct dtls_config const *config, dtls_type type)
{
    // initialize bridge

    if (type == DTLS_SERVER)
    {
        LOG_INF("Starting new dtls server on %s:%d", config->own_ip_address, config->listening_port);

        /* Create the TLS endpoint */
    }
    else if (type == DTLS_CLIENT)
    {
        // starting new client
        LOG_INF("Starting new dtls client on %s:%d", config->target_ip_address, config->target_port);

        /* Create the TLS endpoint */
        bridge->dtls_endpoint = wolfssl_setup_client_endpoint(&config->dtls_config);
    }
    // check tls_endpoint
    if (bridge->dtls_endpoint == NULL)
    {
        LOG_ERR("Failed to create TLS endpoint");
        // kill dtls
        return -1;
    }

    if (type == DTLS_SERVER)
    {
        bridge->dtls_endpoint = wolfssl_setup_dtls_server_endpoint(&config->dtls_config);
        if (setsockopt(bridge->bridge.fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
        {
            LOG_ERR("setsockopt(SO_REUSEADDR) failed: errer %d\n", errno);
            // kill dtls
            return -1;
        }
        struct sockaddr_in server_sock;
        memset(&server_sock, 0, sizeof(server_sock));
        int ret = net_addr_pton(AF_INET, config->own_ip_address, &server_sock.sin_addr);
        if (ret < 0)
        {
            LOG_ERR("Failed to convert IP address: %d", ret);
            // kill dtls
            return -1;
        }
        ret = bind(bridge->bridge.fd, (struct sockaddr *)&server_sock, sizeof(server_sock));
        // check
        if (ret < 0)
        {
            LOG_ERR("Failed to bind socket: %d", ret);
            // kill dtls
            return -1;
        }

        struct sockaddr_in client_address;
        memset(&client_address, 0, sizeof(client_address));
        socklen_t client_address_len = sizeof(client_address);

        setblocking(bridge->bridge.fd, true);

        ret = recvfrom(bridge->bridge.fd, bridge->bridge.buf, bridge->bridge.len, 0, (struct sockaddr *)&client_address, &client_address_len);
        if (ret < 0)
        {
            LOG_ERR("Failed to receive data: %d", ret);
            return -1;
        }
        ret = connect(bridge->bridge.fd, (struct sockaddr *)&client_address, client_address_len);
        if (ret < 0)
        {
            LOG_ERR("Failed to connect to client, errno: %d", errno);
            return -1;
        }
        bridge->dtls_session = wolfssl_create_session(bridge->dtls_endpoint, bridge->bridge.fd);
        if (bridge->dtls_session == NULL)
        {
            LOG_ERR("Failed to create session");
            return -1;
        }
        ret = wolfssl_handshake(bridge->dtls_session);
        if (ret < 0)
        {
            LOG_ERR("Failed to perform handshake: %d", ret);
        }
        ret = wolfssl_handshake(bridge->dtls_session);
        if (ret < 0)
        {
            LOG_ERR("Failed to perform handshake: %d", ret);
            return -1;
        }

        setblocking(bridge->bridge.fd, false);
        // vtable overwrite function pointers
        bridge->bridge.vtable[call_receive] = dtls_socket_receive;
        bridge->bridge.vtable[call_send] = dtls_socket_send;
        bridge->bridge.vtable[call_pipe] = dtls_socket_pipe;
    }
    return 0;
}
int dtls_socket_send(DtlsSocket *bridge, uint8_t *buffer, int buffer_len, int frame_start)
{

    int ret = wolfssl_send(bridge->dtls_session, buffer + frame_start, buffer_len - frame_start);
    if (ret < 0)
    {
        LOG_ERR("Failed to send data: %d", ret);
        return -1;
    }
    return ret;
}

// in case of server, we create a new connection
int dtls_socket_receive(DtlsSocket *bridge)
{
    int ret = wolfssl_receive(bridge->dtls_session, bridge->bridge.buf, sizeof(bridge->bridge.buf));
    if (ret < 0)
    {
        LOG_ERR("Failed to receive data: %d", ret);
        return -1;
    }

    return ret;
}

int dtls_socket_pipe(DtlsSocket *bridge)
{
    /*********ANY PRE_PROCESSING?***************/

    /*********PASS DATA************************/
    int buffer_start = 0;
    // check if pipe is valid
    if (bridge->bridge.l2_gw_pipe == NULL)
    {
        LOG_ERR("Pipe is not valid");
        return -1;
    }
    int ret = bridge->bridge.l2_gw_pipe->vtable[call_send](bridge->bridge.l2_gw_pipe, bridge->bridge.buf, bridge->bridge.len, buffer_start);
    if (ret < 0)
    {
        LOG_ERR("Failed to send data: %d", ret);
        return -1;
    }
    return 0;
}

int dtls_socket_close(DtlsSocket *bridge)
{
    bridge->bridge.l2_gw_pipe = NULL;

    close(bridge->bridge.fd);
    wolfssl_free_session(bridge->dtls_session);
    wolfssl_free_endpoint(bridge->dtls_endpoint);
    free(bridge);

    return 0;
}

// static struct dtls_connection *create_new_connection(DtlsSocket *bridge, struct sockaddr_in *client, int client_len)
// {

//     // reset dtls_connection
//     memset(&local_dtls_connection, 0, sizeof(local_dtls_connection));
//     int session_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
//     if (session_fd < 0)
//     {
//         LOG_ERR("Failed to create socket: %d", ret);
//         return NULL;
//     }
//     struct sockaddr_in gw_ip;
//     socklen_t gw_ip_len = sizeof(gw_ip);
//     memset(&gw_ip, 0, sizeof(gw_ip));
//     int ret = net_addr_ntop(AF_INET, &bridge->own_ip_address, &gw_ip.sin_addr, gw_ip_len);
//     gw_ip.sin_port = htons(bridge->listening_port);

//     int ret = bind(session_fd, (struct sockaddr *)&gw_ip, gw_ip_len);
//     if (ret < 0)
//     {
//         LOG_ERR("Failed to bind socket: %d", ret);
//         return NULL;
//     }
//     local_dtls_connection.dtls_socket = session_fd;
//     if (setsockopt(bridge->bridge.fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
//     {
//         LOG_ERR("setsockopt(SO_REUSEADDR) failed: errer %d\n", errno);
//         // kill dtls
//         return -1;
//     }
//     setblocking(session_fd,true);
//     ret = connect(session_fd, (struct sockaddr *)client, client_len);
//     if ((ret < 0) && (errno != EINPROGRESS))
//     {
//         LOG_ERR("Failed to connect to client: %d", ret);
//         return NULL;
//     }
//     setblocking(session_fd,false);
//     local_dtls_connection.tls_session = wolfssl_create_session(bridge->tls_endpoint, local_dtls_connection.dtls_socket);
//     if (bridge->dtls_session == NULL)
//     {
//         LOG_ERR("Failed to create session");
//         return NULL;
//     }

// #if defined(__ZEPHYR__)
//     /* Store the pointer to the related stack for the client handler thread
//      * (started after the TLS handshake). */
//     pthread_attr_setstack(&local_dtls_connection.thread_attr,
//                           dtls_connection_handler_stack,
//                           K_THREAD_STACK_SIZEOF(dtls_connection_handler_stack));
// #endif
// return &local_dtls_connection;
// }