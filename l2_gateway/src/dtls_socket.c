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

LOG_MODULE_REGISTER(dtls_gateway);
int dtls_socket_server_receive(DtlsSocket *gateway);
int dtls_socket_client_receive(DtlsSocket *gateway);
int dtls_socket_client_send(DtlsSocket *gateway, uint8_t *buffer, int buffer_len, int frame_start);

int init_dtls_client_socket_gateway(DtlsSocket *gateway, const l2_gateway_configg *config, connected_channel channel)
{

    gateway->own_ip_address = (channel == ASSET) ? config->asset_ip : config->tunnel_ip;
    gateway->own_port = (channel == ASSET) ? config->asset_port : config->tunnel_port;
    gateway->target_port = (channel == ASSET) ? config->asset_target_port : config->tunnel_target_port;
    gateway->target_ip_address = (channel == ASSET) ? config->asset_target_ip : config->tunnel_target_ip;
    gateway->dtls_endpoint = wolfssl_setup_dtls_client_endpoint(&config->dtls_config);
    gateway->bridge.channel = channel;
    gateway->bridge.type = DTLS_CLIENT_SOCKET;
    if (gateway->dtls_endpoint == NULL)
    {
        LOG_ERR("failed creating wolfssl dtls endopoint");
        return -1;
    }

    gateway->bridge.fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (gateway->bridge.fd < 0)
    {
        LOG_ERR("Request socket fd failed, errno: %d", gateway->bridge.fd);
        return -1;
    }
    if (setsockopt(gateway->bridge.fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
    {
        LOG_ERR("setsockopt(SO_REUSEADDR) failed: errer %d\n", errno);
        dtls_socket_close(gateway);
        return -1;
    }
    setblocking(gateway->bridge.fd, true);
    struct sockaddr_in client_sock;
    memset(&client_sock, 0, sizeof(client_sock));
    client_sock.sin_family = AF_INET;
    client_sock.sin_port = htons(gateway->own_port);
    int ret = net_addr_pton(AF_INET, gateway->own_ip_address, &client_sock.sin_addr);
    if (ret < 0)
    {
        LOG_ERR("Failed to convert IP address: %d", ret);
        dtls_socket_close(gateway);
        return -1;
    }

    ret = add_ipv4_address((channel == ASSET) ? network_interfaces()->asset : network_interfaces()->tunnel,
                           client_sock.sin_addr);
    if (ret < 0)
    {
        LOG_ERR("couldn't assign ip addr to iface, errno: %d ", errno);
        return -1;
    }
    ret = bind(gateway->bridge.fd, (struct sockaddr *)&client_sock, sizeof(client_sock));
    // check
    if (ret < 0)
    {
        LOG_ERR("Failed to bind socket: %d", ret);
        dtls_socket_close(gateway);
        return -1;
    }

    struct sockaddr_in server_sock;
    memset(&server_sock, 0, sizeof(server_sock));
    server_sock.sin_family = AF_INET;
    server_sock.sin_port = htons(gateway->own_port);
    // ret = connect(gateway->bridge.fd, (struct sockaddr *)&server_sock, sizeof(server_sock));
    // if (ret < 0)
    // {
    //     LOG_ERR("Failed to connect to server: %d", ret);
    //     dtls_socket_close(gateway);
    //     return -1;
    // }


        gateway->dtls_session = wolfssl_create_session(gateway->dtls_endpoint, gateway->bridge.fd);

        if (gateway->dtls_session == NULL)
        {
            LOG_ERR("failed to create a wolfSSL session ");
            return -1;
        }

        ret = wolfssl_dtls_client_handshake(gateway->dtls_session, &server_sock);
        if (ret < 0)
        {
            LOG_ERR("Failed to perform handshake: %d", ret);
            dtls_socket_close(gateway);
            return -1;
        }



    gateway->bridge.vtable[call_receive] = dtls_socket_client_receive;
    gateway->bridge.vtable[call_send] = dtls_socket_client_send;
    gateway->bridge.vtable[call_pipe] = dtls_socket_pipe;
    gateway->bridge.vtable[call_close] = dtls_socket_close;
    return 1;
}
int init_dtls_server_socket_gateway(DtlsSocket *gateway, const l2_gateway_configg *config, connected_channel channel)
{

    gateway->own_ip_address = (channel == ASSET) ? config->asset_ip : config->tunnel_ip;
    gateway->own_port = (channel == ASSET) ? config->asset_port : config->tunnel_port;
    gateway->target_ip_address = (channel == ASSET) ? config->asset_target_ip : config->tunnel_target_ip;
    gateway->dtls_endpoint = wolfssl_setup_dtls_server_endpoint(&config->dtls_config);
    gateway->bridge.channel = channel;
    gateway->bridge.type = DTLS_SERVER_SOCKET;

    if (gateway->dtls_endpoint < 0)
    {
        LOG_ERR("Failed to create endpoint");
        return -1;
    }
    gateway->bridge.fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (setsockopt(gateway->bridge.fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
    {
        LOG_ERR("setsockopt(SO_REUSEADDR) failed: errer %d\n", errno);
        dtls_socket_close(gateway);
        return -1;
    }
    struct sockaddr_in server_sock;
    memset(&server_sock, 0, sizeof(server_sock));
    server_sock.sin_family = AF_INET;
    server_sock.sin_port = htons(gateway->own_port);
    int ret = net_addr_pton(AF_INET, gateway->own_ip_address, &server_sock.sin_addr);
    if (ret < 0)
    {
        LOG_ERR("Failed to convert IP address: %d", ret);
        dtls_socket_close(gateway);
        return -1;
    }
    ret = add_ipv4_address((channel == ASSET) ? network_interfaces()->asset : network_interfaces()->tunnel,
                           server_sock.sin_addr);
    if (ret < 0)
    {
        LOG_ERR("couldn't assign ip addr to iface, errno: %d ", errno);
    }
    ret = bind(gateway->bridge.fd,
               (struct sockaddr *)&server_sock,
               sizeof(server_sock));
    // check
    if (ret < 0)
    {
        LOG_ERR("Failed to bind socket: %d, errno: %d", ret, errno);
        dtls_socket_close(gateway);
        return -1;
    }

    // register functions
    gateway->bridge.vtable[call_receive] = dtls_socket_server_receive;
    gateway->bridge.vtable[call_send] = dtls_socket_send;
    gateway->bridge.vtable[call_pipe] = dtls_socket_pipe;
    gateway->bridge.vtable[call_close] = dtls_socket_close;
    return -1;
}
int dtls_socket_client_send(DtlsSocket *gateway, uint8_t *buffer, int buffer_len, int frame_start)
{
    int ret = -1;
    // struct sockaddr_in server_sock;
    // memset(&server_sock, 0, sizeof(server_sock));
    // server_sock.sin_family = AF_INET;
    // server_sock.sin_port = htons(gateway->target_port);
    // int ret = net_addr_pton(AF_INET, gateway->target_ip_address, &server_sock.sin_addr);
    // if (ret < 0)
    // {
    //     LOG_ERR("Failed to convert IP address: %d", ret);
    //     dtls_socket_close(gateway);
    //     return -1;
    // }
    // ret = sendto(gateway->bridge.fd, buffer + frame_start, buffer_len - frame_start, 0, (struct sockaddr *)&server_sock, sizeof(server_sock));
    // if (ret < 0)
    // {
    //     LOG_ERR("Failed to send data: %d", ret);
    //     return -1;
    // }
    // return ret;

    if (gateway->dtls_session == NULL)
    {
        setblocking(gateway->bridge.fd, true);

        gateway->dtls_session = wolfssl_create_session(gateway->dtls_endpoint, gateway->bridge.fd);

        if (gateway->dtls_session == NULL)
        {
            LOG_ERR("failed to create a wolfSSL session ");
            return -1;
        }

        struct sockaddr_in server_sock;
        memset(&server_sock, 0, sizeof(server_sock));
        server_sock.sin_family = AF_INET;
        server_sock.sin_port = htons(gateway->target_port);
        ret = net_addr_pton(AF_INET, gateway->target_ip_address, &server_sock.sin_addr);
        if (ret < 0)
        {
            LOG_ERR("Failed to convert IP address: %d", ret);
            dtls_socket_close(gateway);
            return -1;
        }

        ret = wolfssl_dtls_client_handshake(gateway->dtls_session, &server_sock);
        if (ret < 0)
        {
            LOG_ERR("Failed to perform handshake: %d", ret);
            dtls_socket_close(gateway);
            return -1;
        }

        // ret = wolfssl_handshake(gateway->dtls_session);
        // if (ret < 0)
        // {
        //     LOG_ERR("Failed to perform handshake: %d", ret);
        //     dtls_socket_close(gateway);
        //     return -1;
        // }
    }

    ret = wolfssl_send(gateway->dtls_session, buffer + frame_start, buffer_len - frame_start);
    if (ret < 0)
    {
        LOG_ERR("Failed to send data: %d", ret);
        return -1;
    }
    return ret;
}

int dtls_socket_send(DtlsSocket *gateway, uint8_t *buffer, int buffer_len, int frame_start)
{

    struct sockaddr_in server_sock;
    memset(&server_sock, 0, sizeof(server_sock));
    server_sock.sin_family = AF_INET;
    server_sock.sin_port = htons(gateway->target_port);
    int ret = net_addr_pton(AF_INET, gateway->target_ip_address, &server_sock.sin_addr);
    if (ret < 0)
    {
        LOG_ERR("Failed to convert IP address: %d", ret);
        dtls_socket_close(gateway);
        return -1;
    }
    ret = sendto(gateway->bridge.fd, buffer + frame_start, buffer_len - frame_start, 0, (struct sockaddr *)&server_sock, sizeof(server_sock));
    if (ret < 0)
    {
        LOG_ERR("Failed to send data: %d", ret);
        return -1;
    }
    return ret;
    if (gateway->dtls_session == NULL)
    {
        return -1;
    }

    ret = wolfssl_send(gateway->dtls_session, buffer + frame_start, buffer_len - frame_start);
    if (ret < 0)
    {
        LOG_ERR("Failed to send data: %d", ret);
        return -1;
    }
    return ret;
}

// in case of server, we create a new connection
int dtls_socket_client_receive(DtlsSocket *gateway)
{

    struct sockaddr_in server_sock;
    memset(&server_sock, 0, sizeof(server_sock));
    server_sock.sin_family = AF_INET;
    server_sock.sin_port = htons(gateway->target_port);
    int ret = net_addr_pton(AF_INET, gateway->target_ip_address, &server_sock.sin_addr);
    if (ret < 0)
    {
        LOG_ERR("Failed to convert IP address: %d", ret);
        dtls_socket_close(gateway);
        return -1;
    }
    int socketlen = sizeof(server_sock);
    ret = recvfrom(gateway->bridge.fd, gateway->bridge.buf, gateway->bridge.len, 0, (struct sockaddr *)&server_sock, &socketlen);
    if (ret < 0)
    {
        LOG_ERR("Failed to receive data: %d", ret);
        return -1;
    }
    return ret;

    ret = wolfssl_receive(gateway->dtls_session, gateway->bridge.buf, sizeof(gateway->bridge.buf));
    if (ret < 0)
    {
        LOG_ERR("Failed to receive data: %d", ret);
        return -1;
    }

    return ret;
}

// in case of server, we create a new connection
int dtls_socket_server_receive(DtlsSocket *gateway)
{
    int ret = 0;
    if (gateway->dtls_session == NULL)
    {

        struct sockaddr_in client_address;
        memset(&client_address, 0, sizeof(client_address));
        int cliLen = sizeof(client_address);

        ret = (int)recvfrom(gateway->bridge.fd, gateway->bridge.buf, sizeof(gateway->bridge.buf), 0,
                            (struct sockaddr *)&client_address, &cliLen);
        if (ret < 0)
        {
            LOG_ERR("recvfrom error: %d", ret);
            return -1;
        }

        ret = wolfssl_dtls_server_handshake(gateway->dtls_session, &client_address);

        if (ret < 0)
        {
            LOG_ERR("recvfrom error: %d", ret);
            return -1;
        }
    }

    // struct sockaddr_in server_sock;
    // memset(&server_sock, 0, sizeof(server_sock));
    // server_sock.sin_family = AF_INET;
    // server_sock.sin_port = htons(gateway->target_port);
    // int ret = net_addr_pton(AF_INET, gateway->target_ip_address, &server_sock.sin_addr);
    // if (ret < 0)
    // {
    //     LOG_ERR("Failed to convert IP address: %d", ret);
    //     dtls_socket_close(gateway);
    //     return -1;
    // }
    // int socklent =sizeof(server_sock);
    // ret = recvfrom(gateway->bridge.fd, gateway->bridge.buf, gateway->bridge.len, 0, (struct sockaddr *)&server_sock, &socklent);
    // if (ret < 0){
    //     LOG_ERR("Failed to receive data: %d", ret);
    //     return -1;
    // }
    // return ret;
    // if (gateway->dtls_session == NULL)
    // {
    //     struct sockaddr_in client_address;
    //     memset(&client_address, 0, sizeof(client_address));
    //     socklen_t client_address_len = sizeof(client_address);
    //     int ret = recvfrom(gateway->bridge.fd, gateway->bridge.buf, gateway->bridge.len, 0, (struct sockaddr *)&client_address, &client_address_len);
    //     if (ret < 0)
    //     {
    //         LOG_ERR("Failed to receive data: %d", ret);
    //         dtls_socket_close(gateway);
    //         return -1;
    //     }

    //     setblocking(gateway->bridge.fd, true);

    //     ret = connect(gateway->bridge.fd, (struct sockaddr *)&client_address, client_address_len);
    //     if (ret < 0)
    //     {
    //         LOG_ERR("Failed to connect to client, errno: %d", errno);
    //         dtls_socket_close(gateway);
    //         return -1;
    //     }
    //     gateway->dtls_session = wolfssl_create_session(gateway->dtls_endpoint, gateway->bridge.fd);
    //     if (gateway->dtls_session == NULL)
    //     {
    //         LOG_ERR("Failed to create session");
    //         dtls_socket_close(gateway);
    //         return -1;
    //     }
    //     ret = wolfssl_handshake(gateway->dtls_session);
    //     if (ret < 0)
    //     {
    //         LOG_ERR("Failed to perform handshake: %d", ret);
    //         dtls_socket_close(gateway);
    //         return -1;
    //     }
    // }

    ret = wolfssl_receive(gateway->dtls_session, gateway->bridge.buf, sizeof(gateway->bridge.buf));
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