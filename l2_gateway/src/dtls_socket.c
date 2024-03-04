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
int dtls_socket_server_send(DtlsSocket *gateway, uint8_t *buffer, int buffer_len, int frame_start);

int init_dtls_client_socket_gateway(DtlsSocket *gateway, const l2_gateway_configg *config, connected_channel channel)
{

    gateway->own_ip_address = (channel == ASSET) ? config->asset_ip : config->tunnel_ip;
    gateway->own_port = (channel == ASSET) ? config->asset_port : config->tunnel_port;
    gateway->target_port = (channel == ASSET) ? config->asset_target_port : config->tunnel_target_port;
    gateway->target_ip_address = (channel == ASSET) ? config->asset_target_ip : config->tunnel_target_ip;
    gateway->bridge.channel = channel;
    gateway->bridge.type = DTLS_CLIENT_SOCKET;
    int err;

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
    gateway->dtls_endpoint = wolfssl_setup_dtls_client_endpoint(&config->dtls_config);
    if (gateway->dtls_endpoint == NULL)
    {
        LOG_ERR("failed creating wolfssl dtls endopoint");
        return -1;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        LOG_ERR("Request socket fd failed, errno: %d", sockfd);
        return -1;
    }
    gateway->bridge.fd = sockfd;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
    {
        LOG_ERR("setsockopt(SO_REUSEADDR) failed: errer %d\n", errno);
        dtls_socket_close(gateway);
        return -1;
    }

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
    net_addr_pton(AF_INET, gateway->target_ip_address, &server_sock.sin_addr);
    ret = wolfssl_dtls_client_handshake(gateway->dtls_session, &server_sock);
    if (ret != WOLFSSL_SUCCESS)
    {
        LOG_ERR("failed to create a wolfSSL session ");
        return -1;
    }
    wolfssl_send(gateway->dtls_session, "I hear you fashizzle!\n", sizeof("I hear you fashizzle!\n"));

    gateway->bridge.vtable[call_receive] = dtls_socket_client_receive;
    gateway->bridge.vtable[call_send] = dtls_socket_client_send;
    gateway->bridge.vtable[call_pipe] = dtls_socket_pipe;
    gateway->bridge.vtable[call_close] = dtls_socket_close;
    return 1;
}

int init_dtls_server_socket_gateway(DtlsSocket *gateway, const l2_gateway_configg *config, connected_channel channel)
{
    int err;

    gateway->own_ip_address = (channel == ASSET) ? config->asset_ip : config->tunnel_ip;
    gateway->own_port = (channel == ASSET) ? config->asset_port : config->tunnel_port;
    gateway->target_port = (channel == ASSET) ? config->asset_target_port : config->tunnel_target_port;
    gateway->target_ip_address = (channel == ASSET) ? config->asset_target_ip : config->tunnel_target_ip;
    gateway->bridge.channel = channel;
    gateway->bridge.type = DTLS_SERVER_SOCKET;

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
        return -1;
    }
    gateway->dtls_endpoint = wolfssl_setup_dtls_server_endpoint(&config->dtls_config);
    if (gateway->dtls_endpoint == NULL)
    {
        LOG_ERR("failed creating wolfssl dtls endopoint");
        return -1;
    }

    int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0)
    {
        LOG_ERR("Request socket fd failed, errno: %d", server_fd);
        return -1;
    }
    gateway->bridge.fd = server_fd;

    if (setsockopt(gateway->bridge.fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
    {
        LOG_ERR("setsockopt(SO_REUSEADDR) failed: errer %d\n", errno);
        dtls_socket_close(gateway);
        return -1;
    }
    if (bind(server_fd, (struct sockaddr *)&server_sock, sizeof(server_sock)) < 0)
    {
        LOG_ERR("bind");
        return -1;
    }
    struct sockaddr_in client_sock;
    int client_len = sizeof(client_sock);
    uint8_t buff[RECV_BUFFER_SIZE];
    while (1)
    {
        memset(&client_sock, 0, sizeof(client_sock));

        gateway->dtls_session = wolfssl_create_session(gateway->dtls_endpoint, server_fd);
        if (gateway->dtls_session == NULL)
        {
            LOG_ERR("failed to create a wolfSSL session ");
            return -1;
        }
        ret = wolfssl_dtls_server_handshake(gateway->dtls_session, &client_sock);
        if (ret < 0)
        {
            LOG_ERR("recvfrom error: %d", ret);
            return -1;
        }
        char ack[] = "I hear you fashizzle!\n";
        wolfssl_send(gateway->dtls_session, ack, sizeof(ack));
    }

    // register functions
    gateway->bridge.vtable[call_receive] = dtls_socket_server_receive;
    gateway->bridge.vtable[call_send] = dtls_socket_server_send;
    gateway->bridge.vtable[call_pipe] = dtls_socket_pipe;
    gateway->bridge.vtable[call_close] = dtls_socket_close;
    return -1;
}
int dtls_socket_client_send(DtlsSocket *gateway, uint8_t *buffer, int buffer_len, int frame_start)
{
    return 0;
}

// in case of server, we create a new connection
int dtls_socket_client_receive(DtlsSocket *gateway)
{
    return 0;
}

// in case of server, we create a new connection
int dtls_socket_server_receive(DtlsSocket *gateway)
{
    return 0;
}
int dtls_socket_server_send(DtlsSocket *gateway, uint8_t *buffer, int buffer_len, int frame_start)
{
    return 0;
}

int dtls_socket_pipe(DtlsSocket *bridge)
{

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