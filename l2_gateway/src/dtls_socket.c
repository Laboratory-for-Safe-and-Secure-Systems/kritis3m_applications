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
#include "l2_util.h"
#define RECV_BUFFER_SIZE 1600
LOG_MODULE_REGISTER(dtls_gateway);

// register functions
int dtls_socket_receive(DtlsSocket *gateway, int fd, int (*register_cb)(int fd));
int dtls_socket_send(DtlsSocket *gateway, int fd, uint8_t *buffer, int buffer_len, int frame_start);

int dtls_socket_close(DtlsSocket *bridge);
int dtls_socket_pipe(DtlsSocket *gateway);

// just used for handshake
int dtls_socket_client_receive(wolfssl_session *session);
int dtls_socket_server_receive(wolfssl_session *session, DtlsSocket *gateway);
int dtls_socket_client_send(wolfssl_session *session, uint8_t *buffer, int buffer_len, int frame_start);
// just used for handshake
int dtls_socket_server_send(wolfssl_session *session);

int init_dtls_client_socket_gateway(DtlsSocket *gateway);
int init_dtls_server_socket_gateway(DtlsSocket *gateway);

int add_session(wolfssl_session *sessions[], int sessions_len, wolfssl_session *session)
{
    int ret = -1;
    for (int i = 0; i < sessions_len; i++)
    {
        if (sessions[i] == NULL)
        {
            sessions[i] = session;
            ret = 1;
            break;
        }
    }
    return ret;
}
int remove_session(wolfssl_session *sessions[], int sessions_len, wolfssl_session *session)
{
    int ret = -1;
    for (int i = 0; i < sessions_len; i++)
    {
        if (sessions[i] == session)
        {
            // session found
            ret = 1;
            // check if next session is null, if so, we are done
            if (i < (sessions_len - 1) && sessions[i + 1] == NULL)
            {
                sessions[i] = NULL;
            }
            else if (i < (sessions_len - 1) && sessions[i + 1] != NULL)
            {
                for (int j = i; j < (sessions_len - 1); j++)
                {
                    sessions[i] = sessions[i + 1];
                }
            }
            else if (i == (sessions_len - 1))
            {
                sessions[i] = NULL;
            }
            else
            {
                LOG_ERR("failed to remove session from list, unknown error");
            }
            break;
        }
    }
    return ret;
}
wolfssl_session *find_session_by_fd(int fd, wolfssl_session *sessions[], int sessions_len)
{
    wolfssl_session *ret = NULL;
    for (int i = 0; i < sessions_len; i++)
    {
        if (sessions[i] == NULL)
        {
            break;
        }
        wolfssl_session *session = sessions[i];
        if (get_fd(session) == fd)
        {
            ret = sessions[i];
            break;
        }
    }
    return ret;
}

int init_dtls_socket_gateway(DtlsSocket *gateway, const l2_gateway_configg *config, connected_channel channel)
{
    int ret = -1;

    gateway->bridge.vtable[call_close] = dtls_socket_close;
    // initialisation
    gateway->client_port = (channel == ASSET) ? CONFIG_NET_IP_ASSET_CLIENT_PORT : CONFIG_NET_IP_TUNNEL_CLIENT_PORT; // we dont care about the port
    gateway->server_port = (channel == ASSET) ? config->asset_port : config->tunnel_port;

    gateway->target_port = (channel == ASSET) ? config->asset_target_port : config->tunnel_target_port;

    gateway->own_ip_address = (channel == ASSET) ? config->asset_ip : config->tunnel_ip;
    gateway->target_ip_address = (channel == ASSET) ? config->asset_target_ip : config->tunnel_target_ip;

    gateway->bridge.channel = channel;
    gateway->bridge.type = DTLS_SERVER_SOCKET;
    gateway->config = config;

    for (int i = 0; i < sizeof(gateway->connection_session) / sizeof(gateway->connection_session[0]); i++)
    {
        gateway->connection_session[i] = NULL;
    }

    // interface configuration
    // this part will be outsourced to the networking module, since it shouldnt be part of application logic

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    ret = net_addr_pton(AF_INET, gateway->own_ip_address, &addr.sin_addr);
    if (ret < 0)
    {
        LOG_ERR("Failed to convert IP address: %d", ret);
        dtls_socket_close(gateway);
        return -1;
    }

    ret = add_ipv4_address((channel == ASSET) ? network_interfaces()->asset : network_interfaces()->tunnel,
                           addr.sin_addr);
    if (ret < 0)
    {
        LOG_ERR("couldn't assign ip addr to iface, errno: %d ", errno);
        return -1;
    }

    ret = init_dtls_server_socket_gateway(gateway);
    if (ret < 0)
    {
        LOG_ERR("failed to initialize dtls client socket");
        dtls_socket_close(gateway);
    }

    ret = init_dtls_client_socket_gateway(gateway);
    if (ret < 0)
    {
        LOG_ERR("failed to initialize dtls client socket");
        dtls_socket_close(gateway);
    }

    gateway->bridge.vtable[call_receive] = dtls_socket_receive;
    gateway->bridge.vtable[call_send] = dtls_socket_send;
    gateway->bridge.vtable[call_pipe] = dtls_socket_pipe;
    return 1;
}

int init_dtls_client_socket_gateway(DtlsSocket *gateway)
{
    int ret = -1;
    struct sockaddr_in helper_addr;
    int helper_addr_len = sizeof(helper_addr);

    gateway->dtls_client_endpoint = wolfssl_setup_dtls_client_endpoint(&gateway->config->dtls_config);
    if (gateway->dtls_client_endpoint == NULL)
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

    setblocking(sockfd, false);
    l2_gateway_register_fd(sockfd, POLLIN | POLLOUT | POLLHUP);
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
    {
        LOG_ERR("setsockopt(SO_REUSEADDR) failed: errer %d\n", errno);
        dtls_socket_close(gateway);
        return -1;
    }
    ret = net_addr_pton(AF_INET, gateway->own_ip_address, &helper_addr.sin_addr);
    if (ret < 0)
    {
        LOG_ERR("failed to convert ip address");
        return -1;
    }
    helper_addr.sin_family = AF_INET;
    helper_addr.sin_port = htons(gateway->client_port);

    ret = bind(sockfd, (struct sockaddr *)&helper_addr, helper_addr_len);
    if (ret < 0)
    {
        LOG_ERR("failed to bind socket, errno: %d", errno);
        return -1;
    }

    helper_addr.sin_port = htons(gateway->target_port);
    ret = net_addr_pton(AF_INET, gateway->target_ip_address, &helper_addr.sin_addr);
    if (ret < 0)
    {
        LOG_ERR("conversion of target ip addr didnt work, errno %d", errno);
        return -1;
    }
    ret = connect(sockfd, (struct sockaddr *)&helper_addr, helper_addr_len);
    if (ret < 0)
    {
        LOG_ERR("failed to connect client to peer, errno %d ", errno);
        return -1;
    }

    setblocking(sockfd, false);
    l2_gateway_register_fd(sockfd, POLLIN | POLLOUT | POLLHUP);
    gateway->dtls_client_session = wolfssl_create_session(gateway->dtls_client_endpoint, sockfd);
    if (gateway->dtls_client_session == NULL)
    {
        LOG_ERR("failed to create a wolfSSL session ");
        return -1;
    }
    wolfssl_handshake(gateway->dtls_client_session);
    return 1;
}

int init_dtls_server_socket_gateway(DtlsSocket *gateway)
{
    int ret;

    gateway->dtls_server_endpoint = wolfssl_setup_dtls_server_endpoint(&gateway->config->dtls_config);
    if (gateway->dtls_server_endpoint == NULL)
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

    if (setsockopt(gateway->bridge.fd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)) < 0)
    {
        LOG_ERR("setsockopt(SO_REUSEADDR) failed: errer %d\n", errno);
        dtls_socket_close(gateway);
        return -1;
    }

    struct sockaddr_in server_sock;
    memset(&server_sock, 0, sizeof(server_sock));
    server_sock.sin_family = AF_INET;
    server_sock.sin_port = htons(gateway->server_port);
    ret = net_addr_pton(AF_INET, gateway->own_ip_address, &server_sock.sin_addr);

    if (ret < 0)
    {
        LOG_ERR("failed to convert ip address");
        return -1;
    }
    if (bind(server_fd, (struct sockaddr *)&server_sock, sizeof(server_sock)) < 0)
    {
        LOG_ERR("bind");
        return -1;
    }
    gateway->dtls_server_session = wolfssl_create_session(gateway->dtls_server_endpoint, server_fd);
    if (gateway->dtls_server_session == NULL)
    {
        LOG_ERR("failed to create a wolfSSL session ");
        return -1;
    }
    setblocking(gateway->bridge.fd, true);

    // register functions
    return 1;
}

int dlts_socket_create_connection(DtlsSocket *gateway, int fd)
{
    int ret = -1;
    uint8_t init_buffer[RECV_BUFFER_SIZE];
    struct sockaddr_in client_addr = {0};
    int client_addr_len = sizeof(client_addr);
    int len_recvd = recvfrom(fd, init_buffer, sizeof(init_buffer), 0, (struct sockaddr *)&client_addr, &client_addr_len);
    if (len_recvd < 0)
    {
        LOG_ERR("DTLS SERVER: failed to receive data");
        return -1;
    }

    // Log the client address
    uint8_t addrp[120];
    if (net_addr_ntop(AF_INET, &client_addr.sin_addr, addrp, sizeof(client_addr.sin_addr)) == NULL)
    {
        LOG_ERR("Failed to convert client address to string");
        return -1;
    }

    LOG_INF("DTLS SERVER: Received data from %s:%d", addrp, ntohs(client_addr.sin_port));

    // create new session socket:
    int server_connection_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_connection_fd < 0)
    {
        LOG_ERR("Request socket fd failed, errno: %d", server_connection_fd);
        return -1;
    }

    // resuse address
    if (setsockopt(server_connection_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
    {
        LOG_ERR("setsockopt(SO_REUSEADDR) failed: errer %d\n", errno);
        dtls_socket_close(gateway);
        return -1;
    }

    if (setsockopt(server_connection_fd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)) < 0)
    {
        LOG_ERR("setsockopt(SO_REUSEADDR) failed: errer %d\n", errno);
        dtls_socket_close(gateway);
        return -1;
    }

    struct sockaddr_in server_sock;
    memset(&server_sock, 0, sizeof(server_sock));
    server_sock.sin_family = AF_INET;
    server_sock.sin_port = htons(gateway->server_port);
    ret = net_addr_pton(AF_INET, gateway->own_ip_address, &server_sock.sin_addr);
    if (ret < 0)
    {
        LOG_ERR("couldnt convert ip addr");
        return -1;
    }
    if (bind(server_connection_fd, (struct sockaddr *)&server_sock, sizeof(server_sock)) < 0)
    {
        LOG_ERR("Couldnt bind server_connection_socket to client address: %d", errno);
        return -1;
    }

    ret = connect(server_connection_fd, (struct sockaddr *)&client_addr, sizeof(client_addr));

    if (ret < 0)
    {
        LOG_ERR("failed to connect to client, errno: %d", errno);
        return -1;
    }

    setblocking(server_connection_fd, false);
    l2_gateway_register_fd(server_connection_fd, POLLIN | POLLOUT | POLLHUP);

    wolfssl_session *new_session = wolfssl_create_session(gateway->dtls_server_endpoint, server_connection_fd);
    if (new_session == NULL)
    {
        LOG_ERR("failed to create new session");
        return -1;
    }

    ret = add_session(gateway->connection_session,
                sizeof(gateway->connection_session) / sizeof(gateway->connection_session[0]),
                new_session);
    if (ret < 0){
        LOG_ERR("failed to add session to list");
        return -1; 
    }

    // pass handshake data to session. Note! that the bufer is a local variable and only valid for the current scope
    ret = wolfssl_dtls_server_handshake(new_session, init_buffer, len_recvd);
    if (ret < 0)
    {
        LOG_ERR("failed to handshake with client");
        wolfssl_free_session(new_session);
        return -1;
    }

    // add session to connections
    int sessions_len = sizeof(gateway->connection_session) / sizeof(gateway->connection_session[0]);
    ret = add_session(gateway->connection_session, sessions_len, new_session);
    if (ret == -1)
    {
        LOG_ERR("failed to add session to list");
        wolfssl_free_session(new_session);
        return -1;
    }

    return server_connection_fd;
}

int dtls_socket_send(DtlsSocket *gateway, int fd, uint8_t *buffer, int buffer_len, int frame_start)
{
    int ret = -1;
    if (fd == gateway->bridge.fd)
    {
        // there is no need to send anything....
        LOG_ERR("DTLS_SOCKET: Sending data on server socket is not supported");
    }
    else
    {

        wolfssl_session *session = NULL;
        session = find_session_by_fd(fd,
                                     gateway->client_sessions,
                                     sizeof(gateway->client_sessions) / sizeof(wolfssl_session *));
        if (session != NULL)
        {
            // only reception on handshake
            ret = dtls_socket_client_send(session, buffer, buffer_len, frame_start);
            return 0;
        }
        else
        {
            session = find_session_by_fd(fd,
                                         gateway->connection_session,
                                         sizeof(gateway->connection_session) / sizeof(gateway->connection_session[0]));
            if (session != NULL)
            {
                // server should only send anything on handshake
                ret = dtls_socket_server_send(session);
            }
        }
    }
    return ret;
}

int dtls_socket_receive(DtlsSocket *gateway, int fd, int (*register_cb)(int fd))
{
    int ret = -1;
    if (fd == gateway->bridge.fd)
    {
        // on initial connection request, a new connection is created
        dlts_socket_create_connection(gateway, fd);
    }
    else
    {
        // check if server connection or client connection
        wolfssl_session *session = NULL;
        session = find_session_by_fd(fd,
                                     gateway->connection_session,
                                     sizeof(gateway->connection_session) / sizeof(gateway->connection_session[0]));
        if (session != NULL)
        {
            ret = dtls_socket_server_receive(session, gateway);
        }
        else
        {
            session = find_session_by_fd(fd,
                                         gateway->client_sessions,
                                         sizeof(gateway->client_sessions) / sizeof(wolfssl_session *));
            if (session != NULL)
            {
                // only reception on handshake
                ret = dtls_socket_client_receive(session);
                return 0;
            }
        }
    }
    return ret;
}

// client is just receiving data at the handshake
int dtls_socket_server_receive(wolfssl_session *session, DtlsSocket *gateway)
{
    int ret = -1;
    int offset = 0;
#if defined CONFIG_NET_VLAN
    offset = VLAN_HEADER_SIZE;
#endif

    ret = wolfssl_receive(session, gateway->bridge.buf + offset, sizeof(gateway->bridge.buf) - offset);
    gateway->bridge.len = ret + offset;
    return ret;
}

// client is just receiving data at the handshake
int dtls_socket_client_receive(wolfssl_session *session)
{
    int ret = wolfssl_handshake(session);
    LOG_INF("DTLS CLIENT: Handshake status: %d", ret);
    return 0;
}

// client is just receiving data at the handshake
int dtls_socket_client_send(wolfssl_session *session, uint8_t *buffer, int buffer_len, int frame_start)
{
    return wolfssl_send(session, buffer + frame_start, buffer_len - frame_start);
}

// client is just receiving data at the handshake
int dtls_socket_server_send(wolfssl_session *session)
{
    return wolfssl_handshake(session);
}

int dtls_socket_pipe(DtlsSocket *gateway)
{
    if (gateway->bridge.l2_gw_pipe == NULL)
    {
        LOG_ERR("DTLS_PIPE:  is null");
        return -1;
    }
    int offset = 0;
#if defined CONFIG_NET_VLAN
    offset = VLAN_HEADER_SIZE;
#endif
    if (gateway->bridge.len == 0)
    {
        LOG_ERR("DTLS_PIPE: No data to pipe");
        return -1;
    }
    int ret = l2_gateway_send(gateway->bridge.l2_gw_pipe, gateway->bridge.buf, gateway->bridge.len, offset);
    if (ret < 0)
    {
        LOG_ERR("Failed to l2_gw_pipe data to other bridge: %d", ret);
        l2_gateway_terminate();
    }
    gateway->bridge.len = 0;
    return ret;
}

int dtls_socket_close(DtlsSocket *bridge)
{
    bridge->bridge.l2_gw_pipe = NULL;

    close(bridge->bridge.fd);
    wolfssl_free_session(bridge->dtls_server_session);
    wolfssl_free_endpoint(bridge->dtls_server_endpoint);
    wolfssl_free_session(bridge->dtls_client_session);
    wolfssl_free_endpoint(bridge->dtls_client_endpoint);
    free(bridge);

    return 0;
}