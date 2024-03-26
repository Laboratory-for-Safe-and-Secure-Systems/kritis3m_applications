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

int dlts_socket_create_connection(DtlsSocket *gateway, int fd);
int dtls_socket_connect(DtlsSocket *gateway);
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

int add_session(dtls_session *sessions, int sessions_len, dtls_session session)
{
    int ret = -1;
    for (int i = 0; i < sessions_len; i++)
    {
        if (sessions[i].session == NULL)
        {
            sessions[i] = session;
            ret = i;
            break;
        }
    }
    return ret;
}

int remove_session(dtls_session *sessions, int sessions_len, dtls_session session)
{
    int ret = -1;
    for (int i = 0; i < sessions_len; i++)
    {
        if (sessions[i].session == session.session)
        {
            // session found
            ret = 1;
            // check if next session is null, if so, we are done
            if (i < (sessions_len - 1) && sessions[i + 1].session == NULL)
            {
                sessions[i].session = NULL;
            }
            else if (i < (sessions_len - 1) && sessions[i + 1].session != NULL)
            {
                for (int j = i; j < (sessions_len - 1); j++)
                {
                    sessions[i] = sessions[i + 1];
                }
            }
            else if (i == (sessions_len - 1))
            {
                sessions[i].session = NULL;
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

dtls_session find_session_by_fd(int fd, dtls_session *sessions, int sessions_len)
{
    dtls_session ret = {0};
    for (int i = 0; i < sessions_len; i++)
    {
        if (sessions[i].session == NULL)
        {
            break;
        }
        wolfssl_session *session = sessions[i].session;
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

    for (int i = 0; i < sizeof(gateway->dtls_sessions) / sizeof(gateway->dtls_sessions[0]); i++)
    {
        gateway->dtls_sessions[i].session = NULL;
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

    gateway->bridge.vtable[call_connect] = dtls_socket_connect;

    return 1;
}

int register_fds(DtlsSocket *gateway)
{
    int ret = -1;
    l2_gateway_register_fd(gateway->bridge.fd, POLLIN);
    for (int i = 0; i < sizeof(gateway->dtls_sessions) / sizeof(dtls_session); i++)
    {
        if (gateway->dtls_sessions[i].session != NULL)
        {
            if (gateway->dtls_sessions[i].type == DTLS_SERVER)
            {
                ret = l2_gateway_register_fd(get_fd(gateway->dtls_sessions[i].session), POLLIN | POLLHUP);
            }
            else if (gateway->dtls_sessions[i].type == DTLS_CLIENT)
            {
                ret = l2_gateway_register_fd(get_fd(gateway->dtls_sessions[i].session), POLLOUT | POLLHUP);
            }
        }
    }
    return 1;
}

int init_dtls_client_session(DtlsSocket *gateway)
{
    int ret = -1;
    struct sockaddr_in helper_addr;
    int helper_addr_len = sizeof(helper_addr);

    wolfssl_session *session = NULL;

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        LOG_ERR("Request socket fd failed, errno: %d", sockfd);
        return -1;
    }

    setblocking(sockfd, false);
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
    session = wolfssl_create_session(gateway->dtls_client_endpoint, sockfd);

    if (session == NULL)
    {
        LOG_ERR("failed to create a wolfSSL session ");
        return -1;
    }

    dtls_session dtls_session = {.session = session, .type = DTLS_CLIENT};
    ret = add_session(gateway->dtls_sessions,
                      sizeof(gateway->dtls_sessions) / sizeof(dtls_session),
                      dtls_session);

    return sockfd;
}

int restart_client(DtlsSocket *gateway, poll_set *poll_set)
{
    // find first dtls client
    for (int i = 0; i < sizeof(gateway->dtls_sessions) / sizeof(dtls_session); i++)
    {
        if (gateway->dtls_sessions[i].session != NULL && gateway->dtls_sessions[i].type == DTLS_CLIENT)
        {
            int fd = get_fd(gateway->dtls_sessions[i].session);
            poll_set_remove_fd(poll_set, fd);
            remove_session(gateway->dtls_sessions,
                           sizeof(gateway->dtls_sessions) / sizeof(dtls_session),
                           gateway->dtls_sessions[i]);
            wolfssl_close_session(gateway->dtls_sessions[i].session);
            wolfssl_free_session(gateway->dtls_sessions[i].session);
            close(fd);
            fd = init_dtls_client_session(gateway);
            if (fd < 0)
            {
                LOG_ERR("failed to restart client");
                return -1;
            }
            poll_set_add_fd(poll_set, fd, POLLOUT);
            return 1;
            //
        }
    }
    return -1;
}
int dtls_socket_connect(DtlsSocket *gateway)
{
    // when is the tunnel connected: when one client is connected and an other server is connected

    /** 1. create poll set where clients and servers can register
     * then, regarding the fd, client or server handshake is called
     * after 10 seconds of handshake the connection is closed
     **/

    int ret = -1;
    bool client_connected = false;
    bool server_connected = false;

    poll_set poll_set;
    poll_set_init(&poll_set);

    init_dtls_client_session(gateway);

    for (int i = 0;
         i < sizeof(gateway->dtls_sessions) / sizeof(gateway->dtls_sessions[0]);
         i++)
    {
        // register all clients
        if (gateway->dtls_sessions[i].session != NULL && gateway->dtls_sessions[i].type == DTLS_CLIENT)
        {
            poll_set_add_fd(&poll_set, get_fd(gateway->dtls_sessions[i].session), POLLIN | POLLHUP);

            // start handshake
            int ret = wolfssl_handshake(gateway->dtls_sessions[i].session);
            LOG_INF("DTLS CLIENT: Handshake status: %d", ret);
        }
    }
    poll_set_add_fd(&poll_set, gateway->bridge.fd, POLLIN | POLLHUP);

    while (1)
    {
        ret = poll(poll_set.fds, poll_set.num_fds, 5000);
        if (ret == 0)
        {
            LOG_INF("poll timeout");
            // retry client handshake
            if (!client_connected)
            {
                // free session and restart
                ret = restart_client(gateway, &poll_set);
            }
            continue;
        }

        if (ret < 0)
        {
            LOG_ERR("poll error: %d", errno);
            continue;
        }

        for (int i = 0; i < poll_set.num_fds; i++)
        {
            int fd = poll_set.fds[i].fd;
            int event = poll_set.fds[i].revents;
            if (fd == gateway->bridge.fd && event & POLLIN)
            {
                int connection_fd = dlts_socket_create_connection(gateway, fd);
                poll_set_add_fd(&poll_set, connection_fd, POLLIN | POLLHUP);
                continue;
            }
            else
            {
                // find dtls session
                dtls_session session = find_session_by_fd(fd,
                                                          gateway->dtls_sessions,
                                                          sizeof(gateway->dtls_sessions) / sizeof(dtls_session));
                if (session.session != NULL)
                {
                    if ((event & POLLIN) || (event & POLLOUT))
                    {
                        ret = wolfssl_handshake(session.session);
                        if (ret == 0 && session.type == DTLS_CLIENT)
                        {
                            client_connected = true;
                            LOG_INF("client connected");
                            poll_set_remove_fd(&poll_set, fd);
                        }
                        else if (ret == 0 && session.type == DTLS_SERVER)
                        {
                            server_connected = true;
                            LOG_INF("Server connected");
                            poll_set_remove_fd(&poll_set, fd);
                        }
                        else if (ret == WOLFSSL_ERROR_WANT_WRITE)
                        {
                            poll_set_update_events(&poll_set, fd, POLLOUT | POLLHUP | POLLIN);
                        }
                        else if (ret == WOLFSSL_ERROR_WANT_READ)
                        {
                            poll_set_update_events(&poll_set, fd, POLLHUP | POLLIN);
                        }

                        if ((client_connected == true) && (server_connected == true))
                        {
                            ret = 1;
                            LOG_INF("DTLS connection established");
                            goto one_client_and_one_server_conn;
                        }
                    }
                    else if ((event & POLLHUP) || (event & POLLERR))
                    {
                        // close connection
                        LOG_INF("Error code is %d on fd: %d ", errno, fd);
                    }
                }
            }
        }
    }

one_client_and_one_server_conn:
    register_fds(gateway);
    gateway->bridge.vtable[call_receive] = dtls_socket_receive;
    gateway->bridge.vtable[call_send] = dtls_socket_send;
    gateway->bridge.vtable[call_pipe] = dtls_socket_pipe;
    gateway->bridge.vtable[call_close] = dtls_socket_close;
    return ret;
}
int init_dtls_client_socket_gateway(DtlsSocket *gateway)
{

    gateway->dtls_client_endpoint = wolfssl_setup_dtls_client_endpoint(&gateway->config->dtls_config);
    if (gateway->dtls_client_endpoint == NULL)
    {
        LOG_ERR("failed creating wolfssl dtls endopoint");
        return -1;
    }
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

    wolfssl_session *new_session = wolfssl_create_session(gateway->dtls_server_endpoint, server_connection_fd);
    if (new_session == NULL)
    {
        LOG_ERR("failed to create new session");
        return -1;
    }
    dtls_session dtls_session_t = {.session = new_session, .type = DTLS_SERVER};
    ret = add_session(gateway->dtls_sessions,
                      sizeof(gateway->dtls_sessions) / sizeof(dtls_session),
                      dtls_session_t);
    if (ret < 0)
    {
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

    return server_connection_fd;
}

int dtls_socket_send(DtlsSocket *gateway, int fd, uint8_t *buffer, int buffer_len, int frame_start)
{
    int ret = -1;
    dtls_session session = {0};
    if (fd == gateway->bridge.fd)
    {
        // there is no need to send anything....
        LOG_ERR("DTLS_SOCKET: Sending data on server socket is not supported");
    }
    else if (fd < 0)
    {
        // from packet socket pipe for testing purposes:
        // we just look for the first client since we dont have a mediator
        for (int i = 0; i < sizeof(gateway->dtls_sessions) / sizeof(dtls_session); i++)
        {
            if (gateway->dtls_sessions[i].session != NULL && gateway->dtls_sessions[i].type == DTLS_CLIENT)
            {
                session = gateway->dtls_sessions[i];
                ret = dtls_socket_client_send(session.session, buffer, buffer_len, frame_start);
                break;
            }
        }
    }
    else
    {
        session = find_session_by_fd(fd,
                                     gateway->dtls_sessions,
                                     sizeof(gateway->dtls_sessions) / sizeof(dtls_session));
        if (session.session != NULL)
        {
            if (session.type == DTLS_SERVER)
            {
                LOG_INF("DTLS Server shouldn't be sending data");
                ret = dtls_socket_server_send(session.session);
            }
            else
            {
                ret = dtls_socket_client_send(session.session, buffer, buffer_len, frame_start);
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
        dtls_session session = {0};
        session = find_session_by_fd(fd,
                                     gateway->dtls_sessions,
                                     sizeof(gateway->dtls_sessions) / sizeof(dtls_session));

        if (session.type == DTLS_SERVER)
        {
            ret = dtls_socket_server_receive(session.session, gateway);
        }
        else if (session.type == DTLS_CLIENT)
        {
            ret = dtls_socket_client_receive(session.session);
        }
        if (session.session != NULL)
        {
            ret = dtls_socket_server_receive(session.session, gateway);
        }
        else
        {
            LOG_INF("DTLS_SOCKET receive: No session found for fd: %d", fd);
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
    int ret = l2_gateway_send(gateway->bridge.l2_gw_pipe, -1, gateway->bridge.buf, gateway->bridge.len, offset);
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

    for (int i = 0; i < sizeof(bridge->dtls_sessions) / sizeof(dtls_session); i++)
    {
        if (bridge->dtls_sessions[i].session != NULL)
        {
            wolfssl_free_session(bridge->dtls_sessions[i].session);
            bridge->dtls_sessions[i].session = NULL;
        }
    }

    wolfssl_free_endpoint(bridge->dtls_server_endpoint);
    wolfssl_free_endpoint(bridge->dtls_client_endpoint);

    free(bridge);

    return 0;
}