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

/******************************************************************************************************
 *  Forward Declarations                                                                              *
 ******************************************************************************************************/
// l2_gateway_functions
int dtls_socket_receive(DtlsSocket *gateway, int fd);
int dtls_socket_send(DtlsSocket *gateway, int fd, uint8_t *buffer, int buffer_len, int frame_start);
int dtls_socket_pipe(DtlsSocket *gateway);
int dtls_socket_close(DtlsSocket *bridge);
// internal functions
int dtls_socket_connect(DtlsSocket *gateway);
int dlts_socket_create_connection(DtlsSocket *gateway, int fd);
int dtls_socket_client_receive(wolfssl_session *session);
int dtls_socket_server_receive(wolfssl_session *session, DtlsSocket *gateway);
int dtls_socket_client_send(wolfssl_session *session, uint8_t *buffer, int buffer_len, int frame_start);
int dtls_socket_server_send(wolfssl_session *session);
int init_dtls_client_socket_gateway(DtlsSocket *gateway);
int init_dtls_server_socket_gateway(DtlsSocket *gateway);

/**
 * Adds a new session to dtls_sessions.
 *
 * @param sessions The array of dtls_sessions.
 * @param sessions_len The number of sessions in @param sessions
 * @param session The dtls_session to be added.
 * @return The index at which the session was added, or -1 if the array is full.
 */
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
    if (ret < 0)
    {
        LOG_ERR("failed to add dtls_session to sessions ... list is full");
    }
    return ret;
}

/**
 * @brief Removes @param session from @param sessions
 *
 * This function removes a specified session from @param sessions. It searches for @param session
 * and removes it from @param sessions. Then, it shifts all subsequent sessions to the left to fill the gap.
 *
 * @param sessions The array of dtls_session.
 * @param sessions_len The number of sessions in @param sessions.
 * @param session The session to be removed.
 * @return Returns the index of the removed session if the session was successfully removed, -1 if the session was not found.
 */
int remove_session(dtls_session *sessions, int sessions_len, dtls_session session)
{
    int ret = -1;
    for (int i = 0; i < sessions_len; i++)
    {
        if (sessions[i].session == session.session)
        {
            ret = i;
            wolfssl_close_session(sessions[i].session);
            wolfssl_free_session(sessions[i].session);
            sessions[i].session = NULL;
            sessions[i].fd = -1;
            ret = i;
            // if a session
            if (i < (sessions_len - 1) && sessions[i + 1].session != NULL)
            {
                // shift all subsequent sessions to the left
                for (int j = i; j < (sessions_len - 1); j++)
                {
                    sessions[i] = sessions[i + 1];
                    sessions[i + 1].session = NULL;
                    sessions[i + 1].fd = -1;
                }
            }
            break;
        }
    }
    if (ret < 0)
    {
        LOG_ERR("failed to remove dtls_session from sessions ... session not found");
    }
    return ret;
}

/**
 * Finds a DTLS session by file descriptor.
 *
 * This function searches through an array of DTLS sessions to find the session
 * associated with the given file descriptor. It returns the found session, or
 * an empty session if no match is found.
 *
 * @param fd The file descriptor to search for.
 * @param sessions An array of DTLS sessions.
 * @param sessions_len The length of the sessions array.
 * @return The found DTLS session, or an empty session if no match is found.
 */
dtls_session find_session_by_fd(int fd, dtls_session *sessions, int sessions_len)
{
    dtls_session ret = {0};
    for (int i = 0; i < sessions_len; i++)
    {
        if (sessions[i].session == NULL)
        {
            LOG_ERR("dtls session with fd %d is not in dtls_sessions", fd);
            break;
        }
        wolfssl_session *session = sessions[i].session;
        if (sessions[i].fd == fd)
        {
            // found matching session by fd
            ret = sessions[i];
            break;
        }
    }
    return ret;
}

/**
 * @brief Registers file descriptors for the DtlsSocket.
 *
 * This function registers the file descriptors associated with the DtlsSocket
 * at the main module l2_gateway, by using l2_gateway_register_fd.
 * The client does not need to get notfied on POLLIN event, since the client is only sending data.
 *
 * @param gateway The DtlsSocket object.
 * @return Returns 1 on success, or -1 on failure.
 */
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
                ret = l2_gateway_register_fd(gateway->dtls_sessions[i].fd, POLLIN | POLLHUP);
            }
            else if (gateway->dtls_sessions[i].type == DTLS_CLIENT)
            {
                ret = l2_gateway_register_fd(gateway->dtls_sessions[i].fd, POLLHUP);
            }

            if (ret < 0)
            {
                LOG_ERR("failed to register fd %d at l2 gateway", gateway->dtls_sessions[i].fd);
                break;
            }
        }
    }

    return ret;
}

/**
 * @brief Sets up DTLS server and client sockets and initializes the parameters for the gateway.
 *
 * dtls client/server endpoint configurations are set up. Then, the handshake routine is started.
 *
 * @param gateway The DtlsSocket object to initialize.
 * @param config The configuration for the DtlsSocket.
 * @param channel The connected channel (ASSET or TUNNEL).
 *
 * @return 1 on success, -1 on failure.
 *
 * @todo in the future the client port will be generated randomly, or is obtained from the config
 * @bug if ip addr is already assigned to the interface, ip addr add fails
 */
int init_dtls_socket_gateway(DtlsSocket *gateway, const l2_gateway_config *config, connected_channel channel)
{
    int ret = -1;

    // parameter initialisation

    gateway->bridge.vtable[call_close] = dtls_socket_close; // provide the close function
// initialisation
#if defined(__ZEPHYR__)
    // in zephyr the client port is obtained from the prj.conf
    gateway->client_port = (channel == ASSET) ? CONFIG_NET_IP_ASSET_CLIENT_PORT : CONFIG_NET_IP_TUNNEL_CLIENT_PORT; // we dont care about the port
#else
    // static client port at 43422
    gateway->client_port = 43422; // (channel == ASSET) ? config->asset_client_port: config->tunnel_client_port;
#endif
    gateway->server_port = (channel == ASSET) ? config->asset_port : config->tunnel_port; // the dtls server port
    // the dtls target port of the counterparts dtls tunnel server
    gateway->target_port = (channel == ASSET) ? config->asset_target_port : config->tunnel_target_port;
    // the ip address of the gateway in the presentation format
    gateway->own_ip_address = (channel == ASSET) ? config->asset_ip : config->tunnel_ip;
    // the tunnel ip address of the counterparts gateway
    gateway->target_ip_address = (channel == ASSET) ? config->asset_target_ip : config->tunnel_target_ip;
    // the connected channel: asset or tunnel
    gateway->bridge.channel = channel;
    gateway->bridge.type = DTLS_SOCKET;
    // the config is stored -- not needed
    gateway->config = config;

    // initialise the dtls sessions
    for (int i = 0; i < sizeof(gateway->dtls_sessions) / sizeof(gateway->dtls_sessions[0]); i++)
    {
        gateway->dtls_sessions[i].session = NULL;
        gateway->dtls_sessions[i].fd = -1;
    }

    // request kernel to add ip address to the interface
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    // convert ip addr to networking format
    ret = net_addr_pton(AF_INET, gateway->own_ip_address, &addr.sin_addr);
    if (ret < 0)
    {
        LOG_ERR("Failed to convert IP address: %d", ret);
        dtls_socket_close(gateway);
        return -1;
    }
    // add ipv4 address to the interface
    // ret = add_ipv4_address((channel == ASSET) ? network_interfaces()->asset : network_interfaces()->tunnel,
    //                        addr.sin_addr);
    // if (ret < 0)
    // {
    //     LOG_ERR("couldn't assign ip addr to iface, errno: %d ", errno);
    // }

    // init dtls server endpoint, init corresponding server socket
    ret = init_dtls_server_socket_gateway(gateway);
    if (ret < 0)
    {
        LOG_ERR("failed to initialize dtls client socket");
        dtls_socket_close(gateway);
        return -1;
    }

    // init dtls client endpoint. The dlts client remains off until the handshake is initiated
    ret = init_dtls_client_socket_gateway(gateway);
    if (ret < 0)
    {
        LOG_ERR("failed to initialize dtls client socket");
        dtls_socket_close(gateway);
        return -1;
    }
    // start handshake routine
    ret = dtls_socket_connect(gateway);
    return ret;
}

/**
 * @brief Initializes the DTLS client socket for the gateway.
 *
 * This function initializes the DTLS client socket for the gateway by setting up the
 * DTLS client endpoint using the provided configuration.
 *
 * @param gateway A pointer to the DtlsSocket structure representing the gateway.
 * @return Returns 1 on success, or -1 if an error occurred.
 */
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

/**
 * @brief Initializes the DTLS server socket for the gateway.
 *
 * This function initializes the DTLS server socket for the gateway by setting up the necessary configurations
 * and creating a socket for communication. It also binds the socket to the specified IP address and port.
 *
 * @param gateway A pointer to the DtlsSocket structure representing the gateway.
 * @return Returns 1 on success, or -1 on failure.
 * 
 * @note On initial receive, the server receives Client Hello. 
 * The data must be passed to the corresponding session by using dtls_server_handshake() function.
 */
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

    /**
     * To reuse the address and port, the SO_REUSEADDR and SO_REUSEPORT options are set.
     * This allows tcp like behaviour, where each client is assigned an own connection socket 
    */
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

    // bind the server to the ip address
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

/**
 * Initializes a DTLS client session for the given gateway.
 *
 *
 * @param gateway The DtlsSocket object representing the gateway.
 * @return The socket file descriptor of the client socket, or -1 on failure.
 *
 * @todo in the future, multiple client sessions will be started regarding DtlsSockets gateway. So a new @param peer_addr will be needed
 */
int init_dtls_client_session(DtlsSocket *gateway)
{
    // local function variables
    int ret = -1;
    struct sockaddr_in helper_addr;
    int helper_addr_len = sizeof(helper_addr);
    wolfssl_session *session = NULL;

    // the dtls client socket
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

    // convert gateways ip address
    ret = net_addr_pton(AF_INET, gateway->own_ip_address, &helper_addr.sin_addr);
    if (ret < 0)
    {
        LOG_ERR("failed to convert ip address");
        return -1;
    }
    helper_addr.sin_family = AF_INET;
    helper_addr.sin_port = htons(gateway->client_port);

    // bind the client to gateways ip addr
    ret = bind(sockfd, (struct sockaddr *)&helper_addr, helper_addr_len);
    if (ret < 0)
    {
        LOG_ERR("failed to bind socket, errno: %d", errno);
        return -1;
    }

    // later, the peer configuration must be provided
    // convert client peer ip address
    helper_addr.sin_port = htons(gateway->target_port);
    ret = net_addr_pton(AF_INET, gateway->target_ip_address, &helper_addr.sin_addr);
    if (ret < 0)
    {
        LOG_ERR("conversion of target ip addr didnt work, errno %d", errno);
        return -1;
    }

    // connect the client to the peer
    ret = connect(sockfd, (struct sockaddr *)&helper_addr, helper_addr_len);
    if (ret < 0)
    {
        LOG_ERR("failed to connect client to peer, errno %d ", errno);
        return -1;
    }

    // create dtls session
    session = wolfssl_create_session(gateway->dtls_client_endpoint, sockfd);
    if (session == NULL)
    {
        LOG_ERR("failed to create a wolfSSL session ");
        return -1;
    }

    // add session to intern session storage
    dtls_session dtls_session = {.session = session, .type = DTLS_CLIENT, .fd = sockfd};
    ret = add_session(gateway->dtls_sessions,
                      sizeof(gateway->dtls_sessions) / sizeof(dtls_session),
                      dtls_session);

    // return the corresponding socket file descriptor
    return sockfd;
}

/**
 * @brief Restarts the DTLS client session. (For testing purposes)
 *
 * 1. Finds the first DTLS client session in the gateway's dtls_sessions storage.
 * 2. Removes the session from the DtlsSocket's poll_set.
 * 3. The client session is closed
 * 4. The memory of the session is freed
 * 5. A new DTLS client session is initialized
 * 6. The new session is added to the poll_set
 * The function returns 1, if no DTLS client session is found, the function returns -1.
 *
 * @param gateway The DtlsSocket object.
 * @param poll_set The poll_set object.
 * @return Returns 1 on success, -1 if no DTLS client session is found.
 */
int restart_client(DtlsSocket *gateway, poll_set *poll_set)
{
    // find first dtls client
    for (int i = 0;
         i < sizeof(gateway->dtls_sessions) / sizeof(dtls_session);
         i++)
    {
        if (gateway->dtls_sessions[i].session != NULL && gateway->dtls_sessions[i].type == DTLS_CLIENT)
        {
            int fd = gateway->dtls_sessions[i].fd;
            poll_set_remove_fd(poll_set, fd);
            // remove session closes the dtls session and frees the memory
            remove_session(gateway->dtls_sessions,
                           sizeof(gateway->dtls_sessions) / sizeof(dtls_session),
                           gateway->dtls_sessions[i]);
            close(fd);

            // restart new client session
            fd = init_dtls_client_session(gateway);
            if (fd < 0)
            {
                LOG_ERR("failed to restart client");
                return -1;
            }
            // get session by fd
            dtls_session session = find_session_by_fd(fd,
                                                      gateway->dtls_sessions,
                                                      sizeof(gateway->dtls_sessions) / sizeof(dtls_session));

            int ret = wolfssl_handshake(session.session);
            // request write permission
            if (ret == WOLFSSL_ERROR_WANT_READ)
            {
                poll_set_add_fd(poll_set, fd, POLLIN | POLLHUP);
            }
            else if (ret == WOLFSSL_ERROR_WANT_WRITE)
            {
                poll_set_add_fd(poll_set, fd, POLLOUT);
            }
            return 1;
            //
        }
    }
    return -1;
}

/**
 * @brief Establishes a DTLS connection with the tunnel interface of the counterpart gateway.
 *
 * This function initiates the DTLS handshake with the client and server,
 * and waits for the handshake to complete. The handshake is complete, when both,
 * client and server are connected. Only then, access the tunnel is accepted.
 * The client reinitiates the handshake if the handshake times out. The timeout is set to 5 seconds via the poll method.
 *
 *
 * @param gateway A pointer to the DtlsSocket structure representing the gateway.
 * @return 0 if the DTLS connection is successfully established, -1 otherwise.
 */
int dtls_socket_connect(DtlsSocket *gateway)
{
    // local function variables
    int ret = -1;
    bool client_connected = false;
    bool server_connected = false;
    poll_set poll_set;

    poll_set_init(&poll_set);                         // init poll set
    int clientfd = init_dtls_client_session(gateway); // starts client session
    dtls_session client_session = find_session_by_fd(clientfd,
                                                     gateway->dtls_sessions,
                                                     sizeof(gateway->dtls_sessions) / sizeof(dtls_session));
    ret = wolfssl_handshake(client_session.session); // start handshake
    if (ret == WOLFSSL_ERROR_WANT_WRITE)
    {
        poll_set_add_fd(&poll_set, clientfd, POLLOUT | POLLHUP);
    }
    else if (ret == WOLFSSL_ERROR_WANT_READ)
    {
        poll_set_add_fd(&poll_set, clientfd, POLLIN | POLLHUP);
    }
    poll_set_add_fd(&poll_set, gateway->bridge.fd, POLLIN | POLLHUP);

    while (1)
    {
        ret = poll(poll_set.fds, poll_set.num_fds, 5000);

        if (ret < 0)
        {
            LOG_ERR("poll error: %d", errno);
            continue;
        }
        if ((ret == 0) && !client_connected)
        {
            restart_client(gateway, &poll_set);
            continue;
        }
        for (int i = 0; i < poll_set.num_fds; i++)
        {
            // check if session matches fd. And operate regarding the event
            int fd = poll_set.fds[i].fd;
            int event = poll_set.fds[i].revents;
            if (event == 0)
            {
                continue;
            }

            if ((fd == gateway->bridge.fd) && (event & POLLIN))
            {
                // new connection request
                LOG_INF("DTLS SERVER: New connection request");
                int connection_fd = dlts_socket_create_connection(gateway, fd);

                poll_set_add_fd(&poll_set, connection_fd, POLLIN | POLLHUP | POLLOUT);
            }
            else
            {
                // it is searched for the session that matches the file descriptor
                dtls_session session = find_session_by_fd(fd,
                                                          gateway->dtls_sessions,
                                                          sizeof(gateway->dtls_sessions) / sizeof(dtls_session));
                if (session.session != NULL)
                {
                    if ((event & POLLIN) || (event & POLLOUT))
                    {
                        // handshake
                        ret = wolfssl_handshake(session.session);
                        if (ret == 0 && session.type == DTLS_CLIENT)
                        {
                            if (is_session_connected(session.session))
                            {
                                client_connected = true;
                                LOG_INF("client connected");
                                poll_set_remove_fd(&poll_set, fd);
                            }
                        }
                        else if (ret == 0 && session.type == DTLS_SERVER)
                        {
                            if (is_session_connected(session.session))
                            {
                                server_connected = true;
                                LOG_INF("client connected");
                                poll_set_remove_fd(&poll_set, fd);
                            }
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
                        return -1;
                    }
                }
            }
        }
    }

one_client_and_one_server_conn:
    register_fds(gateway);                                      // all file descriptors are registered in the main module l2_gateway
    gateway->bridge.vtable[call_receive] = dtls_socket_receive; // callback to receive (server)
    gateway->bridge.vtable[call_send] = dtls_socket_send;       // callback to send (client)
    gateway->bridge.vtable[call_pipe] = dtls_socket_pipe;       // callback to pipe from tunnel to asset
    gateway->bridge.vtable[call_close] = dtls_socket_close;     // callback for gracefull shutdown
    return ret;
}

/**
 * @brief Creates a connection for the DtlsSocket.
 *
 * This function is called after a detected __POLLIN__ event at the server socket.
 * It creates a new remote connection to the peer, by adding a new session to the internal dtls sessions.
 *
 * Then, the handshake data is passed to the session and the handshake can be initiated
 *
 * @param gateway The DtlsSocket object.
 * @param fd The file descriptor to receive data from.
 * @return The file descriptor of the server connection socket if successful, -1 otherwise.
 */

int dlts_socket_create_connection(DtlsSocket *gateway, int fd)
{
    // local function variables
    int ret = -1;
    uint8_t init_buffer[RECV_BUFFER_SIZE]; // on client rx the udp socket receives the handshake data, which is stored in this buffer
    struct sockaddr_in client_addr = {0};  // the storage for the client address
    int client_addr_len = sizeof(client_addr);
    struct sockaddr_in server_sock = {0}; // the storage for the server socket
    uint8_t addrp[120];                   // the storage to convert the peers ip address to presentation format

    int len_recvd = recvfrom(fd, init_buffer, sizeof(init_buffer), 0, (struct sockaddr *)&client_addr, &client_addr_len);
    if (len_recvd < 0)
    {
        LOG_ERR("DTLS SERVER: failed to receive data");
        return -1;
    }

    // The address of the peer
    if (net_addr_ntop(AF_INET, &client_addr.sin_addr, addrp, sizeof(addrp)) == NULL)
    {
        LOG_ERR("Failed to convert client address to string");
        return -1;
    }
    LOG_INF("DTLS SERVER: Incomming connection request from %s:%d", addrp, ntohs(client_addr.sin_port));

    // create new session socket:
    int server_connection_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_connection_fd < 0)
    {
        LOG_ERR("Request socket fd failed, errno: %d", server_connection_fd);
        return -1;
    }

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

    // bindthe server to the gateways ip address
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
    // connect the socket to the peer
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
    dtls_session dtls_session_t = {.session = new_session, .type = DTLS_SERVER, .fd = server_connection_fd};
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
        LOG_ERR("dtls server connection: can't init handshake");
        wolfssl_free_session(new_session);
        return -1;
    }

    return server_connection_fd;
}

/**
 * Used function by the l2_gateway to access the VPN tunnel
 *
 * This function is the callback function which is used from the l2_gateway module to send data via the VPN tunnel.
 * Therefore, the DTLS Client is supposed to be used.
 *
 * @param gateway The DtlsSocket object.
 * @param fd The file descriptor of the socket.
 * @param buffer The buffer containing the data to be sent.
 * @param buffer_len The length of the data buffer.
 * @param frame_start The starting position of the frame in the buffer.
 * @return Returns the number of bytes sent on success, or -1 on failure.
 *
 * @todo By now there is no mediator, that transmitts the data between the asset and the tunnel side. Since just a singular client is used. It is searched for the first client.
 */
int dtls_socket_send(DtlsSocket *gateway, int fd, uint8_t *buffer, int buffer_len, int frame_start)
{
    // local function variables
    int ret = -1;
    dtls_session session = {0};

    if (fd == gateway->bridge.fd)
    {
        // The server fd should write
        LOG_ERR("DTLS_SOCKET: Sending data on server socket is not supported");
    }
    else if (fd < 0)
    {
        // since just a singular client is used, the first client is used if no fd is provided
        for (int i = 0; i < sizeof(gateway->dtls_sessions) / sizeof(dtls_session); i++)
        {
            if (gateway->dtls_sessions[i].session != NULL && gateway->dtls_sessions[i].type == DTLS_CLIENT)
            {
                // client session is found
                session = gateway->dtls_sessions[i];

                ret = dtls_socket_client_send(session.session, buffer, buffer_len, frame_start);
                break;
            }
        }
    }
    else
    {
        // it searched for matching fd's and on match the data is send via the session
        session = find_session_by_fd(fd,
                                     gateway->dtls_sessions,
                                     sizeof(gateway->dtls_sessions) / sizeof(dtls_session));
        if (session.session != NULL)
        {
            if (session.type == DTLS_SERVER)
            {
                LOG_ERR("DTLS Server shouldn't be sending data");
                // ret = dtls_socket_server_send(session.session);
            }
            else
            {
                ret = dtls_socket_client_send(session.session, buffer, buffer_len, frame_start);
            }
        }
    }
    return ret;
}

/**
 * @brief Used function by the l2_gateway to receive from the VPN tunnel
 *
 * This function receives data from a DTLS socket specified by the file descriptor (fd).
 * It also takes a callback function (register_cb) as a parameter, which is used to register the file descriptor.
 *
 * @param gateway The DtlsSocket object.
 * @param fd The file descriptor of the DTLS socket.
 * @return The result of the receive operation. Returns -1 on error, otherwise returns the number of bytes received.
 *
 * @todo Handle incomming connection requests
 */
int dtls_socket_receive(DtlsSocket *gateway, int fd)
{
    // local function variables
    int ret = -1;
    dtls_session session = {0};

    if (fd == gateway->bridge.fd)
    {
        // on initial connection request, a new connection is created
        LOG_ERR("DTLS_SOCKET: Durign the standard transfer, a new connection is not supported");
        // dlts_socket_create_connection(gateway, fd);
    }
    else
    {
        // check if server connection or client connection
        session = find_session_by_fd(fd,
                                     gateway->dtls_sessions,
                                     sizeof(gateway->dtls_sessions) / sizeof(dtls_session));
        if (session.session != NULL)
        {
            if (session.type == DTLS_SERVER)
            {
                ret = dtls_socket_server_receive(session.session, gateway);
                if (ret == 0)
                {
                    LOG_INF("DTLS_SERVER: Connection closed");
                }
            }
            else if (session.type == DTLS_CLIENT)
            {
                LOG_ERR("DTLS_CLIENT: Received data on client socket is not supported");
                // ret = dtls_socket_client_receive(session.session);
            }
        }
    }
    return ret;
}

/**
 * @brief Pipes the data from the DtlsSocket to the L2 gateway pipe.
 *
 * This function pipes the data from the DtlsSocket to the L2 gateway pipe.
 * It checks if the L2 gateway pipe is null and if there is any data to pipe.
 * If the pipe is null or there is no data, it returns -1.
 * Otherwise, it sends the data to the L2 gateway pipe using the l2_gateway_send function.
 * If the send operation fails, it logs an error and terminates the L2 gateway.
 * Finally, it resets the length of the bridge buffer to 0 and returns the result of the send operation.
 *
 * @param gateway The DtlsSocket instance.
 * @return The result of the send operation, or -1 if the pipe is null or there is no data to pipe.
 */
int dtls_socket_pipe(DtlsSocket *gateway)
{
    if (gateway->bridge.l2_gw_pipe == NULL)
    {
        LOG_ERR("DTLS_PIPE: is null");
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

/**
 * @brief Closes the DTLS socket and frees associated resources.
 *
 * This function closes the DTLS socket and frees the memory allocated for the DTLS sessions,
 * server and client endpoints, and the bridge structure.
 *
 * @param bridge The DTLS socket to be closed.
 * @return 0 on success
 */
int dtls_socket_close(DtlsSocket *bridge)
{
    bridge->bridge.l2_gw_pipe = NULL;

    for (int i = 0; i < sizeof(bridge->dtls_sessions) / sizeof(dtls_session); i++)
    {
        if (bridge->dtls_sessions[i].session != NULL)
        {
            int fd = bridge->dtls_sessions[i].fd;
            wolfssl_close_session(bridge->dtls_sessions[i].session);
            wolfssl_free_session(bridge->dtls_sessions[i].session);
            close(fd);
            bridge->dtls_sessions[i].session = NULL;
        }
    }

    wolfssl_free_endpoint(bridge->dtls_server_endpoint);
    wolfssl_free_endpoint(bridge->dtls_client_endpoint);

    close(bridge->bridge.fd);
    free(bridge);

    return 0;
}

/**
 * @brief Receives data from a DTLS socket server.
 *
 * This function receives data from a DTLS socket server using the specified session and gateway.
 * The offset is used to leave space for the VLAN header. This feature is just required on the asset side.
 *
 * @param session The wolfssl_session object representing the DTLS session.
 * @param gateway The DtlsSocket object representing the gateway.
 * @return The number of bytes received, or -1 if an error occurred.
 */
int dtls_socket_server_receive(wolfssl_session *session, DtlsSocket *gateway)
{
    // local function variables
    int ret = -1;
    int offset = 0;

    // check if vlan is enabled
#if defined CONFIG_NET_VLAN
    offset = VLAN_HEADER_SIZE;
#endif
    ret = wolfssl_receive(session, gateway->bridge.buf + offset, sizeof(gateway->bridge.buf) - offset);
    LOG_INF("DTLS SERVER: Receiving data %d", ret);
    gateway->bridge.len = ret + offset;
    return ret;
}

// client is just receiving data at the handshake
int dtls_socket_client_receive(wolfssl_session *session)
{
    LOG_ERR("Not supported yet. Probably usefull for the handshake");
    return -1;
}

/**
 * Sends data from the client socket to the server using DTLS.
 *
 * @param session The DTLS session to send data over.
 * @param buffer The buffer containing the data to send.
 * @param buffer_len The length of the buffer.
 * @param frame_start The starting index of the frame within the buffer.
 * @return The number of bytes sent, or a negative value on error.
 */
int dtls_socket_client_send(wolfssl_session *session, uint8_t *buffer, int buffer_len, int frame_start)
{
    LOG_INF("DTLS CLIENT sending %d data to server", buffer_len - frame_start);
    return wolfssl_send(session, buffer + frame_start, buffer_len - frame_start);
}

int dtls_socket_server_send(wolfssl_session *session)
{
    LOG_ERR("DTLS Server shouldn't be sending data. Probably usefull for the handshake");
}
