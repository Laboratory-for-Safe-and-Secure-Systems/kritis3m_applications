#ifndef PROXY_CONNECTION_H
#define PROXY_CONNECTION_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "tls_proxy.h"

#include "logging.h"
#include "networking.h"

#include "asl.h"


#if defined(__ZEPHYR__)

#define RECV_BUFFER_SIZE 1024

#define MAX_CONNECTIONS_PER_PROXY 3

#define HANDLER_THREAD_PRIORITY 10

#else

#define RECV_BUFFER_SIZE 16384

#define MAX_CONNECTIONS_PER_PROXY 25

#define HANDLER_THREAD_PRIORITY 12

#endif


/* Forward declaration for cross-reference */
typedef struct proxy proxy;

typedef struct proxy_connection
{
        bool in_use;
        enum tls_proxy_direction direction;
        int tunnel_sock;
        int asset_sock;
        asl_session* tls_session;
        log_module* log_module;
        proxy* proxy;
        int slot;

        int management_socket_pair[2];

        pthread_t thread;
        pthread_attr_t thread_attr;

        uint8_t tun2ass_buffer[RECV_BUFFER_SIZE];
        size_t num_of_bytes_in_tun2ass_buffer;

        uint8_t ass2tun_buffer[RECV_BUFFER_SIZE];
        size_t num_of_bytes_in_ass2tun_buffer;
}
proxy_connection;


void init_proxy_connection_pool(void);

proxy_connection* add_new_connection_to_proxy(proxy* proxy, int client_socket,
                                              struct sockaddr* client_addr);

proxy_connection* find_proxy_connection_by_fd(int fd);

int proxy_connection_detach_handling(proxy_connection* connection);

int proxy_connection_stop_handling(proxy_connection* connection);

void proxy_connection_cleanup(proxy_connection* connection);


#endif /* PROXY_CONNECTION_H */
