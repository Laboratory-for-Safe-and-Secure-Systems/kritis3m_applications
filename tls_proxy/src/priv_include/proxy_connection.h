#ifndef PROXY_CONNECTION_H
#define PROXY_CONNECTION_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "tls_proxy.h"

#include "logging.h"
#include "networking.h"
#include "threading.h"

#include "asl.h"

#if defined(__ZEPHYR__)
#define RECV_BUFFER_SIZE 1024
#define MAX_CONNECTIONS_PER_PROXY 10
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
        bool detached;
        bool incoming_tls;
        bool incoming_tls_hs_done;
        bool outgoing_tls;
        bool outgoing_tls_hs_done;
        int incoming_sock;
        int outgoing_sock;
        struct addrinfo* outgoing_addr;
        asl_session* incoming_tls_session;
        asl_session* outgoing_tls_session;
        log_module* log_module;
        proxy* proxy;
        int slot;

        int management_socket_pair[2];

        thread_info thread;

        uint8_t in2out_buffer[RECV_BUFFER_SIZE];
        size_t num_of_bytes_in_in2out_buffer;

        uint8_t out2in_buffer[RECV_BUFFER_SIZE];
        size_t num_of_bytes_in_out2in_buffer;
} proxy_connection;

void init_proxy_connection_pool(void);

proxy_connection* add_new_connection_to_proxy(proxy* proxy,
                                              int client_socket,
                                              struct sockaddr_in6* client_addr);

proxy_connection* find_proxy_connection_by_fd(int fd);

int proxy_connection_detach_handling(proxy_connection* connection);

int proxy_connection_stop_handling(proxy_connection* connection);

int proxy_connection_try_next_target(proxy_connection* connection);

void proxy_connection_cleanup(proxy_connection* connection);

#endif /* PROXY_CONNECTION_H */
