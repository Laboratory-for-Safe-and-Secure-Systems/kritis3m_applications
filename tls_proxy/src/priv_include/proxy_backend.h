#ifndef PROXY_H
#define PROXY_H

#include <stdbool.h>
#include <stdint.h>

#include "asl.h"

#include "tls_proxy.h"

#include "logging.h"
#include "networking.h"
#include "poll_set.h"
#include "proxy_connection.h"

#if defined(__ZEPHYR__)
        #define MAX_PROXYS 2
        #define BACKEND_THREAD_PRIORITY 8
#else
        #define MAX_PROXYS 10
        #define BACKEND_THREAD_PRIORITY 10
#endif

/* Structure declarations */
typedef struct proxy_backend
{
        bool running;
        int management_socket_pair[2];
        pthread_t thread;
        pthread_attr_t thread_attr;
        poll_set poll_set;
} proxy_backend;

typedef struct proxy_connection proxy_connection;

typedef struct proxy
{
        int application_id; // holds the application idenetifier
        bool in_use;
        enum tls_proxy_direction direction;
        int incoming_sock[2];      // IPv4 and IPv6
        uint16_t incoming_port[2]; // IPv4 and IPv6
        struct addrinfo* target_addr;
        asl_endpoint* tls_endpoint;
        log_module log_module;
        int num_connections;
        proxy_connection* connections[MAX_CONNECTIONS_PER_PROXY];
} proxy;

void init_proxy_pool(void);

int proxy_backend_init(proxy_backend* backend, proxy_backend_config const* config);

void proxy_backend_cleanup(proxy_backend* backend);

#endif /* PROXY_H */
