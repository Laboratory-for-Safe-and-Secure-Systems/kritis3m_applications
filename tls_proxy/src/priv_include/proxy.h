#ifndef PROXY_H
#define PROXY_H

#include <stdint.h>
#include <stdbool.h>

#include "asl.h"

#include "tls_proxy.h"

#include "proxy_connection.h"
#include "logging.h"
#include "networking.h"


#if defined(__ZEPHYR__)

#define MAX_PROXYS 2

#else

#define MAX_PROXYS 10

#endif


typedef struct proxy_connection proxy_connection;

typedef struct proxy
{
        bool in_use;
        enum tls_proxy_direction direction;
        int incoming_sock;
        uint16_t incoming_port;
        struct sockaddr_in target_addr;
        asl_endpoint* tls_endpoint;
        log_module log_module;
        int num_connections;
        proxy_connection* connections[MAX_CONNECTIONS_PER_PROXY];
}
proxy;


void init_proxy_pool(void);

int add_new_proxy(enum tls_proxy_direction direction, proxy_config const* config);

proxy* find_proxy_by_fd(int fd);
proxy* find_proxy_by_id(int id);

void kill_proxy(proxy* proxy);

#endif /* PROXY_H */
