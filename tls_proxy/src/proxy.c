#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdio.h>

#include "proxy.h"

#include "logging.h"
#include "networking.h"
#include "poll_set.h"


LOG_MODULE_CREATE(proxy_backend);


#define ERROR_OUT(...) { LOG_ERROR(__VA_ARGS__); goto cleanup; }
#define ERROR_OUT_EX(module, ...) { LOG_ERROR_EX(module, __VA_ARGS__); goto cleanup; }


/* File global variables */
static proxy proxy_pool[MAX_PROXYS];



void init_proxy_pool(void)
{
        for (int i = 0; i < MAX_PROXYS; i++)
        {
                proxy_pool[i].in_use = false;
                proxy_pool[i].direction = REVERSE_PROXY;
                proxy_pool[i].incoming_sock = -1;
                proxy_pool[i].incoming_port = 0;
                proxy_pool[i].tls_endpoint = NULL;
                proxy_pool[i].log_module.name = NULL;
                proxy_pool[i].log_module.level = LOG_LVL_WARN;
                proxy_pool[i].num_connections = 0;

                for (int j = 0; j < MAX_CONNECTIONS_PER_PROXY; j++)
                {
                        proxy_pool[i].connections[j] = NULL;
                }
        }
}


/* Create a new proxy and add it to the main event loop */
int add_new_proxy(enum tls_proxy_direction direction, proxy_config const* config)
{
        /* Search for a free server slot */
        int freeSlot = -1;
        for (int i = 0; i < MAX_PROXYS; i++)
        {
                if (proxy_pool[i].in_use == false)
                {
                        freeSlot = i;
                        break;
                }
        }

        if (freeSlot == -1)
        {
                LOG_ERROR("Cannot create more TLS proxies (no free slot)");
                return -1;
        }

        proxy* proxy = &proxy_pool[freeSlot];

        proxy->in_use = true;
        proxy->direction = direction;

        /* Setup the log module for the proxy */
        char* log_module_name = (char*) malloc(32);
        if (log_module_name == NULL)
                ERROR_OUT("Error allocating memory for log module name");
        snprintf(log_module_name, 32, "tls_proxy_%d", freeSlot+1);
        proxy->log_module.name = log_module_name;
        proxy->log_module.level = config->log_level;

        if (direction == REVERSE_PROXY)
        {
                LOG_INFO_EX(proxy->log_module, "Starting new reverse proxy on port %d",
                        config->listening_port);

                /* Create the TLS endpoint */
                proxy->tls_endpoint = asl_setup_server_endpoint(&config->tls_config);
        }
        else if (direction == FORWARD_PROXY)
        {
                LOG_INFO_EX(proxy->log_module, "Starting new forward proxy to %s:%d",
                config->target_ip_address, config->target_port);

                /* Create the TLS endpoint */
                proxy->tls_endpoint = asl_setup_client_endpoint(&config->tls_config);
        }
        if (proxy->tls_endpoint == NULL)
                ERROR_OUT_EX(proxy->log_module, "Error creating TLS endpoint");

        /* Create the TCP socket for the incoming connection */
        proxy->incoming_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (proxy->incoming_sock == -1)
                ERROR_OUT_EX(proxy->log_module, "Error creating incoming TCP socket");

        if (setsockopt(proxy->incoming_sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
                ERROR_OUT_EX(proxy->log_module, "setsockopt(SO_REUSEADDR) failed: errer %d", errno);

        /* Configure TCP server */
        struct sockaddr_in bind_addr = {
                        .sin_family = AF_INET,
                        .sin_port = htons(config->listening_port)
        };
        net_addr_pton(bind_addr.sin_family, config->own_ip_address, &bind_addr.sin_addr);
        proxy->incoming_port = config->listening_port;

        /* Bind server socket to its destined IPv4 address */
        if (bind(proxy->incoming_sock, (struct sockaddr*) &bind_addr, sizeof(bind_addr)) == -1)
                ERROR_OUT_EX(proxy->log_module, "Cannot bind socket %d to %s:%d: error %d",
                        proxy->incoming_sock, config->own_ip_address, config->listening_port, errno);

        /* If a random port have been used, obtain the actually selected one */
	if (config->listening_port == 0)
	{
		socklen_t sockaddr_len = sizeof(bind_addr);
		if (getsockname(proxy->incoming_sock, (struct sockaddr*)&bind_addr, &sockaddr_len) < 0)
                        ERROR_OUT_EX(proxy->log_module, "getsockname failed with errno: %d", errno);

		proxy->incoming_port = ntohs(bind_addr.sin_port);
	}

        /* Start listening for incoming connections */
        listen(proxy->incoming_sock, MAX_CONNECTIONS_PER_PROXY);

        /* Set the new socket to non-blocking */
        setblocking(proxy->incoming_sock, false);

        /* Configure TCP client */
        proxy->target_addr.sin_family = AF_INET;
        proxy->target_addr.sin_port = htons(config->target_port);
        net_addr_pton(proxy->target_addr.sin_family, config->target_ip_address, &proxy->target_addr.sin_addr);

        LOG_INFO_EX(proxy->log_module, "Waiting for incoming connections on port %d", config->listening_port);

        return freeSlot+1;

cleanup:
        kill_proxy(proxy);

        return -1;
}


proxy* find_proxy_by_fd(int fd)
{
        for (int i = 0; i < MAX_PROXYS; i++)
        {
                if (proxy_pool[i].incoming_sock == fd)
                {
                        return &proxy_pool[i];
                }
        }

        return NULL;
}


proxy* find_proxy_by_id(int id)
{
        if (id < 1 || id >= MAX_PROXYS)
                return NULL;

        if (proxy_pool[id-1].in_use == false)
                return NULL;

        return &proxy_pool[id-1];

}


/* Stop a running proxy and cleanup afterwards */
void kill_proxy(proxy* proxy)
{
        /* Stop the listening socket and clear it from the poll_set */
        if (proxy->incoming_sock >= 0)
        {
                close(proxy->incoming_sock);
                proxy->incoming_sock = -1;
        }

        /* Kill all connections */
        for (int i = 0; i < MAX_CONNECTIONS_PER_PROXY; i++)
        {
                if (proxy->connections[i] != NULL)
                {
                        /* Kill the running thread. This is very ungracefully, but necessary here,
                         * as the thread is probably blocked.
                         */
                        if (proxy->connections[i]->in_use == true)
                        {
                                pthread_cancel(proxy->connections[i]->thread);
                        }

                        /* Cleanup the client */
                        proxy_connection_cleanup(proxy->connections[i]);

                        proxy->connections[i] = NULL;
                }
        }

        /* Clear TLS context */
        if (proxy->tls_endpoint != NULL)
        {
                asl_free_endpoint(proxy->tls_endpoint);
                proxy->tls_endpoint = NULL;
        }

        /* Free log module name */
        if (proxy->log_module.name != NULL)
        {
                free((void*) proxy->log_module.name);
                proxy->log_module.name = NULL;
        }

        proxy->incoming_sock = 0;
        proxy->in_use = false;
}
