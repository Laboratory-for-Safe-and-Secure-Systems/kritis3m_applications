#include "asl_helper.h"
#include "asl.h"
#include "networking.h"
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "logging.h"

LOG_MODULE_CREATE("asl_helper");

int establish_connection(char const* host,
                         uint16_t port,
                         asl_endpoint_configuration const* endpoint_config,
                         asl_endpoint** endpoint,
                         asl_session** session,
                         int* sock_fd)
{
        int ret = 0;
        struct addrinfo* addr_info = NULL;
        const char* hostname = host;

        if (!hostname || port == 0 || !sock_fd || !endpoint || !session)
                return ASL_ARGUMENT_ERROR;
        *sock_fd = -1;
        *endpoint = NULL;
        *session = NULL;

        if (address_lookup_client(hostname, port, &addr_info, AF_UNSPEC) < 0)
        {
                LOG_ERROR("Failed to resolve server hostname: %s", hostname);
                goto error_occured;
        }

        // Create client socket
        *sock_fd = create_client_socket(addr_info->ai_family == AF_INET6 ? AF_INET6 : AF_INET);
        if (*sock_fd < 0)
        {
                LOG_ERROR("Failed to create client socket");
                freeaddrinfo(addr_info);
                return ASL_INTERNAL_ERROR;
        }

        // Connect to the server
        if (ret = connect(*sock_fd, addr_info->ai_addr, addr_info->ai_addrlen), ret < 0)
        {
                LOG_ERROR("Failed to connect to server: %s", strerror(errno));
                goto error_occured;
        }

        // Setup TLS session
        *endpoint = asl_setup_client_endpoint(endpoint_config);
        if (*endpoint == NULL)
        {
                LOG_ERROR("Failed to setup ASL client endpoint");
                goto error_occured;
        }

        // Create ASL session
        *session = asl_create_session(*endpoint, *sock_fd);
        if (*session == NULL)
        {
                LOG_ERROR("Failed to create ASL session");
                goto error_occured;
        }

        // Perform TLS handshake
        ret = asl_handshake(*session);
        if (ret != ASL_SUCCESS)
        {
                LOG_ERROR("TLS handshake failed: %s", asl_error_message(ret));
                goto error_occured;
        }

        freeaddrinfo(addr_info);
        return ret;

error_occured:
        ret = -1;
        freeaddrinfo(addr_info);
        if (!*endpoint)
        {
                asl_free_endpoint(*endpoint);
                *endpoint = NULL;
        }
        if (!*session)
        {
                asl_close_session(*session);
                asl_free_session(*session);
                *session = NULL;
        }
        if (*sock_fd)
        {
                closesocket(*sock_fd);
                *sock_fd = -1;
        }

        return ret;
}

int test_endpoint(char const* host, uint16_t port, asl_endpoint_configuration const* endpoint_config)
{
        int ret = 0;
        asl_endpoint* endpoint;
        asl_session* session;
        int sock_fd;
        if ((ret = establish_connection(host, port, endpoint_config, &endpoint, &session, &sock_fd)) < 0)
        {
                LOG_ERROR("failed to establish connection");
                goto cleanup;
        }
cleanup:
        if (!session)
        {
                asl_close_session(session);
                asl_free_session(session);
                session = NULL;
        }
        if (sock_fd)
        {
                closesocket(sock_fd);
                sock_fd = -1;
        }
        if (!endpoint)
        {
                asl_free_endpoint(endpoint);
                endpoint = NULL;
        }

        return ret;
}