
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdio.h>

#include "proxy_management.h"

#include "logging.h"

LOG_MODULE_CREATE(proxy_backend);

int send_management_message(int socket, tls_proxy_management_message const* msg)
{
        int ret = 0;
        static const int max_retries = 5;
        int retries = 0;

        while ((ret <= 0) && (retries < max_retries))
        {
                ret = send(socket, msg, sizeof(tls_proxy_management_message), 0);
                if (ret < 0)
                {
                        if (errno != EAGAIN)
                        {
                                LOG_ERROR("Error sending message: %d (%s)", errno, strerror(errno));
                                return -1;
                        }

                        usleep(10 * 1000);
                }
                else if (ret != sizeof(tls_proxy_management_message))
                {
                        LOG_ERROR("Sent invalid message");
                        return -1;
                }

                retries++;
        }

        if (retries >= max_retries)
        {
                LOG_ERROR("Failed to send message after %d retries", max_retries);
                return -1;
        }

        return 0;
}


int read_management_message(int socket, tls_proxy_management_message* msg)
{
        int ret = recv(socket, msg, sizeof(tls_proxy_management_message), 0);
        if (ret < 0)
        {
                LOG_ERROR("Error receiving message: %d (%s)", errno, strerror(errno));
                return -1;
        }
        else if (ret != sizeof(tls_proxy_management_message))
        {
                LOG_ERROR("Received invalid response");
                return -1;
        }

        return 0;
}
