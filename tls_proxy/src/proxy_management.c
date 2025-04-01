
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

#include "proxy_backend.h"
#include "proxy_connection.h"
#include "proxy_management.h"

#include "logging.h"
#include "poll_set.h"

LOG_MODULE_CREATE(proxy_management);

int send_management_message(int socket, proxy_management_message const* msg)
{
        int ret = 0;
        static const int max_retries = 5;
        int retries = 0;

        while ((ret <= 0) && (retries < max_retries))
        {
                ret = send(socket, (char const*) msg, sizeof(proxy_management_message), 0);
                if (ret < 0)
                {
                        if (errno != EAGAIN)
                        {
                                LOG_ERROR("Error sending message: %d (%s)", errno, strerror(errno));
                                return -1;
                        }

                        usleep(10 * 1000);
                }
                else if (ret != sizeof(proxy_management_message))
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

int read_management_message(int socket, proxy_management_message* msg)
{
        int ret = recv(socket, (char*) msg, sizeof(proxy_management_message), 0);
        if (ret < 0)
        {
                LOG_ERROR("Error receiving message: %d (%s)", errno, strerror(errno));
                return -1;
        }
        else if (ret != sizeof(proxy_management_message))
        {
                LOG_ERROR("Received invalid response (ret=%d; expected=%lu)",
                          ret,
                          sizeof(proxy_management_message));
                return -1;
        }

        return 0;
}
