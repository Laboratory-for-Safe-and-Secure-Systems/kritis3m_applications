#include "ipc.h"
#include <poll.h>
#include "errno.h"
#include "logging.h"
#include "networking.h"

LOG_MODULE_CREATE(ipc);

enum MSG_RESPONSE_CODE sockpair_read(int socket, void* buffer, size_t length)
{
        if (buffer == NULL || length == 0)
        {
                LOG_ERROR("Buffer is NULL or length is 0");
                return -1;
        }

        struct pollfd fds[1];
        fds[0].fd = socket;
        fds[0].events = POLLIN | POLLERR | POLLHUP;

        int ret = poll(fds, 1, 5000);
        if (ret < 0)
        {
                LOG_ERROR("Failed to read response from external management request");
                return MSG_ERROR;
        }
        if (ret == 0)
        {
                LOG_ERROR("Timeout reading response from external management request");
                return MSG_ERROR;
        }
        if (fds[0].revents & POLLIN)
        {

                ret = recv(socket, (char*) buffer, length, 0);
                if (ret < 0)
                {
                        LOG_ERROR("Error receiving message: %d ", errno);
                        return MSG_ERROR;
                }
                else if (ret != length)
                {
                        LOG_ERROR("Received invalid response (ret=%d; expected=%lu)", ret, length);
                        return MSG_ERROR;
                }
        }else if (fds[0].revents & POLLERR || fds[0].revents & POLLHUP){
                LOG_ERROR("Socket error or hang up");
                return MSG_ERROR;
        }else{
                LOG_ERROR("Unknown event");
                return MSG_ERROR;
        }

        return 0;
}

/* Write to a socket pair
 * Return value is the number of bytes written or -1 in case of an error
 */
int sockpair_write(int socket, void* buffer, size_t length, size_t* retries)
{
        if (buffer == NULL || length == 0)
        {
                LOG_ERROR("Buffer is NULL or length is 0");
                return -1;
        }

        int ret = 0;
        const int max_retries = retries ? *retries : 5;
        int tried = 0;

        while ((ret <= 0) && (tried < max_retries))
        {
                ret = send(socket, (char const*) buffer, length, 0);
                if (ret < 0)
                {
                        if (errno != EAGAIN)
                        {
                                LOG_ERROR("Error sending message: %d (%s)", errno, strerror(errno));
                                return -1;
                        }

                        usleep(10 * 1000);
                }
                else if (ret != length)
                {
                        LOG_ERROR("Sent invalid message");
                        return -1;
                }

                tried++;
        }

        if (tried >= max_retries)
        {
                LOG_ERROR("Failed to send message after %d retries", max_retries);
                return -1;
        }

        return 0;
}

enum MSG_RESPONSE_CODE external_management_request(int socket, void* message, size_t message_size)
{
        int ret = 0;
        enum MSG_RESPONSE_CODE response_code = MSG_ERROR;
        ret = sockpair_write(socket, message, message_size, NULL);
        if (ret < 0)
        {
                LOG_ERROR("Failed to send message to external management request");
                return MSG_ERROR;
        }

        common_message_t response;
        ret = sockpair_read(socket, &response, sizeof(response));
        if (ret < 0)
        {
                LOG_ERROR("Failed to read response from external management request");
                return MSG_ERROR;
        }
        if (response.type != GENERAL_RETURN)
        {
                LOG_ERROR("Received invalid response from external management request");
                return MSG_ERROR;
        }
        response_code = response.data.return_code;

        return response_code;
}
