#ifndef IPC_H
#define IPC_H

#include "kritis3m_configuration.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Enumeration of IPC return codes.
 *
 * This enumeration defines the response codes used for inter-process communication (IPC),
 * indicating the status of a message or request.
 */
enum MSG_RESPONSE_CODE
{
        MSG_ERROR = -1,    /**< Indicates an error occurred. */
        MSG_OK = 0,        /**< Indicates the operation was successful. */
        MSG_FORBIDDEN = 1, /**< Indicates the request was forbidden. */
        MSG_BUSY = 2,      /**< Indicates the system is currently busy. */
};

typedef int32_t common_response_t;

void ipc_log_level_set(int log_level);
enum MSG_RESPONSE_CODE external_management_request(int socket, void* message, size_t message_size);
int sockpair_write(int socket, void* buffer, size_t length, size_t* retries);
enum MSG_RESPONSE_CODE sockpair_read(int socket, void* buffer, size_t length);

#endif // IPC_H
