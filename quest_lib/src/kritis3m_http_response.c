#include "kritis3m_http.h"
#include "logging.h"

LOG_MODULE_CREATE(kritis3m_http_response);

/*------------------------------- private functions -------------------------------*/

/// @brief Allocate object to the qkd_key_info used for storage of the the qkd_key and key_ID.
/// @return returns reference to the allocated object or NULL of no memory is available.
static struct qkd_key_info* allocate_key_info()
{
        /* allocate key_info struct for http_get_respone */
        struct qkd_key_info* key_info;
        key_info = malloc(sizeof(struct qkd_key_info));
        if (key_info == NULL)
        {
                LOG_ERROR("failed to allocate HTTP-GET response key_info parameter.");
                goto ALLOC_ERR;
        }

        return key_info;

ALLOC_ERR:
        return NULL;
}

/*------------------------------- public functions -------------------------------*/
struct http_get_response* allocate_http_response()
{
        /* allocate response struct for http get request */
        struct http_get_response* response;
        response = malloc(sizeof(struct http_get_response));
        if (response == NULL)
        {
                LOG_ERROR("failed to allocate HTTP-GET response.");
                goto ALLOC_ERR;
        }

        memset(response, 0, sizeof(struct http_get_response));

        return response;

ALLOC_ERR:
        return NULL;
}

void populate_http_response(struct http_get_response* response, enum http_get_request_type request_type)
{
        response->buffer_frag_start = NULL;
        response->buffer_len = DEFAULT_BUFFER_LEN;
        response->bytes_received = 0;
        response->error_code = 0;
        response->msg_type = request_type;

        response->key_info = allocate_key_info();
}

void deinit_http_response(struct http_get_response* response)
{
        if (response == NULL)
                return;

        if (response->key_info != NULL)
        {
                free(response->key_info);
        }

        free(response);

        return;
}
