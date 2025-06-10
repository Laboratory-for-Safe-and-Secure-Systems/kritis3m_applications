#ifndef _KRITIS3M_HTTP_REQ
#define _KRITIS3M_HTTP_REQ

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "http_client.h"
#include "http_method.h"
#include <fcntl.h>
#include <unistd.h>
#define DEFAULT_BUFFER_LEN 3000
#define QKD_INFO_MAX_LEN 64

enum http_status_type
{
        HTTP_OK = 0,
        HTTP_ERR = -1,
};

enum http_get_request_type
{
        HTTP_STATUS = 0,
        HTTP_KEY_NO_ID,
        HTTP_KEY_WITH_ID,
};

/// @brief structure containing the key information on the qkd key material
///        populated with the information of the http_get request.
struct qkd_key_info
{
        /* qkd key material from the http_get message */
        char key[QKD_INFO_MAX_LEN];

        /* key ID from the http_get message */
        char key_ID[QKD_INFO_MAX_LEN];

        /* key length from the http_get message */
        int key_len;

        /* identifier length from the http_get message */
        int key_ID_len;
};

/// @brief structure used for the response to http_get requests to the QKD system.
struct http_get_response
{
        /* error code assiged in the http_get_cb function */
        int error_code;

        /* buffer reserved for the QKD key and key-ID json */
        uint8_t buffer[DEFAULT_BUFFER_LEN];

        /* length of the buffer, per default equals to 3000 byte */
        ssize_t buffer_len;

        /* number of bytes received in the callback-function */
        size_t bytes_received;

        /* start address in the buffer */
        uint8_t* buffer_frag_start;

        /* expected type of the preceded http_get request */
        enum http_get_request_type msg_type;

        /* key information derived from the http_get request */
        struct qkd_key_info* key_info;
};

/// @brief frees the parameter of the http_get reponse struct. This is necessary, as the
///        struct contains another struct, which needs to be freed seperatly.
/// @param response reference to http_get_response object allocated and populated before.
void deinit_http_response(struct http_get_response* response);

/// @brief initializes the default parameters of the http_get response.
/// @param response reference to http_get_response object allocated before.
/// @param request_type specifies the expected type of request, which is transmitted to the QKD system.
void populate_http_response(struct http_get_response* response,
                            enum http_get_request_type request_type);

/// @brief allocates a reponse object for the http-get call.
/// @return returns reference to the allocated object or NULL of no memory is available.
struct http_get_response* allocate_http_response();

/// @brief frees the http_get request struct. As this function only contains standard parameter,
///        the function is inlined.
/// @param request reference to the http_request object allocated before.
/// @param msg_type as we allocate a buffer for the URL in the use case of a request with sepcific
///                 key_ID, we only need to free the URL if the message type equals HTTP_KEY_WITH_ID.
void deinit_http_request(struct http_request* request, enum http_get_request_type msg_type);

/// @brief generic http_request builder, which builds the request based on the type of expected
/// response parameter.
///        Therefore a the expected response struct has to be initialized before. It's type defines
///        the assembly of the type of http request.
/// @param request reference to the http_request object allocated before.
/// @param response reference to the http_get_response object allocated before.
/// @param hostname hostname of the server, where the http_get call shall be sent.
/// @param hostport hostport of the server, where the http_get call shall be sent.
/// @param sae_ID secure application entity identifier used in the request url.
/// @param key_ID OPTIONAL parameter, if a http_get request for a referenced key_ID is neccessary.
void populate_http_request(struct http_request* request,
                           struct http_get_response* response,
                           char* hostname,
                           uint16_t hostport,
                           char* sae_ID,
                           char* key_ID);

/// @brief allocates a request object for the http-get call.
/// @return returns reference to the allocated object or NULL of no memory is available.
struct http_request* allocate_http_request();

#endif
