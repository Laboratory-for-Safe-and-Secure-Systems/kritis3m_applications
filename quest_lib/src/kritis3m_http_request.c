#include "kritis3m_http.h"
#include "logging.h"

LOG_MODULE_CREATE(kritis3m_http_request);

/*------------------------------- request callback -------------------------------*/
static void manage_request_error(struct http_get_response* response, cJSON* data)
{
        cJSON* error_msg = cJSON_GetObjectItemCaseSensitive(data, "message");
        if (error_msg == NULL)
        {
                LOG_ERROR("invalid request resumption!");
                response->error_code = HTTP_ERR;
                response->bytes_received = 0;
                response->buffer_frag_start = NULL;
        }
        else
        {
                LOG_ERROR("error occured: %s", error_msg->valuestring);
                response->error_code = HTTP_ERR;
                response->bytes_received = 0;
                response->buffer_frag_start = NULL;
        }
}

static void derive_key_info(struct http_get_response* response, cJSON* data)
{
        cJSON* key;
        cJSON* key_ID;

        cJSON* key_array = cJSON_GetObjectItemCaseSensitive(data, "keys");
        int key_array_size = cJSON_GetArraySize(key_array);

        /* we expect the JSON array to have exactly on element called "keys" */
        if (key_array_size != 1)
                goto QKD_ERROR;

        cJSON* item = cJSON_GetArrayItem(key_array, 0);
        key_ID = cJSON_GetObjectItem(item, "key_ID");
        key = cJSON_GetObjectItem(item, "key");

        if ((key != NULL) && (key_ID != NULL))
        {
                response->key_info->key_len = strlen(key->valuestring);
                response->key_info->key_ID_len = strlen(key_ID->valuestring);

                if ((response->key_info->key_len > QKD_INFO_MAX_LEN) ||
                    (response->key_info->key_ID_len > QKD_INFO_MAX_LEN))
                {
                        goto QKD_ERROR;
                }

                memcpy(response->key_info->key, key->valuestring, (response->key_info->key_len + 1));
                response->key_info->key[response->key_info->key_len] = '\0';

                memcpy(response->key_info->key_ID,
                       key_ID->valuestring,
                       (response->key_info->key_ID_len + 1));

                LOG_INFO("original key: %s -- key_ID: %s", key->valuestring, key_ID->valuestring);
                LOG_INFO("original key size: %d -- key_ID size: %d",
                         (int) strlen(key->valuestring),
                         (int) strlen(key_ID->valuestring));
        }

        return;

QKD_ERROR:
        manage_request_error(response, data);
        return;
}

static void derive_status_info(struct http_get_response* response, cJSON* data)
{
        cJSON* status = cJSON_GetObjectItemCaseSensitive(data, "source_KME_ID");

        if (status == NULL)
        {
                manage_request_error(response, data);
        }
}

static void http_get_cb(struct http_response* rsp, enum http_final_call final_data, void* user_data)
{
        struct http_get_response* http_request_status = (struct http_get_response*) user_data;
        if (http_request_status == NULL)
                return;

        if (final_data == HTTP_DATA_MORE)
        {
                LOG_INFO("partial data received (%zd bytes).", rsp->data_len);
        }
        else if (final_data == HTTP_DATA_FINAL)
        {

                LOG_INFO("Successfully received http response.");

                http_request_status->bytes_received = rsp->body_frag_len;
                http_request_status->buffer_frag_start = rsp->body_frag_start;
                http_request_status->error_code = HTTP_OK;

                cJSON* data = cJSON_Parse((const char*) http_request_status->buffer_frag_start);

                if (http_request_status->msg_type == HTTP_STATUS)
                {
                        derive_status_info(http_request_status, data);
                }
                else
                {
                        derive_key_info(http_request_status, data);
                }

                cJSON_Delete(data);
                return;
        }
}

/*------------------------------- private functions -------------------------------*/

/// @brief Dynamically allocates memory and assembles the url for the http_get request.
/// @param request reference to the http_request object allocated before.
/// @param sae_ID secure application entity identifier used in the url.
/// @param type_url specified url type. (set in populate_request_url() function)
/// @param key_ID OPTIONAL parameter, if a http_get request for a referenced key_ID is neccessary.
static void assemble_url(struct http_request* request, char* sae_ID, char* type_url, char* key_ID)
{
        if ((request == NULL) || (sae_ID == NULL) || (type_url == NULL))
        {
                LOG_ERROR("invalid parameter configuration in url assembly");
                return;
        }

        /* base part of the url, which is identical for all url types. */
        char* base_url = "/api/v1/keys/";

        /* Allocate enough space for the base URL, the sae_ID, the type_url and the null terminator */
        size_t base_url_len = strlen(base_url);
        size_t sae_id_len = strlen(sae_ID);
        size_t type_url_len = strlen(type_url);

        /* <base_url> + <sae_ID> + <type_url> */
        size_t total_len = base_url_len + sae_id_len + type_url_len + 1; // +1 for null terminator

        /* If the key_ID parameter is set, we reserve the additional length of the identifier */
        if (key_ID != NULL)
        {
                size_t key_id_len = strlen(key_ID);
                total_len += key_id_len;
        }

        request->url = (char*) malloc(total_len);
        if (request->url == NULL)
        {
                LOG_ERROR("memory allocation failed in url assembly");
                return;
        }

        /* Initialize request url buffer with zero values */
        memset((char*) request->url, 0, total_len);

        // Copy the base URL and concatenate the key
        strcpy((char*) request->url, base_url);
        strcat((char*) request->url, sae_ID);
        strcat((char*) request->url, type_url);

        if (key_ID != NULL)
        {
                strcat((char*) request->url, key_ID);
        }
}

/// @brief Populate the request url depending on the request type. This function specifies the
///        url assembly depending on the type set in the http_get_response.
/// @param request reference to the http_request object allocated before.
/// @param response reference to the http_get_response object allocated before.
/// @param key_ID OPTIONAL parameter, if a http_get request for a referenced key_ID is neccessary.
static void populate_request_url(struct http_request* request,
                                 struct http_get_response* response,
                                 char* sae_ID,
                                 char* key_ID)
{
        switch (response->msg_type)
        {
        case HTTP_STATUS:
                assemble_url(request, sae_ID, "/status", NULL);
                break;

        case HTTP_KEY_NO_ID:
                assemble_url(request, sae_ID, "/enc_keys?number=1", NULL);
                break;

        case HTTP_KEY_WITH_ID:
                assemble_url(request, sae_ID, "/dec_keys?key_ID=", key_ID);
                break;

        default:
                LOG_ERROR("invalid state of message type");
                break;
        }
}

/*------------------------------- public functions -------------------------------*/
struct http_request* allocate_http_request()
{
        /* allocate actual http_request */
        struct http_request* request;
        request = malloc(sizeof(struct http_request));
        if (request == NULL)
        {
                LOG_ERROR("failed to allocate HTTP-GET request.");
                goto ALLOC_ERR;
        }

        memset(request, 0, sizeof(struct http_request));

        return request;

ALLOC_ERR:
        return NULL;
}

void populate_http_request(struct http_request* request,
                           struct http_get_response* response,
                           char* hostname,
                           uint16_t hostport,
                           char* sae_ID,
                           char* key_ID)
{
        /* set http protocol information and response callback */
        request->method = HTTP_GET;
        request->response = http_get_cb;
        request->protocol = "HTTP/1.1";

        /* set hostname and port of the server */
        request->host = hostname;

        char* hostport_str = malloc(6); // Max length for port is 5 digits + null terminator
        if (hostport_str == NULL)
        {
                LOG_ERROR("failed to allocate memory for hostport string.");
                request->port = NULL;
                return;
        }
        snprintf(hostport_str, 6, "%u", hostport);
        request->port = hostport_str;

        /* reference receive buffer and associated size */
        request->recv_buf = response->buffer;
        request->recv_buf_len = response->buffer_len;

        populate_request_url(request, response, sae_ID, key_ID);
}

void deinit_http_request(struct http_request* request, enum http_get_request_type msg_type)
{
        if (request == NULL)
                return;

        /* Free allocated url */
        if (request->url != NULL)
                free((char*) request->url);

        /* Free allocated hostport string */
        if (request->port != NULL)
                free((char*) request->port);

        /* Free the request object itself */
        free(request);
}
