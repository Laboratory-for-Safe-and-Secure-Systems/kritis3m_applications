#include "kritis3m_http_request.h"

#if (TMP_KEY)
/// @brief This function serves as temporary fix to insert key material into the TLS application.
///        As soon, as the QKD line problem is resolved, this code must be removed from the
///        library implementation!
/// @param response http_response object containing message information and returns the key info
///        to the sender of the http_get call.
static void insert_temporary_key(struct http_get_response* response)
{
        char temp_key[] = "1111 1111 1111 1111 1111 1111 11\0";
        char temp_key_ID[] = "2222 2222 2222 2222 2222 2222 22\0";

        memcpy(response->key_info->key, &temp_key, strlen(temp_key));
        memcpy(response->key_info->key_ID, &temp_key_ID, strlen(temp_key_ID));

        response->key_info->key_len = strlen(temp_key);
}
#endif

static void manage_request_error(struct http_get_response* response, CJSON_PUBLIC(cJSON*) data)
{
        CJSON_PUBLIC(cJSON*) error_msg = cJSON_GetObjectItemCaseSensitive(data, "message");
        if (error_msg == NULL)
        {
                printf("[ QUEST ][ ERROR ] invalid request resumption!\n");
                response->error_code = HTTP_ERR;
        }
        else
        {
                printf("[ QUEST ][ ERROR ] %s\n", error_msg->valuestring);
                response->error_code = HTTP_ERR;
        }

#if (TMP_KEY)
        /* this call is a fix, which can be deactivated as CMAKE option, once the QKD line is fixed */
        insert_temporary_key(response);
#endif
}

static void derive_key_info(struct http_get_response* response, CJSON_PUBLIC(cJSON*) data)
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

#ifdef VERBOSE
                printf("[ QUEST ][ INFO ] original key: %s -- key_ID: %s\n",
                       key->valuestring,
                       key_ID->valuestring);
                printf("[ QUEST ][ INFO ] original key size: %d -- key_ID size: %d\n",
                       (int) strlen(key->valuestring),
                       (int) strlen(key_ID->valuestring));
#endif
        }

        return;

QKD_ERROR:
        manage_request_error(response, data);
        return;
}

static void derive_status_info(struct http_get_response* response, CJSON_PUBLIC(cJSON*) data)
{
        CJSON_PUBLIC(cJSON*) status = cJSON_GetObjectItemCaseSensitive(data, "source_KME_ID");

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
#ifdef VERBOSE
                printf("[ QUEST ][ INFO ] Partial data received (%zd bytes).\n", rsp->data_len);
#endif
        }
        else if (final_data == HTTP_DATA_FINAL)
        {
#ifdef VERBOSE
                printf("[ QUEST ][ INFO ] successfully received http response.\n");
#endif
                http_request_status->bytes_received = rsp->body_frag_len;
                http_request_status->buffer_frag_start = rsp->body_frag_start;
                http_request_status->error_code = HTTP_OK;

                CJSON_PUBLIC(cJSON*)
                data = cJSON_Parse((const char*) http_request_status->buffer_frag_start);

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

        error_occured:
                http_request_status->error_code = HTTP_ERR;
                http_request_status->bytes_received = 0;
                http_request_status->buffer_frag_start = NULL;
                return;
        }
}

static struct qkd_key_info* allocate_key_info()
{
        /* allocate key_info struct for http get resone */
        struct qkd_key_info* key_info;
        key_info = malloc(sizeof(struct qkd_key_info));
        if (key_info == NULL)
        {
                printf("[ QUEST ][ ERROR ] failed to allocate HTTP-GET response key_info parameter.\n");
                goto ALLOC_ERR;
        }

        return key_info;

ALLOC_ERR:
        return NULL;
}

struct http_request* allocate_http_request()
{
        /* allocate actual http_request */
        struct http_request* request;
        request = malloc(sizeof(struct http_request));
        if (request == NULL)
        {
                printf("[ QUEST ][ ERROR ] failed to allocate HTTP-GET request.\n");
                goto ALLOC_ERR;
        }

        memset(request, 0, sizeof(struct http_request));

        return request;

ALLOC_ERR:
        return NULL;
}

struct http_get_response* allocate_http_response()
{
        /* allocate response struct for http get request */
        struct http_get_response* response;
        response = malloc(sizeof(struct http_get_response));
        if (response == NULL)
        {
                printf("[ QUEST ][ ERROR ] failed to allocate HTTP-GET response.\n");
                goto ALLOC_ERR;
        }

        memset(response, 0, sizeof(struct http_get_response));

        return response;

ALLOC_ERR:
        return NULL;
}

static void populate_key_with_id_url(struct http_request* request, char* key_ID)
{
        /*                                                     Template URL */
        /* http://im-lfd-qkd-alice.othr.de:9120/api/v1/keys/bob_sae_etsi_1/dec_keys?key_ID=0a6976fa-f096-42e1-8861-e59dfab12caf */

        /* depending on the host configuration the SAE in the base_url differs respectively */
        char* base_url;
        if (strcmp(request->host, "im-lfd-qkd-bob.othr.de") == 0)
        {
                base_url = "/api/v1/keys/alice_sae_etsi_1/dec_keys?key_ID=";
        }
        else if (strcmp(request->host, "im-lfd-qkd-alice.othr.de") == 0)
        {
                base_url = "/api/v1/keys/bob_sae_etsi_1/dec_keys?key_ID=";
        }
        else
        {
                base_url = NULL;
                printf("[ QUEST ][ ERROR ] invalid host and status configuration to assemble "
                       "url\n");
                return;
        }

        /* Allocate enough space for the base URL, the key, and the null terminator */
        size_t base_url_len = strlen(base_url);
        size_t key_id_len = strlen(key_ID);
        size_t total_len = base_url_len + key_id_len + 1; // +1 for null terminator

        request->url = (char*) malloc(total_len);
        if (request->url == NULL)
        {
                printf("[ QUEST ][ ERROR] Memory allocation failed in url assembly\n");
                return;
        }

        // Copy the base URL and concatenate the key
        strcpy((char*) request->url, base_url);
        strcat((char*) request->url, key_ID);
}

static void populate_key_no_id_url(struct http_request* request)
{
        /*                              Template URL                                         */
        /* http://im-lfd-qkd-bob.othr.de:9120/api/v1/keys/alice_sae_etsi_1/enc_keys?number=1 */

        if (strcmp(request->host, "im-lfd-qkd-bob.othr.de") == 0)
        {
                request->url = "/api/v1/keys/alice_sae_etsi_1/enc_keys?number=1";
        }
        else if (strcmp(request->host, "im-lfd-qkd-alice.othr.de") == 0)
        {
                request->url = "/api/v1/keys/bob_sae_etsi_1/enc_keys?number=1";
        }
        else
        {
                printf("[ QUEST ][ ERROR ] invalid host and status configuration to assemble "
                       "url\n");
        }
}

static void populate_status_url(struct http_request* request)
{
        /*                              Template URL                              */
        /* http://im-lfd-qkd-bob.othr.de:9120/api/v1/keys/alice_sae_etsi_1/status */

        if (strcmp(request->host, "im-lfd-qkd-bob.othr.de") == 0)
        {
                request->url = "/api/v1/keys/alice_sae_etsi_1/status";
        }
        else if (strcmp(request->host, "im-lfd-qkd-alice.othr.de") == 0)
        {
                request->url = "/api/v1/keys/bob_sae_etsi_1/status";
        }
        else
        {
                printf("[ QUEST ][ ERROR ] invalid host and status configuration to assemble "
                       "url\n");
        }
}

static void populate_request_url(struct http_request* request,
                                 struct http_get_response* response,
                                 char* key_ID)
{
        switch (response->msg_type)
        {
        case HTTP_STATUS:
                populate_status_url(request);
                break;

        case HTTP_KEY_NO_ID:
                populate_key_no_id_url(request);
                break;

        case HTTP_KEY_WITH_ID:
                if (key_ID == NULL)
                {
                        printf("[ QUEST ][ ERROR ] invalid key ID parameter");
                        break;
                }
                else
                {
                        populate_key_with_id_url(request, key_ID);
                }
                break;

        default:
                printf("[ QUEST ][ ERROR ] invalid state of message type\n");
                break;
        }
}

void populate_http_request(struct http_request* request,
                           struct http_get_response* response,
                           char* hostname,
                           char* hostport,
                           char* key_ID)
{
        /* set http protocol information and response callback */
        request->method = HTTP_GET;
        request->response = http_get_cb;
        request->protocol = "HTTP/1.1";

        /* set hostname and port of the server */
        request->host = hostname;
        request->port = hostport;

        /* reference receive buffer and associated size */
        request->recv_buf = response->buffer;
        request->recv_buf_len = response->buffer_len;

        populate_request_url(request, response, key_ID);
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

void deinit_http_request(struct http_request* request, enum http_get_request_type msg_type)
{
        if (request == NULL)
                return;

        /* This free shall only be called, if a key with key_ID was requested */
        if ((request->url != NULL) && (msg_type == HTTP_KEY_WITH_ID))
                free((char*) request->url);

        free(request);
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
