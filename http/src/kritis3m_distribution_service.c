
#include "kritis3m_distribution_service.h"

#include "logging.h"
#include "mgmt_certs.h"
#include "cJSON.h"
LOG_MODULE_CREATE(policy_distribution_service);

#define POLICY_SERVERADDR "192.168.3.3"
#define POLICY_SERVERPORT "1231"
#define POLICY_RESPONSE_SIZE 4000

/***
 * @todo link the correct URL
 */
#define POLICY_URL (POLICY_SERVERADDR ":" POLICY_SERVERPORT "/hb_service/moin/")

struct http_policy_distribution_user_data
{
    bool is_finished;
    bool error_occured;
    SystemConfiguration *response;
    char *error_msg;
};

/********   FORWARD DECLARATION ***************/

int parse_system_config(uint8_t *body_msg, int size, SystemConfiguration *sys_cfg);
int parse_standard_appl(cJSON *js_standard_appl, Kritis3mHelperApplication *sys_standard_appl);
int parse_crypto_profile(cJSON *js_crypto_item, CryptoProfile *sys_crypto_profile);
int parse_proxy_appl(cJSON *js_proxy_appl, ProxyApplication *sys_proxy_appl);

static void policy_response_cb(struct http_response *rsp,
                               enum http_final_call final_data,
                               void *user_data)
{
    struct http_policy_distribution_user_data *user_data_ref = (struct http_policy_distribution_user_data *)user_data;
    if (final_data == HTTP_DATA_MORE)
    {
        LOG_INFO("Partial data received (%zd bytes)", rsp->data_len);
        user_data_ref->is_finished = false;
    }
    else if (final_data == HTTP_DATA_FINAL)
    {
        user_data_ref->is_finished = true;
        switch (rsp->http_status_code)
        {
        case HTTP_OK:
            LOG_INFO("SUCCESFULL REQUEST");
            user_data_ref->error_msg = HTTP_OK_MSG;
            int ret = parse_system_config(rsp->body_frag_start, rsp->body_frag_len, user_data_ref->response);
            if (ret < 0)
            {
                user_data_ref->error_occured = true;
                user_data_ref->error_msg = HTTP_DEFAULT_MSG;
                LOG_ERROR("parser error");
            }

            break;
        case HTTP_BAD_REQUEST:
            user_data_ref->error_occured = true;
            user_data_ref->error_msg = HTTP_BAD_REQUEST_MSG;
            LOG_ERROR("bad request");
            break;
        case HTTP_SERVICE_UNAVAILABLE:
            user_data_ref->error_occured = true;
            user_data_ref->error_msg = HTTP_SERVICE_UNAVAILABLE_MSG;
            LOG_INFO("Hardbeat service is not supported from the server");
            ret = -1;
            break;
        case HTTP_TOO_MANY_REQUESTS:
            user_data_ref->error_occured = true;
            user_data_ref->error_msg = HTTP_TOO_MANY_REQUESTS_MSG;
            LOG_INFO("Retry later");
            break;
        default:
            user_data_ref->error_occured = true;
            user_data_ref->error_msg = HTTP_DEFAULT_MSG;
            LOG_ERROR("responded http code is not handled, http response code: %d", rsp->http_status_code);
            break;
        }
    }
}

int call_policy_distribution_server(asl_endpoint *ep, PolicyResponse *rsp)
{
    int ret = -1;
asl_session *policy_rq_session = NULL;

    int req_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (req_fd < 0)
    {
        LOG_ERROR("error obtaining fd, errno: ", errno);
    }
    /********** TCP CONNECTION ************/
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    int server_port = atoi(POLICY_SERVERPORT);
    if (server_port < 0)
    {
        LOG_ERROR("cant convert port to integer");
        goto shutdown;
    }
    server_addr.sin_port = htons(server_port);
    ret = inet_pton(AF_INET, POLICY_SERVERADDR, (struct sockaddr *)&server_addr);
    if (ret < 0)
    {
        LOG_ERROR("cant parse ipv 4 addr, errno: ", errno);
        goto shutdown;
    }
    ret = connect(req_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in));
    if (ret < 0)
    {
        LOG_ERROR("cant connect to client: errno %d", errno);
        return -1;
    }
    policy_rq_session = asl_create_session(ep, req_fd);

    struct http_request req;
    memset(&req, 0, sizeof(req));

    struct http_policy_distribution_user_data user_response_data = {
        .is_finished = false,
        .error_msg = NULL,
        .error_occured = false,
        .response = &rsp->system_configuration};

    uint8_t response_buffer[POLICY_RESPONSE_SIZE] = {0};

    req.method = HTTP_GET;
    req.url = POLICY_URL;
    req.host = POLICY_SERVERADDR;
    req.protocol = "HTTP/1.1";
    /**
     * @todo evaluate if response handling in callback or
     * response handling after request is superior
     */
    req.response = policy_response_cb;
    req.recv_buf = response_buffer;
    req.recv_buf_len = sizeof(response_buffer);

    int32_t timeout = 3 * MSEC_PER_SEC;
    ret = https_client_req(req_fd, policy_rq_session, &req, timeout, &user_response_data);
    if (ret < 0)
    {
        LOG_ERROR("error on client req. need to implment error handler");
        goto shutdown;
    }

    asl_close_session(policy_rq_session);
    asl_free_session(policy_rq_session);
    return 0;
    shutdown:
    //its ok to call these functions withh nullptr. no checks required
    asl_close_session(policy_rq_session);
    asl_free_session(policy_rq_session);


    return -1;
}

int parse_system_config(uint8_t *body_msg, int size, SystemConfiguration *sys_cfg)
{
    int ret = -1;
    cJSON *json = cJSON_ParseWithLength(body_msg, size);
    if (json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            fprintf(stderr, "Error before: %s\n", error_ptr);
        }
        goto parser_error;
    }

    cJSON *system_config = cJSON_GetObjectItemCaseSensitive(json, "SystemConfiguration");
    if (cJSON_IsObject(system_config))
    {
        /************************** CRYPTO PROFILE************************************/

        cJSON *js_item = cJSON_GetObjectItemCaseSensitive(system_config, "number_crypto_profiles");
        if (cJSON_IsNumber(js_item))
        {
            sys_cfg->number_crypto_profiles = js_item->valueint;
        }
        else
        {
            LOG_ERROR("number_crypto_profiles wrong format or not provided");
            goto parser_error;
        }

        cJSON *crypto_profiles = cJSON_GetObjectItemCaseSensitive(system_config, "crypto_profile");
        if (cJSON_IsArray(crypto_profiles))
        {

            int crypto_profile_count = cJSON_GetArraySize(crypto_profiles);
            for (int i = 0; i < crypto_profile_count; i++)
            {

                cJSON *crypto_profile = cJSON_GetArrayItem(crypto_profiles, i);
                int ret = parse_crypto_profile(crypto_profile, &sys_cfg->crypto_profile[i]);
                if (ret < 0)
                {
                    goto parser_error;
                }
            }
        }

        /************************** HARDBEAT ************************************/

        js_item = cJSON_GetObjectItemCaseSensitive(system_config, "hardbeat_interval_s");
        if (cJSON_IsNumber(js_item))
        {
            sys_cfg->hardbeat_interval_s = js_item->valueint;
        }
        else
        {
            LOG_WARN("hardbeat_interval not provided. Using default value");
            sys_cfg->hardbeat_interval_s = HARDBEAT_DEFAULT_S;
        }

        /************************** PROXY APPLICATIONS ************************************/
        cJSON *hardbeat_interval_s = cJSON_GetObjectItemCaseSensitive(system_config, "hardbeat_interval_s");
        sys_cfg->hardbeat_interval_s = cJSON_GetNumberValue(hardbeat_interval_s);

        cJSON *num_proxy_applications = cJSON_GetObjectItemCaseSensitive(system_config, "number_proxy_applications");
        sys_cfg->number_proxy_applications = cJSON_GetNumberValue(num_proxy_applications);

        cJSON *proxy_applications = cJSON_GetObjectItemCaseSensitive(system_config, "proxy_applications");
        if (cJSON_IsArray(proxy_applications))
        {
            int proxy_application_count = cJSON_GetArraySize(proxy_applications);
            for (int i = 0; i < proxy_application_count; i++)
            {
                cJSON *proxy_application = cJSON_GetArrayItem(proxy_applications, i);
                int ret = parse_proxy_appl(proxy_application, &sys_cfg->proxy_applications[i]);
                if (ret < 0)
                {
                    goto parser_error;
                    return -1;
                }
            }
        }
        /************************************** STANDARD APPLICATIONS**************************************/

        cJSON *num_standard_applications = cJSON_GetObjectItemCaseSensitive(system_config, "number_standard_applications");
        sys_cfg->number_standard_applications = cJSON_GetNumberValue(num_standard_applications);

        cJSON *standard_applications = cJSON_GetObjectItemCaseSensitive(system_config, "standard_applications");
        if (cJSON_IsArray(standard_applications))
        {
            int standard_application_count = cJSON_GetArraySize(standard_applications);
            for (int i = 0; i < standard_application_count; i++)
            {
                cJSON *standard_application = cJSON_GetArrayItem(standard_applications, i);
                ret = parse_standard_appl(standard_application, &sys_cfg->standard_applications[i]);
                if (ret < 0)
                {
                    goto parser_error;
                }
            }
        }

        // Final Checks
        // certificat matches
        for (int i = 0; i < sys_cfg->number_proxy_applications; i++)
        {
            ret = -1;
            for (int j = 0; j < sys_cfg->number_crypto_profiles; j++)
            {
                if (strcmp(sys_cfg->proxy_applications[i].tunnel_crypto_profile_ID, sys_cfg->crypto_profile[j].ID) == 0)
                {
                    ret = 1;
                    break;
                }
            }
            if (ret < 0)
            {
                LOG_ERROR("Tunnel Crypto Profile ID does not match any crypto profile");
                goto parser_error;
            }
        }

        for (int i = 0; i < sys_cfg->number_proxy_applications; i++)
        {
            ret = -1;
            for (int j = 0; j < sys_cfg->number_crypto_profiles; j++)
            {
                if (strcmp(sys_cfg->proxy_applications[i].asset_crypto_profile_ID, sys_cfg->crypto_profile[j].ID) == 0)
                {
                    ret = 1;
                    break;
                }
            }
            if (ret < 0)
            {
                LOG_ERROR("Tunnel Crypto Profile ID does not match any crypto profile");
                goto parser_error;
            }
        }
    }
    cJSON_Delete(json);
    return 0;

parser_error:
    cJSON_Delete(json);
    return -1;
}

int parse_standard_appl(cJSON *js_standard_appl, Kritis3mHelperApplication *sys_standard_appl)
{
    cJSON *js_item = cJSON_GetObjectItemCaseSensitive(js_standard_appl, "listening_ip_port");
    if (js_item == NULL)
    {
        // listening_ip_port is a required field
        LOG_WARN("listening_ip_port is not provided. USING 0.0.0.0");
        strcpy(sys_standard_appl->listening_ip_port, "0.0.0.0");
    }
    else if (cJSON_IsString(js_item))
    {
        strcpy(sys_standard_appl->listening_ip_port, js_item->valuestring);
    }
    else
    {
        LOG_ERROR("listening_ip_port wrong format");
        return -1;
    }

    js_item = cJSON_GetObjectItemCaseSensitive(js_standard_appl, "application_type");
    if (js_item == NULL)
    {
        LOG_ERROR("application_type is a required field");
        return -1;
    }
    else if (cJSON_IsNumber(js_item) &&
             ((js_item->valueint >= ECHO_TCP_SERVER) &&
              (js_item->valueint <= TLS_R_PROXY)))
    {
        sys_standard_appl->application_type = js_item->valueint;
    }
    else
    {
        LOG_ERROR("application_type wrong format");
        return -1;
    }

    return 1;
}

int parse_crypto_profile(cJSON *js_crypto_item, CryptoProfile *sys_crypto_profile)
{
    cJSON *js_item = cJSON_GetObjectItemCaseSensitive(js_crypto_item, "ID");
    if (js_item == NULL)
    {
        // ID is a required field
        LOG_ERROR("ID is a required field");
        return -1;
    }
    else if (cJSON_IsString(js_item))
    {
        strcpy(sys_crypto_profile->ID, js_item->valuestring);
    }
    else
    {
        LOG_ERROR("ID wrong format");
        return -1;
    }

    js_item = cJSON_GetObjectItemCaseSensitive(js_crypto_item, "name");
    if (js_item == NULL)
    {
        // name is a required field
        LOG_WARN("no name in crypto profile. Using default");
        strcpy(sys_crypto_profile->name, "default");
    }
    else if (cJSON_IsString(js_item))
    {
        strcpy(sys_crypto_profile->name, js_item->valuestring);
    }
    else
    {
        LOG_ERROR("name wrong format");
        return -1;
    }
    js_item = cJSON_GetObjectItemCaseSensitive(js_crypto_item, "description");
    if (js_item == NULL)
    {
        // description is a required field
        LOG_WARN("no description in crypto profile. Using default");
        strcpy(sys_crypto_profile->description, "default");
    }
    else if (cJSON_IsString(js_item))
    {
        strcpy(sys_crypto_profile->description, js_item->valuestring);
    }
    else
    {
        LOG_ERROR("description wrong format");
        return -1;
    }
    /*******************************CERTIFICATE*****************************************/

    js_item = cJSON_GetObjectItemCaseSensitive(js_crypto_item, "certificate_ID");
    if (js_item == NULL)
    {
        // certificate_ID is a required field
        LOG_ERROR("certificate_ID is a required field");
        return -1;
    }
    else if (cJSON_IsNumber(js_item) &&
             ((js_item->valueint >= PQC) &&
              (js_item->valueint <= CLASSIC)))
    {
        sys_crypto_profile->certificate_ID = js_item->valueint;
    }
    else
    {
        LOG_ERROR("certificate_ID wrong format");
        return -1;
    }

    /**************************** SECURE ELEMENT ************************************/

    js_item = cJSON_GetObjectItemCaseSensitive(js_crypto_item, "use_secure_element");
    if (js_item == NULL)
    {
        // use_secure_element is a required field
        LOG_ERROR("use_secure_element is a required field");
        return -1;
    }
    else if (cJSON_IsBool(js_item))
    {
        sys_crypto_profile->use_secure_element = (bool)js_item->valueint;
    }
    else
    {
        LOG_ERROR("use_secure_element wrong format");
        return -1;
    }

    js_item = cJSON_GetObjectItemCaseSensitive(js_crypto_item, "secure_element_import_keys");
    if (js_item == NULL)
    {
        // secure_element_import_keys is a required field
        LOG_ERROR("secure_element_import_keys is a required field");
        return -1;
    }
    else if (cJSON_IsBool(js_item))
    {
        sys_crypto_profile->secure_element_import_keys = (bool)js_item->valueint;
    }
    else
    {
        LOG_ERROR("secure_element_import_keys wrong format");
        return -1;
    }

    js_item = cJSON_GetObjectItemCaseSensitive(js_crypto_item, "hybrid_signature_mode");
    if (js_item == NULL)
    {
        // hybrid_signature_mode is a required field
        LOG_ERROR("hybrid_signature_mode is a required field");
        return -1;
    }
    else if (cJSON_IsNumber(js_item) &&
             ((js_item->valueint >= HYBRID_SIGNATURE_MODE_NATIVE) &&
              (js_item->valueint <= HYBRID_SIGNATURE_MODE_BOTH)))
    {
        sys_crypto_profile->hybrid_signature_mode = js_item->valueint;
    }
    else
    {
        LOG_ERROR("hybrid_signature_mode wrong format");
        return -1;
    }
    return 1;
}

int parse_proxy_appl(cJSON *js_proxy_appl, ProxyApplication *sys_proxy_appl)
{
    cJSON *js_item = cJSON_GetObjectItemCaseSensitive(js_proxy_appl, "listening_ip_port");
    if (js_item == NULL)
    {
        // listening_ip_port is a required field
        LOG_ERROR("listening_ip_port is a required field");
        return -1;
    }
    else if (cJSON_IsString(js_item))
    {
        strcpy(sys_proxy_appl->listening_ip_port, js_item->valuestring);
    }
    else
    {
        LOG_ERROR("listening_ip_port wrong format");
        return -1;
    }

    js_item = cJSON_GetObjectItemCaseSensitive(js_proxy_appl, "target_ip_port");
    if (js_item == NULL)
    {
        // listening_ip_port is a required field
        LOG_ERROR("target_ip_port is a required field");
        return -1;
    }
    else if (cJSON_IsString(js_item))
    {
        strcpy(sys_proxy_appl->target_ip_port, js_item->valuestring);
    }
    else
    {
        LOG_ERROR("listening_ip_port wrong format");
        return -1;
    }
    js_item = cJSON_GetObjectItemCaseSensitive(js_proxy_appl, "application_type");
    if (js_item == NULL)
    {
        // application_type is a required field
        LOG_ERROR("application_type is a required field");
        return -1;
    }
    else if (cJSON_IsNumber(js_item) &&
             ((js_item->valueint >= DTLS_R_Proxy) &&
              (js_item->valueint <= TLS_R_PROXY)))
    {
        sys_proxy_appl->application_type = js_item->valueint;
    }
    else
    {
        LOG_ERROR("application_type wrong format");
        return -1;
    }

    js_item = cJSON_GetObjectItemCaseSensitive(js_proxy_appl, "listening_proto");
    if (js_item == NULL)
    {
        LOG_ERROR("listening_proto is a required field");
        return -1;
    }
    else if (cJSON_IsNumber(js_item) &&
             ((js_item->valueint >= DTLS) &&
              (js_item->valueint <= UDP)))
    {
        sys_proxy_appl->listening_proto = js_item->valueint;
    }
    else
    {
        LOG_ERROR("listening_proto wrong format");
        return -1;
    }

    js_item = cJSON_GetObjectItemCaseSensitive(js_proxy_appl, "target_proto");
    if (js_item == NULL)
    {
        LOG_ERROR("target_proto is a required field");
        return -1;
    }
    else if (cJSON_IsNumber(js_item) &&
             ((js_item->valueint >= DTLS) &&
              (js_item->valueint <= UDP)))
    {
        sys_proxy_appl->target_proto = js_item->valueint;
    }
    else
    {
        LOG_ERROR("target_proto wrong format");
        return -1;
    }

    js_item = cJSON_GetObjectItemCaseSensitive(js_proxy_appl, "tunnel_crypto_profile_ID");
    if (js_item == NULL)
    {
        LOG_ERROR("tunnel_crypto_profile_ID is a required field");
        return -1;
    }
    else if (cJSON_IsString(js_item))
    {
        strcpy(sys_proxy_appl->tunnel_crypto_profile_ID, js_item->valuestring);
    }
    else
    {
        LOG_ERROR("tunnel_crypto_profile_ID wrong format");
    }

    js_item = cJSON_GetObjectItemCaseSensitive(js_proxy_appl, "asset_crypto_profile_ID");
    if (js_item == NULL)
    {
        LOG_ERROR("asset_crypto_profile_ID is a required field");
        return -1;
    }
    else if (cJSON_IsString(js_item))
    {
        strcpy(sys_proxy_appl->asset_crypto_profile_ID, js_item->valuestring);
    }
    else
    {
        LOG_ERROR("asset_crypto_profile_ID wrong format");
        return -1;
    }

    js_item = cJSON_GetObjectItemCaseSensitive(js_proxy_appl, "num_connections");
    if (js_item == NULL)
    {
        LOG_ERROR("num_connections is a required field");
        return -1;
    }
    else if (cJSON_IsNumber(js_item))
    {
        sys_proxy_appl->num_connections = js_item->valueint;
    }
    else
    {
        LOG_ERROR("num_connections wrong format");
        return -1;
    }
    /********************** ALLOWED CONNECTIONS ***************************************/
    cJSON *connection_whitelist = cJSON_GetObjectItemCaseSensitive(js_proxy_appl, "connection_whitelist");
    if (cJSON_IsArray(connection_whitelist))
    {
        // number connections:
        int number_connections = cJSON_GetArraySize(connection_whitelist);
        sys_proxy_appl->connection_whitelist.number_connections = number_connections;
        for (int i = 0; i < number_connections; i++)
        {
            cJSON *js_connection = cJSON_GetArrayItem(connection_whitelist, i);

            js_item = cJSON_GetObjectItemCaseSensitive(js_connection, "allowed_client_ip_port");
            if (js_item == NULL)
            {
                LOG_ERROR("allowed_client_ip_port is a required field");
                return -1;
            }
            else if (cJSON_IsString(js_item))
            {
                strcpy(&sys_proxy_appl->connection_whitelist.allowed_client_ip_port[0][i], js_item->valuestring);
            }
            else
            {
                LOG_ERROR("allowed_client_ip_port wrong format");
                return -1;
            }
        }
    }
    else
    {
        LOG_ERROR("connection_whitelist wrong format");
        return -1;
    }

    return 1;
}
