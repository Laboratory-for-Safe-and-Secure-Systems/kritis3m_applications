

#include "kritis3m_scale_service.h"

#include "cJSON.h"

#include "logging.h"
LOG_MODULE_CREATE(log_kritis3m_service);

int parse_crypto_profile(cJSON *js_crypto_item, CryptoProfile *sys_crypto_profile);
int parse_proxy_appl(cJSON *js_proxy_appl, ProxyApplication *sys_proxy_appl);

int start_management_service(struct sockaddr_in)
{
  // 1. call distribution server

  // 2. handle response

  while (1)
  {
  }
  return 0;
}

int do_policy_request(struct sockaddr_in *server_addr, int server_addr_len,
                      int server_port)
{
  return 0;
}
int handle_policy_rq_response(char *response, int response_len,
                              SystemConfiguration *configuration)
{
  return 0;
}

/**
 * @todo !test
 */
int parse_configuration(char *response, int response_len)
{
  cJSON *json = cJSON_ParseWithLength(response, response_len);
  if (json == NULL)
  {
    const char *error_ptr = cJSON_GetErrorPtr();
    if (error_ptr != NULL)
    {
      fprintf(stderr, "Error before: %s\n", error_ptr);
    }
    return -1;
  }

  cJSON *system_config = cJSON_GetObjectItemCaseSensitive(json, "SystemConfiguration");
  if (cJSON_IsObject(system_config))
  {
    /************************** CRYPTO PROFILE************************************/

    cJSON *js_item = cJSON_GetObjectItemCaseSensitive(system_config, "number_crypto_profiles");
    if (cJSON_IsNumber(js_item))
    {
      system_configuration.number_crypto_profiles = js_item->valueint;
    }
    else
    {
      LOG_ERROR("number_crypto_profiles wrong format or not provided");
      return -1;
    }

    cJSON *crypto_profiles = cJSON_GetObjectItemCaseSensitive(system_config, "crypto_profile");
    if (cJSON_IsArray(crypto_profiles))
    {

      int crypto_profile_count = cJSON_GetArraySize(crypto_profiles);
      for (int i = 0; i < crypto_profile_count; i++)
      {

        cJSON *crypto_profile = cJSON_GetArrayItem(crypto_profiles, i);
        int ret = parse_crypto_profile(crypto_profile, &system_configuration.crypto_profile[i]);
        if (ret < 0)
        {
          return -1;
        }
      }
    }

    /************************** HARDBEAT ************************************/

    js_item = cJSON_GetObjectItemCaseSensitive(system_config, "hardbeat_interval_s");
    if (cJSON_IsNumber(js_item))
    {
      system_configuration.hardbeat_interval_s = js_item->valueint;
    }
    else
    {
      LOG_WARN("hardbeat_interval not provided. Using default value");
      system_configuration.hardbeat_interval_s = HARDBEAT_DEFAULT_S;
    }

    /************************** PROXY APPLICATIONS ************************************/
    cJSON *hardbeat_interval_s = cJSON_GetObjectItemCaseSensitive(system_config, "hardbeat_interval_s");
    system_configuration.hardbeat_interval_s = cJSON_GetNumberValue(hardbeat_interval_s);

    cJSON *num_proxy_applications = cJSON_GetObjectItemCaseSensitive(system_config, "number_proxy_applications");
    system_configuration.number_proxy_applications = cJSON_GetNumberValue(num_proxy_applications);

    cJSON *proxy_applications = cJSON_GetObjectItemCaseSensitive(system_config, "proxy_applications");
    if (cJSON_IsArray(proxy_applications))
    {
      int proxy_application_count = cJSON_GetArraySize(proxy_applications);
      for (int i = 0; i < proxy_application_count; i++)
      {
        cJSON *proxy_application = cJSON_GetArrayItem(proxy_applications, i);
        int ret = parse_proxy_appl(proxy_application, &system_configuration.proxy_applications[i]);

        strcpy(system_configuration.proxy_applications[i].listening_ip_port, cJSON_GetObjectItemCaseSensitive(proxy_application, "listening_ip_port")->valuestring);
        strcpy(system_configuration.proxy_applications[i].target_ip_port, cJSON_GetObjectItemCaseSensitive(proxy_application, "target_ip_port")->valuestring);
        system_configuration.proxy_applications[i].application_type = cJSON_GetObjectItemCaseSensitive(proxy_application, "application_type")->valueint;
        system_configuration.proxy_applications[i].listening_proto = cJSON_GetObjectItemCaseSensitive(proxy_application, "listening_proto")->valueint;
        system_configuration.proxy_applications[i].target_proto = cJSON_GetObjectItemCaseSensitive(proxy_application, "target_proto")->valueint;
        strcpy(system_configuration.proxy_applications[i].tunnel_crypto_profile_ID, cJSON_GetObjectItemCaseSensitive(proxy_application, "tunnel_crypto_profile_ID")->valuestring);
        strcpy(system_configuration.proxy_applications[i].asset_crypto_profile_ID, cJSON_GetObjectItemCaseSensitive(proxy_application, "asset_crypto_profile_ID")->valuestring);
        system_configuration.proxy_applications[i].num_connections = cJSON_GetObjectItemCaseSensitive(proxy_application, "num_connections")->valueint;

        cJSON *connection_whitelist = cJSON_GetObjectItemCaseSensitive(proxy_application, "connection_whitelist");
        if (cJSON_IsObject(connection_whitelist))
        {
          strcpy(system_configuration.proxy_applications[i].connection_whitelist.allowed_client_ip_port, cJSON_GetObjectItemCaseSensitive(connection_whitelist, "allowed_client_ip_port")->valuestring);
          system_configuration.proxy_applications[i].connection_whitelist.num_allowed = cJSON_GetObjectItemCaseSensitive(connection_whitelist, "num_allowed")->valueint;
        }
      }
    }

    cJSON *num_standard_applications = cJSON_GetObjectItemCaseSensitive(system_config, "number_standard_applications");
    system_configuration.number_standard_applications = cJSON_GetNumberValue(num_standard_applications);

    cJSON *standard_applications = cJSON_GetObjectItemCaseSensitive(system_config, "standard_applications");
    if (cJSON_IsArray(standard_applications))
    {
      int standard_application_count = cJSON_GetArraySize(standard_applications);
      for (int i = 0; i < standard_application_count; i++)
      {
        cJSON *standard_application = cJSON_GetArrayItem(standard_applications, i);
        strcpy(system_configuration.standard_applications[i].listening_ip_port, cJSON_GetObjectItemCaseSensitive(standard_application, "listening_ip_port")->valuestring);
        system_configuration.standard_applications[i].application_type = cJSON_GetObjectItemCaseSensitive(standard_application, "application_type")->valueint;
      }
    }
  }

  cJSON_Delete(json);
  return 0;
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

  return 1;
}