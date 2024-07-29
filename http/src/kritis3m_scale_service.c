

#include "kritis3m_scale_service.h"

#include "cJSON.h"

int start_management_service(struct sockaddr_in)
{
  //1. call distribution server

  //2. handle response

  while(1)
{}
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

    cJSON *system_config = cJSON_GetObjectItemCaseSensitive(json, "SystemConfiguration");
    if (cJSON_IsObject(system_config))
    {
      cJSON *num_crypto_profiles = cJSON_GetObjectItemCaseSensitive(system_config, "number_crypto_profiles");
      system_configuration.number_crypto_profiles = cJSON_GetNumberValue(num_crypto_profiles);

      cJSON *hardbeat_interval_s = cJSON_GetObjectItemCaseSensitive(system_config, "hardbeat_interval_s");
      system_configuration.hardbeat_interval_s = cJSON_GetNumberValue(hardbeat_interval_s);

      cJSON *crypto_profiles = cJSON_GetObjectItemCaseSensitive(system_config, "crypto_profile");
      if (cJSON_IsArray(crypto_profiles))
      {
        int crypto_profile_count = cJSON_GetArraySize(crypto_profiles);
        for (int i = 0; i < crypto_profile_count; i++)
        {
          cJSON *crypto_profile = cJSON_GetArrayItem(crypto_profiles, i);
          strcpy(system_configuration.crypto_profile[i].ID, cJSON_GetObjectItemCaseSensitive(crypto_profile, "ID")->valuestring);
          strcpy(system_configuration.crypto_profile[i].name, cJSON_GetObjectItemCaseSensitive(crypto_profile, "name")->valuestring);
          strcpy(system_configuration.crypto_profile[i].description, cJSON_GetObjectItemCaseSensitive(crypto_profile, "description")->valuestring);
          strcpy(system_configuration.crypto_profile[i].certificate_ID, cJSON_GetObjectItemCaseSensitive(crypto_profile, "certificate_ID")->valuestring);
          system_configuration.crypto_profile[i].smartcard_enable = cJSON_GetObjectItemCaseSensitive(crypto_profile, "smartcard_enable")->valueint;
        }
      }

      cJSON *num_proxy_applications = cJSON_GetObjectItemCaseSensitive(system_config, "number_proxy_applications");
      system_configuration.number_proxy_applications = cJSON_GetNumberValue(num_proxy_applications);

      cJSON *proxy_applications = cJSON_GetObjectItemCaseSensitive(system_config, "proxy_applications");
      if (cJSON_IsArray(proxy_applications))
      {
        int proxy_application_count = cJSON_GetArraySize(proxy_applications);
        for (int i = 0; i < proxy_application_count; i++)
        {
          cJSON *proxy_application = cJSON_GetArrayItem(proxy_applications, i);
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
  }
  return 0;
}
