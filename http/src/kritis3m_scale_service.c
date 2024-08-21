

#include "kritis3m_scale_service.h"

#include "cJSON.h"
#include <sys/time.h>
#include <zephyr/kernel.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <mgmt_certs.h>

#include "poll_set.h"
#include "asl.h"
#include "logging.h"
#include "hb_service.h"
LOG_MODULE_CREATE(log_kritis3m_service);

#if defined(__ZEPHYR__)

#define MGMT_SIZE (60 * 1024)
Z_KERNEL_STACK_DEFINE_IN(mgmt_stack,
                         MGMT_SIZE,
                         __attribute__((section(CONFIG_RAM_SECTION_STACKS_2))));
#endif

typedef struct mgmt_container mgmt_container;
struct mgmt_container
{
  poll_set poll_set;
  int hb_fd;          // timer file descripor
  int hb_response_fd; // hardbeat file descriptor
  int policy_fd;      // call distribution service file descriptor

  pthread_t thread;
  pthread_attr_t thread_attr;

  asl_endpoint *endpoint;
};

/****************** FORWARD DECLARATIONS ****************/
// parsing
int parse_crypto_profile(cJSON *js_crypto_item, CryptoProfile *sys_crypto_profile);
int parse_proxy_appl(cJSON *js_proxy_appl, ProxyApplication *sys_proxy_appl);
int parse_standard_appl(cJSON *js_standard_appl, Kritis3mHelperApplication *sys_standard_appl);
// hardbeat_service
static void hb_timer_event_handler(struct k_timer *timer);
int init_hardbeat_service(mgmt_container *mgmt_container, uint32_t hb_iv_seconds);
// mgmt service:
void *mgmt_main_thread(void *ptr);

// GLOBALS
static mgmt_container mgmt = {0};
K_TIMER_DEFINE(hb_timer, hb_timer_event_handler, NULL);

/**
 * @brief this function is used to reset the timer and use the new hardbeat interval provided from the server
 * @todo this function must be tested
 */
int set_hardbeat_interval(struct mgmt_container *l_mgmnt, uint64_t hb_iv_s)
{
  uint32_t t_hb_iv_s = 0;
  if ((hb_iv_s <= HARDBEAT_MIN_S) || (hb_iv_s > HARDBEAT_MAX_S))
  {
    t_hb_iv_s = HARDBEAT_DEFAULT_S;
    LOG_ERROR("coudlnt reset hardbeat clock");
  }
  else
  {
    t_hb_iv_s = hb_iv_s;
  }

  close(l_mgmnt->hb_fd);
  poll_set_remove_fd(&l_mgmnt->poll_set, l_mgmnt->hb_fd);
  int efd = zvfs_eventfd(0, EFD_NONBLOCK);
  if (efd < 0)
  {
    LOG_ERROR("Failed to create eventfd\n");
    return -1;
  }
  l_mgmnt->hb_fd = efd;
  k_timer_stop(&hb_timer);
  k_timer_user_data_set(&hb_timer, &efd);
  k_timer_start(&hb_timer, K_SECONDS(15), K_SECONDS(t_hb_iv_s));
  poll_set_add_fd(&l_mgmnt->poll_set, efd, POLLIN | POLLERR);
  return 1;
}

void mgmt_crypto_cfg_init(asl_endpoint_configuration *cfg)
{
  cfg->mutual_authentication = true;
  cfg->use_secure_element = false;
  cfg->secure_element_import_keys = false;

  cfg->private_key.buffer = mgmt_classic_server_privateKey;
  cfg->private_key.size = sizeof(mgmt_classic_server_privateKey);
  cfg->private_key.additional_key_buffer = NULL;
  cfg->private_key.additional_key_size = 0;

  cfg->root_certificate.buffer = mgmt_classic_root_cert;
  cfg->root_certificate.size = sizeof(mgmt_classic_root_cert);

  cfg->device_certificate_chain.buffer = mgmt_classic_server_cert_chain;
  cfg->device_certificate_chain.size = sizeof(mgmt_classic_server_cert_chain);
}

int management_service_run()
{
  int ret = 0;

  /********** CRXPTO INITIALISATION ********************/
  memset(&mgmt, 0, sizeof(mgmt_container));
  asl_endpoint_configuration cfg = {0};
  mgmt_crypto_cfg_init(&cfg);
  asl_endpoint *endpoint = asl_setup_client_endpoint(&cfg);
  if (endpoint == NULL)
  {
    LOG_ERROR("can't init asl");
    return -1;
  }
  mgmt.endpoint = endpoint;

  poll_set_init(&mgmt.poll_set);
  pthread_attr_init(&mgmt.thread_attr);
  pthread_attr_setdetachstate(&mgmt.thread_attr, PTHREAD_CREATE_DETACHED);

#if defined(__ZEPHYR__)
  /* We have to properly set the attributes with the stack to use for Zephyr. */
  pthread_attr_setstack(&mgmt.thread_attr, &mgmt, K_THREAD_STACK_SIZEOF(mgmt_stack));
#endif
  /* Create the new thread */
  ret = pthread_create(&mgmt.thread, &mgmt.thread_attr, mgmt_main_thread, &mgmt);

  return 0;
}

/** @brief This funciton handles the connection to the management server.
 * The communication is based on https.
 */
void *mgmt_main_thread(void *ptr)
{
  int ret = -1;
  uint32_t hb_iv_seconds = 60;
  mgmt_container *l_mgmt = (mgmt_container *)ptr;

#if !defined(__ZEPHYR__)
  LOG_INFO("MGMT service started");
#endif

  ret = init_hardbeat_service(l_mgmt, hb_iv_seconds);
  if (ret < 0)
  {
    goto shutdown;
  }

  while (1)
  {
    // waiting for ever
    ret = poll(&l_mgmt->poll_set.fds[0],
               l_mgmt->poll_set.num_fds,
               -1);
    if (ret < 0)
    {
      LOG_ERROR("error occured in poll function, errno: %d", errno);
    }
    int number_events = ret;
    if (number_events == 0)
    {
      // no event occured
      continue;
    }
    if (number_events > l_mgmt->poll_set.num_fds)
    {
      LOG_ERROR("to many events-> PANIC");
    }

    // for each event, the matching fd is searched
    for (int i = 0; i < number_events; i++)
    {
      struct pollfd pfd = l_mgmt->poll_set.fds[i];
      // event exists?
      if (pfd.revents == 0)
      {
        continue;
      }
      int event_ret = -1;
      if (pfd.fd == l_mgmt->policy_fd)
      {
        // event_ret = handle_policy_event(mgmt, pfd.fd);
        if (ret < 0)
        {
          LOG_ERROR("error policy event");
        }
      }
      else if (pfd.fd == l_mgmt->hb_fd)
      {
        HardbeatResponse rsp = {0};
        ret = handle_hb_event(&pfd, l_mgmt->endpoint, &rsp);
        // Hardbeat request was succesfull.
        //  Set new hardbeat interval
        //  perform hardbeat instruction
        if (ret > 0)
        {
          ret = set_hardbeat_interval(l_mgmt, rsp.HardbeatInterval_s);
          if (ret < 0)
          {
            LOG_ERROR("couldn't set timer interval");
            goto shutdown;
          }
          /**
           * @todo hardbeat instruction
           */

          //ret = handle_hardbeat_instruction
        }
      }
      else
      {
        LOG_INFO("not found");
      }
      switch (event_ret)
      {
      case ASL_SUCCESS:
        break;
      case ASL_WANT_WRITE:
        break;
      case ASL_WANT_READ:
        break;
      default:
        break;
      }
    }
  }

shutdown:
  LOG_ERROR("Error occured in mgmt_module.\n Shut DOWN!");
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
  int ret = -1;
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
        if (ret < 0)
        {
          return -1;
        }
      }
    }
    /************************************** STANDARD APPLICATIONS**************************************/

    cJSON *num_standard_applications = cJSON_GetObjectItemCaseSensitive(system_config, "number_standard_applications");
    system_configuration.number_standard_applications = cJSON_GetNumberValue(num_standard_applications);

    cJSON *standard_applications = cJSON_GetObjectItemCaseSensitive(system_config, "standard_applications");
    if (cJSON_IsArray(standard_applications))
    {
      int standard_application_count = cJSON_GetArraySize(standard_applications);
      for (int i = 0; i < standard_application_count; i++)
      {
        cJSON *standard_application = cJSON_GetArrayItem(standard_applications, i);
        ret = parse_standard_appl(standard_application, &system_configuration.standard_applications[i]);
        if (ret < 0)
        {
          return -1;
        }
      }
    }

    // Final Checks
    // certificat matches
    for (int i = 0; i < system_configuration.number_proxy_applications; i++)
    {
      ret = -1;
      for (int j = 0; j < system_configuration.number_crypto_profiles; j++)
      {
        if (strcmp(system_configuration.proxy_applications[i].tunnel_crypto_profile_ID, system_configuration.crypto_profile[j].ID) == 0)
        {
          ret = 1;
          break;
        }
      }
      if (ret < 0)
      {
        LOG_ERROR("Tunnel Crypto Profile ID does not match any crypto profile");
        return -1;
      }
    }

    for (int i = 0; i < system_configuration.number_proxy_applications; i++)
    {
      ret = -1;
      for (int j = 0; j < system_configuration.number_crypto_profiles; j++)
      {
        if (strcmp(system_configuration.proxy_applications[i].asset_crypto_profile_ID, system_configuration.crypto_profile[j].ID) == 0)
        {
          ret = 1;
          break;
        }
      }
      if (ret < 0)
      {
        LOG_ERROR("Tunnel Crypto Profile ID does not match any crypto profile");
        return -1;
      }
    }

    cJSON_Delete(json);
    return 0;
  }
  return 0;
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
        strcpy(sys_proxy_appl->connection_whitelist.allowed_client_ip_port[i], js_item->valuestring);
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

int init_hardbeat_service(mgmt_container *mgmt, uint32_t hb_iv_seconds)
{

  int ret = -1;
  // non blocking fd
  int efd = zvfs_eventfd(0, EFD_NONBLOCK);
  if (efd < 0)
  {
    LOG_ERROR("Failed to create eventfd\n");
    return -1;
  }
  mgmt->hb_fd = efd;

  k_timer_user_data_set(&hb_timer, &efd);
  // timout = first offset
  // period = period
  k_timer_start(&hb_timer, K_SECONDS(0), K_SECONDS(hb_iv_seconds)); // 2-second periodic

  ret = poll_set_add_fd(&mgmt->poll_set,
                        efd,
                        POLLIN | POLLERR | POLLHUP);
  if (ret < 0)
  {
    LOG_ERROR("no space in poll_set");
    return ret;
  }
  return 1;
}

static void hb_timer_event_handler(struct k_timer *timer)
{
  int *efd = k_timer_user_data_get(timer);
  uint64_t u = 1;                              // increment eventfd by 1
  int ret = write(*efd, &u, sizeof(uint64_t)); // content doesnt matter at the moment
  if (ret < 0)
  {
    LOG_ERROR("Failed to write to eventfd, errno: %d\n", errno);
  }
}
