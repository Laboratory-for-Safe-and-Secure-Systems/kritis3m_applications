

#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include "logging.h"
#include "sys/timerfd.h"
#include "http_service.h"
#include "networking.h"
#include "utils.h"

#include "cJSON.h"
#include "http_client.h"

#include "crypto_parser.h"
#include "kritis3m_scale_service.h"
#include "kritis3m_application_manager.h"

LOG_MODULE_CREATE(kritis3m_service);

#define SIMULTANIOUS_REQs 5
#define ENROLL_BUFFER_SIZE 2000
#define REENROLL_BUFFER_SIZE 2000
#define DISTRIBUTION_BUFFER_SIZE 3000
#define POLICY_RESP_BUFFER_SIZE 1000
#define HEARTBEAT_REQ_BUFFER_SIZE 1000

// returned by http request
// thread object for http get requests
struct http_get_request
{
  char *request_url;
  struct sockaddr_in server_addr;
  enum used_service used_service;
  asl_endpoint *ep; // used for tls
  t_http_get_cb cb; // callback function to signal the mainthread the result
};

// main service object
struct kritis3m_service
{
  bool initialized;
  Kritis3mNodeConfiguration node_configuration;
  ConfigurationManager configuration_manager;
  int management_socket[2];
  pthread_t mainthread;
  pthread_attr_t thread_attr;
  poll_set pollfd;
  asl_endpoint_configuration management_endpoint_config;
  asl_endpoint *client_endpoint;
};

// will be used for management service
enum service_message_type
{
  SVC_MSG_INITIAL_POLICY_REQ_RSP,
  SVC_MSG_POLICY_REQ_RSP,
  SVC_MSG_KRITIS3M_SERVICE_STOP,
  SVC_MSG_RESPONSE,
  SVC_MSG_APPLICATION_MANGER_STATUS_REQ,
};

typedef struct service_message
{
  enum service_message_type msg_type;
  union kritis3m_service_payload
  {
    struct appl_manager_status
    {
      ApplicationManagerStatus status;
    } appl_status;
    ManagementReturncode return_code;
  } payload;
} service_message;

// forward declarations
void *start_kristis3m_service(void *arg);
void init_configuration_manager(ConfigurationManager *manager, Kritis3mNodeConfiguration *node_config);
int create_folder_structure(Kritis3mNodeConfiguration *node_cfg);
enum MSG_RESPONSE_CODE svc_request_helper(int socket, service_message *msg);
int initial_policy_request_cb(struct response response);

// cfg_id and version number are temporary arguments and will be cleaned up after the testing
ManagementReturncode handle_svc_message(int socket, service_message *msg, int cfg_id, int version_number);
static int send_svc_message(int socket, service_message *msg);
static int read_svc_message(int socket, service_message *msg);

void cleanup_kritis3m_service();

int respond_with(int socket, enum MSG_RESPONSE_CODE response_code);

int prepare_all_interfaces(HardwareConfiguration hw_config[], int num_configs);

/*********************************************************
 *              HTTP-SERVICE
 */
static struct kritis3m_service svc = {0};
void set_kritis3m_serivce_defaults(struct kritis3m_service *svc)
{
  if (svc == NULL)
    return;
  memset(&svc->configuration_manager, 0, sizeof(ConfigurationManager));
  memset(&svc->management_endpoint_config, 0, sizeof(asl_endpoint_configuration));
  memset(&svc->node_configuration, 0, sizeof(Kritis3mNodeConfiguration));
  create_socketpair(svc->management_socket);
  pthread_attr_init(&svc->thread_attr);
  pthread_attr_setdetachstate(&svc->thread_attr, PTHREAD_CREATE_JOINABLE);
  poll_set_init(&svc->pollfd);
}

int start_kritis3m_service(char *config_file, int log_level)
{
  // initializations
  int ret = 0;

  CryptoProfile default_profile = {
      .ASLKeyExchangeMethod = ASL_KEX_DEFAULT,
      .HybridSignatureMode = ASL_HYBRID_SIGNATURE_MODE_DEFAULT,
      .MutualAuthentication = true,
      .Name = "default",
      .NoEncryption = false,
      .UseSecureElement = false,
  };
  /** -------------- set log level ----------------------------- */
  asl_enable_logging(true);
  asl_set_log_level(log_level);
  LOG_LVL_SET(log_level);

  // get global node config
  set_kritis3m_serivce_defaults(&svc);
  svc.node_configuration.config_path = config_file;
  svc.node_configuration.config_path_size = strlen(config_file);
  init_application_manager();

  // reads and the configfile and parses content to node_configuration
  ret = get_Kritis3mNodeConfiguration(config_file, &svc.node_configuration);
  if (ret < 0)
  {
    LOG_ERROR("can't parse Config, error occured: %d ", errno);
    return ret;
  }
  if ((svc.node_configuration.primary_path == NULL) || (svc.node_configuration.config_path == NULL) || (svc.node_configuration.pki_cert_path == NULL))
  {
    LOG_ERROR("filepaths incorrect"); 
    return -1;
  }

  // pass middleware and pin from cli to endpoint conf
  svc.management_endpoint_config.pkcs11.long_term_crypto_module.path = svc.node_configuration.management_identity.secure_middleware_path;
  svc.management_endpoint_config.pkcs11.long_term_crypto_module.pin = svc.node_configuration.management_identity.pin;

  // 2. setsup endpoint configuration, used to communicate with the controller
  ret = create_endpoint_config(&svc.node_configuration.management_identity.identity, &default_profile, &svc.management_endpoint_config);
  if (ret < 0)
  {
    LOG_ERROR("endpoint config error");
    goto error_occured;
  }

  // 3. initializeation of http service, which is responsible for handling the communication with the controller
  ret = init_http_service(&svc.node_configuration.management_identity, &svc.management_endpoint_config);
  if (ret < 0)
  {
    LOG_ERROR("can't init http_service");
  }

  // 4. initialization of configuration manager
  /**
   * @brief the configuration manager stores the application data.
   * To ensure a secure update with rollback functionality, two applicationconfigs, primary and secondary are used
   * - In this state only the primary object is used
   */
  init_configuration_manager(&svc.configuration_manager, &svc.node_configuration);

  // 5. calls the distibution server
  /**
   * @brief at the moment, the server request is synchronous, so there is no need to offload it to the main thread
   * in the future each request will be handled in an own thread, using the thread pool
   */
  ret = initial_call_controller(initial_policy_request_cb);
  if (ret < 0)
  {
    LOG_ERROR("error occured calling distribution service");
    goto error_occured;
  }
  // set primary application config
  if (svc.configuration_manager.active_configuration == CFG_NONE)
  {
    LOG_INFO("no configuration selected. Starting with primary configuration");
    svc.configuration_manager.active_configuration = CFG_PRIMARY;
  }

  // 5. Read and Parse application config
  ManagementReturncode retval = get_Systemconfig(&svc.configuration_manager, &svc.node_configuration);
  if (retval != MGMT_OK)
    goto error_occured;

  // 6. prepare hardware
  ret = prepare_all_interfaces(svc.configuration_manager.primary.application_config.hw_config,
                               svc.configuration_manager.primary.application_config.number_hw_config);
  svc.initialized = true;

  // 7. start management application
  ret = pthread_create(&svc.mainthread, &svc.thread_attr, start_kristis3m_service, &svc);
  if (ret < 0)
  {
    LOG_ERROR("can't create kritis3m_service thread");
    goto error_occured;
  }

  return 0;
error_occured:
  LOG_INFO("exit kritis3m_service");
  stop_application_manager();
  cleanup_kritis3m_service();
  return ret;
}

void *start_kristis3m_service(void *arg)
{

  enum appl_state
  {
    APPLICATION_MANAGER_OFF,
    APPLICATION_MANAGER_ENABLED,
  };

  LOG_INFO("kritis3m_service started");

  struct kritis3m_service *svc = (struct kritis3m_service *)arg;
  if (svc == NULL)
    goto terminate;

  int hb_interval_sec = 10;
  int ret = 0;
  SystemConfiguration *selected_sys_cfg = NULL;
  ManagementReturncode retval = MGMT_OK;
  int cfg_id = -1;
  int version_number = -1;

  asl_endpoint_configuration *ep_cfg = &svc->management_endpoint_config;
  Kritis3mNodeConfiguration node_configuration = svc->node_configuration;
  ConfigurationManager application_configuration_manager = svc->configuration_manager;

  ret = poll_set_add_fd(&svc->pollfd, svc->management_socket[THREAD_INT], POLLIN | POLLERR);
  if (ret < 0)
  {
    LOG_ERROR("cant add fd to to pollset, shutting down management service");
    goto terminate;
  }

  // 8. Start application manager
  ret = start_application_manager(&application_configuration_manager.primary.application_config);
  if (ret < 0)
  {
    LOG_ERROR("can't start application manage");
    goto terminate;
  }

  cfg_id = application_configuration_manager.primary.cfg_id;
  version_number = application_configuration_manager.primary.version;

  while (1)
  {

    ret = poll(svc->pollfd.fds, svc->pollfd.num_fds, -1);

    if (ret == -1)
    {
      LOG_ERROR("poll error: %d", errno);
      continue;
    }
    if (ret == 0)
    {
      continue;
    }
    for (int i = 0; i < svc->pollfd.num_fds; i++)
    {
      int fd = svc->pollfd.fds[i].fd;
      short event = svc->pollfd.fds[i].revents;

      if (event == 0)
        continue;

      /* Check management socket */
      if (fd == svc->management_socket[THREAD_INT])
      {
        if (event & POLLIN)
        {
          service_message req = {0};
          ManagementReturncode return_code = handle_svc_message(svc->management_socket[THREAD_INT], &req, cfg_id, version_number);

          if (return_code == MGMT_THREAD_STOP)
          {
            poll_set_remove_fd(&svc->pollfd, svc->management_socket[THREAD_INT]);
            goto terminate;
          }
          else if (return_code < 0)
          {
            poll_set_remove_fd(&svc->pollfd, svc->management_socket[THREAD_INT]);
            closesocket(svc->management_socket[THREAD_INT]);
            closesocket(svc->management_socket[THREAD_EXT]);
            LOG_ERROR("error occured in handling service message");
            goto terminate;
          }
        }
      }
    }
  }

terminate:
  LOG_DEBUG("Leaving kritis3m_service main thread");

  stop_application_manager();
  cleanup_kritis3m_service();
  pthread_detach(pthread_self());
  return NULL;
}

// deprecated
int create_identity_folder(const char *base_path, network_identity identity)
{
  char identity_path[256];

  // Get the path for the identity folder
  if (get_identity_folder_path(identity_path, sizeof(identity_path), base_path, identity) == -1)
  {
    return -1;
  }
  // Create the directory for the specified identity
  if (create_directory(identity_path) == -1)
  {
    return -1;
  }

  return 0;
}

//@todo clean up
int create_folder_structure(Kritis3mNodeConfiguration *node_config)
{
  char helper_string[512];
  /**---------------------- Create Base Folder Structure -------------------------- */
  if (!directory_exists(node_config->config_path))
  {
    LOG_ERROR("config path does not exist. Pls check the config folder path, or create the folder");
    return -1;
  }
  if (!directory_exists(node_config->crypto_path))
  {
    LOG_ERROR("crypto path does not exist. Pls check the crypto folder path, or create the folder");
    return -1;
  }

  /**---------------------- Create Identity Path and machine path -------------------------- */
  if (create_directory(node_config->pki_cert_path) == -1)
    return -1;
  if (create_directory(node_config->machine_crypto_path) == -1)
    return -1;
  if (create_directory(node_config->management_path) == -1)
    return -1;
  if (create_directory(node_config->management_service_path) == -1)
    return -1;
  if (create_directory(node_config->remote_path) == -1)
    return -1;
  if (create_directory(node_config->production_path) == -1)
    return -1;

  /**------------------------Create Subfolder for application config primary and secondary ----*/
  return 0;
}

void init_configuration_manager(ConfigurationManager *manager, Kritis3mNodeConfiguration *node_config)
{
  if ((node_config == NULL) || (manager == NULL))
    return;
  manager->active_configuration = node_config->selected_configuration;
  strncpy(manager->primary_file_path, node_config->primary_path, MAX_FILEPATH_SIZE);
  strncpy(manager->secondary_file_path, node_config->secondary_path, MAX_FILEPATH_SIZE);
  cleanup_Systemconfiguration(&manager->primary);
  cleanup_Systemconfiguration(&manager->secondary);
}

//------------------------------------------ HARDWARE INFORMATION --------------------------------------- //
#define MAX_CMD_LENGTH 512

static int is_ipv6_address(const char *ip_cidr)
{
  return (strchr(ip_cidr, ':') != NULL);
}

static int parse_ip_cidr(const char *ip_cidr, char *ip_addr, char *cidr)
{
  const char *slash = strchr(ip_cidr, '/');
  if (!slash)
  {
    return -1;
  }

  size_t ip_len = slash - ip_cidr;
  strncpy(ip_addr, ip_cidr, ip_len);
  ip_addr[ip_len] = '\0';

  strncpy(cidr, slash + 1, 3);
  cidr[3] = '\0';

  return 0;
}

int prepare_all_interfaces(HardwareConfiguration hw_config[], int num_configs)
{
  if (!hw_config || num_configs <= 0 || num_configs > MAX_NUMBER_HW_CONFIG)
  {
    return -1;
  }

  char ip_addr[INET6_ADDRSTRLEN];
  char cidr[4];
  int failures = 0;

  // Process each interface configuration
  for (int i = 0; i < num_configs; i++)
  {
    if (parse_ip_cidr(hw_config[i].ip_cidr, ip_addr, cidr) != 0)
    {
      failures++;
      continue;
    }

    int is_ipv6 = is_ipv6_address(hw_config[i].ip_cidr);

    if (add_ip_address(hw_config[i].device, ip_addr, cidr, is_ipv6) < 0)
    {
      failures++;
    }
  }

  return (failures > 0) ? -1 : 0;
}

/*------------------------------------ MANAGEMENT REQUESTS ------------------------------------------------*/

// status report
//@brief sends report to controller
int req_send_status_report(ApplicationManagerStatus manager_status)
{
  int socket = -1;
  int ret = 0;
  service_message request = {0};

  if ((!svc.initialized) || (svc.management_socket[THREAD_EXT] < 0))
  {
    LOG_ERROR("Kritis3m_service is not initialized");
    ret = -1;
    return ret;
  }

  socket = svc.management_socket[THREAD_EXT];
  request.msg_type = SVC_MSG_APPLICATION_MANGER_STATUS_REQ;
  request.payload.appl_status.status = manager_status;

  enum MSG_RESPONSE_CODE retval = svc_request_helper(socket, &request);
  if (retval == MSG_ERROR)
  {
    LOG_DEBUG("req_send_status_report: Error occured, calling internal kritis3m_service thread");
  }
  else if (retval == MSG_OK)
  {
    ret = -1;
    LOG_DEBUG("req_send_status_report: succesfully send request to internal thread");
  }
  else if (retval == MSG_BUSY)
  {
    LOG_INFO("req_send_status_report: internal thread busy");
  }
  return retval;
}

// initiates cleanup and appl_manager termination
int stop_kritis3m_service()
{

  int socket = -1;
  int ret = 0;
  service_message request = {0};

  if ((!svc.initialized) || (svc.management_socket[THREAD_EXT] < 0))
  {
    LOG_ERROR("Kritis3m_service is not initialized");
    ret = -1;
    return ret;
  }

  socket = svc.management_socket[THREAD_EXT];
  request.msg_type = SVC_MSG_KRITIS3M_SERVICE_STOP;

  enum MSG_RESPONSE_CODE retval = svc_request_helper(socket, &request);
  if (retval == MGMT_THREAD_STOP)
  {
    LOG_DEBUG("Application service stop thread");
  }
  else if (retval == MSG_OK)
  {
    ret = -1;
    LOG_DEBUG("Kritis3m service stop request succesfull");
  }
  else
  {
    LOG_INFO("closed application_manager succesfully");
  }

  if (svc.management_socket[THREAD_INT] > 0)
  {
    closesocket(svc.management_socket[THREAD_INT]);
    svc.management_socket[THREAD_INT] = -1;
  }
  if (svc.management_socket[THREAD_EXT] > 0)
  {
    closesocket(svc.management_socket[THREAD_EXT]);
    svc.management_socket[THREAD_EXT] = -1;
  }
  pthread_join(svc.mainthread, NULL);
  LOG_DEBUG("mainthread closed");

  return ret;
}

int svc_respond_with(int socket, enum MSG_RESPONSE_CODE response_code)
{
  service_message response = {0};
  response.msg_type = SVC_MSG_RESPONSE;
  response.payload.return_code = response_code;
  return send_svc_message(socket, &response);
}

static int send_svc_message(int socket, service_message *msg)
{
  int ret = 0;
  static const int max_retries = 5;
  int retries = 0;

  while ((ret <= 0) && (retries < max_retries))
  {
    ret = send(socket, msg, sizeof(service_message), 0);
    if (ret < 0)
    {
      if (errno != EAGAIN)
      {
        LOG_ERROR("Error sending message: %d (%s)", errno, strerror(errno));
        return -1;
      }
      usleep(1 * 1000);
    }
    else if (ret != sizeof(service_message))
    {
      LOG_ERROR("Sent invalid message");
      return -1;
    }

    retries++;
  }

  if (retries >= max_retries)
  {
    LOG_ERROR("Failed to send message after %d retries", max_retries);
    return -1;
  }

  return 0;
}

// cfg_id and version number are temporary arguments and will be cleaned up after the testing
ManagementReturncode handle_svc_message(int socket, service_message *msg, int cfg_id, int version_number)
{
  int ret = 0;
  ManagementReturncode return_code = MGMT_OK;
  service_message rsp = {0};
  enum MSG_RESPONSE_CODE response_code = MSG_OK;
  ret = read_svc_message(socket, msg);
  if (ret < 0)
    goto error_occured;

  switch (msg->msg_type)
  {
  case SVC_MSG_INITIAL_POLICY_REQ_RSP:
  {
    LOG_WARN("SVC_MSG_INITIAL_POLICY_REQ_RSP: handler not implemented yet");
    break;
  }
  case SVC_MSG_POLICY_REQ_RSP:
  {
    LOG_WARN("SVC_MSG_POLICY_REQ_RSP: handler not implemented yet");
    break;
  }
  case SVC_MSG_APPLICATION_MANGER_STATUS_REQ:
  {
    char json_status[200];
    char *json_buffer = applicationManagerStatusToJson(&msg->payload.appl_status.status, json_status, 200);
    if (json_buffer == NULL)
    {
      response_code = MSG_ERROR;
    }
    else
    {
      int ret = send_statusto_server(NULL, version_number,
                                     cfg_id,
                                     json_buffer,
                                     200);
      if (ret > 0)
      {
        response_code = MSG_OK;
        LOG_DEBUG("succesfully send status to server");
      }
      else
      {
        LOG_ERROR("couldnt send status to server");
        response_code = MSG_ERROR;
      }
    }

    break;
  }
  case SVC_MSG_KRITIS3M_SERVICE_STOP:
  {
    LOG_INFO("SVC STOP: ");
    LOG_INFO("Kritis3m service: Received Stop Request");
    response_code = MSG_OK;
    return_code = MGMT_THREAD_STOP;
    break;
  }
  case SVC_MSG_RESPONSE:
  {
    LOG_INFO("received response: %d", msg->payload.return_code);
    return_code = MGMT_OK;
    return return_code;
    break;
  }
  default:
    LOG_WARN("message type %d, not covered", msg->msg_type);
    return_code = MGMT_ERR;
    return return_code;
    break;
  }
  svc_respond_with(socket, response_code);
  return return_code;

error_occured:
  return_code = MGMT_ERR;
  svc_respond_with(socket, MSG_ERROR);
  LOG_ERROR("handle_svc_message error: %d", ret);
  return ret;
}

static int read_svc_message(int socket, service_message *msg)
{
  int ret = recv(socket, msg, sizeof(service_message), 0);
  if (ret < 0)
  {
    LOG_ERROR("Error receiving message: %d (%s)", errno, strerror(errno));
    return -1;
  }
  else if (ret != sizeof(service_message))
  {
    LOG_ERROR("Received invalid response (ret=%d; expected=%lu)", ret, sizeof(service_message));
    return -1;
  }
  return 0;
}

enum MSG_RESPONSE_CODE svc_request_helper(int socket, service_message *msg)
{
  int ret;
  enum MSG_RESPONSE_CODE retval = MSG_OK;
  service_message response = {0};

  if (socket < 0)
    goto error_occured;
  ret = send_svc_message(socket, msg);
  if (ret < 0)
    goto error_occured;
  ret = read_svc_message(socket, &response);
  if (ret < 0)
    goto error_occured;
  if (response.msg_type == MSG_RESPONSE)
    retval = response.payload.return_code;
  else
    goto error_occured;
  return retval;

error_occured:
  retval = MSG_ERROR;
  return retval;
}

void cleanup_kritis3m_service()
{
  svc.initialized = false;
  free_NodeConfig(&svc.node_configuration);
  cleanup_configuration_manager(&svc.configuration_manager);
}

/**------------------------------ HTTP Callbacks */

int initial_policy_request_cb(struct response response)
{
  // -------------------- INIT ---------------------------//
  int ret = 0;
  service_message resp = {0};
  service_message req = {0};
  char *policy_filepath = svc.node_configuration.primary_path;

  if ((response.ret != MGMT_OK) || (policy_filepath == NULL) || (response.buffer == NULL))
  {
    LOG_ERROR("RETURN CODE: %d", response.ret);
    goto error_occured;
  }

  LOG_DEBUG("HTTP status code is %d", response.http_status_code);

  LOG_INFO("Received %d bytes from mgmt server: ", response.bytes_received);
  LOG_DEBUG("write response to %s", policy_filepath);
  if (response.http_status_code = 200)
  {
    if (response.bytes_received < 10)
    {
      LOG_ERROR("No config activated ");
      goto error_occured;
    }
    ret = write_file(policy_filepath, response.buffer_frag_start, response.bytes_received);
  }
  if (ret < 0)
  {
    LOG_ERROR("can't write response into buffer");
    goto error_occured;
  }
  /**
   * @todo signal main thread
   */
  return ret;
error_occured:
  ret = -1;
  return ret;
}
