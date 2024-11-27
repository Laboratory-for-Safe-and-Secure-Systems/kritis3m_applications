

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
  poll_set pollfd[10];
  asl_endpoint_configuration management_endpoint_config;
  asl_endpoint *client_endpoint;
};

// will be used for management service
enum service_message_type
{
  SVC_MSG_INITIAL_POLICY_REQ_RSP,
  SVC_MSG_POLICY_REQ_RSP,
  SVC_MSG_KRITIS3M_SERVICE_STOP,
  SVC_MSG_RESPONSE
};

typedef struct service_message
{
  enum service_message_type msg_type;
  union kritis3m_service_payload
  {
    int placeholder;
    ManagementReturncode return_code;
  } payload;
} service_message;

// forward declarations
void *start_kristis3m_service(void *arg);
int setup_socketpair(int management_socket[2], bool blocking);
void init_configuration_manager(ConfigurationManager *manager, Kritis3mNodeConfiguration *node_config);
int create_folder_structure(Kritis3mNodeConfiguration *node_cfg);

enum MSG_RESPONSE_CODE svc_request_helper(int socket, service_message *msg);
int initial_policy_request_cb(struct response response);

ManagementReturncode handle_svc_message(int socket, service_message *msg);
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
  svc->management_socket[THREAD_EXT] = -1;
  svc->management_socket[THREAD_INT] = -1;
  pthread_attr_init(&svc->thread_attr);
  pthread_attr_setdetachstate(&svc->thread_attr, PTHREAD_CREATE_JOINABLE);
  poll_set_init(svc->pollfd);
  create_socketpair(svc->management_socket);
}

int start_kritis3m_service(char *config_file)
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
  asl_enable_logging(true);
  asl_set_log_level(ASL_LOG_LEVEL_DBG);

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

  ret = create_folder_structure(&svc.node_configuration);
  if (ret < 0)
  {
    LOG_ERROR("folder structure is incorrect");
    goto error_occured;
  }

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
    return 0;
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
  if (ret < 0)
  {
    LOG_ERROR("can't prepare iface");
    goto error_occured;
  }
  svc.initialized = true;

  // 7. start management application
  ret = pthread_create(&svc.mainthread, &svc.thread_attr, start_kristis3m_service, &svc);
  if (ret < 0)
  {
    LOG_ERROR("can't create kritis3m_service thread");
    goto error_occured;
  }

  // 8. Start application manager
  ret = start_application_manager(&svc.configuration_manager.primary.application_config);
  if (ret < 0)
  {
    LOG_ERROR("can't start application manage");
    goto error_occured;
  }

  return 0;
error_occured:

  LOG_ERROR("exit kritis3m_service");
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
  struct poll_set *pollfd = svc->pollfd;
  int hb_interval_sec = 10;
  int ret = 0;
  SystemConfiguration *selected_sys_cfg = NULL;
  ManagementReturncode retval = MGMT_OK;

  asl_endpoint_configuration *ep_cfg = &svc->management_endpoint_config;
  Kritis3mNodeConfiguration node_configuration = svc->node_configuration;
  ConfigurationManager application_configuration_manager = svc->configuration_manager;
  enum appl_state appl_state = APPLICATION_MANAGER_OFF;

  ret = poll_set_add_fd(pollfd, svc->management_socket[THREAD_INT], POLLIN | POLLERR);
  if (ret < 0)
  {
    LOG_ERROR("cant add fd to to pollset, shutting down management service");
    goto terminate;
  }

  while (1)
  {

    ret = poll(pollfd->fds, pollfd->num_fds, -1);

    if (ret == -1)
    {
      LOG_ERROR("poll error: %d", errno);
      continue;
    }
    if (ret == 0)
    {
      continue;
    }
    for (int i = 0; i < pollfd->num_fds; i++)
    {
      int fd = pollfd->fds[i].fd;
      short event = pollfd->fds[i].revents;

      if (event == 0)
        continue;

      /* Check management socket */
      if (fd == svc->management_socket[THREAD_INT])
      {
        if (event & POLLIN)
        {
          service_message req = {0};
          ManagementReturncode return_code = handle_svc_message(svc->management_socket[THREAD_INT], &req);
          if (return_code == MGMT_THREAD_STOP)
            pthread_exit(NULL);
        }
      }
    }
  }

terminate:
  cleanup_kritis3m_service();
  pthread_exit(NULL);
  // terminate_application_manager
  // store config
  return NULL;
}
int setup_socketpair(int management_socket[2], bool blocking)
{
  int ret = create_socketpair(management_socket);
  if (ret < 0)
  {
    LOG_ERROR("Error creating management socket pair: %d (%s)", errno, strerror(errno));
    return -1;
  }
  if (!blocking)
  {
    ret = setblocking(management_socket[THREAD_EXT], false);
    if (ret < 0)
    {
      LOG_ERROR("Error unblocking socket: %d (%s)", errno, strerror(errno));
      return -1;
    }
    ret = setblocking(management_socket[THREAD_INT], false);
    if (ret < 0)
    {
      LOG_ERROR("Error unblocking socket: %d (%s)", errno, strerror(errno));
      return -1;
    }
  }
  LOG_INFO("created management socketpair");
  return 0;
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
  manager->active_configuration = node_config->selected_configuration;
  strncpy(manager->primary_file_path, node_config->primary_path, MAX_FILEPATH_SIZE);
  strncpy(manager->secondary_file_path, node_config->secondary_path, MAX_FILEPATH_SIZE);
  cleanup_Systemconfiguration(&manager->primary);
  cleanup_Systemconfiguration(&manager->secondary);
}

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
  LOG_DEBUG("Policy response is %d bytes long", response.bytes_received);

  LOG_INFO("Received %d bytes from mgmt server: ", response.bytes_received);
  LOG_DEBUG("write response to %s", policy_filepath);
  if (response.http_status_code = 200)
  {
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
  request.msg_type = SVC_MSG_INITIAL_POLICY_REQ_RSP;

  enum MSG_RESPONSE_CODE retval = svc_request_helper(socket, &request);
  if (retval != MSG_OK)
  {
    ret = -1;
    LOG_ERROR("error occured in application service");
  }
  else
  {
    LOG_INFO("closed application_manager succesfully");
  }
  closesocket(socket); // closing socket anyway
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

ManagementReturncode handle_svc_message(int socket, service_message *msg)
{
  int ret = 0;
  ManagementReturncode return_code = MGMT_OK;
  service_message rsp = {0};
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

    stop_application_manager();
    svc_respond_with(socket, MGMT_OK);
    cleanup_kritis3m_service();
    LOG_WARN("SVC_MSG_POLICY_REQ_RSP: handler not implemented yet");
    return_code = MGMT_THREAD_STOP;
    break;
  }
  case SVC_MSG_KRITIS3M_SERVICE_STOP:
  {
    LOG_WARN("SVC_MSG_INITIAL_POLICY_REQ_RSP: handler not implemented yet");
    break;
  }
  case SVC_MSG_RESPONSE:
  {
    LOG_INFO("received response: %d", msg->payload.return_code);
    break;
  }
  default:
    LOG_WARN("message type %d, not covered", msg->msg_type);
    return_code = MGMT_ERR;
    break;
  }
  return return_code;

error_occured:
  return_code = MGMT_ERR;
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
  closesocket(svc.management_socket[THREAD_EXT]);
  closesocket(svc.management_socket[THREAD_INT]);
  free_NodeConfig(&svc.node_configuration);
  cleanup_configuration_manager(&svc.configuration_manager);
}