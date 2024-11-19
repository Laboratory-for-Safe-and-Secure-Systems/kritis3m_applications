

#include "kritis3m_scale_service.h"
#include "logging.h"
LOG_MODULE_CREATE(kritis3m_service);
#include "cJSON.h"
#include "http_client.h"
#include "sys/timerfd.h"
#include "http_service.h"
#include "crypto_parser.h"
#include "networking.h"
#include "utils.h"
#include <errno.h>
#include <pthread.h>
#include "kritis3m_application_manager.h"


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
  TimerPipe *hardbeat_timer;
  poll_set pollfd[10];
  asl_endpoint_configuration management_endpoint_config;
  asl_endpoint *client_endpoint;
};

enum service_message_type
{
  HTTP_SERVICE,
  MANAGEMENT_MESSAGE,
  RESPONSE,
};

typedef struct service_message
{
  enum service_message_type msg_type;
  union kritis3m_service_payload
  {
    enum ManagementEvents event;
    int return_code;
  } payload;
} service_message;

// forward declarations
void *start_kristis3m_service(void *arg);
int setup_socketpair(int management_socket[2], bool blocking);
void *http_get_request(void *http_get_data);
void init_configuration_manager(ConfigurationManager *manager, Kritis3mNodeConfiguration *node_config);
int create_folder_structure(Kritis3mNodeConfiguration *node_cfg);

// callbacks used from the http threads
int initial_policy_request_cb(struct response response);
static int send_management_message(int socket, service_message *msg);
static int read_management_message(int socket, service_message *msg);

/*********************************************************
 *              HTTP-SERVICE
 */
static struct kritis3m_service svc = {0};
void set_kritis3m_serivce_defaults(struct kritis3m_service *svc)
{
  if (svc == NULL)
    return;
  svc->hardbeat_timer = get_timer_pipe();
  init_posix_timer(svc->hardbeat_timer);
  memset(&svc->configuration_manager, 0, sizeof(ConfigurationManager));
  memset(&svc->management_endpoint_config, 0, sizeof(asl_endpoint_configuration));
  memset(&svc->node_configuration, 0, sizeof(Kritis3mNodeConfiguration));
  svc->management_socket[THREAD_EXT] = -1;
  svc->management_socket[THREAD_INT] = -1;
  pthread_attr_init(&svc->thread_attr);
  pthread_attr_setdetachstate(&svc->thread_attr, PTHREAD_CREATE_JOINABLE);
  init_posix_timer(svc->hardbeat_timer);
  poll_set_init(svc->pollfd);
  setup_socketpair(svc->management_socket, true);
}

int initialize_crypto(kritis3m_service *svc)
{
  int ret = 0;
  char private_key_buffer[512];
  memset(private_key_buffer, 0, 512);

  // check if privae key available
  const char *privateKey = "management_service_privateKey.pem";
  const char *chain = "management_service_chain.pem";
  const char *root = "management_service_root.pem";
  ret = create_file_path(private_key_buffer, sizeof(private_key_buffer),
                         svc->node_configuration.pki_cert_path, svc->node_configuration.pki_cert_path_size,
                         privateKey, sizeof(privateKey));
  if (ret < 0)
    goto error_occured;
  if (access(private_key_buffer, F_OK) != 0)
  {
    LOG_INFO("call crypto with machine key");
  }
  LOG_INFO("calling pki not implemented yet");
error_occured:
  ret = -1;
  LOG_ERROR("error occured during crypto initialization");
  return ret;
}

int init_kritis3m_service(char *config_file)
{
  // initializations
  int ret = 0;
  CryptoProfile default_profile = {
      .ASLKeyExchangeMethod = ASL_KEX_DEFAULT,
      .HybridSignatureMode = ASL_HYBRID_SIGNATURE_MODE_DEFAULT,
      .Keylog = "/home/philipp/kritis/linux_development/kritis3m_workspace/repositories/kritis3m_tls_linux/keylog.txt",
      .MutualAuthentication = true,
      .Name = "default",
      .NoEncryption = false,
      .UseSecureElement = false,
  };

  // get global node config
  set_kritis3m_serivce_defaults(&svc);
  svc.node_configuration.config_path = config_file;
  svc.node_configuration.config_path_size = strlen(config_file);

  ret = get_Kritis3mNodeConfiguration(config_file, &svc.node_configuration);
  if (ret < 0)
  {
    LOG_ERROR("can't parse Config, error occured: %d ", errno);
    return ret;
  }
  // create_folder_structure(&svc.node_configuration);

  ret = create_endpoint_config(&svc.node_configuration.management_identity.identity, &default_profile, &svc.management_endpoint_config);
  if (ret < 0)
  {
    LOG_ERROR("endpoint config error");
    goto error_occured;
  }

  ret = init_http_service(&svc.node_configuration.management_identity, &svc.management_endpoint_config);
  if (ret < 0)
  {
    LOG_ERROR("can't init http_service");
  }
  init_configuration_manager(&svc.configuration_manager, &svc.node_configuration);
  ret = call_distribution_service(initial_policy_request_cb, svc.node_configuration.primary_path);
  if (ret < 0 ){
    LOG_ERROR("error occured calling distribution service");
    return 0;
  }
  if (svc.configuration_manager.active_configuration == CFG_NONE)
  {
    LOG_INFO("no configuration selected. Starting with primary configuration");
    svc.configuration_manager.active_configuration = CFG_PRIMARY;
  }
  ManagementReturncode retval = get_Systemconfig(&svc.configuration_manager, &svc.node_configuration);
  if (retval != MGMT_OK)
    goto error_occured;
  
  svc.initialized = true;

  init_application_manager();
  start_application_manager(&svc.configuration_manager.primary.application_config);
  while(1){
usleep(10* 1000);

  }


  ret = pthread_create(&svc.mainthread, &svc.thread_attr, start_kristis3m_service, &svc);

  return 0;
error_occured:
  free_NodeConfig(&svc.node_configuration);
  ret = -1;
  // dont forget to free configuration and endpoint
  return ret;
}

void *start_kristis3m_service(void *arg)
{

  struct kritis3m_service *svc = (struct kritis3m_service *)arg;
  if (svc == NULL)
    goto terminate;

  struct poll_set *pollfd = svc->pollfd;
  TimerPipe *heartbeat_timer = svc->hardbeat_timer;
  int hb_interval_sec = 10;
  int ret = 0;
  SystemConfiguration *selected_sys_cfg = NULL;
  ManagementReturncode retval = MGMT_OK;

  asl_endpoint_configuration *ep_cfg = &svc->management_endpoint_config;
  Kritis3mNodeConfiguration node_configuration = svc->node_configuration;
  ConfigurationManager application_configuration_manager = svc->configuration_manager;

  ret = poll_set_add_fd(pollfd, get_clock_signal_fd(heartbeat_timer), POLLIN | POLLERR);
  if (ret < 0)
  {
    LOG_ERROR("cant add fd to to pollset, shutting down management service");
    goto terminate;
  }
  ret = poll_set_add_fd(pollfd, svc->management_socket[THREAD_INT], POLLIN | POLLERR);
  if (ret < 0)
  {
    LOG_ERROR("cant add fd to to pollset, shutting down management service");
    goto terminate;
  }

  ret = timer_start(heartbeat_timer, hb_interval_sec);
  while (1)
  {
    ret = poll(pollfd->fds, pollfd->num_fds, -1);

    if (ret == -1)
    {
      LOG_ERROR("poll error: %d", errno);
      continue;
    }
    for (int i = 0; i < pollfd->num_fds; i++)
    {
      int fd = pollfd->fds[i].fd;
      short event = pollfd->fds[i].revents;

      if (event == 0)
        continue;
      /* Check management socket */
      if (fd == svc->management_socket[1])
      {
        if (event & POLLIN)
        {
          /* Handle the message */
          // event = handle_management_message(svc->management_socket[1], fd, svc);
          if (ret == 1)
          {
          }
        }
      }
      else if (fd == get_clock_signal_fd(heartbeat_timer))
      {
        int buffer;
        read(fd, &buffer, sizeof(int));
        LOG_INFO("Heartbeat timer expired");
      }

      // services to embedd:
      //  timer
      //  application manger
      //  starting http request responses
    }
  }

terminate:
  free_NodeConfig(&svc->node_configuration);
  timer_terminate(heartbeat_timer);
  poll_set_remove_fd(pollfd, get_clock_signal_fd(heartbeat_timer));
  // terminate_application_manager
  // store config
  return NULL;
}
int setup_socketpair(int management_socket[2], bool blocking)
{
  int ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, management_socket);
  if (ret < 0)
  {
    LOG_ERROR("Error creating management socket pair: %d (%s)", errno, strerror(errno));
    return -1;
  }
  if (!blocking)
  {
    ret = setblocking(management_socket[0], false);
    if (ret < 0)
    {
      LOG_ERROR("Error unblocking socket: %d (%s)", errno, strerror(errno));
      return -1;
    }
    ret = setblocking(management_socket[1], false);
    if (ret < 0)
    {
      LOG_ERROR("Error unblocking socket: %d (%s)", errno, strerror(errno));
      return -1;
    }
  }
  LOG_INFO("created management socketpair");
  return 0;
}

static int send_management_message(int socket, service_message *msg)
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
      usleep(10 * 1000);
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
int create_folder_structure(Kritis3mNodeConfiguration *node_config)
{
  if (create_directory(node_config->config_path) == -1)
    return -1;
  if (create_directory(node_config->crypto_path) == -1)
    return -1;
  if (create_directory(node_config->pki_cert_path) == -1)
    return -1;
  if (create_directory(node_config->machine_crypto_path) == -1)
    return -1;

  create_identity_folder(node_config->pki_cert_path, MANAGEMENT_SERVICE);
  create_identity_folder(node_config->pki_cert_path, REMOTE);
  create_identity_folder(node_config->pki_cert_path, MANAGEMENT);
  create_identity_folder(node_config->pki_cert_path, PRODUCTION);
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
  // check if req was succesfull
  int ret = 0;
  service_message resp = {0};
  service_message req = {0};

  if (response.ret != MGMT_OK)
    goto error_occured;
  if (response.buffer == NULL)
    goto error_occured;
  LOG_INFO("Received %d bytes from mgmt server: ", response.bytes_received);
  if (response.meta.policy_req.destination_path == NULL)
    goto error_occured;
  ret = write_file(response.meta.policy_req.destination_path, response.buffer_frag_start, response.bytes_received);
  if (ret < 0)
  {
    LOG_ERROR("can't write response into buffer");
  }
  return ret;

  // req.msg_type = HTTP_SERVICE;
  // req.payload.event = MGMT_EV_MGM_RESP;

  // ret = send_management_message(svc.management_socket[THREAD_EXT], &req);
  // if (ret < 0)
  // {
  //   LOG_ERROR("cant send mgmt message");
  //   goto error_occured;
  // }
  // ret = read_management_message(svc.management_socket[THREAD_EXT], &resp);
  // if (ret < 0)
  // {
  //   LOG_ERROR("receive mgmt_message");
  //   goto error_occured;
  // }
  // if ((resp.msg_type == RESPONSE) && (resp.payload.return_code == 0))
  // {
  //   LOG_ERROR("Resposne was succefull ");
  // }

  if (response.buffer != NULL)
    free(response.buffer);
  return ret;
error_occured:

  if (response.buffer != NULL)
    free(response.buffer);
  return ret;
}