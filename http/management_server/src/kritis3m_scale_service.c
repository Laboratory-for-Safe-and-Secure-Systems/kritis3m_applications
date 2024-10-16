

#include "kritis3m_scale_service.h"
#include "kritis3m_application_manager.h"
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

enum ManagementState
{
  /*0*/ MGMT_ERROR,
  /*1*/ MGMT_START,
  /*2*/ MGMT_INITIALIZING,
  /*3*/ MGMT_MGMT_UPDATE,
  /*4*/ MGMT_CONFIG_INCOMPLETE,
  /*5*/ MGMT_PKI_UPDATE,
  /*6*/ MGMT_RUNNING,
  /*7*/ MGMT_RUNNING_HB_HANDLE,
  /*8*/ MGMT_RUNNING_MGMT_UPDATE,
  /*9*/ MGMT_RUNNING_CONFIG_AVAILABLE,
  /*10*/ MGMT_RUNNING_PKI_UPDATE,
  elems_ManagementState,
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

const enum ManagementEvents ev_error = MGMT_EV_ERROR;
const enum ManagementEvents ev_start = MGMT_EV_START;
const enum ManagementEvents ev_init = MGMT_EV_INIT;
const enum ManagementEvents ev_mgm_resp = MGMT_EV_MGM_RESP;
const enum ManagementEvents ev_cfg_available = MGMT_EV_CONFIG_AVAILABLE;
const enum ManagementEvents ev_pki_resp = MGMT_EV_PKI_RESP;
const enum ManagementEvents ev_clock_req = MGMT_EV_HB_CLOCK_REQ;
const enum ManagementEvents ev_hb_resp = MGMT_EV_HB_RESP;
const enum ManagementEvents ev_cfg_complete = MGMT_EV_CONFIG_COMPLETE;

enum ManagementState state_transition_table[elems_ManagementState][elems_ManagementEvent] = {

    [MGMT_ERROR] = {
        MGMT_ERROR, // MGMT_EV_ERROR,
        MGMT_START, // MGMT_EV_START,
        MGMT_ERROR, // MGMT_EV_INIT
        MGMT_ERROR, // MGMT_EV_MGM_RESP,
        MGMT_ERROR, // MGMT_EV_CONFIG_AVAILABLE
        MGMT_ERROR, // MGMT_EV_PKI_RESP,
        MGMT_ERROR, // ,MGMT_EV_HB_CLOCK_REQ,
        MGMT_ERROR, // MGMT_EV_HB_RESP,
        MGMT_ERROR, // MGMT_EV_CONFIG_COMPLETE,
    },
    [MGMT_START] = {
        MGMT_ERROR,        // MGMT_EV_ERROR,
        MGMT_START,        // MGMT_EV_START,
        MGMT_INITIALIZING, // MGMT_EV_INIT
        MGMT_ERROR,        // MGMT_EV_MGM_RESP,
        MGMT_ERROR,        // MGMT_EV_CONFIG_AVAILABLE
        MGMT_ERROR,        // MGMT_EV_PKI_RESP,
        MGMT_ERROR,        // MGMT_EV_HB_CLOCK_REQ,
        MGMT_ERROR,        // MGMT_EV_HB_RESP,
        MGMT_ERROR,        // MGMT_EV_CONFIG_COMPLETE,
    },
    [MGMT_INITIALIZING] = {
        MGMT_ERROR,             // MGMT_EV_ERROR,
        MGMT_START,             // MGMT_EV_START,
        MGMT_INITIALIZING,      // MGMT_EV_INIT
        MGMT_MGMT_UPDATE,       // MGMT_EV_MGM_RESP,
        MGMT_CONFIG_INCOMPLETE, // MGMT_EV_CONFIG_AVAILABLE
        MGMT_ERROR,             // MGMT_EV_PKI_RESP,
        MGMT_ERROR,             // MGMT_EV_HB_CLOCK_REQ,
        MGMT_ERROR,             // MGMT_EV_HB_RESP,
        MGMT_ERROR,             // MGMT_EV_CONFIG_COMPLETE,
    },
    [MGMT_MGMT_UPDATE] = {
        MGMT_ERROR,        // MGMT_EV_ERROR,
        MGMT_START,        // MGMT_EV_START,
        MGMT_ERROR,        // MGMT_EV_INIT
        MGMT_MGMT_UPDATE,  // MGMT_EV_MGM_RESP,
        MGMT_INITIALIZING, // MGMT_EV_CONFIG_AVAILABLE
        MGMT_ERROR,        // MGMT_EV_PKI_RESP,
        MGMT_ERROR,        // MGMT_EV_HB_CLOCK_REQ,
        MGMT_ERROR,        // MGMT_EV_HB_RESP,
        MGMT_ERROR,        // MGMT_EV_CONFIG_COMPLETE,
    },
    [MGMT_CONFIG_INCOMPLETE] = {
        MGMT_ERROR,      // MGMT_EV_ERROR,
        MGMT_START,      // MGMT_EV_START,
        MGMT_ERROR,      // MGMT_EV_INIT
        MGMT_ERROR,      // MGMT_EV_MGM_RESP,
        MGMT_ERROR,      // MGMT_EV_CONFIG_AVAILABLE
        MGMT_PKI_UPDATE, // MGMT_EV_PKI_RESP,
        MGMT_ERROR,      // MGMT_EV_HB_CLOCK_REQ,
        MGMT_ERROR,      // MGMT_EV_HB_RESP,
        MGMT_RUNNING,    // MGMT_EV_CONFIG_COMPLETE,
    },
    [MGMT_PKI_UPDATE] = {
        MGMT_ERROR,             // MGMT_EV_ERROR,
        MGMT_START,             // MGMT_EV_START,
        MGMT_ERROR,             // MGMT_EV_INIT
        MGMT_ERROR,             // MGMT_EV_MGM_RESP,
        MGMT_CONFIG_INCOMPLETE, // MGMT_EV_CONFIG_AVAILABLE
        MGMT_PKI_UPDATE,        // MGMT_EV_PKI_RESP,
        MGMT_ERROR,             // MGMT_EV_HB_CLOCK_REQ,
        MGMT_ERROR,             // MGMT_EV_HB_RESP,
        MGMT_ERROR,             // MGMT_EV_CONFIG_COMPLETE,
    },
    [MGMT_RUNNING] = {
        MGMT_ERROR,             // MGMT_EV_ERROR,
        MGMT_START,             // MGMT_EV_START,
        MGMT_ERROR,             // MGMT_EV_INIT
        MGMT_ERROR,             // MGMT_EV_MGM_RESP,
        MGMT_ERROR,             // MGMT_EV_CONFIG_AVAILABLE
        MGMT_ERROR,             // MGMT_EV_PKI_RESP,
        MGMT_RUNNING,           // MGMT_EV_HB_CLOCK_REQ,
        MGMT_RUNNING_HB_HANDLE, // MGMT_EV_HB_RESP,
        MGMT_ERROR,             // MGMT_EV_CONFIG_COMPLETE,
    },

    [MGMT_RUNNING_MGMT_UPDATE] = {
        MGMT_ERROR,                    // MGMT_EV_ERROR,
        MGMT_START,                    // MGMT_EV_START,
        MGMT_ERROR,                    // MGMT_EV_INIT
        MGMT_ERROR,                    // MGMT_EV_MGM_RESP,
        MGMT_RUNNING_CONFIG_AVAILABLE, // MGMT_EV_CONFIG_AVAILABLE
        MGMT_ERROR,                    // MGMT_EV_PKI_RESP,
        MGMT_ERROR,                    // MGMT_EV_HB_CLOCK_REQ,
        MGMT_ERROR,                    // MGMT_EV_HB_RESP,
        MGMT_ERROR,                    // MGMT_EV_CONFIG_COMPLETE,
    },
    [MGMT_RUNNING_HB_HANDLE] = {
        MGMT_RUNNING,             // MGMT_EV_ERROR,
        MGMT_START,               // MGMT_EV_START,
        MGMT_ERROR,               // MGMT_EV_INIT
        MGMT_RUNNING_MGMT_UPDATE, // MGMT_EV_MGM_RESP,
        MGMT_ERROR,               // MGMT_EV_CONFIG_AVAILABLE
        MGMT_ERROR,               // MGMT_EV_PKI_RESP,
        MGMT_ERROR,               // MGMT_EV_HB_CLOCK_REQ,
        MGMT_ERROR,               // MGMT_EV_HB_RESP,
        MGMT_ERROR,               // MGMT_EV_CONFIG_COMPLETE,
    },

    [MGMT_RUNNING_CONFIG_AVAILABLE] = {
        MGMT_RUNNING,            // MGMT_EV_ERROR,
        MGMT_START,              // MGMT_EV_START,
        MGMT_ERROR,              // MGMT_EV_INIT
        MGMT_ERROR,              // MGMT_EV_MGM_RESP,
        MGMT_ERROR,              // MGMT_EV_CONFIG_AVAILABLE
        MGMT_RUNNING_PKI_UPDATE, // MGMT_EV_PKI_RESP,
        MGMT_ERROR,              // MGMT_EV_HB_CLOCK_REQ,
        MGMT_ERROR,              // MGMT_EV_HB_RESP,
        MGMT_RUNNING,            // MGMT_EV_CONFIG_COMPLETE,
    },
    [MGMT_RUNNING_PKI_UPDATE] = {
        MGMT_RUNNING,                  // MGMT_EV_ERROR,
        MGMT_START,                    // MGMT_EV_START,
        MGMT_ERROR,                    // MGMT_EV_INIT
        MGMT_ERROR,                    // MGMT_EV_MGM_RESP,
        MGMT_RUNNING_CONFIG_AVAILABLE, // MGMT_EV_CONFIG_AVAILABLE
        MGMT_RUNNING_PKI_UPDATE,       // MGMT_EV_PKI_RESP,
        MGMT_ERROR,                    // MGMT_EV_HB_CLOCK_REQ,
        MGMT_ERROR,                    // MGMT_EV_HB_RESP,
        MGMT_RUNNING,                  // MGMT_EV_CONFIG_COMPLETE,
    },
};
typedef enum ManagementState (*StateHandler)(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev);

enum ManagementState mgmt_error_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev);
enum ManagementState mgmt_start_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev);
enum ManagementState mgmt_initializing_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev);
enum ManagementState mgmt_mgmt_update_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev);
enum ManagementState mgmt_config_incomplete_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev);
enum ManagementState mgmt_pki_update_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev);
enum ManagementState mgmt_running_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev);
enum ManagementState mgmt_running_hb_handle_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev);
enum ManagementState mgmt_running_mgmt_update_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev);
enum ManagementState mgmt_running_config_available_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev);
enum ManagementState mgmt_running_pki_update_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev);

StateHandler state_handlers[elems_ManagementState] = {
    mgmt_error_handler,                    // MGMT_ERROR
    mgmt_start_handler,                    // MGMT_START
    mgmt_initializing_handler,             // MGMT_INITIALIZING
    mgmt_mgmt_update_handler,              // MGMT_MGMT_UPDATE
    mgmt_config_incomplete_handler,        // MGMT_CONFIG_INCOMPLETE
    mgmt_pki_update_handler,               // MGMT_PKI_UPDATE
    mgmt_running_handler,                  // MGMT_RUNNING
    mgmt_running_hb_handle_handler,        // MGMT_RUNNING_HB_HANDLE
    mgmt_running_mgmt_update_handler,      // MGMT_RUNNING_MGMT_UPDATE
    mgmt_running_config_available_handler, // MGMT_RUNNING_CONFIG_AVAILABLE
    mgmt_running_pki_update_handler        // MGMT_RUNNING_PKI_UPDATE
};
enum ManagementState handle_event(enum ManagementState current_state, enum ManagementEvents event, struct kritis3m_service *svc, void *data)
{
  enum ManagementEvents const *optional_ev = NULL;
  enum ManagementEvents current_event;

  enum ManagementState next_state = state_transition_table[current_state][event];
  if (next_state < elems_ManagementState)
  {
    current_state = state_handlers[next_state](event, svc, data, &optional_ev);
  }
  while (optional_ev != NULL)
  {
    event = *optional_ev;
    optional_ev = NULL;
    enum ManagementState next_state = state_transition_table[current_state][event];
    if (next_state < elems_ManagementState)
    {
      current_state = state_handlers[next_state](event, svc, data, &optional_ev);
    }
  }
  return current_state;
}

// forward declarations
void *start_kristis3m_service(void *arg);
int setup_socketpair(int management_socket[2], bool blocking);
void *http_get_request(void *http_get_data);
int init_configuration_manager(ConfigurationManager *manager, Kritis3mNodeConfiguration *node_config);
int create_folder_structure(Kritis3mNodeConfiguration *node_cfg);
static void http_get_cb(struct http_response *rsp,
                        enum http_final_call final_data,
                        void *user_data);

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
  svc->management_socket[0] = -1;
  svc->management_socket[1] = -1;
  pthread_attr_init(&svc->thread_attr);
  pthread_attr_setdetachstate(&svc->thread_attr, PTHREAD_CREATE_JOINABLE);
  init_posix_timer(svc->hardbeat_timer);
  poll_set_init(svc->pollfd);
  setup_socketpair(svc->management_socket, true);
}

int initialize_crypto(kritis3m_service *svc)
{
  int ret = 0;
  // check pki management_service certificates
  // if they are not initialized, enroll is called

  // requirements: management_service_chain.pem available
  // requirements: management_service_root.pem available
  // requirements: management_service_privateKey.pem available
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

int init_kristis3m_service(char *config_file)
{
  // initializations
  int ret = 0;
  // get global node config
  set_kritis3m_serivce_defaults(&svc);
  svc.node_configuration.kritis3m_node_configuration_path = config_file;
  ret = get_Kritis3mNodeConfiguration(config_file, &svc.node_configuration);
  if (ret < 0)
  {
    LOG_ERROR("can't parse Config, error occured: %d ", errno);
    return ret;
  }
  // set default of main service object
  // initialize_crypto(&svc); // enroll would be called
  // now, the certificates for further communication with the management server should be available
  // The PKI-Client is not implemented yet, but will be in the future
  // The Certificates are now obtained from the file system and parsed into the asl_endpoint_configuration object
  create_folder_structure(&svc.node_configuration);
  char management_identity[400];
  ret = get_identity_folder_path(management_identity, sizeof(management_identity),
                                 svc.node_configuration.pki_cert_path,
                                 svc.node_configuration.management_identity.identity.identity);
  if (ret < 0)
    goto error_occured;
  certificates_to_endpoint(management_identity, sizeof(management_identity),
                           &svc.node_configuration.management_identity.identity,
                           &svc.management_endpoint_config);
  init_http_service(&svc.node_configuration.management_identity, &svc.management_endpoint_config);
  // initialize configuration manager
  ret = init_configuration_manager(&svc.configuration_manager, &svc.node_configuration);
  ret = pthread_create(&svc.mainthread, &svc.thread_attr, start_kristis3m_service, &svc);

  return 0;
error_occured:
  free_NodeConfig(&svc.node_configuration);
  ret = -1;
  // dont forget to free configuration and endpoint
  return ret;
}
// check secondary and primary
int complete_crypto_dependencies()
{
  int ret = -1;
  // search for identities in cryptos
  // for each identity call pki for updates
  LOG_INFO("call management pki");
  LOG_INFO("call remote pki");
  LOG_INFO("call remote pki");

  return ret;
}
void *start_kristis3m_service(void *arg)
{
  // // SystemConfiguration *active_config = get_active_configuration(svc->configuration_manager);
  // if (active_config == NULL)
  // {
  //   LOG_ERROR("shutdown kritis3m_service, no active config availalble");
  //   goto terminate;
  // }
  // complete_crypto_dependencies();

  // application_manager_config application_config;
  // application_config.log_level = LOG_LVL_DEBUG;
  // init_application_manager(&application_config);

  // 1. call hardbeat service for updates
  // 2. wait for response
  // 3. ask configuration service if changed
  // 4. Attach workers

  // things to do:
  // read config
  // derive jobs
  // -> call pki
  // ->call management server
  // others:
  // start jobs:
  // await jobs

  struct poll_set *pollfd = NULL;
  TimerPipe *mpipe = NULL;
  int hb_interval_sec = 2;
  SystemConfiguration *selected_sys_cfg = NULL;
  int ret = 0;
  ManagementReturncode retval = MGMT_OK;
  asl_endpoint_configuration *ep_cfg = NULL;
  struct kritis3m_service *svc = (struct kritis3m_service *)arg;

  mpipe = svc->hardbeat_timer;
  pollfd = svc->pollfd;

  enum ManagementState current_state = MGMT_START;
  enum ManagementEvents current_event = MGMT_EV_START;
  void *data = NULL;

  if (svc == NULL)
    goto terminate;

  // holds both, primary and secondary configuration.
  // either primary or secondary configuration is used by the application manager. The free configuration is used for the update process
  Kritis3mNodeConfiguration node_configuration = svc->node_configuration;
  ConfigurationManager application_configuration_manager = svc->configuration_manager;

  // retval = get_Systemconfig(&application_configuration_manager, &node_configuration);

  // if ((retval == MGMT_EMPTY_OBJECT_ERROR) ||
  //     (retval == MGMT_PARSE_ERROR) ||
  //     (retval == MGMT_ERR))
  // {
  //   SelectedConfiguration selected_config = application_configuration_manager.active_configuration;
  // }

  // else if (retval < MGMT_OK)
  //   goto terminate;

  ret = poll_set_add_fd(pollfd, get_clock_signal_fd(mpipe), POLLIN | POLLERR);
  if (ret < 0)
  {
    LOG_ERROR("cant add fd to to pollset, shutting down management service");
    goto terminate;
  }
  ret = poll_set_add_fd(pollfd, svc->management_socket[1], POLLIN | POLLERR);
  if (ret < 0)
  {
    LOG_ERROR("cant add fd to to pollset, shutting down management service");
    goto terminate;
  }

  ret = timer_start(mpipe, hb_interval_sec);
  while (1)
  {

    current_state = handle_event(current_state, current_event, svc, data);
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
      else if (fd == get_clock_signal_fd(mpipe))
      {
      }

      // services to embedd:
      //  timer
      //  application manger
      //  starting http request responses
    }
  }

terminate:
  free_NodeConfig(&svc->node_configuration);
  timer_terminate(mpipe);
  poll_set_remove_fd(pollfd, get_clock_signal_fd(mpipe));
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

static int read_management_message(int socket, service_message *msg)
{
  int ret = recv(socket, msg, sizeof(service_message), 0);
  if (ret < 0)
  {
    LOG_ERROR("Error receiving message: %d (%s)", errno, strerror(errno));
    return -1;
  }
  else if (ret != sizeof(service_message))
  {
    LOG_ERROR("Received invalid response (ret=%d; expected=%lu)", ret, sizeof(application_message));
    return -1;
  }

  return 0;
}

enum ManagementState mgmt_error_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev)
{
  printf("MGMT_ERROR: Handling event %d\n", event);
  // Perform error handling logic here

  return MGMT_ERROR;
}
enum ManagementState mgmt_start_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev)
{
  printf("MGMT_START: Handling event %d\n", event);
  LOG_INFO("Starting service");
  if (optional_ev != NULL)
    *optional_ev = &ev_init;
  return MGMT_START;
}
enum ManagementState mgmt_initializing_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev)
{
  if (optional_ev != NULL)
    *optional_ev = NULL;
  printf("MGMT_INITIALIZING: Handling event %d\n", event);
  LOG_INFO("reading config");
  Kritis3mNodeConfiguration node_configuration = svc->node_configuration;
  ConfigurationManager application_configuration_manager = svc->configuration_manager;
  call_distribution_service(initial_policy_request_cb, application_configuration_manager.primary_file_path);
  return MGMT_INITIALIZING;
}

enum ManagementState mgmt_mgmt_update_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev)
{
  if (optional_ev == NULL)
    *optional_ev = NULL;
  printf("MGMT_MGMT_UPDATE: Handling event %d\n", event);
  int ret = 0;
  struct response *rsp = (struct response *)data;

  if ((rsp->service_used == MGMT_POLICY_REQ) && (rsp->ret == MGMT_OK))
  {
    // ret = write_SystemConfig_toflash(&svc->configuration_manager, rsp->buffer, rsp->bytes_received);
    if (ret < 0)
    {
      LOG_ERROR("can't store response to flash");
      return MGMT_ERROR;
    }
  }
  else
  {
    LOG_ERROR("service returned with error");
    return MGMT_ERROR;
  }
  *optional_ev = &ev_init;
  return MGMT_MGMT_UPDATE;
}
enum ManagementState mgmt_config_incomplete_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev)
{
  printf("MGMT_CONFIG_INCOMPLETE: Handling event %d\n", event);
  // read out all certificates
  int ret = -1;
  SystemConfiguration *active_config = get_active_config(&svc->configuration_manager);
  if (active_config == NULL)
    return MGMT_ERROR;
  for (int i = 0; i < active_config->application_config.number_crypto_identity; i++)
  {
    // call pki server
    // will be implemented in the fututure
  }
  for (int i = 0; i < active_config->application_config.number_crypto_profiles; i++)
  {
    ret = initialize_crypto_endpoint(
        svc->node_configuration.pki_cert_path,
        svc->node_configuration.pki_cert_path_size,
        &active_config->application_config.crypto_profile[i]);
    if (ret < 0)
    {
      LOG_ERROR("can't parse crypto to endpoint");
    }
    return MGMT_ERROR;
  }

  if (event == MGMT_EV_PKI_RESP)
  {
    // handle pki event. By now its a shell skript
    return MGMT_CONFIG_INCOMPLETE;
  }
  if (optional_ev != NULL)
    *optional_ev = &ev_cfg_complete;
  return MGMT_CONFIG_INCOMPLETE;
}
enum ManagementState mgmt_pki_update_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev)
{
  if (optional_ev != NULL)
    *optional_ev = &ev_cfg_available;
  return MGMT_PKI_UPDATE;
}
enum ManagementState mgmt_running_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev)
{
  printf("MGMT_RUNNING: Handling event %d\n", event);
  SystemConfiguration *appl_config = NULL;
  int ret = 0;
  if (event == MGMT_EV_CONFIG_COMPLETE)
  {
    if (is_running())
    {
      stop_application_manager();
    }
    appl_config = get_active_config(&svc->configuration_manager);
    if (appl_config != NULL)
    {
      ret = start_application_manager(&appl_config->application_config);
      if (ret < 0)
        return MGMT_ERROR;
    }
  }
  else if (event == MGMT_EV_HB_CLOCK_REQ)
  {
    // do_heartbeat_request()
  }
  else
  {
    LOG_INFO("state running");
  }
  return MGMT_RUNNING;
}
enum ManagementState mgmt_running_hb_handle_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev)
{
  *optional_ev = NULL;
  printf("MGMT_RUNNING_HB_HANDLE: Handling event %d\n", event);
  if (event == MGMT_EV_MGM_RESP)
  {
    return MGMT_RUNNING_MGMT_UPDATE;
  }
  return MGMT_RUNNING_HB_HANDLE;
}
enum ManagementState mgmt_running_mgmt_update_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev)
{
  printf("MGMT_RUNNING_MGMT_UPDATE: Handling event %d\n", event);
  if (event == MGMT_EV_CONFIG_AVAILABLE)
  {
    return MGMT_RUNNING_CONFIG_AVAILABLE;
  }
  return MGMT_RUNNING_MGMT_UPDATE;
}
enum ManagementState mgmt_running_config_available_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev)
{
  printf("MGMT_RUNNING_CONFIG_AVAILABLE: Handling event %d\n", event);
  if (event == MGMT_EV_PKI_RESP)
  {
    return MGMT_RUNNING_PKI_UPDATE;
  }
  return MGMT_RUNNING_CONFIG_AVAILABLE;
}
enum ManagementState mgmt_running_pki_update_handler(enum ManagementEvents event, struct kritis3m_service *svc, void *data, enum ManagementEvents const **optional_ev)
{
  printf("MGMT_RUNNING_PKI_UPDATE: Handling event %d\n", event);
  if (event == MGMT_EV_CONFIG_COMPLETE)
  {
    return MGMT_RUNNING;
  }
  return MGMT_RUNNING_PKI_UPDATE;
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
  if (create_directory(node_config->application_configuration_path) == -1)
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

int init_configuration_manager(ConfigurationManager *manager, Kritis3mNodeConfiguration *node_config)
{
  int ret = 0;
  memset(&manager->primary, 0, sizeof(SystemConfiguration));
  memset(&manager->secondary, 0, sizeof(SystemConfiguration));
  ret = create_file_path(manager->primary_file_path, MAX_FILEPATH_SIZE,
                         node_config->application_configuration_path, node_config->application_configuration_path_size,
                         PRIMARY_FILENAME, sizeof(PRIMARY_FILENAME));
  if (ret < 0)
    return -1;
  ret = create_file_path(manager->secondary_file_path, MAX_FILEPATH_SIZE,
                         node_config->application_configuration_path, node_config->application_configuration_path_size,
                         SECONDARY_FILENAME, sizeof(SECONDARY_FILENAME));

  if (ret < 0)
    return -1;

  return ret;
}

int initial_policy_request_cb(struct response response)
{
  // check if req was succesfull
  int ret = 0;
  service_message resp = {0};
  service_message req = {0};

  if (response.ret != MGMT_OK)
    goto error_occured;
  if (response.buffer != NULL)
    goto error_occured;
  LOG_INFO("Received %d bytes from mgmt server: ", response.bytes_received);

  if (response.meta.policy_req.destination_path == NULL)
    goto error_occured;
  ret = write_file(response.meta.policy_req.destination_path, response.buffer_frag_start, response.bytes_received);
  if (ret < 0)
  {
    LOG_ERROR("can't write response into buffer");
  }

  req.msg_type = HTTP_SERVICE;
  req.payload.event = MGMT_EV_MGM_RESP;

  ret = send_management_message(svc.management_socket[0], &req);
  if (ret < 0)
  {
    LOG_ERROR("cant send mgmt message");
    goto error_occured;
  }
  ret = read_management_message(svc.management_socket[0], &resp);
  if (ret < 0)
  {
    LOG_ERROR("receive mgmt_message");
    goto error_occured;
  }
  if ((resp.msg_type == RESPONSE) && (resp.payload.return_code == 0))
  {
    LOG_ERROR("Resposne was succefull ");
  }

  if (response.buffer != NULL)
    free(response.buffer);
  return ret;
error_occured:

  if (response.buffer != NULL)
    free(response.buffer);
  return ret;
}