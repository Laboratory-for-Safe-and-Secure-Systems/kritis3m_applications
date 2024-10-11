

#include "kritis3m_scale_service.h"
#include "kritis3m_application_manager.h"
#include "logging.h"
LOG_MODULE_CREATE(kritis3m_service);
#include "cJSON.h"
#include "http_client.h"
#include "sys/timerfd.h"
#include "crypto_parser.h"
#include "networking.h"
#include "utils.h"
#include <errno.h>
#include <pthread.h>
#define SIMULTANIOUS_REQs 5
// returned by http request
struct response
{
  enum used_service service_used;
  ManagementReturncode ret;
  uint8_t *buffer;
  uint32_t bytes_received;
};
struct ThreadPool
{
  pthread_t threads[SIMULTANIOUS_REQs];
  pthread_attr_t thread_attr;
  int available[SIMULTANIOUS_REQs]; // 1 = available, 0 = in use
  pthread_mutex_t lock;
  pthread_cond_t cond;
};
typedef int (*t_http_get_cb)(struct response response);
// thread object for http get requests
struct http_get_request
{
  char *const request_url;
  struct sockaddr_in server_addr;
  uint8_t *response_buffer;
  int response_buffer_size;
  enum used_service used_service;
  asl_endpoint *ep; // used for tls
  t_http_get_cb cb; // callback function to signal the mainthread the result
  int thread_id;
  struct ThreadPool *pool; // used to tell the process when thread is finished
};
// management interface
typedef struct service_message
{
  enum service_message_type msg_type;
  union kritis3m_service_payload
  {
    struct response response;
    ManagementReturncode ret;
  } payload;
} service_message;
// main service object
struct kritis3m_service
{
  bool initialized;
  Kritis3mNodeConfiguration node_configuration;
  ConfigurationManager configuration_manager;
  int management_socket[2];
  struct ThreadPool threadpool;
  pthread_attr_t thread_attr;
  TimerPipe *hardbeat_timer;
  poll_set pollfd[10];
  asl_endpoint_configuration management_endpoint_config;
  asl_endpoint *client_endpoint;
};

// forward declarations
void *start_kristis3m_service(void *arg);
int send_management_message(int socket, service_message *msg);
int read_management_message(int socket, service_message *msg);
int setup_socketpair(int management_socket[2], bool blocking);
void *http_get_request(void *http_get_data);
static void http_get_cb(struct http_response *rsp,
                        enum http_final_call final_data,
                        void *user_data);

// callbacks used from the http threads
int request_cb(struct response response);
// http functions:
int do_policy_request(Kritis3mManagemntConfiguration *management_configuration, uint8_t *response_buffer, uint32_t buffer_size, asl_endpoint *ep, struct ThreadPool *pool);
int do_enroll_request(crypto_identity *crypto_id, uint8_t *response_buffer, uint32_t buffer_size);
int do_reenroll_request(crypto_identity *crypto_id, uint8_t *response_buffer, uint32_t buffer_size);
int do_heartbeat_request(Kritis3mManagemntConfiguration *management_configuration, uint8_t *response_buffer, uint32_t buffer_size);
int do_policy_confirm_request(Kritis3mManagemntConfiguration *management_configuration, uint8_t *response_buffer, uint32_t buffer_size);

int get_free_thread_id(struct ThreadPool *threadpool);
void signal_thread_finished(struct ThreadPool *pool, int thread_id);

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
  svc->management_socket[0] = -1;
  svc->management_socket[1] = -1;
  pthread_attr_init(&svc->thread_attr);
  init_posix_timer(svc->hardbeat_timer);
  poll_set_init(svc->pollfd);
  setup_socketpair(svc->management_socket, true);
  return;
}

int request_cb(struct response http_get_response)
{
  int ret = 0;
  struct service_message request = {0};
  struct service_message response = {0};
  struct response http_response = {0};
  if ((!svc.initialized) ||
      (svc.management_socket[0] < 0) ||
      (svc.management_socket[1] < 0))
    goto error_occured;

  request.msg_type = HTTP_GET_REQUEST_RESPONSE;
  request.payload.response = http_get_response;

  ret = send_management_message(svc.management_socket[0], &request);
  if (ret < 0)
  {
    LOG_ERROR("couldnt send http get request response to kritis3m_service main thread");
    goto error_occured;
  }
  ret = read_management_message(svc.management_socket[0], &response);
  if (ret < 0)
  {
    LOG_ERROR("couldnt receive http get request response from kritis3m_service main thread");
    goto error_occured;
  }
  if (response.msg_type == HTTP_RESPONSE)
  {
    ManagementReturncode returncode = response.payload.ret;
    if (returncode == MSG_OK)
      LOG_INFO("http request was sucefully");
  }
  return ret;
error_occured:
  if (ret > -1)
    ret = -1;
  return ret;
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
  initialize_crypto(&svc); // enroll would be called
  // now, the certificates for further communication with the management server should be available
  // The PKI-Client is not implemented yet, but will be in the future
  // The Certificates are now obtained from the file system and parsed into the asl_endpoint_configuration object
  certificates_to_endpoint(svc.node_configuration.pki_cert_path,
                           svc.node_configuration.pki_cert_path_size,
                           &svc.node_configuration.management_identity.identity,
                           &svc.management_endpoint_config);

  // call pki if certificates are outdated
  // parse configuration to startup the system
  // check if dependencies of configurations are complete

  // check if dependencies of cfg are available
  //  get dependencies
  // check if machine config has valid certificates
  // generate private key
  //  call pki and get signed cert by csr
  return 0;
error_occured:
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
  uint8_t policy_buffer[4000];
  memset(policy_buffer, 0, 4000);

  uint8_t pki_buffer[4000];
  memset(pki_buffer, 0, 4000);

  uint8_t pki1_buffer[4000];
  memset(pki1_buffer, 0, 4000);

  uint8_t pki2_buffer[4000];
  memset(pki2_buffer, 0, 4000);

  uint8_t heartbeat_buffer[500];
  memset(heartbeat_buffer, 0, 500);

  struct poll_set *pollfd = NULL;
  TimerPipe *mpipe = NULL;
  int hb_interval_sec = 2;
  SystemConfiguration *selected_sys_cfg = NULL;
  int ret = 0;
  ManagementReturncode retval = MGMT_OK;
  asl_endpoint_configuration *ep_cfg = NULL;
  struct kritis3m_service *svc = (struct kritis3m_service *)arg;
  
  if (svc == NULL)
    goto terminate;

  // holds both, primary and secondary configuration.
  // either primary or secondary configuration is used by the application manager. The free configuration is used for the update process
  Kritis3mNodeConfiguration node_configuration = svc->node_configuration;
  ConfigurationManager application_configuration_manager = svc->configuration_manager;

  retval = get_Systemconfig(&application_configuration_manager, &node_configuration);

  if ((retval == MGMT_EMPTY_OBJECT_ERROR) ||
      (retval == MGMT_PARSE_ERROR) ||
      (retval == MGMT_ERROR))
  {

  }
  SelectedConfiguration selected_config = application_configuration_manager.active_configuration;


  else if (retval < MGMT_OK) goto terminate;

  ret = poll_set_add_fd(pollfd, get_clock_signal_fd(mpipe), POLLIN | POLLERR);
  if (ret < 0)
  {
    LOG_ERROR("cant add fd to to pollset, shutting down management service");
    goto terminate;
  }

  ret = timer_start(mpipe, hb_interval_sec);
  while (1)
  {

    // services to embedd:
    //  timer
    //  application manger
    //  starting http request responses
  }

terminate:
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

int send_management_message(int socket, service_message *msg)
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

int read_management_message(int socket, service_message *msg)
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

/********   FORWARD DECLARATION ***************/

static void http_get_cb(struct http_response *rsp,
                        enum http_final_call final_data,
                        void *user_data)
{
  struct response *http_request_status = (struct response *)user_data;
  if (http_request_status == NULL)
    return;
  if (final_data == HTTP_DATA_MORE)
  {
    LOG_INFO("Partial data received (%zd bytes)", rsp->data_len);
  }
  else if (final_data == HTTP_DATA_FINAL)
  {
    switch (rsp->http_status_code)
    {
    case HTTP_OK:
      LOG_INFO("SUCCESFULL REQUEST");
      http_request_status->bytes_received = rsp->body_frag_len;
      http_request_status->buffer = rsp->body_frag_start;
      http_request_status->ret = MGMT_OK;
      break;
    case HTTP_BAD_REQUEST:
      LOG_ERROR("bad request");
      http_request_status->ret = MGMT_BAD_PARAMS;
      goto error_occured;
      break;
    case HTTP_SERVICE_UNAVAILABLE:
      LOG_INFO("Hardbeat service is not supported from the server");
      http_request_status->ret = MGMT_BAD_REQUEST;
      goto error_occured;
      break;
    case HTTP_TOO_MANY_REQUESTS:
      LOG_INFO("Retry later");
      http_request_status->ret = MGMT_BUSY;
      goto error_occured;
      break;
    default:
      LOG_ERROR("responded http code is not handled, http response code: %d", rsp->http_status_code);
      break;
    }
  }
  return;
error_occured:
  http_request_status->bytes_received = 0;
  http_request_status->buffer = NULL;
  return;
}

void *http_get_request(void *http_get_data)
{
  struct http_get_request *http_req_data = (struct http_get_request *)http_get_data;
  if (http_get_data == NULL)
    return NULL;
  struct response request_response = {0};
  request_response.service_used = http_req_data->used_service;
  asl_endpoint *client_ep = http_req_data->ep;
  struct sockaddr_in server_addr = http_req_data->server_addr;
  char *const request_url = http_req_data->request_url;
  uint8_t *response_buffer = http_req_data->response_buffer;
  int response_buffer_size = http_req_data->response_buffer_size;
  t_http_get_cb client_callback = http_req_data->cb;

  struct http_request req = {0};
  asl_session *policy_rq_session = NULL;
  int req_fd = -1;
  int ret = 0;

  if ((request_url == NULL) ||
      (response_buffer == NULL) ||
      (client_ep == NULL) ||
      (client_callback == NULL))
  {
    goto shutdown;
  }

  req_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (req_fd < 0)
  {
    LOG_ERROR("error obtaining fd, errno: ", errno);
    goto shutdown;
  }
  /********** TCP CONNECTION ************/
  ret = connect(req_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in));
  if (ret < 0)
  {
    LOG_ERROR("cant connect to client: errno %d", errno);
    goto shutdown;
  }
  policy_rq_session = asl_create_session(client_ep, req_fd);
  if (policy_rq_session == NULL)
  {
    ret = MGMT_ERROR;
    goto shutdown;
  }

  req.method = HTTP_GET;
  req.url = request_url; // @todo see if url must be seperated from host since the url is now in the format https://ip.ip.ip.ip:<port>/url
  // req.host = server_ip; //@todo see if this is required
  req.protocol = "HTTP/1.1";
  /**
   * @todo evaluate if response handling in callback or
   * response handling after request is superior
   */
  req.response = http_get_cb;
  req.recv_buf = response_buffer;
  req.recv_buf_len = response_buffer_size;

  int32_t timeout = 3 * MSEC_PER_SEC;
  ret = https_client_req(req_fd, policy_rq_session, &req, timeout, &request_response);
  if (ret < 0)
  {
    LOG_ERROR("error on client req. need to implment error handler");
    goto shutdown;
  }

  client_callback(request_response);
  asl_close_session(policy_rq_session);
  asl_free_session(policy_rq_session);
  signal_thread_finished(http_req_data->pool, http_req_data->thread_id);
  if (req_fd > 0)
    close(req_fd);
  pthread_exit(NULL);
shutdown:
  client_callback(request_response);
  signal_thread_finished(http_req_data->pool, http_req_data->thread_id);
  // its ok to call these functions withh nullptr. no checks required
  asl_close_session(policy_rq_session);
  asl_free_session(policy_rq_session);
  if (req_fd > 0)
    close(req_fd);
  pthread_exit(NULL);
}

// @todo include serial number into do_policy_request
int do_policy_request(Kritis3mManagemntConfiguration *management_configuration,
                      uint8_t* serial_number, int serial_number_size,
                      uint8_t *response_buffer,
                      uint32_t buffer_size,
                      asl_endpoint *ep,
                      struct ThreadPool *pool)
{
  int ret = 0;
  struct http_get_request req = {0};
  struct sockaddr_in server_addr = {0};
  if ((management_configuration == NULL) ||
      (response_buffer = NULL))
    goto error_occured;
  // will be handed to the get request thread
  req.used_service = MGMT_POLICY_REQ;
  req.response_buffer = response_buffer;
  req.response_buffer_size = buffer_size;

  ret = extrack_addr_from_url(management_configuration->management_server_url, &server_addr);
  if (ret < 0)
  {
    LOG_ERROR("can't obtain socket address from url");
    goto error_occured;
  }
  req.cb = request_cb;
  req.ep = ep;
  /* Create the new thread */
  req.thread_id = get_free_thread_id(pool);
  req.pool = pool;
  if (req.thread_id < 0)
    goto error_occured;
  ret = pthread_create(&pool->threads[req.thread_id], &pool->thread_attr, http_get_request, &req);

error_occured:
  if (ret > -1)
    ret = -1;
  return ret;
}
int do_reenroll_request(crypto_identity *crypto_id, uint8_t *response_buffer, uint32_t buffer_size)
{
  int ret = 0;
}
int do_enroll_request(crypto_identity *crypto_id, uint8_t *response_buffer, uint32_t buffer_size)
{
  int ret = 0;
}
int do_heartbeat_request(Kritis3mManagemntConfiguration *management_configuration, uint8_t *response_buffer, uint32_t buffer_size)
{
  int ret = 0;
}
int do_policy_confirm_request(Kritis3mManagemntConfiguration *management_configuration, uint8_t *response_buffer, uint32_t buffer_size)
{
  int ret = 0;
}

int get_free_thread_id(struct ThreadPool *pool)
{

  int thread_id = -1;

  pthread_mutex_lock(&pool->lock);

  // Wait until a thread becomes available
  while (thread_id == -1)
  {
    for (int i = 0; i < SIMULTANIOUS_REQs; i++)
    {
      if (pool->available[i] == 1)
      {
        thread_id = i;
        pool->available[i] = 0; // Mark the thread as in use
        break;
      }
    }
    if (thread_id == -1)
    {
      // No threads are available, wait for one to finish
      pthread_cond_wait(&pool->cond, &pool->lock);
    }
  }
  return thread_id;
}

void signal_thread_finished(struct ThreadPool *pool, int thread_id)
{
  pthread_mutex_lock(&pool->lock);
  pool->available[thread_id] = 1;   // Mark the thread as available
  pthread_cond_signal(&pool->cond); // Signal the condition variable
  pthread_mutex_unlock(&pool->lock);
}