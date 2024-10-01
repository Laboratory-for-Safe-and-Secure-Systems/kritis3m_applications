

#include "kritis3m_scale_service.h"
#include "kritis3m_application_manager.h"
#include "logging.h"
LOG_MODULE_CREATE(kritis3m_service);
#include "cJSON.h"
#include "sys/timerfd.h"
#include "crypto_parser.h"
#include "networking.h"
#include <errno.h>

void *start_kristis3m_service(void *arg);

struct kritis3m_service
{
  Kritis3mNodeConfiguration *node_configuration;
  ConfigurationManager *configuration_manager;

  pthread_t thread;
  pthread_attr_t thread_attr;

  TimerPipe *hardbeat_timer;

  poll_set pollfd[10];
  asl_endpoint_configuration management_endpoint_config;
};

static struct kritis3m_service svc = {0};

int setup_socketpair(int management_socket[2], bool blocking);

void set_kritis3m_serivce_defaults(struct kritis3m_service *svc)
{
  svc->configuration_manager = NULL;
  memset(&svc->management_endpoint_config, 0, sizeof(asl_endpoint_configuration));
  pthread_attr_init(&svc->thread_attr);
  svc->service_config = NULL;
  init_posix_timer(svc->hardbeat_timer);
  poll_set_init(svc->pollfd);
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
                         svc->node_configuration->pki_cert_path, svc->node_configuration->pki_cert_path_size,
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
  Kritis3mNodeConfiguration config;
  // get global node config
  ret = get_Kritis3mNodeConfiguration(config_file, &config);
  if (ret < 0)
  {
    LOG_ERROR("can't parse Config, error occured: %d ", errno);
    return ret;
  }
  set_kritis3m_serivce_defaults(&svc);
  svc.node_configuration = &config;
  initialize_crypto(&svc); // enroll would be called
  // now, the certificates for further communication with the management server should be available
  // The PKI-Client is not implemented yet, but will be in the future
  // The Certificates are now obtained from the file system and parsed into the asl_endpoint_configuration object
  certificates_to_endpoint(config.pki_cert_path, config.pki_cert_path_size, &config.management_identity.identity, &svc.management_endpoint_config);

  int get_Application_config(svc.configuration_manager, svc.node_configuration);

  // call pki if certificates are outdated
  // parse configuration to startup the system
  svc.configuration_manager = parse_configuration(config->configuration_path);
  if (&svc.configuration_manager == NULL)
  {
    LOG_ERROR("couldnt load configuration. Abort");
    return -1;
  }
  // check if dependencies of configurations are complete

  // check if dependencies of cfg are available
  //  get dependencies
  // check if machine config has valid certificates
  // generate private key
  //  call pki and get signed cert by csr
  pthread_create(&svc.thread, &svc.thread_attr, start_kristis3m_service, &svc);
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
  struct kritis3m_service *svc = (struct kritis3m_service *)arg;
  SystemConfiguration *active_config = get_active_configuration(svc->configuration_manager);
  if (active_config == NULL)
  {
    LOG_ERROR("shutdown kritis3m_service, no active config availalble");
    goto terminate;
  }
  complete_crypto_dependencies();

  application_manager_config application_config;
  application_config.log_level = LOG_LVL_DEBUG;
  init_application_manager(&application_config);

  // 1. call hardbeat service for updates
  // 2. wait for response
  // 3. ask configuration service if changed
  // 4. Attach workers
  int ret = 0;

  struct poll_set *pollfd;
  TimerPipe *mpipe;
  int hb_interval_sec = 2;

  if (ret < 0)
  {
    ret = -1;
    LOG_ERROR("cant start hardbeat service due to timer error: %d, shutting down management service");
    goto terminate;
  }

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