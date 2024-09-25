

#include "kritis3m_scale_service.h"
#include "kritis3m_application_manager.h"
#include "logging.h"
LOG_MODULE_CREATE(kritis3m_service);
#include "cJSON.h"
#include "sys/timerfd.h"
#include "networking.h"
#include <errno.h>

void *start_kristis3m_service(void *arg);

struct kritis3m_service
{
  struct kritis3m_service_configuration *service_config;
  ConfigurationManager *configuration_manager;

  int application_socket_fd;

  pthread_t thread;
  pthread_attr_t thread_attr;

  TimerPipe *hardbeat_timer;

  poll_set pollfd[10];
};

static struct kritis3m_service svc = {0};

int setup_socketpair(int management_socket[2], bool blocking);

int init_kristis3m_service(struct kritis3m_service_configuration *config)
{
  int ret = 0;

  svc.configuration_manager = parse_configuration(config->configuration_path);
  if (&svc.configuration_manager == NULL)
  {
    LOG_ERROR("couldnt load configuration. Abort");
    return -1;
  }
  SystemConfiguration *active_config = get_active_configuration(svc.configuration_manager);
  int application_socketpair[2];
  ret = setup_socketpair(application_socketpair, true);
  if (ret < 0)
  {
    return -1;
  }
  svc.application_socket_fd = application_socketpair[0];
  poll_set_init(svc.pollfd);
  application_manager_config application_config;
  application_config.log_level = LOG_LVL_DEBUG;
  init_application_manager(&application_config);

  ret = init_posix_timer(svc.hardbeat_timer);
  if (ret < 0)
  {
    LOG_ERROR("hardbeat_timer couldnt be initialized");
    return ret;
  }

  pthread_attr_init(&svc.thread_attr);
  pthread_create(&svc.thread, &svc.thread_attr, start_kristis3m_service, &svc);
  return 0;
}

void *start_kristis3m_service(void *arg)
{
  struct kritis3m_service *svc = (struct kritis3m_service *)arg;
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
  return ret;
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