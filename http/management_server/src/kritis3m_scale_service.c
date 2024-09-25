

#include "kritis3m_scale_service.h"
#include "kritis3m_application_manager.h"
#include "logging.h"
LOG_MODULE_CREATE(kritis3m_service);
#include "cJSON.h"
#include "sys/timerfd.h"
#include "networking.h"
#include <errno.h>

struct kritis3m_service
{
  struct kritis3m_service_configuration *service_config;
  ConfigurationManager configuration_manager;

  int application_socket_fd;

  pthread_t thread;
  pthread_attr_t thread_attr;

  TimerPipe *hardbeat_timer;
};

static struct kritis3m_service svc = {0};

int setup_socketpair(int management_socket[2], bool blocking);

int init_kristis3m_service(struct kritis3m_service_configuration *config)
{
  int ret = 0;
  ret = load_configuration(config->configuration_path, &svc.configuration_manager);
  if (ret < 0)
  {
    LOG_ERROR("couldnt load configuration. Abort");
    return -1;
  }
  SystemConfiguration *active_config = get_active_configuration(&svc.configuration_manager);
  int application_socketpair[2];
  ret = setup_socketpair(application_socketpair, true);
  if (ret < 0)
  {
    return -1;
  }
  svc.application_socket_fd = application_socketpair[0];
  start_applications(active_config, application_socketpair[1]);

  ret = init_posix_timer(&svc.hardbeat_timer);
  if (ret < 0)
  {
    LOG_ERROR("hardbeat_timer couldnt be initialized");
    return ret;
  }

  while (1)
  {
  }
}

int start_kristis3m_service(struct kritis3m_service_configuration *config)
{
  // 1. call hardbeat service for updates
  // 2. wait for response
  // 3. ask configuration service if changed
  // 4. Attach workers
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