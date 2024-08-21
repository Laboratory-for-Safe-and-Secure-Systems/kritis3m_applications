

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
#include <stdarg.h>

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
int handle_hb_instruction(mgmt_container *l_mgmt, HardbeatInstructions instruction, int hb_iv, int log_level);
static void hb_timer_event_handler(struct k_timer *timer);
int init_hardbeat_service(mgmt_container *mgmt_container, uint32_t hb_iv_seconds);
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

int handle_hb_instruction(mgmt_container *l_mgmt, HardbeatInstructions instruction, int hb_iv, int log_level)
{
  int ret = -1;
  switch (instruction)
  {
  case HB_CHANGE_HB_INTEVAL:
    ret = set_hardbeat_interval(l_mgmt, hb_iv);
    break;
  case HB_NOTHING:
    ret = 0;
    break;
  case HB_REQUEST_POLICIES:
    PolicyResponse rsp;
    ret = call_policy_distribution_server(l_mgmt->endpoint, &rsp);
    if (ret < 0)
    {
      break;
    }
    /*
     *@todo Implement Configuration Service
     * In the future, the configuration should be stored on the flash
     */
    memcpy(&system_configuration, &rsp.system_configuration, sizeof(SystemConfiguration));
    break;
  case HB_POST_SYSTEM_STATUS:
    LOG_INFO("no logging implemented");
    ret = 0;
    break;
  case HB_SET_DEBUG_LEVEL:
    LOG_INFO("change debug log level not implemented yet");
    ret = 0;
    break;
  case HB_ERROR:
    LOG_INFO("error not handled");
    ret = -1;
    break;
  }
  return ret;
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
        if (ret < 0)
        {
          LOG_ERROR("todo implement error");
        }
        else
        {
          for (int i = 0; i < rsp.hb_instructions_count; i++)
          {
            ret = handle_hb_instruction(l_mgmt, rsp.HardbeatInstruction[i], rsp.HardbeatInterval_s, 0);

            if (ret < 0)
            {
              LOG_ERROR("couldn't set timer interval");
              goto shutdown;
            }
          }
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
