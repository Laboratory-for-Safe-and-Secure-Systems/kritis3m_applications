

#include "kritis3m_scale_service.h"
#include "kritis3m_application_manager.h"
#include "logging.h"
LOG_MODULE_CREATE(kritis3m_service);
#include "cJSON.h"

struct kritis3m_service
{
  struct kritis3m_service_configuration *service_config;
  ConfigurationManager configuration_manager;
};

static struct kritis3m_service kritis3m_service = {0};

int init_kristis3m_service(struct kritis3m_service_configuration *config)
{
  int ret = 0;
  ret = load_configuration(config->configuration_path, &kritis3m_service);
  if (ret < 0)
  {
    LOG_ERROR("couldnt load configuration. Abort");
    return -1;
  }
  SystemConfiguration *active_config = get_active_configuration(&kritis3m_service);
  start_applications(active_config);

  while(1){
    
  }

}



int start_kristis3m_service(struct kritis3m_service_configuration *config)
{
  //1. call hardbeat service for updates
  //2. wait for response
  //3. ask configuration service if changed
  //4. Attach workers
}


