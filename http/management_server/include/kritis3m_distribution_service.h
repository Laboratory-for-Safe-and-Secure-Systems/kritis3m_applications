#ifndef KRITIS3M_DISTRIBUTION_SERVICE_H
#define  KRITIS3M_DISTRIBUTION_SERVICE_H


#include "asl.h"
#include "poll.h"
#include "poll_set.h"
#include "http_client.h"
#include "kritis3m_scale_service.h"
#include <stdlib.h>


typedef struct PolicyResponse PolicyResponse;
struct PolicyResponse;


struct PolicyResponse{
    SystemConfiguration system_configuration;
};

int call_policy_distribution_server(asl_endpoint* ep, PolicyResponse* rsp);




#endif //KRITIS3M_DISTRIBUTION_SERVICE_H
