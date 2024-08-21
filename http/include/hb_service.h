#ifndef HB_SERVICE_H
#define HB_SERVICE_H

#include "asl.h"
#include "poll.h"
#include "poll_set.h"
#include "http_client.h"
#include "kritis3m_scale_service.h"


#define HB_SERVERADDR "192.168.3.3"
#define HB_SERVERPORT "1231"
#define HB_RESPONSE_SIZE 400
#define HB_URL (HB_SERVERADDR ":" HB_SERVERPORT "/hb_service/moin/")

typedef struct HardbeatResponse HardbeatResponse;
struct HardbeatResponse;

typedef enum HardbeatInstructions HardbeatInstructions;
enum HardbeatInstructions;

enum HardbeatInstructions
{
    HB_ERROR = -1,
    HB_NOTHING = 0,            // keep current configuration
    HB_CHANGE_HB_INTEVAL = 1,  // change the hardbeat interval
    HB_REQUEST_POLICIES = 2,   // request new configuration policies/config from the distribution server
    HB_POST_SYSTEM_STATUS = 3, // post system status to the distribution server
    HB_SET_DEBUG_LEVEL = 4,    // set the debug level to either DEBUG,INFO, WARN, ERROR
};

struct HardbeatResponse{
    HardbeatInstructions HardbeatInstruction;
    uint64_t HardbeatInterval_s;
};


int handle_hb_event(struct pollfd *pfd, asl_endpoint* ep, HardbeatResponse*rsp);


void handle_hb_server_response_cb(struct http_response *rsp,
                                  enum http_final_call final_data,
                                  void *user_data);

#endif // HB_SERVICE_H