#ifndef HB_SERVICE_H
#define HB_SERVICE_H

#include "asl.h"
#include "poll.h"
#include "poll_set.h"
#include "http_client.h"
#include "kritis3m_scale_service.h"



int handle_hb_event(struct pollfd *pfd, asl_endpoint* ep, HardbeatResponse*rsp);


void handle_hb_server_response_cb(struct http_response *rsp,
                                  enum http_final_call final_data,
                                  void *user_data);

#endif // HB_SERVICE_H