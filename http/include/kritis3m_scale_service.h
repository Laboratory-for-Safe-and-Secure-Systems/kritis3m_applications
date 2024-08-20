#ifndef KRITIS3M_SCALE_SERVICE_H
#define KRITIS3M_SCALE_SERVICE_H

#define JSMN_PARENT_LINKS

#include <netinet/in.h>
#include "kritis3m_configuration.h"

typedef enum HardbeatInstructions HardbeatInstructions;
enum HardbeatInstructions;

static SystemConfiguration system_configuration = {0};

/*********************************************************
 *              MANAGEMENT SERVICE STARTUP
 */

int start_management_service(struct sockaddr_in);

/*********************************************************
 *              CONFIGURATION DISTRIBUTION
 */

int do_policy_request(struct sockaddr_in *server_addr, int server_addr_len, int server_port);
int handle_policy_rq_response(char *response, int response_len, SystemConfiguration *configuration);

int parse_configuration(char *response, int response_len);

/**********************************************************
 *                      Hardbeat Service
 */

// INSTRUCTIONS
int do_hardbeat_request(struct sockaddr_in *server_addr, int server_addr_len, int server_port);
int handle_hardbeat_rq_response(char *response, int response_len, HardbeatInstructions *instruction);

enum HardbeatInstructions
{
    HB_ERROR = -1,
    HB_NOTHING = 0,            // keep current configuration
    HB_CHANGE_HB_INTEVAL = 1,  // change the hardbeat interval
    HB_REQUEST_POLICIES = 2,   // request new configuration policies/config from the distribution server
    HB_POST_SYSTEM_STATUS = 3, // post system status to the distribution server
    HB_SET_DEBUG_LEVEL = 4,    // set the debug level to either DEBUG,INFO, WARN, ERROR
};

#endif // KRITIS3M_SCALE_SERVICE_H
