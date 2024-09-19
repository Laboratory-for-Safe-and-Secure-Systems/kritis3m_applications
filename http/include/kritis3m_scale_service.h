#ifndef KRITIS3M_SCALE_SERVICE_H
#define KRITIS3M_SCALE_SERVICE_H

#define JSMN_PARENT_LINKS

#include <netinet/in.h>
#include "kritis3m_configuration.h"
#include "kritis3m_distribution_service.h"
#include "hb_service.h"

static SystemConfiguration system_configuration = {0};

/*********************************************************
 *              MANAGEMENT SERVICE STARTUP
 */


int management_service_run();

/*********************************************************
 *              CONFIGURATION DISTRIBUTION
 */


int handle_policy_rq_response(char *response, int response_len, SystemConfiguration *configuration);

int parse_configuration(char *response, int response_len);

/**********************************************************
 *                      Hardbeat Service
 */

#define HTTP_OK 200
#define HTTP_CREATED 201
#define HTTP_NO_CONTENT 204
#define HTTP_BAD_REQUEST 400
#define HTTP_UNAUTHORIZED 401
#define HTTP_FORBIDDEN 403
#define HTTP_NOT_FOUND 404
#define HTTP_METHOD_NOT_ALLOWED 405
#define HTTP_TOO_MANY_REQUESTS 429
#define HTTP_INTERNAL_SERVER_ERROR 500
#define HTTP_BAD_GATEWAY 502
#define HTTP_SERVICE_UNAVAILABLE 503
#define HTTP_GATEWAY_TIMEOUT 504

/**********ERROR MSGS **********/
#define HTTP_OK_MSG "OK"
#define HTTP_CREATED_MSG "Created"
#define HTTP_NO_CONTENT_MSG "No Content"
#define HTTP_BAD_REQUEST_MSG "Bad Request"
#define HTTP_UNAUTHORIZED_MSG "Unauthorized"
#define HTTP_FORBIDDEN_MSG "Forbidden"
#define HTTP_NOT_FOUND_MSG "Not Found"
#define HTTP_METHOD_NOT_ALLOWED_MSG "Method Not Allowed"
#define HTTP_TOO_MANY_REQUESTS_MSG "Too Many Requests"
#define HTTP_INTERNAL_SERVER_ERROR_MSG "Internal Server Error"
#define HTTP_BAD_GATEWAY_MSG "Bad Gateway"
#define HTTP_SERVICE_UNAVAILABLE_MSG "Service Unavailable"
#define HTTP_GATEWAY_TIMEOUT_MSG "Gateway Timeout"
#define HTTP_DEFAULT_MSG "HTTP error occured"

#endif // KRITIS3M_SCALE_SERVICE_H
