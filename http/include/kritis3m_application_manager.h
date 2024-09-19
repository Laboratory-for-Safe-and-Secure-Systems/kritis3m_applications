#ifndef KRITIS3M_APPLICATION_MANAGER_H
#define KRITIS3M_APPLICATION_MANAGER_H

#include <sys/socket.h>
#include <netinet/in.h>
#include "kritis3m_configuration.h"

#include "tls_proxy.h"
#include "tcp_echo_server.h"
// #include "tcp_client_stdin_bridge.h"
#include "poll_set.h"


typedef int (*unregister_fd_cb)(int);
typedef int (*register_fd_cb)(int);

/**
 * Application management commands
 * each application must handle these request and responses
 */
typedef enum ApplicationReqCommands ApplicationReqCommands;
enum ApplicationReqCommands{
    APK_ERR=-2,
    APK_REFUSE_CLIENT=-1,
    APK_OK=0,
};

typedef enum ApplicationCommandResp ApplicationCommandResp;
enum ApplicationCommandResp{
    APK_STOP=1,
    APK_SHUTDOWN=2,
    APK_RESTART=3,
};
struct application_identifier{
    int mgmt_fd;
    int application_id;
    int application_type;
};

struct application_manager
{
    int active_applications;
    unregister_fd_cb unreg_cb;
    register_fd_cb reg_cb;
    int applications_count;
    struct application_identifier applications[20];

};

ApplicationCommandResp is_client_trustworthy(char* ip_addr, int port);
void init_application_manager(struct SystemConfiguration* configuration);
void manage(SystemConfiguration* configuration);
#endif  //KRITIS3M_APPLICATION_MANAGER_H