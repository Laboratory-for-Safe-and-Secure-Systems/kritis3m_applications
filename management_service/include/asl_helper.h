#ifndef ASL_HELPER_H
#define ASL_HELPER_H

#include "asl.h"

// 0 on success, -1 on failure
int establish_connection(char const* host,
                         uint16_t port,
                         asl_endpoint_configuration const* endpoint_config,
                         asl_endpoint** endpoint,
                         asl_session** session,
                         int* sock_fd);

int test_endpoint(char const* host, uint16_t port, asl_endpoint_configuration const* endpoint_config);

void asl_helper_log_level_set(int log_level);

#endif // ASL_HELPER_H
