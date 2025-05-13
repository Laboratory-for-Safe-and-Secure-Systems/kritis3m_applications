#ifndef KRITIS3M_CONFIGURATION_H
#define KRITIS3M_CONFIGURATION_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "asl.h"
#include "file_io.h"
#include "networking.h"

#define USE_MANAGEMENT

#define MAX_FILEPATH_SIZE 400
// lengths
#define ID_LEN 256
#define NAME_LEN 256
#define DESCRIPTION_LEN 256

#define MAX_TRUSTED_APPLICATIONS 10
#define MAX_NAME_SIZE 256
#define MAX_NUMBER_CRYPTOPROFILE 20
#define MAX_NUMBER_HW_CONFIG 15
#define MAX_NUMBER_APPLICATIONS 7
#define MAX_NUMBER_TRUSTED_CLIENTS 7

#define SERIAL_NUMBER_SIZE 254
#define ENDPOINT_LEN 254

#define THREAD_INT 0
#define THREAD_EXT 1

typedef enum ManagementReturncode
{
        MGMT_BAD_REQUEST = -6,
        MGMT_PARSE_ERROR = -5,
        MGMT_EMPTY_OBJECT_ERROR = -4,
        MGMT_BAD_PARAMS = -3,
        MGMT_CONNECT_ERROR = -2,
        MGMT_ERR = -1,
        MGMT_OK = 0,
        MGMT_FORBIDDEN = 1,
        MGMT_BUSY = 2,
        MGMT_THREAD_STOP = 3
} ManagementReturncode;

enum ApplicationStatus
{
        APK_ERR = -1,
        APK_OK = 0,
};


typedef struct
{
        char device[IF_NAMESIZE];
        char ip_cidr[INET6_ADDRSTRLEN + 4];
} HardwareConfiguration;

#endif // KRITIS3M_CONFIGURATION_H
