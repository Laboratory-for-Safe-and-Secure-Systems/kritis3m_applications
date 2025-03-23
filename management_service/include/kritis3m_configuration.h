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

typedef enum
{

        UNDEFINED = -1,
        TLS_FORWARD_PROXY = 0,
        TLS_REVERSE_PROXY = 1,
        TLS_TLS_PROXY = 2,
        ECHO_SERVER = 3,
        TCP_CLIENT_STDIN_BRIDGE = 4,
        L2_BRIDGE = 5,
} Kritis3mApplicationtype;

enum ApplicationStatus
{
        APK_ERR = -1,
        APK_OK = 0,
};

typedef struct SystemConfiguration SystemConfiguration;
struct SystemConfiguration;

typedef struct CryptoProfile CryptoProfile;
struct CryptoProfile;

typedef struct ConnectionWhitelist ConnectionWhitelist;
struct ConnectionWhitelist;

typedef struct ApplicationConfiguration ApplicationConfiguration;
struct ApplicationConfiguration;

typedef struct
{
        enum ApplicationStatus Status;
        int running_applications;
} ApplicationManagerStatus;

typedef struct
{
        char* address; // Stores IP or IPv4/URL
        uint16_t port; // Stores parsed port
} EndpointAddr;

typedef struct
{
        uint32_t config_id;
        uint32_t id;
        Kritis3mApplicationtype type;

        EndpointAddr server_endpoint_addr;
        EndpointAddr client_endpoint_addr;

        bool state;
        int32_t ep1_id;
        int32_t ep2_id;
        int log_level;
} Kritis3mApplications;

typedef union
{
        struct sockaddr sockaddr;
        struct sockaddr_in sockaddr_in;
        struct sockaddr_in6 sockaddr_in6;
} Kritis3mSockaddr;

typedef struct
{
        int32_t id;
        Kritis3mSockaddr trusted_client;

        int number_trusted_applications;
        int trusted_applications_id[MAX_TRUSTED_APPLICATIONS];
} TrustedClients;

typedef struct
{
        int number_trusted_clients;
        TrustedClients TrustedClients[MAX_NUMBER_TRUSTED_CLIENTS];
} Whitelist;

typedef struct
{
        char device[IF_NAMESIZE];
        char ip_cidr[INET6_ADDRSTRLEN + 4];
} HardwareConfiguration;

struct ApplicationConfiguration
{
        int log_level;
        pthread_mutex_t lock;
        Whitelist whitelist;

        int number_hw_config;
        HardwareConfiguration hw_config[MAX_NUMBER_HW_CONFIG];

        int number_applications;
        Kritis3mApplications applications[MAX_NUMBER_APPLICATIONS];
};

#endif // KRITIS3M_CONFIGURATION_H
