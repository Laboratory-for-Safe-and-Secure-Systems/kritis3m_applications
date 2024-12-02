#ifndef KRITIS3M_CONFIGURATION_H
#define KRITIS3M_CONFIGURATION_H

#include <stdint.h>
#include "asl.h"
#include <stdbool.h>
#include <net/if.h>
#include <sys/socket.h>
#include <time.h>
#include <pthread.h>
// #include "kritis3m_pki_client.h"
#include <netinet/in.h>

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

typedef enum SelectedConfiguration
{
    CFG_NONE = 0,
    CFG_PRIMARY = 1,
    CFG_SECONDARY = 2,
} SelectedConfiguration;

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

typedef struct SystemConfiguration SystemConfiguration;
struct SystemConfiguration;

typedef struct CryptoProfile CryptoProfile;
struct CryptoProfile;

typedef struct ConnectionWhitelist ConnectionWhitelist;
struct ConnectionWhitelist;

typedef struct ApplicationConfiguration ApplicationConfiguration;
struct ApplicationConfiguration;

typedef struct certificates
{
    uint8_t *chain_buffer; /* Entity and intermediate certificates */
    size_t chain_buffer_size;

    uint8_t *key_buffer;
    size_t key_buffer_size;

    uint8_t *additional_key_buffer;
    size_t additional_key_buffer_size;

    uint8_t *root_buffer;
    size_t root_buffer_size;
} certificates;

enum ApplicationStatus
{
    APK_ERR = -1,
    APK_OK = 0,
};

typedef struct
{
    enum ApplicationStatus Status;
    int running_applications;
} ApplicationManagerStatus;

typedef enum
{
    MANAGEMENT_SERVICE,
    MANAGEMENT,
    REMOTE,
    PRODUCTION,
    max_identities
} network_identity;


typedef struct
{
    char address[ENDPOINT_LEN]; // Stores IP or IPv4/URL
    uint16_t port;              // Stores parsed port
} EndpointAddr;

typedef struct
{
    int32_t id;
    network_identity identity;

    char *revocation_list_url;
    int revocation_list_url_size;

    char *secure_middleware_path;
    int secure_middleware_path_int;

    EndpointAddr server_endpoint_addr;

    char *server_url;
    int server_url_size;

    char *filepath;
    int32_t filepath_size;

    bool certificates_available;
    certificates certificates;
} crypto_identity;

struct CryptoProfile
{
    int32_t id;
    char Name[MAX_NAME_SIZE];
    bool MutualAuthentication;
    bool NoEncryption;
    enum asl_key_exchange_method ASLKeyExchangeMethod;
    bool UseSecureElement;
    enum asl_hybrid_signature_mode HybridSignatureMode;
    bool Keylog;
    int32_t crypto_identity_id;
    char *secure_middleware_path;
    char *pin;
};

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

    int number_crypto_profiles;
    CryptoProfile crypto_profile[MAX_NUMBER_CRYPTOPROFILE];

    int number_hw_config;
    HardwareConfiguration hw_config[MAX_NUMBER_HW_CONFIG];

    crypto_identity crypto_identity[MAX_NUMBER_CRYPTOPROFILE];
    int number_crypto_identity;

    int number_applications;
    Kritis3mApplications applications[MAX_NUMBER_APPLICATIONS];
};

struct SystemConfiguration
{
    uint32_t cfg_id;
    uint32_t node_id;
    char locality[NAME_LEN];
    char serial_number[NAME_LEN];
    uint32_t node_network_index;

    uint64_t heartbeat_interval;

    uint32_t version;
    ApplicationConfiguration application_config;
};

typedef struct
{

    char primary_file_path[MAX_FILEPATH_SIZE];
    char secondary_file_path[MAX_FILEPATH_SIZE];

    SelectedConfiguration active_configuration;
    SystemConfiguration primary;
    SystemConfiguration secondary;

} ConfigurationManager;

typedef struct { char serial_number[SERIAL_NUMBER_SIZE];
    EndpointAddr server_endpoint_addr;

    char *secure_middleware_path;
    int secure_middleware_path_size;

    char *pin;
    int pin_size;

    crypto_identity identity;
} Kritis3mManagemntConfiguration;

typedef struct
{
    Kritis3mManagemntConfiguration management_identity;

    char *primary_path;
    int primary_path_size;

    char *secondary_path;
    int secondary_path_size;

    char *machine_crypto_path;
    int machine_crypto_path_size;

    char *pki_cert_path;
    int pki_cert_path_size;

    char *management_service_path;
    int management_service_path_size;

    char *management_path;
    int management_path_size;

    char *production_path;
    int production_path_size;

    char *remote_path;
    int remote_path_size;

    char *crypto_path;
    int crypto_path_size;

    char *config_path;
    int config_path_size;

    SelectedConfiguration selected_configuration;
} Kritis3mNodeConfiguration;

enum MSG_RESPONSE_CODE
{
    MSG_ERROR = -1,
    MSG_OK = 0,
    MSG_FORBIDDEN = 1,
    MSG_BUSY = 2,
};

enum used_service
{
    EST_ENROLL = 0,
    EST_REENROLL,
    MGMT_POLICY_REQ,
    MGMT_SEND_STATUS_REQ,
    MGMT_HEARTBEAT_REQ,
    MGMT_POLICY_CONFIRM,
};

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

int get_Kritis3mNodeConfiguration(char *filename, Kritis3mNodeConfiguration *config);
int get_Systemconfig(ConfigurationManager *applconfig, Kritis3mNodeConfiguration *node_config);
SystemConfiguration *get_active_config(ConfigurationManager *manager);
SystemConfiguration *get_inactive_config(ConfigurationManager *manager);
Kritis3mApplications *find_application_by_application_id(Kritis3mApplications *appls, int number_appls, int appl_id);
int get_identity_folder_path(char *out_path, size_t size, const char *base_path, network_identity identity);
//used to send ApplicationStatus to Controller
char* applicationManagerStatusToJson(
    const ApplicationManagerStatus* status, 
    char* json_buffer, 
    size_t buffer_length
);

/*Cleanup Functions */

void cleanup_configuration_manager(ConfigurationManager *configuation_manager);
void cleanup_Systemconfiguration(SystemConfiguration *systemconfiguration);

void free_ManagementConfiguration(Kritis3mManagemntConfiguration *config);
void free_CryptoIdentity(crypto_identity *identity);
void free_NodeConfig(Kritis3mNodeConfiguration *config);

#endif // KRITIS3M_CONFIGURATION_H