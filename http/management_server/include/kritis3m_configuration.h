#ifndef KRITIS3M_CONFIGURATION_H
#define KRITIS3M_CONFIGURATION_H

#include <stdint.h>
#include "asl.h"
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
// #include "kritis3m_pki_client.h"
#include <netinet/in.h>

#define MAX_FILEPATH_SIZE 400
// lengths
#define IPv4_LEN 16
#define ID_LEN 256
#define NAME_LEN 256
#define DESCRIPTION_LEN 256
#define IPv4_PORT_LEN 40
#define MAX_TRUSTED_APPLICATIONS 10
#define MAX_NAME_SIZE 256
#define MAX_NUMBER_CRYPTOPROFILE 20
#define MAX_NUMBER_APPLICATIONS 7
#define MAX_NUMBER_TRUSTED_CLIENTS 7
#define HARDBEAT_DEFAULT_S 24 * 60 * 60
#define HARDBEAT_MIN_S 20
#define HARDBEAT_MAX_S 60 * 60 * 24
#define SERIAL_NUMBER_SIZE 254

#define PRIMARY_FILENAME "primary.json"
#define SECONDARY_FILENAME "secondary.json"

#define PKI_MANAGEMENT_URL "path/to/management/pki/"
#define PKI_REMOTE_URL "path/to/remote/pki/"
#define PKI_PRODUCTION_URL "path/to/remote/pki/"

#define PKI_MANAGEMENT_PATH "path/to/management/pki/"
#define PKI_REMOTE_PATH "path/to/remote/pki/"
#define PKI_PRODUCTION_PATH "path/to/remote/pki/"

#define MANAGEMENT_SERVICE_STR "management_service"
#define MANAGEMENT_STR "management"
#define REMOTE_STR "remote"
#define PRODUCTION_STR "production"

#define THREAD_INT 0
#define THREAD_EXT 1

typedef enum ManagementReturncode
{
    MGMT_BAD_REQUEST = -6,
    MGMT_PARSE_ERROR = -5,
    MGMT_EMPTY_OBJECT_ERROR = -4,
    MGMT_BAD_PARAMS = -3,
    MGMT_CONNECT_ERROR = -3,
    MGMT_ERR = -1,
    MGMT_OK = 0,
    MGMT_FORBIDDEN = 1,
    MGMT_BUSY = 2,
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
/**
 * @brief supported protocols for the proxy applications
 */
typedef enum Kritis3mProto
{
    DTLS = 0,
    TLS = 1,
    TCP = 2,
    UDP = 3
} Kritis3mProto;

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

/**
 * @brief ConnectionWhitelist details the allowed connections for the proxy applications based on the client IP and Port
 */

struct ConnectionWhitelist
{
    char allowed_client_ip_port[IPv4_PORT_LEN];
    int number_connections;
};

/**
 * @note when extending Kritis3mApplicationtype: DTLS_R_PROXY = MIN && TLS_R_PROXY = MAX
 * @example extension:
 * num Kritis3mApplicationtype
 * {
 *     DTLS_R_Proxy = 0,
 *     DTLS_F_Proxy = 1,
 *     DTLS_TUNNEL = 2
 *     TLS_F_PROXY = 3,
 *     TLS_R_PROXY = 4
 * };
 *
 */

/**
* @note when extending Kritis3mHelper Applicaitontype: ECHO_TCP_SERVER = minimal number and L2_BRIDGE = maximal number
* @example extension:
* enum Kritis3mHelperApplicationtype {
*    ECHO_TCP_SERVER = 0,
*    ECHO_UDP_SERVER = 1,
*    EXAMPLE_STANDARD_APPL = 2,
*    L2_BRIDGE =3,
};
 */

enum ApplicationStatus
{
    APK_ERR = -1,
    APK_OK = 1,
};

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
    int32_t id;
    network_identity identity;

    char *revocation_list_url;
    int revocation_list_url_size;

    char *server_addr;
    int server_addr_size;

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
};

typedef struct
{
    uint32_t config_id;
    uint32_t id;
    Kritis3mApplicationtype type;
    char server_ip[INET_ADDRSTRLEN];
    uint16_t server_port;

    char client_ip[INET_ADDRSTRLEN];
    uint16_t client_port;

    bool state;
    int32_t ep1_id;
    int32_t ep2_id;
    int log_level;
} Kritis3mApplications;

typedef struct
{
    int32_t id;
    char client_ip_port[IPv4_PORT_LEN];
    struct sockaddr_in addr;
    int number_trusted_applications;
    int trusted_applications_id[MAX_TRUSTED_APPLICATIONS];
} TrustedClients;

typedef struct
{
    int number_trusted_clients;
    TrustedClients TrustedClients[MAX_NUMBER_TRUSTED_CLIENTS];
} Whitelist;

struct ApplicationConfiguration
{
    pthread_mutex_t lock;
    Whitelist whitelist;

    int number_crypto_profiles;
    CryptoProfile crypto_profile[MAX_NUMBER_CRYPTOPROFILE];

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

typedef struct
{
    char serial_number[SERIAL_NUMBER_SIZE];
    char *server_addr;
    int server_addr_size;
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

    char *crypto_path;
    int crypto_path_size;

    char *config_path;
    int config_path_size;

    SelectedConfiguration selected_configuration;
} Kritis3mNodeConfiguration;

enum used_service
{
    EST_ENROLL = 0,
    EST_REENROLL,
    MGMT_POLICY_REQ,
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
int write_Kritis3mNodeConfig_toflash(Kritis3mNodeConfiguration *config);
int write_SystemConfig_toflash(SystemConfiguration *sys_cfg, char *filepath, int filepath_size);
Kritis3mApplications *find_application_by_application_id(Kritis3mApplications *appls, int number_appls, int appl_id);
int get_identity_folder_path(char *out_path, size_t size, const char *base_path, network_identity identity);

/*Cleanup Functions */

void cleanup_Systemconfiguration(SystemConfiguration *systemconfiguration);
void free_ManagementConfiguration(Kritis3mManagemntConfiguration *config);
void free_CryptoIdentity(crypto_identity *identity);
void free_NodeConfig(Kritis3mNodeConfiguration *config);

#endif // KRITIS3M_CONFIGURATION_H