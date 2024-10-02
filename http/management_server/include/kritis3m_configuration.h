#ifndef KRITIS3M_CONFIGURATION_H
#define KRITIS3M_CONFIGURATION_H

#include <stdint.h>
#include "asl.h"
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include "kritis3m_pki_client.h"
#include <netinet/in.h>

// lengths
#define IPv4_LEN 16
#define ID_LEN 256
#define NAME_LEN 256
#define DESCRIPTION_LEN 256
#define IPv4_PORT_LEN 40
#define MAX_NUMBER_CRYPTOPROFILE 20
#define MAX_NUMBER_APPLICATIONS 7
#define MAX_NUMBER_TRUSTED_CLIENTS 7
#define NUMBER_STD_APK 4
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




typedef enum
{
    TLS_FORWARD_PROXY,
    TLS_REVERSE_PROXY,
    TLS_TLS_PROXY,
    ECHO_SERVER,
    TCP_CLIENT_STDIN_BRIDGE,
    L2_BRIDGE,
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
} network_identity;

typedef struct
{
    network_identity identity;
    char *pki_base_url;
    int pki_base_url_size;
    int revocation_days;
    int32_t algorithm; // the algorithm is a feature of the identity and does not define it
} crypto_identity;

struct CryptoProfile
{
    uint32_t ID;
    char Name[256];
    bool MutualAuthentication;
    bool NoEncryption;
    enum asl_key_exchange_method ASLKeyExchangeMethod;
    bool UseSecureElement;
    enum asl_hybrid_signature_mode HybridSignatureMode;
    bool Keylog;
    crypto_identity Identity;
};

typedef struct
{
    uint32_t config_id;
    uint32_t id;
    Kritis3mApplicationtype type;
    char *server_ip_port;
    char *client_ip_port;
    bool state;
    uint32_t ep1_id;
    uint32_t ep2_id;
    int log_level;
} Kritis3mApplications;

typedef struct
{
    char client_ip_port[IPv4_PORT_LEN];
    int number_trusted_applications;
    int trusted_applications_id[10];
} TrustedClients;

typedef struct
{
    int number_trusted_clients;
    TrustedClients TrustedClients[MAX_NUMBER_TRUSTED_CLIENTS];
} Whitelist;

struct ApplicationConfiguration
{
    Whitelist whitelist;
    int number_crypto_profiles;
    CryptoProfile crypto_profile[MAX_NUMBER_CRYPTOPROFILE];

    int number_applications;
    Kritis3mApplications applications[MAX_NUMBER_APPLICATIONS];
};

struct SystemConfiguration
{
    uint32_t id;
    uint32_t node_id;
    char locality[256];
    char serial_number[256];
    uint32_t node_network_index;

    uint64_t heartbeat_interval;
    uint64_t updated_at;
    uint32_t version;
    ApplicationConfiguration application_config;
};

typedef struct
{
    const char *folderpath;
    SystemConfiguration primary;
    SystemConfiguration secondary;

    pthread_mutex_t primaryLock;
    pthread_mutex_t secondaryLock;

} ConfigurationManager;

typedef struct
{
    char serial_number[SERIAL_NUMBER_SIZE];
    char *management_server_url;
    int management_server_url_size;

    char *management_service_ip;
    crypto_identity identity;
} Kritis3mManagemntConfiguration;

typedef struct
{
    Kritis3mManagemntConfiguration management_identity;
    char *application_configuration_path;
    int application_configuration_path_size;

    char *machine_crypto_path;
    int machine_crypto_path_size;

    char *pki_cert_path;
    int pki_cert_path_size;

    char *kritis3m_node_configuration_path;

    int selected_configuration;
} Kritis3mNodeConfiguration;

int get_Kritis3mNodeConfiguration(char *filename, Kritis3mNodeConfiguration *config);
int get_Systemconfig(ConfigurationManager *applconfig, Kritis3mNodeConfiguration *node_config);
int write_Kritis3mNodeConfig_toflash(Kritis3mNodeConfiguration *config);

#endif // KRITIS3M_CONFIGURATION_H