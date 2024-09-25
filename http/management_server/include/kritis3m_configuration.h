#ifndef KRITIS3M_CONFIGURATION_H
#define KRITIS3M_CONFIGURATION_H

#include <stdint.h>
#include "asl.h"
#include <stdbool.h>
#include <time.h>
#include <pthread.h>

// lengths
#define IPv4_LEN 16
#define ID_LEN 256
#define NAME_LEN 256
#define DESCRIPTION_LEN 256
#define IPv4_PORT_LEN 40
#define NUMBER_CRYPTOPROFILE 20
#define NUMBER_PROXIES 7
#define MAX_NUMBER_TRUSTED_CLIENTS 7
#define NUMBER_STD_APK 4
#define HARDBEAT_DEFAULT_S 24 * 60 * 60
#define HARDBEAT_MIN_S 20
#define HARDBEAT_MAX_S 60 * 60 * 24

/** defining supported applications for Kritis3m Gateway
 * DTLS_R_Proxy
 * DTLS_F_Proxy
 * TLS_F_PROXY
 * TLS_R_PROXY
 */
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
    uint8_t Identity;
};

typedef struct
{
    uint32_t application_id;
    unsigned int id;
    Kritis3mApplicationtype type;
    char *server_ip_port;
    char *client_ip_port;
    bool state;
    unsigned int ep1_id;
    unsigned int ep2_id;
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
    CryptoProfile crypto_profile[NUMBER_CRYPTOPROFILE];

    int number_applications;
    Kritis3mApplications applications[NUMBER_PROXIES];
};

struct SystemConfiguration
{
    uint32_t id;
    uint32_t node_id;
    char locality[256];
    char serial_number[256];
    uint32_t node_network_index;

    uint64_t hardbeat_interval;
    uint64_t updated_at;
    uint32_t version;
    ApplicationConfiguration application_config;
};

typedef struct
{
    SystemConfiguration primary;
    SystemConfiguration secondary;
    char active_configuration[256];

    pthread_mutex_t primaryLock;
    pthread_mutex_t secondaryLock;

} ConfigurationManager;
ConfigurationManager *parse_configuration(char *filename);
SystemConfiguration *get_active_configuration(ConfigurationManager *config);
SystemConfiguration *get_free_configuration(ConfigurationManager *config);

#endif // KRITIS3M_CONFIGURATION_H