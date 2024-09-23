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
typedef enum Kritis3mApplicationtype Kritis3mApplicationtype;

/**
 * @brief Represents the system configuration.
 * Including:
 * - Accepted connections
 * - Proxy Server Port
 * - Proxy Endpoint
 * - Used Crypto Profile
 */
typedef struct SystemConfiguration SystemConfiguration;
struct SystemConfiguration;

/**
 * @brief Cryptoprofile details the supported crypto profiles for the Kritis3m Gateway
 * Including:
 * - Use of SmartCard
 * - Certificates
 * - Algorithms
 */
typedef struct CryptoProfile CryptoProfile;
struct CryptoProfile;
/**
 * @brief supported protocols for the proxy applications
 */
typedef enum Kritis3mProto Kritis3mProto;
enum Kritis3mProto;

/**
 * @brief ConnectionWhitelist details the allowed connections for the proxy applications based on the client IP and Port
 */
typedef struct ConnectionWhitelist ConnectionWhitelist;
struct ConnectionWhitelist;

/** @brief supported applications for the helper applications
 * ECHO_TCP_SERVER
 * ECHO_UDP_SERVER
 */
typedef enum Kritis3mHelperApplicationtype Kritis3mHelperApplicationtype;
enum Kritis3mHelperApplicationtype;

/** @brief Defining structure of Kritis3mHelper Applications  */
typedef struct Kritis3mHelperApplication Kritis3mHelperApplication;
struct Kritis3mHelperApplication;

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
enum Kritis3mApplicationtype
{
    DTLS_R_Proxy = 0,
    DTLS_F_Proxy = 1,
    TLS_F_PROXY = 2,
    TLS_R_PROXY = 3
};

/**
 * @note when extending Kritis3mProto: DTLS = MIN && UDP = MAX
 * @example extension:
 *enum Kritis3mProto
 *{
 *    DTLS = 0,
 *    TLS = 1,
 *    TCP = 2,
 *    MACSEC = 3,
 *    UDP = 4
 *};
 */
enum Kritis3mProto
{
    DTLS = 0,
    TLS = 1,
    TCP = 2,
    UDP = 3
};

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
enum Kritis3mHelperApplicationtype
{
    ECHO_TCP_SERVER = 0,
    ECHO_UDP_SERVER = 1,
    L2_BRIDGE = 2,
};

enum ApplicationStatus
{
    APK_ERR = -1,
    APK_OK = 1,
};

/****************** CRYPTO PROVILE DEFINITIONS ******************/
enum CertificatID
{
    PQC = 0,
    HYBRID_CLASSIC = 1,
    HYBRID_PQC = 2,
    CLASSIC = 3
};

struct Kritis3mHelperApplication
{
    char listening_ip_port[IPv4_PORT_LEN];
    Kritis3mHelperApplicationtype application_type;
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
    unsigned int id;
    unsigned int type;
    char *server_ip_port;
    char *client_ip_port;
    bool state;
    unsigned int ep1_id;
    unsigned int ep2_id;
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

struct SystemConfiguration
{
    pthread_mutex_t config_mutex;
    uint32_t id;
    uint32_t node_id;
    char locality[256];
    char serial_number[256];
    uint32_t node_network_index;

    uint64_t hardbeat_interval;
    uint64_t updated_at;
    uint32_t version;

    Whitelist whitelist;
    int number_crypto_profiles;
    CryptoProfile crypto_profile[NUMBER_CRYPTOPROFILE];

    int number_applications;
    Kritis3mApplications applications[NUMBER_PROXIES];
};

typedef struct
{
    SystemConfiguration primary;
    SystemConfiguration secondary;
    char active_configuration[256];
} ConfigurationManager;


int load_configuration(const char *filename, ConfigurationManager *config);
SystemConfiguration* get_active_configuration(ConfigurationManager *config);
SystemConfiguration* get_free_configuration(ConfigurationManager *config);

#endif // KRITIS3M_CONFIGURATION_H