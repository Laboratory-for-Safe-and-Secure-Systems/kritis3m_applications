#ifndef KRITIS3M_CONFIGURATION_H
#define KRITIS3M_CONFIGURATION_H

#include <stdint.h>
#include "asl.h"
#include <stdbool.h>
#include <time.h>

// lengths
#define IPv4_LEN 16
#define ID_LEN 256
#define NAME_LEN 256
#define DESCRIPTION_LEN 256
#define IPv4_PORT_LEN 40
#define NUMBER_CRYPTOPROFILE 20
#define NUMBER_PROXIES 7
#define NUMBER_STD_APK 4
#define HARDBEAT_DEFAULT_S 24 * 60 * 60
#define HARDBEAT_MIN_S 20
#define HARDBEAT_MAX_S 60 * 60 * 24

#define MAX_CONS 5

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
    char allowed_client_ip_port[IPv4_PORT_LEN][MAX_CONS];
    int number_connections;
};

/**
 * @warning !READ! Min and Max are used as boundaries in the parser
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
 * @warning !READ! Min and Max are used as boundaries in the parser
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
 * @warning !READ! Min and Max are used as boundaries in the parser
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

/****************** CRYPTO PROVILE DEFINITIONS ******************
 * @warning !READ! Min and Max are used as boundaries in the parser
 *
 */
enum CertificatID
{
    PQC = 0,
    HYBRID_CLASSIC = 1,
    HYBRID_PQC = 2,
    CLASSIC = 3
};
#define N_PQC "PQC"
#define N_HB_CLASSIC "HYBRID_CLASSIC"
#define N_HB_PQC "HYBRID_PQC"
#define N_CLASSIC "CLASSIC"

struct Kritis3mHelperApplication
{
    char listening_ip_port[IPv4_PORT_LEN];
    Kritis3mHelperApplicationtype application_type;
};

struct CryptoProfile
{
    char ID[ID_LEN];                   // ID of the configuration
    char name[NAME_LEN];               // Name of Crypto Profile
    char description[DESCRIPTION_LEN]; // Description of the Crypto Profile. We can log that
    int certificate_ID;                // certificate ID
    bool use_secure_element;           // Use of Secure Element
    bool secure_element_import_keys;
    enum asl_hybrid_signature_mode hybrid_signature_mode;
};

// Structure for JS_ProxyApplication
typedef struct
{
    char listening_ip_port[IPv4_PORT_LEN];
    char target_ip_port[IPv4_PORT_LEN];
    Kritis3mApplicationtype application_type;
    Kritis3mProto listening_proto;
    Kritis3mProto target_proto;
    char tunnel_crypto_profile_ID[ID_LEN];
    char asset_crypto_profile_ID[ID_LEN];
    int num_connections;
    ConnectionWhitelist connection_whitelist;
} ProxyApplication;

struct SystemConfiguration
{
    int number_crypto_profiles;
    int hardbeat_interval_s;
    CryptoProfile crypto_profile[NUMBER_CRYPTOPROFILE];
    int number_proxy_applications;
    ProxyApplication proxy_applications[NUMBER_PROXIES];
    int number_standard_applications;
    Kritis3mHelperApplication standard_applications[NUMBER_STD_APK];
};

#endif //KRITIS3M_CONFIGURATION_H