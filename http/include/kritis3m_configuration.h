#ifndef KRITIS3M_CONFIGURATION_H
#define KRITIS3M_CONFIGURATION_H

#include <stdint.h>
#include <time.h>
#include <netinet/in.h>

//lengths 
#define IPv4_LEN 16
#define ID_LEN 256
#define NAME_LEN 256
#define DESCRIPTION_LEN 256
#define IPv4_PORT_LEN 40
#define NUMBER_CRYPTOPROFILE 20 
#define NUMBER_PROXIES 7
#define NUMBER_STD_APK 4

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

struct ConnectionWhitelist{
    char allowed_client_ip_port[IPv4_PORT_LEN];
    int num_allowed;
};

enum Kritis3mApplicationtype {
    DTLS_R_Proxy = 0 ,
    DTLS_F_Proxy = 1,
    TLS_F_PROXY = 2,
    TLS_R_PROXY= 3
};

enum Kritis3mProto {
    DTLS= 0,
    TLS = 1,
    TCP = 2,
    UDP = 3
};
enum Kritis3mHelperApplicationtype {
    ECHO_TCP_SERVER = 0,
    ECHO_UDP_SERVER = 1,
    STD_IN_BRIDGE = 2
};

struct Kritis3mHelperApplication{
    char listening_ip_port[IPv4_PORT_LEN];
    Kritis3mHelperApplicationtype application_type;
};

struct CryptoProfile{
    char ID[ID_LEN]; // ID of the configuration
    char name[NAME_LEN]; // Name of Crypto Profile
    char description[DESCRIPTION_LEN]; // Description of the Crypto Profile. We can log that
    char certificate_ID[ID_LEN];// certificate ID
    int smartcard_enable;
};

// Structure for JS_ProxyApplication
typedef struct {
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


struct SystemConfiguration{
    int number_crypto_profiles;
    int hardbeat_interval_s;
    CryptoProfile crypto_profile[NUMBER_CRYPTOPROFILE]; 
    int number_proxy_applications;
    ProxyApplication proxy_applications[NUMBER_PROXIES];
    int number_standard_applications;
    Kritis3mHelperApplication standard_applications[NUMBER_STD_APK];

};

#endif //KRITIS3M_CONFIGURATION_H