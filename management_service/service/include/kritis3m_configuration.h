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

typedef enum
{
        MANAGEMENT_SERVICE,
        MANAGEMENT,
        REMOTE,
        PRODUCTION,
        max_identities
} network_identity;

enum ApplicationStatus
{
        APK_ERR = -1,
        APK_OK = 0,
};

/**
 * @brief Enumeration of IPC return codes.
 *
 * This enumeration defines the response codes used for inter-process communication (IPC),
 * indicating the status of a message or request.
 */
enum MSG_RESPONSE_CODE
{
        MSG_ERROR = -1,    /**< Indicates an error occurred. */
        MSG_OK = 0,        /**< Indicates the operation was successful. */
        MSG_FORBIDDEN = 1, /**< Indicates the request was forbidden. */
        MSG_BUSY = 2,      /**< Indicates the system is currently busy. */
};

/**
 * @brief Enumeration of services used to identify requests in the HTTP module.
 *
 * This enumeration specifies the type of service being requested, which is used
 * to identify and handle the request within the HTTP module. Currently only MGMT_POLICY_REQ &
 * MGMT_SEND_STATUS_REQ is implemented.
 */
enum used_service
{
        EST_ENROLL = 0,       /**< Request for EST enrollment. */
        EST_REENROLL,         /**< Request for EST re-enrollment. */
        MGMT_POLICY_REQ,      /**< Request to retrieve the management policy. */
        MGMT_SEND_STATUS_REQ, /**< Request to send the status to the management server. */
        MGMT_POLICY_CONFIRM,  /**< Request to confirm the management policy. */
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
        int32_t id;
        network_identity identity;

        char* revocation_list_url;
        int revocation_list_url_size;

        char* secure_middleware_path;
        int secure_middleware_path_int;

        EndpointAddr server_endpoint_addr;

        char* server_url;
        int server_url_size;

        char* filepath;
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
        bool Keylog;
        int32_t crypto_identity_id;
        char* secure_middleware_path;
        char* pin;
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

typedef struct
{
        char serial_number[SERIAL_NUMBER_SIZE];
        EndpointAddr server_endpoint_addr;

        char* secure_middleware_path;
        int secure_middleware_path_size;

        char* pin;
        int pin_size;

        crypto_identity identity;
} Kritis3mManagemntConfiguration;

typedef struct
{
        Kritis3mManagemntConfiguration management_identity;

        char* primary_path;
        int primary_path_size;

        char* secondary_path;
        int secondary_path_size;

        char* machine_crypto_path;
        int machine_crypto_path_size;

        char* pki_cert_path;
        int pki_cert_path_size;

        char* management_service_path;
        int management_service_path_size;

        char* management_path;
        int management_path_size;

        char* production_path;
        int production_path_size;

        char* remote_path;
        int remote_path_size;

        char* crypto_path;
        int crypto_path_size;

        char* config_path;
        int config_path_size;

        SelectedConfiguration selected_configuration;
} Kritis3mNodeConfiguration;

/* ------------------------- Startup Configuration ----------------------------*/

/**
 * @brief Retrieves the initial node configuration from the specified startup JSON file.
 *
 * This function reads the startup configuration data from the given file path
 * and populates the provided Kritis3mNodeConfiguration structure.
 *
 * @param filename The path to the startup.json file containing the initial configuration.
 * @param[out] config Pointer to the Kritis3mNodeConfiguration structure
 * @return 0 on success, or an error code on failure.
 */
int get_Kritis3mNodeConfiguration(char* filename, Kritis3mNodeConfiguration* config);
int get_identity_folder_path(char* out_path, size_t size, const char* base_path, network_identity identity);

/*-------------------------  Systemconfiguration ---------------------------------- */

/**
 * @brief Reads the application configuration from the filesystem.
 *
 * This function retrieves the system configuration, containing the configurations of the kritis3m applications
 * (forward- & reverse proxy) and populates these within the ConfigurationManager struct. Ensure that
 * the control server has been called beforehand to obtain the latest configuration.
 *
 * @param[out] applconfig Pointer to the ConfigurationManager structure to store application configuration.
 * @param[in] node_config Pointer to the Kritis3mNodeConfiguration structure, containing the required filepaths.
 * @return 0 on success, or an error code on failure.
 */
int get_Systemconfig(ConfigurationManager* applconfig, Kritis3mNodeConfiguration* node_config);
SystemConfiguration* get_active_config(ConfigurationManager* manager);
SystemConfiguration* get_inactive_config(ConfigurationManager* manager);
Kritis3mApplications* find_application_by_application_id(Kritis3mApplications* appls,
                                                         int number_appls,
                                                         int appl_id);
// parses an ApplicationManagerStatus object into json format and writes content to json_buffer
char* applicationManagerStatusToJson(const ApplicationManagerStatus* status,
                                     char* json_buffer,
                                     size_t buffer_length);

/*-------------------------- Networking Functions ---------------------------------*/
// net helper methods
int parse_addr_toKritis3maddr(char* ip_port, Kritis3mSockaddr* dst);
// creates filepaths of certificates and reads certificate
int load_certificates(crypto_identity* identity);
// obtains endpoint configuration from crypto identity and crypto_profile object
int create_endpoint_config(crypto_identity* crypto_id,
                           CryptoProfile* crypto_profile,
                           asl_endpoint_configuration* ep_cfg);

/*Cleanup Functions */
void cleanup_configuration_manager(ConfigurationManager* configuation_manager);
void cleanup_Systemconfiguration(SystemConfiguration* systemconfiguration);
void free_ManagementConfiguration(Kritis3mManagemntConfiguration* config);
void free_CryptoIdentity(crypto_identity* identity);
void free_NodeConfig(Kritis3mNodeConfiguration* config);

#endif // KRITIS3M_CONFIGURATION_H