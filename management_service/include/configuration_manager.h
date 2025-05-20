#ifndef CONFIGURATION_MANAGER_H
#define CONFIGURATION_MANAGER_H

#include "asl.h"
#include "kritis3m_configuration.h"
#include "tls_proxy.h"
#include <pthread.h>
#include <time.h>

int init_configuration_manager(char* base_path);

enum ACTIVE
{
        ACTIVE_NONE = 0,
        ACTIVE_ONE,
        ACTIVE_TWO,
};
enum PROXY_TYPE
{
        PROXY_UNSPECIFIC = 0,
        PROXY_FORWARD = 1,
        PROXY_REVERSE = 2,
        PROXY_TLS_TLS = 3,
};

#define  RSA2048   "rsa2048"
#define  RSA3072   "rsa3072"
#define  RSA4096   "rsa4096"
#define  SECP256   "secp256"
#define  SECP384   "secp384"
#define  SECP521   "secp521"
#define  ED25519   "ed25519"
#define  ED448     "ed448"
#define  MLDSA44   "mldsa44"
#define  MLDSA65   "mldsa65"
#define  MLDSA87   "mldsa87"
#define  FALCON512 "falcon512"
#define  FALCON102 "falcon10244"

struct coordinator_status
{
        int32_t module;
        int32_t state;
        char* msg;
};

struct sysconfig
{
        // controlplane
        char* serial_number;
        int log_level;

        enum ACTIVE controlplane_cert_active;
        enum ACTIVE dataplane_cert_active;

        enum ACTIVE application_active;

        char* broker_host;

        char* est_host;
        int est_port;
        asl_endpoint_configuration* endpoint_config;
};
struct worker_controlplane_set_certificate_args
{
        char* buffer;
        size_t size;
        void* arg;
};
struct hardware_configs
{
        HardwareConfiguration* hw_configs;
        int number_of_hw_configs;
};

struct proxy_wrapper
{
        char* name;
        proxy_config proxy_config;
        int proxy_id;
        int direction;
};

struct group_config
{
        asl_endpoint_configuration* endpoint_config;
        int number_proxies;
        struct proxy_wrapper* proxy_wrapper;
};

struct application_manager_config
{
        struct group_config* group_config;
        int number_of_groups;
};




void cfg_manager_log_level_set(int log_level);

const struct sysconfig* get_sysconfig();

int get_application_inactive(struct application_manager_config* config,
                             struct hardware_configs* hw_config);

/**
 * @brief Reads hardware configuration based on the active dataplane configuration
 *
 * This function reads in the hardware configuration from either application_1_path or application_2_path
 * based on which dataplane configuration is active, and populates the provided structures.
 *
 * @param[out] app_config Pointer to application_manager_config structure to be populated
 * @param[out] hw_configs Pointer to hardware_configs structure to be populated
 * @return 0 on success, -1 on failure
 *
 * @note Both structures are allocated by this function and must be freed by the caller.
 *       In case of an error, any allocated memory is freed internally.
 */
int get_active_hardware_config(struct application_manager_config* app_config,
                               struct hardware_configs* hw_configs);

int application_store_inactive(char* buffer, size_t size);



void cleanup_application_config(struct application_manager_config* config);
void cleanup_hardware_configs(struct hardware_configs* hw_configs);
void cleanup_configuration_manager(void);
char* get_base_path(void);

enum CONFIG_TYPE
{
        CONFIG_CONTROLPLANE = 0,
        CONFIG_DATAPLANE,
        CONFIG_APPLICATION
};

struct config_update
{
        enum CONFIG_TYPE type;

        void* new_config;

        size_t config_size;
        bool (*validation_callback)(void* config);
        void* validation_context;

        enum ACTIVE* active_path;

        bool is_validating;
        bool validation_success;
};

struct config_state
{
        enum ACTIVE active_path;
        bool is_validating;
        bool validation_success;
};


// Transaction states
enum TRANSACTION_STATE
{
        TRANSACTION_IDLE = 0,
        TRANSACTION_PENDING,
        TRANSACTION_VALIDATING,
        TRANSACTION_COMMITTED,
        TRANSACTION_FAILED
};

// Callback function types
typedef int (*config_fetch_callback)(void* context, enum CONFIG_TYPE type, void* to_fetch);
typedef int (*config_validate_callback)(void* context, enum CONFIG_TYPE type,void* to_fetch);
typedef void (*config_notify_callback)();

struct config_transaction
{
        enum CONFIG_TYPE type;
        void* context;

        void* to_fetch;

        config_fetch_callback fetch;
        config_validate_callback validate;
        config_notify_callback notify;

        enum TRANSACTION_STATE state;
        pthread_t worker_thread;
        bool thread_running;
        pthread_mutex_t mutex;
        pthread_cond_t cond;
        // Timeout related fields
        struct timespec timeout;
        bool has_timeout;
        void (*timeout_callback)(void* context);
};

// Transaction management functions
int init_config_transaction(struct config_transaction* transaction,
                            enum CONFIG_TYPE type,
                            void* context, //defines how to reach out to the server
                            void* to_fetch, //defines the return value
                            config_fetch_callback fetch, //defines the function to fetch the config
                            config_validate_callback validate, //defines the function to validate the config
                            config_notify_callback notify //defines the function to notify the caller of the transaction
                            ); //defines the function to cleanup the transaction

int start_config_transaction(struct config_transaction* transaction);
int cancel_config_transaction(struct config_transaction* transaction);
void cleanup_config_transaction(struct config_transaction* transaction);

/**
 * @brief Creates a deep copy of hardware_configs structure
 * 
 * @param src The source hardware_configs structure to copy
 * @return struct hardware_configs* A newly allocated deep copy, or NULL on failure
 */
struct hardware_configs* deep_copy_hardware_configs(const struct hardware_configs* src);

/**
 * @brief Creates a deep copy of application_manager_config structure
 * 
 * @param src The source application_manager_config structure to copy
 * @return struct application_manager_config* A newly allocated deep copy, or NULL on failure
 */
struct application_manager_config* deep_copy_application_config(const struct application_manager_config* src);

char const* get_algorithm(char* algo);



#endif // CONFIGURATION_MANAGER_H
