
enum proxy_type
{
    FORWARD_PROXY,
    REVERSE_PROXY,
    DTLS_FORWARD_PROXY,
    DTLS_REVERSE_PROXY
};
enum standard_application_type
{
    ECHO_CLIENT,
    ECHO_SERVER,
};

struct standard_application
{
    enum standard_application_type type;
    char* server_ip_port;
    char* client_ip_port;
};

enum crypto_protocol
{
    TLS_1_2,
    TLS_1_3,
    DTLS_1_2,
    DTLS_1_3,
};
enum tls_auth
{
    SERVER_AUTH_ONLY,
    MUTUAL_AUTH,
};
enum certificate_identifier{
    ECC,
    PQC,
    RSA,
};

struct crypto_config
{
    enum crypto_protocol protocol_version;
    enum tls_auth auth_type;
    enum certificate_identifier cert_id;
};

struct proxy_mappings
{
    char* incomming_client_ip_port; // the client that connects to the proxy
    char* proxy_target_server_ip_port; // the destination the proxy is targetting
};

struct proxy_application
{
    char* listening_ip_port; // the server ip addr of the proxy
    char* client_ip_port; // the source ip of the proxy client
    enum proxy_type type;
    struct crypto_config crypto_config;

    struct proxy_mappings mappings[6];
    int mapping_count;  

};

struct application_config
{
    struct proxy_application proxies[6];
    int proxy_count;

    struct standard_application standard_apps[6];
    int standard_app_count;
};