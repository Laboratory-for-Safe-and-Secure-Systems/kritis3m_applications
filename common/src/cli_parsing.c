#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "logging.h"

#include "cli_parsing.h"


LOG_MODULE_REGISTER(cli_parsing);


struct certificates
{
        char const* certificate_path;
        char const* private_key_path;
        char const* additional_key_path;
        char const* intermediate_path;
        char const* root_path;

#if defined(__ZEPHYR__)
        /* Temporary helper until we have a proper file system in Zephyr */
        char const* identity;
#endif

        uint8_t* chain_buffer; /* Entity and intermediate certificates */
        size_t chain_buffer_size;

        uint8_t* key_buffer;
        size_t key_buffer_size;

        uint8_t* additional_key_buffer;
        size_t additional_key_buffer_size;
        
        uint8_t* root_buffer;
        size_t root_buffer_size;
};


static const struct option cli_options[] =
{
    { "reverse_proxy",    no_argument,          0, 'w' },
    { "forward_proxy",    no_argument,          0, 'x' },
    { "echo_server",      no_argument,          0, 'y' },
    { "echo_client",      no_argument,          0, 'z' },
    { "incoming",         required_argument,    0, 'a' },
    { "outgoing",         required_argument,    0, 'b' },
    { "identity",         required_argument,    0, 'v' },
    { "cert",             required_argument,    0, 'c' },
    { "key",              required_argument,    0, 'k' },
    { "intermediate",     required_argument,    0, 'i' },
    { "root",             required_argument,    0, 'r' },
    { "additionalKey",    required_argument,    0, 'l' },
    { "mutualAuth",       required_argument,    0, 'n' },
    { "noEncryption",     required_argument,    0, 'o' },
    { "hybrid_signature", required_argument,    0, 'q' },
    { "secure_element",   no_argument,          0, 's' },
    { "middleware_path",  required_argument,    0, 'm' },
    { "se_import_keys",   required_argument,    0, 'p' },
    { "debug",            no_argument,          0, 'd' },
    { "bridge_lan",       required_argument,    0, 'e' },
    { "bridge_wan",       required_argument,    0, 'f' },
    { "help",             no_argument,          0, 'h' },
    {NULL, 0, NULL, 0}
};


static int read_certificates(const struct shell *sh, struct certificates* certs,
                             enum application_role* role);
static void print_help(const struct shell *sh, char const* name);


/* Parse the provided argv array and store the information in the provided config variables. 
 * 
 * Returns 0 on success, +1 in case the help was printed and  -1 on failure (error is printed
 * on console).
 */
int parse_cli_arguments(enum application_role* role, struct proxy_config* proxy_config,
                        wolfssl_library_configuration* wolfssl_config, l2_bridge_config* bridge_config,
                        struct shell const* sh, size_t argc, char** argv)
{
        if ((role == NULL) || (proxy_config == NULL))
        {
                shell_error(sh, "mandatory argument missing for parse_cli_arguments()");
                return -1;
        }

	/* Set default values */
        *role = NOT_SET;

        proxy_config->own_ip_address = NULL;
        proxy_config->listening_port = 0;
        proxy_config->target_ip_address = NULL;
        proxy_config->target_port = 0;
        proxy_config->tls_config.mutual_authentication = true;
        proxy_config->tls_config.no_encryption = false;
        proxy_config->tls_config.use_secure_element = false;
        proxy_config->tls_config.secure_element_import_keys = false;
        proxy_config->tls_config.hybrid_signature_mode = HYBRID_SIGNATURE_MODE_BOTH;
        proxy_config->tls_config.device_certificate_chain.buffer = NULL;
        proxy_config->tls_config.device_certificate_chain.size = 0;
        proxy_config->tls_config.private_key.buffer = NULL;
        proxy_config->tls_config.private_key.size = 0;
        proxy_config->tls_config.private_key.additional_key_buffer = NULL;
        proxy_config->tls_config.private_key.additional_key_size = 0;
        proxy_config->tls_config.root_certificate.buffer = NULL;
        proxy_config->tls_config.root_certificate.size = 0;
	
        if (wolfssl_config != NULL)
        {
                wolfssl_config->loggingEnabled = false;
                wolfssl_config->secure_element_support = false;
                wolfssl_config->secure_element_middleware_path = NULL;
        }

        if (bridge_config != NULL)
        {
                bridge_config->lan_interface = NULL;
                bridge_config->wan_interface = NULL;
        }

        struct certificates certs = {
                .certificate_path = NULL,
                .private_key_path = NULL,
                .additional_key_path = NULL,
                .intermediate_path = NULL,
                .root_path = NULL,

        #if defined(__ZEPHYR__)
                .identity = NULL,
        #endif

                .chain_buffer = NULL,
                .chain_buffer_size = 0,
                .key_buffer = NULL,
                .key_buffer_size = 0,
                .additional_key_buffer = NULL,
                .additional_key_buffer_size = 0,
                .root_buffer = NULL,
                .root_buffer_size = 0,
        };


	/* Parse arguments */
	int index = 0;
#if defined(__ZEPHYR__)
        getopt_init();
#endif
	while (true)
	{
		int result = getopt_long(argc, argv, "wxyza:b:v:c:k:i:r:l:n:o:q:sm:p:de:f:h", cli_options, &index);

		if (result == -1) 
		        break; /* end of list */

		switch (result)
		{
                        case 'w':
                                if (*role != NOT_SET)
                                {
                                        shell_error(sh, "you can only specify one role at a time");
                                        return -1;
                                }
                                *role = ROLE_REVERSE_PROXY;
                                break;
                        case 'x':
                                if (*role != NOT_SET)
                                {
                                        shell_error(sh, "you can only specify one role at a time");
                                        return -1;
                                }
                                *role = ROLE_FORWARD_PROXY;
                                break;
                        case 'y':
                                if (*role != NOT_SET)
                                {
                                        shell_error(sh, "you can only specify one role at a time");
                                        return -1;
                                }
                                *role = ROLE_ECHO_SERVER;
                                break;
                        case 'z':
                                if (*role != NOT_SET)
                                {
                                        shell_error(sh, "you can only specify one role at a time");
                                        return -1;
                                }
                                *role = ROLE_ECHO_CLIENT;
                                break;
			case 'a':
			{
				/* Check if an IP address is provided */
				char* separator = strchr(optarg, ':');
				char* port_str = NULL;
				if (separator == NULL)
				{
					port_str = optarg;
					proxy_config->own_ip_address = "0.0.0.0";
				}
				else
				{
					*separator = '\0';
					proxy_config->own_ip_address = optarg;
					port_str = separator + 1;
				}

				/* Parse the port */
				unsigned long new_port = strtoul(port_str, NULL, 10);
				if ((new_port == 0) || (new_port > 65535))
				{
					shell_error(sh, "invalid port number %lu", new_port);
					return -1;
				}
				proxy_config->listening_port = (uint16_t) new_port;
				break;
			}
			case 'b':
			{
				proxy_config->target_ip_address = strtok(optarg, ":");

				char* port_str = strtok(NULL, ":");
				unsigned long dest_port = strtoul(port_str, NULL, 10);
				if ((dest_port == 0) || (dest_port > 65535))
				{
					shell_error(sh, "invalid port number %lu", dest_port);
					return -1;
				}
				proxy_config->target_port = (uint16_t) dest_port;
				break;
			}
                        case 'v':
                        #if defined(__ZEPHYR__)
                                certs.identity = optarg;
                        #else
                                shell_warn(sh, "--identity is not supported, ignoring...");
                        #endif
                                break;
			case 'c':
				certs.certificate_path = optarg;
				break;
			case 'k':
				certs.private_key_path = optarg;
				break;
			case 'i':
				certs.intermediate_path = optarg;
				break;
			case 'r':
				certs.root_path = optarg;
				break;
                        case 'l':
                                certs.additional_key_path = optarg;
                                break;
                        case 'n':
                                proxy_config->tls_config.mutual_authentication = (bool) strtoul(optarg, NULL, 10);
                                break;
                        case 'o':
                                proxy_config->tls_config.no_encryption = (bool) strtoul(optarg, NULL, 10);
                                break;
                        case 'q':
                        {
                                enum hybrid_signature_mode mode;
                                if (strcmp(optarg, "both") == 0)
                                        mode = HYBRID_SIGNATURE_MODE_BOTH;
                                else if (strcmp(optarg, "native") == 0)
                                        mode = HYBRID_SIGNATURE_MODE_NATIVE;
                                else if (strcmp(optarg, "alternative") == 0)
                                        mode = HYBRID_SIGNATURE_MODE_ALTERNATIVE;
                                else
                                {
                                        shell_warn(sh, "invalid hybrid signature mode: %s", optarg);
                                        print_help(sh, argv[0]);
                                        return 1;
                                }
                                proxy_config->tls_config.hybrid_signature_mode = mode;
                                break;
                        }
			case 's':
                                proxy_config->tls_config.use_secure_element = true;
				if (wolfssl_config != NULL)
                                        wolfssl_config->secure_element_support = true;
				break;
                        case 'm':
                                if (wolfssl_config != NULL)
                                        wolfssl_config->secure_element_middleware_path = optarg;
                                break;
                        case 'p':
                                proxy_config->tls_config.secure_element_import_keys = (bool) strtoul(optarg, NULL, 10);
                                break;
                        case 'd':
                                if (wolfssl_config != NULL)
                                        wolfssl_config->loggingEnabled = true;
                                break;
                        case 'e':
                                if (bridge_config != NULL)
                                        bridge_config->lan_interface = optarg;
                                break;
                        case 'f':
                                if (bridge_config != NULL)
                                        bridge_config->wan_interface = optarg;
                                break;
			case 'h':
				print_help(sh, argv[0]);
				return 1;
				break;
			default:
				shell_warn(sh, "unknown option: %c", result);
                                print_help(sh, argv[0]);
                                return 1;
		}
    	}

	/* Read certificates */
    	if (read_certificates(sh, &certs, role) != 0)
	{
        	return -1;
	}

	/* Set TLS config */
	proxy_config->tls_config.device_certificate_chain.buffer = certs.chain_buffer;
	proxy_config->tls_config.device_certificate_chain.size = certs.chain_buffer_size;
	proxy_config->tls_config.private_key.buffer = certs.key_buffer;
	proxy_config->tls_config.private_key.size = certs.key_buffer_size;
        proxy_config->tls_config.private_key.additional_key_buffer = certs.additional_key_buffer;
	proxy_config->tls_config.private_key.additional_key_size = certs.additional_key_buffer_size;
	proxy_config->tls_config.root_certificate.buffer = certs.root_buffer;
	proxy_config->tls_config.root_certificate.size = certs.root_buffer_size;

        return 0;
}


static void print_help(const struct shell *sh, char const* name)
{
        shell_print(sh, "Usage: %s [OPTIONS]", name);
        shell_print(sh, "Roles:\n");
        shell_print(sh, "  --reverse_proxy                  start a TLS reverse proxy (use --incoming and --outgoing for connection configuration)");
        shell_print(sh, "  --forward_proxy                  start a TLS forward proxy (use --incoming and --outgoing for connection configuration)");
        shell_print(sh, "  --echo_server                    start a TLS echo server (use --incoming for connection configuration)");
        shell_print(sh, "  --echo_client                    start a TLS stdin echo client (use --outgoing for connection configuration)");
        shell_print(sh, "\nConnection configuration:\n");
        shell_print(sh, "  --incoming <ip:>port             configuration of the incoming TCP/TLS connection");
        shell_print(sh, "  --outgoing ip:port               configuration of the outgoing TCP/TLS connection");
        shell_print(sh, "\nOptions:\n");
#if defined(__ZEPHYR__)
        shell_print(sh, "  -v, --identity name              use stored certificates for given identity");
#endif
        shell_print(sh, "  -c, --cert file_path             path to the certificate file");
        shell_print(sh, "  -k, --key file_path              path to the private key file");
        shell_print(sh, "  -i, --intermediate file_path     path to an intermediate certificate file");
        shell_print(sh, "  -r, --root file_path             path to the root certificate file");
        shell_print(sh, "  --additionalKey file_path        path to an additional private key file (hybrid signature mode)\n");
        shell_print(sh, "  --mutualAuth 0|1                 enable or disable mutual authentication (default enabled)");
        shell_print(sh, "  --noEncryption 0|1               enable or disable encryption (default enabled)");
        shell_print(sh, "  --hybrid_signature mode          mode for hybrid signatures: both, native, alternative (default: both)\n");
        shell_print(sh, "  --secure_element                 use secure element");
        shell_print(sh, "  --middleware_path file_path      path to the secure element middleware");
        shell_print(sh, "  --se_import_keys 0|1             import provided keys into secure element (default disabled)\n");
        shell_print(sh, "  -d, --debug                      enable debug output\n");
        shell_print(sh, "  --bridge_lan interface           name of the LAN interface for the Layer 2 bridge");
        shell_print(sh, "  --bridge_wan interface           name of the WAN interface for the Layer 2 bridge\n");
        shell_print(sh, "  -h, --help                       display this help and exit");
}


#if defined(__ZEPHYR__)

#include "certificates.h"


/* Read all certificate and key files from the paths provided in the `certs` 
 * structure and store the data in the buffers. Memory is allocated internally
 * and must be freed by the user. 
 * 
 * Returns 0 on success, -1 on failure (error is printed on console). */
static int read_certificates(const struct shell *sh, struct certificates* certs,
                             enum application_role* role)
{
        (void) role;
        
        if (certs->certificate_path != NULL)
        {
                shell_warn(sh, "--cert not support in Zephyr at the moment, ignoring...");
        }
        if (certs->private_key_path != NULL)
        {
                shell_warn(sh, "--key not support in Zephyr at the moment, ignoring...");
        }
        if (certs->intermediate_path != NULL)
        {
                shell_warn(sh, "--intermediate not support in Zephyr at the moment, ignoring...");
        }
        if (certs->root_path != NULL)
        {
                shell_warn(sh, "--root not support in Zephyr at the moment, ignoring...");
        }

        if (certs->identity == NULL)
        {
                shell_error(sh, "no identity specified");
                return -1;
        }
        else if (strcmp(certs->identity, "ecc2") == 0)
        {
                certs->chain_buffer = (uint8_t*) ecc2_server_cert_chain;
                certs->chain_buffer_size = sizeof(ecc2_server_cert_chain);

                certs->key_buffer = (uint8_t*) ecc2_server_privateKey;
                certs->key_buffer_size = sizeof(ecc2_server_privateKey);

                certs->root_buffer = (uint8_t*) ecc2_root_cert;
                certs->root_buffer_size = sizeof(ecc2_root_cert);
        }
        else if (strcmp(certs->identity, "ecc3") == 0)
        {
                certs->chain_buffer = (uint8_t*) ecc3_server_cert_chain;
                certs->chain_buffer_size = sizeof(ecc3_server_cert_chain);

                certs->key_buffer = (uint8_t*) ecc3_server_privateKey;
                certs->key_buffer_size = sizeof(ecc3_server_privateKey);

                certs->root_buffer = (uint8_t*) ecc3_root_cert;
                certs->root_buffer_size = sizeof(ecc3_root_cert);
        }
        else if (strcmp(certs->identity, "dil2") == 0)
        {
                certs->chain_buffer = (uint8_t*) dil2_server_cert_chain;
                certs->chain_buffer_size = sizeof(dil2_server_cert_chain);

                certs->key_buffer = (uint8_t*) dil2_server_privateKey;
                certs->key_buffer_size = sizeof(dil2_server_privateKey);

                certs->root_buffer = (uint8_t*) dil2_root_cert;
                certs->root_buffer_size = sizeof(dil2_root_cert);
        }
        else if (strcmp(certs->identity, "dil3") == 0)
        {
                certs->chain_buffer = (uint8_t*) dil3_server_cert_chain;
                certs->chain_buffer_size = sizeof(dil3_server_cert_chain);

                certs->key_buffer = (uint8_t*) dil3_server_privateKey;
                certs->key_buffer_size = sizeof(dil3_server_privateKey);

                certs->root_buffer = (uint8_t*) dil3_root_cert;
                certs->root_buffer_size = sizeof(dil3_root_cert);
        }
        else if (strcmp(certs->identity, "hybrid_classic") == 0)
        {
                certs->chain_buffer = (uint8_t*) hybrid_classic_server_cert_chain;
                certs->chain_buffer_size = sizeof(hybrid_classic_server_cert_chain);

                certs->key_buffer = (uint8_t*) hybrid_classic_server_privateKey;
                certs->key_buffer_size = sizeof(hybrid_classic_server_privateKey);

                certs->additional_key_buffer = (uint8_t*) hybrid_classic_server_altPrivateKey;
                certs->additional_key_buffer_size = sizeof(hybrid_classic_server_altPrivateKey);

                certs->root_buffer = (uint8_t*) hybrid_classic_root_cert;
                certs->root_buffer_size = sizeof(hybrid_classic_root_cert);
        }
        else if (strcmp(certs->identity, "hybrid_pqc") == 0)
        {
                certs->chain_buffer = (uint8_t*) hybrid_pqc_server_cert_chain;
                certs->chain_buffer_size = sizeof(hybrid_pqc_server_cert_chain);

                certs->key_buffer = (uint8_t*) hybrid_pqc_server_privateKey;
                certs->key_buffer_size = sizeof(hybrid_pqc_server_privateKey);

                certs->additional_key_buffer = (uint8_t*) hybrid_pqc_server_altPrivateKey;
                certs->additional_key_buffer_size = sizeof(hybrid_pqc_server_altPrivateKey);

                certs->root_buffer = (uint8_t*) hybrid_pqc_root_cert;
                certs->root_buffer_size = sizeof(hybrid_pqc_root_cert);
        }
        else 
        {
                shell_error(sh, "no valid identity specified");
                shell_error(sh, "valid options are: ecc2, ecc3, dil2, dil3, hybrid_classic and hybrid_pqc");
                return -1;
        }

        return 0;
}

#else /* __ZEPHYR__ */

static const size_t certificate_chain_buffer_size = 32 * 1024;
static const size_t private_key_buffer_size = 16 * 1024;
static const size_t root_certificate_buffer_size = 16 * 1024;


static int readFile(const char* filePath, uint8_t* buffer, size_t bufferSize)
{
    /* Open the file */
    FILE* file = fopen(filePath, "r");
    
    if (file == NULL)
    {
        LOG_ERR("file (%s) cannot be opened", filePath);
        return -1;
    }
    
    /* Get length of file */
    fseek(file, 0, SEEK_END);
    int fileSize = ftell(file);
    rewind(file);

    if (fileSize > bufferSize)
    {
        LOG_ERR("file (%s) is too large for internal buffer", filePath);
        fclose(file);
        return -1;
    }
    
    /* Read file to buffer */
    int bytesRead = 0;
    while (bytesRead < fileSize)
    {
        int read = fread(buffer + bytesRead, sizeof(uint8_t), fileSize - bytesRead, file);
        if (read < 0)
        {
            LOG_ERR("unable to read file (%s)", filePath);
            fclose(file);
            return -1;
        }
        bytesRead += read;
    }
    
    fclose(file);

    return bytesRead;
}


/* Read all certificate and key files from the paths provided in the `certs` 
 * structure and store the data in the buffers. Memory is allocated internally
 * and must be freed by the user. 
 * 
 * Returns 0 on success, -1 on failure (error is printed on console). */
static int read_certificates(const struct shell *sh, struct certificates* certs,
                             enum application_role* role)
{
        /* Read certificate chain */
        if (certs->certificate_path != NULL)
        {
                certs->chain_buffer = (uint8_t*) malloc(certificate_chain_buffer_size);
                if (certs->chain_buffer == NULL)
                {
                        LOG_ERR("unable to allocate memory for certificate chain");
                        goto error;
                }

                int cert_size = readFile(certs->certificate_path,
                                         certs->chain_buffer,
                                         certificate_chain_buffer_size);
                if (cert_size < 0)
                {
                        LOG_ERR("unable to read certificate from file %s", certs->certificate_path);
                        goto error;
                }

                certs->chain_buffer_size = cert_size;

                if (certs->intermediate_path != NULL)
                {
                        int inter_size = readFile(certs->intermediate_path,
                                                  certs->chain_buffer + cert_size,
                                                  certificate_chain_buffer_size - cert_size);
                        if (inter_size < 0)
                        {
                                LOG_ERR("unable to read intermediate certificate from file %s", certs->intermediate_path);
                                goto error;
                        }

                        certs->chain_buffer_size += inter_size;
                }
        }
        else if ((*role == ROLE_REVERSE_PROXY) || (*role == ROLE_ECHO_SERVER))
        {
                LOG_ERR("no certificate file specified");
                goto error;
        }

        /* Read private key */
        if (certs->private_key_path != 0)
        {
                certs->key_buffer = (uint8_t*) malloc(private_key_buffer_size);
                if (certs->key_buffer == NULL)
                {
                        LOG_ERR("unable to allocate memory for private key");
                        goto error;
                }

                int key_size = readFile(certs->private_key_path,
                                        certs->key_buffer,
                                        private_key_buffer_size);
                if (key_size < 0)
                {
                        LOG_ERR("unable to read private key from file %s", certs->private_key_path);
                        goto error;
                }

                certs->key_buffer_size = key_size;
        }
        else if ((*role == ROLE_REVERSE_PROXY) || (*role == ROLE_ECHO_SERVER))
        {
                LOG_ERR("no private key file specified");
                goto error;
        }

        /* Read addtional private key */
        if (certs->additional_key_path != 0)
        {
                certs->additional_key_buffer = (uint8_t*) malloc(private_key_buffer_size);
                if (certs->additional_key_buffer == NULL)
                {
                        LOG_ERR("unable to allocate memory for additional private key");
                        goto error;
                }

                int key_size = readFile(certs->additional_key_path,
                                        certs->additional_key_buffer,
                                        private_key_buffer_size);
                if (key_size < 0)
                {
                        LOG_ERR("unable to read private key from file %s", certs->private_key_path);
                        goto error;
                }

                certs->additional_key_buffer_size = key_size;
        }

        /* Read root certificate */
        if (certs->root_path != 0)
        {
                certs->root_buffer = (uint8_t*) malloc(root_certificate_buffer_size);
                if (certs->root_buffer == NULL)
                {
                        LOG_ERR("unable to allocate memory for root certificate");
                        goto error;
                }

                int root_size = readFile(certs->root_path,
                                        certs->root_buffer,
                                        root_certificate_buffer_size);
                if (root_size < 0)
                {
                        LOG_ERR("unable to read root certificate from file %s", certs->root_path);
                        goto error;
                }

                certs->root_buffer_size = root_size;
        }
        else
        {
                LOG_ERR("no root certificate file specified");
                goto error;
        }

        return 0;

error:
        free(certs->chain_buffer);
        free(certs->key_buffer);
        free(certs->additional_key_buffer);
        free(certs->root_buffer);

        return -1;
}

#endif // __ZEPHYR__
