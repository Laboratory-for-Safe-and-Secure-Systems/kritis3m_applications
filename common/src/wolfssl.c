
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>

#include "logging.h"
#include "networking.h"

#include "secure_element/wolfssl_pkcs11_pqc.h"

#include "wolfssl.h"

#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/memory.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/wc_pkcs11.h"
#include "wolfssl/error-ssl.h"


LOG_MODULE_REGISTER(wolfssl);


#ifdef WOLFSSL_STATIC_MEMORY
static WOLFSSL_HEAP_HINT* wolfssl_heap;
extern uint8_t* wolfsslMemoryBuffer;
extern size_t wolfsslMemoryBufferSize;
#else
#define wolfssl_heap NULL
#endif


enum connection_state
{
	CONNECTION_STATE_NOT_CONNECTED,
	CONNECTION_STATE_HANDSHAKE,
	CONNECTION_STATE_CONNECTED,
};


/* Data structure for an endpoint */
struct wolfssl_endpoint
{
        WOLFSSL_CTX* context;

#if defined(HAVE_SECRET_CALLBACK)
        char const* keylog_file;
#endif
};


/* Data structure for an active session */
struct wolfssl_session
{
        WOLFSSL* session;
	enum connection_state state;

        struct
	{
		struct timespec start_time;
		struct timespec end_time;
		uint32_t txBytes;
		uint32_t rxBytes;
	}
	handshake_metrics_priv;
};


/* PKCS#11 module for the secure element */
static pkcs11_module secure_element;


/* Internal method declarations */
static int errorOccured(int32_t ret);
static int wolfssl_read_callback(WOLFSSL* session, char* buffer, int size, void* ctx);
static int wolfssl_write_callback(WOLFSSL* session, char* buffer, int size, void* ctx);
static void wolfssl_logging_callback(int level, const char* str);
static int wolfssl_configure_context(WOLFSSL_CTX* context,
		wolfssl_endpoint_configuration const* config);


/* Check return value for an error. Print error message in case. */
static int errorOccured(int32_t ret)
{
	if (ret != WOLFSSL_SUCCESS)
	{
		char errMsg[WOLFSSL_MAX_ERROR_SZ];
		wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));
		LOG_ERR("error: %s", errMsg);

		return -1;
	}

	return 0;
}

static int wolfssl_read_callback(WOLFSSL* wolfssl, char* buffer, int size, void* ctx)
{
	int socket = wolfSSL_get_fd(wolfssl);
	wolfssl_session* session = (wolfssl_session*) ctx;

	int ret = recv(socket, buffer, size, 0);

	if (ret == 0)
	{
		// LOG_WRN("connection closed by peer");
		return WOLFSSL_CBIO_ERR_CONN_CLOSE;
	}
	else if (ret < 0)
	{
		int error = errno;
		// LOG_WRN("recv error: %d", error);
		if ((error == EAGAIN) || (error == EWOULDBLOCK))
			return WOLFSSL_CBIO_ERR_WANT_READ;
		else
			return WOLFSSL_CBIO_ERR_GENERAL;
	}

	/* Update handshake metrics */
	if (session != NULL && session->state == CONNECTION_STATE_HANDSHAKE)
	{
		session->handshake_metrics_priv.rxBytes += ret;
	}

	return ret;
}

static int wolfssl_write_callback(WOLFSSL* wolfssl, char* buffer, int size, void* ctx)
{
	int socket = wolfSSL_get_fd(wolfssl);
	wolfssl_session* session = (wolfssl_session*) ctx;

	int ret = send(socket, buffer, size, 0);

	if (ret < 0)
	{
		int error = errno;
		// LOG_WRN("send error: %d", error);
		if ((error == EAGAIN) || (error == EWOULDBLOCK))
			return WOLFSSL_CBIO_ERR_WANT_WRITE;
		else if (error == ECONNRESET)
			return WOLFSSL_CBIO_ERR_CONN_RST;
		else
			return WOLFSSL_CBIO_ERR_GENERAL;
	}

	/* Update handshake metrics */
	if (session != NULL && session->state == CONNECTION_STATE_HANDSHAKE)
	{
		session->handshake_metrics_priv.txBytes += ret;
	}

	return ret;
}

static void wolfssl_logging_callback(int level, const char* str)
{
	(void) level;

	LOG_INF("%s", str);
}

#if defined(HAVE_SECRET_CALLBACK)
/* Callback function for TLS v1.3 secrets for use with Wireshark */
static int wolfssl_secret_callback(WOLFSSL* ssl, int id, const uint8_t* secret,
    				   int secretSz, void* ctx)
{
	int i;
	const char* str = NULL;
	unsigned char serverRandom[32];
	int serverRandomSz;
	FILE* fp = stderr;
	if (ctx)
	{
		fp = fopen((const char*)ctx, "a");
		if (fp == NULL)
		{
			return BAD_FUNC_ARG;
		}
	}

	serverRandomSz = (int)wolfSSL_get_client_random(ssl, serverRandom,
							sizeof(serverRandom));

	if (serverRandomSz <= 0)
	{
		LOG_ERR("Error getting server random: %d\n", serverRandomSz);
	}

	switch (id)
	{
		case CLIENT_EARLY_TRAFFIC_SECRET:
			str = "CLIENT_EARLY_TRAFFIC_SECRET";
			break;
		case EARLY_EXPORTER_SECRET:
			str = "EARLY_EXPORTER_SECRET";
			break;
		case CLIENT_HANDSHAKE_TRAFFIC_SECRET:
			str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
			break;
		case SERVER_HANDSHAKE_TRAFFIC_SECRET:
			str = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
			break;
		case CLIENT_TRAFFIC_SECRET:
			str = "CLIENT_TRAFFIC_SECRET_0";
			break;
		case SERVER_TRAFFIC_SECRET:
			str = "SERVER_TRAFFIC_SECRET_0";
			break;
		case EXPORTER_SECRET:
			str = "EXPORTER_SECRET";
			break;
		default:
			str = "UNKNOWN";
			break;
	}

	fprintf(fp, "%s ", str);
	for (i = 0; i < (int)serverRandomSz; i++)
	{
		fprintf(fp, "%02x", serverRandom[i]);
	}
	fprintf(fp, " ");
	for (i = 0; i < secretSz; i++)
	{
		fprintf(fp, "%02x", secret[i]);
	}
	fprintf(fp, "\n");

	if (fp != stderr)
	{
		fclose(fp);
	}

	return 0;
}
#endif /* HAVE_SECRET_CALLBACK */


/* Initialize WolfSSL library.
 *
 * Parameter is a pointer to a filled library_configuration structure.
 *
 * Returns 0 on success, -1 in case of an error (error message is logged to the console).
 */
int wolfssl_init(struct wolfssl_library_configuration const* config)
{
        /* Initialize WolfSSL */
	int ret = wolfSSL_Init();
	if (errorOccured(ret))
		return -1;

#ifdef WOLFSSL_STATIC_MEMORY
	/* Load static memory to avoid malloc */
	if ((config->staticMemoryBuffer.buffer != NULL) && (config->staticMemoryBuffer.size > 0))
	{
		if (wc_LoadStaticMemory(&wolfssl_heap, config->staticMemoryBuffer.buffer,
					config->staticMemoryBuffer.size, WOLFMEM_GENERAL, 1) != 0)
		{
			LOG_ERR("unable to load static memory");
			return -1;
		}
	}
#endif

	/* Configure the logging interface */
	LOG_LEVEL_SET(config->logLevel);
	if (config->loggingEnabled)
	{
		wolfSSL_SetLoggingCb(wolfssl_logging_callback);
    		ret = wolfSSL_Debugging_ON();
		if (ret != 0)
		{
			LOG_WRN("Debug output is not compiled in, please compile with DEBUG_WOLFSSL preprocessor makro defined");
		}
	}

	/* Load the secure element middleware */
	if ((config->secure_element_support == true) && (config->secure_element_middleware_path != NULL))
	{
	#ifdef HAVE_PKCS11
		LOG_INF("Initializing secure element");

		/* Initialize the PKCS#11 library */
		ret = wc_Pkcs11_Initialize(&secure_element.device,
					   config->secure_element_middleware_path, wolfssl_heap);
		if (ret != 0)
		{
			LOG_ERR("unable to initialize PKCS#11 library: %d", ret);
			return -1;
		}

		/* Initialize the token */
		ret = wc_Pkcs11Token_Init_NoLogin(&secure_element.token,
					  	  &secure_element.device,
					  	  -1, NULL);
		if (ret != 0)
		{
			LOG_ERR("unable to initialize PKCS#11 token: %d", ret);
			wc_Pkcs11_Finalize(&secure_element.device);
			return -1;
		}

		/* Register the device with WolfSSL */
		ret = wc_CryptoCb_RegisterDevice(secure_element_device_id(),
						 wc_Pkcs11_CryptoDevCb,
						 &secure_element.token);
		if (ret != 0)
		{
			LOG_ERR("Failed to register PKCS#11 callback: %d", ret);
			wc_Pkcs11Token_Final(&secure_element.token);
			wc_Pkcs11_Finalize(&secure_element.device);
			return -1;
		}

		/* Create a persistent session with the secure element */
		ret = wc_Pkcs11Token_Open(&secure_element.token, 1);
		if (ret == 0)
		{
			secure_element.initialized = true;
			LOG_INF("Secure element initialized");
		}
		else
		{
			secure_element.initialized = false;
			wc_Pkcs11Token_Final(&secure_element.token);
			wc_Pkcs11_Finalize(&secure_element.device);
			LOG_ERR("Secure element initialization failed: %d", ret);
		}
	#else
		LOG_ERR("Secure element support is not compiled in, please compile with HAVE_PKCS11 preprocessor makro defined");
	#endif
	}
	else
	{
		secure_element.initialized = false;
	}

        return 0;
}


/* Configure the new context.
 *
 * Returns 0 on success, -1 on failure (error message is logged to the console).
 */
static int wolfssl_configure_context(WOLFSSL_CTX* context, struct wolfssl_endpoint_configuration const* config)
{
        /* Only allow TLS version 1.3 */
	int ret = wolfSSL_CTX_SetMinVersion(context, WOLFSSL_TLSV1_3);
	if (errorOccured(ret))
		return -1;

	/* Load root certificate */
	ret = wolfSSL_CTX_load_verify_buffer(context,
					     config->root_certificate.buffer,
					     config->root_certificate.size,
					     WOLFSSL_FILETYPE_PEM);
	if (errorOccured(ret))
		return -1;

	/* Load device certificate chain */
	if (config->device_certificate_chain.buffer != NULL)
	{
		ret = wolfSSL_CTX_use_certificate_chain_buffer_format(context,
								config->device_certificate_chain.buffer,
								config->device_certificate_chain.size,
								WOLFSSL_FILETYPE_PEM);
		if (errorOccured(ret))
			return -1;
	}

	/* Load the private key */
	bool privateKeyLoaded = false;
	if (secure_element.initialized == true && config->use_secure_element == true)
	{
		// wolfSSL_CTX_SetDevId(context, secure_element_device_id());

		/* Import private key into secure element if requested */
		if (config->secure_element_import_keys)
		{
			if (config->private_key.buffer != NULL)
			{
				ret = pkcs11_import_pem_key(&secure_element,
							    config->private_key.buffer,
							    config->private_key.size,
							    secure_element_private_key_id(),
							    secure_element_private_key_id_size());
				if (ret != 0)
				{
					LOG_ERR("Failed to import private key into secure element");
					return -1;
				}
			}
			else
			{
				LOG_ERR("No private key buffer provided for import into secure element");
				return -1;
			}

			if (config->private_key.additional_key_buffer != NULL)
			{
				ret = pkcs11_import_pem_key(&secure_element,
							    config->private_key.additional_key_buffer,
							    config->private_key.additional_key_size,
							    secure_element_private_key_id(),
							    secure_element_private_key_id_size());
				if (ret != 0)
				{
					LOG_ERR("Failed to import additional private key into secure element");
					return -1;
				}
			}
		}

		/* Use keys on the secure element (this also loads the id for the alt key) */
		ret = wolfSSL_CTX_use_PrivateKey_Id(context,
						    secure_element_private_key_id(),
						    secure_element_private_key_id_size(),
						    secure_element_device_id());

		privateKeyLoaded = true;
	}
	else if (config->private_key.buffer != NULL)
	{
		/* Load the private key from the buffer */
		ret = wolfSSL_CTX_use_PrivateKey_buffer(context,
							config->private_key.buffer,
							config->private_key.size,
							WOLFSSL_FILETYPE_PEM);

		/* Load the additional private key from the buffer */
		if (config->private_key.additional_key_buffer != NULL)
		{
			if (errorOccured(ret))
				return -1;

			ret = wolfSSL_CTX_use_AltPrivateKey_buffer(context,
					config->private_key.additional_key_buffer,
					config->private_key.additional_key_size,
					WOLFSSL_FILETYPE_PEM);
		}

		privateKeyLoaded = true;
	}

	if (errorOccured(ret))
		return -1;


	/* Check if the private key and the device certificate match */
	if (privateKeyLoaded == true)
	{
		ret = wolfSSL_CTX_check_private_key(context);
		if (errorOccured(ret))
			return -1;
	}

	/* Configure the available curves for Key Exchange */
	int wolfssl_key_exchange_curves[] = {
		WOLFSSL_ECC_SECP384R1,
		// WOLFSSL_KYBER_LEVEL1,
        	WOLFSSL_KYBER_LEVEL3,
        	WOLFSSL_KYBER_LEVEL5,
        	// WOLFSSL_P256_KYBER_LEVEL1,
        	WOLFSSL_P384_KYBER_LEVEL3,
        	WOLFSSL_P521_KYBER_LEVEL5,
	};
	ret = wolfSSL_CTX_set_groups(context, wolfssl_key_exchange_curves,
				     sizeof(wolfssl_key_exchange_curves) / sizeof(int));
	if (errorOccured(ret))
		return -1;

	/* Set the IO callbacks for send and receive */
	wolfSSL_CTX_SetIORecv(context, wolfssl_read_callback);
	wolfSSL_CTX_SetIOSend(context, wolfssl_write_callback);

	/* Configure peer authentification */
	int verify_mode = WOLFSSL_VERIFY_NONE;
	if (config->mutual_authentication == true)
	{
		verify_mode = WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	}
	wolfSSL_CTX_set_verify(context, verify_mode, NULL);

	return 0;
}


/* Setup a TLS server endpoint.
 *
 * Parameter is a pointer to a filled endpoint_configuration structure.
 *
 * Return value is a pointer to the newly created endpoint or NULL in case of an error
 * (error message is logged to the console).
 */
wolfssl_endpoint* wolfssl_setup_server_endpoint(wolfssl_endpoint_configuration const* config)
{
	if (config == NULL)
	{
		LOG_ERR("Configuration is NULL");
		return NULL;
	}

	/* Create a new endpoint object */
	wolfssl_endpoint* new_endpoint = malloc(sizeof(wolfssl_endpoint));
	if (new_endpoint == NULL)
	{
		LOG_ERR("Unable to allocate memory for new WolfSSL endpoint");
		return NULL;
	}

        /* Create the TLS server context */
	new_endpoint->context = wolfSSL_CTX_new_ex(wolfTLS_server_method_ex(wolfssl_heap), wolfssl_heap);
	if (new_endpoint->context == NULL)
	{
		LOG_ERR("Unable to create a new WolfSSL server context");
		free(new_endpoint);
		return NULL;
	}

	/* Configure the new context */
        int ret = wolfssl_configure_context(new_endpoint->context, config);
        if (ret == -1)
        {
                LOG_ERR("Failed to configure new TLS server context\r\n");
                wolfSSL_CTX_free(new_endpoint->context);
		free(new_endpoint);
	        return NULL;
        }

	/* Configure the available cipher suites for TLS 1.3
	 * We only support AES GCM with 256 bit key length and the
	 * integrity only cipher with SHA384.
	 */
	ret = wolfSSL_CTX_set_cipher_list(new_endpoint->context,
				"TLS13-AES256-GCM-SHA384:TLS13-SHA384-SHA384");
	if (errorOccured(ret))
	{
                LOG_ERR("Failed to set ciphersuites\r\n");
                wolfSSL_CTX_free(new_endpoint->context);
		free(new_endpoint);
	        return NULL;
        }

	/* Set the preference for verfication of hybrid signatures to be for both the
	 * native and alternative chains.
	 */
        static uint8_t cks_order[] = {
            WOLFSSL_CKS_SIGSPEC_BOTH,
            WOLFSSL_CKS_SIGSPEC_NATIVE,
	    WOLFSSL_CKS_SIGSPEC_ALTERNATIVE
        };

        ret = wolfSSL_CTX_UseCKS(new_endpoint->context, cks_order, sizeof(cks_order));
	if (errorOccured(ret))
	{
                LOG_ERR("Failed to set hybrid signature CKS\r\n");
                wolfSSL_CTX_free(new_endpoint->context);
		free(new_endpoint);
	        return NULL;
        }

#ifdef HAVE_SECRET_CALLBACK
	new_endpoint->keylog_file = config->keylog_file;
#endif

        return new_endpoint;
}


/* Setup a TLS client endpoint.
 *
 * Parameter is a pointer to a filled endpoint_configuration structure.
 *
 * Return value is a pointer to the newly created endpoint or NULL in case of an error
 * (error message is logged to the console).
 */
wolfssl_endpoint* wolfssl_setup_client_endpoint(wolfssl_endpoint_configuration const* config)
{
	if (config == NULL)
	{
		LOG_ERR("Configuration is NULL");
		return NULL;
	}

	/* Create a new endpoint object */
	wolfssl_endpoint* new_endpoint = malloc(sizeof(wolfssl_endpoint));
	if (new_endpoint == NULL)
	{
		LOG_ERR("Unable to allocate memory for new WolfSSL endpoint");
		return NULL;
	}

        /* Create the TLS client context */
	new_endpoint->context = wolfSSL_CTX_new_ex(wolfTLS_client_method_ex(wolfssl_heap), wolfssl_heap);
	if (new_endpoint->context == NULL)
	{
		LOG_ERR("Unable to create a new WolfSSL client context");
		free(new_endpoint);
		return NULL;
	}

	/* Configure the new context */
        int ret = wolfssl_configure_context(new_endpoint->context, config);
        if (ret == -1)
        {
                LOG_ERR("Failed to confiugre new TLS client context\r\n");
                wolfSSL_CTX_free(new_endpoint->context);
		free(new_endpoint);
	        return NULL;
        }

	/* Configure the available cipher suites for TLS 1.3
	 * We only support AES GCM with 256 bit key length and the
	 * integrity only cipher with SHA384.
	 */
	char const* cipher_list = "TLS13-AES256-GCM-SHA384";
	if (config->no_encryption)
	{
		cipher_list = "TLS13-SHA384-SHA384";
	}
	ret = wolfSSL_CTX_set_cipher_list(new_endpoint->context, cipher_list);
	if (errorOccured(ret))
	{
                LOG_ERR("Failed to set ciphersuites\r\n");
                wolfSSL_CTX_free(new_endpoint->context);
		free(new_endpoint);
	        return NULL;
        }

	/* Set the preference for verfication of hybrid signatures to the user defined.
	 */
        static uint8_t cks[] = {WOLFSSL_CKS_SIGSPEC_BOTH};
	switch (config->hybrid_signature_mode)
	{
		case HYBRID_SIGNATURE_MODE_NATIVE:
			cks[0] = WOLFSSL_CKS_SIGSPEC_NATIVE;
			break;
		case HYBRID_SIGNATURE_MODE_ALTERNATIVE:
			cks[0] = WOLFSSL_CKS_SIGSPEC_ALTERNATIVE;
			break;
		case HYBRID_SIGNATURE_MODE_BOTH:
		default:
			cks[0] = WOLFSSL_CKS_SIGSPEC_BOTH;
			break;
        };
        ret = wolfSSL_CTX_UseCKS(new_endpoint->context, cks, sizeof(cks));
	if (errorOccured(ret))
	{
                LOG_ERR("Failed to set hybrid signature CKS\r\n");
                wolfSSL_CTX_free(new_endpoint->context);
		free(new_endpoint);
	        return NULL;
        }

#ifdef HAVE_SECRET_CALLBACK
	new_endpoint->keylog_file = config->keylog_file;
#endif

        return new_endpoint;
}


/* Create a new session for the endpoint.
 *
 * Parameters are a pointer to a configured endpoint and the socket fd of the underlying
 * network connection.
 *
 * Return value is a pointer to the newly created session or NULL in case of an error
 * (error message is logged to the console).
 */
wolfssl_session* wolfssl_create_session(wolfssl_endpoint* endpoint, int socket_fd)
{
	if (endpoint == NULL)
	{
		LOG_ERR("Endpoint is NULL");
		return NULL;
	}

	/* Create a new session object */
	wolfssl_session* new_session = malloc(sizeof(wolfssl_session));
	if (new_session == NULL)
	{
		LOG_ERR("Unable to allocate memory for new WolfSSL session");
		return NULL;
	}

	/* Create a new TLS session */
	new_session->session = wolfSSL_new(endpoint->context);
	if (new_session->session == NULL)
	{
		LOG_ERR("Unable to create a new WolfSSL session");
		free(new_session);
		return NULL;
	}

	/* Initialize the remaining attributes */
	new_session->state = CONNECTION_STATE_NOT_CONNECTED;
	new_session->handshake_metrics_priv.txBytes = 0;
	new_session->handshake_metrics_priv.rxBytes = 0;

	/* Store the socket fd */
	wolfSSL_set_fd(new_session->session, socket_fd);

	/* Store a pointer to our session object to get access to the metrics from
	 * the read and write callback. This must be done AFTER the call to
	 * wolfSSL_set_fd() as this method overwrites the ctx variables.
	 */
	wolfSSL_SetIOReadCtx(new_session->session, new_session);
	wolfSSL_SetIOWriteCtx(new_session->session, new_session);

#ifdef HAVE_SECRET_CALLBACK
	if (endpoint->keylog_file != NULL)
	{
		/* required for getting random used */
		wolfSSL_KeepArrays(new_session->session);

		/* optional logging for wireshark */
		wolfSSL_set_tls13_secret_cb(new_session->session,
					    wolfssl_secret_callback,
					    (void*)endpoint->keylog_file);
	}
#endif

	return new_session;
}


/* Perform the TLS handshake for a newly created session.
 *
 * Returns 0 on success, -1 on failure (error message is logged to the console) and a positive
 * integer in case the handshake is not done yet (and you have to call the method again when new
 * data from the peer is present). The return code is then either WOLFSSL_ERROR_WANT_READ or
 * WOLFSSL_ERROR_WANT_WRITE.
 */
int wolfssl_handshake(wolfssl_session* session)
{
        int ret = -1;

	if (session == NULL)
	{
		LOG_ERR("Session is NULL");
		return -1;
	}

	/* Obtain handshake metrics */
	if (session->state == CONNECTION_STATE_NOT_CONNECTED)
	{
		session->state = CONNECTION_STATE_HANDSHAKE;

		/* Get start time */
		if (clock_gettime(CLOCK_MONOTONIC,
				  &session->handshake_metrics_priv.start_time) != 0)
		{
			LOG_ERR("Error starting handshake timer");
			session->state = CONNECTION_STATE_NOT_CONNECTED;
			return -1;
		}
	}

	while (ret != 0)
	{
		ret = wolfSSL_negotiate(session->session);

		if (ret == WOLFSSL_SUCCESS)
		{
			session->state = CONNECTION_STATE_CONNECTED;

			/* Get end time */
			if (clock_gettime(CLOCK_MONOTONIC,
					&session->handshake_metrics_priv.end_time) != 0)
			{
				// Handle error
				LOG_ERR("Error stopping handshake timer");
				return -1;
			}

		#ifdef HAVE_SECRET_CALLBACK
        		wolfSSL_FreeArrays(session->session);
    		#endif

			ret = 0;
			break;
		}
		else
		{
			ret = wolfSSL_get_error(session->session, ret);

			if ((ret == WOLFSSL_ERROR_WANT_READ) || (ret == WOLFSSL_ERROR_WANT_WRITE))
			{
				break;
			}
			else
			{
				char errMsg[WOLFSSL_MAX_ERROR_SZ];
				wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));

				LOG_ERR("TLS handshake failed: %s", errMsg);
				ret = -1;
				break;
			}
		}
	}

	return ret;
}


/* Receive new data from the TLS peer.
 *
 * Returns the number of received bytes on success, -1 on failure (error message is logged
 * to the console).
 */
int wolfssl_receive(wolfssl_session* session, uint8_t* buffer, int max_size)
{
	uint8_t* tmp = buffer;
	int bytes_read = 0;

	if (session == NULL)
	{
		LOG_ERR("Session is NULL");
		return -1;
	}

	while (1)
	{
		int ret = wolfSSL_read(session->session, tmp, max_size - bytes_read);

		if (ret <= 0)
		{
			ret = wolfSSL_get_error(session->session, ret);

			if (ret == WOLFSSL_ERROR_WANT_WRITE)
			{
				/* Call wolfSSL_read() again */
				continue;
			}
			else if (ret == WOLFSSL_ERROR_WANT_READ)
			{
				/* No more data, we have to asynchronously wait for new */
				break;
			}
			else if ((ret == WOLFSSL_ERROR_ZERO_RETURN) || (ret == WOLFSSL_ERROR_SYSCALL))
			{
				bytes_read = -1;
				break;
			}
			else
			{
				char errMsg[WOLFSSL_MAX_ERROR_SZ];
				wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));

				LOG_ERR("wolfSSL_read returned %d: %s", ret, errMsg);
				bytes_read = -1;
				break;
			}
		}

		tmp += ret;
		bytes_read += ret;

		break;
	}

	return bytes_read;
}


/* Send data to the TLS remote peer.
 *
 * Returns 0 on success, -1 on failure (error message is logged to the console). In case
 * we cannot write the data in one call, WOLFSSL_ERROR_WANT_WRITE is returned, indicating
 * that you have to call the method again (with the same data!) once the socket is writable.
 */
int wolfssl_send(wolfssl_session* session, uint8_t const* buffer, int size)
{
        uint8_t const* tmp = buffer;
	int ret = 0;

	if (session == NULL)
	{
		LOG_ERR("Session is NULL");
		return -1;
	}

	while (size > 0)
	{
		ret = wolfSSL_write(session->session, tmp, size);

		if (ret > 0)
		{
			/* We successfully sent data */
			size -= ret;
			tmp += ret;
			ret = 0;
		}
		else
		{
			ret = wolfSSL_get_error(session->session, ret);

            		if (ret == WOLFSSL_ERROR_WANT_READ)
			{
				/* We have to first receive data from the peer. In this case,
				 * we discard the data and continue reading data from it. */
				ret = 0;
				break;
			}
			else if (ret == WOLFSSL_ERROR_WANT_WRITE)
			{
				/* We have more to write. */
				break;
			}
			else if (ret == WOLFSSL_ERROR_SYSCALL)
			{
				ret = -1;
				break;
			}
			else
			{
				if (ret != 0)
				{
					char errMsg[WOLFSSL_MAX_ERROR_SZ];
					wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));

					LOG_ERR("wolfSSL_write returned %d: %s", ret, errMsg);
				}
				ret = -1;

				break;
			}
		}

	}

	return ret;
}

/* Get metics of the handshake. */
tls_handshake_metrics wolfssl_get_handshake_metrics(wolfssl_session* session)
{
	tls_handshake_metrics metrics;

	metrics.duration_us = (session->handshake_metrics_priv.end_time.tv_sec - session->handshake_metrics_priv.start_time.tv_sec) * 1000000.0 +
			      (session->handshake_metrics_priv.end_time.tv_nsec - session->handshake_metrics_priv.start_time.tv_nsec) / 1000.0;
	metrics.txBytes = session->handshake_metrics_priv.txBytes;
	metrics.rxBytes = session->handshake_metrics_priv.rxBytes;

	return metrics;
}


/* Close the connection of the active session */
void wolfssl_close_session(wolfssl_session* session)
{
	if (session != NULL)
	{
		wolfSSL_shutdown(session->session);
		session->state = CONNECTION_STATE_NOT_CONNECTED;
	}
}


/* Free ressources of a session. */
void wolfssl_free_session(wolfssl_session* session)
{
	if (session != NULL)
	{
		if (session->session != NULL)
		{
			wolfSSL_free(session->session);
		}

		free(session);
	}
}


/* Free ressources of an endpoint. */
void wolfssl_free_endpoint(wolfssl_endpoint* endpoint)
{
	if (endpoint != NULL)
	{
		if (endpoint->context != NULL)
		{
			wolfSSL_CTX_free(endpoint->context);
		}

		free(endpoint);
	}
}
