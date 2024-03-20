
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
#include "logging.h"
#include "networking.h"

#include "secure_element/wolfssl_pkcs11_pqc.h"

#include "wolfssl.h"

#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/memory.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/wc_pkcs11.h"
#include "wolfssl/error-ssl.h"
#include "wolfssl/certs_test.h"

LOG_MODULE_REGISTER(wolfssl);

#ifdef WOLFSSL_STATIC_MEMORY
static WOLFSSL_HEAP_HINT *wolfssl_heap;
extern uint8_t *wolfsslMemoryBuffer;
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
	WOLFSSL_CTX *context;
};

/* Data structure for an active session */
struct wolfssl_session
{
	WOLFSSL *session;
	enum connection_state state;

	struct
	{
		struct timespec start_time;
		struct timespec end_time;
		uint32_t txBytes;
		uint32_t rxBytes;
	} handshake_metrics_priv;

	struct sockaddr_in cliAddr; /* server sockaddr */
	socklen_t cliSz;			/* length of servAddr */

	struct sockaddr_in servAddr; /* server sockaddr */
	socklen_t servSz;			 /* length of servAddr */
	byte* rxBuf;
	word32 rxSz;
};

/* PKCS#11 */
typedef struct pkcs11_secure_element
{
#ifdef HAVE_PKCS11
	Pkcs11Dev device;
	Pkcs11Token token;
#endif
	bool initialized;
} pkcs11_secure_element;

static pkcs11_secure_element pkcs11_secure_element_instance;

/* Internal method declarations */
static int errorOccured(int32_t ret);
static int wolfssl_read_callback(WOLFSSL *session, char *buffer, int size, void *ctx);
static int wolfssl_write_callback(WOLFSSL *session, char *buffer, int size, void *ctx);

static int wolfssl_read_client_dtls_callback(WOLFSSL *session, char *buffer, int size, void *ctx);
static int wolfssl_write_client_dtls_callback(WOLFSSL *session, char *buffer, int size, void *ctx);

static int wolfssl_read_dtls_callback(WOLFSSL *session, char *buffer, int size, void *ctx);
static int wolfssl_write_dtls_callback(WOLFSSL *session, char *buffer, int size, void *ctx);
static void wolfssl_logging_callback(int level, const char *str);
static int wolfssl_import_pem_key_into_secure_element(uint8_t const *pem_buffer,
													  uint32_t pem_size, uint8_t const *id, int len);
static int wolfssl_configure_context(WOLFSSL_CTX *context,
									 wolfssl_endpoint_configuration const *config);
static int wolfssl_configure_dtls_context(WOLFSSL_CTX *context,
										  wolfssl_endpoint_configuration const *config);

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

static int wolfssl_read_client_dtls_callback(WOLFSSL *wolfssl, char *buffer, int size, void *ctx)
{
	// wolfssl_session *session = (wolfssl_session *)ctx;
	int fd = wolfSSL_get_fd(wolfssl);
	int recvd;
	struct sockaddr addr;
	socklen_t addrSz = sizeof(addr);

	LOG_INF("my_IORecv fd %d, buf %d\n", fd, size);

	/* Receive datagram */
	recvd = recvfrom(fd, buffer, size, 0, &addr, &addrSz);
	if (recvd == -1)
	{
		/* error encountered. Be responsible and report it in wolfSSL terms */

		LOG_ERR("IO RECEIVE ERROR: %d\n", errno);
		switch (errno)
		{
#if EAGAIN != EWOULDBLOCK
		case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
#endif
		case EWOULDBLOCK:
			if (!wolfSSL_dtls(wolfssl) || wolfSSL_get_using_nonblock(wolfssl))
			{
				LOG_ERR("would block\n");
				return WOLFSSL_CBIO_ERR_WANT_READ;
			}
			else
			{
				LOG_ERR("socket timeout\n");
				return WOLFSSL_CBIO_ERR_TIMEOUT;
			}
		case ECONNRESET:
			LOG_ERR("connection reset\n");
			return WOLFSSL_CBIO_ERR_CONN_RST;
		case EINTR:
			LOG_ERR("socket interrupted\n");
			return WOLFSSL_CBIO_ERR_GENERAL;
			/* NOTE: Don't return WOLFSSL_CBIO_ERR_ISR. It keeps trying to recv */
		case ECONNREFUSED:
			LOG_ERR("connection refused\n");
			return WOLFSSL_CBIO_ERR_WANT_READ;
		case ECONNABORTED:
			LOG_ERR("connection aborted\n");
			return WOLFSSL_CBIO_ERR_CONN_CLOSE;
		default:
			LOG_ERR("general error\n");
			return WOLFSSL_CBIO_ERR_GENERAL;
		}
	}
	else if (recvd == 0)
	{
		LOG_INF("Connection closed\n");
		return WOLFSSL_CBIO_ERR_CONN_CLOSE;
	}

	/* successful receive */
	LOG_INF("my_IORecv: received %d bytes from %d\n", recvd, fd);
	return recvd;
}
static int wolfssl_write_client_dtls_callback(WOLFSSL *wolfssl, char *buffer, int size, void *ctx)
{
	wolfssl_session *session = (wolfssl_session *)ctx;
	int fd = wolfSSL_get_fd(wolfssl);
	int sent;
	const struct sockaddr *addr = NULL;
	socklen_t addrSz = 0;

	if (session)
	{
		addr = (const struct sockaddr *)&session->servAddr;
		addrSz = session->servSz;
	}

	LOG_INF("my_IOSend fd %d, buf %d\n", fd, size);

	/* Send datagram */
	sent = sendto(fd, buffer, size, 0, addr, addrSz);
	if (sent == -1)
	{
		/* error encountered. Be responsible and report it in wolfSSL terms */

		LOG_INF("IO SEND ERROR: %d\n", errno);
		switch (errno)
		{
#if EAGAIN != EWOULDBLOCK
		case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
#endif
		case EWOULDBLOCK:
			LOG_ERR("would block\n");
			return WOLFSSL_CBIO_ERR_WANT_READ;
		case ECONNRESET:
			LOG_ERR("connection reset\n");
			return WOLFSSL_CBIO_ERR_CONN_RST;
		case EINTR:
			LOG_ERR("socket interrupted\n");
			return WOLFSSL_CBIO_ERR_GENERAL;
			/* NOTE: Don't return WOLFSSL_CBIO_ERR_ISR. It keeps trying to send */
		case EPIPE:
			LOG_ERR("socket EPIPE\n");
			return WOLFSSL_CBIO_ERR_CONN_CLOSE;
		default:
			LOG_ERR("general error\n");
			return WOLFSSL_CBIO_ERR_GENERAL;
		}
	}
	else if (sent == 0)
	{
		LOG_INF("Connection closed\n");
		return 0;
	}

	/* successful send */
	LOG_INF("my_IOSend: sent %d bytes to %d\n", sent, fd);
	return sent;
}

static int wolfssl_read_dtls_callback(WOLFSSL *wolfssl, char *buffer, int size, void *ctx)
{
	int socket = wolfSSL_get_fd(wolfssl);
	wolfssl_session *session = (wolfssl_session *)ctx;
	// memset(&session->cliAddr, 0, sizeof(session->cliAddr));
	int ret = -1;

	// first rx from recv from
	if (session->rxSz > 0)
	{
		ret = session->rxSz;
		if (ret > size)
			ret = size;
		memcpy(buffer, session->rxBuf, ret);
		session->rxSz -= ret;
		memcpy(session->rxBuf, &session->rxBuf[ret], session->rxSz);
	}
	else
	{
		ret = recvfrom(socket, buffer, size, 0, (struct sockaddr *)&session->cliAddr, &session->cliSz);
	}
	if (ret == 0)
	{
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
static int wolfssl_write_dtls_callback(WOLFSSL *wolfssl, char *buffer, int size, void *ctx)
{

	int socket = wolfSSL_get_fd(wolfssl);
	wolfssl_session *session = (wolfssl_session *)ctx;
	const struct sockaddr *addr = NULL;
	socklen_t addrSz = 0;

	if (session)
	{
		addr = (const struct sockaddr *)&session->cliAddr;
		addrSz = session->cliSz;
	}

	int ret = sendto(socket, buffer, size, 0, addr, addrSz);

	if (ret < 0)
	{
		int error = errno;
		// LOG_WRN("send error: %d", error);
		if ((error == EAGAIN) || (error == EWOULDBLOCK))
			return WOLFSSL_CBIO_ERR_WANT_WRITE;
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

static int wolfssl_read_callback(WOLFSSL *wolfssl, char *buffer, int size, void *ctx)
{
	int socket = wolfSSL_get_fd(wolfssl);
	wolfssl_session *session = (wolfssl_session *)ctx;
	int ret = recv(socket, buffer, size, 0);

	if (ret == 0)
	{
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

static int wolfssl_write_callback(WOLFSSL *wolfssl, char *buffer, int size, void *ctx)
{
	int socket = wolfSSL_get_fd(wolfssl);
	wolfssl_session *session = (wolfssl_session *)ctx;

	int ret = send(socket, buffer, size, 0);

	if (ret < 0)
	{
		int error = errno;
		// LOG_WRN("send error: %d", error);
		if ((error == EAGAIN) || (error == EWOULDBLOCK))
			return WOLFSSL_CBIO_ERR_WANT_WRITE;
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

static void wolfssl_logging_callback(int level, const char *str)
{
	(void)level;

	LOG_INF("%s", str);
}

/* Import the public/private key pair in the given PEM file into the secure element.
 *
 * Returns 0 on success, -1 in case of an error (error message is logged to the console).
 */
static int wolfssl_import_pem_key_into_secure_element(uint8_t const *pem_buffer, uint32_t pem_size,
													  uint8_t const *id, int len)
{
#ifdef HAVE_PKCS11
	DerBuffer *der = NULL;
	EncryptedInfo info;
	int keyFormat = 0;
	int type = 0;
	void *key = NULL;
	int ret = -1;

	memset(&info, 0, sizeof(EncryptedInfo));

	/* Convert key to DER (binary) */
	ret = PemToDer(pem_buffer, pem_size, PRIVATEKEY_TYPE, &der, NULL,
				   &info, &keyFormat);
	if (ret < 0)
	{
		FreeDer(&der);
		LOG_ERR("Error converting private key to DER");
		return -1;
	}

	/* Check which key type we have */
	if (keyFormat == RSAk)
	{
		/* Create the key object */
		key = create_rsa_key_from_buffer(der->buffer, der->length, id, len);

		type = PKCS11_KEY_TYPE_RSA;
	}
	else if (keyFormat == ECDSAk)
	{
		/* Create the key object */
		key = create_ecc_key_from_buffer(der->buffer, der->length, id, len);

		type = PKCS11_KEY_TYPE_EC;
	}
	else if ((keyFormat == FALCON_LEVEL1k) || (keyFormat == FALCON_LEVEL5k))
	{
		/* Create the key object */
		key = create_falcon_key_from_buffer(keyFormat, der->buffer, der->length,
											id, len);

		type = PKCS11_KEY_TYPE_FALCON;
	}
	else if ((keyFormat == DILITHIUM_LEVEL2k) || (keyFormat == DILITHIUM_LEVEL3k) ||
			 (keyFormat == DILITHIUM_LEVEL5k))
	{
		/* Create the key object */
		key = create_dilithium_key_from_buffer(keyFormat, der->buffer, der->length,
											   id, len);

		type = PKCS11_KEY_TYPE_DILITHIUM;
	}

	if (key == NULL)
	{
		FreeDer(&der);
		LOG_ERR("Error creating private key object");
		return -1;
	}

	/* Import the key into the secure element */
	ret = wc_Pkcs11StoreKey_ex(&pkcs11_secure_element_instance.token, type, 1, key, 1);
	if (ret != 0)
	{
		LOG_ERR("Error importing private key into secure element: %d", ret);
		ret = -1;
	}

	/* Free key */
	switch (keyFormat)
	{
	case RSAk:
		wc_FreeRsaKey(key);
		break;
	case ECDSAk:
		wc_ecc_free(key);
		break;
	case FALCON_LEVEL1k:
	case FALCON_LEVEL5k:
		wc_falcon_free(key);
		break;
	case DILITHIUM_LEVEL2k:
	case DILITHIUM_LEVEL3k:
	case DILITHIUM_LEVEL5k:
		wc_dilithium_free(key);
		break;
	}
	free(key);

	FreeDer(&der);

	return ret;
#else
	return -1;
#endif
}

/* Initialize WolfSSL library.
 *
 * Parameter is a pointer to a filled library_configuration structure.
 *
 * Returns 0 on success, -1 in case of an error (error message is logged to the console).
 */
int wolfssl_init(struct wolfssl_library_configuration const *config)
{
	/* Initialize WolfSSL */
	int ret = wolfSSL_Init();
	if (errorOccured(ret))
		return -1;

#ifdef WOLFSSL_STATIC_MEMORY
	/* Load static memory to avoid malloc */
	if (wc_LoadStaticMemory(&wolfssl_heap, config->staticMemoryBuffer.buffer,
							config->staticMemoryBuffer.size, WOLFMEM_GENERAL, 1) != 0)
	{
		LOG_ERR("unable to load static memory");
		return -1;
	}
#endif

	/* Configure the logging interface */
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
	if ((config->use_secure_element == true) && (config->secure_element_middleware_path != NULL))
	{
#ifdef HAVE_PKCS11
		LOG_INF("Initializing secure element");

		/* Initialize the PKCS#11 library */
		ret = wc_Pkcs11_Initialize(&pkcs11_secure_element_instance.device,
								   config->secure_element_middleware_path, wolfssl_heap);
		if (ret != 0)
		{
			LOG_ERR("unable to initialize PKCS#11 library: %d", ret);
			return -1;
		}

		/* Initialize the token */
		ret = wc_Pkcs11Token_Init(&pkcs11_secure_element_instance.token,
								  &pkcs11_secure_element_instance.device,
								  -1, NULL,
								  "12345678", 8);
		if (ret != 0)
		{
			LOG_ERR("unable to initialize PKCS#11 token: %d", ret);
			wc_Pkcs11_Finalize(&pkcs11_secure_element_instance.device);
			return -1;
		}

		/* Register the device with WolfSSL */
		ret = wc_CryptoCb_RegisterDevice(secure_element_device_id(),
										 wc_Pkcs11_CryptoDevCb,
										 &pkcs11_secure_element_instance.token);
		if (ret != 0)
		{
			LOG_ERR("Failed to register PKCS#11 callback: %d", ret);
			wc_Pkcs11Token_Final(&pkcs11_secure_element_instance.token);
			wc_Pkcs11_Finalize(&pkcs11_secure_element_instance.device);
			return -1;
		}

		/* Create a persistent session with the secure element */
		ret = wc_Pkcs11Token_Open(&pkcs11_secure_element_instance.token, 1);
		if (ret == 0)
		{
			pkcs11_secure_element_instance.initialized = true;
			LOG_INF("Secure element initialized");
		}
		else
		{
			pkcs11_secure_element_instance.initialized = false;
			wc_Pkcs11Token_Final(&pkcs11_secure_element_instance.token);
			wc_Pkcs11_Finalize(&pkcs11_secure_element_instance.device);
			LOG_ERR("Secure element initialization failed: %d", ret);
		}
#else
		LOG_ERR("Secure element support is not compiled in, please compile with HAVE_PKCS11 preprocessor makro defined");
#endif
	}
	else
	{
		pkcs11_secure_element_instance.initialized = false;
	}

	return 0;
}

static int wolfssl_configure_dtls_context(WOLFSSL_CTX *context,
										  wolfssl_endpoint_configuration const *config)
{
	int ret = wolfSSL_CTX_SetMinVersion(context, WOLFSSL_DTLSV1_3);
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

	if (config->private_key.buffer != NULL)
	{
		/* Load the private key from the buffer */
		ret = wolfSSL_CTX_use_PrivateKey_buffer(context,
												config->private_key.buffer,
												config->private_key.size,
												WOLFSSL_FILETYPE_PEM);
	}
	/* Configure peer authentification */
	int verify_mode = WOLFSSL_VERIFY_NONE;
	if (config->mutual_authentication == true)
	{
		verify_mode = WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	}

	wolfSSL_CTX_set_verify(context, verify_mode, NULL);

	return ret;
}

/* Configure the new context.
 *
 * Returns 0 on success, -1 on failure (error message is logged to the console).
 */
static int wolfssl_configure_context(WOLFSSL_CTX *context, struct wolfssl_endpoint_configuration const *config)
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
	if (pkcs11_secure_element_instance.initialized == true)
	{
#ifdef HAVE_LIBOQS
		// wolfSSL_CTX_SetDevId(context, secure_element_device_id());

		/* Import private key into secure element if present */
		if (config->private_key.buffer != NULL)
		{
			ret = wolfssl_import_pem_key_into_secure_element(config->private_key.buffer,
															 config->private_key.size,
															 secure_element_private_key_id(),
															 secure_element_private_key_id_size());
			if (ret != 0)
			{
				LOG_ERR("Failed to import private key into secure element");
				return -1;
			}
		}

		/* Load the private key from the secure element */
		ret = wolfSSL_CTX_use_PrivateKey_Id(context,
											secure_element_private_key_id(),
											secure_element_private_key_id_size(),
											secure_element_device_id());

		/* Import the additional private key into secure element if present */
		if (config->private_key.additional_key_buffer != NULL)
		{
			if (errorOccured(ret))
				return -1;

			ret = wolfssl_import_pem_key_into_secure_element(config->private_key.additional_key_buffer,
															 config->private_key.additional_key_size,
															 secure_element_additional_private_key_id(),
															 secure_element_additional_private_key_id_size());
			if (ret != 0)
			{
				LOG_ERR("Failed to import additional private key into secure element");
				return -1;
			}

			/* Load the private key from the secure element */
			ret = wolfSSL_CTX_use_AltPrivateKey_Id(context,
												   secure_element_additional_private_key_id(),
												   secure_element_additional_private_key_id_size(),
												   secure_element_device_id());
		}

		privateKeyLoaded = true;
#endif
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
#ifdef WOLFSSL_DUAL_ALG_CERTS
			if (errorOccured(ret))
				return -1;

			ret = wolfSSL_CTX_use_AltPrivateKey_buffer(context,
													   config->private_key.additional_key_buffer,
													   config->private_key.additional_key_size,
													   WOLFSSL_FILETYPE_PEM);
#endif
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

	/* Configure the available cipher suites for TLS 1.3
	 * We only support AES GCM with 256 bit key length and the
	 * integrity only cipher with SHA384.
	 */
	ret = wolfSSL_CTX_set_cipher_list(context, "TLS13-AES256-GCM-SHA384:TLS13-SHA384-SHA384");
	if (errorOccured(ret))
		return -1;
#ifdef HAVE_LIBOQS
	/* Configure the available curves for Key Exchange */
	int wolfssl_key_exchange_curves[] = {
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
#endif
#ifdef WOLFSSL_DUAL_ALG_CERTS

	/* Set the preference for verfication of hybrid signatures to be for both the
	 * native and alternative chains.
	 */
	static uint8_t cks_order[3] = {
		WOLFSSL_CKS_SIGSPEC_BOTH,
		WOLFSSL_CKS_SIGSPEC_ALTERNATIVE,
		WOLFSSL_CKS_SIGSPEC_NATIVE,
	};

	ret = wolfSSL_CTX_UseCKS(context, cks_order, sizeof(cks_order));
	if (errorOccured(ret))
		return -1;

#endif

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
wolfssl_endpoint *wolfssl_setup_dtls_server_endpoint(wolfssl_endpoint_configuration const *config)
{
	if (config == NULL)
	{
		LOG_ERR("Configuration is NULL");
		return NULL;
	}
	int ret = 0;
	/* Create a new endpoint object */
	wolfssl_endpoint *new_endpoint = malloc(sizeof(wolfssl_endpoint));
	if (new_endpoint == NULL)
	{
		LOG_ERR("Unable to allocate memory for new WolfSSL endpoint");
		return NULL;
	}

	/* Create the TLS server context */
	new_endpoint->context = wolfSSL_CTX_new_ex(wolfDTLSv1_3_server_method_ex(wolfssl_heap), wolfssl_heap);
	if (new_endpoint->context == NULL)
	{
		LOG_ERR("Unable to create a new WolfSSL server context");
		free(new_endpoint);
		return NULL;
	}

	/* Configure the new context */
	ret = wolfssl_configure_dtls_context(new_endpoint->context, config);
	if (ret == -1)
	{
		LOG_ERR("Failed to configure new DTLS server context\r\n");
		wolfSSL_CTX_free(new_endpoint->context);
		free(new_endpoint);
		return NULL;
	}
	/* Set the IO callbacks for send and receive */
	wolfSSL_CTX_SetIORecv(new_endpoint->context, wolfssl_read_dtls_callback);
	wolfSSL_CTX_SetIOSend(new_endpoint->context, wolfssl_write_dtls_callback);

	return new_endpoint;
}

/* Setup a TLS server endpoint.
 *
 * Parameter is a pointer to a filled endpoint_configuration structure.
 *
 * Return value is a pointer to the newly created endpoint or NULL in case of an error
 * (error message is logged to the console).
 */
wolfssl_endpoint *wolfssl_setup_server_endpoint(wolfssl_endpoint_configuration const *config)
{
	if (config == NULL)
	{
		LOG_ERR("Configuration is NULL");
		return NULL;
	}

	/* Create a new endpoint object */
	wolfssl_endpoint *new_endpoint = malloc(sizeof(wolfssl_endpoint));
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

	return new_endpoint;
}

wolfssl_endpoint *wolfssl_setup_dtls_client_endpoint(wolfssl_endpoint_configuration const *config)
{
	if (config == NULL)
	{
		LOG_ERR("Configuration is NULL");
		return NULL;
	}

	/* Create a new endpoint object */
	wolfssl_endpoint *new_endpoint = malloc(sizeof(wolfssl_endpoint));
	if (new_endpoint == NULL)
	{
		LOG_ERR("Unable to allocate memory for new WolfSSL endpoint");
		return NULL;
	}

	/* Create the TLS client context */
	new_endpoint->context = wolfSSL_CTX_new_ex(wolfDTLSv1_3_client_method_ex(wolfssl_heap), wolfssl_heap);
	if (new_endpoint->context == NULL)
	{
		LOG_ERR("Unable to create a new WolfSSL client context");
		free(new_endpoint);
		return NULL;
	}

	/* Configure the new context */
	int ret = wolfssl_configure_dtls_context(new_endpoint->context, config);
	if (ret == -1)
	{
		LOG_ERR("Failed to confiugre new TLS client context\r\n");
		wolfSSL_CTX_free(new_endpoint->context);
		free(new_endpoint);
		return NULL;
	}

	/* Set the IO callbacks for send and receive */
	wolfSSL_CTX_SetIORecv(new_endpoint->context, wolfssl_read_client_dtls_callback);
	wolfSSL_CTX_SetIOSend(new_endpoint->context, wolfssl_write_client_dtls_callback);
	return new_endpoint;
}


int wolfssl_dtls_is_connected(wolfssl_session *session){
	if (session == NULL)
	{
		LOG_ERR("Session is NULL");
		return -1;
	}else if (session->state == CONNECTION_STATE_CONNECTED)
	{
		return 1;
	}
	return 0;
}

/* Setup a TLS client endpoint.
 *
 * Parameter is a pointer to a filled endpoint_configuration structure.
 *
 * Return value is a pointer to the newly created endpoint or NULL in case of an error
 * (error message is logged to the console).
 */
wolfssl_endpoint *wolfssl_setup_client_endpoint(wolfssl_endpoint_configuration const *config)
{
	if (config == NULL)
	{
		LOG_ERR("Configuration is NULL");
		return NULL;
	}

	/* Create a new endpoint object */
	wolfssl_endpoint *new_endpoint = malloc(sizeof(wolfssl_endpoint));
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

	return new_endpoint;
}

int wolfssl_dtls_client_handshake(wolfssl_session *session, struct sockaddr_in *servAddr)
{
	session->servSz = sizeof(struct sockaddr_in);
	memcpy(&session->servAddr, servAddr, session->servSz);
	int ret = 0;
	if (wolfSSL_dtls_set_peer(session->session, &servAddr, sizeof(servAddr)) != WOLFSSL_SUCCESS)
	{
		LOG_ERR("wolfSSL_dtls_set_peer failed\n");
	}

	/* Perform SSL connection */
	ret = wolfSSL_connect(session->session);
	if (ret != SSL_SUCCESS)
	{
		ret = wolfSSL_get_error(session->session, 0);
		LOG_ERR("wolfSSL_connect failed: %d", ret);
		ret = -1;
	}
	session->state = CONNECTION_STATE_CONNECTED;

	return ret;
}

int wolfssl_dtls_server_handshake(wolfssl_session *session)
{
	int ret = 0;
	int fd = wolfSSL_get_fd(session->session);
	ret = (int)recvfrom(fd,
						(char *)session->rxBuf,
						sizeof(session->rxBuf),
						0,
						(struct sockaddr *)&session->cliAddr,
						&session->cliSz);
	if (ret > 0)
	{
		session->rxSz = ret;
		LOG_INF("connected");
	}
	else
	{
		LOG_ERR("Recvfrom failed: %d", ret);
	}

	/* Perform SSL connection */
	if (wolfSSL_accept(session->session) != SSL_SUCCESS)
	{
		ret = wolfSSL_get_error(session->session, 0);
		LOG_ERR("wolfSSL_connect failed: %d", ret);
		return ret;
	}
	session->state = CONNECTION_STATE_CONNECTED;

	return ret;
}

/* Create a new session for the endpoint.
 *
 * Parameters are a pointer to a configured endpoint and the socket fd of the underlying
 * network connection.
 *
 * Return value is a pointer to the newly created session or NULL in case of an error
 * (error message is logged to the console).
 */
wolfssl_session *wolfssl_create_session(wolfssl_endpoint *endpoint, int socket_fd)
{
	if (endpoint == NULL)
	{
		LOG_ERR("Endpoint is NULL");
		return NULL;
	}

	/* Create a new session object */
	wolfssl_session *new_session = malloc(sizeof(wolfssl_session));
	if (new_session == NULL)
	{
		LOG_ERR("Unable to allocate memory for new WolfSSL session");
		return NULL;
	}
	memset(&new_session->cliAddr, 0, sizeof(new_session->cliAddr));
	new_session->cliSz = sizeof(new_session->cliAddr);

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
	int ret = wolfSSL_set_fd(new_session->session, socket_fd);
	if (ret < 0)
	{
		LOG_ERR("Unable to set the socket fd for the WolfSSL session");
		return NULL;
	}

	/* Store a pointer to our session object to get access to the metrics from
	 * the read and write callback. This must be done AFTER the call to
	 * wolfSSL_set_fd() as this method overwrites the ctx variables.
	 */
	wolfSSL_SetIOReadCtx(new_session->session, new_session);
	wolfSSL_SetIOWriteCtx(new_session->session, new_session);
	return new_session;
}

/* Perform the TLS handshake for a newly created session.
 *
 * Returns 0 on success, -1 on failure (error message is logged to the console) and a positive
 * integer in case the handshake is not done yet (and you have to call the method again when new
 * data from the peer is present). The return code is then either WOLFSSL_ERROR_WANT_READ or
 * WOLFSSL_ERROR_WANT_WRITE.
 */
int wolfssl_handshake(wolfssl_session *session)
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
int wolfssl_receive(wolfssl_session *session, uint8_t *buffer, int max_size)
{
	uint8_t *tmp = buffer;
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
			else if ((ret == WOLFSSL_ERROR_ZERO_RETURN) || (ret == SOCKET_PEER_CLOSED_E))
			{
				LOG_INF("TLS connection was closed gracefully");
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
int wolfssl_send(wolfssl_session *session, uint8_t const *buffer, int size)
{
	uint8_t const *tmp = buffer;
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
tls_handshake_metrics wolfssl_get_handshake_metrics(wolfssl_session *session)
{
	tls_handshake_metrics metrics;

	metrics.duration_us = (session->handshake_metrics_priv.end_time.tv_sec - session->handshake_metrics_priv.start_time.tv_sec) * 1000000.0 +
						  (session->handshake_metrics_priv.end_time.tv_nsec - session->handshake_metrics_priv.start_time.tv_nsec) / 1000.0;
	metrics.txBytes = session->handshake_metrics_priv.txBytes;
	metrics.rxBytes = session->handshake_metrics_priv.rxBytes;

	return metrics;
}

/* Close the connection of the active session */
void wolfssl_close_session(wolfssl_session *session)
{
	if (session != NULL)
	{
		wolfSSL_shutdown(session->session);
		session->state = CONNECTION_STATE_NOT_CONNECTED;
	}
}

/* Free ressources of a session. */
void wolfssl_free_session(wolfssl_session *session)
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
void wolfssl_free_endpoint(wolfssl_endpoint *endpoint)
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


int get_fd(wolfssl_session *session){
	return wolfSSL_get_fd(session->session);
}