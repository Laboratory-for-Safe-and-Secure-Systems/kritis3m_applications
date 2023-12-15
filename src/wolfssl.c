
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>

#include "logging.h"
#include "networking.h"

#include "secure_element/secure_element.h"
#include "secure_element/wolfssl_pkcs11_pqc.h"

#include "wolfssl.h"

#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/memory.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/error-ssl.h"


LOG_MODULE_REGISTER(wolfssl);


#ifdef WOLFSSL_STATIC_MEMORY
static WOLFSSL_HEAP_HINT* wolfssl_heap;
extern uint8_t* wolfsslMemoryBuffer;
extern size_t wolfsslMemoryBufferSize;
#else
#define wolfssl_heap NULL
#endif



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

static int wolfssl_read_callback(WOLFSSL* session, char* buffer, int size, void* ctx)
{
	(void) ctx;

	int socket = wolfSSL_get_fd(session);

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
	
	return ret;
}

static int wolfssl_write_callback(WOLFSSL* session, char* buffer, int size, void* ctx)
{
	(void) ctx;

	int socket = wolfSSL_get_fd(session);

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

	return ret;
}

static void wolfssl_logging_callback(int level, const char* str)
{
	(void) level;

	LOG_INF("%s", str);
}




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
	if (wc_LoadStaticMemory(&wolfssl_heap, config->staticMemoryBuffer.buffer, config->staticMemoryBuffer.size, WOLFMEM_GENERAL, 1) != 0)
	{
		LOG_ERR("unable to load static memory");
		return -1;
	}
#endif

	/* Configure the logging interface */
	if (config->loggingEnabled)
	{
		wolfSSL_SetLoggingCb(wolfssl_logging_callback);
    		wolfSSL_Debugging_ON();
	}

	/* Load the secure element middleware */
	if (config->secure_element_middleware_path != NULL)
	{
		pkcs11_setLibraryPath(config->secure_element_middleware_path);

		/* Install the crypto callback to forward calls to the external secure element */
		if (wolfssl_install_crypto_callback_secure_element(NULL) != 0)
		{
			return -1;
		}
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
	ret = wolfSSL_CTX_use_certificate_chain_buffer_format(context,
							      config->device_certificate_chain.buffer,
							      config->device_certificate_chain.size,
							      WOLFSSL_FILETYPE_PEM);
	if (errorOccured(ret))
		return -1;

	/* Load the private key */
	if (config->use_secure_element)
	{
		// wolfSSL_CTX_SetDevId(context, wolfssl_get_secure_element_device_id());

		/* Import private key into secure element if present */
		if (config->private_key.buffer != NULL)
		{
			wolfssl_import_key_pair_into_secure_element(config->private_key.buffer,
								    config->private_key.size);
		}

		/* Load the private key from the secure element */
		ret = wolfSSL_CTX_use_PrivateKey_Id(context,
						    wolfssl_get_secure_element_private_key_id(),
						    wolfssl_get_secure_element_private_key_id_size(),
						    wolfssl_get_secure_element_device_id());
	}
	else
	{
		/* Load the private key from the buffer */
		ret = wolfSSL_CTX_use_PrivateKey_buffer(context,
							config->private_key.buffer,
							config->private_key.size,
							WOLFSSL_FILETYPE_PEM);
	}

	if (errorOccured(ret))
		return -1; 


	/* Check if the private key and the device certificate match */
	ret = wolfSSL_CTX_check_private_key(context);
	if (errorOccured(ret))
		return -1;

	/* Configure the available cipher suites for TLS 1.3;
	 * We only support AES GCM with 256 bit key length */
	ret = wolfSSL_CTX_set_cipher_list(context, "TLS13-AES256-GCM-SHA384");
	if (errorOccured(ret))
		return -1;

	/* Configure the available curves for Key Exchange */
	// int wolfssl_key_exchange_curves[] = {
	// 	WOLFSSL_KYBER_LEVEL1,
        // 	WOLFSSL_KYBER_LEVEL3,
        // 	WOLFSSL_KYBER_LEVEL5,
        // 	WOLFSSL_P256_KYBER_LEVEL1,
        // 	WOLFSSL_P384_KYBER_LEVEL3,
        // 	WOLFSSL_P521_KYBER_LEVEL5,
	// };
	// ret = wolfSSL_CTX_set_groups(context, wolfssl_key_exchange_curves,
	// 			     sizeof(wolfssl_key_exchange_curves) / sizeof(int));
	// if (errorOccured(ret))
	// 	return -1;

	/* Set the IO callbacks for send and receive */
	wolfSSL_CTX_SetIORecv(context, wolfssl_read_callback);
	wolfSSL_CTX_SetIOSend(context, wolfssl_write_callback);

	/* Set peer authentification to required */
	wolfSSL_CTX_set_verify(context, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	return 0;
}


/* Setup a TLS server context.
 *
 * Parameter is a pointer to a filled endpoint_configuration structure.
 *
 * Return value is a pointer to the newly created context or NULl in case of an error
 * (error message is logged to the console).
 */
WOLFSSL_CTX* wolfssl_setup_server_context(struct wolfssl_endpoint_configuration const* config)
{
        /* Create the TLS server context */
	WOLFSSL_CTX* new_context = wolfSSL_CTX_new_ex(wolfTLS_server_method_ex(wolfssl_heap), wolfssl_heap);
	if (new_context == NULL)
	{
		LOG_ERR("Unable to create a new WolfSSL server context");
		return NULL;
	}

	/* Configure the new context */
        int ret = wolfssl_configure_context(new_context, config);
        if (ret == -1)
        {
                LOG_ERR("Failed to configure new TLS server context\r\n");
                wolfSSL_CTX_free(new_context);
	        return NULL;
        }

        return new_context;
}


/* Setup a TLS client context.
 *
 * Parameter is a pointer to a filled endpoint_configuration structure.
 *
 * Return value is a pointer to the newly created context or NULl in case of an error
 * (error message is logged to the console).
 */
WOLFSSL_CTX* wolfssl_setup_client_context(struct wolfssl_endpoint_configuration const* config)
{
        /* Create the TLS client context */
	WOLFSSL_CTX* new_context = wolfSSL_CTX_new_ex(wolfTLS_client_method_ex(wolfssl_heap), wolfssl_heap);
	if (new_context == NULL)
	{
		LOG_ERR("Unable to create a new WolfSSL client context");
		return NULL;
	}

	/* Configure the new context */
        int ret = wolfssl_configure_context(new_context, config);
        if (ret == -1)
        {
                LOG_ERR("Failed to confiugre new TLS client context\r\n");
                wolfSSL_CTX_free(new_context);
	        return NULL;
        }

        return new_context;
}


/* Perform the TLS handshake for a newly created session.
 *
 * Returns 0 on success, -1 on failure (error message is logged to the console) and a positive
 * integer in case the handshake is not done yet (and you have to call the method again when new
 * data from the peer is present). The return code is then either WOLFSSL_ERROR_WANT_READ or
 * WOLFSSL_ERROR_WANT_WRITE.
 */
int wolfssl_handshake(WOLFSSL* session)
{
        int ret = -1;

	while (ret != 0)
	{
		ret = wolfSSL_negotiate(session);

		if (ret == WOLFSSL_SUCCESS)
		{
			ret = 0;
			break;
		}
		else
		{
			ret = wolfSSL_get_error(session, ret);

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


/* Receive new data from the TLS peer (blocking read).
 *
 * Returns the number of received bytes on success, -1 on failure (error message is logged
 * to the console).
 */
int wolfssl_receive(WOLFSSL* session, uint8_t* buffer, int max_size)
{
	uint8_t* tmp = buffer;
	int bytes_read = 0;
	
	while (1)
	{
		int ret = wolfSSL_read(session, tmp, max_size - bytes_read);

		if (ret <= 0) 
		{
			ret = wolfSSL_get_error(session, ret);

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
int wolfssl_send(WOLFSSL* session, uint8_t* buffer, int size)
{
        uint8_t* tmp = buffer;
	int ret = 0;

	while (size > 0)
	{
		ret = wolfSSL_write(session, tmp, size);

		if (ret > 0)
		{
			/* We successfully sent data */
			size -= ret;
			tmp += ret;
			ret = 0;
		}
		else
		{
			ret = wolfSSL_get_error(session, ret);

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
