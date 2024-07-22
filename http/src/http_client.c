/** @file
 * @brief HTTP client API
 *
 * An API for applications to send HTTP requests
 */

/*
 * Copyright (c) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

<<<<<<< HEAD
=======
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_http_client, CONFIG_NET_HTTP_LOG_LEVEL);

#include <zephyr/kernel.h>
>>>>>>> d0ce145 (added http libs and CMake integration)
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

<<<<<<< HEAD
/********************************************
 *              PLATFORM SPECIFIC			*
 *******************************************/

/********************************************
 * 			    ZEPHYR				  	    *
 * *****************************************/
#if defined(__ZEPYHR__)
#include <zephyr/kernel.h>
#endif

#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>

#include "http_client.h"
#include "logging.h"

LOG_MODULE_CREATE(http);
=======
#include <zephyr/net/net_ip.h>
#include <zephyr/net/socket.h>
// #include <zephyr/net/http/client.h>
#include "http_client.h"

#include "net_private.h"
>>>>>>> d0ce145 (added http libs and CMake integration)

#define HTTP_CONTENT_LEN_SIZE 11
#define MAX_SEND_BUF_LEN 192

<<<<<<< HEAD
/***
 * This function can be used to send data (http fraction or full http request) to an endpoint
 * @param req_end_timepoint - is the timeout value in ms used in poll()
 * @todo timeout
 * @todo remove function, since asl_send is already sendall
 */
static int asl_sendall(asl_session *session,
					   const void *buf,
					   size_t len,
					   const k_timepoint_t req_end_timepoint)
{
	int ret = 0;
	ret = asl_send(session, buf, len);
	switch (ret)
	{
	case ASL_SUCCESS:
		return 0;
		break;
	case ASL_ARGUMENT_ERROR:
		LOG_ERROR("asl error");
		return -1;
		break;
	case ASL_WANT_READ:
		LOG_ERROR("asl error");
		return -1;
		break;
	}
	return -1;
}

static int https_send_data(asl_session *session, char *send_buf,
						   size_t send_buf_max_len, size_t *send_buf_pos,
						   const k_timepoint_t req_end_timepoint,
						   ...)
{
	const char *data;
	va_list va;
	int ret, end_of_send = *send_buf_pos;
	int end_of_data, remaining_len;
	int sent = 0;

	va_start(va, req_end_timepoint);

	data = va_arg(va, const char *);

	while (data)
	{
		end_of_data = 0;

		do
		{
			int to_be_copied;

			remaining_len = strlen(data + end_of_data);
			to_be_copied = send_buf_max_len - end_of_send;

			if (remaining_len > to_be_copied)
			{
				strncpy(send_buf + end_of_send,
						data + end_of_data,
						to_be_copied);

				end_of_send += to_be_copied;
				end_of_data += to_be_copied;
				remaining_len -= to_be_copied;
				// LOG_HEXDUMP_DBG(send_buf, end_of_send,
				// 		"Data to send");
				ret = asl_sendall(session, send_buf, end_of_send, req_end_timepoint);
				if (ret < 0)
				{
					LOG_DEBUG("Cannot send %d bytes (%d)",
							  end_of_send, ret);
					goto err;
				}
				sent += end_of_send;
				end_of_send = 0;
				continue;
			}
			else
			{
				strncpy(send_buf + end_of_send,
						data + end_of_data,
						remaining_len);
				end_of_send += remaining_len;
				remaining_len = 0;
			}
		} while (remaining_len > 0);

		data = va_arg(va, const char *);
	}

	va_end(va);

	if (end_of_send > (int)send_buf_max_len)
	{
		LOG_ERROR("Sending overflow (%d > %zd)", end_of_send,
				  send_buf_max_len);
		return -EMSGSIZE;
	}

	*send_buf_pos = end_of_send;

	return sent;

err:
	va_end(va);

	return ret;
}

/***
 * This function can be used to send data (http fraction or full http request) to an endpoint
 * @param req_end_timepoint - is the timeout value in ms used in poll()
 */
static int sendall(int sock,
				   const void *buf,
				   size_t len,
				   const k_timepoint_t req_end_timepoint)
{
	while (len)
	{
		ssize_t out_len = send(sock, buf, len, 0);

		if ((out_len == 0) || (out_len < 0 && errno == EAGAIN))
		{
			struct pollfd pfd;
=======
static int sendall(int sock, const void *buf, size_t len,
			const k_timepoint_t req_end_timepoint)
{
	while (len) {
		ssize_t out_len = zsock_send(sock, buf, len, 0);

		if ((out_len == 0) || (out_len < 0 && errno == EAGAIN)) {
			struct zsock_pollfd pfd;
>>>>>>> d0ce145 (added http libs and CMake integration)
			int pollres;
			k_ticks_t req_timeout_ticks =
				sys_timepoint_timeout(req_end_timepoint).ticks;
			int req_timeout_ms = k_ticks_to_ms_floor32(req_timeout_ticks);

			pfd.fd = sock;
<<<<<<< HEAD
			pfd.events = POLLOUT;
			pollres = poll(&pfd, 1, req_timeout_ms);
			if (pollres == 0)
			{
				return -ETIMEDOUT;
			}
			else if (pollres > 0)
			{
				continue;
			}
			else
			{
				return -errno;
			}
		}
		else if (out_len < 0)
		{
=======
			pfd.events = ZSOCK_POLLOUT;
			pollres = zsock_poll(&pfd, 1, req_timeout_ms);
			if (pollres == 0) {
				return -ETIMEDOUT;
			} else if (pollres > 0) {
				continue;
			} else {
				return -errno;
			}
		} else if (out_len < 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
			return -errno;
		}

		buf = (const char *)buf + out_len;
		len -= out_len;
	}

	return 0;
}

static int http_send_data(int sock, char *send_buf,
<<<<<<< HEAD
						  size_t send_buf_max_len, size_t *send_buf_pos,
						  const k_timepoint_t req_end_timepoint,
						  ...)
=======
			  size_t send_buf_max_len, size_t *send_buf_pos,
			  const k_timepoint_t req_end_timepoint,
			  ...)
>>>>>>> d0ce145 (added http libs and CMake integration)
{
	const char *data;
	va_list va;
	int ret, end_of_send = *send_buf_pos;
	int end_of_data, remaining_len;
	int sent = 0;

	va_start(va, req_end_timepoint);

	data = va_arg(va, const char *);

<<<<<<< HEAD
	while (data)
	{
		end_of_data = 0;

		do
		{
=======
	while (data) {
		end_of_data = 0;

		do {
>>>>>>> d0ce145 (added http libs and CMake integration)
			int to_be_copied;

			remaining_len = strlen(data + end_of_data);
			to_be_copied = send_buf_max_len - end_of_send;

<<<<<<< HEAD
			if (remaining_len > to_be_copied)
			{
				strncpy(send_buf + end_of_send,
						data + end_of_data,
						to_be_copied);
=======
			if (remaining_len > to_be_copied) {
				strncpy(send_buf + end_of_send,
					data + end_of_data,
					to_be_copied);
>>>>>>> d0ce145 (added http libs and CMake integration)

				end_of_send += to_be_copied;
				end_of_data += to_be_copied;
				remaining_len -= to_be_copied;
<<<<<<< HEAD
				// LOG_HEXDUMP_DBG(send_buf, end_of_send,
				// 		"Data to send");

				ret = sendall(sock, send_buf, end_of_send, req_end_timepoint);
				if (ret < 0)
				{
					LOG_DEBUG("Cannot send %d bytes (%d)",
							  end_of_send, ret);
=======

				LOG_HEXDUMP_DBG(send_buf, end_of_send,
						"Data to send");

				ret = sendall(sock, send_buf, end_of_send, req_end_timepoint);
				if (ret < 0) {
					NET_DBG("Cannot send %d bytes (%d)",
						end_of_send, ret);
>>>>>>> d0ce145 (added http libs and CMake integration)
					goto err;
				}
				sent += end_of_send;
				end_of_send = 0;
				continue;
<<<<<<< HEAD
			}
			else
			{
				strncpy(send_buf + end_of_send,
						data + end_of_data,
						remaining_len);
=======
			} else {
				strncpy(send_buf + end_of_send,
					data + end_of_data,
					remaining_len);
>>>>>>> d0ce145 (added http libs and CMake integration)
				end_of_send += remaining_len;
				remaining_len = 0;
			}
		} while (remaining_len > 0);

		data = va_arg(va, const char *);
	}

	va_end(va);

<<<<<<< HEAD
	if (end_of_send > (int)send_buf_max_len)
	{
		LOG_ERROR("Sending overflow (%d > %zd)", end_of_send,
				  send_buf_max_len);
=======
	if (end_of_send > (int)send_buf_max_len) {
		NET_ERR("Sending overflow (%d > %zd)", end_of_send,
			send_buf_max_len);
>>>>>>> d0ce145 (added http libs and CMake integration)
		return -EMSGSIZE;
	}

	*send_buf_pos = end_of_send;

	return sent;

err:
	va_end(va);

	return ret;
}

<<<<<<< HEAD
static int https_flush_data(asl_session *session, const char *send_buf, size_t send_buf_len,
							const k_timepoint_t req_end_timepoint)
{
	int ret;

	// LOG_HEXDUMP_DBG(send_buf, send_buf_len, "Data to send");
	ret = asl_sendall(session, send_buf, send_buf_len, req_end_timepoint);
	/**
	 * @todo test if workaround is sufficient
	 */
	// ret = sendall(sock, send_buf, send_buf_len, req_end_timepoint);
	if (ret < 0)

	{
		LOG_ERROR("couldnt sendall ");
		return ret;
	}

	return (int)send_buf_len;
}

static int http_flush_data(int sock, const char *send_buf, size_t send_buf_len,
						   const k_timepoint_t req_end_timepoint)
{
	int ret;

	// LOG_HEXDUMP_DBG(send_buf, send_buf_len, "Data to send");

	ret = sendall(sock, send_buf, send_buf_len, req_end_timepoint);
	if (ret < 0)
	{
=======
static int http_flush_data(int sock, const char *send_buf, size_t send_buf_len,
				const k_timepoint_t req_end_timepoint)
{
	int ret;

	LOG_HEXDUMP_DBG(send_buf, send_buf_len, "Data to send");

	ret = sendall(sock, send_buf, send_buf_len, req_end_timepoint);
	if (ret < 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
		return ret;
	}

	return (int)send_buf_len;
}

static void print_header_field(size_t len, const char *str)
{
<<<<<<< HEAD
	if (IS_ENABLED(CONFIG_NET_HTTP_LOG_LEVEL_DBG))
	{
=======
	if (IS_ENABLED(CONFIG_NET_HTTP_LOG_LEVEL_DBG)) {
>>>>>>> d0ce145 (added http libs and CMake integration)
#define MAX_OUTPUT_LEN 128
		char output[MAX_OUTPUT_LEN];

		/* The value of len does not count \0 so we need to increase it
		 * by one.
		 */
<<<<<<< HEAD
		if ((len + 1) > sizeof(output))
		{
=======
		if ((len + 1) > sizeof(output)) {
>>>>>>> d0ce145 (added http libs and CMake integration)
			len = sizeof(output) - 1;
		}

		snprintk(output, len + 1, "%s", str);

<<<<<<< HEAD
		LOG_DEBUG("[%zd] %s", len, output);
=======
		NET_DBG("[%zd] %s", len, output);
>>>>>>> d0ce145 (added http libs and CMake integration)
	}
}

static int on_url(struct http_parser *parser, const char *at, size_t length)
{
	struct http_request *req = CONTAINER_OF(parser,
<<<<<<< HEAD
											struct http_request,
											internal.parser);
	print_header_field(length, at);

	if (req->internal.response.http_cb &&
		req->internal.response.http_cb->on_url)
	{
=======
						struct http_request,
						internal.parser);
	print_header_field(length, at);

	if (req->internal.response.http_cb &&
	    req->internal.response.http_cb->on_url) {
>>>>>>> d0ce145 (added http libs and CMake integration)
		req->internal.response.http_cb->on_url(parser, at, length);
	}

	return 0;
}

static int on_status(struct http_parser *parser, const char *at, size_t length)
{
	struct http_request *req = CONTAINER_OF(parser,
<<<<<<< HEAD
											struct http_request,
											internal.parser);
=======
						struct http_request,
						internal.parser);
>>>>>>> d0ce145 (added http libs and CMake integration)
	uint16_t len;

	len = MIN(length, sizeof(req->internal.response.http_status) - 1);
	memcpy(req->internal.response.http_status, at, len);
	req->internal.response.http_status[len] = 0;
	req->internal.response.http_status_code =
		(uint16_t)parser->status_code;

<<<<<<< HEAD
	LOG_DEBUG("HTTP response status %d %s", parser->status_code,
			  req->internal.response.http_status);

	if (req->internal.response.http_cb &&
		req->internal.response.http_cb->on_status)
	{
=======
	NET_DBG("HTTP response status %d %s", parser->status_code,
		req->internal.response.http_status);

	if (req->internal.response.http_cb &&
	    req->internal.response.http_cb->on_status) {
>>>>>>> d0ce145 (added http libs and CMake integration)
		req->internal.response.http_cb->on_status(parser, at, length);
	}

	return 0;
}

static int on_header_field(struct http_parser *parser, const char *at,
<<<<<<< HEAD
						   size_t length)
{
	struct http_request *req = CONTAINER_OF(parser,
											struct http_request,
											internal.parser);
=======
			   size_t length)
{
	struct http_request *req = CONTAINER_OF(parser,
						struct http_request,
						internal.parser);
>>>>>>> d0ce145 (added http libs and CMake integration)
	const char *content_len = "Content-Length";
	uint16_t len;

	len = strlen(content_len);
<<<<<<< HEAD
	if (length >= len && strncasecmp(at, content_len, len) == 0)
	{
=======
	if (length >= len && strncasecmp(at, content_len, len) == 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
		req->internal.response.cl_present = true;
	}

	print_header_field(length, at);

	if (req->internal.response.http_cb &&
<<<<<<< HEAD
		req->internal.response.http_cb->on_header_field)
	{
		req->internal.response.http_cb->on_header_field(parser, at,
														length);
=======
	    req->internal.response.http_cb->on_header_field) {
		req->internal.response.http_cb->on_header_field(parser, at,
								length);
>>>>>>> d0ce145 (added http libs and CMake integration)
	}

	return 0;
}

<<<<<<< HEAD
#define MAX_NUM_DIGITS 16

static int on_header_value(struct http_parser *parser, const char *at,
						   size_t length)
{
	struct http_request *req = CONTAINER_OF(parser,
											struct http_request,
											internal.parser);
	char str[MAX_NUM_DIGITS];

	if (req->internal.response.cl_present)
	{
		if (length <= MAX_NUM_DIGITS - 1)
		{
=======
#define MAX_NUM_DIGITS	16

static int on_header_value(struct http_parser *parser, const char *at,
			   size_t length)
{
	struct http_request *req = CONTAINER_OF(parser,
						struct http_request,
						internal.parser);
	char str[MAX_NUM_DIGITS];

	if (req->internal.response.cl_present) {
		if (length <= MAX_NUM_DIGITS - 1) {
>>>>>>> d0ce145 (added http libs and CMake integration)
			long int num;

			memcpy(str, at, length);
			str[length] = 0;

			num = strtol(str, NULL, 10);
<<<<<<< HEAD
			if (num == LONG_MIN || num == LONG_MAX)
			{
=======
			if (num == LONG_MIN || num == LONG_MAX) {
>>>>>>> d0ce145 (added http libs and CMake integration)
				return -EINVAL;
			}

			req->internal.response.content_length = num;
		}

		req->internal.response.cl_present = false;
	}

	if (req->internal.response.http_cb &&
<<<<<<< HEAD
		req->internal.response.http_cb->on_header_value)
	{
		req->internal.response.http_cb->on_header_value(parser, at,
														length);
=======
	    req->internal.response.http_cb->on_header_value) {
		req->internal.response.http_cb->on_header_value(parser, at,
								length);
>>>>>>> d0ce145 (added http libs and CMake integration)
	}

	print_header_field(length, at);

	return 0;
}

static int on_body(struct http_parser *parser, const char *at, size_t length)
{
	struct http_request *req = CONTAINER_OF(parser,
<<<<<<< HEAD
											struct http_request,
											internal.parser);
=======
						struct http_request,
						internal.parser);
>>>>>>> d0ce145 (added http libs and CMake integration)

	req->internal.response.body_found = 1;
	req->internal.response.processed += length;

<<<<<<< HEAD
	LOG_DEBUG("Processed %zd length %zd", req->internal.response.processed,
			  length);

	if (req->internal.response.http_cb &&
		req->internal.response.http_cb->on_body)
	{
=======
	NET_DBG("Processed %zd length %zd", req->internal.response.processed,
		length);

	if (req->internal.response.http_cb &&
	    req->internal.response.http_cb->on_body) {
>>>>>>> d0ce145 (added http libs and CMake integration)
		req->internal.response.http_cb->on_body(parser, at, length);
	}

	/* Reset the body_frag_start pointer for each fragment. */
<<<<<<< HEAD
	if (!req->internal.response.body_frag_start)
	{
=======
	if (!req->internal.response.body_frag_start) {
>>>>>>> d0ce145 (added http libs and CMake integration)
		req->internal.response.body_frag_start = (uint8_t *)at;
	}

	/* Calculate the length of the body contained in the recv_buf */
	req->internal.response.body_frag_len = req->internal.response.data_len -
<<<<<<< HEAD
										   (req->internal.response.body_frag_start - req->internal.response.recv_buf);
=======
		(req->internal.response.body_frag_start - req->internal.response.recv_buf);
>>>>>>> d0ce145 (added http libs and CMake integration)

	return 0;
}

static int on_headers_complete(struct http_parser *parser)
{
	struct http_request *req = CONTAINER_OF(parser,
<<<<<<< HEAD
											struct http_request,
											internal.parser);

	if (req->internal.response.http_cb &&
		req->internal.response.http_cb->on_headers_complete)
	{
		req->internal.response.http_cb->on_headers_complete(parser);
	}

	if (parser->status_code >= 500 && parser->status_code < 600)
	{
		LOG_DEBUG("Status %d, skipping body", parser->status_code);
=======
						struct http_request,
						internal.parser);

	if (req->internal.response.http_cb &&
	    req->internal.response.http_cb->on_headers_complete) {
		req->internal.response.http_cb->on_headers_complete(parser);
	}

	if (parser->status_code >= 500 && parser->status_code < 600) {
		NET_DBG("Status %d, skipping body", parser->status_code);
>>>>>>> d0ce145 (added http libs and CMake integration)
		return 1;
	}

	if ((req->method == HTTP_HEAD || req->method == HTTP_OPTIONS) &&
<<<<<<< HEAD
		req->internal.response.content_length > 0)
	{
		LOG_DEBUG("No body expected");
		return 1;
	}

	LOG_DEBUG("Headers complete");
=======
	    req->internal.response.content_length > 0) {
		NET_DBG("No body expected");
		return 1;
	}

	NET_DBG("Headers complete");
>>>>>>> d0ce145 (added http libs and CMake integration)

	return 0;
}

static int on_message_begin(struct http_parser *parser)
{
	struct http_request *req = CONTAINER_OF(parser,
<<<<<<< HEAD
											struct http_request,
											internal.parser);

	if (req->internal.response.http_cb &&
		req->internal.response.http_cb->on_message_begin)
	{
		req->internal.response.http_cb->on_message_begin(parser);
	}

	LOG_DEBUG("-- HTTP %s response (headers) --",
			  http_method_str(req->method));
=======
						struct http_request,
						internal.parser);

	if (req->internal.response.http_cb &&
	    req->internal.response.http_cb->on_message_begin) {
		req->internal.response.http_cb->on_message_begin(parser);
	}

	NET_DBG("-- HTTP %s response (headers) --",
		http_method_str(req->method));
>>>>>>> d0ce145 (added http libs and CMake integration)

	return 0;
}

static int on_message_complete(struct http_parser *parser)
{
	struct http_request *req = CONTAINER_OF(parser,
<<<<<<< HEAD
											struct http_request,
											internal.parser);

	if (req->internal.response.http_cb &&
		req->internal.response.http_cb->on_message_complete)
	{
		req->internal.response.http_cb->on_message_complete(parser);
	}

	LOG_DEBUG("-- HTTP %s response (complete) --",
			  http_method_str(req->method));
=======
						struct http_request,
						internal.parser);

	if (req->internal.response.http_cb &&
	    req->internal.response.http_cb->on_message_complete) {
		req->internal.response.http_cb->on_message_complete(parser);
	}

	NET_DBG("-- HTTP %s response (complete) --",
		http_method_str(req->method));
>>>>>>> d0ce145 (added http libs and CMake integration)

	req->internal.response.message_complete = 1;

	return 0;
}

static int on_chunk_header(struct http_parser *parser)
{
	struct http_request *req = CONTAINER_OF(parser,
<<<<<<< HEAD
											struct http_request,
											internal.parser);

	if (req->internal.response.http_cb &&
		req->internal.response.http_cb->on_chunk_header)
	{
=======
						struct http_request,
						internal.parser);

	if (req->internal.response.http_cb &&
	    req->internal.response.http_cb->on_chunk_header) {
>>>>>>> d0ce145 (added http libs and CMake integration)
		req->internal.response.http_cb->on_chunk_header(parser);
	}

	return 0;
}

static int on_chunk_complete(struct http_parser *parser)
{
	struct http_request *req = CONTAINER_OF(parser,
<<<<<<< HEAD
											struct http_request,
											internal.parser);

	if (req->internal.response.http_cb &&
		req->internal.response.http_cb->on_chunk_complete)
	{
=======
						struct http_request,
						internal.parser);

	if (req->internal.response.http_cb &&
	    req->internal.response.http_cb->on_chunk_complete) {
>>>>>>> d0ce145 (added http libs and CMake integration)
		req->internal.response.http_cb->on_chunk_complete(parser);
	}

	return 0;
}

static void http_client_init_parser(struct http_parser *parser,
<<<<<<< HEAD
									struct http_parser_settings *settings)
=======
				    struct http_parser_settings *settings)
>>>>>>> d0ce145 (added http libs and CMake integration)
{
	http_parser_init(parser, HTTP_RESPONSE);

	settings->on_body = on_body;
	settings->on_chunk_complete = on_chunk_complete;
	settings->on_chunk_header = on_chunk_header;
	settings->on_headers_complete = on_headers_complete;
	settings->on_header_field = on_header_field;
	settings->on_header_value = on_header_value;
	settings->on_message_begin = on_message_begin;
	settings->on_message_complete = on_message_complete;
	settings->on_status = on_status;
	settings->on_url = on_url;
}

/* Report a NULL HTTP response to the caller.
 * A NULL response is when the HTTP server intentionally closes the TLS socket (using FINACK)
 * without sending any HTTP payload.
 */
static void http_report_null(struct http_request *req)
{
<<<<<<< HEAD
	/********
	 *  @todo probably need to add asl support
	 */
	if (req->internal.response.cb)
	{
		LOG_DEBUG("Calling callback for Final Data"
				  "(NULL HTTP response)");
=======
	if (req->internal.response.cb) {
		NET_DBG("Calling callback for Final Data"
			"(NULL HTTP response)");
>>>>>>> d0ce145 (added http libs and CMake integration)

		/* Status code 0 representing a null response */
		req->internal.response.http_status_code = 0;

		/* Zero out related response metrics */
		req->internal.response.processed = 0;
		req->internal.response.data_len = 0;
		req->internal.response.content_length = 0;
		req->internal.response.body_frag_start = NULL;
		memset(req->internal.response.http_status, 0, HTTP_STATUS_STR_SIZE);

		req->internal.response.cb(&req->internal.response, HTTP_DATA_FINAL,
<<<<<<< HEAD
								  req->internal.user_data);
=======
					  req->internal.user_data);
>>>>>>> d0ce145 (added http libs and CMake integration)
	}
}

/* Report a completed HTTP transaction (with no error) to the caller */
static void http_report_complete(struct http_request *req)
{
<<<<<<< HEAD
	if (req->internal.response.cb)
	{
		LOG_DEBUG("Calling callback for %zd len data", req->internal.response.data_len);
		req->internal.response.cb(&req->internal.response, HTTP_DATA_FINAL,
								  req->internal.user_data);
=======
	if (req->internal.response.cb) {
		NET_DBG("Calling callback for %zd len data", req->internal.response.data_len);
		req->internal.response.cb(&req->internal.response, HTTP_DATA_FINAL,
					  req->internal.user_data);
>>>>>>> d0ce145 (added http libs and CMake integration)
	}
}

/* Report that some data has been received, but the HTTP transaction is still ongoing. */
static void http_report_progress(struct http_request *req)
{
<<<<<<< HEAD
	if (req->internal.response.cb)
	{
		LOG_DEBUG("Calling callback for partitioned %zd len data",
				  req->internal.response.data_len);

		req->internal.response.cb(&req->internal.response, HTTP_DATA_MORE,
								  req->internal.user_data);
	}
}
static int https_wait_data(int sock, asl_session *session,
						   struct http_request *req,
						   const k_timepoint_t req_end_timepoint)
{
	int total_received = 0;
	size_t offset = 0;
	int received, ret;
	struct zsock_pollfd fds[1];
	int nfds = 1;

	fds[0].fd = sock;
	fds[0].events = ZSOCK_POLLIN;

	do
	{
		k_ticks_t req_timeout_ticks =
			sys_timepoint_timeout(req_end_timepoint).ticks;
		int req_timeout_ms = k_ticks_to_ms_floor32(req_timeout_ticks);

		ret = zsock_poll(fds, nfds, req_timeout_ms);
		if (ret == 0)
		{
			LOG_DEBUG("Timeout");
			ret = -ETIMEDOUT;
			goto error;
		}
		else if (ret < 0)
		{
			ret = -errno;
			goto error;
		}
		if (fds[0].revents & (ZSOCK_POLLERR | ZSOCK_POLLNVAL))
		{
			ret = -errno;
			goto error;
		}
		else if (fds[0].revents & ZSOCK_POLLHUP)
		{
			/* Connection closed */
			goto closed;
		}
		else if (fds[0].revents & ZSOCK_POLLIN)
		{
			// asl_receive(session, req)
			received = asl_receive(session, req->internal.response.recv_buf + offset,
								   req->internal.response.recv_buf_len - offset);
			switch (received)
			{
			case ASL_CONN_CLOSED:
				goto closed;
				break;
			case ASL_WANT_READ:
				break;
			case ASL_ARGUMENT_ERROR:
				LOG_ERROR("wrong params");
				break;
			case ASL_INTERNAL_ERROR:
				ret = -errno;
				goto error;
				break;
				return -1;
			default:
				// my logic goes here:

				req->internal.response.data_len += received;
				(void)http_parser_execute(
					&req->internal.parser, &req->internal.parser_settings,
					req->internal.response.recv_buf + offset, received);
				break;
			}

			total_received += received;
			offset += received;

			if (offset >= req->internal.response.recv_buf_len)
			{
				offset = 0;
			}

			if (req->internal.response.message_complete)
			{
				http_report_complete(req);
				break;
			}
			else if (offset == 0)
			{
				http_report_progress(req);

				/* Re-use the result buffer and start to fill it again */
				req->internal.response.data_len = 0;
				req->internal.response.body_frag_start = NULL;
				req->internal.response.body_frag_len = 0;
			}
		}

	} while (true);

	return total_received;

closed:
	LOG_DEBUG("Connection closed");

	/* If connection was closed with no data sent, this is a NULL response, and is a special
	 * case valid response.
	 */
	if (total_received == 0)
	{
		http_report_null(req);
		return total_received;
	}

	/* Otherwise, connection was closed mid-way through response, and this should be
	 * considered an error.
	 */
	ret = -ECONNRESET;

error:
	LOG_DEBUG("Connection error (%d)", ret);
	return ret;
}
=======
	if (req->internal.response.cb) {
		NET_DBG("Calling callback for partitioned %zd len data",
			req->internal.response.data_len);

		req->internal.response.cb(&req->internal.response, HTTP_DATA_MORE,
					  req->internal.user_data);
	}
}
>>>>>>> d0ce145 (added http libs and CMake integration)

static int http_wait_data(int sock, struct http_request *req, const k_timepoint_t req_end_timepoint)
{
	int total_received = 0;
	size_t offset = 0;
	int received, ret;
	struct zsock_pollfd fds[1];
	int nfds = 1;

	fds[0].fd = sock;
	fds[0].events = ZSOCK_POLLIN;

<<<<<<< HEAD
	do
	{
=======
	do {
>>>>>>> d0ce145 (added http libs and CMake integration)
		k_ticks_t req_timeout_ticks =
			sys_timepoint_timeout(req_end_timepoint).ticks;
		int req_timeout_ms = k_ticks_to_ms_floor32(req_timeout_ticks);

		ret = zsock_poll(fds, nfds, req_timeout_ms);
<<<<<<< HEAD
		if (ret == 0)
		{
			LOG_DEBUG("Timeout");
			ret = -ETIMEDOUT;
			goto error;
		}
		else if (ret < 0)
		{
			ret = -errno;
			goto error;
		}
		if (fds[0].revents & (ZSOCK_POLLERR | ZSOCK_POLLNVAL))
		{
			ret = -errno;
			goto error;
		}
		else if (fds[0].revents & ZSOCK_POLLHUP)
		{
			/* Connection closed */
			goto closed;
		}
		else if (fds[0].revents & ZSOCK_POLLIN)
		{
			received = zsock_recv(sock, req->internal.response.recv_buf + offset,
								  req->internal.response.recv_buf_len - offset, 0);
			if (received == 0)
			{
				/* Connection closed */
				goto closed;
			}
			else if (received < 0)
			{
				ret = -errno;
				goto error;
			}
			else
			{
=======
		if (ret == 0) {
			LOG_DBG("Timeout");
			ret = -ETIMEDOUT;
			goto error;
		} else if (ret < 0) {
			ret = -errno;
			goto error;
		}
		if (fds[0].revents & (ZSOCK_POLLERR | ZSOCK_POLLNVAL)) {
			ret = -errno;
			goto error;
		} else if (fds[0].revents & ZSOCK_POLLHUP) {
			/* Connection closed */
			goto closed;
		} else if (fds[0].revents & ZSOCK_POLLIN) {
			received = zsock_recv(sock, req->internal.response.recv_buf + offset,
					      req->internal.response.recv_buf_len - offset, 0);
			if (received == 0) {
				/* Connection closed */
				goto closed;
			} else if (received < 0) {
				ret = -errno;
				goto error;
			} else {
>>>>>>> d0ce145 (added http libs and CMake integration)
				req->internal.response.data_len += received;

				(void)http_parser_execute(
					&req->internal.parser, &req->internal.parser_settings,
					req->internal.response.recv_buf + offset, received);
			}

			total_received += received;
			offset += received;

<<<<<<< HEAD
			if (offset >= req->internal.response.recv_buf_len)
			{
				offset = 0;
			}

			if (req->internal.response.message_complete)
			{
				http_report_complete(req);
				break;
			}
			else if (offset == 0)
			{
=======
			if (offset >= req->internal.response.recv_buf_len) {
				offset = 0;
			}

			if (req->internal.response.message_complete) {
				http_report_complete(req);
				break;
			} else if (offset == 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
				http_report_progress(req);

				/* Re-use the result buffer and start to fill it again */
				req->internal.response.data_len = 0;
				req->internal.response.body_frag_start = NULL;
				req->internal.response.body_frag_len = 0;
			}
		}

	} while (true);

	return total_received;

closed:
<<<<<<< HEAD
	LOG_DEBUG("Connection closed");
=======
	LOG_DBG("Connection closed");
>>>>>>> d0ce145 (added http libs and CMake integration)

	/* If connection was closed with no data sent, this is a NULL response, and is a special
	 * case valid response.
	 */
<<<<<<< HEAD
	if (total_received == 0)
	{
=======
	if (total_received == 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
		http_report_null(req);
		return total_received;
	}

	/* Otherwise, connection was closed mid-way through response, and this should be
	 * considered an error.
	 */
	ret = -ECONNRESET;

error:
<<<<<<< HEAD
	LOG_DEBUG("Connection error (%d)", ret);
=======
	LOG_DBG("Connection error (%d)", ret);
>>>>>>> d0ce145 (added http libs and CMake integration)
	return ret;
}

int http_client_req(int sock, struct http_request *req,
<<<<<<< HEAD
					int32_t timeout, void *user_data)
=======
		    int32_t timeout, void *user_data)
>>>>>>> d0ce145 (added http libs and CMake integration)
{
	/* Utilize the network usage by sending data in bigger blocks */
	char send_buf[MAX_SEND_BUF_LEN];
	const size_t send_buf_max_len = sizeof(send_buf);
	size_t send_buf_pos = 0;
	int total_sent = 0;
	int ret, total_recv, i;
	const char *method;
	k_timeout_t req_timeout = K_MSEC(timeout);
	k_timepoint_t req_end_timepoint = sys_timepoint_calc(req_timeout);

	if (sock < 0 || req == NULL || req->response == NULL ||
<<<<<<< HEAD
		req->recv_buf == NULL || req->recv_buf_len == 0)
	{
=======
	    req->recv_buf == NULL || req->recv_buf_len == 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
		return -EINVAL;
	}

	memset(&req->internal.response, 0, sizeof(req->internal.response));

	req->internal.response.http_cb = req->http_cb;
	req->internal.response.cb = req->response;
	req->internal.response.recv_buf = req->recv_buf;
	req->internal.response.recv_buf_len = req->recv_buf_len;
	req->internal.user_data = user_data;
	req->internal.sock = sock;

	method = http_method_str(req->method);

	ret = http_send_data(sock, send_buf, send_buf_max_len, &send_buf_pos,
<<<<<<< HEAD
						 req_end_timepoint, method,
						 " ", req->url, " ", req->protocol,
						 HTTP_CRLF, NULL);
	if (ret < 0)
	{
=======
				req_end_timepoint, method,
				" ", req->url, " ", req->protocol,
				HTTP_CRLF, NULL);
	if (ret < 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
		goto out;
	}

	total_sent += ret;

<<<<<<< HEAD
	if (req->port)
	{
		ret = http_send_data(sock, send_buf, send_buf_max_len,
							 &send_buf_pos, req_end_timepoint, "Host", ": ", req->host,
							 ":", req->port, HTTP_CRLF, NULL);

		if (ret < 0)
		{
=======
	if (req->port) {
		ret = http_send_data(sock, send_buf, send_buf_max_len,
					&send_buf_pos, req_end_timepoint, "Host", ": ", req->host,
					":", req->port, HTTP_CRLF, NULL);

		if (ret < 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
			goto out;
		}

		total_sent += ret;
<<<<<<< HEAD
	}
	else
	{
		ret = http_send_data(sock, send_buf, send_buf_max_len,
							 &send_buf_pos, req_end_timepoint, "Host", ": ", req->host,
							 HTTP_CRLF, NULL);

		if (ret < 0)
		{
=======
	} else {
		ret = http_send_data(sock, send_buf, send_buf_max_len,
				     &send_buf_pos, req_end_timepoint, "Host", ": ", req->host,
				     HTTP_CRLF, NULL);

		if (ret < 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
			goto out;
		}

		total_sent += ret;
	}

<<<<<<< HEAD
	if (req->optional_headers_cb)
	{
		ret = http_flush_data(sock, send_buf, send_buf_pos, req_end_timepoint);
		if (ret < 0)
		{
=======
	if (req->optional_headers_cb) {
		ret = http_flush_data(sock, send_buf, send_buf_pos, req_end_timepoint);
		if (ret < 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
			goto out;
		}

		send_buf_pos = 0;
		total_sent += ret;

		ret = req->optional_headers_cb(sock, req, user_data);
<<<<<<< HEAD
		if (ret < 0)
		{
=======
		if (ret < 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
			goto out;
		}

		total_sent += ret;
<<<<<<< HEAD
	}
	else
	{
		for (i = 0; req->optional_headers && req->optional_headers[i];
			 i++)
		{
			ret = http_send_data(sock, send_buf, send_buf_max_len,
								 &send_buf_pos, req_end_timepoint,
								 req->optional_headers[i], NULL);
			if (ret < 0)
			{
=======
	} else {
		for (i = 0; req->optional_headers && req->optional_headers[i];
		     i++) {
			ret = http_send_data(sock, send_buf, send_buf_max_len,
					     &send_buf_pos, req_end_timepoint,
					     req->optional_headers[i], NULL);
			if (ret < 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
				goto out;
			}

			total_sent += ret;
		}
	}

<<<<<<< HEAD
	for (i = 0; req->header_fields && req->header_fields[i]; i++)
	{
		ret = http_send_data(sock, send_buf, send_buf_max_len,
							 &send_buf_pos, req_end_timepoint, req->header_fields[i],
							 NULL);
		if (ret < 0)
		{
=======
	for (i = 0; req->header_fields && req->header_fields[i]; i++) {
		ret = http_send_data(sock, send_buf, send_buf_max_len,
				     &send_buf_pos, req_end_timepoint, req->header_fields[i],
				     NULL);
		if (ret < 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
			goto out;
		}

		total_sent += ret;
	}

<<<<<<< HEAD
	if (req->content_type_value)
	{
		ret = http_send_data(sock, send_buf, send_buf_max_len,
							 &send_buf_pos, req_end_timepoint, "Content-Type", ": ",
							 req->content_type_value, HTTP_CRLF, NULL);
		if (ret < 0)
		{
=======
	if (req->content_type_value) {
		ret = http_send_data(sock, send_buf, send_buf_max_len,
				     &send_buf_pos, req_end_timepoint, "Content-Type", ": ",
				     req->content_type_value, HTTP_CRLF, NULL);
		if (ret < 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
			goto out;
		}

		total_sent += ret;
	}

<<<<<<< HEAD
	if (req->payload || req->payload_cb)
	{
		if (req->payload_len)
		{
			char content_len_str[HTTP_CONTENT_LEN_SIZE];

			ret = snprintk(content_len_str, HTTP_CONTENT_LEN_SIZE,
						   "%zd", req->payload_len);
			if (ret <= 0 || ret >= HTTP_CONTENT_LEN_SIZE)
			{
=======
	if (req->payload || req->payload_cb) {
		if (req->payload_len) {
			char content_len_str[HTTP_CONTENT_LEN_SIZE];

			ret = snprintk(content_len_str, HTTP_CONTENT_LEN_SIZE,
				       "%zd", req->payload_len);
			if (ret <= 0 || ret >= HTTP_CONTENT_LEN_SIZE) {
>>>>>>> d0ce145 (added http libs and CMake integration)
				ret = -ENOMEM;
				goto out;
			}

			ret = http_send_data(sock, send_buf, send_buf_max_len,
<<<<<<< HEAD
								 &send_buf_pos, req_end_timepoint,
								 "Content-Length", ": ",
								 content_len_str, HTTP_CRLF,
								 HTTP_CRLF, NULL);
		}
		else
		{
			ret = http_send_data(sock, send_buf, send_buf_max_len,
								 &send_buf_pos, req_end_timepoint, HTTP_CRLF, NULL);
		}

		if (ret < 0)
		{
=======
						&send_buf_pos, req_end_timepoint,
						"Content-Length", ": ",
						content_len_str, HTTP_CRLF,
						HTTP_CRLF, NULL);
		} else {
			ret = http_send_data(sock, send_buf, send_buf_max_len,
				     &send_buf_pos, req_end_timepoint, HTTP_CRLF, NULL);
		}

		if (ret < 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
			goto out;
		}

		total_sent += ret;

		ret = http_flush_data(sock, send_buf, send_buf_pos, req_end_timepoint);
<<<<<<< HEAD
		if (ret < 0)
		{
=======
		if (ret < 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
			goto out;
		}

		send_buf_pos = 0;
		total_sent += ret;

<<<<<<< HEAD
		if (req->payload_cb)
		{
			ret = req->payload_cb(sock, req, user_data);
			if (ret < 0)
			{
=======
		if (req->payload_cb) {
			ret = req->payload_cb(sock, req, user_data);
			if (ret < 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
				goto out;
			}

			total_sent += ret;
<<<<<<< HEAD
		}
		else
		{
			uint32_t length;

			if (req->payload_len == 0)
			{
				length = strlen(req->payload);
			}
			else
			{
=======
		} else {
			uint32_t length;

			if (req->payload_len == 0) {
				length = strlen(req->payload);
			} else {
>>>>>>> d0ce145 (added http libs and CMake integration)
				length = req->payload_len;
			}

			ret = sendall(sock, req->payload, length, req_end_timepoint);
<<<<<<< HEAD
			if (ret < 0)
			{
=======
			if (ret < 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
				goto out;
			}

			total_sent += length;
		}
<<<<<<< HEAD
	}
	else
	{
		ret = http_send_data(sock, send_buf, send_buf_max_len,
							 &send_buf_pos, req_end_timepoint, HTTP_CRLF, NULL);
		if (ret < 0)
		{
=======
	} else {
		ret = http_send_data(sock, send_buf, send_buf_max_len,
				     &send_buf_pos, req_end_timepoint, HTTP_CRLF, NULL);
		if (ret < 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
			goto out;
		}

		total_sent += ret;
	}

<<<<<<< HEAD
	if (send_buf_pos > 0)
	{
		ret = http_flush_data(sock, send_buf, send_buf_pos, req_end_timepoint);
		if (ret < 0)
		{
=======
	if (send_buf_pos > 0) {
		ret = http_flush_data(sock, send_buf, send_buf_pos, req_end_timepoint);
		if (ret < 0) {
>>>>>>> d0ce145 (added http libs and CMake integration)
			goto out;
		}

		total_sent += ret;
	}

<<<<<<< HEAD
	LOG_DEBUG("Sent %d bytes", total_sent);

	http_client_init_parser(&req->internal.parser,
							&req->internal.parser_settings);

	/* Request is sent, now wait data to be received */
	total_recv = http_wait_data(sock, req, req_end_timepoint);
	if (total_recv < 0)
	{
		LOG_DEBUG("Wait data failure (%d)", total_recv);
=======
	NET_DBG("Sent %d bytes", total_sent);

	http_client_init_parser(&req->internal.parser,
				&req->internal.parser_settings);

	/* Request is sent, now wait data to be received */
	total_recv = http_wait_data(sock, req, req_end_timepoint);
	if (total_recv < 0) {
		NET_DBG("Wait data failure (%d)", total_recv);
>>>>>>> d0ce145 (added http libs and CMake integration)
		ret = total_recv;
		goto out;
	}

<<<<<<< HEAD
	LOG_DEBUG("Received %d bytes", total_recv);

	return total_sent;

out:
	return ret;
}

int https_client_req(int sock, asl_session *session, struct http_request *req,
					 int32_t timeout, void *user_data)
{
	/* Utilize the network usage by sending data in bigger blocks */
	char send_buf[MAX_SEND_BUF_LEN];
	const size_t send_buf_max_len = sizeof(send_buf);
	size_t send_buf_pos = 0;
	int total_sent = 0;
	int ret, total_recv, i;
	const char *method;
	k_timeout_t req_timeout = K_MSEC(timeout);
	k_timepoint_t req_end_timepoint = sys_timepoint_calc(req_timeout);

	if (sock < 0 || session == NULL || req == NULL || req->response == NULL ||
		req->recv_buf == NULL || req->recv_buf_len == 0)
	{
		return -EINVAL;
	}

	memset(&req->internal.response, 0, sizeof(req->internal.response));

	req->internal.response.http_cb = req->http_cb;
	req->internal.response.cb = req->response;
	req->internal.response.recv_buf = req->recv_buf;
	req->internal.response.recv_buf_len = req->recv_buf_len;
	req->internal.user_data = user_data;
	req->internal.sock = sock;

	method = http_method_str(req->method);

	ret = https_send_data(session, send_buf, send_buf_max_len, &send_buf_pos,
						  req_end_timepoint, method,
						  " ", req->url, " ", req->protocol,
						  HTTP_CRLF, NULL);
	if (ret < 0)
	{
		goto out;
	}

	total_sent += ret;

	if (req->port)
	{
		ret = https_send_data(session, send_buf, send_buf_max_len,
							  &send_buf_pos, req_end_timepoint, "Host", ": ", req->host,
							  ":", req->port, HTTP_CRLF, NULL);

		if (ret < 0)
		{
			goto out;
		}

		total_sent += ret;
	}
	else
	{
		ret = https_send_data(session, send_buf, send_buf_max_len,
							  &send_buf_pos, req_end_timepoint, "Host", ": ", req->host,
							  HTTP_CRLF, NULL);

		if (ret < 0)
		{
			goto out;
		}

		total_sent += ret;
	}

	if (req->optional_headers_cb)
	{
		ret = https_flush_data(session, send_buf, send_buf_pos, req_end_timepoint);
		if (ret < 0)
		{
			goto out;
		}

		send_buf_pos = 0;
		total_sent += ret;

		LOG_ERROR("optional headers_cb for https must use asl");
		ret = req->optional_headers_cb(sock, req, user_data);
		if (ret < 0)
		{
			goto out;
		}

		total_sent += ret;
	}
	else
	{
		for (i = 0; req->optional_headers && req->optional_headers[i];
			 i++)
		{
			ret = https_send_data(session, send_buf, send_buf_max_len,
								  &send_buf_pos, req_end_timepoint,
								  req->optional_headers[i], NULL);
			if (ret < 0)
			{
				goto out;
			}

			total_sent += ret;
		}
	}

	for (i = 0; req->header_fields && req->header_fields[i]; i++)
	{
		ret = https_send_data(session, send_buf, send_buf_max_len,
							  &send_buf_pos, req_end_timepoint, req->header_fields[i],
							  NULL);
		if (ret < 0)
		{
			goto out;
		}

		total_sent += ret;
	}

	if (req->content_type_value)
	{
		ret = https_send_data(session, send_buf, send_buf_max_len,
							  &send_buf_pos, req_end_timepoint, "Content-Type", ": ",
							  req->content_type_value, HTTP_CRLF, NULL);
		if (ret < 0)
		{
			goto out;
		}

		total_sent += ret;
	}

	if (req->payload || req->payload_cb)
	{
		if (req->payload_len)
		{
			char content_len_str[HTTP_CONTENT_LEN_SIZE];

			ret = snprintk(content_len_str, HTTP_CONTENT_LEN_SIZE,
						   "%zd", req->payload_len);
			if (ret <= 0 || ret >= HTTP_CONTENT_LEN_SIZE)
			{
				ret = -ENOMEM;
				goto out;
			}

			ret = https_send_data(session, send_buf, send_buf_max_len,
								  &send_buf_pos, req_end_timepoint,
								  "Content-Length", ": ",
								  content_len_str, HTTP_CRLF,
								  HTTP_CRLF, NULL);
		}
		else
		{
			ret = https_send_data(session, send_buf, send_buf_max_len,
								  &send_buf_pos, req_end_timepoint, HTTP_CRLF, NULL);
		}

		if (ret < 0)
		{
			goto out;
		}

		total_sent += ret;

		ret = https_flush_data(session, send_buf, send_buf_pos, req_end_timepoint);
		if (ret < 0)
		{
			goto out;
		}

		send_buf_pos = 0;
		total_sent += ret;

		if (req->payload_cb)
		{
			ret = req->payload_cb(sock, req, user_data);
			if (ret < 0)
			{
				goto out;
			}

			total_sent += ret;
		}
		else
		{
			uint32_t length;

			if (req->payload_len == 0)
			{
				length = strlen(req->payload);
			}
			else
			{
				length = req->payload_len;
			}

			ret = asl_sendall(session, req->payload, length, req_end_timepoint);
			if (ret < 0)
			{
				goto out;
			}

			total_sent += length;
		}
	}
	else
	{
		ret = https_send_data(session, send_buf, send_buf_max_len,
							  &send_buf_pos, req_end_timepoint, HTTP_CRLF, NULL);
		if (ret < 0)
		{
			goto out;
		}

		total_sent += ret;
	}

	if (send_buf_pos > 0)
	{
		ret = https_flush_data(session, send_buf, send_buf_pos, req_end_timepoint);
		if (ret < 0)
		{
			goto out;
		}

		total_sent += ret;
	}

	LOG_DEBUG("Sent %d bytes", total_sent);

	http_client_init_parser(&req->internal.parser,
							&req->internal.parser_settings);

	/* Request is sent, now wait data to be received */
	/***
	 * @todo this functionality must be tested
	 */
	total_recv = https_wait_data(sock, session, req, req_end_timepoint);
	/**
	 * @todo error handling
	 */
	// total_recv = http_wait_data(sock, req, req_end_timepoint);
	if (total_recv < 0)
	{
		LOG_DEBUG("Wait data failure (%d)", total_recv);
		ret = total_recv;
		goto out;
	}

	LOG_DEBUG("Received %d bytes", total_recv);
=======
	NET_DBG("Received %d bytes", total_recv);
>>>>>>> d0ce145 (added http libs and CMake integration)

	return total_sent;

out:
	return ret;
}
