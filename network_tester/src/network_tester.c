
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>
#include <limits.h>
#include <pthread.h>

#include "logging.h"
#include "networking.h"
#include "timing_metrics.h"

#include "network_tester.h"


LOG_MODULE_CREATE(network_tester);


#define ERROR_OUT(...) { LOG_ERROR(__VA_ARGS__); ret = -1; goto cleanup; }

#define RECV_BUFFER_SIZE 1024

#if defined(__ZEPHYR__)

#define BACKEND_STACK_SIZE (32*1024)
Z_KERNEL_STACK_DEFINE_IN(backend_stack, BACKEND_STACK_SIZE, \
                __attribute__((section(CONFIG_RAM_SECTION_STACKS_2))));
#endif


enum network_tester_management_message_type
{
        MANAGEMENT_MSG_START,
	MANAGEMENT_MSG_STATUS_REQUEST,
	MANAGEMENT_MSG_SHUTDOWN,
	MANAGEMENT_RESPONSE
};

typedef struct network_tester_management_message
{
	enum network_tester_management_message_type type;

        union
        {
                network_tester_config config;      /* START */
                network_tester_status* status_ptr; /* STATUS_REQUEST */
                int dummy_unused;                  /* SHUTDOWN */
		int response_code;                 /* RESPONSE */
        }
        payload;
}
network_tester_management_message;


typedef struct network_tester
{
        bool running;
        bool use_tls;
        int tcp_socket;
        int progress_percent;
        int iterations;
        asl_endpoint* tls_endpoint;
        asl_session* tls_session;
        timing_metrics* handshake_times;
        pthread_t thread;
        pthread_attr_t thread_attr;
        int management_socket_pair[2];
        uint8_t recv_buffer[RECV_BUFFER_SIZE];
}
network_tester;


/* File global variables */
static network_tester the_tester = {
        .running = false,
        .use_tls = false,
        .tcp_socket = -1,
        .progress_percent = 0,
        .iterations = 0,
        .tls_endpoint = NULL,
        .tls_session = NULL,
        .handshake_times = NULL,
        .management_socket_pair = {-1, -1},
};


/* Internal method declarations */
static void asl_log_callback(int32_t level, char const* message);
static void print_progress(size_t count, network_tester* tester);
static void* network_tester_main_thread(void* ptr);
static int send_management_message(int socket, network_tester_management_message const* msg);
static int read_management_message(int socket, network_tester_management_message* msg);
static int handle_management_message(network_tester* tester, int socket);
static void tester_cleanup(network_tester* tester);


static void asl_log_callback(int32_t level, char const* message)
{
        switch (level)
        {
        case ASL_LOG_LEVEL_ERR:
                LOG_ERROR("%s", message);
                break;
        case ASL_LOG_LEVEL_WRN:
                LOG_WARN("%s", message);
                break;
        case ASL_LOG_LEVEL_INF:
                LOG_INFO("%s", message);
                break;
        case ASL_LOG_LEVEL_DBG:
                LOG_DEBUG("%s", message);
                break;
        default:
                LOG_ERROR("unknown log level %d: %s", level, message);
                break;
        }
}


static void print_progress(size_t count, network_tester* tester)
{
        const int bar_width = 50;

        float progress = ((float) count) / tester->iterations;
        int progress_percent = progress * 100;
        int bar_length = progress * bar_width;

        /* Early exit in case the percentage hasn't changed */
        if (progress_percent == tester->progress_percent)
                return;

        tester->progress_percent = progress_percent;

        /* Print progress bar */
        printf("\033[A\rProgress: [");
        for (int i = 0; i < bar_length; ++i)
        {
                printf("#");
        }
        for (int i = bar_length; i < bar_width; ++i)
        {
                printf(" ");
        }
        printf("] %d%%\r\n", progress_percent);

        fflush(stdout);
}


static void* network_tester_main_thread(void* ptr)
{
        network_tester* tester = (network_tester*) ptr;
        network_tester_config* config = NULL;
        int ret = 0;
        uint8_t test_message[] = {0x55};

        tester->running = true;

        /* Read the START message with the configuration */
        network_tester_management_message start_msg = {0};
        ret = read_management_message(tester->management_socket_pair[1], &start_msg);
        if (ret != 0)
        {
                ERROR_OUT("Error reading start message");
        }
        else if (start_msg.type != MANAGEMENT_MSG_START)
        {
                ERROR_OUT("Received invalid start message");
        }
        config = &start_msg.payload.config;

        tester->iterations = config->iterations;
        tester->use_tls = config->use_tls;

        setblocking(tester->management_socket_pair[1], false);

        /* Create the timing metrics */
        tester->handshake_times = timing_metrics_create("handshake_time", config->iterations, LOG_MODULE_GET());

        /* Initialize the Agile Security Library */
        if (config->use_tls == true)
        {
                LOG_DEBUG("Initializing ASL");

                asl_configuration asl_config = {
                        .logging_enabled = true,
                        .log_level = LOG_LVL_GET(),
                        .custom_log_callback = asl_log_callback,
                };
                ret = asl_init(&asl_config);
                if (ret != ASL_SUCCESS)
                        ERROR_OUT("Error initializing ASL: %d (%s)", ret, asl_error_message(ret));
        }

        /* Configure TCP destination */
        struct sockaddr_in target_addr = {
                        .sin_family = AF_INET,
                        .sin_port = htons(config->target_port)
        };
        inet_pton(target_addr.sin_family, config->target_ip, &target_addr.sin_addr);

        /* Configure TLS endpoint */
        if (config->use_tls == true)
        {
                LOG_DEBUG("Setting up TLS client endpoint");

                tester->tls_endpoint = asl_setup_client_endpoint(&config->tls_config);
                if (tester->tls_endpoint == NULL)
                        ERROR_OUT("Error creating TLS endpoint");
        }

        /* Send response */
        start_msg.type = MANAGEMENT_RESPONSE;
        start_msg.payload.response_code = 0;
        ret = send_management_message(tester->management_socket_pair[1], &start_msg);
        if (ret < 0)
        {
                ERROR_OUT("Error sending response");
        }

        /* Create the output file (if requested) */
        if (config->output_path != NULL)
        {
                ret = timing_metrics_prepare_output_file(tester->handshake_times, config->output_path);
                if (ret < 0)
                        ERROR_OUT("Error creating output file");
        }

        if (!config->silent_test)
                printf("\r\n"); /* New line necessary for proper progress print */

        /* Main loop */
        for (int i = 0; i < config->iterations; i++)
        {
                /* Create the TCP socket for the outgoing connection */
                tester->tcp_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (tester->tcp_socket == -1)
                        ERROR_OUT("Error creating TCP socket");

                /* Set TCP_NODELAY option to disable Nagle algorithm */
                if (setsockopt(tester->tcp_socket, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0)
                        ERROR_OUT("setsockopt(TCP_NODELAY) failed: error %d", errno);

        #if !defined(__ZEPHYR__)
                /* Set retry count to send a total of 3 SYN packets => Timeout ~7s */
                if (setsockopt(tester->tcp_socket, IPPROTO_TCP, TCP_SYNCNT, &(int){2}, sizeof(int)) < 0)
                        ERROR_OUT("setsockopt(TCP_SYNCNT) failed: error %d", errno);
        #endif

                /* Create the TLS session */
                if (config->use_tls == true)
                {
                        LOG_DEBUG("Creating TLS session");

                        tester->tls_session = asl_create_session(tester->tls_endpoint, tester->tcp_socket);
                        if (tester->tls_session == NULL)
                                ERROR_OUT("Error creating TLS session");
                }

                timing_metrics_start_measurement(tester->handshake_times);

                /* Connect to the peer */
                LOG_DEBUG("Establishing TCP connection");
                ret = connect(tester->tcp_socket, (struct sockaddr*) &target_addr, sizeof(target_addr));
                if ((ret != 0) && (errno != EINPROGRESS))
                        ERROR_OUT("Error establishing TCP connection to target peer");

                /* Do TLS handshake */
                if (config->use_tls == true)
                {
                        LOG_DEBUG("Performing TLS handshake");

                        ret = asl_handshake(tester->tls_session);
                        if (ret != ASL_SUCCESS)
                                ERROR_OUT("Error performing TLS handshake: %d (%s)", ret, asl_error_message(ret));
                }

                /* Write message to the peer */
                if (config->use_tls)
                {
                        ret = asl_send(tester->tls_session, test_message, sizeof(test_message));
                        if (ret != ASL_SUCCESS)
                                ERROR_OUT("Error sending message: %d (%s)", ret, asl_error_message(ret));
                }
                else
                {
                        ret = send(tester->tcp_socket, test_message, sizeof(test_message), 0);
                        if (ret == -1)
                                ERROR_OUT("Error sending message");
                }

                /* Read response */
                if (config->use_tls)
                {
                        ret = asl_receive(tester->tls_session, tester->recv_buffer, sizeof(test_message));
                        if (ret < 0)
                                ERROR_OUT("Error receiving message: %d (%s)", ret, asl_error_message(ret));
                }
                else
                {
                        ret = recv(tester->tcp_socket, tester->recv_buffer, sizeof(test_message), 0);
                        if (ret == -1)
                                ERROR_OUT("Error receiving message");
                }

                if ((ret != sizeof(test_message)) || (memcmp(test_message, tester->recv_buffer, sizeof(test_message)) != 0))
                        ERROR_OUT("Echo NOT successfull");

                timing_metrics_end_measurement(tester->handshake_times);

                /* Close connection */
                if (config->use_tls)
                {
                        asl_close_session(tester->tls_session);
                        asl_free_session(tester->tls_session);
                        tester->tls_session = NULL;
                }

                close(tester->tcp_socket);
                tester->tcp_socket = -1;

                /* Print progress bar to the console */
                if (!config->silent_test)
                        print_progress(i+1, tester);

                /* Check if we have received a management message */
                ret = handle_management_message(tester, tester->management_socket_pair[1]);
                if (ret > 0)
                {
                        /* We have received a STOP message */
                        break;
                }

                if (config->delay > 0)
                {
                        usleep(config->delay * 1000);
                }
        }

        /* Print results */
        timing_metrics_results results;
        timing_metrics_get_results(tester->handshake_times, &results);

        LOG_INFO("Handshake time");
        LOG_INFO("Number of measurements: %lu", results.num_measurements);
        LOG_INFO("Minimum: %.3fms", (double) results.min / 1000);
        LOG_INFO("Maximum: %.3fms", (double) results.max / 1000);
        LOG_INFO("Average: %.3fms", results.avg / 1000);
        LOG_INFO("Standard deviation: %.3fms", results.std_dev / 1000);
        LOG_INFO("Median: %.3fms", results.median / 1000);
        LOG_INFO("90th percentile: %.3fms", results.percentile_90 / 1000);
        LOG_INFO("99th percentile: %.3fms", results.percentile_99 / 1000);

        /* Store results in file */
        if (config->output_path != NULL)
        {
                ret = timing_metrics_write_to_file(tester->handshake_times);
                if (ret < 0)
                        ERROR_OUT("Error writing results to file");
        }

cleanup:
        /* Cleanup */
        tester_cleanup(tester);

        LOG_DEBUG("Network tester thread terminated");

        /* Detach the thread here, as it is terminating by itself. With that,
         * the thread resources are freed immediatelly. */
        pthread_detach(pthread_self());

        return NULL;
}


static int send_management_message(int socket, network_tester_management_message const* msg)
{
        int ret = 0;
        static const int max_retries = 5;
        int retries = 0;

        while ((ret <= 0) && (retries < max_retries))
        {
                ret = send(socket, msg, sizeof(network_tester_management_message), 0);
                if (ret < 0)
                {
                        if (errno != EAGAIN)
                        {
                                LOG_DEBUG("Error sending message: %d (%s)", errno, strerror(errno));
                                return -1;
                        }

                        usleep(10 * 1000);
                }
                else if (ret != sizeof(network_tester_management_message))
                {
                        LOG_ERROR("Sent invalid message");
                        return -1;
                }

                retries++;
        }

        if (retries >= max_retries)
        {
                LOG_ERROR("Failed to send message after %d retries", max_retries);
                return -1;
        }

        return 0;
}


static int read_management_message(int socket, network_tester_management_message* msg)
{
        int ret = recv(socket, msg, sizeof(network_tester_management_message), 0);
        if (ret < 0 && errno == EAGAIN )
        {
                /* No message available on the non-blocking socket. This error condition is no
                 * actual error in this application. We indicate that with the +1 return value.
                 */
                LOG_DEBUG("No message available");
                return 1;
        }
        else if (ret < 0)
        {
                LOG_DEBUG("Error receiving mgmt message: %d (%s)", errno, strerror(errno));
                return -1;
        }
        else if (ret != sizeof(network_tester_management_message))
        {
                LOG_ERROR("Received invalid response (ret=%d; expected=%lu)",
                          ret, sizeof(network_tester_management_message));
                return -1;
        }

        return 0;
}


/* Handle incoming management messages.
 *
 * Return 0 in case the message has been processed successfully, -1 otherwise. In case the connection thread has
 * to be stopped and the connection has to be cleaned up, +1 in returned.
 */
static int handle_management_message(network_tester* tester, int socket)
{
        /* Read message from the management socket. */
	network_tester_management_message msg;
	int ret = read_management_message(socket, &msg);
	if (ret < 0)
	{
		LOG_ERROR("Error reading management message: %d", ret);
		return -1;
	}
        else if (ret > 0)
        {
                /* No message available */
                return 0;
        }

        switch (msg.type)
        {
		case MANAGEMENT_MSG_STATUS_REQUEST:
                {
			/* Fill status object */
			network_tester_status* status = msg.payload.status_ptr;
			status->is_running = tester->running;
                        status->progress_percent = tester->progress_percent;

                        /* Send response */
			msg.type = MANAGEMENT_RESPONSE;
			msg.payload.response_code = 0;
                        ret = send_management_message(socket, &msg);
                        break;
                }
		case MANAGEMENT_MSG_SHUTDOWN:
                {
                        /* Return 1 to indicate we have to stop the connection thread and cleanup */
                        ret = 1;

                        /* Send response */
			msg.type = MANAGEMENT_RESPONSE;
			msg.payload.response_code = 0;

                        /* Do not update ret here to make sure the thread terminates */
                        send_management_message(socket, &msg);

			LOG_DEBUG("Received shutdown message, stopping tester");
                        break;
                }
                default:
                        LOG_ERROR("Received invalid management message: msg->type=%d", msg.type);
                        ret = -1;
                        break;
	}

	return ret;
}


static void tester_cleanup(network_tester* tester)
{
        /* Clean up */
        if ((tester->use_tls == true) && (tester->tls_session != NULL))
        {
                asl_free_session(tester->tls_session);
        }
        if ((tester->use_tls == true) && (tester->tls_endpoint != NULL))
        {
                asl_free_endpoint(tester->tls_endpoint);
                asl_cleanup();
        }
        if (tester->tcp_socket != -1)
        {
                close(tester->tcp_socket);
        }

        timing_metrics_destroy(&tester->handshake_times);

        /* Close the management socket pair */
        if (tester->management_socket_pair[0] != -1)
        {
                close(tester->management_socket_pair[0]);
                tester->management_socket_pair[0] = -1;
        }
        if (tester->management_socket_pair[1] != -1)
        {
                close(tester->management_socket_pair[1]);
                tester->management_socket_pair[1] = -1;
        }

        tester->running = false;
}


/* Start a new thread and run the network tester application.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int network_tester_run(network_tester_config const* config)
{
        /* Set the log level */
        LOG_LVL_SET(config->log_level);

        /* Init app config */
        the_tester.management_socket_pair[0] = -1;
        the_tester.management_socket_pair[1] = -1;

        pthread_attr_init(&the_tester.thread_attr);
        pthread_attr_setdetachstate(&the_tester.thread_attr, PTHREAD_CREATE_JOINABLE);

#if defined(__ZEPHYR__)
        /* We have to properly set the attributes with the stack to use for Zephyr. */
        pthread_attr_setstack(&the_tester.thread_attr, &backend_stack, K_THREAD_STACK_SIZEOF(backend_stack));
#endif

        /* Create the socket pair for external management */
        int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, the_tester.management_socket_pair);
        if (ret < 0)
                ERROR_OUT("Error creating socket pair for management: %d (%s)", errno, strerror(errno));

        LOG_DEBUG("Created management socket pair (%d, %d)", the_tester.management_socket_pair[0],
                                                            the_tester.management_socket_pair[1]);

        /* Create the new thread */
        ret = pthread_create(&the_tester.thread, &the_tester.thread_attr, network_tester_main_thread, &the_tester);
        if (ret != 0)
                ERROR_OUT("Error starting network tester thread: %d (%s)", errno, strerror(errno));

        /* Create a START message */
        network_tester_management_message msg = {0};
        msg.type = MANAGEMENT_MSG_START;
        msg.payload.config = *config;

        /* Send request */
        ret = send_management_message(the_tester.management_socket_pair[0], &msg);
        if (ret < 0)
                ERROR_OUT("Error sending management message");

        /* Wait for response */
        ret = read_management_message(the_tester.management_socket_pair[0], &msg);
        if (ret != 0)
        {
                ERROR_OUT("Error reading management response");
        }
        else if (msg.type != MANAGEMENT_RESPONSE)
        {
                ERROR_OUT("Received invalid response");
        }
        else if (msg.payload.response_code < 0)
        {
                ERROR_OUT("Error starting network tester (error %d)", msg.payload.response_code);
        }

        return msg.payload.response_code;

cleanup:
        tester_cleanup(&the_tester);

        return ret;
}


/* Querry status information from the network tester.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int network_tester_get_status(network_tester_status* status)
{
        if ((the_tester.management_socket_pair[0] < 0) || (the_tester.management_socket_pair[0] < 0))
        {
                LOG_DEBUG("Tester thread not running");
                return -1;
        }

        /* Create the STATUS_REQUEST message. Object is used for the response, too. */
        network_tester_management_message msg = {0};
        msg.type = MANAGEMENT_MSG_STATUS_REQUEST;
        msg.payload.status_ptr = status;

        /* Send request */
        int ret = send_management_message(the_tester.management_socket_pair[0], &msg);
        if (ret != 0)
        {
                /* Background thread terminated */
                status->is_running = false;
                return 0;
        }

        /* Wait for response */
        ret = read_management_message(the_tester.management_socket_pair[0], &msg);
        if (ret != 0)
        {
                /* Background thread terminated */
                status->is_running = false;
                return 0;
        }
        else if (msg.type != MANAGEMENT_RESPONSE)
        {
                LOG_ERROR("Received invalid response");
                return -1;
        }
        else if (msg.payload.response_code < 0)
        {
                LOG_ERROR("Error obtaining tester status (error %d)", msg.payload.response_code);
                return -1;
        }

        return 0;
}


/* Terminate the network tester application.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int network_tester_terminate(void)
{
        if ((the_tester.management_socket_pair[0] < 0) ||
            (the_tester.management_socket_pair[0] < 0))
        {
                LOG_DEBUG("Tester thread not running");
                return -1;
        }

        /* Send shutdown message to the management socket */
	network_tester_management_message msg = {0};
        msg.type = MANAGEMENT_MSG_SHUTDOWN;
        msg.payload.dummy_unused = 0;

	/* Send request */
        int ret = send_management_message(the_tester.management_socket_pair[0], &msg);
        if (ret < 0)
        {
                return -1;
        }

        /* Wait for response */
        ret = read_management_message(the_tester.management_socket_pair[0], &msg);
        if (ret < 0)
        {
                return -1;
        }
        else if (msg.type != MANAGEMENT_RESPONSE)
        {
                LOG_ERROR("Received invalid response");
                return -1;
        }
        else if (msg.payload.response_code < 0)
        {
                LOG_ERROR("Error stopping bridge (error %d)", msg.payload.response_code);
                return -1;
        }

        /* Wait until the main thread is terminated */
        pthread_join(the_tester.thread, NULL);

        return 0;
}
