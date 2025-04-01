
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

#include "logging.h"
#include "networking.h"
#include "threading.h"
#include "timing_metrics.h"

#include "network_tester.h"

LOG_MODULE_CREATE(network_tester);

#define ERROR_OUT(...)                                                                             \
        {                                                                                          \
                LOG_ERROR(__VA_ARGS__);                                                            \
                ret = -1;                                                                          \
                goto cleanup;                                                                      \
        }

#if defined(__ZEPHYR__)

#define TESTER_STACK_SIZE (32 * 1024)
Z_KERNEL_STACK_DEFINE_IN(tester_stack,
                         TESTER_STACK_SIZE,
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
        } payload;
} network_tester_management_message;

typedef struct network_tester
{
        bool running;
        int return_code;
        int progress_percent;
        int total_iterations;
        int tcp_socket;
        struct addrinfo* target_addr;
        struct addrinfo* current_target;
        network_tester_config* config;
        asl_endpoint* tls_endpoint;
        asl_session* tls_session;
        timing_metrics* handshake_times;
        timing_metrics* messsage_latency_times;
        uint8_t* tx_buffer;
        uint8_t* rx_buffer;
        pthread_t thread;
        int management_socket_pair[2];
} network_tester;

/* File global variables */
static network_tester the_tester = {
        .running = false,
        .return_code = 0,
        .progress_percent = -1,
        .total_iterations = 0,
        .tcp_socket = -1,
        .target_addr = NULL,
        .current_target = NULL,
        .config = NULL,
        .tls_endpoint = NULL,
        .tls_session = NULL,
        .handshake_times = NULL,
        .messsage_latency_times = NULL,
        .tx_buffer = NULL,
        .rx_buffer = NULL,
        .management_socket_pair = {-1, -1},
};

/* Internal method declarations */
static void asl_log_callback(int32_t level, char const* message);
static void print_progress(network_tester* tester, size_t count);
static int network_init(network_tester* tester);
static int connection_setup(network_tester* tester);
static int test_echo_message(network_tester* tester, size_t num_of_bytes);
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

static void print_progress(network_tester* tester, size_t count)
{
        const int bar_width = 50;

        float progress = ((float) count) / tester->total_iterations;
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
                printf("=");
        }
        for (int i = bar_length; i < bar_width; ++i)
        {
                printf(" ");
        }
        printf("] %d%%\r\n", progress_percent);

        fflush(stdout);
}

static int network_init(network_tester* tester)
{
        int ret = 0;

        /* After reading the initial start message, we set the management_socket
         * to non-blocking. */
        setblocking(tester->management_socket_pair[1], false);

        /* Initialize the Agile Security Library */
        if (tester->config->use_tls == true)
        {
                LOG_DEBUG("Initializing ASL");

                asl_configuration asl_config = asl_default_config();
                asl_config.logging_enabled = true;
                asl_config.log_level = LOG_LVL_GET();
                asl_config.log_callback = asl_log_callback;

                ret = asl_init(&asl_config);
                if (ret != ASL_SUCCESS)
                        ERROR_OUT("Error initializing ASL: %d (%s)", ret, asl_error_message(ret));
        }

        /* Configure TCP destination.
         * Do a DNS lookup to make sure we have an IP address. If we already have an IP, this
         * results in a noop. */
        if (address_lookup_client(tester->config->target_ip,
                                  tester->config->target_port,
                                  &tester->target_addr,
                                  AF_UNSPEC) < 0)
                ERROR_OUT("Error looking up target IP address");

        tester->current_target = tester->target_addr;

        /* Configure TLS endpoint */
        if (tester->config->use_tls == true)
        {
                LOG_DEBUG("Setting up TLS client endpoint");

                tester->tls_endpoint = asl_setup_client_endpoint(&tester->config->tls_config);
                if (tester->tls_endpoint == NULL)
                        ERROR_OUT("Error creating TLS endpoint");
        }

cleanup:
        return ret;
}

static int connection_setup(network_tester* tester)
{
        int ret = 0;

        if (tester->tcp_socket > 0)
                closesocket(tester->tcp_socket);

        /* Create the TCP socket for the outgoing connection */
        tester->tcp_socket = create_client_socket(tester->current_target->ai_family);
        if (tester->tcp_socket == -1)
                ERROR_OUT("Error creating TCP socket");

        /* Create the TLS session */
        if (tester->config->use_tls == true && tester->tls_session == NULL)
        {
                LOG_DEBUG("Creating TLS session");

                tester->tls_session = asl_create_session(tester->tls_endpoint, tester->tcp_socket);
                if (tester->tls_session == NULL)
                        ERROR_OUT("Error creating TLS session");
        }

cleanup:
        return ret;
}

static int test_echo_message(network_tester* tester, size_t num_of_bytes)
{
        int ret = 0;

        if (num_of_bytes > tester->config->message_latency_test.size)
                ERROR_OUT("Message size too large");

        /* Write message to the peer */
        if (tester->config->use_tls)
        {
                ret = asl_send(tester->tls_session, tester->tx_buffer, num_of_bytes);
                if (ret != ASL_SUCCESS)
                        ERROR_OUT("Error sending message: %d (%s)", ret, asl_error_message(ret));
        }
        else
        {
                ret = send(tester->tcp_socket, tester->tx_buffer, num_of_bytes, 0);
                if (ret == -1)
                        ERROR_OUT("Error sending message: %d (%s)", ret, strerror(errno));
        }

        /* Read response */
        size_t bytes_received = 0;
        while (bytes_received < num_of_bytes)
        {
                if (tester->config->use_tls)
                {
                        ret = asl_receive(tester->tls_session,
                                          tester->rx_buffer + bytes_received,
                                          num_of_bytes - bytes_received);
                        if (ret < 0)
                                ERROR_OUT("Error receiving message: %d (%s)",
                                          ret,
                                          asl_error_message(ret));
                }
                else
                {
                        ret = recv(tester->tcp_socket,
                                   tester->rx_buffer + bytes_received,
                                   num_of_bytes - bytes_received,
                                   0);
                        if (ret == -1)
                                ERROR_OUT("Error receiving message: %d (%s)", ret, strerror(errno));
                }

                bytes_received += ret;
        }

        /* Check if the echod data is correct */
        if ((bytes_received != num_of_bytes) ||
            (memcmp(tester->tx_buffer, tester->rx_buffer, num_of_bytes) != 0))
                ERROR_OUT("Echo NOT successfull");

        ret = 0;

cleanup:
        return ret;
}

static void* network_tester_main_thread(void* ptr)
{
        network_tester* tester = (network_tester*) ptr;
        int ret = 0;

        tester->running = true;
        tester->return_code = 0;

        /* Read the START message with the configuration */
        network_tester_management_message start_msg = {0};
        ret = read_management_message(tester->management_socket_pair[1], &start_msg);
        if (ret != 0)
                ERROR_OUT("Error reading start message");
        if (start_msg.type != MANAGEMENT_MSG_START)
                ERROR_OUT("Received invalid start message");

        tester->config = &start_msg.payload.config;

        /* Initialize all network related stuff */
        ret = network_init(tester);
        if (ret < 0)
                ERROR_OUT("Error initializing network structures");

        /* Allocate the buffers for the message exchange */
        if (tester->config->message_latency_test.size <= 0)
                ERROR_OUT("Invalid message size: %d", tester->config->message_latency_test.size);

        tester->tx_buffer = (uint8_t*) malloc(tester->config->message_latency_test.size);
        tester->rx_buffer = (uint8_t*) malloc(tester->config->message_latency_test.size);
        if ((tester->tx_buffer == NULL) || (tester->rx_buffer == NULL))
                ERROR_OUT("Error allocating memory for message buffers");

        /* Fill the message buffer with a known pattern */
        for (size_t i = 0; i < tester->config->message_latency_test.size; i++)
        {
                tester->tx_buffer[i] = i & 0xFF;
        }

        /* Calculate the number of total number of measurements we are taking for the
         * message latencies (this is also needed for the progress bar). The total number
         * of measurements we are taking is the number of message iterations multiplied
         * with the number of handshakes (as we are taking `message_latency_test.iterations`
         * measurements per handshake). As special cases, we have to consider when we don't
         * want to measure either of the two types at all (and hence one of the iteration
         * number is zero). */
        if (tester->config->handshake_test.iterations == 0)
                tester->total_iterations = tester->config->message_latency_test.iterations;
        else if (tester->config->message_latency_test.iterations == 0)
                tester->total_iterations = tester->config->handshake_test.iterations;
        else
                tester->total_iterations = tester->config->handshake_test.iterations *
                                           tester->config->message_latency_test.iterations;

        if (tester->total_iterations == 0)
                ERROR_OUT("No measurements to take");

        /* Create the timing metrics for the handshake measurements */
        if (tester->config->handshake_test.iterations > 0)
        {
                tester->handshake_times = timing_metrics_create("handshake_time",
                                                                tester->config->handshake_test.iterations,
                                                                LOG_MODULE_GET());
                if (tester->handshake_times == NULL)
                        ERROR_OUT("Error creating handshake timing metrics");
        }

        /* Create the timing metrics for the message latency measurements. */
        if (tester->config->message_latency_test.iterations > 0)
        {
                tester->messsage_latency_times = timing_metrics_create("message_latency_time",
                                                                       tester->total_iterations,
                                                                       LOG_MODULE_GET());
                if (tester->messsage_latency_times == NULL)
                        ERROR_OUT("Error creating message latency timing metrics");
        }

        /* Create the output file (if requested) */
        if (tester->config->output_path != NULL)
        {
                ret = timing_metrics_prepare_output_file(tester->handshake_times,
                                                         tester->config->output_path);
                if (ret < 0)
                        ERROR_OUT("Error creating output file");

                ret = timing_metrics_prepare_output_file(tester->messsage_latency_times,
                                                         tester->config->output_path);
                if (ret < 0)
                        ERROR_OUT("Error creating output file");
        }

        /* Send the response to the management interface */
        start_msg.type = MANAGEMENT_RESPONSE;
        start_msg.payload.response_code = 0;
        ret = send_management_message(tester->management_socket_pair[1], &start_msg);
        if (ret < 0)
        {
                ERROR_OUT("Error sending response");
        }

        if (tester->config->silent_test == false)
        {
                printf("\r\n"); /* New line necessary for proper progress print */
                print_progress(tester, 0);
        }

        /* Loop over all handshake iterations we want to perform. We use a do {} while() loop here
         * to make sure the handshake loop is executed at least once, also in case no handshake
         * measurements should be taken (`handshake_test.iterations` is zero). */
        int handshake_count = 0;
        do
        {
                bool tcp_connected = false;
                do
                {
                        /* Setup the connection */
                        ret = connection_setup(tester);
                        if (ret < 0)
                                ERROR_OUT("Error setting up connection");

                        /* Start the measurement of the handshake time */
                        timing_metrics_start_measurement(tester->handshake_times);

                        /* Connect to the peer */
                        LOG_DEBUG("Establishing TCP connection");
                        ret = connect(tester->tcp_socket,
                                      (struct sockaddr*) tester->current_target->ai_addr,
                                      tester->current_target->ai_addrlen);

                        if (ret != 0)
                        {
                                if ((errno == ECONNREFUSED) && (tester->current_target->ai_next != NULL))
                                {
                                        tester->current_target = tester->current_target->ai_next;
                                        LOG_DEBUG("Connection refused by target peer, try "
                                                  "next target address");
                                }
                                else
                                        ERROR_OUT("Error connecting to target peer: %d", errno);
                        }
                        else
                                tcp_connected = true;
                }
                while (tcp_connected == false);

                /* Do TLS handshake */
                if (tester->config->use_tls == true)
                {
                        LOG_DEBUG("Performing TLS handshake");

                        ret = asl_handshake(tester->tls_session);
                        if (ret != ASL_SUCCESS)
                                ERROR_OUT("Error performing TLS handshake: %d (%s)",
                                          ret,
                                          asl_error_message(ret));
                }

                /* Check if the echo of a single bytes works. This means that the connection is fully established. */
                ret = test_echo_message(tester, 1);
                if (ret < 0)
                        ERROR_OUT("Error testing echo message");

                /* As soon as the echo of a single byte is done, we consider the handshake done and stop the measurement. */
                timing_metrics_end_measurement(tester->handshake_times);

                /* Loop over all requested message latency measurements per handshake */
                for (int message_count = 0;
                     message_count < tester->config->message_latency_test.iterations;
                     message_count++)
                {
                        /* Start the measurement of the message latency */
                        timing_metrics_start_measurement(tester->messsage_latency_times);

                        /* Send the requested number of bytes and wait for the echo */
                        ret = test_echo_message(tester, tester->config->message_latency_test.size);
                        if (ret < 0)
                                ERROR_OUT("Error testing echo message");

                        /* End the measurement of the message latency */
                        timing_metrics_end_measurement(tester->messsage_latency_times);

                        /* Print progress bar to the console */
                        if (tester->config->silent_test == false)
                                print_progress(tester,
                                               (handshake_count *
                                                tester->config->message_latency_test.iterations) +
                                                       message_count + 1);

                        /* ToDo: Check fo a management message here?! Does that influece the results? */

                        if (tester->config->message_latency_test.delay_us > 0)
                        {
                                usleep(tester->config->message_latency_test.delay_us);
                        }
                }

                /* Close connection */
                if (tester->config->use_tls)
                {
                        asl_close_session(tester->tls_session);
                        asl_free_session(tester->tls_session);
                        tester->tls_session = NULL;
                }

                closesocket(tester->tcp_socket);
                tester->tcp_socket = -1;

                /* Print progress bar to the console */
                if (tester->config->silent_test == false)
                {
                        if (tester->config->handshake_test.iterations == 0)
                                print_progress(tester, tester->config->message_latency_test.iterations);
                        else if (tester->config->message_latency_test.iterations == 0)
                                print_progress(tester, handshake_count + 1);
                        else
                                print_progress(tester,
                                               (handshake_count +
                                                1) * tester->config->message_latency_test.iterations);
                }

                /* Check if we have received a management message */
                ret = handle_management_message(tester, tester->management_socket_pair[1]);
                if (ret > 0)
                {
                        /* We have received a STOP message */
                        break;
                }

                if (tester->config->handshake_test.delay_ms > 0)
                {
                        usleep(tester->config->handshake_test.delay_ms * 1000);
                }

                handshake_count += 1;
        }
        while (handshake_count < tester->config->handshake_test.iterations);

        /* Print results */
        LOG_INFO("Test results:\r\n");
        timing_metrics_results results;

        if (tester->config->handshake_test.iterations > 0)
        {
                timing_metrics_get_results(tester->handshake_times, &results);

                LOG_INFO("Handshake time");
                LOG_INFO("Number of measurements: %lu", results.num_measurements);
                LOG_INFO("Minimum: %.3fms", (double) results.min / 1000);
                LOG_INFO("Maximum: %.3fms", (double) results.max / 1000);
                LOG_INFO("Average: %.3fms", results.avg / 1000);
                LOG_INFO("Standard deviation: %.3fms", results.std_dev / 1000);
                LOG_INFO("Median: %.3fms", results.median / 1000);
                LOG_INFO("90th percentile: %.3fms", results.percentile_90 / 1000);
                LOG_INFO("99th percentile: %.3fms\r\n", results.percentile_99 / 1000);
        }

        if (tester->config->message_latency_test.iterations > 0)
        {
                timing_metrics_get_results(tester->messsage_latency_times, &results);

                LOG_INFO("Message latency");
                LOG_INFO("Number of measurements: %lu", results.num_measurements);
                LOG_INFO("Minimum: %.3fus", (double) results.min);
                LOG_INFO("Maximum: %.3fus", (double) results.max);
                LOG_INFO("Average: %.3fus", results.avg);
                LOG_INFO("Standard deviation: %.3fus", results.std_dev);
                LOG_INFO("Median: %.3fus", results.median);
                LOG_INFO("90th percentile: %.3fus", results.percentile_90);
                LOG_INFO("99th percentile: %.3fus\r\n", results.percentile_99);
        }

        /* Store results in file (when no output is requested, the fails gracefully) */
        ret = timing_metrics_write_to_file(tester->handshake_times);
        if (ret < 0)
                ERROR_OUT("Error writing results to file");

        /* Store results in file (when no output is requested, the fails gracefully) */
        ret = timing_metrics_write_to_file(tester->messsage_latency_times);
        if (ret < 0)
                ERROR_OUT("Error writing results to file");

cleanup:
        tester->return_code = -ret;

        /* Cleanup */
        tester_cleanup(tester);
        terminate_thread(LOG_MODULE_GET());
        return NULL;
}

static int send_management_message(int socket, network_tester_management_message const* msg)
{
        int ret = 0;
        static const int max_retries = 5;
        int retries = 0;

        while ((ret <= 0) && (retries < max_retries))
        {
                ret = send(socket, (char const*) msg, sizeof(network_tester_management_message), 0);
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
        int ret = recv(socket, (char*) msg, sizeof(network_tester_management_message), 0);
        if (ret < 0 && (errno == EAGAIN || errno == 0))
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
                          ret,
                          sizeof(network_tester_management_message));
                return -1;
        }

        return 0;
}

/* Handle incoming management messages.
 *
 * Return 0 in case the message has been processed successfully, -1 otherwise. In case the
 * connection thread has to be stopped and the connection has to be cleaned up, +1 in returned.
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
                        status->return_code = tester->return_code;
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
        if ((tester->config->use_tls == true) && (tester->tls_session != NULL))
        {
                asl_free_session(tester->tls_session);
        }
        if ((tester->config->use_tls == true) && (tester->tls_endpoint != NULL))
        {
                asl_free_endpoint(tester->tls_endpoint);
                asl_cleanup();
                tester->tls_endpoint = NULL;
        }
        if (tester->tcp_socket != -1)
        {
                closesocket(tester->tcp_socket);
        }

        timing_metrics_destroy(&tester->handshake_times);

        /* Close the management socket pair */
        if (tester->management_socket_pair[0] != -1)
        {
                int sock = tester->management_socket_pair[0];
                tester->management_socket_pair[0] = -1;
                closesocket(sock);
        }
        if (tester->management_socket_pair[1] != -1)
        {
                int sock = tester->management_socket_pair[1];
                tester->management_socket_pair[1] = -1;
                closesocket(sock);
        }

        if (tester->target_addr != NULL)
        {
                freeaddrinfo(tester->target_addr);
                tester->target_addr = NULL;
        }

        tester->progress_percent = -1;
        tester->running = false;
}

/* Create the default config for the network_tester */
network_tester_config network_tester_default_config(void)
{
        network_tester_config default_config = {0};

        /* Network tester config */
        default_config.log_level = LOG_LVL_WARN;
        default_config.output_path = NULL;

        default_config.handshake_test.iterations = 0;
        default_config.handshake_test.delay_ms = 0;

        default_config.message_latency_test.iterations = 0;
        default_config.message_latency_test.delay_us = 0;
        default_config.message_latency_test.size = 100;

        default_config.target_ip = NULL;
        default_config.target_port = 0;

        default_config.use_tls = true;

        /* TLS endpoint config */
        default_config.tls_config = asl_default_endpoint_config();

        return default_config;
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

        /* Create the socket pair for external management */
        int ret = create_socketpair(the_tester.management_socket_pair);
        if (ret < 0)
                ERROR_OUT("Error creating socket pair for management: %d (%s)", errno, strerror(errno));

        LOG_DEBUG("Created management socket pair (%d, %d)",
                  the_tester.management_socket_pair[0],
                  the_tester.management_socket_pair[1]);

        /* Create the new thread */
        thread_attibutes attr = {0};
        attr.function = network_tester_main_thread;
        attr.argument = &the_tester;
#if defined(__ZEPHYR__)
        attr.stack_size = K_THREAD_STACK_SIZEOF(tester_stack);
        attr.stack = tester_stack;
#endif
        ret = start_thread(&the_tester.thread, &attr);
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
        if ((the_tester.management_socket_pair[0] < 0) ||
            (the_tester.management_socket_pair[0] < 0) || (the_tester.running == false))
        {
                LOG_DEBUG("Tester thread not running");
                status->is_running = false;
                status->return_code = the_tester.return_code;
                status->progress_percent = the_tester.progress_percent;
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
        if ((the_tester.management_socket_pair[0] > 0) && (the_tester.management_socket_pair[1] > 0))
        {
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
        }

        /* Wait until the main thread is terminated */
        wait_for_thread(the_tester.thread);

        return 0;
}
