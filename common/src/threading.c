#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "kritis3m_application_config.h"

#ifdef ENABLE_STACK_USAGE_REPORTING
#include <unistd.h>
#endif

#include "logging.h"
#include "threading.h"

LOG_MODULE_CREATE(threading);

#define ERROR_OUT(...)                                                                             \
        {                                                                                          \
                LOG_ERROR(__VA_ARGS__);                                                            \
                ret = -1;                                                                          \
                goto cleanup;                                                                      \
        }

#define STACK_CHECK_VAL 0x55

/* Start a new thread with given attributes.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int start_thread(thread_info* thread, thread_attibutes* attributes)
{
        int ret = 0;
        pthread_attr_t thread_attr;

        pthread_attr_init(&thread_attr);

        if (thread == NULL || attributes == NULL)
                ERROR_OUT("Invalid thread or attributes");

        pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);

#if defined(ENABLE_STACK_USAGE_REPORTING)
#if !defined(__ZEPHYR__)
        if (attributes->stack == NULL && attributes->stack_size == 0)
        {
                attributes->stack_size = 2 * 1024 * 1024; /* 2MB */

                ret = posix_memalign((void**) &attributes->stack,
                                     sysconf(_SC_PAGESIZE),
                                     attributes->stack_size);
                if (ret != 0 || attributes->stack == NULL)
                        ERROR_OUT("posix_memalign failed");
        }
#endif
        thread->stack = attributes->stack;
        thread->stack_size = attributes->stack_size;

        /* Fill the stack with our check value */
        memset(attributes->stack, STACK_CHECK_VAL, attributes->stack_size);
#endif

        /* Set the stack in case user provided one. Otherwise, we leave those attibutes empty,
         * resulting in the system dynamically allocating a stack for us. */
        if (attributes->stack != NULL && attributes->stack_size > 0)
        {
                pthread_attr_setstack(&thread_attr, attributes->stack, attributes->stack_size);
        }

        /* Set the priority of the client handler thread to be one higher than the backend thread.
         * This priorizes active connections before handshakes of new ones. */
        // struct sched_param param = {
        // 	.sched_priority = BACKEND_THREAD_PRIORITY,
        // };
        // pthread_attr_setschedparam(&thread_attr, &param);
        // pthread_attr_setschedpolicy(&thread_attr, SCHED_RR);

        /* Create the new thread */
        ret = pthread_create(&thread->id, &thread_attr, attributes->function, attributes->argument);
        if (ret != 0)
                ERROR_OUT("Error starting new thread: %d (%s)", errno, strerror(errno));

cleanup:
        pthread_attr_destroy(&thread_attr);

        return ret;
}

/* Wait for the thread to finish */
void wait_for_thread(thread_info* thread)
{
        /* Wait for the thread to be terminated */
        if (thread != NULL)
                pthread_join(thread->id, NULL);
}

/* Terminate the thread by itself */
void terminate_thread(thread_info* thread, log_module const* module)
{
        pthread_t this = pthread_self();
        if (thread == NULL || (thread != NULL && thread->id != this))
        {
                LOG_ERROR("Thread %ld is terminating, but it is not the one that is referenced", this);
                pthread_exit(NULL);
        }

#ifdef ENABLE_STACK_USAGE_REPORTING
        size_t unused = 0;

        /* Check the stack usage */
        uint8_t* stack = (uint8_t*) thread->stack;
        for (unused = 0; unused < thread->stack_size; unused++)
        {
                if (stack[unused] != STACK_CHECK_VAL)
                {
                        break;
                }
        }

        if (module != NULL)
                LOG_INFO_EX(*module, "Max stack usage: %ld bytes", thread->stack_size - unused);

#endif

        if (module != NULL)
                LOG_DEBUG_EX(*module, "Thread terminated", this);

        /* Detach the thread here, as it is terminating by itself. With that,
         * the thread resources are freed immediatelly. */
        pthread_detach(this);

        pthread_exit(NULL);
        /* This should never be reached */
}
