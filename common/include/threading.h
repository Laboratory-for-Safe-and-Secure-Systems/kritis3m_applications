#ifndef THREADING_H
#define THREADING_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <pthread.h>

#include "kritis3m_application_config.h"

#include "logging.h"

typedef struct
{
        void* stack;
        size_t stack_size;
        void* argument;
        void* (*function)(void*);
} thread_attibutes;

typedef struct
{
        pthread_t id;

#ifdef ENABLE_STACK_USAGE_REPORTING
        void* stack;
        size_t stack_size;
#endif

} thread_info;

/* Start a new thread with given attributes.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int start_thread(thread_info* thread, thread_attibutes* attributes);

/* Wait for the thread to finish */
void wait_for_thread(thread_info* thread);

/* Terminate the thread by itself */
void terminate_thread(thread_info* thread, log_module const* module);

#endif /* THREADING_H */
