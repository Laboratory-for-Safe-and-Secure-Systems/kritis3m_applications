#ifndef THREADING_H
#define THREADING_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <pthread.h>

#include "logging.h"

typedef struct
{
        void* stack;
        size_t stack_size;
        void* argument;
        void* (*function)(void*);
} thread_attibutes;

/* Start a new thread with given attributes.
 *
 * Returns 0 on success, -1 on failure (error message is printed to console).
 */
int start_thread(pthread_t* thread, thread_attibutes* attributes);

/* Wait for the thread to finish */
void wait_for_thread(pthread_t thread);

/* Terminate the thread by itself */
void terminate_thread(log_module const* module);

#endif /* THREADING_H */
