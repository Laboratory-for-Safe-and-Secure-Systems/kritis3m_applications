#include "log_buffer.h"
#include "logging.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define LOG_BUFFER_SIZE 1024
#define MAX_LOG_LENGTH 256
#define FLUSH_INTERVAL_SEC 5
#define MAX_BATCH_SIZE 50

LOG_MODULE_CREATE(log_buffer);

typedef struct {
    char module_name[32];
    int32_t level;
    char message[MAX_LOG_LENGTH];
    time_t timestamp;
} log_entry_t;

typedef struct {
    log_entry_t entries[LOG_BUFFER_SIZE];
    size_t write_pos;
    size_t read_pos;
    size_t count;
    pthread_mutex_t mutex;
    pthread_t flush_thread;
    bool running;
    bool remote_enabled;
} log_buffer_t;

static log_buffer_t* log_buffer = NULL;

// Forward declaration of the function that sends logs to MQTT
extern int send_log_message(const char* message);

static void* flush_thread_func(void* arg) {
    log_buffer_t* buffer = (log_buffer_t*)arg;
    char batch_buffer[MAX_BATCH_SIZE * (MAX_LOG_LENGTH + 64)];  // Extra space for formatting
    
    while (buffer->running) {
        sleep(FLUSH_INTERVAL_SEC);
        
        if (!buffer->remote_enabled || buffer->count == 0) {
            continue;
        }

        pthread_mutex_lock(&buffer->mutex);
        
        size_t batch_count = 0;
        batch_buffer[0] = '[';  // Start JSON array
        size_t batch_pos = 1;
        
        // Process up to MAX_BATCH_SIZE entries
        while (buffer->count > 0 && batch_count < MAX_BATCH_SIZE) {
            log_entry_t* entry = &buffer->entries[buffer->read_pos];
            
            // Format the log entry as JSON
            int written = snprintf(batch_buffer + batch_pos, 
                                 sizeof(batch_buffer) - batch_pos,
                                 "%s{\"timestamp\":%ld,\"module\":\"%s\",\"level\":%d,\"message\":\"%s\"}",
                                 batch_count > 0 ? "," : "",
                                 entry->timestamp,
                                 entry->module_name,
                                 entry->level,
                                 entry->message);
                                 
            if (written < 0 || written >= sizeof(batch_buffer) - batch_pos) {
                // Buffer full or error, break the batch
                break;
            }
            
            batch_pos += written;
            batch_count++;
            
            buffer->read_pos = (buffer->read_pos + 1) % LOG_BUFFER_SIZE;
            buffer->count--;
        }
        
        // Close JSON array
        if (batch_count > 0 && batch_pos < sizeof(batch_buffer) - 1) {
            batch_buffer[batch_pos++] = ']';
            batch_buffer[batch_pos] = '\0';
            
            // Release the mutex before sending to avoid blocking
            pthread_mutex_unlock(&buffer->mutex);
            
            // Send the batch to MQTT
            if (send_log_message(batch_buffer) != 0) {
                LOG_WARN("Failed to send log batch to MQTT broker");
            }
        } else {
            pthread_mutex_unlock(&buffer->mutex);
        }
    }
    
    return NULL;
}

int log_buffer_init(void) {
    if (log_buffer != NULL) {
        return 0;  // Already initialized
    }
    
    log_buffer = calloc(1, sizeof(log_buffer_t));
    if (log_buffer == NULL) {
        return -1;
    }
    
    if (pthread_mutex_init(&log_buffer->mutex, NULL) != 0) {
        free(log_buffer);
        log_buffer = NULL;
        return -1;
    }
    
    log_buffer->running = true;
    log_buffer->remote_enabled = false;
    
    if (pthread_create(&log_buffer->flush_thread, NULL, flush_thread_func, log_buffer) != 0) {
        pthread_mutex_destroy(&log_buffer->mutex);
        free(log_buffer);
        log_buffer = NULL;
        return -1;
    }
    
    return 0;
}

void log_buffer_cleanup(void) {
    if (log_buffer == NULL) {
        return;
    }
    
    log_buffer->running = false;
    pthread_join(log_buffer->flush_thread, NULL);
    pthread_mutex_destroy(&log_buffer->mutex);
    
    free(log_buffer);
    log_buffer = NULL;
}

int log_buffer_add_message(const char* module_name, int32_t level, const char* message) {
    if (log_buffer == NULL || !log_buffer->remote_enabled) {
        return 0;  // Not initialized or remote logging disabled
    }
    
    pthread_mutex_lock(&log_buffer->mutex);
    
    if (log_buffer->count >= LOG_BUFFER_SIZE) {
        pthread_mutex_unlock(&log_buffer->mutex);
        return -1;  // Buffer full
    }
    
    log_entry_t* entry = &log_buffer->entries[log_buffer->write_pos];
    
    strncpy(entry->module_name, module_name, sizeof(entry->module_name) - 1);
    entry->level = level;
    strncpy(entry->message, message, sizeof(entry->message) - 1);
    entry->timestamp = time(NULL);
    
    log_buffer->write_pos = (log_buffer->write_pos + 1) % LOG_BUFFER_SIZE;
    log_buffer->count++;
    
    pthread_mutex_unlock(&log_buffer->mutex);
    return 0;
}

void log_buffer_set_remote_enabled(bool enabled) {
    if (log_buffer != NULL) {
        log_buffer->remote_enabled = enabled;
        
        // If disabling, flush remaining messages
        if (!enabled) {
            log_buffer_flush();
        }
    }
}

bool log_buffer_is_remote_enabled(void) {
    return log_buffer != NULL && log_buffer->remote_enabled;
}

int log_buffer_flush(void) {
    if (log_buffer == NULL || !log_buffer->remote_enabled) {
        return 0;
    }
    
    // Force the flush thread to run immediately
    pthread_mutex_lock(&log_buffer->mutex);
    bool has_messages = log_buffer->count > 0;
    pthread_mutex_unlock(&log_buffer->mutex);
    
    if (has_messages) {
        flush_thread_func(log_buffer);
    }
    
    return 0;
} 