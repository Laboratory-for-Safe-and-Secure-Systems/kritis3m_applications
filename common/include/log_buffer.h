#ifndef LOG_BUFFER_H_
#define LOG_BUFFER_H_

#include <stdbool.h>
#include <stdint.h>

// Initialize the log buffer system
int log_buffer_init(void);

// Clean up the log buffer system
void log_buffer_cleanup(void);

// Add a log message to the buffer
// Returns 0 on success, negative value on error
int log_buffer_add_message(const char* module_name, int32_t level, const char* message);

// Enable/disable remote logging
void log_buffer_set_remote_enabled(bool enabled);

// Check if remote logging is enabled
bool log_buffer_is_remote_enabled(void);

// Force flush the buffer immediately
// Returns 0 on success, negative value on error
int log_buffer_flush(void);

#endif /* LOG_BUFFER_H_ */ 