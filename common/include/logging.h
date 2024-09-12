#ifndef LOGGING_H_
#define LOGGING_H_

#include <stdint.h>
#include <stdarg.h>


enum LOG_LVL
{
    LOG_LVL_NONE  = 0U,
    LOG_LVL_ERROR = 1U,
    LOG_LVL_WARN  = 2U,
    LOG_LVL_INFO  = 3U,
    LOG_LVL_DEBUG = 4U,
};


typedef struct log_module
{
    char const* name;
    int32_t level;
}
log_module;


/* Create a new logging module */
#define LOG_MODULE_CREATE(module_name) static log_module log_inst = { \
                                                .name = #module_name, \
                                                .level = LOG_LVL_WARN \
                                        }

#define LOG_MODULE_CREATE_EX(module_name, log_level) static log_module log_inst = { \
                                                .name = #module_name, \
                                                .level = log_level \
                                        }

#define LOG_MODULE_GET() &log_inst

#define LOG_INFO(...) log_message(&log_inst, LOG_LVL_INFO, __VA_ARGS__)
#define LOG_WARN(...) log_message(&log_inst, LOG_LVL_WARN, __VA_ARGS__)
#define LOG_ERROR(...) log_message(&log_inst, LOG_LVL_ERROR, __VA_ARGS__)
#define LOG_DEBUG(...) log_message(&log_inst, LOG_LVL_DEBUG, __VA_ARGS__)

#define LOG_INFO_EX(module,...) log_message(&module, LOG_LVL_INFO, __VA_ARGS__)
#define LOG_WARN_EX(module,...) log_message(&module, LOG_LVL_WARN, __VA_ARGS__)
#define LOG_ERROR_EX(module,...) log_message(&module, LOG_LVL_ERROR, __VA_ARGS__)
#define LOG_DEBUG_EX(module,...) log_message(&module, LOG_LVL_DEBUG, __VA_ARGS__)

#define LOG_LVL_SET(level) log_level_set(&log_inst, level)
#define LOG_LVL_GET() log_inst.level


void log_message(log_module const* module, int32_t level, char const* fmt, ...);
void log_level_set(log_module* module, int32_t level);

#endif /* LOGGING_H_ */
