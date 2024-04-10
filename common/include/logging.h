#ifndef LOGGING_H_
#define LOGGING_H_

#if defined(__ZEPHYR__)

#include <zephyr/logging/log.h>

#else

#include <stdint.h>
#include <stdarg.h>


enum LOG_LEVEL
{
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR
};

typedef struct LOG_MODULE
{
    char const* name;
    enum LOG_LEVEL level;
}
LOG_MODULE;


/* Register a new logging module */
#define LOG_MODULE_REGISTER(module_name) static LOG_MODULE log_module = { \
                                                .name = #module_name, \
                                                .level = LOG_LEVEL_INFO \
                                        }

#define LOG_INF(fmt, ...) log_message(&log_module, LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define LOG_WRN(fmt, ...) log_message(&log_module, LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) log_message(&log_module, LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)

#define LOG_LEVEL_SET(level) log_level_set(&log_module, level)


void log_message(LOG_MODULE const* module, enum LOG_LEVEL level, char const* fmt, ...);
void log_level_set(LOG_MODULE* module, enum LOG_LEVEL level);


struct shell
{
        int dummy;
};

#define shell_print(sh, fmt, ...) shell_log(sh, fmt, ##__VA_ARGS__)
#define shell_warn(sh, fmt, ...) shell_log(sh, fmt, ##__VA_ARGS__)
#define shell_error(sh, fmt, ...) shell_log(sh, fmt, ##__VA_ARGS__)

void shell_log(struct shell const* sh, char const* fmt, ...);

#endif

#endif /* LOGGING_H_ */
