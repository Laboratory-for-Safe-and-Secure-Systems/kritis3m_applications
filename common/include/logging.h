#ifndef LOGGING_H_
#define LOGGING_H_

#if defined(__ZEPHYR__)

#include <zephyr/logging/log.h>

#else

#include <stdint.h>
#include <stdarg.h>


enum LOG_LEVEL
{
    LOG_LEVEL_NONE  = 0U,
    LOG_LEVEL_ERR   = 1U,
    LOG_LEVEL_WRN   = 2U,
    LOG_LEVEL_INF   = 3U,
    LOG_LEVEL_DBG   = 4U,
};

typedef struct LOG_MODULE
{
    char const* name;
    int32_t level;
}
LOG_MODULE;


/* Register a new logging module */
#define LOG_MODULE_REGISTER(module_name) static struct LOG_MODULE log_module = { \
                                                .name = #module_name, \
                                                .level = LOG_LEVEL_WRN \
                                        }

#define LOG_MODULE_REGISTER_EX(module_name, log_level) static struct LOG_MODULE log_module = { \
                                                .name = #module_name, \
                                                .level = log_level \
                                        }

#define LOG_INF(fmt, ...) log_message(&log_module, LOG_LEVEL_INF, fmt, ##__VA_ARGS__)
#define LOG_WRN(fmt, ...) log_message(&log_module, LOG_LEVEL_WRN, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) log_message(&log_module, LOG_LEVEL_ERR, fmt, ##__VA_ARGS__)

#define LOG_LEVEL_SET(level) log_level_set(&log_module, level)


void log_message(LOG_MODULE const* module, int32_t level, char const* fmt, ...);
void log_level_set(LOG_MODULE* module, int32_t level);


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
