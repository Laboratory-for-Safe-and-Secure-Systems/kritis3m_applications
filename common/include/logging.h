#ifndef LOGGING_H_
#define LOGGING_H_

#if defined(__ZEPHYR__)

#include <zephyr/logging/log.h>

#else

#include <stdint.h>
#include <stdarg.h>

/* Register a new logging module */
#define LOG_MODULE_REGISTER(name) static char const* log_module_name = #name

#define LOG_INF(fmt, ...) log_message(log_module_name, "INFO", fmt, ##__VA_ARGS__)
#define LOG_WRN(fmt, ...) log_message(log_module_name, "WARN", fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) log_message(log_module_name, "ERROR", fmt, ##__VA_ARGS__)


void log_message(char const* module, char const* level, char const* fmt, ...);

#endif

#endif /* LOGGING_H_ */
