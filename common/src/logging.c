#include "logging.h"

#if !defined (__ZEPHYR__)

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/syscall.h>




void log_message(LOG_MODULE const* module, enum LOG_LEVEL level, char const* fmt, ...)
{
    if (level < module->level)
    {
        return;
    }

    va_list args;
    va_start(args, fmt);

    char message[256];
    vsnprintf(message, sizeof(message), fmt, args);

    va_end(args);

    char const* level_str = "";
    switch (level)
    {
    case LOG_LEVEL_INFO:
        level_str = "INFO";
        break;
    case LOG_LEVEL_WARN:
        level_str = "WARN";
        break;
    case LOG_LEVEL_ERROR:
        level_str = "ERROR";
        break;
    default:
        break;
    }

    printf("<%s>\t%s (%ld): %s\r\n", level_str, module->name, syscall(SYS_gettid), message);
}

void log_level_set(LOG_MODULE* module, enum LOG_LEVEL level)
{
    module->level = level;
}

void shell_log(struct shell const* sh, char const* fmt, ...)
{
    (void) sh;

    va_list args;
    va_start(args, fmt);

    char message[256];
    vsnprintf(message, sizeof(message), fmt, args);

    va_end(args);

    printf("%s\r\n", message);
}

#endif
