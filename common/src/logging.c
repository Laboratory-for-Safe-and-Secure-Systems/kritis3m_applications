#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>


void log_message(log_module const* module, int32_t level, char const* fmt, ...)
{
    if (level > module->level)
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
    case LOG_LVL_DEBUG:
        level_str = "DEBUG";
        break;
    case LOG_LVL_INFO:
        level_str = "INFO";
        break;
    case LOG_LVL_WARN:
        level_str = "WARN";
        break;
    case LOG_LVL_ERROR:
        level_str = "ERROR";
        break;
    default:
        break;
    }

    printf("<%s>\t%s: %s\r\n", level_str, module->name, message);
}

void log_level_set(log_module* module, int32_t level)
{
    module->level = level;
}
