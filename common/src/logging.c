#include "logging.h"
#include "log_buffer.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

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

        // Local console logging
        printf("<%s>\t%s: %s\r\n", level_str, module->name, message);

        // Remote logging through the buffer if enabled
        if (log_buffer_is_remote_enabled()) {
                //only print message if level is greater than INFO
                if (level < LOG_LVL_INFO) {
                        log_buffer_add_message(module->name, level, message);
                }
        }
}

void log_level_set(log_module* module, int32_t level)
{
        module->level = level;
}
