#include "logging.h"

#if !defined (__ZEPHYR__)

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>


void log_message(char const* module, char const* level, char const* fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    char message[256];
    vsnprintf(message, sizeof(message), fmt, args);

    va_end(args);

    printf("<%s> %s: %s\r\n", level, module, message);
}

#endif
