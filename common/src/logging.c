#include "logging.h"

#if !defined (__ZEPHYR__)

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/syscall.h>


void log_message(char const* module, char const* level, char const* fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    char message[256];
    vsnprintf(message, sizeof(message), fmt, args);

    va_end(args);

    printf("<%s>\t%s (%ld): %s\r\n", level, module, syscall(SYS_gettid), message);
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
