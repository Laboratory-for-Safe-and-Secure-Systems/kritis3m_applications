#ifndef HB_SERVICE_H
#define HB_SERVICE_H

#include "asl.h"
#include "poll.h"
#include "poll_set.h"
#include "kritis3m_scale_service.h"

#include <stdio.h>

#if defined(__ZEPHYR__)
#include <zephyr/posix/pthread.h>
#include <zephyr/posix/unistd.h>
#include <zephyr/posix/time.h>
#include <zephyr/posix/signal.h>
#include <zephyr/kernel.h>
#else
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#endif

#define HB_SERVERADDR "192.168.3.3"
#define HB_SERVERPORT "1231"
#define HB_RESPONSE_SIZE 400
#define HB_MAX_INSTRUCTIONS 4
#define HB_URL (HB_SERVERADDR ":" HB_SERVERPORT "/hb_service/moin/")

typedef struct HardbeatResponse HardbeatResponse;
struct HardbeatResponse;

typedef struct TimerPipe TimerPipe;
struct TimerPipe;
int timer_start(TimerPipe *pipe, uint32_t interval_sec);
int timer_stop(TimerPipe *pipe);
int timer_change_interval(TimerPipe *pipe, int new_interval_sec);
int init_posix_timer(TimerPipe *pipe);
int timer_terminate(TimerPipe *pipe);
int get_clock_signal_fd(TimerPipe *pipe);

typedef enum
{
    HB_ERROR = -1,
    HB_NOTHING = 0,            // keep current configuration
    HB_CHANGE_HB_INTEVAL = 1,  // change the hardbeat interval
    HB_REQUEST_POLICIES = 2,   // request new configuration policies/config from the distribution server
    HB_POST_SYSTEM_STATUS = 3, // post system status to the distribution server
    HB_SET_DEBUG_LEVEL = 4,    // set the debug level to either DEBUG,INFO, WARN, ERROR
} HardbeatInstructions;

struct HardbeatResponse
{
    HardbeatInstructions HardbeatInstruction[HB_MAX_INSTRUCTIONS];
    int hb_instructions_count;
    uint64_t HardbeatInterval_s;
};

#endif // HB_SERVICE_H