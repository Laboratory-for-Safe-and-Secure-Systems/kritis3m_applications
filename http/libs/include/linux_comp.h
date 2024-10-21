#ifndef LINUX_SYS_CLOCK_H_
#define LINUX_SYS_CLOCK_H_

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct timepoint timepoint;
    typedef struct duration duration;

    duration ms_toduration(int ms);
    int duration_toms(duration duration);

    timepoint timepoint_add_duration(timepoint tp, duration duration);
    duration get_differential_duration(timepoint reference, timepoint timepoint);
    duration get_remaining_duration_reference_now(timepoint timepoint);
    timepoint get_now();
    // reference to now
    timepoint get_timepoint_in(duration duration);

#if defined(__ZEPHYR__)

    struct duration
    {
        int a;
    };
    // Struct definitions
    struct timepoint
    {
        int b;
    };
#else
#include <time.h>
struct duration
{
    struct timespec timespan;
};
// Struct definitions
struct timepoint
{
    struct timespec time;
};

#endif

    // future time


#ifdef __cplusplus
}
#endif

#endif /* LINUX_SYS_CLOCK_H_ */
