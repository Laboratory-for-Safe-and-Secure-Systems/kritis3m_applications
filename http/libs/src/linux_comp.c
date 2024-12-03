#include "linux_comp.h"



#if defined(__ZEPHYR__)

#else

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>


// Convert milliseconds to duration
duration ms_toduration(int ms)
{
    duration dur;
    dur.timespan.tv_sec = ms / 1000;              // Convert milliseconds to seconds
    dur.timespan.tv_nsec = (ms % 1000) * 1000000; // Convert remaining milliseconds to nanoseconds
    return dur;
}

timepoint get_now()
{
    timepoint now;
    clock_gettime(CLOCK_MONOTONIC, &now.time); // Get the current time
    return now;
}

timepoint get_timepoint_in(duration duration)
{
    timepoint now = get_now();
    return timepoint_add_duration(now, duration);
}

// Convert duration to milliseconds
int duration_toms(duration dur)
{
    return (dur.timespan.tv_sec * 1000) + (dur.timespan.tv_nsec / 1000000);
}

// Add a duration to a timepoint
timepoint timepoint_add_duration(timepoint tp, duration dur)
{
    // Add seconds
    tp.time.tv_sec += dur.timespan.tv_sec;
    // Add nanoseconds
    tp.time.tv_nsec += dur.timespan.tv_nsec;

    // Normalize nanoseconds if they overflow
    if (tp.time.tv_nsec >= 1000000000)
    {
        tp.time.tv_sec += tp.time.tv_nsec / 1000000000;
        tp.time.tv_nsec %= 1000000000;
    }

    return tp;
}

// Get the difference between two timepoints as a duration
duration get_differential_duration(timepoint ref, timepoint tp)
{
    duration diff;

    // Calculate the difference in seconds and nanoseconds
    diff.timespan.tv_sec = tp.time.tv_sec - ref.time.tv_sec;
    diff.timespan.tv_nsec = tp.time.tv_nsec - ref.time.tv_nsec;

    // Handle nanosecond underflow
    if (diff.timespan.tv_nsec < 0)
    {
        diff.timespan.tv_sec -= 1;
        diff.timespan.tv_nsec += 1000000000;
    }

    return diff;
}

// Get the remaining duration from now to a future timepoint
duration get_remaining_duration_reference_now(timepoint tp)
{
    timepoint now;
    clock_gettime(CLOCK_MONOTONIC, &now.time); // Get the current time

    return get_differential_duration(now, tp); // Get the remaining duration
}
#endif