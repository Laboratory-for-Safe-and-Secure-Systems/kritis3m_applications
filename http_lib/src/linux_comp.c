#include "linux_comp.h"

#if defined(__ZEPHYR__)

/*------------------------------- public functions -------------------------------*/
duration ms_to_duration(int ms)
{
        duration dur;
        dur.timespan = K_MSEC(ms);
        return dur;
}

int duration_to_ms(duration dur)
{
        return k_ticks_to_ms_floor32(dur.timespan.ticks);
}

timepoint get_timepoint_in(duration duration)
{
        /* we dont need to get the current time here, 
         * as the kernel does this for us. */
        timepoint now;
        return timepoint_add_duration(now, duration);
}

timepoint timepoint_add_duration(timepoint tp, duration dur)
{
        tp.time = sys_timepoint_calc(dur.timespan);
        return tp;
}

duration get_remaining_duration_reference_now(timepoint tp)
{
        duration dur;
        dur.timespan.ticks =  sys_timepoint_timeout(tp.time).ticks;
        return dur;
}

#else

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>

/*------------------------------ private functions -------------------------------*/

/// @brief get the current timepoint value.
/// @return returns timpoint value.
static timepoint get_now()
{
        timepoint now;
        clock_gettime(CLOCK_MONOTONIC, &now.time);
        return now;
}

/// @brief get the difference between two timpoints.
/// @param ref reference timepoint value used to calculate difference.
/// @param tp second timepoint value subtracted from the reference timepoint.
/// @return returns the difference between the two timepoints as duration (can be negative).
static duration get_differential_duration(timepoint ref, timepoint tp)
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

/*------------------------------- public functions -------------------------------*/
duration ms_to_duration(int ms)
{
        duration dur;
        dur.timespan.tv_sec = ms / 1000;              // Convert milliseconds to seconds
        dur.timespan.tv_nsec = (ms % 1000) * 1000000; // Convert remaining milliseconds to nanoseconds
        return dur;
}

int duration_to_ms(duration dur)
{
        return (dur.timespan.tv_sec * 1000) + (dur.timespan.tv_nsec / 1000000);
}

timepoint get_timepoint_in(duration duration)
{
        timepoint now = get_now();
        return timepoint_add_duration(now, duration);
}

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

duration get_remaining_duration_reference_now(timepoint tp)
{
        timepoint now;
        clock_gettime(CLOCK_MONOTONIC, &now.time); // Get the current time

        return get_differential_duration(now, tp); // Get the remaining duration
}

#endif