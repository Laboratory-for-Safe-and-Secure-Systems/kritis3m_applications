#ifndef LINUX_SYS_CLOCK_H_
#define LINUX_SYS_CLOCK_H_

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>

#ifdef __cplusplus
extern "C"
{
#endif
#define K_TIMEOUT_EQ(a, b) ((a).ticks == (b).ticks)
    /* Define k_ticks_t based on 64-bit Linux timing */
    typedef int64_t k_ticks_t;

#define K_TICKS_FOREVER ((k_ticks_t) - 1)

    typedef struct
    {
        k_ticks_t ticks;
    } k_timeout_t;

/* Define timeout macros */
#define Z_TIMEOUT_NO_WAIT ((k_timeout_t){0})
#define Z_TIMEOUT_TICKS(t) ((k_timeout_t){.ticks = (t)})
#define Z_FOREVER Z_TIMEOUT_TICKS(K_TICKS_FOREVER)

/* Time conversion constants */
#define NSEC_PER_USEC 1000U
#define NSEC_PER_MSEC 1000000U
#define USEC_PER_MSEC 1000U
#define MSEC_PER_SEC 1000U
#define SEC_PER_MIN 60U
#define MIN_PER_HOUR 60U
#define HOUR_PER_DAY 24U

#define USEC_PER_SEC ((USEC_PER_MSEC) * (MSEC_PER_SEC))
#define NSEC_PER_SEC ((NSEC_PER_USEC) * (USEC_PER_MSEC) * (MSEC_PER_SEC))

#define K_MSEC(ms) Z_TIMEOUT_TICKS(ms)

    static inline uint32_t k_ticks_to_ms_floor32(uint64_t ticks)
    {
        return (uint32_t)(ticks * MSEC_PER_SEC / NSEC_PER_SEC); // Convert ticks to milliseconds, truncating (flooring) the result
    }

    /* Kernel clock functions using POSIX timers */
    typedef struct
    {
        struct timespec time; /* Linux timespec for high precision timing */
    } k_timepoint_t;

    /* Get current time in ticks */
    static inline k_timepoint_t sys_timepoint_calc(k_timeout_t timeout)
    {
        k_timepoint_t timepoint;
        clock_gettime(CLOCK_MONOTONIC, &timepoint.time); // CLOCK_MONOTONIC is like system uptime
        return timepoint;
    }

    /* Calculate timeout */
    static inline k_timeout_t sys_timepoint_timeout(k_timepoint_t timepoint)
    {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        /* Subtract the current time from the target time */
        k_ticks_t delta_sec = timepoint.time.tv_sec - now.tv_sec;
        k_ticks_t delta_nsec = timepoint.time.tv_nsec - now.tv_nsec;

        if (delta_sec < 0 || (delta_sec == 0 && delta_nsec <= 0))
        {
            return Z_TIMEOUT_NO_WAIT;
        }

        return Z_TIMEOUT_TICKS(delta_sec * MSEC_PER_SEC + delta_nsec / NSEC_PER_MSEC);
    }

    /* Compare two timepoints */
    static inline int sys_timepoint_cmp(k_timepoint_t a, k_timepoint_t b)
    {
        if (a.time.tv_sec == b.time.tv_sec)
        {
            return (a.time.tv_nsec == b.time.tv_nsec) ? 0 : (a.time.tv_nsec < b.time.tv_nsec ? -1 : 1);
        }
        return a.time.tv_sec < b.time.tv_sec ? -1 : 1;
    }

    /* Check if the timepoint has expired */
    static inline bool sys_timepoint_expired(k_timepoint_t timepoint)
    {
        return K_TIMEOUT_EQ(sys_timepoint_timeout(timepoint), Z_TIMEOUT_NO_WAIT);
    }

#ifdef __cplusplus
}
#endif


#endif /* LINUX_SYS_CLOCK_H_ */
