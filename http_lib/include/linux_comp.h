#ifndef LINUX_SYS_CLOCK_H_
#define LINUX_SYS_CLOCK_H_

#ifdef __cplusplus
extern "C"
{
#endif


/* foreward declaration of time structs */
typedef struct timepoint timepoint;
typedef struct duration duration;


#if defined(__ZEPHYR__)

#include <zephyr/kernel.h>
//#include <inttypes.h>

struct duration
{
        k_timeout_t timespan;
};
struct timepoint
{
        k_timepoint_t time;
};


#else /* __ZEPHYR__ */

#include <time.h>

struct duration
{
        struct timespec timespan;
};
struct timepoint
{
        struct timespec time;
};

#endif /* __ZEPHYR__ */


/// @brief converts integer value for miliseconds to duration datatype.
/// @param ms duration parameter specifying the length of the time duration.
/// @return returns duration value of the respective duration.
duration ms_to_duration(int ms);

/// @brief converts duration value for miliseconds to integer datatype.
/// @param duration duration parameter specifying the length of the duration.
/// @return returns integer value of the respective duration.
int duration_to_ms(duration duration);

/// @brief add time duration on top of a specific timepoint. 
/// @param tp timepoint value specifying the time. 
/// @param duration time duration to be added on top of the timepoint. 
/// @return returns resulting timepoint including the duration value. 
timepoint timepoint_add_duration(timepoint tp, duration duration);

/// @brief get the duration value to a specific time point. 
/// @param timepoint Timepoint value used to calculate the time delate.
/// @return returns the time delta as value of type duration (can be a negative value). 
duration get_remaining_duration_reference_now(timepoint timepoint);

/// @brief get timepoint, when the time duration is reached.
/// @param duration time duration value added ontop of the current timepoint.
/// @return returns future timepoint value when the duration is reached. 
timepoint get_timepoint_in(duration duration);

#ifdef __cplusplus
}
#endif

#endif /* LINUX_SYS_CLOCK_H_ */
