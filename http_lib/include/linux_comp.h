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
// Struct definitions
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
// Struct definitions
struct timepoint
{
        struct timespec time;
};

#endif /* __ZEPHYR__ */


/* method declaration */

duration ms_to_duration(int ms);

int duration_to_ms(duration duration);

timepoint timepoint_add_duration(timepoint tp, duration duration);

duration get_remaining_duration_reference_now(timepoint timepoint);

timepoint get_timepoint_in(duration duration);



#ifdef __cplusplus
}
#endif

#endif /* LINUX_SYS_CLOCK_H_ */
