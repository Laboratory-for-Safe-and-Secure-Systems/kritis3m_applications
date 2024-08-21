#ifndef TIMING_METRICS_H_
#define TIMING_METRICS_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include "logging.h"


typedef struct timing_metrics
{
    struct timespec start_time;
    struct timespec end_time;

    char* file;
    log_module* log_module;
}
timing_metrics;


timing_metrics* timing_metrics_create(char const* output_path, char const* filename, log_module* log_module);

void timing_metrics_start_measurement(timing_metrics* metrics);
void timing_metrics_end_measurement(timing_metrics* metrics);

void timing_metrics_print(timing_metrics* metrics);

void timing_metrics_destroy(timing_metrics** metrics);


#endif // TIMING_METRICS_H_
