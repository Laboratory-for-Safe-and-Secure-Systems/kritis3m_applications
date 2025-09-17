#ifndef TIMING_METRICS_H_
#define TIMING_METRICS_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "logging.h"

/* Forward declaration. Full declaration is hidden in source file */
typedef struct timing_metrics timing_metrics;

typedef struct timing_metrics_results
{
        /* All timing values are in microseconds */

        size_t num_measurements;
        float min;
        float max;
        double avg;
        double std_dev;
        double median;
        double percentile_90;
        double percentile_99;
} timing_metrics_results;

/* Create a new timing_metrics object.
 *
 * Returns NULL on failure.
 */
timing_metrics* timing_metrics_create(char const* name, size_t max_measurements, log_module* log_module);

/* Start the next measurement */
void timing_metrics_start_measurement(timing_metrics* metrics);

/* Stop the current measurement and store the data */
void timing_metrics_end_measurement(timing_metrics* metrics);

/* Calculate the results of the measurement */
void timing_metrics_get_results(timing_metrics* metrics, timing_metrics_results* results);

/* Prepare the output file. This creates a new CSV file at `path` that is named
 * after the `name` argument passed to `timing_metrics_create()`. The final file
 * path is stored in the timing_metrics object.
 * If a file with the same name already exists, an incremental number is added to
 * the new file name.
 *
 * Returns 0 on success, -1 on failure.
 */
int timing_metrics_prepare_output_file(timing_metrics* metrics, char const* path);

/* Write the measured values in CSV format to the prepared output file.
 *
 * Returns 0 on success, -1 on failure.
 */
int timing_metrics_write_to_file(timing_metrics* metrics);

/* Destroy the timing_metrics object and free all memory */
void timing_metrics_destroy(timing_metrics** metrics);

#endif // TIMING_METRICS_H_
