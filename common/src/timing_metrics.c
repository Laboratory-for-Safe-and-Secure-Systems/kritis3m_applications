
#include <stdio.h>
#include <string.h>
#include <math.h>


#include "timing_metrics.h"


#define ERROR_OUT(...) { LOG_ERROR_EX(*metrics->log_module, __VA_ARGS__); ret = -1; goto cleanup; }


struct timing_metrics
{
        struct timespec last_start_time;

        uint32_t measurements_count;
        uint32_t max_measurements;
        uint32_t* measurements;

        char const* name;
        log_module* log_module;

        char* output_file;
};


/* Create a new timing_metrics object.
 *
 * Returns NULL on failure.
 */
timing_metrics* timing_metrics_create(char const* name, size_t max_measurements,
                                      log_module* log_module)
{
        if (name == NULL || log_module == NULL)
                return NULL;

        if (max_measurements == 0)
                return NULL;

        timing_metrics* self = malloc(sizeof(timing_metrics));

        if(self != NULL)
        {
                self->last_start_time.tv_sec = 0;
                self->last_start_time.tv_nsec = 0;

                self->measurements_count = 0;
                self->max_measurements = max_measurements;
                self->measurements = (uint32_t*) malloc(max_measurements * sizeof(uint32_t));

                if(self->measurements == NULL)
                {
                        free(self);
                        return NULL;
                }

                self->name = name;
                self->log_module = log_module;

                self->output_file = NULL;
        }

        return self;
}


// #ifdef _WIN32

// #include <winsock2.h>

// static int clock_gettime(int dummy, struct timespec *spec)
// {
//         (void)dummy;
//         __int64 wintime;

//         GetSystemTimeAsFileTime((FILETIME*)&wintime);

//         wintime      -=116444736000000000i64;  //1jan1601 to 1jan1970
//         spec->tv_sec  =wintime / 10000000i64;           //seconds
//         spec->tv_nsec =wintime % 10000000i64 * 100;      //nano-seconds

//         return 0;
// }
// #define CLOCK_MONOTONIC 0

// #endif


/* Start the next measurement */
void timing_metrics_start_measurement(timing_metrics* metrics)
{
        if (metrics == NULL)
                return;

        if(clock_gettime(CLOCK_MONOTONIC, &metrics->last_start_time) != 0)
                LOG_ERROR_EX(*metrics->log_module, "Error in clock_gettime() - start_time.");
}


/* Stop the current measurement and store the data */
void timing_metrics_end_measurement(timing_metrics* metrics)
{
        if (metrics == NULL)
                return;

        struct timespec end_time = {0};

        if(clock_gettime(CLOCK_MONOTONIC, &end_time) != 0)
                LOG_ERROR_EX(*metrics->log_module, "Error in clock_gettime() - end_time.");

        /* Calculate duration */
        uint32_t duration_us = (end_time.tv_sec - metrics->last_start_time.tv_sec) * 1000000.0 +
                                (end_time.tv_nsec - metrics->last_start_time.tv_nsec) / 1000.0;

        /* Store measurement */
        if (metrics->measurements_count < metrics->max_measurements)
        {
                metrics->measurements[metrics->measurements_count++] = duration_us;
                LOG_DEBUG_EX(*metrics->log_module, "Duration: %lldus", duration_us);
        }
}


int compare(const void *a, const void *b)
{
        return (*(uint32_t *)a - *(uint32_t *)b);
}

/* Calculate the results of the measurement */
void timing_metrics_get_results(timing_metrics* metrics, timing_metrics_results* results)
{
        if (metrics == NULL)
                return;

        results->num_measurements = metrics->measurements_count;
        results->min = metrics->measurements[0];
        results->max = metrics->measurements[0];
        uint64_t average_sum = 0;

        /* Copy the array */
        uint32_t* measurements_copy = (uint32_t*) malloc(metrics->measurements_count * sizeof(uint32_t));
        if (measurements_copy == NULL)
                /* In case we cannot allocate memory for a copy, we just sort the actual data */
                measurements_copy = metrics->measurements;

        memcpy(measurements_copy, metrics->measurements, metrics->measurements_count * sizeof(uint32_t));

        /* Sort the measurements */
        qsort(measurements_copy, metrics->measurements_count, sizeof(uint32_t), compare);

        /* Iterate over measurement array to find min and max and also to
         * sum all elements for average calculation. */
        for (int i = 0; i < metrics->measurements_count; i++)
        {
                average_sum += metrics->measurements[i];

                if (metrics->measurements[i] < results->min)
                        results->min = metrics->measurements[i];

                if (metrics->measurements[i] > results->max)
                        results->max = metrics->measurements[i];
        }

        /* Calculate average */
        results->avg = (double) average_sum / metrics->measurements_count;

        /* Calculate standard deviation */
        double sum = 0;
        for (int i = 0; i < metrics->measurements_count; i++)
        {
                double diff = metrics->measurements[i] - results->avg;
                sum += diff * diff;
        }
        results->std_dev = sqrt(sum / metrics->measurements_count);

        /* Calculate median */
        if (metrics->measurements_count % 2 == 0)
        {
                results->median = (measurements_copy[metrics->measurements_count / 2 - 1] +
                                   measurements_copy[metrics->measurements_count / 2]) / 2;
        }
        else
        {
                results->median = measurements_copy[metrics->measurements_count / 2];
        }

        /* Calculate 90th percentile */
        size_t index = (size_t)(metrics->measurements_count * 0.9);
        results->percentile_90 = measurements_copy[index];

        /* Calculate 99th percentile */
        index = (size_t)(metrics->measurements_count * 0.99);
        results->percentile_99 = measurements_copy[index];

        /* Free the copy if it was allocated */
        if (measurements_copy != metrics->measurements)
                free(measurements_copy);
}


/* Prepare the output file. This creates a new CSV file at `path` that is named
 * after the `name` argument passed to `timing_metrics_create()`. The final file
 * path is stored in the timing_metrics object.
 * If a file with the same name already exists, an incremental number is added to
 * the new file name.
 *
 * Returns 0 on success, -1 on failure.
 */
int timing_metrics_prepare_output_file(timing_metrics* metrics, char const* path)
{
#if defined(__ZEPHYR__) || defined(_WIN32)
        /* Not supported on Zephyr */
        return 0;
#else
        if (metrics == NULL)
                return 0; /* No error */

        if (path == NULL)
                return -1;

        int ret = 0;

        if (metrics->output_file != NULL)
                free(metrics->output_file);

        /* Generate the full output filename */
        metrics->output_file = (char*) malloc(1024);
        if (metrics->output_file == NULL)
                ERROR_OUT("Failed to allocate memory for file path.");

        strcpy(metrics->output_file, path);
        strcat(metrics->output_file, "/");
        strcat(metrics->output_file, metrics->name);
        strcat(metrics->output_file, ".csv");

        /* Check if the file already exists */
        int i = 1;
        while (access(metrics->output_file, F_OK) == 0)
        {
                LOG_DEBUG_EX(*metrics->log_module ,"File %s already exists", metrics->output_file);

                char* filename = strstr(metrics->output_file, metrics->name);
                if (filename == NULL)
                        ERROR_OUT("Error in filename handling.");

                char* extension = filename + strlen(metrics->name);

                /* Append a number to the filename */
                sprintf(extension, "_%d.csv", i);
                i += 1;
        }

        LOG_INFO_EX(*metrics->log_module ,"Output file: %s", metrics->output_file);

        /* Write initial information to the file to test if writing is possible */
        FILE* fptr = fopen(metrics->output_file, "w");
        if (fptr == NULL)
                ERROR_OUT("Failed to open file %s.", metrics->output_file);

        fprintf(fptr, "# name: %s\n", metrics->name);
        fprintf(fptr, "# all measurements are in microseconds\n");

cleanup:
        if (fptr != NULL)
                fclose(fptr);

        return ret;
#endif
}


/* Write the measured values in CSV format to the prepared output file.
 *
 * Returns 0 on success, -1 on failure.
 */
int timing_metrics_write_to_file(timing_metrics* metrics)
{
#if defined(__ZEPHYR__) || defined(_WIN32)
        /* Not supported on Zephyr */
        return 0;
#else
        if (metrics == NULL || metrics->output_file == NULL)
                return 0; /* No error */

        int ret = 0;

        /* Check if the file still exists */
        if (access(metrics->output_file, F_OK) != 0)
        {
                ERROR_OUT("File %s doesn't exist", metrics->output_file);

        }

        FILE* fptr = fopen(metrics->output_file, "a");
        if (fptr == NULL)
                ERROR_OUT("Failed to open file %s.", metrics->output_file);

        fprintf(fptr, "# measurements_count: %d\n", metrics->measurements_count);

        /* Get the results of the measurement */
        timing_metrics_results results = {0};
        timing_metrics_get_results(metrics, &results);

        /* Write the results to the file */
        fprintf(fptr, "# minimum: %d\n", results.min);
        fprintf(fptr, "# maximum: %d\n", results.max);
        fprintf(fptr, "# average: %.2f\n", results.avg);
        fprintf(fptr, "# standard deviation: %.2f\n", results.std_dev);
        fprintf(fptr, "# median: %.2f\n", results.median);
        fprintf(fptr, "# 90th percentile: %.0f\n", results.percentile_90);
        fprintf(fptr, "# 99th percentile: %.0f\n", results.percentile_99);

        fprintf(fptr, "\nduration\n");

        for (uint32_t i = 0; i < metrics->measurements_count; i++)
        {
                fprintf(fptr, "%d\n", metrics->measurements[i]);
        }

cleanup:
        if (fptr != NULL)
                fclose(fptr);

        return ret;
#endif
}


/* Destroy the timing_metrics object and free all memory */
void timing_metrics_destroy(timing_metrics** metrics)
{
        if (metrics != NULL && *metrics != NULL)
        {
                free((*metrics)->measurements);

                if ((*metrics)->output_file != NULL)
                        free((*metrics)->output_file);

                free(*metrics);
                *metrics = NULL;
        }
}
