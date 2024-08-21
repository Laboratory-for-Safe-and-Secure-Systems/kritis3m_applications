
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>

#include "timing_metrics.h"


timing_metrics* timing_metrics_create(char const* output_path, char const* filename, log_module* log_module)
{
        timing_metrics* self = malloc(sizeof(timing_metrics));

        if(self != NULL)
        {
                self->start_time.tv_sec = 0;
                self->start_time.tv_nsec = 0;

                self->end_time.tv_sec = 0;
                self->end_time.tv_nsec = 0;

                self->log_module = log_module;

                if (output_path != NULL && filename != NULL)
                {
                        self->file = (char*) malloc(PATH_MAX);
                        if (self->file == NULL)
                        {
                                printf("Failed to allocate memory for file path.");
                                exit(1);
                        }
                        strcpy(self->file, output_path);
                        strcat(self->file, "/");
                        strcat(self->file, filename);

                        if (access(self->file, F_OK) != 0)
                        {
                                FILE* fptr = fopen(self->file, "w");

                                if(fptr == NULL)
                                {
                                        printf("Failed to open file %s.", self->file);
                                        exit(1);
                                }

                                fprintf(fptr, "duration\n");

                                fclose(fptr);
                        }
                }
                else
                {
                        self->file = NULL;
                }
        }

        return self;
}


void timing_metrics_start_measurement(timing_metrics* metrics)
{
        if (metrics == NULL)
                return;

        if(clock_gettime(CLOCK_MONOTONIC, &metrics->start_time) != 0)
                LOG_ERROR_EX(*metrics->log_module, "Error in clock_gettime() - start_time.");
}


void timing_metrics_end_measurement(timing_metrics* metrics)
{
        if (metrics == NULL)
                return;

        if(clock_gettime(CLOCK_MONOTONIC, &metrics->end_time) != 0)
                LOG_ERROR_EX(*metrics->log_module, "Error in clock_gettime() - end_time.");
}


void timing_metrics_print(timing_metrics* metrics)
{
        if (metrics == NULL)
                return;

        long long duration_us = (metrics->end_time.tv_sec - metrics->start_time.tv_sec) * 1000000.0 +
                                (metrics->end_time.tv_nsec - metrics->start_time.tv_nsec) / 1000.0;

        LOG_DEBUG_EX(*metrics->log_module, "Duration: %lldus", duration_us);

        if (metrics->file != NULL)
        {
                FILE* fptr = fopen(metrics->file, "a");

                if(fptr == NULL)
                {
                        printf("Failed to open file %s.", metrics->file);
                        return;
                }

                fprintf(fptr, "%lld\n", duration_us);

                fclose(fptr);
        }
}


void timing_metrics_destroy(timing_metrics** metrics)
{
        if (metrics != NULL && *metrics != NULL)
        {
                if ((*metrics)->file != NULL)
                {
                        free((*metrics)->file);
                }

                free(*metrics);
                *metrics = NULL;
        }
}
