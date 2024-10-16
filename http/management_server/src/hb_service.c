#include "hb_service.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "logging.h"
#include "mgmt_certs.h"
#include "cJSON.h"

LOG_MODULE_CREATE(hb_service);

/*********** FORWARD DECLARATIONS ******************/

struct http_user_data
{
    bool is_finished;
    bool error_occured;
    HeartbeatResponse response;
    char *error_msg;
};
struct TimerPipe
{
    int pipe_fds[2];
    timer_t timerid;
};

static TimerPipe timer_pipe = {0};

TimerPipe *get_timer_pipe() {return &timer_pipe;}

int get_clock_signal_fd(TimerPipe *pipe)
{
    int ret = pipe->pipe_fds[0];
    if (ret < 0)
    {
        LOG_ERROR("Error: Invalid file descriptor");
        return -1;
    }
    return ret;
}

static void timer_handler(union sigval arg)
{
    TimerPipe *tp = (TimerPipe *)arg.sival_ptr;
    uint8_t signal = 1;
    write(tp->pipe_fds[1], &signal, sizeof(signal)); // Notify the pipe on timer expiration
}

// Function to start the timer with the given interval
int timer_start(TimerPipe *pipe, uint32_t interval_sec)
{
    int ret = 0;
    struct itimerspec its;
    its.it_value.tv_sec = interval_sec;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = interval_sec; // Repeat at the same interval
    its.it_interval.tv_nsec = 0;

    if (timer_settime(pipe->timerid, 0, &its, NULL) == -1)
    {
        ret = -1;
        LOG_ERROR("timer_settime failed\n");
        return ret;
    }
    LOG_INFO("Timer started with interval %d seconds\n", interval_sec);
    return ret;
}

// Function to stop the timer
int timer_stop(TimerPipe *pipe)
{
    int ret = 0;
    struct itimerspec its;
    memset(&its, 0, sizeof(struct itimerspec)); // Set both interval and value to
                                                // zero to stop the timer

    if (timer_settime(pipe->timerid, 0, &its, NULL) == -1)
    {
        LOG_ERROR("timer_stop failed");
        ret = -1;
        return ret;
    }

    LOG_INFO("Timer stopped");
    return ret;
}

// Function to change the timer interval while it is running
int timer_change_interval(TimerPipe *pipe, int new_interval_sec)
{
    int ret = 0;
    struct itimerspec its;
    its.it_value.tv_sec = new_interval_sec;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = new_interval_sec;
    its.it_interval.tv_nsec = 0;

    if (timer_settime(pipe->timerid, 0, &its, NULL) == -1)
    {
        ret = -1;
        LOG_ERROR("timer_change_interval failed");
        return ret;
    }
    LOG_INFO("Timer interval changed to %d seconds", new_interval_sec);
    return ret;
}

// Initialize the POSIX timer and pipe for communication
int init_posix_timer(TimerPipe *timer_pipe)
{
    int ret = 0;
    struct sigevent sev;

    // Set up the pipe for communication
    if (pipe(timer_pipe->pipe_fds) == -1)
    {
        ret = -1;
        LOG_ERROR("pipe failed");
        return ret;
    }

    // Set pipe to non-blocking mode
    fcntl(timer_pipe->pipe_fds[0], F_SETFL, O_NONBLOCK);

    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_value.sival_ptr = timer_pipe;
    sev.sigev_notify_function = timer_handler;
    sev.sigev_notify_attributes = NULL; // Use default thread attributes

    if (timer_create(CLOCK_REALTIME, &sev, &timer_pipe->timerid) == -1)
    {
        ret = -1;
        LOG_ERROR("timer_create failed\n");
        return ret;
    }
    return ret;
}

// Function to terminate the timer and clean up resources
int timer_terminate(TimerPipe *timer_pipe)
{
    int ret = 0;

    // Stop the timer before deleting
    ret = timer_stop(timer_pipe);
    if (ret < 0)
    {
        LOG_ERROR("couldn't stop timer");
        ret = -1;
    }

    // Delete the timer
    if (timer_delete(timer_pipe->timerid) == -1)
    {
        LOG_ERROR("failed timer delete");
        ret = -1;
        return ret;
    }

    // Close the communication pipes
    close(timer_pipe->pipe_fds[0]);
    close(timer_pipe->pipe_fds[1]);

    LOG_INFO("Timer terminated");
    return ret;
}
