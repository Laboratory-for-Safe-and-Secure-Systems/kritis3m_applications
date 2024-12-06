
#include <errno.h>

#include "poll_set.h"

void poll_set_init(poll_set* poll_set)
{
        poll_set->num_fds = 0;

        for (int i = 0; i < NUM_FDS; i++)
        {
                poll_set->fds[i].fd = -1;
                poll_set->fds[i].events = 0;
        }
}

int poll_set_add_fd(poll_set* poll_set, int fd, short events)
{
        if (poll_set->num_fds < NUM_FDS)
        {
                int i = poll_set->num_fds++;

                poll_set->fds[i].fd = fd;
                poll_set->fds[i].events = events;
                poll_set->fds[i].revents = 0;

                return 0;
        }
        else
        {
                return -1;
        }
}

void poll_set_update_events(poll_set* poll_set, int fd, short events)
{
        for (int i = 0; i < poll_set->num_fds; i++)
        {
                if (poll_set->fds[i].fd == fd)
                {
                        poll_set->fds[i].events = events;
                }
        }
}

void poll_set_add_events(poll_set* poll_set, int fd, short events)
{
        for (int i = 0; i < poll_set->num_fds; i++)
        {
                if (poll_set->fds[i].fd == fd)
                {
                        poll_set->fds[i].events |= events;
                }
        }
}

void poll_set_remove_events(poll_set* poll_set, int fd, short events)
{
        for (int i = 0; i < poll_set->num_fds; i++)
        {
                if (poll_set->fds[i].fd == fd)
                {
                        poll_set->fds[i].events &= ~events;
                }
        }
}

void poll_set_remove_fd(poll_set* poll_set, int fd)
{
        for (int i = 0; i < poll_set->num_fds; i++)
        {
                if (poll_set->fds[i].fd == fd)
                {
                        /* Move all remaining fds one slot down to fill the hole in the array */
                        for (int j = i; j < (poll_set->num_fds - 1); j++)
                        {
                                poll_set->fds[j] = poll_set->fds[j + 1];
                        }

                        poll_set->fds[poll_set->num_fds - 1].fd = -1;
                        poll_set->fds[poll_set->num_fds - 1].events = 0;

                        poll_set->num_fds -= 1;

                        break;
                }
        }
}
