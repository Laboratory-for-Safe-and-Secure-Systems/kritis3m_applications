#ifndef POLL_SET_H
#define POLL_SET_H


#include <stdint.h>
#include <sys/socket.h>
#include <poll.h>


#ifdef CONFIG_NET_SOCKETS_POLL_MAX
#define NUM_FDS CONFIG_NET_SOCKETS_POLL_MAX
#else
#define NUM_FDS 30
#endif


typedef struct poll_set 
{
	struct pollfd fds[NUM_FDS];
	int num_fds;
}
poll_set;


/* Method declarations for interacting with a poll set */
void poll_set_init(poll_set* poll_set);

int poll_set_add_fd(poll_set* poll_set, int fd, short events);
void poll_set_remove_fd(poll_set* poll_set, int fd);

void poll_set_update_events(poll_set* poll_set, int fd, short events);
void poll_set_add_events(poll_set* poll_set, int fd, short events);
void poll_set_remove_events(poll_set* poll_set, int fd, short events);



#endif
