#ifndef NETWORKING_H
#define NETWORKING_H

#if defined(__ZEPHYR__)

#include <zephyr/net/net_if.h>

#else

#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define net_addr_ntop inet_ntop
#define net_addr_pton inet_pton

#endif

struct network_interfaces
{
	void *management;
	void *asset;
	void *tunnel;
};

/* Initialize the network interfaces */
int initialize_network_interfaces();

/* Get a const pointer to the initialized structure containing the network interfaces */
struct network_interfaces const *network_interfaces(void);

/* Add an ip address to a network interface */
int add_ipv4_address(void *iface, struct in_addr ipv4_addr);

/* Remove an ip address from a network interface */
int remove_ipv4_address(void *iface, struct in_addr ipv4_addr);

/* Helper method to set a socket to (non) blocking */
int setblocking(int fd, bool val);

/* Temporary helper method to send data synchronously */
int blocking_send(int fd, char *data, size_t length);

#endif