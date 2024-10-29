#ifndef NETWORKING_H
#define NETWORKING_H

#if defined(__ZEPHYR__)

#include <zephyr/net/net_if.h>

#define closesocket close

#elif defined(_WIN32)

#include <stdbool.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define poll WSAPoll

#define net_addr_ntop inet_ntop
#define net_addr_pton inet_pton

#else

#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#define closesocket close

#define net_addr_ntop inet_ntop
#define net_addr_pton inet_pton

#endif

struct network_interfaces
{
	void* management;
	void* lan;
	void* wan;
};


/* Initialize the network interfaces */
int initialize_network_interfaces();


/* Get a const pointer to the initialized structure containing the network interfaces */
struct network_interfaces const* network_interfaces(void);


/* Add an ip address to a network interface */
int add_ipv4_address(void* iface, struct in_addr ipv4_addr);


/* Remove an ip address from a network interface */
int remove_ipv4_address(void* iface, struct in_addr ipv4_addr);


/* Helper method to set a socket to (non) blocking */
int setblocking(int fd, bool val);


/* Generic method to create a socketpair for inter-thread communication */
int create_socketpair(int socket_pair[2]);


/* Lookup the provided destination and fill the struct accordingly. */
int address_lookup(char const* dest, uint16_t port, struct addrinfo** addr);


#endif
