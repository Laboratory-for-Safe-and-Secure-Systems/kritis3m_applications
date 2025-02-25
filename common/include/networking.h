#ifndef NETWORKING_H
#define NETWORKING_H

#if defined(__ZEPHYR__)
#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>

#define closesocket close
#define addrinfo zsock_addrinfo
#elif defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>

#include <netioapi.h>

#define poll WSAPoll

#define net_addr_ntop inet_ntop
#define net_addr_pton inet_pton
#else
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

#include <netdb.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>

#define closesocket close

#define net_addr_ntop inet_ntop
#define net_addr_pton inet_pton
#endif

#include <stdbool.h>
#include <stdint.h>

struct network_interfaces
{
        void* management;
        void* lan;
        void* wan;
};

/* Initialize the network interfaces */
int initialize_network_interfaces(int32_t log_level);

/* Get a const pointer to the initialized structure containing the network interfaces */
struct network_interfaces const* network_interfaces(void);

/* Add an ip address to a network interface */
int add_ip_address(const void* iface, const char* ip_addr, const char* cidr, bool is_ipv6);

/* Remove an ip address from a network interface */
int remove_ipv4_address(const void* iface, const char* ip_addr, const char* cidr, bool is_ipv6);

/* Helper method to set a socket to (non) blocking */
int setblocking(int fd, bool val);

/* Generic method to create a socketpair for inter-thread communication */
int create_socketpair(int socket_pair[2]);

/* Lookup the provided outgoing destination and fill the linked-list accordingly. */
int address_lookup_client(char const* dest, uint16_t port, struct addrinfo** addr, int family);

/* Lookup the provided incoming destination and fill the linked-list accordingly. */
int address_lookup_server(char const* dest, uint16_t port, struct addrinfo** addr, int family);

/* Create a new listening socket for given type and address.
 *
 * Return value is the socket file descriptor or -1 in case of an error.
 */
int create_listening_socket(int type, struct sockaddr* addr, socklen_t addr_len);

/* Create a new client socket for given type and address.
 *
 * Return value is the socket file descriptor or -1 in case of an error
 */
int create_client_socket(int type);

/* Configure a peer socket obtained from an accept() call to a listening socket.
 *
 * Returns 0 in case of success, -1 otherwise.
 */
int configure_peer_socket(int peer_sock);

/**
 * @brief Parses an input string to extract an IP address and port number.
 *
 * @param input The input string containing an IP address and/or port (e.g., "127.0.0.1:4433",
 * "[::1]:4433", "localhost:4433").
 * @param ip Pointer to a string where the extracted IP address will be stored. Memory is allocated
 * dynamically and must be freed by the caller.
 * @param port Pointer to a `uint16_t` where the extracted port number will be stored. If no port is
 * provided, it will be set to 0.
 * @return 0 on success, -1 on failure (error messages are logged).
 *
 * @note The function supports IPv4, IPv6, and URI formats, and checks for invalid port numbers or
 * malformed input.
 */
int parse_ip_address(char* input, char** ip, uint16_t* port);

int parse_ip_cidr(const char* ip_cidr, char* ip_addr, size_t ip_len, char* cidr, size_t cidr_len);

int is_ipv6(const char* ip_str);

#endif
