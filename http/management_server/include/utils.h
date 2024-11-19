#ifndef UTILS_H__
#define UTILS_H__

#include <netinet/in.h>

// Function to create a file path by combining folder path and file name
int create_file_path(char *dest_buffer, size_t dest_buf_len,
                     const char *folder_path, size_t folder_path_len,
                     const char *file_name, size_t file_name_len);

int parse_IPv4_fromIpPort(const char *src_ip_port, char *dst_ip);
int extract_addr_from_url(const char *url, struct sockaddr_in *addr);
char* extract_path_from_url(char *url);
int parse_ip_port_to_sockaddr_in(char *ip_port, struct sockaddr_in *ret);
int parse_port_fromIpPort(const char *src_ip_port);
/**
 * this function dynamically allocates a buffer for the files content and stores it into buffer.
 * The file size is stored into buffersize
 * !free buffer after its usage */
int read_file(const char *filename, uint8_t **buffer, int *buffer_size);
int write_file(const char *filename, char *buffer, int buffer_size);
char *duplicate_string(char const *source);
int create_directory(const char *path);
void ensure_trailing_slash(char *path, size_t size);



uint64_t parse_time_string(const char *time_str); 
#endif