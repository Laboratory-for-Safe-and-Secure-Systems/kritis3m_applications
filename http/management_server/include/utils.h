#ifndef UTILS_H__
#define UTILS_H__

#include <netinet/in.h>
#include "kritis3m_configuration.h"

// Function to create a file path by combining folder path and file name
int create_file_path(char *dest_buffer, size_t dest_buf_len,
                     const char *folder_path, size_t folder_path_len,
                     const char *file_name, size_t file_name_len);

/**
 * this function dynamically allocates a buffer for the files content and stores it into buffer.
 * The file size is stored into buffersize
 * !free buffer after its usage */
int read_file(const char *filename, uint8_t **buffer, int *buffer_size);
int write_file(const char *filename, char *buffer, int buffer_size);
char *string_duplicate(char const *source);
int create_directory(const char *path);
void ensure_trailing_slash(char *path, size_t size);



int parse_addr_toKritis3maddr(char* ip_port, Kritis3mSockaddr *dst);
int parse_endpoint_addr(const char *endpoint_addr, char *dst_ip, int dst_ip_len, uint16_t *port);
int directory_exists(const char *path); 

uint64_t parse_time_string(const char *time_str); 
#endif