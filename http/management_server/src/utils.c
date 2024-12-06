

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "asl.h"
#include "logging.h"
#include "utils.h"

LOG_MODULE_CREATE(utils_logmodule);

// Function to create a file path by combining folder path and file name

int create_file_path(char* dest_buffer,
                     size_t dest_buf_len,
                     const char* folder_path,
                     size_t folder_path_len,
                     const char* file_name,
                     size_t file_name_len)
{
        // Validate input parameters
        if (dest_buffer == NULL || folder_path == NULL || file_name == NULL)
        {
                return -1;
        }

        // If folder_path_len or file_name_len is 0, calculate the actual lengths
        if ((folder_path_len == 0) || (file_name_len == 0))
        {
                return -1;
        }

        // Ensure there's enough space in the destination buffer
        size_t total_len = folder_path_len + file_name_len + 2; // +2 for '/' and '\0'
        if (dest_buf_len < total_len)
        {
                printf("Insufficient buffer length\n");
                return -1;
        }

        // Start by copying the folder path to the destination buffer
        strncpy(dest_buffer, folder_path, folder_path_len);
        dest_buffer[folder_path_len] = '\0'; // Null-terminate to ensure safe strcat

        // Append a '/' if needed
        if (folder_path[folder_path_len - 1] != '/')
        {
                strncat(dest_buffer, "/", dest_buf_len - strlen(dest_buffer) - 1);
        }

        // Append the file name
        strncat(dest_buffer, file_name, dest_buf_len - strlen(dest_buffer) - 1);

        // Final null-termination (just in case)
        dest_buffer[dest_buf_len - 1] = '\0';

        return 0;
}

/**
 * this function dynamically allocates a buffer for the files content and stores it into buffer.
 * The file size is stored into buffersize
 * !free buffer after its usage */
int read_file(const char* filename, uint8_t** buffer, int* buffer_size)
{
        int ret = 0;
        if ((filename == NULL) || (buffer == NULL))
        {
                LOG_ERROR("read_file: filename or buffer is null");
                goto error_occured;
        }
        *buffer = NULL;
        FILE* file = NULL;

        file = fopen(filename, "r");
        if (!file)
        {
                LOG_ERROR("Error opening file: %s", filename);
                goto error_occured;
        }
        // https://cplusplus.com/reference/cstdio/fseek/
        //  go to  end
        fseek(file, 0, SEEK_END);
        // obtain position of file pointer
        int file_size = ftell(file);
        LOG_DEBUG("file is %d bytes long", file_size);
        // go back to position 0
        fseek(file, 0, SEEK_SET);

        *buffer = (char*) malloc(file_size + 1);
        if (!*buffer)
        {
                ret = -1;
                LOG_ERROR("Memory allocation failed");
                goto error_occured;
        }
        fread(*buffer, 1, file_size, file);
        (*buffer)[file_size] = '\0';
        *buffer_size = file_size;

        fclose(file);
        return ret;

error_occured:
        LOG_ERROR("error read_file");
        if (ret > 0)
                ret = -1;
        if (file != NULL)
                fclose(file);
        if (*buffer != NULL)
                free(*buffer);
        *buffer_size = 0;
        return ret;
}

char* string_duplicate(char const* source)
{
        if (source == NULL)
                return NULL;

        char* dest = (char*) malloc(strlen(source) + 1);
        if (dest == NULL)
        {
                LOG_ERROR("unable to allocate memory for string duplication");
                return NULL;
        }
        strcpy(dest, source);

        return dest;
}

int write_file(const char* filename, char* buffer, int buffer_size)
{
        int ret = 0;
        FILE* file = NULL;

        if ((filename == NULL) || (buffer == NULL))
                goto error_occured;

        file = fopen(filename, "w");
        if (!file)
        {
                LOG_ERROR("Error opening file: %s\n", filename);
                ret = -1;
                goto error_occured;
        }
        // Write the buffer to the file with the specified length
        size_t written = fwrite(buffer, sizeof(char), buffer_size, file);
        if (written != buffer_size)
        {
                LOG_ERROR("Error writing buffer to file: %s\n", filename);
                ret = -1;
                goto error_occured;
        }

        if (file != NULL)
                fclose(file);
        return ret;
error_occured:
        if (ret > 0)
                ret = -1;
        if (file != NULL)
                fclose(file);
        return ret;
}

int directory_exists(const char* path)
{
        return (access(path, F_OK) != -1); // F_OK checks for existence
}
int create_directory(const char* path)
{
        if (mkdir(path, 0755) == -1)
        {
                if (errno == EEXIST)
                {
                        LOG_DEBUG("Directory '%s' already exists.\n", path);
                        return 0;
                }
                else
                {
                        LOG_ERROR("mkdir");
                        return -1;
                }
        }
        printf("Directory '%s' created successfully.\n", path);
        return 0;
}

void ensure_trailing_slash(char* path, size_t size)
{
        size_t len = strlen(path);
        if (len > 0 && path[len - 1] != '/')
        {
                if (len + 1 < size)
                {
                        path[len] = '/';
                        path[len + 1] = '\0';
                }
        }
}

// !not working with url
int parse_addr_toKritis3maddr(char* ip_port, Kritis3mSockaddr* dst)
{
        uint16_t port = 0;
        char ip[INET6_ADDRSTRLEN];
        int proto_family = -1;
        int ret = 0;

        // Validate input
        if (ip_port == NULL)
        {
                goto error_occured;
        }
        ret = parse_endpoint_addr(ip_port, ip, INET6_ADDRSTRLEN, &port);
        if (ret < 0)
                goto error_occured;

        if (inet_pton(AF_INET, ip, &dst->sockaddr_in.sin_addr) == 1)
        {
                dst->sockaddr_in.sin_family = AF_INET;
                dst->sockaddr_in.sin_port = htons(port);
        }
        else if (inet_pton(AF_INET6, ip, &dst->sockaddr_in6.sin6_addr) == 1)
        {
                dst->sockaddr_in6.sin6_family = AF_INET6;
                dst->sockaddr_in6.sin6_port = htons(port);
        }
        else
        {
                goto error_occured;
        }

        return 0;

error_occured:
        LOG_ERROR("can't parse json ip format to KRITIS3MSocket");
        return -1;
}

int parse_endpoint_addr(const char* endpoint_addr, char* dst_ip, int dst_ip_len, uint16_t* port)
{
        if (!endpoint_addr || !dst_ip || dst_ip_len <= 0 || !port)
        {
                return -1; // Invalid parameters
        }

        const char* port_str = NULL;
        const char* addr_start = endpoint_addr;
        const char* addr_end = NULL;
        size_t addr_len;

        // Initialize output parameters
        *port = 0;
        dst_ip[0] = '\0';

        // Check if this is an IPv6 address (contains multiple colons)
        int colon_count = 0;
        const char* p = endpoint_addr;
        while (*p)
        {
                if (*p == ':')
                        colon_count++;
                p++;
        }

        if (colon_count > 1)
        { // IPv6 address
                // Check if address is wrapped in brackets
                if (endpoint_addr[0] == '[')
                {
                        addr_start = endpoint_addr + 1;
                        const char* closing_bracket = strchr(addr_start, ']');
                        if (!closing_bracket)
                        {
                                return -1; // Malformed IPv6 address
                        }
                        addr_end = closing_bracket;

                        // Check for port after the brackets
                        if (*(closing_bracket + 1) == ':')
                        {
                                port_str = closing_bracket + 2;
                        }
                        else if (*(closing_bracket + 1) != '\0')
                        {
                                return -1; // Invalid character after IPv6 address
                        }
                }
                else
                {
                        // No brackets, must be just an IPv6 address without port
                        addr_end = endpoint_addr + strlen(endpoint_addr);
                }
        }
        else
        { // IPv4 address or hostname
                const char* colon = strchr(endpoint_addr, ':');
                if (colon)
                {
                        addr_end = colon;
                        port_str = colon + 1;
                }
                else
                {
                        // Check if the string is all digits (just a port)
                        int all_digits = 1;
                        for (p = endpoint_addr; *p; p++)
                        {
                                if (!isdigit((unsigned char) *p))
                                {
                                        all_digits = 0;
                                        break;
                                }
                        }

                        if (all_digits)
                        {
                                port_str = endpoint_addr;
                                addr_start = NULL;
                        }
                        else
                        {
                                addr_end = endpoint_addr + strlen(endpoint_addr);
                        }
                }
        }

        // Parse port if present
        if (port_str)
        {
                char* endptr;
                long port_val = strtol(port_str, &endptr, 10);
                if (*endptr != '\0' || port_val < 0 || port_val > 65535)
                {
                        return -1; // Invalid port number
                }
                *port = (uint16_t) port_val;
        }

        // Copy address/hostname if present
        if (addr_start)
        {
                addr_len = addr_end - addr_start;
                if (addr_len >= (size_t) dst_ip_len)
                {
                        return -1; // Buffer too small
                }
                memcpy(dst_ip, addr_start, addr_len);
                dst_ip[addr_len] = '\0';
        }

        return 0;
}