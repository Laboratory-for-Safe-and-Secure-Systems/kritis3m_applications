
#include "utils.h"
#include "logging.h"

#include <sys/types.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include "asl.h"
#include <netinet/in.h>

LOG_MODULE_CREATE(utils_logmodule);

// Function to create a file path by combining folder path and file name

int create_file_path(char *dest_buffer, size_t dest_buf_len,
                     const char *folder_path, size_t folder_path_len,
                     const char *file_name, size_t file_name_len)
{
    // Validate input parameters
    if (dest_buffer == NULL || folder_path == NULL || file_name == NULL)
    {
        return -1;
    }

    // If folder_path_len or file_name_len is 0, calculate the actual lengths
    if (folder_path_len == 0)
    {
        folder_path_len = strlen(folder_path);
    }
    if (file_name_len == 0)
    {
        file_name_len = strlen(file_name);
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
int read_file(const char *filename, uint8_t **buffer, int *buffer_size)
{
    int ret = 0;
    if ((filename == NULL) || (buffer == NULL))
        goto error_occured;
    *buffer = NULL;
    FILE *file = NULL;

    file = fopen(filename, "r");
    if (!file)
    {
        LOG_ERROR("Error opening file: %s\n", filename);
        ret = -1;
        goto error_occured;
    }
    // https://cplusplus.com/reference/cstdio/fseek/
    //  go to  end
    fseek(file, 0, SEEK_END);
    // obtain position of file pointer
    long file_size = ftell(file);
    // go back to position 0
    fseek(file, 0, SEEK_SET);

    *buffer = (char *)malloc(file_size + 1);
    if (!*buffer)
    {
        ret = -1;
        LOG_ERROR("Memory allocation failed\n");
        goto error_occured;
    }
    fread(*buffer, 1, file_size, file);
    (*buffer)[file_size] = '\0';
    *buffer_size = file_size;

    fclose(file);
    return ret;

error_occured:
    if (ret > 0)
        ret = -1;
    if (file != NULL)
        fclose(file);
    if (*buffer != NULL)
        free(*buffer);
    *buffer_size = 0;
    return ret;
}

char *duplicate_string(char const *source)
{
    if (source == NULL)
        return NULL;

    char *dest = (char *)malloc(strlen(source) + 1);
    if (dest == NULL)
    {
        LOG_ERROR("unable to allocate memory for string duplication");
        return NULL;
    }
    strcpy(dest, source);

    return dest;
}

int write_file(const char *filename, char *buffer, int buffer_size)
{
    int ret = 0;
    FILE *file = NULL;

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

int create_directory(const char *path)
{
    if (mkdir(path, 0755) == -1)
    {
        if (errno == EEXIST)
        {
            printf("Directory '%s' already exists.\n", path);
            return 0;
        }
        else
        {
            perror("mkdir");
            return -1;
        }
    }
    printf("Directory '%s' created successfully.\n", path);
    return 0;
}

void ensure_trailing_slash(char *path, size_t size)
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
char *extract_path_from_url(char *full_url)
{

    char *protocol_end = strstr(full_url, "://");
    if (protocol_end == NULL)
    {
        protocol_end = full_url; // No protocol found, start from beginning
    }
    else
    {
        protocol_end += 3; // Skip "://"
    }

    // Find the first slash after the protocol
    char *path_start = strchr(protocol_end, '/');

    if (path_start != NULL)
    {
        // Return the pointer to the beginning of the path
        return path_start;
    }

    return NULL;
}

// !not working with url
int parse_addr_toKritis3maddr(char *ip_port, Kritis3mSockaddr *dst)
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
    ret = parse_endpoint_addr(ip_port, ip,INET6_ADDRSTRLEN, &port);
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

int parse_endpoint_addr(const char *endpoint_addr, char *dst_ip, int dst_ip_len, uint16_t *port)
{
    if (!endpoint_addr || !dst_ip || !port)
    {
        LOG_ERROR("can't parse ip addr");
        return -1;
    }

    // Find the last colon to handle IPv6 addresses
    char *last_colon = strrchr(endpoint_addr, ':');
    if (!last_colon)
    {
        LOG_ERROR("can't parse ip addr. Didnt found <:> ");
        return -1;
    }

    // Copy address part, handling IPv6 brackets
    size_t addr_len = last_colon - endpoint_addr;
    if (dst_ip_len < addr_len){
        LOG_ERROR("dst_buffer to small. cant store endpoint");
        return -1;
    }  

    if (endpoint_addr[0] == '[' && endpoint_addr[addr_len - 1] == ']')
    {
        // Remove brackets for IPv6
        strncpy(dst_ip, endpoint_addr + 1, addr_len - 2);
        dst_ip[addr_len - 2] = '\0';
    }
    else
    {
        // Regular address copy
        strncpy(dst_ip, endpoint_addr, addr_len);
        dst_ip[addr_len] = '\0';
    }

    // Parse port
    char *port_str = last_colon + 1;
    char *endptr;
    long port_val = strtol(port_str, &endptr, 10);

    // Validate port parsing
    if (*endptr != '\0' ||
        port_val < 0 ||
        port_val > 65535)
    {
        LOG_ERROR("port invalid");
        return -1;
    }

    *port = (uint16_t)port_val;
    return 0;
}