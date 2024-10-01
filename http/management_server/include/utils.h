#ifndef UTILS_H__
#define UTILS_H__

#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include "asl.h"
#include "logging.h"
#include <netinet/in.h>
LOG_MODULE_CREATE(utils_logmodule);

// Function to create a file path by combining folder path and file name
int create_file_path(char *dest_buffer, size_t dest_buf_len,
                     const char *folder_path, size_t folder_path_len,
                     const char *file_name, size_t file_name_len)
{
    int ret = 0;
    // Ensure the destination buffer has enough space for both paths and the null terminator
    if (dest_buf_len < folder_path_len + file_name_len + 2)
    { // +2 for '/' and '\0'
        LOG_ERROR("insufficient length");
        return -1;
    }

    // Check if the folder path ends with a slash
    int needs_slash = (folder_path[folder_path_len - 1] != '/');

    // Construct the path based on whether a slash is needed
    if (needs_slash)
    {
        ret = snprintf(dest_buffer, dest_buf_len, "%.*s/%.*s",
                       (int)folder_path_len, folder_path,
                       (int)file_name_len, file_name);
    }
    else
    {
        ret = snprintf(dest_buffer, dest_buf_len, "%.*s%.*s",
                       (int)folder_path_len, folder_path,
                       (int)file_name_len, file_name);
    }
    return ret;
}

int parse_IPv4_fromIpPort(const char *src_ip_port, char *dst_ip)
{
    // Find the position of the colon
    const char *colon_pos = strchr(src_ip_port, ':');

    if (colon_pos != NULL)
    {
        // Copy the part before the colon to the ip_address
        size_t ip_length = colon_pos - src_ip_port;
        strncpy(dst_ip, src_ip_port, ip_length);
        return 1;
    }
    else if (colon_pos == NULL)
    {
        // If no colon is found, assume the entire input is an IP address
        char *ip = "0.0.0.0";
        int len = strlen(ip);
        strncpy(dst_ip, ip, len);
        return 1;
    }
    return -1;
}

int extrack_addr_from_url(const char *url, struct sockaddr_in *addr)
{
    int ret = 0;
    char ip[INET_ADDRSTRLEN] = {0};
    int port = 0;
    int offset = 0;
    const char *http = "http://";
    const char *https = "https://";
    // Check if the URL starts with "https://"
    if (strncmp(url, https, strlen(https)) != 0)
    {
        LOG_WARN("Url is not HTTPS");
        if (strncmp(url, http, strlen(http)) != 0)
        {
            LOG_ERROR("Url is not HTTPS and HTTP, can't extract addr from url, errno: %d", errno);
            goto error_occured;
        }
        else
        {
            // case http
            offset = strlen(http);
        }
    }
    else
    {
        // case https
        offset = strlen(https);
    }
    // Extract IP and port (assuming IP address is after "https://")
    if (sscanf(url + offset, "%[^:]:%d", ip, &port) != 2)
    {
        LOG_ERROR("cant parse ip address and port from the url");
        goto error_occured;
    }

    // Clear the sockaddr_in structure
    memset(addr, 0, sizeof(addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);

    // Convert IP address from string to binary form
    if (inet_pton(AF_INET, ip, addr->sin_addr) <= 0)
    {
        LOG_ERROR("cant covert ip address from string");
        goto error_occured;
    }
    return ret;
error_occured:
    ret = -1;
    return ret;
}

int parse_port_fromIpPort(const char *src_ip_port)
{
    // Find the position of the colon
    const char *colon_pos = strchr(src_ip_port, ':');

    if (colon_pos != NULL)
    {
        // found
        return atoi(colon_pos + 1);
    }
    return -1;
}

/**
 * this function dynamically allocates a buffer for the files content and stores it into buffer.
 * The file size is stored into buffersize
 * !free buffer after its usage */
int read_file(const char *filename, char *buffer, int *buffer_size)
{
    int ret = 0;
    FILE *file = fopen(filename, "r");
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

    buffer = (char *)malloc(file_size + 1);
    if (!buffer)
    {
        ret = -1;
        LOG_ERROR("Memory allocation failed\n");
        goto error_occured;
    }
    fread(buffer, 1, file_size, file);
    buffer[file_size] = '\0';
    fclose(file);

    return ret;

error_occured:
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

#endif