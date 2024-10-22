
#include "utils.h"
#include "logging.h"

LOG_MODULE_CREATE(utils_logmodule);

#include <sys/types.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include "asl.h"
#include <netinet/in.h>

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

uint64_t parse_time_string(const char *time_str) {
    struct tm tm = {0};
    char *fraction_ptr;
    long timezone_offset = 0;
    long nanoseconds = 0;
    int offset_sign = 1;

    // Parse the date and time part
    strptime(time_str, "%Y-%m-%dT%H:%M:%S", &tm);

    // Find the start of the fractional seconds and timezone
    fraction_ptr = strchr(time_str, '.');
    if (fraction_ptr) {
        // Parse the fractional part (nanoseconds)
        sscanf(fraction_ptr, ".%9ld", &nanoseconds);

        // Parse timezone offset (+02:00) part after the seconds
        char sign;
        int hours, minutes;
        sscanf(fraction_ptr + 10, "%c%02d:%02d", &sign, &hours, &minutes);
        offset_sign = (sign == '-') ? -1 : 1;
        timezone_offset = offset_sign * (hours * 3600 + minutes * 60);
    }

    // Convert tm to time_t (seconds since epoch)
    time_t epoch_seconds = mktime(&tm);

    // Apply the timezone offset
    epoch_seconds -= timezone_offset;

    // Convert to nanoseconds and add fractional nanoseconds
    uint64_t total_nanoseconds = (uint64_t)epoch_seconds * 1000000000ULL + nanoseconds;

    return total_nanoseconds;
}

int parse_ip_port_to_sockaddr_in(char *ip_port, struct sockaddr_in *dst)
{
    int ret = 0;
    memset(dst, 0, sizeof(struct sockaddr_in));
    char ip[INET_ADDRSTRLEN] = {0};
    int port = 0;

    // Initialize sockaddr_in
    dst->sin_family = AF_INET;

    if (ip_port == NULL)
    {
        LOG_ERROR("ip_port is NULL");
        return -1;
    }
    else if (strcmp(ip_port, "*:*") == 0) // Check for the format "*:*"
    {
        dst->sin_addr.s_addr = htonl(INADDR_ANY); // 0.0.0.0
        dst->sin_port = 0;                        // Port 0 (any port)
        ret = 0;
    }
    else if (sscanf(ip_port, "%[^:]:%d", ip, &port) == 2) // Parse the ip:port string
    {
        // Handle the case "*:<port>"
        if (strcmp(ip, "*") == 0)
        {
            dst->sin_addr.s_addr = htonl(INADDR_ANY); // 0.0.0.0
            dst->sin_port = htons(port);              // Set the provided port
        }
        // Handle the case "<ip>:<port>"
        else
        {
            if (inet_pton(AF_INET, ip, &dst->sin_addr) <= 0)
            {
                LOG_ERROR("Invalid IP address: %s", ip);
                ret = -1;
            }
            dst->sin_port = htons(port); // Set the provided port
        }
    }
    else if (sscanf(ip_port, "%[^:]:*", ip) == 1) // Handle the case "<ip>:*"
    {
        if (strcmp(ip, "*") == 0)
        {
            dst->sin_addr.s_addr = htonl(INADDR_ANY); // 0.0.0.0
        }
        else
        {
            if (inet_pton(AF_INET, ip, &dst->sin_addr) <= 0)
            {
                LOG_ERROR("Invalid IP address: %s", ip);
                ret = -1;
            }
        }
        dst->sin_port = 0; // Port 0 (any port)
    }
    // Invalid format
    else
    {
        LOG_ERROR("Can't parse IP address and port from the string: %s", ip_port);
        ret = -1;
    }
    return ret;
}
int extract_addr_from_url(const char *url, struct sockaddr_in *addr)
{
    int ret = 0;
    char ip[INET_ADDRSTRLEN] = {0};
    int port = 0;
    int offset = 0;
    const char *http = "http://";
    const char *https = "https://";
    if (addr == NULL)
        goto error_occured;
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
    if (inet_pton(AF_INET, ip, &addr->sin_addr) <= 0)
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
        // Check if the port part is a wildcard '*'
        if (strcmp(colon_pos + 1, "*") == 0)
        {
            return 0; // Assign port 0 if wildcard is found
        }

        // Otherwise, convert the port to an integer
        int port = atoi(colon_pos + 1);

        // Validate the port number range (0 to 65535)
        if (port >= 0 && port <= 65535)
        {
            return port;
        }
    }

    // Return -1 for invalid format or out-of-range port
    return -1;
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
char *extract_path_from_url( char *full_url)
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