#ifndef _IO_H_
#define _IO_H_

#include <inttypes.h>
#include <unistd.h>

typedef struct certificates
{
        char const* certificate_path;
        char const* private_key_path;
        char const* additional_key_path;
        char const* intermediate_path;
        char const* root_path;

        uint8_t* chain_buffer; /* Entity and intermediate certificates */
        size_t chain_buffer_size;

        uint8_t* key_buffer;
        size_t key_buffer_size;

        uint8_t* additional_key_buffer;
        size_t additional_key_buffer_size;

        uint8_t* root_buffer;
        size_t root_buffer_size;
} certificates;

/**
 * @brief Reads the contents of a file into a buffer.
 *
 * @param filePath Path to the file to be read.
 * @param buffer Pointer to a pointer for storing the file's contents. If NULL, memory will be allocated.
 * @param bufferSize Current size of the buffer. If 0 and buffer is NULL, memory will be allocated.
 * @return Number of bytes read on success, or -1 on error.
 */
int readFile(const char* filePath, uint8_t** buffer, size_t bufferSize);

int write_file(const char* filename, char* buffer, int buffer_size);

/**
 * @brief Dynamically duplicates a string.
 *
 * @param source Pointer to the source string to duplicate.
 * @return Pointer to the duplicated string, or NULL if allocation fails or source is NULL.
 */
char* duplicate_string(char const* source);

// reads certificates from filesystem into struct certs
int read_certificates(struct certificates* certs);

// free mem
void cleanup_certificates(struct certificates* certs);

// check if file estists
int file_exists(const char* filepath);

#endif //_IO_H_