#ifndef _FILE_IO_H_
#define _FILE_IO_H_

#include <inttypes.h>
#include <stdbool.h>
#include <unistd.h>

#ifdef _WIN32

#include <io.h>
#define F_OK 0
#define access _access

#endif

#ifndef __ZEPHYR__

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

#endif

/**
 * @brief Reads the contents of a file into a buffer. If the buffer is already allocated and filled
 * with data, it will be reallocated to fit the new additional data.
 *
 * @param filePath Path to the file to be read.
 * @param buffer Pointer to a buffer for storing the file's contents. If NULL, memory will be allocated.
 * @param bytesInBuffer Pointer to a variable containg the current number of bytes in the buffer.
 *      If 0 and buffer is NULL, memory will be allocated. Will be updated with the new number after the
 *      read operation.
 *
 * @return Number of bytes read on success, or -1 on error.
 */
int read_file(const char* filePath, uint8_t** buffer, size_t* bytesInBuffer);

/**
 * @brief Writes a buffer to a file.
 *
 * @param filename Path to the file to be written.
 * @param buffer Pointer to the buffer to be written.
 * @param buffer_size Size of the buffer.
 * @param append If true, the data will be appended to the file. Otherwise, the file will be overwritten.
 *
 * @return Number of bytes written on success, or -1 on error.
 */
int write_file(const char* filename, uint8_t const* buffer, size_t buffer_size, bool append);

/**
 * @brief Dynamically duplicates a string.
 *
 * @param source Pointer to the source string to duplicate.
 *
 * @return Pointer to the duplicated string, or NULL if allocation fails or source is NULL.
 */
char* duplicate_string(char const* source);

#ifndef __ZEPHYR__

/* Get a properly initialized, empty certificates object */
certificates get_empty_certificates(void);

/* Read all certificate and key files from the paths provided in the `certs`
 * structure and store the data in the buffers. Memory is allocated internally
 * and must be freed by the user.
 *
 * Returns 0 on success, -1 on failure (error is printed on console). */
int read_certificates(certificates* certs);

// free mem
void cleanup_certificates(certificates* certs);

#endif

// check if file estists
int file_exists(const char* filepath);

#endif //_FILE_IO_H_