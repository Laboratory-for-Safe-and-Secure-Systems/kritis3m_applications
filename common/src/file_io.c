#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "file_io.h"
#include "logging.h"

LOG_MODULE_CREATE(file_io);

// asl defines
#define PKCS11_LABEL_IDENTIFIER "pkcs11:"
#define PKCS11_LABEL_IDENTIFIER_LEN 7

int read_file(const char* filePath, uint8_t** buffer, size_t* bytesInBuffer)
{
#ifndef __ZEPHYR__
        uint8_t* destination = NULL;
        if (!buffer || !filePath || !bytesInBuffer)
                return -1;

        /* Open the file */
        FILE* file = fopen(filePath, "rb");

        if (file == NULL)
        {
                LOG_ERROR("file (%s) cannot be opened (error %d: %s)", filePath, errno, strerror(errno));
                return -1;
        }

        /* Get length of file */
        fseek(file, 0, SEEK_END);
        long fileSize = ftell(file);
        rewind(file);

        /* Allocate buffer for file content. We allocate one byte more to store a NULL
         * byte after the read file content. This makes sure that in case we read an
         * ASCII string from the file, the string is properly null-terminated. */
        if ((*buffer == NULL) && (*bytesInBuffer == 0))
        {
                *buffer = (uint8_t*) malloc(fileSize + 1);
                destination = *buffer;
        }
        else if ((*buffer != NULL) && (*bytesInBuffer > 0))
        {
                *buffer = (uint8_t*) realloc(*buffer, *bytesInBuffer + fileSize + 1);
                destination = *buffer + *bytesInBuffer;
        }
        else
        {
                LOG_ERROR("invalid file read setup from %s", filePath);
                fclose(file);
                return -1;
        }

        if (*buffer == NULL)
        {
                LOG_ERROR("unable to allocate memory for file contents of %s", filePath);
                fclose(file);
                return -1;
        }

        /* Read file to buffer */
        int bytesRead = 0;
        while (bytesRead < fileSize)
        {
                int read = fread(destination + bytesRead, sizeof(uint8_t), fileSize - bytesRead, file);
                if (read < 0)
                {
                        LOG_ERROR("unable to read file (%s)", filePath);
                        fclose(file);
                        return -1;
                }
                bytesRead += read;
        }

        /* Write the NULL byte to terminate a potential ASCII string */
        destination[bytesRead] = '\0';

        *bytesInBuffer += bytesRead;

        fclose(file);

        return bytesRead;
#else
        LOG_ERROR("File I/O not supported on Zephyr");
        return -1;
#endif
}

/**
 * @brief Dynamically duplicates a string.
 *
 * @param source Pointer to the source string to duplicate.
 * @return Pointer to the duplicated string, or NULL if allocation fails or source is NULL.
 */
char* duplicate_string(char const* source)
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

#ifndef __ZEPHYR__

/* Get a properly initialized, empty certificates object */
certificates get_empty_certificates(void)
{
        certificates certs;

        certs.certificate_path = NULL;
        certs.private_key_path = NULL;
        certs.additional_key_path = NULL;
        certs.intermediate_path = NULL;
        certs.root_path = NULL;

        certs.chain_buffer = NULL;
        certs.chain_buffer_size = 0;

        certs.key_buffer = NULL;
        certs.key_buffer_size = 0;

        certs.additional_key_buffer = NULL;
        certs.additional_key_buffer_size = 0;

        certs.root_buffer = NULL;
        certs.root_buffer_size = 0;

        return certs;
}

/* Read all certificate and key files from the paths provided in the `certs`
 * structure and store the data in the buffers. Memory is allocated internally
 * and must be freed by the user.
 *
 * Returns 0 on success, -1 on failure (error is printed on console). */
int read_certificates(struct certificates* certs)
{
        int ret = 0;

        /* Read certificate chain */
        if (certs->certificate_path != NULL)
        {
                if (strncmp(certs->certificate_path,
                            PKCS11_LABEL_IDENTIFIER,
                            PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                        certs->chain_buffer = (uint8_t*) duplicate_string(certs->certificate_path);
                        if (certs->chain_buffer == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for certificate chain label");
                                goto error;
                        }
                        certs->chain_buffer_size = strlen(certs->certificate_path) + 1;
                }
                else
                {
                        certs->chain_buffer_size = 0;
                        ret = read_file(certs->certificate_path,
                                        &certs->chain_buffer,
                                        &certs->chain_buffer_size);
                        if (ret < 0)
                        {
                                LOG_ERROR("unable to read certificate from file %s",
                                          certs->certificate_path);
                                goto error;
                        }

                        if (certs->intermediate_path != NULL)
                        {
                                ret = read_file(certs->intermediate_path,
                                                &certs->chain_buffer,
                                                &certs->chain_buffer_size);
                                if (ret < 0)
                                {
                                        LOG_ERROR("unable to read intermediate certificate from "
                                                  "file %s",
                                                  certs->intermediate_path);
                                        goto error;
                                }
                        }
                }
        }

        /* Read private key */
        if (certs->private_key_path != NULL)
        {
                if (strncmp(certs->private_key_path,
                            PKCS11_LABEL_IDENTIFIER,
                            PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                        certs->key_buffer = (uint8_t*) duplicate_string(certs->private_key_path);
                        if (certs->key_buffer == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for key label");
                                goto error;
                        }
                        certs->key_buffer_size = strlen(certs->private_key_path) + 1;
                }
                else
                {
                        certs->key_buffer_size = 0;
                        ret = read_file(certs->private_key_path,
                                        &certs->key_buffer,
                                        &certs->key_buffer_size);
                        if (ret < 0)
                        {
                                LOG_ERROR("unable to read private key from file %s",
                                          certs->private_key_path);
                                goto error;
                        }
                }
        }

        /* Read addtional private key */
        if (certs->additional_key_path != NULL)
        {
                if (strncmp(certs->additional_key_path,
                            PKCS11_LABEL_IDENTIFIER,
                            PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                        certs->additional_key_buffer = (uint8_t*) duplicate_string(
                                certs->additional_key_path);
                        if (certs->additional_key_buffer == NULL)
                        {
                                LOG_ERROR("unable to allocate memory for key label");
                                goto error;
                        }
                        certs->additional_key_buffer_size = strlen(certs->additional_key_path) + 1;
                }
                else
                {
                        certs->additional_key_buffer_size = 0;
                        ret = read_file(certs->additional_key_path,
                                        &certs->additional_key_buffer,
                                        &certs->additional_key_buffer_size);
                        if (ret < 0)
                        {
                                LOG_ERROR("unable to read private key from file %s",
                                          certs->additional_key_path);
                                goto error;
                        }
                }
        }

        /* Read root certificate */
        if (certs->root_path != NULL)
        {
                certs->root_buffer_size = 0;
                ret = read_file(certs->root_path, &certs->root_buffer, &certs->root_buffer_size);
                if (ret < 0)
                {
                        LOG_ERROR("unable to read root certificate from file %s", certs->root_path);
                        goto error;
                }
        }

        return 0;

error:
        cleanup_certificates(certs);
        return -1;
}

void cleanup_certificates(struct certificates* certs)
{
        if (certs == NULL)
        {
                return;
        }
        // Free path strings
        if (certs->certificate_path)
        {
                free((char*) certs->certificate_path);
                certs->certificate_path = NULL;
        }

        if (certs->private_key_path)
        {
                free((char*) certs->private_key_path);
                certs->private_key_path = NULL;
        }

        if (certs->additional_key_path)
        {
                free((char*) certs->additional_key_path);
                certs->additional_key_path = NULL;
        }

        if (certs->intermediate_path)
        {
                free((char*) certs->intermediate_path);
                certs->intermediate_path = NULL;
        }

        if (certs->root_path)
        {
                free((char*) certs->root_path);
                certs->root_path = NULL;
        }

        // Free dynamically allocated buffers
        if (certs->chain_buffer)
        {
                free(certs->chain_buffer);
                certs->chain_buffer = NULL;
                certs->chain_buffer_size = 0;
        }

        if (certs->key_buffer)
        {
                free(certs->key_buffer);
                certs->key_buffer = NULL;
                certs->key_buffer_size = 0;
        }

        if (certs->additional_key_buffer)
        {
                free(certs->additional_key_buffer);
                certs->additional_key_buffer = NULL;
                certs->additional_key_buffer_size = 0;
        }

        if (certs->root_buffer)
        {
                free(certs->root_buffer);
                certs->root_buffer = NULL;
                certs->root_buffer_size = 0;
        }
}

#endif

int file_exists(const char* filepath)
{
#ifndef __ZEPHYR__
        // Use the access() system call to check file existence
        // F_OK flag checks for file existence
        if (access(filepath, F_OK) == 0)
                return 1; // File exists
        else
                return 0; // File does not exist
#else
        LOG_ERROR("File I/O not supported on Zephyr");
        return -1;
#endif
}

int write_file(const char* file_path, uint8_t const* buffer, size_t buffer_size, bool append)
{
#ifndef __ZEPHYR__
        FILE* file = NULL;

        if (!file_path || !buffer )
        {
                LOG_ERROR("file_path, buffer or buffer_size is 0 or NULL");
                goto error_occured;
        }

        file = fopen(file_path, append ? "ab" : "wb");
        if (!file)
        {
                LOG_ERROR("file (%s) cannot be opened (error %d: %s)", file_path, errno, strerror(errno));
                goto error_occured;
        }

        /* Write buffer to file */
        size_t bytesWriten = 0;
        uint8_t const* ptr = buffer;
        while (bytesWriten < buffer_size)
        {
                int written = fwrite(ptr, sizeof(uint8_t), buffer_size - bytesWriten, file);
                if (written < 0)
                {
                        LOG_ERROR("Error writing buffer to file: %s\n", file_path);
                        goto error_occured;
                }
                bytesWriten += written;
                ptr += written;
        }

        fclose(file);

        return 0;

error_occured:
        if (file != NULL)
                fclose(file);
        return -1;
#else
        LOG_ERROR("File I/O not supported on Zephyr");
        return -1;
#endif
}