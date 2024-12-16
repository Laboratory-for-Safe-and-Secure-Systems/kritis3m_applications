#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "file_io.h"
#include "logging.h"

LOG_MODULE_CREATE(networking);

// asl defines
#define PKCS11_LABEL_IDENTIFIER "pkcs11:"
#define PKCS11_LABEL_IDENTIFIER_LEN 7

int readFile(const char* filePath, uint8_t** buffer, size_t bufferSize)
{
        uint8_t* destination = NULL;
        if (!buffer || filePath)
                return -1;

        /* Open the file */
        FILE* file = fopen(filePath, "rb");

        if (file == NULL)
        {
                LOG_ERROR("file (%s) cannot be opened", filePath);
                return -1;
        }

        /* Get length of file */
        fseek(file, 0, SEEK_END);
        long fileSize = ftell(file);
        rewind(file);

        /* Allocate buffer for file content */
        if (*buffer == NULL && bufferSize == 0)
        {
                *buffer = (uint8_t*) malloc(fileSize);
                destination = *buffer;
        }
        else if (*buffer != NULL && bufferSize > 0)
        {
                *buffer = (uint8_t*) realloc(*buffer, bufferSize + fileSize);
                destination = *buffer + bufferSize;
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

        fclose(file);

        return bytesRead;
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

/* Read all certificate and key files from the paths provided in the `certs`
 * structure and store the data in the buffers. Memory is allocated internally
 * and must be freed by the user.
 *
 * Returns 0 on success, -1 on failure (error is printed on console). */
int read_certificates(struct certificates* certs)
{
        /* Read certificate chain */
        if (certs->certificate_path != NULL)
        {
                int cert_size = readFile(certs->certificate_path, &certs->chain_buffer, 0);
                if (cert_size < 0)
                {
                        LOG_ERROR("unable to read certificate from file %s", certs->certificate_path);
                        goto error;
                }

                certs->chain_buffer_size = cert_size;

                if (certs->intermediate_path != NULL)
                {
                        int inter_size = readFile(certs->intermediate_path,
                                                  &certs->chain_buffer,
                                                  cert_size);
                        if (inter_size < 0)
                        {
                                LOG_ERROR("unable to read intermediate certificate from file %s",
                                          certs->intermediate_path);
                                goto error;
                        }

                        certs->chain_buffer_size += inter_size;
                }
        }

        /* Read private key */
        if (certs->private_key_path != 0)
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
                        int key_size = readFile(certs->private_key_path, &certs->key_buffer, 0);
                        if (key_size < 0)
                        {
                                LOG_ERROR("unable to read private key from file %s",
                                          certs->private_key_path);
                                goto error;
                        }

                        certs->key_buffer_size = key_size;
                }
        }

        /* Read addtional private key */
        if (certs->additional_key_path != 0)
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
                        int key_size = readFile(certs->additional_key_path,
                                                &certs->additional_key_buffer,
                                                0);
                        if (key_size < 0)
                        {
                                LOG_ERROR("unable to read private key from file %s",
                                          certs->additional_key_path);
                                goto error;
                        }

                        certs->additional_key_buffer_size = key_size;
                }
        }

        /* Read root certificate */
        if (certs->root_path != 0)
        {
                int root_size = readFile(certs->root_path, &certs->root_buffer, 0);
                if (root_size < 0)
                {
                        LOG_ERROR("unable to read root certificate from file %s", certs->root_path);
                        goto error;
                }

                certs->root_buffer_size = root_size;
        }
        else
        {
                LOG_ERROR("no root certificate file specified");
                goto error;
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

int file_exists(const char* filepath)
{
        // Use the access() system call to check file existence
        // F_OK flag checks for file existence
        if (access(filepath, F_OK) == 0)
        {
                return 1; // File exists
        }
        else
        {
                return 0; // File does not exist
        }
}

int write_file(const char* file_path, char* buffer, int buffer_size)
{
        int ret = 0;
        FILE* file = NULL;

        if (!file_path || !buffer || (buffer_size == 0))
        {
                LOG_ERROR("file_path, buffer or buffer_size is 0 or NULL");
        }

        file = fopen(file_path, "w");
        if (!file)
        {
                LOG_ERROR("Error opening file: %s\n", file_path);
                ret = -1;
                goto error_occured;
        }

        size_t written = fwrite(buffer, sizeof(char), buffer_size, file);
        if (written != buffer_size)
        {
                LOG_ERROR("Error writing buffer to file: %s\n", file_path);
                ret = -1;
                goto error_occured;
        }
        if (file != NULL)
                fclose(file);

        return ret;
error_occured:
        if (file != NULL)
                fclose(file);
        return -1;
}