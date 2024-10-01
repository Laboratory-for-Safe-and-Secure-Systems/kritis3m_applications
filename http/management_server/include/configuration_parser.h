#ifndef CONFIGURATION_PARSER_H
#define CONFIGURATION_PARSER_H

#include "kritis3m_configuration.h"

void free_NodeConfig(Kritis3mNodeConfiguration *config);
int parse_buffer_to_Config(char *json_buffer, int json_buffer_size, Kritis3mNodeConfiguration *config);

//please pass an empty pointer 
int parse_buffer_to_SystemConfiguration(char *json_buffer, int json_buffer_size,  SystemConfiguration *config);
// parse_buffer_to_Config will call free in case of an error

#endif // CONFIGURATION_PARSER_H