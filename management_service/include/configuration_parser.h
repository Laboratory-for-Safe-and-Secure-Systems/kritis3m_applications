#ifndef CONFIGURATION_PARSER_H
#define CONFIGURATION_PARSER_H

#include "configuration_manager.h"
#include "kritis3m_configuration.h"

int parse_buffer_to_sysconfig(char* json_buffer, int json_buffer_size, struct sysconfig* config);

// parse json to Kritis3mNodeConfiguration, which stores the startup information
int parse_buffer_to_Config(char* json_buffer, int json_buffer_size, Kritis3mNodeConfiguration* config);

// Parses a json structure to the Systemconfiguration structure
ManagementReturncode parse_buffer_to_SystemConfiguration(char* json_buffer,
                                                         int json_buffer_size,
                                                         SystemConfiguration* config,
                                                         char* crypto_path,
                                                         char* secure_middleware_path,
                                                         char* pin);

#endif // CONFIGURATION_PARSER_H