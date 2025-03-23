#ifndef CONFIGURATION_PARSER_H
#define CONFIGURATION_PARSER_H

#include "configuration_manager.h"
#include "kritis3m_configuration.h"

int parse_sysconfig_to_json(struct sysconfig* config, char* json_buffer, int json_buffer_size);
int parse_buffer_to_sysconfig(char* json_buffer, int json_buffer_size, struct sysconfig* config);

int parse_config(char* buffer,
                 int buffer_len,
                 struct application_manager_config* config,
                 struct hardware_configs* hw_configs);

#endif // CONFIGURATION_PARSER_H