#ifndef UTILS_H__
#define UTILS_H__

#include <sys/types.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include "asl.h"

/**
 * @todo implementation
 * @todo modification CryptoProfile
 */
int parse_asl_from_crypto_profile(CryptoProfile* cryptoprofile, asl_endpoint* asl){

return -1; 
}

int parse_IPv4_fromIpPort(const char* src_ip_port, uint8_t* dst_ip)
{
    // Find the position of the colon
    const char *colon_pos = strchr(src_ip_port, ':');
    
    if (colon_pos != NULL) {
        // Copy the part before the colon to the ip_address
        size_t ip_length = colon_pos - src_ip_port;
        strncpy(dst_ip, src_ip_port, ip_length);
        dst_ip[ip_length] = '\0'; // Null-terminate the string
        return 1;
    } else if (colon_pos == NULL) {
        // If no colon is found, assume the entire input is an IP address
        char* ip = "0.0.0.0";
        int len = strlen(ip);
        strncpy(dst_ip, ip, len);
        dst_ip[len] = '\0'; // Null-terminate the string
        return 1;
    }
    return -1;
}

int parse_port_fromIpPort(const char* src_ip_port)
{
    // Find the position of the colon
    const char *colon_pos = strchr(src_ip_port, ':');

    if ( colon_pos != NULL){
        //found
        return atoi(colon_pos + 1);
    }
    return -1;
    
}

#endif