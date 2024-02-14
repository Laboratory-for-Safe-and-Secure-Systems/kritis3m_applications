// include guards

#ifndef _L2_UTIL_H_
#define _L2_UTIL_H_

#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/socket.h>
#include "zephyr/net/net_ip.h"


#include <string.h>

#define MAC_SIZE 6

#define VLAN_HEADER_SIZE 4


/**
 * @brief Structure representing a L2 address.
 *
 * This structure is used to store a L2 address, which consists of 6 bytes.
 * The structure is packed to ensure that there is no padding between the bytes.
 */

struct __attribute__((packed)) cst_l2_addr
{
    uint8_t addr[6];
};

/**
 * @brief Structure representing the CST TCI (Tag Control Information) fields.
 *
 * This structure is used to store the PCP (Priority Code Point), DEI (Drop Eligible Indicator),
 * and VID (VLAN Identifier) of TCI.
 * The structure is packed to ensure that there is no padding between the fields.
 */
struct __attribute__((packed)) cst_tci
{
    uint16_t PCP : 3;  /**< Priority Code Point */
    uint16_t DEI : 1;  /**< Drop Eligible Indicator */
    uint16_t VID : 12; /**< VLAN Identifier */
};

/**
 * @brief Structure representing an IEEE 802.1Q packet.
 *
 * This structure is used to encapsulate an IEEE 802.1Q tagged packet.
 * The structure is packed to ensure that there are no padding bytes between the fields.
 */
struct __attribute__((packed)) cst_ieee8021_q
{
    uint16_t TPID;      /**< Tag Protocol Identifier (TPID) */
    struct cst_tci TCI; /**< Tag Control Information (TCI) */
};

/** packet_header is used to parse received packets
 * 1. The first 6 bytes are the destination MAC address
 * 2. The next 6 bytes are the source MAC address
 * 3. The next 2 bytes are the ethernet type
 */
struct __attribute__((packed)) packet_header_in
{
    struct cst_l2_addr dest;
    struct cst_l2_addr src;
    struct cst_ieee8021_q vlan;
    uint16_t ethertype;
};



uint16_t get_vlan_tag(uint8_t *packet);

/**
 * @brief Retrieves the Ethernet type from the given packet header.
 *
 * This function extracts the Ethernet type from the provided packet header.
 *
 * @param header The pointer to the packet header structure.
 * @return The Ethernet type value as a 16-bit unsigned integer.
 */
uint16_t get_ethtype(uint8_t *header);

void update_vlan_tag(uint8_t *header, uint16_t tag);

/**
 * @brief Checks if the packet header is VLAN tagged.
 *
 * This function takes a pointer to a packet header and checks if it is VLAN tagged.
 *
 * @param header Pointer to the packet header.
 * @return true if the packet header is VLAN tagged, false otherwise.
 */
bool is_vlan_tagged(uint8_t *header);

// make sure packet is vlan tagged-> header is shifted 2 bytes to the right to overwrite vlan tag
uint8_t *remove_vlan_tag(uint8_t *header);

// add tag to packet
uint8_t *apply_vlan_tag(uint8_t *packet, uint8_t tag);


#endif