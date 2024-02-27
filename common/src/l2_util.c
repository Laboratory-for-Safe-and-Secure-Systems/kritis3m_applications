
#include "l2_util.h"

LOG_MODULE_REGISTER(l2_util);

#define MAC_SIZE 6

#define VLAN_HEADER_SIZE 4

uint16_t get_vlan_tag(uint8_t *packet)
{
    if (!is_vlan_tagged(packet))
    {
        return -1;
    }
    uint16_t *vlan = (uint16_t *)(packet + (MAC_SIZE * 2) + 2);
    uint16_t vlan_id = 0x0fff & *vlan;
    vlan_id = ntohs(vlan_id);
    return vlan_id;
}

uint16_t get_ethtype(uint8_t *packet)
{
    if (is_vlan_tagged(packet))
    {
        uint16_t ethertype = ntohs(*(uint16_t *)(packet + (2 * MAC_SIZE) + VLAN_HEADER_SIZE));
        // printf("ethertype: %04x\n", ethertype);
        return ethertype;
    }
    else
    {
        uint16_t ethertype = ntohs(*(uint16_t *)(packet + (2 * MAC_SIZE)));
        // printf("ethertype: %04x\n", ethertype);
        return ethertype;
    }
}

void update_vlan_tag(uint8_t *packet, uint16_t tag);

bool is_vlan_tagged(uint8_t *packet)
{
    uint16_t *p_tpid = (uint16_t *)(packet + (2 * MAC_SIZE));
    uint16_t tpid = ntohs(*p_tpid);
    if (tpid == 0x8100)
    {
        LOG_INF("tpid: %04x\n", tpid);
        return true;
    }
    else
    {
        return false;
    }
}

uint8_t *remove_vlan_tag(uint8_t *packet)
{
    if (is_vlan_tagged(packet))
    {
        return (uint8_t *)memmove((packet + VLAN_HEADER_SIZE), packet, 2 * MAC_SIZE);
    }
    else
    {
        LOG_INF("failure, no vlan tag \n");
        return packet;
    }
}

uint8_t *apply_vlan_tag(uint8_t *packet, uint8_t tag)
{
    uint8_t vlan[] = {0x81, 0x00, 0x00, tag};
    memmove(packet, packet + 4, MAC_SIZE * 2);
    memcpy(packet + (MAC_SIZE * 2), vlan, 4);
    return packet;
}


//not tested
void set_vlan_tag(uint8_t* packet, int packet_len, uint16_t tci, uint16_t tag){
    memmove(packet, packet + 4, MAC_SIZE * 2);
    uint8_t vlan_id[] = {0x81, 0x00};
    memcpy(packet + (MAC_SIZE * 2), vlan_id, sizeof(vlan_id));
    uint16_t val_tci = (tci & 0xf000) | (tag & 0x0fff);
    memcpy(packet + (MAC_SIZE * 2)+sizeof(vlan_id), &val_tci, sizeof(uint16_t));

}