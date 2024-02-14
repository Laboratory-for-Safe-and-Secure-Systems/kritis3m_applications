#include "packet_socket.h"

#include "l2_util.h"

#include <zephyr/kernel.h>
#include <unistd.h> // Include the necessary header file for the 'close' function
#include <sys/socket.h>

LOG_MODULE_REGISTER(packet_socket);

int init_packet_socket_bridge(PacketSocket *bridge)
{
    bridge->bridge.vtable[call_send] = (int (*)())packet_socket_send;
    bridge->bridge.vtable[call_receive] = (int (*)())packet_socket_receive;
    bridge->bridge.vtable[call_pipe] = (int (*)())packet_socket_pipe;
    // get fd
    bridge->bridge.fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (bridge->bridge.fd < 0)
    {
        LOG_ERR("socket");
        return -1;
    }
    // bind to interface
    memset(&bridge->addr, 0, sizeof(bridge->addr));
    int ret = bind(bridge->bridge.fd, (struct sockaddr *)&bridge->addr, sizeof(bridge->addr));
    if (ret < 0)
    {
        LOG_ERR("bind packet socket");

        close(bridge->bridge.fd);
        return -1;
    }
    return ret;
}

int packet_socket_send(PacketSocket *bridge, uint8_t *data, size_t len)
{
    int ret = sendto(bridge->bridge.fd, data, len, 0, (struct sockaddr *)&bridge->addr, sizeof(bridge->addr));
    if (ret < 0)
    {
        LOG_ERR("Failed to send data on packet socket: %s", strerror(errno));
    }
    switch (bridge->bridge.type)
    {
    case PACKET_SOCKET_VLAN:
        return -1;
    case PACKET_SOCKET:
        return -1;
    default:
        LOG_ERR("Invalid interface type");
        return -1;
    }
    return ret;
}

int packet_socket_receive(PacketSocket *bridge)
{
    int ret = recvfrom(bridge->bridge.fd, bridge->bridge.buf, sizeof(bridge->bridge.buf), 0, NULL, NULL);
    if (ret < 0)
    {
        LOG_ERR("Failed to receive data on packet socket: %s", strerror(errno));
    }
    return ret;
}

int packet_socket_pipe(PacketSocket *bridge, uint8_t *data, size_t len)
{
    // check if this interface uses vlan
    uint8_t *send_buf = NULL;
    int vlan_header_len= 0;
    switch (bridge->bridge.type)
    {
    case PACKET_SOCKET_VLAN:
        if (is_vlan_tagged(bridge->bridge.buf))
        {
            vlan_header_len = 4;
            send_buf = remove_vlan_tag(bridge->bridge.buf);

        }
        else
        {
            send_buf = bridge->bridge.buf;
        }
        break;
    case PACKET_SOCKET:
        send_buf = bridge->bridge.buf;
        break;
    default:
        LOG_ERR("Invalid interface type");
        return -1;
    }
    return bridge_send(bridge->bridge.pipe, send_buf, bridge->bridge.len-vlan_header_len);
}
