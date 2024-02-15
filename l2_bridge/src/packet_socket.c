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

int packet_socket_send(PacketSocket *bridge, uint8_t *buffer, int buffer_len, int frame_start)
{
    // pre processing of the data
    switch (bridge->bridge.type)
    {
    // apply vlan tag to the frames
    case PACKET_SOCKET_VLAN:
        return -1;
    case PACKET_SOCKET:
        return -1;
    default:
        LOG_ERR("Invalid interface type");
        return -1;
    }

    int ret = sendto(bridge->bridge.fd, buffer, buffer_len, 0, (struct sockaddr *)&bridge->addr, sizeof(bridge->addr));
    if (ret < 0)
    {
        LOG_ERR("Failed to send data on packet socket: %s", strerror(errno));
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

int packet_socket_pipe(PacketSocket *bridge)
{
    // check if data available
    if(bridge->bridge.len <= 0){
        LOG_ERR("No data available to pipe");
        return -1;
    }
    int offset = 0;
    switch (bridge->bridge.type)
    {
    case PACKET_SOCKET_VLAN:
        if (is_vlan_tagged(bridge->bridge.buf))
        {

            remove_vlan_tag(bridge->bridge.buf);
            offset = VLAN_HEADER_SIZE;
        }
        else
        {
            LOG_INF("No VLAN tag found");
        }
        break;
    case PACKET_SOCKET:
        LOG_INF("no preprocessing required");
        break;
    default:
        LOG_ERR("Invalid interface type");
        return -1;
    }
    /**
     * here would be a good place to apply a filter on the frames
     */

    return bridge_send(bridge->bridge.pipe, bridge->bridge.buf, bridge->bridge.len, offset);
}
