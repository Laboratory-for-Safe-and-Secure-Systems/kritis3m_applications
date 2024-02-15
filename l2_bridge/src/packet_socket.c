#include "packet_socket.h"

#include "l2_util.h"

#include <zephyr/kernel.h>
#include <unistd.h> // Include the necessary header file for the 'close' function
#include <sys/socket.h>
#include <errno.h>

LOG_MODULE_REGISTER(packet_socket);

int init_packet_socket_bridge(PacketSocket *bridge, interface_config *interface, connected_channel channel)
{

    int proto = ETH_P_ALL;
#if !defined(__ZEPHYR__)
    proto = htons(proto);
#endif

    memset(&bridge->addr, 0, sizeof(bridge->addr));
    memset(&bridge->source, 0, sizeof(bridge->source));

    bridge->addr.sll_family = AF_PACKET;
    bridge->addr.sll_protocol = proto;
    bridge->bridge.type = PACKET_SOCKET;
    bridge->bridge.channel = channel;
    bridge->bridge.vlan_tag = interface->vlan_tag;
    bridge->bridge.fd = socket(bridge->addr.sll_family, SOCK_RAW, bridge->addr.sll_protocol);

    // check if socket initialization was successful
    if (bridge->bridge.fd < 0)
    {
        LOG_ERR("Failed to create packet socket: %d", errno);
        return -1;
    }

#if defined(__ZEPHYR__)
    bridge->addr.sll_ifindex = net_if_get_by_iface((struct net_if *)interface->interface);
    // get vlan tag of interface
#else
    /* We have to get the mapping between interface name and index */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, (char const *)interface->interface, IFNAMSIZ);
    ioctl(bridge->bridge.fd, SIOCGIFINDEX, &ifr);
    bridge->addr.sll_ifindex = ifr.ifr_ifindex;
#endif

    /* Bind the packet sockets to their interfaces */
    if (bind(bridge->bridge.fd, (struct sockaddr *)&bridge->addr, sizeof(bridge->addr)) < 0)
    {
        LOG_ERR("binding ASSET socket to interface failed: error %d\n", errno);
        return -1;
    }

#if !defined(__ZEPHYR__)
    if (setsockopt(bridge->bridge.fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &(int){1}, sizeof(int)) < 0)
    {
        LOG_ERR("setsockopt(PACKET_IGNORE_OUTGOING) on LAN socket failed: error %d\n", errno);
        return -1;
    }
#endif

    bridge->bridge.vtable[call_send] = (int (*)())packet_socket_send;
    bridge->bridge.vtable[call_receive] = (int (*)())packet_socket_receive;
    bridge->bridge.vtable[call_pipe] = (int (*)())packet_socket_pipe;
    bridge->bridge.vtable[call_close] = (int (*)())packet_socket_close;

    return 1;
}

int packet_socket_close(PacketSocket *bridge)
{
    if (bridge == NULL)
    {
        LOG_ERR("Bridge is NULL");
        return -1;
    }
    // check if pipe is NULL
    if (bridge->bridge.pipe != NULL)
    {
        // tell other connection, that this connection is closed
        bridge->bridge.pipe->pipe = NULL;
    }
    close(bridge->bridge.fd);
    free(bridge);
    return 1;
}
int packet_socket_send(PacketSocket *bridge, uint8_t *buffer, int buffer_len, int frame_start)
{
    if (bridge == NULL)
    {
        LOG_ERR("Bridge is NULL");
        return -1;
    }
    // pre processing of the data
    // check if vlan
    if (bridge->bridge.vlan_tag > 0)
    {
        // check if offset is large enough
        if (frame_start != VLAN_HEADER_SIZE)
        {
            LOG_ERR("Invalid frame start");
            return -1;
        }
        // get vlan tag from interface and apply it to the frame
        apply_vlan_tag(buffer, bridge->bridge.vlan_tag);
    }

    int ret = sendto(bridge->bridge.fd, buffer, buffer_len, 0, (struct sockaddr *)&bridge->addr, sizeof(bridge->addr));
    if (ret < 0)
    {

        if (errno == EAGAIN)
        {
            return 1;
        }
        else
        {

            LOG_ERR("Failed to send data on packet socket: %s", strerror(errno));
        }
    }
    return ret;
}

int packet_socket_receive(PacketSocket *bridge)
{
    if (bridge == NULL)
    {
        LOG_ERR("Bridge is NULL");
        return -1;
    }

    int source_len = sizeof(bridge->source);
    int ret = recvfrom(bridge->bridge.fd,
                       bridge->bridge.buf,
                       sizeof(bridge->bridge.buf),
                       0, (struct sockaddr *)&bridge->source,
                       &source_len);
    if (ret < 0)
    {
        LOG_ERR("Failed to receive data on packet socket: %s", strerror(errno));
        return ret;
    }
    bridge->bridge.len = ret;
    return ret;
}

int packet_socket_pipe(PacketSocket *bridge)
{
    if (bridge == NULL)
    {
        LOG_ERR("Bridge is NULL");
        return -1;
    }
    // check if data available
    if (bridge->bridge.len <= 0)
    {
        LOG_ERR("No data available to pipe");
        return -1;
    }
    // check if packet is destined for upper layers
    if (!((bridge->source.sll_pkttype == PACKET_OTHERHOST) ||
          (bridge->source.sll_pkttype == PACKET_MULTICAST) ||
          (bridge->source.sll_pkttype == PACKET_BROADCAST)))
    {
        LOG_INF("Packet will be handled in upper layers");
        bridge->bridge.len = 0;
        return 1;
    }

    // check if pipe esits
    if (bridge->bridge.pipe == NULL)
    {
        LOG_ERR("No pipe available to send data to");
        return -1;
    }

    // prepare frame for piping
    int offset = 0;
    if (bridge->bridge.vlan_tag > 0)
    {
        if (is_vlan_tagged(bridge->bridge.buf))
        {
            remove_vlan_tag(bridge->bridge.buf);
            // remove_vlan tag moves dst- and src-mac 4 bytes to the right
            // offset indicates that the frame starts after 4 bytes
            offset = VLAN_HEADER_SIZE;
        }
        else
        {
            LOG_INF("VLAN Iface received frame without vlan tag");
        }
    }
    /**
     * here would be a good place to apply a filter on the frames
     */

    int ret = bridge_send(bridge->bridge.pipe, bridge->bridge.buf, bridge->bridge.len, offset);
    if (ret < 0)
    {
        LOG_ERR("Failed to pipe data to other bridge: %d", ret);
    }
    bridge->bridge.len = 0;
    return ret;
}
