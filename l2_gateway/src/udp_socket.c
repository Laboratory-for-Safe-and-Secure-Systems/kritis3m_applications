
#include "udp_socket.h"

#include "l2_util.h"

#include <unistd.h> // Include the necessary header file for the 'close' function
#include <sys/socket.h>
#include <errno.h>
#include "networking.h"
#include "logging.h"

LOG_MODULE_REGISTER(udp_socket);

int init_udp_socket_bridge(UdpSocket *bridge, const interface_config *interface, connected_channel channel)
{

    int proto = IPPROTO_UDP;
#if !defined(__ZEPHYR__)
    proto = htons(proto);
#endif

    memset(&bridge->addr, 0, sizeof(bridge->addr));
    memset(&bridge->source, 0, sizeof(bridge->source));

    bridge->addr.sin_family = AF_INET;
    bridge->bridge.type = UDP_SOCKET;
    bridge->bridge.channel = channel;

    struct net_if *t_iface = NULL;

    // switch (channel)
    // {
    // case ASSET:
    //     net_addr_pton(AF_INET, CONFIG_NET_IP_ASSET, &bridge->addr.sin_addr);
    //     break;
    // case TUNNEL:
    //     net_addr_pton(AF_INET, CONFIG_NET_IP_TUNNEL, &bridge->addr.sin_addr);
    //     break;
    // }

#if defined(__ZEPHYR__)
    switch (channel)
    {
    case ASSET:
        t_iface = (struct net_if *)network_interfaces()->asset;
        break;
    case TUNNEL:
        t_iface = (struct net_if *)network_interfaces()->tunnel;

        break;
    }
    // get vlan tag of interface
#else
    /* We have to get the mapping between interface name and index */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, (char const *)interface->interface, IFNAMSIZ);
    ioctl(bridge->bridge.fd, SIOCGIFINDEX, &ifr);
    // bridge->addr.sll_ifindex = ifr.ifr_ifindex;
#endif

    bridge->bridge.fd = socket(bridge->addr.sin_family, SOCK_DGRAM, proto);

    // check if socket initialization was successful
    if (bridge->bridge.fd < 0)
    {
        LOG_ERR("Failed to create packet socket: %d", errno);
        return -1;
    }
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

    bridge->bridge.vtable[call_send] = (int (*)())udp_socket_send;
    bridge->bridge.vtable[call_receive] = (int (*)())udp_socket_receive;
    bridge->bridge.vtable[call_pipe] = (int (*)())udp_socket_pipe;
    bridge->bridge.vtable[call_close] = (int (*)())udp_socket_close;

    return 1;
}

int udp_socket_close(UdpSocket *bridge)
{
    if (bridge == NULL)
    {
        LOG_ERR("L2_Gateway is NULL");
        return -1;
    }
    // check if l2_gw_pipe is NULL
    if (bridge->bridge.l2_gw_pipe != NULL)
    {
        // tell other connection, that this connection is closed
        bridge->bridge.l2_gw_pipe->l2_gw_pipe = NULL;
    }
    close(bridge->bridge.fd);
    free(bridge);
    return 1;
}
int udp_socket_send(UdpSocket *bridge, uint8_t *buffer, int buffer_len, int frame_start)
{
    if (bridge == NULL)
    {
        LOG_ERR("L2_Gateway is NULL");
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

    // LOG to sending packet
    // switch (bridge->bridge.channel)
    // {
    // case (TUNNEL):
    //     printf("Interface: Tunnel\n");
    //     break;

    // case (ASSET):
    //     printf("Interface: Asset\n");
    //     break;
    // }
    // for (int i = 0; i < buffer_len; i++)
    // {
    //     // print hex val of buffer
    //     printf("%02x", buffer[i]);
    // }
    // printf("\n");
    setblocking(bridge->bridge.fd, true);
    int ret = sendto(bridge->bridge.fd, buffer, buffer_len, 0, (struct sockaddr *)&bridge->addr, sizeof(bridge->addr));
    setblocking(bridge->bridge.fd, false);
    if (ret < 0)
    {

        if (errno == EAGAIN)
        {
            return 1;
        }
        else
        {

            LOG_ERR("failed to send packet");
        }
    }
    return ret;
}

int udp_socket_receive(UdpSocket *bridge)
{
    if (bridge == NULL)
    {
        LOG_ERR("L2_Gateway is NULL");
        return -1;
    }

    int source_len = sizeof(bridge->source);
    memset(&bridge->source, 0, sizeof(bridge->source));
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

int udp_socket_pipe(UdpSocket *bridge)
{
    if (bridge == NULL)
    {
        LOG_ERR("L2_Gateway is NULL");
        return -1;
    }
    // check if data available
    if (bridge->bridge.len <= 0)
    {
        LOG_ERR("No data available to l2_gw_pipe");
        return -1;
    }
    // // check if packet is destined for upper layers
    // if (!((bridge->source.sll_pkttype == PACKET_OTHERHOST) ||
    //       (bridge->source.sll_pkttype == PACKET_MULTICAST) ||
    //       (bridge->source.sll_pkttype == PACKET_BROADCAST)))
    // {
    //     LOG_INF("Packet will be handled in upper layers");
    //     bridge->bridge.len = 0;
    //     return 1;
    // }

    // check if l2_gw_pipe esits
    if (bridge->bridge.l2_gw_pipe == NULL)
    {
        LOG_ERR("No l2_gw_pipe available to send data to");
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
    int ret = l2_gateway_send(bridge->bridge.l2_gw_pipe, bridge->bridge.buf, bridge->bridge.len, offset);
    if (ret < 0)
    {
        LOG_ERR("Failed to l2_gw_pipe data to other bridge: %d", ret);
    }
    bridge->bridge.len = 0;
    return ret;
}
