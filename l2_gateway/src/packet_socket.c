#include "packet_socket.h"

#include "l2_util.h"

#include <unistd.h> // Include the necessary header file for the 'close' function
#include <sys/socket.h>
#include <errno.h>
#include "networking.h"

#if defined(__ZEPHYR__)
#include <zephyr/net/ethernet.h>
#else
#include <errno.h>      //For errno - the error number
#include <netinet/ip.h> //Provides declarations for ip header
#include <arpa/inet.h>   
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */ // inet_addr
#endif

#include "tcp_echo_server.h"

#include "logging.h"
#include "poll_set.h"
#include "networking.h"
#include "wolfssl.h"

LOG_MODULE_REGISTER(packet_socket);

int init_packet_socket_bridge(PacketSocket *l2_gw, const interface_config *interface, connected_channel channel)
{

    int proto = ETH_P_ALL;
#if !defined(__ZEPHYR__)
    proto = htons(proto);
#endif

    memset(&l2_gw->addr, 0, sizeof(l2_gw->addr));
    memset(&l2_gw->source, 0, sizeof(l2_gw->source));

    l2_gw->addr.sll_family = AF_PACKET;
    l2_gw->addr.sll_protocol = proto;
    l2_gw->addr.sll_pkttype = (PACKET_BROADCAST | PACKET_MULTICAST | PACKET_OTHERHOST);
    l2_gw->bridge.type = PACKET_SOCKET;
    l2_gw->bridge.channel = channel;

    struct net_if *t_iface = NULL;
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
    ioctl(l2_gw->bridge.fd, SIOCGIFINDEX, &ifr);
    l2_gw->addr.sll_ifindex = ifr.ifr_ifindex;
#endif

    int tag = net_eth_get_vlan_tag(t_iface);
    l2_gw->bridge.vlan_tag = tag;
    l2_gw->addr.sll_ifindex = net_if_get_by_iface(t_iface);

    l2_gw->bridge.fd = socket(l2_gw->addr.sll_family, SOCK_RAW, l2_gw->addr.sll_protocol);

    // check if socket initialization was successful
    if (l2_gw->bridge.fd < 0)
    {
        LOG_ERR("Failed to create packet socket: %d", errno);
        return -1;
    }
    /* Bind the packet sockets to their interfaces */
    if (bind(l2_gw->bridge.fd, (struct sockaddr *)&l2_gw->addr, sizeof(l2_gw->addr)) < 0)
    {
        LOG_ERR("binding ASSET socket to interface failed: error %d\n", errno);
        return -1;
    }

#if !defined(__ZEPHYR__)
    if (setsockopt(l2_gw->bridge.fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &(int){1}, sizeof(int)) < 0)
    {
        LOG_ERR("setsockopt(PACKET_IGNORE_OUTGOING) on LAN socket failed: error %d\n", errno);
        return -1;
    }
#endif

    l2_gw->bridge.vtable[call_send] = (int (*)())packet_socket_send;
    l2_gw->bridge.vtable[call_receive] = (int (*)())packet_socket_receive;
    l2_gw->bridge.vtable[call_pipe] = (int (*)())packet_socket_pipe;
    l2_gw->bridge.vtable[call_close] = (int (*)())packet_socket_close;

    return 1;
}

int packet_socket_close(PacketSocket *l2_gw)
{
    if (l2_gw == NULL)
    {
        LOG_ERR("L2_Gateway is NULL");
        return -1;
    }
    // check if pipe is NULL
    if (l2_gw->bridge.l2_gw_pipe != NULL)
    {
        // tell other connection, that this connection is closed
        l2_gw->bridge.l2_gw_pipe->l2_gw_pipe = NULL;
    }
    close(l2_gw->bridge.fd);
    free(l2_gw);
    return 1;
}
int packet_socket_send(PacketSocket *l2_gw, uint8_t *buffer, int buffer_len, int frame_start)
{
    if (l2_gw == NULL)
    {
        LOG_ERR("L2_Gateway is NULL");
        return -1;
    }
    // pre processing of the data
    // check if vlan
    if (l2_gw->bridge.vlan_tag > 0)
    {
        // check if offset is large enough
        if (frame_start != VLAN_HEADER_SIZE)
        {
            LOG_ERR("Invalid frame start");
            return -1;
        }
        // get vlan tag from interface and apply it to the frame
        apply_vlan_tag(buffer, l2_gw->bridge.vlan_tag);
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
    setblocking(l2_gw->bridge.fd, true);
    int ret = sendto(l2_gw->bridge.fd, buffer, buffer_len, 0, (struct sockaddr *)&l2_gw->addr, sizeof(l2_gw->addr));
    setblocking(l2_gw->bridge.fd, false);
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

int packet_socket_receive(PacketSocket *l2_gw)
{
    if (l2_gw == NULL)
    {
        LOG_ERR("L2_Gateway is NULL");
        return -1;
    }

    int source_len = sizeof(l2_gw->source);
    memset(&l2_gw->source, 0, sizeof(l2_gw->source));
    int ret = recvfrom(l2_gw->bridge.fd,
                       l2_gw->bridge.buf,
                       sizeof(l2_gw->bridge.buf),
                       0, (struct sockaddr *)&l2_gw->source,
                       &source_len);
    if (ret < 0)
    {
        LOG_ERR("Failed to receive data on packet socket: %s", strerror(errno));
        return ret;
    }
    l2_gw->bridge.len = ret;
    return ret;
}

int packet_socket_pipe(PacketSocket *l2_gw)
{
    if (l2_gw == NULL)
    {
        LOG_ERR("L2_Gateway is NULL");
        return -1;
    }
    // check if data available
    if (l2_gw->bridge.len <= 0)
    {
        LOG_ERR("No data available to l2_gw_pipe");
        return -1;
    }
    if (l2_gw->source.sll_pkttype & PACKET_HOST)
    {
        LOG_INF("upper layer will handle this pkt");
    }

    // check if l2_gw_pipe esits
    if (l2_gw->bridge.l2_gw_pipe == NULL)
    {
        LOG_ERR("No l2_gw_pipe available to send data to");
        return -1;
    }

    // prepare frame for piping
    int offset = 0;
    if (l2_gw->bridge.vlan_tag > 0)
    {
        if (is_vlan_tagged(l2_gw->bridge.buf))
        {
            remove_vlan_tag(l2_gw->bridge.buf);
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
    int ret = l2_gateway_send(l2_gw->bridge.l2_gw_pipe, l2_gw->bridge.buf, l2_gw->bridge.len, offset);
    if (ret < 0)
    {
        LOG_ERR("Failed to l2_gw_pipe data to other bridge: %d", ret);
    }
    l2_gw->bridge.len = 0;
    return ret;
}
