#include "packet_socket.h"


int packet_socket_send(Bridge* bridge, uint8_t* data, size_t len){
    int ret = sendto(bridge->fd, data, len, 0, (struct sockaddr*)&bridge->asset_interface, sizeof(bridge->asset_interface));
    if(ret < 0){
        LOG_ERR("Failed to send data on packet socket: %s", strerror(errno));
    }
    return ret;
}


int packet_socket_receive(Bridge* bridge){
    int ret = recvfrom(bridge->fd, bridge->buf, sizeof(bridge->buf), 0, NULL, NULL);
    if(ret < 0){
        LOG_ERR("Failed to receive data on packet socket: %s", strerror(errno));
    }
    return ret;
}


int packet_socket_pipe(Bridge* bridge, uint8_t* data, size_t len){
    int bridge_send(bridge,data,len);
}