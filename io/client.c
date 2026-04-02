#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include "io.h"

int client_on_udp(vfast_io_t *io, uint8_t *data, int len, struct sockaddr_in *src) {
    vfast_submit_write(io, io->tun_fd, OP_TUN_WRITE, data, len, NULL);
    return 0;
}

int client_on_tun(vfast_io_t *io, uint8_t *data, int len) {
    vfast_submit_write(io, io->udp_fd, OP_UDP_SEND, data, len, &io->remote_addr);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) { printf("Usage: %s <server_public_ip>\n", argv[0]); return 1; }

    // 设置客户端为 10.0.0.2
    int tun_fd = vfast_setup_tun("vfast0", "10.0.0.2");
    if (tun_fd < 0) { perror("TUN setup failed"); return 1; }

    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);

    vfast_io_t io;
    memset(&io.remote_addr, 0, sizeof(io.remote_addr));
    io.remote_addr.sin_family = AF_INET;
    io.remote_addr.sin_port = htons(9999);
    inet_pton(AF_INET, argv[1], &io.remote_addr.sin_addr);

    vfast_ops_t ops = { client_on_udp, client_on_tun };
    vfast_io_init(&io, udp_fd, tun_fd, ops);

    printf("Client running on 10.0.0.2, connecting to %s:9999\n", argv[1]);
    vfast_io_run(&io);
    return 0;
}