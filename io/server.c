#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include "io.h"

static int has_peer = 0;

int server_on_udp(vfast_io_t *io, uint8_t *data, int len, struct sockaddr_in *src) {
    memcpy(&io->remote_addr, src, sizeof(struct sockaddr_in));
    has_peer = 1;
    vfast_submit_write(io, io->tun_fd, OP_TUN_WRITE, data, len, NULL);
    return 0;
}

int server_on_tun(vfast_io_t *io, uint8_t *data, int len) {
    if (has_peer) vfast_submit_write(io, io->udp_fd, OP_UDP_SEND, data, len, &io->remote_addr);
    return 0;
}

int main() {
    // 设置服务器为 10.0.0.1
    int tun_fd = vfast_setup_tun("vfast0", "10.0.0.1");
    if (tun_fd < 0) { perror("TUN setup failed"); return 1; }

    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in bind_addr = { .sin_family = AF_INET, .sin_port = htons(9999), .sin_addr.s_addr = INADDR_ANY };
    bind(udp_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr));

    vfast_io_t io;
    vfast_ops_t ops = { server_on_udp, server_on_tun };
    vfast_io_init(&io, udp_fd, tun_fd, ops);

    printf("Server running on 10.0.0.1:9999 (TUN: vfast0)\n");
    vfast_io_run(&io);
    return 0;
}