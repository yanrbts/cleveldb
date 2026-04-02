#include "io.h"
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>

#include "io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

/* --- 工具函数：分配 TUN 设备 --- */
int alloc_tun(char *dev) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // IFF_TUN (IP层), IFF_NO_PI (不包含额外包头)
    if (*dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}

/* --- 工具函数：创建 UDP 套接字 --- */
int alloc_udp(int port) {
    int fd;
    struct sockaddr_in addr;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    // 设置端口复用，方便调试
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    return fd;
}

/* --- 业务回调：处理 UDP -> TUN (解密/剥包路径) --- */
int my_on_udp_recv(vfast_vpn_t *vpn, uint8_t **data, int len, vfast_ioctx_t *ctx) {
    (void)vpn;
    // 假设 VFast 协议头是 24 字节
    if (len <= 24) return -1; 

    // 零拷贝剥离头部：直接移动指针
    *data += 24; 

    printf("[UDP -> TUN] Src: %s:%d, Payload: %d bytes\n", 
           inet_ntoa(ctx->addr.sin_addr), ntohs(ctx->addr.sin_port), len - 24);
    return len - 24;
}

/* --- 业务回调：处理 TUN -> UDP (加密/封包路径) --- */
int my_on_tun_read(vfast_vpn_t *vpn, uint8_t **data, int len, vfast_ioctx_t *ctx) {
    (void)vpn;
    // 演示：强制将所有从 TUN 读到的包发往特定对端 (127.0.0.1:9999)
    // 实际业务中这里应该根据 IP 头部的目的地址查找 Session 表
    ctx->addr.sin_family = AF_INET;
    ctx->addr.sin_port = htons(9999); 
    inet_pton(AF_INET, "127.0.0.1", &ctx->addr.sin_addr);

    // 演示：这里不加头直接发（如果需要加头，需要配合 Headroom 预留空间，否则会越界）
    printf("[TUN -> UDP] Captured IP Packet: %d bytes -> 127.0.0.1:9999\n", len);
    return len; 
}

int main(int argc, char *argv[]) {
    char tun_name[IFNAMSIZ] = "vfast0";
    int udp_port = 8888;

    if (argc > 1) udp_port = atoi(argv[1]);

    // 1. 准备文件描述符
    int tun_fd = alloc_tun(tun_name);
    if (tun_fd < 0) return 1;

    int udp_fd = alloc_udp(udp_port);
    if (udp_fd < 0) return 1;

    printf("Successfully initialized %s and UDP port %d\n", tun_name, udp_port);
    printf("Please run: 'sudo ip addr add 10.0.0.1/24 dev %s && sudo ip link set %s up'\n", tun_name, tun_name);

    // 2. 初始化引擎
    vfast_vpn_t vpn;
    if (vfast_vpn_init(&vpn, udp_fd, tun_fd) < 0) {
        fprintf(stderr, "VPN Engine Init Failed\n");
        return 1;
    }

    // 3. 注册业务逻辑
    vpn.on_udp_recv = my_on_udp_recv;
    vpn.on_tun_read = my_on_tun_read;

    // 4. 进入 io_uring 运行循环
    vfast_vpn_run(&vpn);

    vfast_vpn_destroy(&vpn);
    return 0;
}