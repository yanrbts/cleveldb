/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "tun.h"

#define VPN_TUN_DEVICE "/dev/net/tun"

int vpn_tun_init(vpn_tun_ctx_t *ctx, const char *dev_name, int multi_queue) {
    struct ifreq ifr;
    int fd;

    if (!ctx) return -EINVAL;

    // 1. 打开 TUN 字符设备
    if ((fd = open(VPN_TUN_DEVICE, O_RDWR)) < 0) {
        perror("Failed to open /dev/net/tun");
        return -errno;
    }

    memset(&ifr, 0, sizeof(ifr));
    
    // IFF_TUN: 三层 IP 模式 (VPN 常用)
    // IFF_NO_PI: 不包含 4 字节的包信息头，减少封装开销，提升性能
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    // 开启多队列支持，配合 io_uring 实现万级并发下的并行处理
    if (multi_queue) {
        ifr.ifr_flags |= IFF_MULTI_QUEUE;
    }

    if (dev_name && *dev_name) {
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
    }

    // 2. 向内核注册设备
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl(TUNSETIFF) failed");
        close(fd);
        return -errno;
    }

    // 3. 设置为非阻塞模式 (O_NONBLOCK)
    // 这是 io_uring 配合网络/字符设备时获得高性能的关键
    int ret = vpn_set_nonblocking(fd);
    if (ret < 0) {
        close(fd);
        return ret;
    }

    // 4. 保存上下文信息
    ctx->fd = fd;
    strncpy(ctx->name, ifr.ifr_name, IFNAMSIZ);

    return 0; 
}

int vpn_tun_set_status(const char *dev_name, int mtu, int up) {
    int sock;
    struct ifreq ifr;

    if (!dev_name) return -EINVAL;

    // 需要一个临时的 socket 来执行网卡控制 ioctl
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -errno;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);

    // 1. 设置 MTU
    // 建议值：1400（为加密头和 UDP 封装留出空间，防止在物理链路上分片）
    if (mtu > 0) {
        ifr.ifr_mtu = mtu;
        if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
            perror("SIOCSIFMTU failed");
            close(sock);
            return -errno;
        }
    }

    // 2. 设置 Up/Down 状态
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        perror("SIOCGIFFLAGS failed");
        close(sock);
        return -errno;
    }

    if (up) {
        ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    } else {
        ifr.ifr_flags &= ~IFF_UP;
    }

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        perror("SIOCSIFFLAGS failed");
        close(sock);
        return -errno;
    }

    close(sock);
    return 0;
}

void vpn_tun_destroy(vpn_tun_ctx_t *ctx) {
    if (!ctx) return;

    if (ctx->fd >= 0) {
        // 关闭 FD 后，如果没开启 persist-tun，内核会自动销毁该虚拟接口
        close(ctx->fd);
        ctx->fd = -1;
    }
    
    // 清空名称
    memset(ctx->name, 0, IFNAMSIZ);
}