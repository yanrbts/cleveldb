/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>

#include "log.h"
#include "utils.h"
#include "vfast.h"

/* 全局上下文，在 vfast.h 中 extern */
vfast_ctx_t vfastctx;

/* 优雅退出信号处理 */
static void client_signal_handler(int sig) {
    log_info("Caught signal %d, stopping client...", sig);
    atomic_store(&vfastctx.running, false);
}

/**
 * 客户端环境预配置
 */
static int setup_client_env(const char *ip, const char *gw, uint16_t port) {
    (void)gw; // 目前未使用网关参数，未来可扩展
    int ret;

    /* 1. 初始化 TUN 设备 */
    ret = vpn_tun_init(&vfastctx.tun, "tun0", 1);
    if (ret < 0) return ret;

    /* 2. 配置内网 IP (工业级加固版接口) */
    ret = vpn_tun_set_ip(vfastctx.tun.name, "10.0.0.2", "255.255.255.0");
    if (ret < 0) return ret;

    /* 3. 设置 MTU 并启动网卡 */
    /* 注意：由于 UDP/IP 头部占 28 字节，MTU 设为 1400 预留足够空间防止分片 */
    ret = vpn_tun_set_status(vfastctx.tun.name, 1400, 1);
    if (ret < 0) return ret;

    /* 4. 初始化 UDP 套接字并连接服务器 */
    vfastctx.udp = udp_init_listener(0, 20); // 随机端口，20MB 缓冲区
    if (!vfastctx.udp) return -1;

    ret = udp_set_connect(vfastctx.udp, inet_addr(ip), port);
    if (ret < 0) return ret;

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <server_ip>\n", argv[0]);
        return 1;
    }

    /* 初始化上下文 */
    memset(&vfastctx, 0, sizeof(vfast_ctx_t));
    vfastctx.free_top = -1;
    atomic_store(&vfastctx.running, true);

    signal(SIGINT, client_signal_handler);
    signal(SIGTERM, client_signal_handler);

    /* 1. 环境准备 */
    if (setup_client_env(argv[1], "10.0.0.2", 9999) < 0) {
        log_error("Failed to setup client environment");
        goto cleanup;
    }

    /* 2. 初始化 io_uring */
    if (vpn_iouring_init(&vfastctx.io_ring, IO_RING_DEPTH) < 0) {
        log_error("io_uring init failed");
        goto cleanup;
    }

    /* 3. 填充 Buffer 池 */
    for (int i = 0; i < IO_BUF_POOL_SIZE; i++) {
        vfast_buf_push(&vfastctx, i);
    }

    /* 4. 预提交读取请求 (保持 Pipeline 充满) */
    for (int i = 0; i < 128; i++) {
        int idx_t = vfast_buf_pop(&vfastctx);
        int idx_s = vfast_buf_pop(&vfastctx);

        if (idx_t != -1) {
            vpn_io_data_t *d = malloc(sizeof(vpn_io_data_t));
            d->type = IO_TYPE_TUN_READ;
            d->fd = vfastctx.tun.fd;
            vpn_iouring_submit_read(&vfastctx.io_ring, d->fd, idx_t, d);
        }
        if (idx_s != -1) {
            vpn_io_data_t *d = malloc(sizeof(vpn_io_data_t));
            d->type = IO_TYPE_SOCK_READ;
            d->fd = vfastctx.udp->fd;
            vpn_iouring_submit_read(&vfastctx.io_ring, d->fd, idx_s, d);
        }
    }

    log_info("VFAST Client started. Tunneling to %s:9999", argv[1]);

    /* 5. 主循环：Zero-Copy 转发逻辑 */
    while (atomic_load(&vfastctx.running)) {
        struct io_uring_cqe *cqe;
        
        int ret = io_uring_wait_cqe(&vfastctx.io_ring.ring, &cqe);
        if (ret < 0) {
            if (ret == -EINTR) continue;
            break;
        }

        vpn_io_data_t *data = (vpn_io_data_t *)io_uring_cqe_get_data(cqe);
        int res = cqe->res;
        int current_idx = data->buf_idx;

        if (res <= 0) {
            /* 错误处理：重新提交读取或回收 Buffer */
            if (data->type == IO_TYPE_TUN_READ || data->type == IO_TYPE_SOCK_READ) {
                vpn_iouring_submit_read(&vfastctx.io_ring, data->fd, current_idx, data);
            } else {
                vfast_buf_push(&vfastctx, current_idx);
                free(data);
            }
        } else {
            /* 状态机切换：跨 FD 转发 */
            switch (data->type) {
                case IO_TYPE_TUN_READ:
                    atomic_fetch_add(&vfastctx.stats.tx_packets, 1);
                    data->type = IO_TYPE_SOCK_WRITE;
                    vpn_iouring_submit_write(&vfastctx.io_ring, vfastctx.udp->fd, current_idx, res, data);
                    break;

                case IO_TYPE_SOCK_READ:
                    atomic_fetch_add(&vfastctx.stats.rx_packets, 1);
                    data->type = IO_TYPE_TUN_WRITE;
                    vpn_iouring_submit_write(&vfastctx.io_ring, vfastctx.tun.fd, current_idx, res, data);
                    break;

                case IO_TYPE_SOCK_WRITE:
                    /* 发送服务器完成，变回读取 TUN */
                    data->type = IO_TYPE_TUN_READ;
                    vpn_iouring_submit_read(&vfastctx.io_ring, vfastctx.tun.fd, current_idx, data);
                    break;

                case IO_TYPE_TUN_WRITE:
                    /* 注入系统完成，变回读取 Socket */
                    data->type = IO_TYPE_SOCK_READ;
                    vpn_iouring_submit_read(&vfastctx.io_ring, vfastctx.udp->fd, current_idx, data);
                    break;
            }
        }
        io_uring_cqe_seen(&vfastctx.io_ring.ring, cqe);
        vpn_iouring_flush(&vfastctx.io_ring);
    }

cleanup:
    vpn_tun_destroy(&vfastctx.tun);
    if (vfastctx.udp) udp_close(vfastctx.udp);
    vpn_iouring_destroy(&vfastctx.io_ring);
    log_info("Client shutdown complete.");
    return 0;
}