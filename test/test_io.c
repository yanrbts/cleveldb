/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <liburing.h>
#include <errno.h>
#include "iouring.h"
#include "utils.h"
#include "vfast.h"

/* 模拟外部定义的封装/解包长度 */
#define VPN_TNL_HLEN 8 

/* Buffer index management */
static int free_stack[IO_BUF_POOL_SIZE];
static int top = -1;

void push_index(int idx) {
    if (top < IO_BUF_POOL_SIZE - 1) free_stack[++top] = idx;
}

int pop_index() {
    return (top >= 0) ? free_stack[top--] : -1;
}

int main() {
    vpn_iouring_ctx_t ctx;
    int ret;
    int tun_fd = 3;  // 假设的 TUN 文件描述符
    int sock_fd = 4; // 假设的 Socket 文件描述符

    /* 1. 初始化 io_uring */
    if (vpn_iouring_init(&ctx, IO_RING_DEPTH) < 0) {
        fprintf(stderr, "Failed to init io_uring\n");
        return 1;
    }

    for (int i = 0; i < IO_BUF_POOL_SIZE; i++) push_index(i);

    /* 2. 初始投放：启动 TUN 读取 (方向 A 开始) */
    for (int i = 0; i < 128; i++) {
        int idx = pop_index();
        if (idx == -1) break;

        vpn_io_data_t *io_data = malloc(sizeof(vpn_io_data_t));
        io_data->buf_idx = idx;
        io_data->fd = tun_fd;
        
        /* 使用你的接口：内部自动处理 Base + 8 偏移 */
        vpn_submit_tun_read(&ctx, tun_fd, idx, io_data);
    }
    vpn_iouring_flush(&ctx);

    /* 3. 事件循环 */
    while (1) {
        struct io_uring_cqe *cqe;
        ret = io_uring_wait_cqe(&ctx.ring, &cqe);
        if (ret < 0) break;

        vpn_io_data_t *d = (vpn_io_data_t *)io_uring_cqe_get_data(cqe);
        int res = cqe->res;

        if (unlikely(res <= 0)) {
            /* 错误处理：回收并重新挂载 */
            if (d->type == IO_TYPE_TUN_READ) vpn_submit_tun_read(&ctx, tun_fd, d->buf_idx, d);
            else push_index(d->buf_idx); // 简化处理
            goto seen;
        }

        switch (d->type) {
            case IO_TYPE_TUN_READ:
                /* 方向 A (1): 读完网卡 -> 转换 -> 准备发给 UDP */
                // 此时 IP 包在 Base + 8，长度为 res
                // 假设此处进行了 vpn_pack，总长度变为 res + 8
                d->buf_len = res + VPN_TNL_HLEN; 
                
                /* 使用 sendmsg 发送封包后的数据 */
                vpn_submit_udp_sendmsg(&ctx, sock_fd, d->buf_idx, d->buf_len, d);
                break;

            case IO_TYPE_SOCK_WRITE:
                /* 方向 A (2): 发完了 -> 重置 -> 回到网卡继续等下一个包 */
                vpn_submit_tun_read(&ctx, tun_fd, d->buf_idx, d);
                break;

            case IO_TYPE_SOCK_READ:
                /* 方向 B (1): 读完物理网络 -> 转换 -> 准备写回内核 */
                // 假设此处进行了 vpn_unpack，得到纯 IP 包长度存入 buf_len
                // d->buf_len = unpack_result_len; 
                
                /* 使用你的接口：内部自动计算 Base + 8 偏移并使用 d->buf_len */
                vpn_submit_tun_write(&ctx, tun_fd, d->buf_idx, d);
                break;

            case IO_TYPE_TUN_WRITE:
                /* 方向 B (2): 写进去了 -> 重置 -> 回到网络继续等下一个包 */
                vpn_submit_udp_recvmsg(&ctx, sock_fd, d->buf_idx, d);
                break;
        }

    seen:
        io_uring_cqe_seen(&ctx.ring, cqe);
        vpn_iouring_flush(&ctx);
    }

    vpn_iouring_destroy(&ctx);
    return 0;
}