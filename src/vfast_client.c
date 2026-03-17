/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * Description: Clean Logic VFAST VPN Client.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <sys/uio.h>

#include "log.h"
#include "utils.h"
#include "vfast.h"
#include "zmalloc.h"
#include "protocol.h"
#include "iouring.h"

/* ---------------- 全局上下文 ---------------- */
vfast_ctx_t vfastctx;

#define get_buf_ptr(idx) ((uint8_t *)vfastctx.io_ring.iovecs[idx].iov_base)

static void client_signal_handler(int sig) {
    (void)sig;
    atomic_store(&vfastctx.running, false);
}

/* ---------------- 任务提交模块 (Submissions) ---------------- */

/**
 * submit_tun_read - 发送路径：必须偏移 8 字节
 * 理由：TUN 读进来的是原始 IP 包，我们需要在前面空出 8 字节写 VFAST 头。
 */
static inline int submit_tun_read(int idx) {
    vpn_io_data_t *d = &vfastctx.io_data_pool[idx];
    d->type = IO_TYPE_TUN_READ;
    d->buf_idx = idx;

    uint8_t *read_ptr = get_buf_ptr(idx) + VPN_TNL_HLEN; // 偏移 8
    struct io_uring_sqe *sqe = io_uring_get_sqe(&vfastctx.io_ring.ring);
    if (unlikely(!sqe)) return -1;

    io_uring_prep_read_fixed(sqe, vfastctx.tun.fd, read_ptr, IO_BUF_SIZE - VPN_TNL_HLEN, 0, idx);
    io_uring_sqe_set_data(sqe, d);
    return 0;
}

/**
 * submit_udp_read - 接收路径：不偏移 (从 0 开始)
 * 理由：接收的是完整的 VFAST 包，直接从 buffer 开头存，逻辑最清晰。
 */
static inline int submit_udp_read(int idx) {
    vpn_io_data_t *d = &vfastctx.io_data_pool[idx];
    d->type = IO_TYPE_SOCK_READ;
    d->buf_idx = idx;

    uint8_t *ptr = get_buf_ptr(idx); // 不偏移
    struct io_uring_sqe *sqe = io_uring_get_sqe(&vfastctx.io_ring.ring);
    if (unlikely(!sqe)) return -1;

    io_uring_prep_read_fixed(sqe, vfastctx.udp->fd, ptr, IO_BUF_SIZE, 0, idx);
    io_uring_sqe_set_data(sqe, d);
    return 0;
}

/**
 * submit_fixed_write_raw - 通用写入：直接按指针写
 */
static inline int submit_fixed_write_raw(int fd, int idx, void *ptr, int len, int type) {
    vpn_io_data_t *d = &vfastctx.io_data_pool[idx];
    d->type = type;
    d->buf_idx = idx;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&vfastctx.io_ring.ring);
    if (unlikely(!sqe)) return -1;

    io_uring_prep_write_fixed(sqe, fd, ptr, len, 0, idx);
    io_uring_sqe_set_data(sqe, d);
    return 0;
}

/* ---------------- 核心事件处理器 (Handler) ---------------- */

static void handle_io_event(struct io_uring_cqe *cqe, uint32_t *sid_ctx) {
    vpn_io_data_t *data = (vpn_io_data_t *)io_uring_cqe_get_data(cqe);
    int res = cqe->res;
    int idx = data->buf_idx;
    uint8_t *base_ptr = get_buf_ptr(idx);

    if (unlikely(res <= 0)) {
        goto recycle;
    }

    switch (data->type) {
        case IO_TYPE_TUN_READ: {
            /* 1. TUN 读进来的 IP 包在 base_ptr + 8 */
            uint8_t *ip_in_buf = base_ptr + VPN_TNL_HLEN;
            
            /* 2. vpn_pack 会从 base_ptr[0] 开始写头，返回 [头+IP包] 的总长度 */
            int total = vpn_pack(base_ptr, res, IO_BUF_SIZE, VPN_MSG_DATA, *sid_ctx);
            if (likely(total > 0)) {
                submit_fixed_write_raw(vfastctx.udp->fd, idx, base_ptr, total, IO_TYPE_SOCK_WRITE);
            } else {
                goto recycle;
            }
            break;
        }

        case IO_TYPE_SOCK_READ: {
            int p_len = 0; 
            uint32_t r_sid = 0;
            
            /* 1. UDP 读进来的完整 VFAST 包就在 base_ptr[0] */
            /* 2. vpn_unpack 内部逻辑应该是：读头，然后返回 base_ptr + 8 */
            uint8_t *ip_pkt = vpn_unpack(base_ptr, res, &p_len, &r_sid);

            if (ip_pkt && p_len > 0) {
                if (r_sid != 0) *sid_ctx = r_sid;
                /* 3. 将剥离头部的纯 IP 包写回 TUN */
                submit_fixed_write_raw(vfastctx.tun.fd, idx, ip_pkt, p_len, IO_TYPE_TUN_WRITE);
            } else {
                goto recycle;
            }
            break;
        }

        case IO_TYPE_SOCK_WRITE:
            submit_tun_read(idx);
            break;

        case IO_TYPE_TUN_WRITE:
            submit_udp_read(idx);
            break;
    }
    return;

recycle:
    if (data->type == IO_TYPE_TUN_READ || data->type == IO_TYPE_SOCK_WRITE) {
        submit_tun_read(idx);
    } else {
        submit_udp_read(idx);
    }
}

/* ---------------- 资源清理与 Main ---------------- */

static void vfast_cleanup() {
    log_info("Cleaning up...");
    if (vfastctx.io_ring.ring.ring_fd > 0) vpn_iouring_destroy(&vfastctx.io_ring);
    if (vfastctx.tun.fd > 0) close(vfastctx.tun.fd);
    if (vfastctx.udp && vfastctx.udp->fd > 0) close(vfastctx.udp->fd);
    if (vfastctx.io_data_pool) zfree(vfastctx.io_data_pool);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        return 1;
    }

    uint32_t current_sid = 0x12345678;
    memset(&vfastctx, 0, sizeof(vfast_ctx_t));
    atomic_store(&vfastctx.running, true);

    struct sigaction sa = {.sa_handler = client_signal_handler};
    sigaction(SIGINT, &sa, NULL);

    vfastctx.io_data_pool = (vpn_io_data_t *)zmalloc(IO_BUF_POOL_SIZE * sizeof(vpn_io_data_t));
    if (vpn_iouring_init(&vfastctx.io_ring, IO_RING_DEPTH) < 0) return 1;

    if (vpn_tun_init(&vfastctx.tun, "tun0", 1) < 0) return 1;
    vpn_tun_set_ip(vfastctx.tun.name, "10.0.0.2", "255.255.255.0");
    vpn_tun_set_status(vfastctx.tun.name, 1400, 1);
    
    vfastctx.udp = udp_init_listener(0, 20);
    udp_set_connect(vfastctx.udp, inet_addr(argv[1]), 9999);

    // 初始分配：一半 Buffer 守 TUN，一半守 UDP
    for (int i = 0; i < (IO_BUF_POOL_SIZE / 2); i++) {
        submit_tun_read(i);
        submit_udp_read(i + (IO_BUF_POOL_SIZE / 2));
    }
    io_uring_submit(&vfastctx.io_ring.ring);

    struct io_uring_cqe *cqes[16];
    while (likely(atomic_load(&vfastctx.running))) {
        struct io_uring_cqe *cqe_wait;
        if (io_uring_wait_cqe(&vfastctx.io_ring.ring, &cqe_wait) < 0) continue;

        int count = io_uring_peek_batch_cqe(&vfastctx.io_ring.ring, cqes, 16);
        for (int i = 0; i < count; i++) {
            handle_io_event(cqes[i], &current_sid);
            io_uring_cqe_seen(&vfastctx.io_ring.ring, cqes[i]);
        }
        io_uring_submit(&vfastctx.io_ring.ring);
    }

    vfast_cleanup();
    return 0;
}