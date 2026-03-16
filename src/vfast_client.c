/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * Description: Full Industrial-grade VFAST VPN Client with Lifecycle Management.
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

/* ---------------- 全局上下文 ---------------- */
vfast_ctx_t vfastctx;

/* 宏定义：方便获取固定 Buffer 的指针 */
#define get_buf_ptr(idx) ((uint8_t *)vfastctx.io_ring.iovecs[idx].iov_base)

/* 信号处理：优雅退出 */
static void client_signal_handler(int sig) {
    (void)sig;
    log_info("Catch signal, set running to false...");
    atomic_store(&vfastctx.running, false);
}

/* ---------------- 任务提交模块 (Submissions) ---------------- */

static inline int submit_tun_read(int idx) {
    vpn_io_data_t *d = &vfastctx.io_data_pool[idx];
    d->type = IO_TYPE_TUN_READ;
    d->buf_idx = idx;

    // 偏移协议头长度，给 vpn_pack 留出填充空间
    uint8_t *read_ptr = get_buf_ptr(idx) + VPN_TNL_HLEN;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&vfastctx.io_ring.ring);
    if (unlikely(!sqe)) return -1;

    io_uring_prep_read(sqe, vfastctx.tun.fd, read_ptr, IO_BUF_SIZE - VPN_TNL_HLEN, 0);
    io_uring_sqe_set_data(sqe, d);
    return 0;
}

static inline int submit_udp_read(int idx) {
    vpn_io_data_t *d = &vfastctx.io_data_pool[idx];
    d->type = IO_TYPE_SOCK_READ;
    d->buf_idx = idx;

    uint8_t *ptr = get_buf_ptr(idx) + VPN_TNL_HLEN;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&vfastctx.io_ring.ring);
    if (unlikely(!sqe)) return -1;

    io_uring_prep_recv(sqe, vfastctx.udp->fd, ptr, IO_BUF_SIZE - VPN_TNL_HLEN, 0);
    io_uring_sqe_set_data(sqe, d);
    return 0;
}

static inline int submit_generic_write(int fd, int idx, int len, int type) {
    vpn_io_data_t *d = &vfastctx.io_data_pool[idx];
    d->type = type;
    d->buf_idx = idx;

    uint8_t *ptr = get_buf_ptr(idx);
    struct io_uring_sqe *sqe = io_uring_get_sqe(&vfastctx.io_ring.ring);
    if (unlikely(!sqe)) return -1;

    io_uring_prep_write(sqe, fd, ptr, len, 0);
    io_uring_sqe_set_data(sqe, d);
    return 0;
}

/* ---------------- 核心事件处理器 (Handler) ---------------- */

static void handle_io_event(struct io_uring_cqe *cqe, uint32_t *sid_ctx) {
    vpn_io_data_t *data = (vpn_io_data_t *)io_uring_cqe_get_data(cqe);
    int res = cqe->res;
    int idx = data->buf_idx;
    uint8_t *ptr = get_buf_ptr(idx);

    // 基础错误检查
    if (unlikely(res <= 0)) {
        if (res < 0 && res != -EAGAIN && res != -EINTR) {
            log_error("IO Error: type=%d, res=%s", data->type, strerror(-res));
        }
        goto recycle;
    }

    switch (data->type) {
        case IO_TYPE_TUN_READ: {
            // 只处理 IPv4
            if (unlikely((*(ptr + VPN_TNL_HLEN) >> 4) != 4)) goto recycle;

            int total = vpn_pack(ptr, res, IO_BUF_SIZE, VPN_MSG_DATA, *sid_ctx);
            if (likely(total > 0)) {
                submit_generic_write(vfastctx.udp->fd, idx, total, IO_TYPE_SOCK_WRITE);
            } else {
                goto recycle;
            }
            break;
        }

        case IO_TYPE_SOCK_READ: {
            int p_len = 0; uint32_t r_sid = 0;
            uint8_t *ip_pkt = vpn_unpack(ptr, res, &p_len, &r_sid);
            
            if (ip_pkt && p_len > 0) {
                if (r_sid != 0) *sid_ctx = r_sid;
                // 异步写回 TUN
                submit_generic_write(vfastctx.tun.fd, idx, p_len, IO_TYPE_TUN_WRITE);
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
    // 任务回收重连：如果是读任务或写任务失败，恢复到对应的读状态
    if (data->type == IO_TYPE_TUN_READ || data->type == IO_TYPE_SOCK_WRITE) {
        submit_tun_read(idx);
    } else {
        submit_udp_read(idx);
    }
}

/* ---------------- 资源清理 (Cleanup) ---------------- */

static void vfast_cleanup() {
    log_info("Cleaning up resources...");
    
    // 1. 关闭 io_uring
    if (vfastctx.io_ring.ring.ring_fd > 0) {
        io_uring_queue_exit(&vfastctx.io_ring.ring);
    }

    // 2. 关闭网卡和 Socket
    if (vfastctx.tun.fd > 0) close(vfastctx.tun.fd);
    if (vfastctx.udp && vfastctx.udp->fd > 0) close(vfastctx.udp->fd);

    // 3. 释放内存
    if (vfastctx.io_data_pool) zfree(vfastctx.io_data_pool);
    
    log_info("Cleanup finished. Exit.");
}

/* ---------------- 主程序 (Main) ---------------- */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // 0. 基础配置
    uint32_t current_sid = 0x12345678;
    memset(&vfastctx, 0, sizeof(vfast_ctx_t));
    atomic_store(&vfastctx.running, true);
    vfastctx.free_top = -1;

    // 信号注册
    struct sigaction sa = {.sa_handler = client_signal_handler};
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // 1. 内存池分配
    vfastctx.io_data_pool = (vpn_io_data_t *)zmalloc(IO_BUF_POOL_SIZE * sizeof(vpn_io_data_t));
    if (!vfastctx.io_data_pool) {
        log_error("Failed to allocate IO data pool.");
        return EXIT_FAILURE;
    }
    // 初始化空闲 Buffer 栈
    for (int i = 0; i < IO_BUF_POOL_SIZE; i++) vfast_buf_push(&vfastctx, i);

    // 2. VPN 网卡初始化 (tun0, 10.0.0.2)
    if (vpn_tun_init(&vfastctx.tun, "tun0", 1) < 0) {
        vfast_cleanup();
        return EXIT_FAILURE;
    }
    vpn_tun_set_ip(vfastctx.tun.name, "10.0.0.2", "255.255.255.0");
    vpn_tun_set_status(vfastctx.tun.name, 1400, 1);
    
    // 3. UDP Socket 初始化
    vfastctx.udp = udp_init_listener(0, 20); // 监听随机物理端口
    if (!vfastctx.udp) {
        vfast_cleanup();
        return EXIT_FAILURE;
    }
    // 强行关联服务端地址
    udp_set_connect(vfastctx.udp, inet_addr(argv[1]), 9999);

    // 4. io_uring 初始化
    if (vpn_iouring_init(&vfastctx.io_ring, IO_RING_DEPTH) < 0) {
        vfast_cleanup();
        return EXIT_FAILURE;
    }

    // 5. 投放第一批异步任务 (Seed Tasks)
    // 工业级做法：一半 Buffer 用于监听 TUN，一半用于监听 UDP
    for (int i = 0; i < (IO_BUF_POOL_SIZE / 2); i++) {
        int idx_t = vfast_buf_pop(&vfastctx);
        if (idx_t != -1) submit_tun_read(idx_t);

        int idx_s = vfast_buf_pop(&vfastctx);
        if (idx_s != -1) submit_udp_read(idx_s);
    }
    // 初始提交
    io_uring_submit(&vfastctx.io_ring.ring);

    log_info("VFAST Client Running. Peer: %s:9999", argv[1]);

    // 6. 主事件循环
    struct io_uring_cqe *cqes[16];
    while (likely(atomic_load(&vfastctx.running))) {
        struct io_uring_cqe *cqe_wait;
        
        // 阻塞等待至少 1 个 CQE，节省 CPU 功耗
        int ret = io_uring_wait_cqe(&vfastctx.io_ring.ring, &cqe_wait);
        if (unlikely(ret < 0)) {
            if (ret == -EINTR) continue;
            log_error("io_uring_wait_cqe failed: %s", strerror(-ret));
            break;
        }

        // 批量消费已完成任务
        int count = io_uring_peek_batch_cqe(&vfastctx.io_ring.ring, cqes, 16);
        for (int i = 0; i < count; i++) {
            handle_io_event(cqes[i], &current_sid);
            io_uring_cqe_seen(&vfastctx.io_ring.ring, cqes[i]);
        }

        // 关键：每一轮处理完后，必须把新产生的 SQE 提交给内核
        io_uring_submit(&vfastctx.io_ring.ring);
    }

    // 7. 退出后的清理
    vfast_cleanup();

    return 0;
}