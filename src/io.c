/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */

#include "io.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/**
 * @brief 将使用完毕的缓冲区回收至 io_uring_buf_ring
 * @note 必须通过 io_uring_buf_ring_advance 通知内核新增了多少可用 Buffer
 */
static inline void _release_buffer(vfast_vpn_t *vpn, uint32_t bid, uint32_t *re_add_count)
{
    uint32_t mask = io_uring_buf_ring_mask(IO_BUF_COUNT);
    void *ptr = (uint8_t *)vpn->buf_base + (size_t)bid * IO_BUF_SIZE;
    
    /* 将缓冲区重新挂载到 Ring 的尾部 */
    io_uring_buf_ring_add(vpn->br, ptr, IO_BUF_SIZE, (uint16_t)bid, (int)mask, 0);
    if (re_add_count) (*re_add_count)++;
}

/**
 * @brief 向 SQ 提交一个异步 TUN 读取请求
 * @param bid 指定用于存放读取数据的缓冲区 ID
 */
static inline void _submit_tun_read(vfast_vpn_t *vpn, uint32_t bid)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&vpn->ring);
    if (!sqe) return;

    vfast_ioctx_t *ctx = &vpn->ctx_pool[bid];
    ctx->op  = OP_TYPE_TUN_READ;
    ctx->bid = bid;

    /* 异步读取 TUN 设备数据面 */
    io_uring_prep_read(sqe, IDX_TUN,
                       (uint8_t *)vpn->buf_base + (size_t)bid * IO_BUF_SIZE,
                       IO_BUF_SIZE, 0);
    
    sqe->flags |= IOSQE_FIXED_FILE; /* 使用注册过的文件索引加速 */
    io_uring_sqe_set_data(sqe, ctx);
}

/**
 * @brief 初始化或重置 UDP Multishot 接收模式
 * @note Multishot 允许一个 SQE 触发多次 CQE，极大减少系统调用开销
 */
static inline void _submit_udp_multishot(vfast_vpn_t *vpn)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&vpn->ring);
    if (!sqe) return;

    /* 准备多重接收：不指定固定地址，由内核从 Buffer Group 中自动选择 */
    io_uring_prep_recv_multishot(sqe, IDX_UDP, NULL, 0, 0);
    sqe->flags |= (IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT);
    sqe->buf_group = BR_GROUP_ID;
    
    /* Multishot SQE 的 data 通常设为 NULL 或特殊标记，因为 CQE 会携带不同的 Buffer ID */
    io_uring_sqe_set_data(sqe, NULL);
}

/**
 * @brief 将处理后的数据通过 UDP 发送给对端
 * @param len 发送数据的字节长度
 */
static inline void _submit_udp_send(vfast_vpn_t *vpn, vfast_ioctx_t *ctx, int len)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&vpn->ring);
    if (!sqe) return;

    ctx->op = OP_TYPE_SEND_BACK;
    
    /* 指向当前处理中的缓冲区起始位置 */
    ctx->iov.iov_base = (uint8_t *)vpn->buf_base + (size_t)ctx->bid * IO_BUF_SIZE;
    ctx->iov.iov_len  = (size_t)len;

    /* 使用 sendmsg 以支持 sockaddr_in 中指定的动态对端地址 */
    io_uring_prep_sendmsg(sqe, IDX_UDP, &ctx->msg, 0);
    sqe->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data(sqe, ctx);
}

int vfast_vpn_init(vfast_vpn_t *vpn, int udp_fd, int tun_fd)
{
    struct io_uring_params params = {0};
    
    /* 启用内核线程轮询 (SQPOLL)，数据包处理过程可实现完全的用户态零打扰 */
    params.flags |= IORING_SETUP_SQPOLL;
    params.sq_thread_idle = 2000;

    int ret = io_uring_queue_init_params(IO_RING_DEPTH, &vpn->ring, &params);
    if (ret < 0) {
        fprintf(stderr, "io_uring_queue_init_params failed: %s (code: %d)\n", strerror(-ret), ret);
        return -1;
    }

    /* 注册文件描述符，减少内核在 IO 路径上查找 FD 产生的开销 */
    int fds[2] = {udp_fd, tun_fd};
    if (io_uring_register_files(&vpn->ring, fds, 2) < 0) {
        perror("io_uring_register_files");
        goto err_ring;
    }

    /* 初始化 Buffer Ring */
    uint32_t mask = io_uring_buf_ring_mask(IO_BUF_COUNT);
    size_t br_size = (size_t)(mask + 1) * sizeof(struct io_uring_buf);

    if (posix_memalign((void **)&vpn->br, 4096, br_size) != 0) {
        perror("posix_memalign br");
        goto err_ring;
    }

    struct io_uring_buf_reg reg = {
        .ring_addr    = (uintptr_t)vpn->br,
        .ring_entries = IO_BUF_COUNT,
        .bgid         = BR_GROUP_ID
    };

    if (io_uring_register_buf_ring(&vpn->ring, &reg, 0) < 0) {
        perror("io_uring_register_buf_ring");
        goto err_br;
    }

    /* 分配并对齐大块缓冲区内存池 */
    if (posix_memalign(&vpn->buf_base, 4096, (size_t)IO_BUF_COUNT * IO_BUF_SIZE) != 0) {
        perror("posix_memalign buf_base");
        goto err_br_reg;
    }

    /* 初始化上下文池 */
    vpn->ctx_pool = calloc(IO_BUF_COUNT, sizeof(vfast_ioctx_t));
    if (!vpn->ctx_pool) {
        perror("calloc ctx_pool");
        goto err_buf;
    }

    io_uring_buf_ring_init(vpn->br);

    /* 预填充 Buffer 并初始化上下文默认值 */
    for (int i = 0; i < IO_BUF_COUNT; i++) {
        void *ptr = (uint8_t *)vpn->buf_base + (size_t)i * IO_BUF_SIZE;
        io_uring_buf_ring_add(vpn->br, ptr, IO_BUF_SIZE, (uint16_t)i, (int)mask, 0);

        vfast_ioctx_t *ctx   = &vpn->ctx_pool[i];
        ctx->bid             = i;
        ctx->msg.msg_name    = &ctx->addr;
        ctx->msg.msg_namelen = sizeof(struct sockaddr_in);
        ctx->msg.msg_iov     = &ctx->iov;
        ctx->msg.msg_iovlen  = 1;
    }

    /* 提交所有初始缓冲区给内核 */
    io_uring_buf_ring_advance(vpn->br, IO_BUF_COUNT);

    vpn->on_udp_recv = NULL;
    vpn->on_tun_read = NULL;

    return 0;

err_buf:
    free(vpn->buf_base);
err_br_reg:
    io_uring_unregister_buf_ring(&vpn->ring, BR_GROUP_ID);
err_br:
    free(vpn->br);
err_ring:
    io_uring_queue_exit(&vpn->ring);
    return -1;
}

void vfast_vpn_run(vfast_vpn_t *vpn)
{
    struct io_uring_cqe *cqe;
    unsigned head;
    uint32_t cqe_count = 0, re_add_count = 0;

    /* 启动接收流：UDP 使用 Multishot，TUN 使用预热读队列 */
    _submit_udp_multishot(vpn);
    for (int i = 0; i < 256; i++) {
        _submit_tun_read(vpn, (uint32_t)i);
    }

    while (1) {
        cqe_count = 0;
        re_add_count = 0;

        /* 阻塞等待至少 1 个事件完成 */
        io_uring_submit_and_wait(&vpn->ring, 1);

        io_uring_for_each_cqe(&vpn->ring, head, cqe) {
            cqe_count++;
            int res = cqe->res;
            
            /* 错误处理：通常是资源暂时不可用或连接重置 */
            if (res < 0) {
                if (res != -EAGAIN)
                    fprintf(stderr, "CQE error: %d\n", res);
                goto next_cqe;
            }

            /* --- 路径 A: UDP 数据进入 (解密并转发至 TUN) --- */
            if (cqe->flags & IORING_CQE_F_BUFFER) {
                uint32_t bid = (uint32_t)(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
                uint8_t *data = (uint8_t *)vpn->buf_base + (size_t)bid * IO_BUF_SIZE;

                vfast_ioctx_t *ctx = &vpn->ctx_pool[bid];
                ctx->op = OP_TYPE_TUN_WRITE_ASYNC;

                int processed_len = res;
                if (vpn->on_udp_recv) {
                    /* 回调业务层进行协议解析与解密 */
                    processed_len = vpn->on_udp_recv(vpn, &data, res, ctx);
                }

                if (processed_len > 0) {
                    struct io_uring_sqe *sqe = io_uring_get_sqe(&vpn->ring);
                    if (sqe) {
                        /* 零拷贝写入 TUN 设备：注意此处的指针可能已被业务层偏移 */
                        io_uring_prep_write(sqe, IDX_TUN, data, processed_len, 0);
                        sqe->flags |= IOSQE_FIXED_FILE;
                        io_uring_sqe_set_data(sqe, ctx);
                    } else {
                        _release_buffer(vpn, bid, &re_add_count);
                    }
                } else {
                    _release_buffer(vpn, bid, &re_add_count);
                }
            } 
            /* --- 路径 B: 链式操作完成通知 --- */
            else {
                vfast_ioctx_t *ctx = (vfast_ioctx_t *)io_uring_cqe_get_data(cqe);
                if (!ctx) goto next_cqe;

                switch (ctx->op) {
                    case OP_TYPE_TUN_WRITE_ASYNC:
                        /* TUN 写入完成后回收 Buffer */
                        _release_buffer(vpn, ctx->bid, &re_add_count);
                        break;

                    case OP_TYPE_TUN_READ: {
                        /* 从 TUN 读到明文 -> 业务加密 -> 发回 UDP */
                        uint8_t *data = (uint8_t *)vpn->buf_base + (size_t)ctx->bid * IO_BUF_SIZE;
                        int processed_len = res;

                        if (vpn->on_tun_read)
                            processed_len = vpn->on_tun_read(vpn, &data, res, ctx);

                        if (processed_len > 0) {
                            _submit_udp_send(vpn, ctx, processed_len);
                        } else {
                            /* 业务层认为此包无效，重投读取请求 */
                            _submit_tun_read(vpn, ctx->bid);
                        }
                        break;
                    }

                    case OP_TYPE_SEND_BACK:
                        /* UDP 发送完成后，该 Buffer 对应的 context 重新进入 TUN 读取状态 */
                        _submit_tun_read(vpn, ctx->bid);
                        break;

                    default:
                        break;
                }
            }

        next_cqe:
            /* 检查 Multishot 是否因错误中断，若是则需要重新提交 */
            if ((cqe->flags & IORING_CQE_F_BUFFER) && !(cqe->flags & IORING_CQE_F_MORE)) {
                _submit_udp_multishot(vpn);
            }
        }

        /* 批量回收缓冲区并推进完成队列 */
        if (re_add_count > 0)
            io_uring_buf_ring_advance(vpn->br, re_add_count);

        if (cqe_count > 0)
            io_uring_cq_advance(&vpn->ring, cqe_count);
    }
}

void vfast_vpn_destroy(vfast_vpn_t *vpn)
{
    if (!vpn) return;
    io_uring_unregister_buf_ring(&vpn->ring, BR_GROUP_ID);
    io_uring_queue_exit(&vpn->ring);
    free(vpn->br);
    free(vpn->buf_base);
    free(vpn->ctx_pool);
    memset(vpn, 0, sizeof(*vpn));
}