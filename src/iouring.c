/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/resource.h>
#include "log.h"
#include "iouring.h"

/**
 * vpn_iouring_init - Initialize the io_uring instance.
 * @entries: Queue depth (e.g., 4096).
 */
int vpn_iouring_init(vpn_iouring_ctx_t *ctx, uint32_t entries) {
    struct io_uring_params params;
    struct rlimit rlim;

    /* INDUSTRIAL TIP: Raise RLIMIT_MEMLOCK to allow io_uring to register fixed buffers.
     * Without this, register_buffers will fail on most systems with default settings.
     */
    if (getrlimit(RLIMIT_MEMLOCK, &rlim) == 0) {
        rlim.rlim_cur = RLIM_INFINITY;
        rlim.rlim_max = RLIM_INFINITY;
        if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0) {
            log_warn("Failed to set RLIMIT_MEMLOCK to infinity, buffer registration might fail.");
        }
    }

    memset(&params, 0, sizeof(params));
    ctx->pending_sqes = 0;

    /* IORING_SETUP_COOP_TASKRUN: Optimizes CPU transitions (needs 5.19+)
     * IORING_SETUP_CQSIZE: Avoids CQ overflows if application is slow
     */
    params.flags |= IORING_SETUP_CQSIZE;
    params.cq_entries = entries * 2;

    // Initialize ring
    if (io_uring_queue_init_params(entries, &ctx->ring, &params) < 0) return -1;

    // 1. Fixed Buffers: Allocate page-aligned memory
    // Alignment is critical for io_uring performance
    if (posix_memalign(&ctx->buffer_base, 4096, IO_BUF_POOL_SIZE * IO_BUF_SIZE) != 0) {
        return -ENOMEM;
    }

    // 2. Prepare iovecs for registration
    for (int i = 0; i < IO_BUF_POOL_SIZE; i++) {
        ctx->iovecs[i].iov_base = (char *)ctx->buffer_base + (i * IO_BUF_SIZE);
        ctx->iovecs[i].iov_len = IO_BUF_SIZE;
    }

    // 3. Register buffers with the kernel
    // After this, kernel 'knows' this memory, avoiding repeated mapping
    if (io_uring_register_buffers(&ctx->ring, ctx->iovecs, IO_BUF_POOL_SIZE) < 0) {
        log_error("io_uring_register_buffers");
        return -1;
    }

    return 0;
}

/**
 * vpn_iouring_submit_read - Prepare and submit an asynchronous read.
 */
int vpn_iouring_submit_read(vpn_iouring_ctx_t *ctx, int fd, int buf_idx, vpn_io_data_t *io_data) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    
    /* Handle SQ overflow by forcing a submission to free up slots */
    if (!sqe) {
        io_uring_submit(&ctx->ring);
        sqe = io_uring_get_sqe(&ctx->ring);
        if (!sqe) return -EBUSY;
    }

    io_data->fd = fd;
    io_data->buf_idx = buf_idx;

    /* Prepare a fixed-buffer read to avoid page table overhead */
    io_uring_prep_read_fixed(sqe, fd, ctx->iovecs[buf_idx].iov_base, 
                             ctx->iovecs[buf_idx].iov_len, 0, buf_idx);
    
    io_uring_sqe_set_data(sqe, io_data);
    
    /* Batching: Only enter kernel when threshold is met to reduce syscall overhead */
    if (++ctx->pending_sqes >= IO_MAX_BATCH_SIZE) {
        int ret = io_uring_submit(&ctx->ring);
        ctx->pending_sqes = 0;
        if (ret < 0) return ret;
    }

    return 0;
}

/**
 * vpn_iouring_submit_write - Prepare and submit an asynchronous write.
 */
int vpn_iouring_submit_write(vpn_iouring_ctx_t *ctx, int fd, int buf_idx, size_t len, vpn_io_data_t *io_data) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    
    if (!sqe) {
        io_uring_submit(&ctx->ring);
        sqe = io_uring_get_sqe(&ctx->ring);
        if (!sqe) return -EBUSY;
    }

    io_data->fd = fd;
    io_data->buf_idx = buf_idx;
    io_data->buf_len = len;

    /* Perform Zero-copy write directly from the registered memory pool */
    io_uring_prep_write_fixed(sqe, fd, ctx->iovecs[buf_idx].iov_base, len, 0, buf_idx);
    
    io_uring_sqe_set_data(sqe, io_data);
    
    if (++ctx->pending_sqes >= IO_MAX_BATCH_SIZE) {
        int ret = io_uring_submit(&ctx->ring);
        ctx->pending_sqes = 0;
        if (ret < 0) return ret;
    }

    return 0;
}

int vpn_iouring_submit_recvmsg(vpn_iouring_ctx_t *ctx, int fd, int buf_idx, vpn_io_data_t *io_data) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
        io_uring_submit(&ctx->ring);
        sqe = io_uring_get_sqe(&ctx->ring);
        if (!sqe) return -EBUSY;
    }

    io_data->fd = fd;
    io_data->buf_idx = buf_idx;
    io_data->type = IO_TYPE_SOCK_READ;

    /* 初始化用于 recvmsg 的元数据 */
    io_data->udp_meta.iov.iov_base = ctx->iovecs[buf_idx].iov_base;
    io_data->udp_meta.iov.iov_len = ctx->iovecs[buf_idx].iov_len;
    
    memset(&io_data->udp_meta.msg, 0, sizeof(struct msghdr));
    io_data->udp_meta.msg.msg_name = &io_data->udp_meta.client_addr;
    io_data->udp_meta.msg.msg_namelen = sizeof(struct sockaddr_in);
    io_data->udp_meta.msg.msg_iov = &io_data->udp_meta.iov;
    io_data->udp_meta.msg.msg_iovlen = 1;

    /* 关键：使用 prep_recvmsg 而不是 read_fixed */
    io_uring_prep_recvmsg(sqe, fd, &io_data->udp_meta.msg, 0);
    io_uring_sqe_set_data(sqe, io_data);

    if (++ctx->pending_sqes >= IO_MAX_BATCH_SIZE) {
        io_uring_submit(&ctx->ring);
        ctx->pending_sqes = 0;
    }
    return 0;
}

void vpn_iouring_destroy(vpn_iouring_ctx_t *ctx) {
    if (ctx) {
        /* Unregister buffers before closing the ring */
        io_uring_unregister_buffers(&ctx->ring);
        io_uring_queue_exit(&ctx->ring);
        
        /* Free the aligned memory base */
        if (ctx->buffer_base) {
            free(ctx->buffer_base);
            ctx->buffer_base = NULL;
        }
    }
}

void vpn_iouring_flush(vpn_iouring_ctx_t *ctx) {
    if (ctx->pending_sqes > 0) {
        io_uring_submit(&ctx->ring);
        ctx->pending_sqes = 0;
    }
}