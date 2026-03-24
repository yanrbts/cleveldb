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
#include "utils.h"
#include "protocol.h"
#include "iouring.h"
#include "crypto.h"

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
     * IORING_SETUP_SQPOLL: Enables a dedicated kernel thread to poll the SQ ring.
     * This eliminates the need for the application to perform the io_uring_enter() 
     * system call to submit tasks, significantly reducing context switches.
     */
    params.flags |= IORING_SETUP_CQSIZE | IORING_SETUP_SQPOLL;
    params.cq_entries = entries * 2;

    /* sq_thread_idle: Defines the time (in ms) the kernel thread stays active 
     * without new tasks before going to sleep. 2000ms is a balanced value.
     */
    params.sq_thread_idle = 2000;

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
 * vpn_submit_udp_recvmsg - Submits an asynchronous UDP recvmsg request.
 * * INDUSTRIAL-GRADE OPTIMIZATIONS:
 * 1. ZERO-COPY: Directly uses the fixed buffer registered in iovecs[buf_idx].
 * 2. SELF-CONTAINED: Automatically configures msghdr for peer address discovery (essential for UDP).
 * 3. BATCHED: Respects the pending SQE threshold to minimize syscall overhead.
 */
int vpn_submit_udp_recvmsg(vpn_iouring_ctx_t *ctx, int fd, int buf_idx, vpn_io_data_t *io_data) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    
    /* 1. Ensure SQE availability by flushing if necessary */
    if (unlikely(!sqe)) {
        io_uring_submit(&ctx->ring);
        sqe = io_uring_get_sqe(&ctx->ring);
        if (!sqe) return -EBUSY;
    }

    /* 2. Setup IO metadata for CQE tracking */
    io_data->fd = fd;
    io_data->buf_idx = buf_idx;
    io_data->buf_len = ctx->iovecs[buf_idx].iov_len;
    io_data->type = IO_TYPE_SOCK_READ;

    /* 3. Prepare iovec pointing to the FULL capacity of the fixed buffer.
     * Unlike TUN_READ, SOCK_READ (UDP) starts from the very beginning (Base) 
     * because the incoming data already contains the VFAST header.
     */
    io_data->udp_meta.iov.iov_base = ctx->iovecs[buf_idx].iov_base;
    io_data->udp_meta.iov.iov_len  = ctx->iovecs[buf_idx].iov_len;

    /* 4. Prepare msghdr to capture the sender's (Client/Remote) IP and port.
     * This is critical for session mapping in a UDP-based VPN.
     */
    memset(&io_data->udp_meta.msg, 0, sizeof(struct msghdr));
    io_data->udp_meta.msg.msg_name    = &io_data->udp_meta.client_addr;
    io_data->udp_meta.msg.msg_namelen = sizeof(struct sockaddr_in);
    io_data->udp_meta.msg.msg_iov     = &io_data->udp_meta.iov;
    io_data->udp_meta.msg.msg_iovlen  = 1;

    /* 5. Prepare the recvmsg SQE.
     * Note: io_uring_prep_recvmsg is used instead of read_fixed because 
     * we need to retrieve the peer's address (msg_name).
     */
    io_uring_prep_recvmsg(sqe, fd, &io_data->udp_meta.msg, 0);
    io_uring_sqe_set_data(sqe, io_data);

    /* 6. Industrial Batch Submission Control */
    if (++ctx->pending_sqes >= IO_MAX_BATCH_SIZE) {
        io_uring_submit(&ctx->ring);
        ctx->pending_sqes = 0;
    }

    return 0;
}

/**
 * vpn_iouring_submit_sendmsg - Prepare and submit an asynchronous sendmsg.
 * This is required for unconnected UDP sockets so we can specify
 * the destination address per-packet.
 */
int vpn_submit_udp_sendmsg(vpn_iouring_ctx_t *ctx, int fd, int buf_idx, size_t len, vpn_io_data_t *io_data) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);

    if (!sqe) {
        io_uring_submit(&ctx->ring);
        sqe = io_uring_get_sqe(&ctx->ring);
        if (!sqe) return -EBUSY;
    }

    if (unlikely(len > IO_BUF_SIZE || len == 0)) {
        log_error("Invalid send length: %zu", len);
        return -EMSGSIZE;
    }

    io_data->fd = fd;
    io_data->buf_idx = buf_idx;
    io_data->buf_len = ctx->iovecs[buf_idx].iov_len;
    io_data->type = IO_TYPE_SOCK_WRITE;

    /* Setup iovec pointing to the fixed registered buffer base */
    io_data->udp_meta.iov.iov_base = ctx->iovecs[buf_idx].iov_base;
    io_data->udp_meta.iov.iov_len = len;

    /* Prepare msghdr to carry destination address */
    memset(&io_data->udp_meta.msg, 0, sizeof(struct msghdr));
    io_data->udp_meta.msg.msg_name = &io_data->udp_meta.client_addr;
    io_data->udp_meta.msg.msg_namelen = sizeof(struct sockaddr_in);
    io_data->udp_meta.msg.msg_iov = &io_data->udp_meta.iov;
    io_data->udp_meta.msg.msg_iovlen = 1;

    /* Use sendmsg so we can provide per-packet destination */
    io_uring_prep_sendmsg(sqe, fd, &io_data->udp_meta.msg, 0);
    io_uring_sqe_set_data(sqe, io_data);

    if (++ctx->pending_sqes >= IO_MAX_BATCH_SIZE) {
        io_uring_submit(&ctx->ring);
        ctx->pending_sqes = 0;
    }
    return 0;
}

int vpn_submit_udp_send(vpn_iouring_ctx_t *ctx, int fd, int buf_idx, size_t len, vpn_io_data_t *io_data) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (unlikely(!sqe)) {
        io_uring_submit(&ctx->ring);
        sqe = io_uring_get_sqe(&ctx->ring);
        if (!sqe) return -EBUSY;
    }

    /* Defensive validation: prevent submitting a write larger than the fixed buffer.
     * Without this check, io_uring_prep_write_fixed may later fail and produce a
     * negative completion result (e.g., -EMSGSIZE), which surfaces as I/O errors.
     */
    if (unlikely(len > IO_BUF_SIZE || len == 0)) {
        log_error("Invalid send length (write): %zu", len);
        return -EMSGSIZE;
    }

    /* 3. Asynchronous Submission to io_uring
     * Prepare the state machine for the next stage (Transmission Completion). */
    io_data->type = IO_TYPE_SOCK_WRITE;
    io_data->buf_idx = buf_idx;
    io_data->buf_len = ctx->iovecs[buf_idx].iov_len;
    io_data->fd = fd;

    uint8_t *base = (uint8_t *)ctx->iovecs[buf_idx].iov_base;
    /* 4. Prepare Fixed Buffer Write
     * io_uring_prep_write_fixed provides the highest throughput by avoiding 
     * repetitive page mapping and kernel-to-user memory pinning. */
    io_uring_prep_write_fixed(sqe, fd, base, (unsigned)len, 0, buf_idx);
    /* Re-attach metadata to the SQE for context recovery in the completion loop. */
    io_uring_sqe_set_data(sqe, io_data);

    return 0;
}

/**
 * vpn_iouring_destroy - Cleanly decommission the io_uring instance and resources.
 * @ctx: Pointer to the vpn_iouring_ctx_t structure.
 *
 * This function follows the "Exit-First" paradigm for io_uring teardown.
 */
void vpn_iouring_destroy(vpn_iouring_ctx_t *ctx) {
    /* Guard against NULL context or already closed rings */
    if (!ctx || ctx->ring.ring_fd <= 0) {
        return;
    }

    /* CRITICAL IMPROVEMENT: Skip manual unregistration of buffers and files.
     *
     * Calling io_uring_unregister_buffers/files manually while I/O requests 
     * are still in-flight (e.g., blocked on a TUN device or Socket) can cause 
     * the thread to hang in an uninterruptible sleep (D-state) as the kernel 
     * waits indefinitely for the refcount to drop to zero.
     *
     * By calling io_uring_queue_exit() directly:
     * 1. It automatically triggers the teardown of the SQPOLL kernel thread (if active).
     * 2. It handles the unregistration of all pinned memory and fixed files 
     * internally as part of the ring's quiescence process.
     * 3. It safely reclaims the SQ/CQ ring memory.
     */
    io_uring_queue_exit(&ctx->ring);
    
    /* Mark the ring FD as invalid to prevent double-free or accidental reuse */
    ctx->ring.ring_fd = -1;

    /* Now that the kernel has completely released the 'pinned' memory pages 
     * associated with the ring, it is safe to free the aligned buffer base 
     * without risking a kernel-level memory access violation.
     */
    if (ctx->buffer_base) {
        free(ctx->buffer_base);
        ctx->buffer_base = NULL;
    }

    log_info("io_uring resources released by kernel.");
}

void vpn_iouring_flush(vpn_iouring_ctx_t *ctx) {
    if (ctx->pending_sqes > 0) {
        io_uring_submit(&ctx->ring);
        ctx->pending_sqes = 0;
    }
}

/**
 * Unified TUN Read Implementation.
 * In a professional VPN, we ALWAYS leave space (headroom) for the protocol header
 * during the initial READ. This prevents using memmove() later for encapsulation.
 */
int vpn_submit_tun_read(vpn_iouring_ctx_t *ctx, int tun_fd, int buf_idx, vpn_io_data_t *d) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (unlikely(!sqe)) {
        io_uring_submit(&ctx->ring);
        sqe = io_uring_get_sqe(&ctx->ring);
        if (!sqe) return -EBUSY;
    }

    /* * OFFSET LOGIC: 
     * We point the kernel to start writing at (base + 8).
     * This leaves the first 8 bytes (VPN_TNL_HLEN) empty for the VFAST Header.
     */
    uint8_t *target_ptr = (uint8_t *)ctx->iovecs[buf_idx].iov_base + VPN_TNL_HLEN;
    size_t target_len = ctx->iovecs[buf_idx].iov_len - VPN_TNL_HLEN;

    d->type = IO_TYPE_TUN_READ;
    d->buf_idx = buf_idx;
    d->fd = tun_fd;
    d->buf_len = ctx->iovecs[buf_idx].iov_len;
    
    /* Use read_fixed for maximum performance with pre-registered buffers */
    io_uring_prep_read_fixed(sqe, tun_fd, target_ptr, target_len, 0, buf_idx);
    io_uring_sqe_set_data(sqe, d);
    
    return 0;
}

/**
 * vpn_submit_tun_write - Submits a TUN write request with automatic offset calculation.
 * @param ctx     : The io_uring context containing registered buffers.
 * @param tun_fd  : File descriptor for the TUN device.
 * @param buf_idx : The index of the pre-registered fixed buffer.
 * @param d       : User data for state tracking.
 * * NOTE: This function automatically skips the VFAST header (VPN_TNL_HLEN).
 */
int vpn_submit_tun_write(vpn_iouring_ctx_t *ctx, int tun_fd, int buf_idx, vpn_io_data_t *d) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    
    if (unlikely(!sqe)) {
        io_uring_submit(&ctx->ring);
        sqe = io_uring_get_sqe(&ctx->ring);
        if (!sqe) return -EBUSY;
    }

    /* 2. AUTOMATIC OFFSET CALCULATION
     * We know the IP packet starts right after the VFAST header (VPN_TNL_HLEN = 8).
     * By using ctx->iovecs[buf_idx].iov_base, we get the absolute start of the buffer.
     */
    uint8_t *target_ptr = (uint8_t *)ctx->iovecs[buf_idx].iov_base + VPN_TNL_HLEN;
    size_t target_len = ctx->iovecs[buf_idx].iov_len - VPN_TNL_HLEN;

    /* 1. Set operation metadata */
    d->type = IO_TYPE_TUN_WRITE;
    d->buf_idx = buf_idx;
    d->fd = tun_fd;
    d->buf_len = ctx->iovecs[buf_idx].iov_len;

    /* 3. Prepare fixed write using the calculated internal pointer.
     * The kernel validates that target_ptr is within the buffer registered at buf_idx.
     */
    io_uring_prep_write_fixed(sqe, tun_fd, target_ptr, target_len, 0, buf_idx);
    
    io_uring_sqe_set_data(sqe, d);

    /* 4. Batch submission logic */
    if (++ctx->pending_sqes >= IO_MAX_BATCH_SIZE) {
        io_uring_submit(&ctx->ring);
        ctx->pending_sqes = 0;
    }

    return 0;
}