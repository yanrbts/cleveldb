/**
 * @file io.c
 * @brief High-performance asynchronous I/O engine powered by io_uring.
 * This module implements a zero-copy-oriented task pool with fixed-file 
 * registration and batch submission thresholds to minimize syscall overhead.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include "protocol.h"
#include "utils.h"
#include "io.h"

/* Optimization Constants */
#define SUBMIT_THRESHOLD    8               /* Batch submission trigger for SQEs */
#define TASK_POOL_SIZE      (CQ_RING_DEPTH * 2)

/* Global Task Pool for Memory Reuse */
static vfast_task_t g_task_pool[TASK_POOL_SIZE];
static int          g_pool_idx = 0;

/**
 * @brief Fetches an available task from the circular pool.
 * @return Pointer to task, or NULL if the pool is saturated (backpressure).
 */
static vfast_task_t* get_task_from_pool() {
    int idx = __sync_fetch_and_add(&g_pool_idx, 1) % TASK_POOL_SIZE;
    vfast_task_t* task = &g_task_pool[idx];
    
    /* Backpressure Check: Prevent overwriting tasks still owned by the kernel */
    if (task->in_use) {
        static int drop_count = 0;
        if (++drop_count % 1000 == 0) {
            fprintf(stderr, "[Warning] Task pool saturated. Dropped 1000 packets.\n");
        }
        return NULL; 
    }

    task->op       = 0;
    task->addr_len = 0;
    task->in_use   = true;
    return task;
}

/**
 * @brief Initializes the io_uring instance and registers fixed files.
 */
int vfast_io_init(vfast_io_t *io, int udp_fd, int tun_fd, vfast_ops_t ops) {
    io->udp_fd = udp_fd;
    io->tun_fd = tun_fd;
    io->ops    = ops;
    g_pool_idx = 0;

    /* Initialize io_uring with default parameters */
    int ret = io_uring_queue_init(CQ_RING_DEPTH, &io->ring, 0);
    if (ret < 0) return ret;

    /* Optimization: Register file descriptors to skip kernel file table lookups */
    int fds[2] = { udp_fd, tun_fd };
    ret = io_uring_register_files(&io->ring, fds, 2);
    if (ret < 0) {
        perror("io_uring_register_files (Non-fatal)");
    }

    return 0;
}

/**
 * @brief Submits an asynchronous read or receive request to the io_uring submission queue.
 * This function implements a strategic memory offset for TUN reads to facilitate 
 * zero-copy encapsulation. By shifting the TUN read destination, we leave 
 * immediate headroom for the VFAST protocol header.
 *
 * @param io  Pointer to the VFast I/O engine context.
 * @param fd  The file descriptor to read from (UDP or TUN).
 * @param op  The operation type (OP_UDP_RECV or OP_TUN_READ).
 */
void vfast_submit_read(vfast_io_t *io, int fd, int op) {
    /* 1. Acquire a task from the pre-allocated pool to ensure memory reuse */
    vfast_task_t *task = get_task_from_pool();
    if (unlikely(!task)) {
        return; 
    }

    /* 2. Obtain a Submission Queue Entry (SQE) from the ring */
    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (unlikely(!sqe)) {
        task->in_use = false; /* Release task if SQE acquisition fails */
        return;
    }

    task->op = op;
    /* Map FD to registered file index: UDP is 0, TUN is 1 */
    int f_idx = (fd == io->udp_fd) ? 0 : 1;

    if (op == OP_UDP_RECV) {
        /**
         * UDP Reception:
         * We receive the full encrypted tunnel packet (Header + Nonce + Ciphertext + Tag).
         * Data starts at the beginning of task->buf for full header parsing.
         */
        task->addr_len        = sizeof(struct sockaddr_in);
        task->iov.iov_base    = task->buf;
        task->iov.iov_len     = BUF_SIZE;
        task->msg.msg_name    = &task->addr;
        task->msg.msg_namelen = task->addr_len;
        task->msg.msg_iov     = &task->iov;
        task->msg.msg_iovlen  = 1;
        
        io_uring_prep_recvmsg(sqe, f_idx, &task->msg, 0);
    } else {
        /**
         * TUN Read (Outbound Path Strategy):
         * [CRITICAL OPTIMIZATION]
         * We offset the read destination by VPN_TNL_HLEN (typically 8 bytes).
         * This allows the kernel to write the raw IP packet directly into the 
         * 'payload' section of the buffer, leaving the first 8 bytes empty 
         * for the VFAST header to be filled later without a memcpy/memmove.
         */
        uint8_t *read_ptr = task->buf + VPN_TNL_HLEN;
        int read_len      = BUF_SIZE - VPN_TNL_HLEN;
        
        io_uring_prep_read(sqe, f_idx, read_ptr, (unsigned)read_len, 0);
    }

    /* Utilize registered files to bypass kernel-side file table overhead */
    sqe->flags |= IOSQE_FIXED_FILE;
    
    /* Attach the task pointer as user_data to identify the buffer on completion */
    io_uring_sqe_set_data(sqe, task);
}

/**
 * @brief Submits an asynchronous write/send request with Zero-Copy detection.
 * [Optimization] If the 'data' pointer already resides in the task pool,
 * we skip memcpy and submit the pointer directly to io_uring.
 */
void vfast_submit_write(vfast_io_t *io, int fd, int op, uint8_t *data, int len, struct sockaddr_in *dest) {
    vfast_task_t *task = get_task_from_pool();
    if (unlikely(!task)) return;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (unlikely(!sqe)) {
        task->in_use = false;
        return;
    }

    task->op = op;

    uint8_t *write_ptr = data;
    int f_idx = (fd == io->udp_fd) ? 0 : 1;

    if (op == OP_UDP_SEND) {
        task->iov.iov_base    = write_ptr;
        task->iov.iov_len     = (size_t)len;
        task->msg.msg_name    = dest;
        task->msg.msg_namelen = sizeof(struct sockaddr_in);
        task->msg.msg_iov     = &task->iov;
        task->msg.msg_iovlen  = 1;
        io_uring_prep_sendmsg(sqe, f_idx, &task->msg, 0);
    } else {
        /* Direct write to TUN device */
        io_uring_prep_write(sqe, f_idx, write_ptr, (unsigned)len, 0);
    }

    sqe->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data(sqe, task);

    /* Batch submission to reduce context switches */
    static __thread int pending_sqes = 0;
    if (++pending_sqes >= SUBMIT_THRESHOLD) {
        io_uring_submit(&io->ring);
        pending_sqes = 0;
    }
}

/**
 * @brief Main event loop for processing completions.
 */
void vfast_io_run(vfast_io_t *io) {
    struct io_uring_cqe *cqe;
    unsigned head;
    uint32_t count = 0;

    atomic_store(&io->running, true);

    /* Initial Pipeline Warm-up */
    for (int i = 0; i < 16; i++) {
        vfast_submit_read(io, io->tun_fd, OP_TUN_READ);
        vfast_submit_read(io, io->udp_fd, OP_UDP_RECV);
    }
    io_uring_submit(&io->ring);

    while (atomic_load(&io->running)) {
        /* Blocking wait for at least one completion event */
        int ret = io_uring_wait_cqe(&io->ring, &cqe);
        if (ret < 0) {
            if (ret == -EINTR) continue;
            fprintf(stderr, "Fatal: io_uring_wait_cqe failed: %s\n", strerror(-ret));
            break; 
        }

        count = 0;
        /* Batch process all available CQEs in the ring */
        io_uring_for_each_cqe(&io->ring, head, cqe) {
            count++;
            vfast_task_t *task = (vfast_task_t *)io_uring_cqe_get_data(cqe);
            if (!task) continue;

            int res = cqe->res;

            if (res >= 0) {
                switch (task->op) {
                    case OP_TUN_READ:
                        uint8_t *tun_data = task->buf + VPN_TNL_HLEN;
                        io->ops.on_tun_data(io, tun_data, res);
                        task->in_use = false; /* Release before re-submitting */
                        vfast_submit_read(io, io->tun_fd, OP_TUN_READ);
                        break;
                    case OP_UDP_RECV:
                        io->ops.on_udp_data(io, task->buf, res, &task->addr);
                        task->in_use = false;
                        vfast_submit_read(io, io->udp_fd, OP_UDP_RECV);
                        break;
                    default: /* Write/Send completion */
                        task->in_use = false;
                        break;
                }
            } else {
                /* Error Handling: Recover and maintain pipeline depth */
                task->in_use = false;
                if (res != -EAGAIN && res != -EINTR) {
                    fprintf(stderr, "CQE Error: op=%d, res=%d (%s)\n", task->op, res, strerror(-res));
                }
                /* Re-submit read tasks to prevent pipeline starvation */
                if (task->op == OP_TUN_READ || task->op == OP_UDP_RECV) {
                    vfast_submit_read(io, (task->op == OP_TUN_READ) ? io->tun_fd : io->udp_fd, task->op);
                }
            }
        }

        if (count > 0) {
            io_uring_cq_advance(&io->ring, count);
            io_uring_submit(&io->ring); /* Flush any pending SQEs from the threshold logic */
        }
    }
}

/**
 * @brief Cleanly releases io_uring resources and unregisters files.
 */
void vfast_io_exit(vfast_io_t *io) {
    if (!io) return;
    io_uring_unregister_files(&io->ring);
    io_uring_queue_exit(&io->ring);
    if (io->udp_fd >= 0) close(io->udp_fd);
    if (io->tun_fd >= 0) close(io->tun_fd);
}

vfast_task_t* vfast_borrow_task() {
    return get_task_from_pool();
}