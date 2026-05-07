/**
 * @file io.c
 * @brief High-performance asynchronous I/O engine powered by io_uring.
 * This module implements a zero-copy-oriented task pool with fixed-file 
 * registration and batch submission thresholds to minimize syscall overhead.
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <linux/errqueue.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "protocol.h"
#include "utils.h"
#include "log.h"
#include "zmalloc.h"
#include "io.h"
#include "cmdengine.h"

/**
 * @brief Thread-safe acquisition of an available task from the instance's private pool.
 * This function implements a Lock-Free "Round-Robin" search using Atomic CAS (Compare-And-Swap).
 * It ensures that a task buffer currently owned by the kernel (in_use == true) is never 
 * overwritten, preventing memory corruption and race conditions.
 * @param io Pointer to the specific I/O instance (Data or Control plane).
 * @return Pointer to an available vf_task_t, or NULL if the pool is fully saturated.
 */
static vf_task_t* get_task_from_instance(vf_io_t *io) {
    /* Limit the search to the pool size to avoid infinite loops.
     * We attempt to find at least one free slot among all pre-allocated tasks.
     */
    for (int i = 0; i < io->pool_size; i++) {
        /* Atomically increment the pool index and wrap around.
         * This provides a simple load-balancing (Round-Robin) across the buffer pool.
         */
        int idx = atomic_fetch_add(&io->pool_idx, 1) % io->pool_size;
        vf_task_t* task = &io->task_pool[idx];
        
        /**
         * CRITICAL SECTION: Atomic Ownership Acquisition.
         * We only take the task if 'in_use' is false. 
         * atomic_compare_exchange_strong performs the following atomically:
         * 1. Check if task->in_use is equal to 'expected' (false).
         * 2. If true, set task->in_use to true and return 1 (Success).
         * 3. If false (meaning the kernel still owns the buffer), do nothing and return 0.
         */
        bool expected = false;
        if (atomic_compare_exchange_strong(&task->in_use, &expected, true)) {
            /* Ownership successfully transferred to the current thread.
             * Reset task metadata before preparing the next I/O operation.
             */
            task->op = 0;
            return task;
        }

        /* If CAS failed, the slot is busy. 
         * Continue to the next index to find an available buffer.
         */
    }

    /**
     * BACKPRESSURE: All tasks in this instance's pool are currently in-flight.
     * The caller must handle this (e.g., drop the packet or retry later).
     */
    return NULL; 
}

/**
 * @brief Professional Path MTU Discovery (PMTUD) Handler
 * Optimized for memory alignment, dual-stack support, and kernel compliance.
 */
void vfast_check_icmp_errors(vf_io_t *io, int udp_fd) {
    if (unlikely(!io || udp_fd < 0)) return;

    /* 1. Use a union to guarantee alignment for CMSG macros.
     * CMSG_SPACE ensures sufficient padding for the structures.
     */
    union {
        struct cmsghdr cm;
        char buf[CMSG_SPACE(sizeof(struct sock_extended_err)) + 
                 CMSG_SPACE(sizeof(struct sockaddr_in6))];
    } cmsg_un;

    struct iovec iov;
    uint8_t dummy[1];
    struct msghdr msg;
    struct sockaddr_in6 target_addr;

    /* Initialize persistent iov */
    iov.iov_base = dummy;
    iov.iov_len  = sizeof(dummy);

    /* 2. The loop must reset control buffer lengths 
     * because recvmsg() modifies msg_controllen on every call.
     */
    while (true) {
        memset(&msg, 0, sizeof(msg));
        msg.msg_name       = &target_addr;
        msg.msg_namelen    = sizeof(target_addr);
        msg.msg_iov        = &iov;
        msg.msg_iovlen     = 1;
        msg.msg_control    = cmsg_un.buf;
        msg.msg_controllen = sizeof(cmsg_un.buf);

        ssize_t res = recvmsg(udp_fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
        if (res < 0) {
            /* EAGAIN/EWOULDBLOCK means the error queue is drained */
            break; 
        }

        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            bool is_v4_err = (cmsg->cmsg_level == IPPROTO_IP   && cmsg->cmsg_type == IP_RECVERR);
            bool is_v6_err = (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_RECVERR);

            if (is_v4_err || is_v6_err) {
                struct sock_extended_err *ee = (struct sock_extended_err *)CMSG_DATA(cmsg);
                uint32_t mtu = ee->ee_info;

                /* Validate origin and type for PMTU Discovery */
                bool is_icmp_mtu = false;

                if (ee->ee_origin == SO_EE_ORIGIN_ICMP) {
                    if (ee->ee_type == ICMP_DEST_UNREACH && ee->ee_code == ICMP_FRAG_NEEDED)
                        is_icmp_mtu = true;
                } else if (ee->ee_origin == SO_EE_ORIGIN_ICMP6) {
                    if (ee->ee_type == ICMP6_PACKET_TOO_BIG)
                        is_icmp_mtu = true;
                } else if (ee->ee_origin == SO_EE_ORIGIN_LOCAL && ee->ee_errno == EMSGSIZE) {
                    is_icmp_mtu = true;
                }

                if (is_icmp_mtu && mtu > 0) {
                    /* Trigger Callback */
                    if (io->pmtud_cb) {
                        io->pmtud_cb(mtu, io->pmtud_arg);
                    }

                    const char *origin = (ee->ee_origin == SO_EE_ORIGIN_LOCAL) ? "LOCAL" : 
                                         (is_v4_err ? "ICMPv4" : "ICMPv6");
                    log_info("PMTUD: Path MTU identified as %u bytes via %s", mtu, origin);
                }
            }
        }
    }
}

/**
 * @brief Initializes the io_uring instance and registers fixed files.
 */
int vf_io_init(vf_io_t *io, int udp_fd, int tun_fd, int pool_size, int io_ring_depth, vf_ops_t ops) {
    io->udp_fd = udp_fd;
    io->tun_fd = tun_fd;
    io->ops    = ops;
    io->pool_size = pool_size;
    io->io_ring_depth = io_ring_depth;

    /* Initialize io_uring with default parameters */
    // io->task_pool = zcalloc(pool_size * sizeof(vf_task_t));
    // if (!io->task_pool) return -1;

    /* MEMORY ALIGNMENT: 
     * Fixed buffers require page-aligned memory for the kernel to effectively 
     * pin the physical pages and map them into the async I/O context.
     * _SC_PAGESIZE ensures the pool starts at a hardware-friendly boundary.
     */
    size_t pool_bytes = pool_size * sizeof(vf_task_t);
    if (posix_memalign((void**)&io->task_pool, sysconf(_SC_PAGESIZE), pool_bytes) != 0) {
        return -1;
    }
    memset(io->task_pool, 0, pool_bytes);

    int ret = io_uring_queue_init(io_ring_depth, &io->ring, 0);
    if (ret < 0) {
        free(io->task_pool);
        return ret;
    }

    /* IORING_REGISTER_BUFFERS:
     * By registering the entire task pool, we perform a one-time translation 
     * from virtual to physical addresses. This eliminates the per-I/O overhead 
     * of page mapping and pinning (get_user_pages).
     * NOTE: This will fail if 'RLIMIT_MEMLOCK' is too low.
     */
    struct iovec iov = {
        .iov_base = io->task_pool,
        .iov_len  = pool_bytes
    };
    ret = io_uring_register_buffers(&io->ring, &iov, 1);
    if (ret < 0) {
        /* Fallback: Log warning but continue; fixed-buffer operations 
         * will fail back to normal buffers or must be handled at the submission level. 
         */
        log_warn("io_uring_register_buffers failed: %s (Check MEMLOCK ulimit)", strerror(-ret));
    }

    /* IORING_REGISTER_FILES:
     * Registers FDs to bypass the kernel's file table lookup for every I/O.
     * This reduces lock contention on the process file descriptor table.
     */
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
void vf_io_read(vf_io_t *io, int fd, int op) {
    /* 1. Acquire a task from the pre-allocated pool to ensure memory reuse */
    vf_task_t *task = get_task_from_instance(io);
    if (unlikely(!task)) {
        return;
    }

    /* 2. Obtain a Submission Queue Entry (SQE) from the ring */
    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (unlikely(!sqe)) {
        atomic_store(&task->in_use, false); /* Release task if SQE acquisition fails */
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
 * @brief High-performance Zero-Copy write submission.
 * [PRECONDITION]: This function assumes that 'data' ALWAYS originates from the 
 * internal task_pool. This allows for a direct pointer-to-task resolution 
 * without expensive memory range checks or memcpy operations.
 *
 * @param io   The I/O instance handle (supporting instance-level isolation).
 * @param fd   Raw file descriptor (mapped to registered file index).
 * @param op   Operation type: OP_TUN_WRITE or OP_UDP_SEND.
 * @param data Pointer to the payload (usually task->buf or offsetted payload).
 * @param len  Length of data to be transmitted.
 * @param dest Destination address (used for UDP; ignored for TUN).
 */
void vf_io_write(vf_io_t *io, int fd, int op, uint8_t *data, int len, struct sockaddr_in *dest) {
    /**
     * Reconstruct the vf_task_t pointer from the data buffer address.
     * Since 'data' is guaranteed to be a member of the task pool, we calculate
     * the task's base address using the fixed offset of the 'buf' member.
     */
    vf_task_t *task = vfast_data_to_task(data);

    /* Acquire a Submission Queue Entry (SQE) from the instance's ring */
    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (unlikely(!sqe)) {
        /**
         * BACKPRESSURE: If the SQ is full, we must release the task ownership.
         * Failing to reset 'in_use' here would cause a permanent leak in the pool.
         */
        atomic_store(&task->in_use, false);
        return;
    }

    task->op = op;
    /* Map FD to registered file index: UDP is 0, TUN is 1 */
    int f_idx = (fd == io->udp_fd) ? 0 : 1;

    if (op == OP_UDP_SEND) {
        /**
         * UDP Asynchronous Send:
         * We point the iovec directly to the provided 'data' pointer, allowing 
         * for zero-copy transmission of encapsulated payloads with protocol headers.
         */
        task->iov.iov_base = data; 
        task->iov.iov_len  = (size_t)len;
        task->addr_len = sizeof(struct sockaddr_in);
        task->addr = *dest;
        task->msg.msg_name = &task->addr;
        task->msg.msg_namelen = task->addr_len;
        task->msg.msg_iov  = &task->iov;
        task->msg.msg_iovlen = 1;
        io_uring_prep_sendmsg(sqe, f_idx, &task->msg, 0);
    } else {
        /**
         * TUN Asynchronous Write:
         * Direct write to the character device using the task's internal buffer.
         */
        io_uring_prep_write(sqe, f_idx, data, (unsigned)len, 0);
    }

    /* Optimization: Use registered files to bypass kernel file table lookups */
    sqe->flags |= IOSQE_FIXED_FILE;
    
    /* Attach the task as user_data for retrieval in the completion loop */
    io_uring_sqe_set_data(sqe, task);

    /**
     * Strategic Batching:
     * Control plane instances (small pools) favor low latency (immediate submit).
     * Data plane instances (large pools) utilize thresholds to minimize syscall overhead.
     */
    if (io->pool_size <= 64) {
        io_uring_submit(&io->ring);
    } else {
        static __thread int pending = 0;
        if (++pending >= 8) { /* SUBMIT_THRESHOLD */
            io_uring_submit(&io->ring);
            pending = 0;
        }
    }
}

/**
 * @brief Submits a raw buffer for asynchronous transmission, bypassing the task pool.
 * @note The 'data' buffer must remain valid until the CQE is reaped (e.g., session member).
 */
void vf_io_raw(vf_io_t *io, int fd, void *data, size_t len, struct sockaddr_in *dst) {
    if (unlikely(!io || !data || len == 0)) return;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    
    /* Handle SQ saturation: in a high-load scenario, we must flush and retry */
    if (unlikely(!sqe)) {
        io_uring_submit(&io->ring);
        sqe = io_uring_get_sqe(&io->ring);
        if (!sqe) return; // Drop if still full (Backpressure)
    }

    /* Map FD to registered fixed-file index: UDP=0, TUN=1 */
    int f_idx = (fd == io->udp_fd) ? 0 : 1;

    /**
     * Set user_data to NULL to flag this as a 'RAW' operation.
     * The completion loop must skip ownership release for NULL tasks.
     */
    io_uring_sqe_set_data(sqe, NULL);

    /* Prepare asynchronous sendto */
    io_uring_prep_sendto(sqe, f_idx, data, (unsigned)len, 0,
                         (struct sockaddr *)dst, sizeof(struct sockaddr_in));

    /* Optimization: Use registered files and trigger immediate submission 
     * for control messages to ensure low-latency delivery. 
     */
    sqe->flags |= IOSQE_FIXED_FILE;
    
    /**
     * For control packets (Probes/ACKs), we bypass the batching threshold 
     * to avoid delay, ensuring heartbeat precision.
     */
    io_uring_submit(&io->ring);
}

static inline void vf_monitor_pool_status(vf_io_t *io) {
    int tun_read = 0, udp_recv = 0, tun_write = 0, udp_send = 0, unknown = 0;
    int pool_size = io->pool_size;
    vf_task_t *pool = io->task_pool;

    for (int i = 0; i < pool_size; i++) {
        if (__atomic_load_n(&pool[i].in_use, __ATOMIC_RELAXED)) {
            switch(pool[i].op) {
                case OP_TUN_READ: tun_read++; break;
                case OP_UDP_RECV: udp_recv++; break;
                case OP_TUN_WRITE: tun_write++; break;
                case OP_UDP_SEND: udp_send++; break;
                default: unknown++; break;
            }
        }
    }
    int total_busy = tun_read + udp_recv + tun_write + udp_send + unknown;
    cmd_task_pool_set(pool_size, total_busy, tun_read, udp_recv, tun_write, udp_send);
    // printf("\r[POOL] R_TUN:%d R_UDP:%d | W_TUN:%d W_UDP:%d | UNK:%d | TOTAL_BUSY:%d/%d",
    //         tun_read, udp_recv, tun_write, udp_send, unknown, 
    //         (tun_read+udp_recv+tun_write+udp_send+unknown), pool_size);
    // fflush(stdout);
}

/**
 * @brief Main event loop for processing completions.
 */
void vf_io_run(vf_io_t *io) {
    struct io_uring_cqe *cqe;
    unsigned head;
    uint32_t count = 0;

    atomic_store(&io->running, true);
    uint64_t last_tick_ms = vf_now_ms();
    uint64_t last_stat_ms = 0;

    /* Initial Pipeline Warm-up */
    for (int i = 0; i < 16; i++) {
        vf_io_read(io, io->tun_fd, OP_TUN_READ);
        vf_io_read(io, io->udp_fd, OP_UDP_RECV);
    }
    io_uring_submit(&io->ring);

    /* We set a 100ms wait timeout. 
     * This ensures the loop wakes up even if there is no network traffic,
     * allowing the timer callback to trigger with 100ms precision.
     */
    struct __kernel_timespec ts = {
        .tv_sec = 0, 
        .tv_nsec = 100000000 /* 100ms */
    };

    while (atomic_load(&io->running)) {
        /* Blocking wait for at least one completion event */
        
        int ret = io_uring_wait_cqe_timeout(&io->ring, &cqe, &ts);
        // int ret = io_uring_wait_cqe(&io->ring, &cqe);

        /* --- TICK PROCESSING SECTION --- */
        uint64_t now = vf_now_ms();

        if (io->pmtud_cb && (now - io->last_pmtud_check_ms >= 1000)) {
            vfast_check_icmp_errors(io, io->udp_fd);
            io->last_pmtud_check_ms = now;
        }

        if (io->timer_cb && io->timer_interval_ms > 0) {
            if (now - last_tick_ms >= io->timer_interval_ms) {
                /* Execute injected business logic (e.g., Session Maintenance) */
                io->timer_cb(io, io->timer_arg);
                last_tick_ms = now;
            }
        }

        /* --- I/O PROCESSING SECTION --- */
        if (ret < 0) {
            if (ret == -ETIME || ret == -EINTR) continue;
            log_error("Fatal: io_uring_wait_cqe failed: %s\n", strerror(-ret));
            break; 
        }

        count = 0;
        /* Batch process all available CQEs in the ring */
        io_uring_for_each_cqe(&io->ring, head, cqe) {
            count++;
            vf_task_t *task = (vf_task_t *)io_uring_cqe_get_data(cqe);
            if (!task) continue;

            int res = cqe->res;
            vf_task_state_t st;

            if (res >= 0) {
                switch (task->op) {
                    case OP_TUN_READ:
                        uint8_t *tun_data = task->buf + VPN_TNL_HLEN;
                        st = io->ops.on_tun_data(io, tun_data, res, &task->addr, io->ops.ctx);
                        vf_io_read(io, io->tun_fd, OP_TUN_READ);
                        break;
                    case OP_UDP_RECV:
                        st = io->ops.on_udp_data(io, task->buf, res, &task->addr, io->ops.ctx);
                        vf_io_read(io, io->udp_fd, OP_UDP_RECV);
                        break;
                    default: /* Write/Send completion */
                        st = IO_TASK_DONE;
                        break;
                }
            } else {
                /* Error Handling: Recover and maintain pipeline depth */
                if (res != -EAGAIN && res != -EINTR) {
                    log_error("CQE Error: op=%d, res=%d (%s)", task->op, res, strerror(-res));
                }

                /* Re-submit read tasks to prevent pipeline starvation */
                if (task->op == OP_TUN_READ || task->op == OP_UDP_RECV) {
                    vf_io_read(io, (task->op == OP_TUN_READ) ? io->tun_fd : io->udp_fd, task->op);
                }
                st = IO_TASK_DONE;
            }
           /* RELEASE OWNERSHIP: 
            * We mark the task as not in use BEFORE invoking the callback.
            * This allows the business logic (ops) to immediately reuse this 
            * buffer or borrow a new one for outbound responses (Zero-Copy).
            */
            if (st == IO_TASK_DONE) atomic_store(&task->in_use, false);
        }

        if (count > 0) {
            io_uring_cq_advance(&io->ring, count);
            io_uring_submit(&io->ring); /* Flush any pending SQEs from the threshold logic */
        }

        if (now - last_stat_ms >= 1000) {
            vf_monitor_pool_status(io); 
            last_stat_ms = now;
        }
    }
}

/**
 * @brief Cleanly releases io_uring resources and unregisters files.
 */
void vf_io_exit(vf_io_t *io) {
    if (!io) return;

    if (io->udp_fd >= 0) close(io->udp_fd);
    if (io->tun_fd >= 0) close(io->tun_fd);

    // io_uring_unregister_files(&io->ring);
    io_uring_queue_exit(&io->ring);
    
    /* CRITICAL: Free the dynamically allocated private task pool.
     * This was allocated during vf_io_init via calloc.
     */
    if (io->task_pool) {
        free(io->task_pool);
        io->task_pool = NULL;
    }
    log_info("vfast_io resources released successfully.");
}

vf_task_t* vf_io_task(vf_io_t *io) {
    if (unlikely(!io)) return NULL;
    return get_task_from_instance(io);
}

/**
 * @brief Configures a periodic timer callback for the I/O event loop.
 * @details 
 * This implements the Dependency Injection pattern, allowing the I/O core 
 * to trigger external logic (like session maintenance) without having 
 * a direct compile-time dependency on those modules.
 * @param io       Pointer to the initialized vf_io_t context.
 * @param ms       Interval in milliseconds. If 0, the timer is disabled.
 * @param cb       The callback function to execute on every tick.
 * @param arg      User-defined context passed back to the callback.
 */
void vf_io_set_timer(vf_io_t *io, uint32_t ms, on_timer_cb cb, void *arg) {
    if (unlikely(!io)) {
        return;
    }

    /* Thread-safe assignment if called during initialization or reconfiguration */
    io->timer_cb = cb;
    io->timer_arg = arg;
    io->timer_interval_ms = ms;

    if (cb && ms > 0) {
        log_info("IO: Timer registered at %u ms interval.", ms);
    } else {
        log_info("IO: Timer disabled.");
    }
}

void vf_io_set_pmtud_callback(vf_io_t *io, on_pmtud_cb cb, void *arg) {
    if (unlikely(!io)) {
        return;
    }

    io->pmtud_cb = cb;
    io->pmtud_arg = arg;
    io->last_pmtud_check_ms = 0; /* Reset the last check timestamp */

    if (cb) {
        log_info("IO: PMTUD callback registered.");
    } else {
        log_info("IO: PMTUD callback disabled.");
    }
}