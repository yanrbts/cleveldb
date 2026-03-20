/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * Description: Production-grade VFAST VPN Client Implementation.
 * Optimized for high-throughput I/O via io_uring and zero-copy packet handling.
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
#include "fsm.h"
#include "zmalloc.h"
#include "protocol.h"
#include "iouring.h"

/**
 * client_signal_handler - Graceful shutdown trigger.
 * Switches the global running state to false to allow clean resource release.
 */
static void client_signal_handler(int sig) {
    (void)sig;
    atomic_store(&vfastctx.running, false);
}

/**
 * handle_io_event - FSM Dispatcher for I/O Completion.
 * Refactored to eliminate 'goto' statements for better structured flow.
 */
static void handle_io_event(struct io_uring_cqe *cqe) {
    vpn_io_data_t *data = (vpn_io_data_t *)io_uring_cqe_get_data(cqe);

    if (unlikely(!data)) return;

    int res = cqe->res;
    int idx = data->buf_idx;
    data->sid = client_fsm.sid;

    /* Handle I/O errors (e.g., interface down, buffer overflow) */
    if (unlikely(res <= 0)) {
        if (res < 0 && res != -EAGAIN && res != -ECANCELED) {
            log_error("I/O error at idx %d, type %d: %s", idx, data->type, strerror(-res));
        }
        vfast_auto_reschedule(idx);
        return;
    }
    /* Primary State Transition Logic */
    switch (data->type) {
    case IO_TYPE_TUN_READ:
        if (vfast_fsm_is_connected()) {
            if (!vfast_tun_client_rx(res, idx, data)) {
                vfast_auto_reschedule(idx);
            }
        } else {
            vfast_auto_reschedule(idx);
        }
        break; // --->SOCK_WRITE
    case IO_TYPE_SOCK_READ:
        if (!vfast_udp_client_rx(res, idx, data)) {
            vfast_auto_reschedule(idx);
        }
        break; // --->TUN_WRITE
    case IO_TYPE_SOCK_WRITE:
    case IO_TYPE_TUN_WRITE:
        vfast_auto_reschedule(idx);
        break;
    default:
        log_warn("Undefined state for buffer %d, forcing recycle", idx);
        vfast_auto_reschedule(idx);
        break;
    }
}

/**
 * vfast_cleanup - Resource teardown.
 * Ensures sockets, rings, and memory are released in reverse order of creation.
 */
static void vfast_cleanup() {
    log_info("Initiating system shutdown and resource cleanup...");

    vpn_iouring_destroy(&vfastctx.io_ring);
    vpn_tun_destroy(&vfastctx.tun);
    
    if (vfastctx.udp) {
        udp_close(vfastctx.udp);
    }
    
    if (vfastctx.io_data_pool) {
        zfree(vfastctx.io_data_pool);
    }
    
    log_info("Cleanup complete. Exit.");
}

/**
 * vfast_init_server - Pipeline and Environment Setup.
 * Initializes memory, kernel interfaces, and warms up the I/O ring.
 */
static int vfast_init_client(const char *remote_ip) {
    memset(&vfastctx, 0, sizeof(vfast_ctx_t));
    atomic_store(&vfastctx.running, true);

    /* Signal Registration */
    struct sigaction sa = { .sa_handler = client_signal_handler };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    /* Memory Allocation */
    vfastctx.io_data_pool = (vpn_io_data_t *)zmalloc(IO_BUF_POOL_SIZE * sizeof(vpn_io_data_t));
    if (!vfastctx.io_data_pool) {
        log_error("Critical: Failed to allocate I/O buffer pool.");
        return -1;
    }

    /* Networking Subsystem Initialization */
    if (vpn_iouring_init(&vfastctx.io_ring, IO_RING_DEPTH) < 0) return -1;

    if (vpn_tun_init(&vfastctx.tun, "tun0", 0) < 0) return -1;
    // vpn_tun_set_ip(vfastctx.tun.name, "10.0.0.2", "255.255.255.0");
    vpn_tun_set_status(vfastctx.tun.name, VPN_MTU_DEFAULT, 1);
    
    vfastctx.udp = udp_init_listener(0, 20);
    if (!vfastctx.udp) {
        log_error("Failed to initialize UDP listener.");
        return -1;
    }
    udp_set_connect(vfastctx.udp, inet_addr(remote_ip), 9999);

    /* Prime the I/O pipelines */
    vfast_io_warmup(&vfastctx);

    log_info("VFAST Client initialized successfully. Connecting to %s...", remote_ip);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    /* System Bootstrap */
    if (vfast_init_client(argv[1]) < 0) {
        log_error("System initialization failed. Aborting.");
        vfast_cleanup();
        return EXIT_FAILURE;
    }

    vfast_fsm_init(vfastctx.udp, argv[1], 9999);

    struct io_uring_cqe *cqes[16];
    
    /* Main Event Loop */
    while (likely(atomic_load(&vfastctx.running))) {
        struct io_uring_cqe *cqe_wait;
        
        /* Blocking wait for at least one event */
        int ret = io_uring_wait_cqe(&vfastctx.io_ring.ring, &cqe_wait);
        if (unlikely(ret < 0)) {
            if (ret == -EINTR) continue;
            log_error("io_uring_wait_cqe failed: %s", strerror(-ret));
            break;
        }

        /* Batch processing for high-load efficiency */
        int count = io_uring_peek_batch_cqe(&vfastctx.io_ring.ring, cqes, 16);
        for (int i = 0; i < count; i++) {
            handle_io_event(cqes[i]);
            io_uring_cqe_seen(&vfastctx.io_ring.ring, cqes[i]);
        }
        
        /* Flush all pending SQEs generated in handle_io_event */
        io_uring_submit(&vfastctx.io_ring.ring);
    }

    vfast_cleanup();
    return EXIT_SUCCESS;
}