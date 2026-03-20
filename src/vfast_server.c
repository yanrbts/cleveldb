/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 * 
 * 
 * [ PUBLIC INTERNET ]                   [ VIRTUAL NETWORK ]
        (Remote Clients)                      (Google / Kernel)
               |                                     ^
               |                                     |
    +----------V----------+               +----------|----------+
    |  IO_TYPE_SOCK_READ  |               |  IO_TYPE_TUN_WRITE  |
    | (Listen for Uplink) |               | (Inject to System)  |
    +----------+----------+               +----------^----------+
               |                                     |
        [Decap & Learn]                       [Packet Ready]
               |                                     |
    +----------V----------+               +----------|----------+
    |    handle_udp_rx    |-------------->|  vfast_tun_write   |
    +---------------------+  (Pipeline B) +---------------------+
                                 Ingress
    -------------------------------------------------------------
                                 Egress
    +---------------------+  (Pipeline A) +---------------------+
    |  vpn_iouring_submit |<--------------|    handle_tun_rx    |
    |    (sock_write)     |               |  (Encap & Lookup)   |
    +----------+----------+               +----------^----------+
               |                                     |
        [Send to Client]                      [Capture Response]
               |                                     |
    +----------V----------+               +----------|----------+
    |  IO_TYPE_SOCK_WRITE |               |  IO_TYPE_TUN_READ   |
    | (UDP Outbound Done) |               | (Listen for Downlink)|
    +----------|----------+               +----------^----------+
               |                                     |
               +-------------------------------------+
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <signal.h>
#include <linux/ip.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <errno.h>

#include "log.h"
#include "utils.h"
#include "vfast.h"
#include "session.h"
#include "iouring.h"
#include "zmalloc.h"
#include "udp.h"
#include "protocol.h"

/* Simple signal handling for graceful shutdown */
static void vfast_signal_handler(int sig) {
    (void)sig;
    atomic_store(&vfastctx.running, false);
}

/**
 * vfast_setup_signals - Industrial-grade signal registration.
 * Registers SIGINT and SIGTERM to trigger a graceful exit.
 * * NOTE: We explicitly omit SA_RESTART. This ensures that blocking 
 * system calls like io_uring_wait_cqe are interrupted (returning -EINTR),
 * allowing the event loop to terminate immediately on the first Ctrl+C.
 */
int vfast_setup_signals(void) {
    struct sigaction sa;

    /* Initialize sigaction structure */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = vfast_signal_handler;
    sigemptyset(&sa.sa_mask);

    /* * sa_flags = 0 is critical here. 
     * By default, many systems use SA_RESTART, which would cause 
     * io_uring_wait_cqe to resume internally after a signal, 
     * ignoring our 'running' state change.
     */
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        log_error("Failed to configure SIGINT handler: %s", strerror(errno));
        return -1;
    }

    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        log_error("Failed to configure SIGTERM handler: %s", strerror(errno));
        return -1;
    }

    log_info("Signal handlers configured (SIGINT, SIGTERM).");
    return 0;
}

static int vfast_clean_server(void) {
    log_info("Initiating graceful shutdown...");
    /* 1. Stop the Transport (UDP) */
    if (vfastctx.udp) {
        udp_close(vfastctx.udp);
        vfastctx.udp = NULL;
    }

    /* 3. Close the TUN device */
    vpn_tun_destroy(&vfastctx.tun);

    /* 4. Business logic teardown */
    vpn_session_destroy();
    vpn_ip_pool_destroy(&vfastctx.ip_pool);

    /* 2. Destroy the Ring FIRST (The most sensitive resource) */
    /* This will force cancellation of all inflight SQEs */
    vpn_iouring_destroy(&vfastctx.io_ring);

    if (vfastctx.io_data_pool) {
        zfree(vfastctx.io_data_pool);
    }

    log_info("VFAST server halted safely.");
    return 0;
}

static int vfast_init_server(void) {
    memset(&vfastctx, 0, sizeof(vfast_ctx_t));
    atomic_store(&vfastctx.running, true);

    /* 1. Setup specialized signal handling */
    if (vfast_setup_signals() < 0) return -1;

    /* Initialize IPAM (The IP Pool) - MUST be before sessions */
    /* Starting from 10.0.0.0 with 65536 addresses (/16) */
    if (vpn_ip_pool_init(&vfastctx.ip_pool, "10.0.0.0", 65536) != 0) {
        log_error("Failed to initialize IP Pool");
        return -1;
    }

    if (vpn_session_init() < 0) {
        log_error("Failed to initialize session manager");
        return -1;
    }

    if (vpn_iouring_init(&vfastctx.io_ring, IO_RING_DEPTH) < 0) {
        log_error("Init iouring failed");
        return -1;
    }

    if (vpn_tun_init(&vfastctx.tun, "tun0", 0) < 0) {
        log_error("Failed to initialize TUN device");
        return -1;
    }
    vpn_tun_disable_ipv6("tun0");
    vpn_tun_set_ip(vfastctx.tun.name, "10.0.0.1", VFAST_BROADCAST);
    vpn_tun_set_status(vfastctx.tun.name, VPN_MTU_DEFAULT, 1); /* MTU 1400 to allow header overhead */
    vpn_set_nonblocking(vfastctx.tun.fd);

    vfastctx.udp = udp_init_listener(9999, 20); 
    if (!vfastctx.udp) {
        log_error("Failed to init UDP listener");
        goto cleanup;
    }
    vpn_set_nonblocking(vfastctx.udp->fd);

    vfastctx.io_data_pool = zcalloc(sizeof(vpn_io_data_t) * IO_BUF_POOL_SIZE);
    if (!vfastctx.io_data_pool) goto cleanup;

    vfast_io_warmup(&vfastctx);
    return 0;

cleanup:
    vfast_clean_server();
    return -1;
}

/* * Core Event Loop - Optimized for Clarity
 */
int main(int argc, char *argv[]) {
    UNUSED(argc); UNUSED(argv);

    if (vfast_init_server() < 0) return 1;

    struct io_uring_cqe *cqes[16]; // Batch processing array
    static uint64_t last_check_pkt = 0;

    while (atomic_load(&vfastctx.running)) {
        /* Batch-peek completions to minimize synchronization overhead */
        int count = io_uring_peek_batch_cqe(&vfastctx.io_ring.ring, cqes, 16);
        
        /* If no completions, wait for at least one */
        if (count == 0) {
            struct io_uring_cqe *cqe;
            int ret = io_uring_wait_cqe(&vfastctx.io_ring.ring, &cqe);
            if (ret < 0) {
                if (ret == -EINTR) break; /* Normal exit on signal */
                log_error("Fatal io_uring error: %d", ret);
                break;
            }
            cqes[0] = cqe;
            count = 1;
        }

        for (int i = 0; i < count; i++) {
            struct io_uring_cqe *cqe = cqes[i];
            vpn_io_data_t *data = (vpn_io_data_t *)io_uring_cqe_get_data(cqe);
            int res = cqe->res, idx = data->buf_idx;

            if (unlikely(res <= 0)) {
                atomic_fetch_add(&vfastctx.stats.drop_io_errors, 1);
                vfast_auto_reschedule(idx);
            } else {
                /* Finite State Machine: High-speed packet routing */
                switch (data->type) {
                case IO_TYPE_TUN_READ:
                    if (!vfast_tun_rx(res, idx, data)) {
                        vfast_auto_reschedule(idx);
                    }
                    break;  // --->SOCK_WRITE
                case IO_TYPE_SOCK_READ: 
                    if (!vfast_udp_rx(res, idx, data)) {
                        vfast_auto_reschedule(idx);
                    }
                    break; // --->TUN_WRITE
                case IO_TYPE_SOCK_WRITE:
                case IO_TYPE_TUN_WRITE:
                    vfast_auto_reschedule(idx);
                    break;
                }
            }
            io_uring_cqe_seen(&vfastctx.io_ring.ring, cqe);

            last_check_pkt++;
        }

        if (unlikely(last_check_pkt >= 50000)) {
            last_check_pkt = 0;
            vpn_session_clean_timeout(&vfastctx.ip_pool, 60);
            log_info("Periodic cleanup: scan timeout sessions.");

            vfast_report_performance();
        }
        /* Submit all queued SQEs in one single batch to improve SQPOLL efficiency */
        vpn_iouring_flush(&vfastctx.io_ring);
    }

    vfast_clean_server();
    return 0;
}