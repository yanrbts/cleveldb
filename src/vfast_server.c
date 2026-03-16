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
    |    handle_udp_rx    |-------------->|  submit_tun_write   |
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

/* Global Context Instance */
vfast_ctx_t vfastctx;


/* Simple signal handling for graceful shutdown */
static void signal_handler(int sig) {
    (void)sig;
    atomic_store(&vfastctx.running, false);
}

/* --- Internal Helpers (Short Names) --- */
static void submit_tun_read(int idx, vpn_io_data_t *d) {
    d->type = IO_TYPE_TUN_READ;
    d->buf_idx = idx;
    vpn_iouring_submit_read(&vfastctx.io_ring, vfastctx.tun.fd, idx, d);
}

static void submit_tun_write(int idx, uint8_t *ptr, int len, vpn_io_data_t *d) {
    d->type = IO_TYPE_TUN_WRITE;
    d->buf_idx = idx;
    void *org_ptr = vfastctx.io_ring.iovecs[idx].iov_base;
    vfastctx.io_ring.iovecs[idx].iov_base = ptr;

    vpn_iouring_submit_write(&vfastctx.io_ring, vfastctx.tun.fd, idx, len, d);
    vfastctx.io_ring.iovecs[idx].iov_base = org_ptr;
}

/* --- Core Event Handlers --- */

static void handle_tun_rx(int res, int idx, vpn_io_data_t *data) {
    atomic_fetch_add(&vfastctx.stats.rx_packets, 1);
    atomic_fetch_add(&vfastctx.stats.rx_bytes, (uint64_t)res);

    uint8_t *base = (uint8_t *)vfastctx.io_ring.iovecs[idx].iov_base;
    struct iphdr *iph = (struct iphdr *)(base + VPN_TNL_HLEN);
    struct sockaddr_in remote;

    if (unlikely(!vpn_session_lookup(iph->daddr, &remote))) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->daddr, ip_str, sizeof(ip_str));
        log_warn("SESSION MISS: Kernel wants to send to %s, but I don't know this client!", ip_str);

        atomic_fetch_add(&vfastctx.stats.drop_session_miss, 1);
        submit_tun_read(idx, data);
        return;
    }

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->daddr, ip_str, sizeof(ip_str));
    char client_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &remote.sin_addr, client_ip_str, sizeof(client_ip_str));

    log_info("Found session for %s <--> %s:%d", ip_str, client_ip_str, ntohs(remote.sin_port));

    int tlen = vpn_pack(base, res, IO_BUF_SIZE, VPN_MSG_DATA, data->sid);
    if (unlikely(tlen <= 0)) {
        atomic_fetch_add(&vfastctx.stats.drop_pack_error, 1);
        submit_tun_read(idx, data);
        return;
    }

    /* Send encapsulated packet to client's UDP endpoint. Use sendmsg so
     * we can specify destination per-packet (the server socket is not
     * connected to a single client). */
    data->type = IO_TYPE_SOCK_WRITE;
    memcpy(&data->udp_meta.client_addr, &remote, sizeof(remote));
    vpn_iouring_submit_sendmsg(&vfastctx.io_ring, vfastctx.udp->fd, idx, tlen, data);
}

static void handle_udp_rx(int res, int idx, vpn_io_data_t *data) {
    atomic_fetch_add(&vfastctx.stats.tx_packets, 1);
    atomic_fetch_add(&vfastctx.stats.tx_bytes, (uint64_t)res);

    uint8_t *base = (uint8_t *)vfastctx.io_ring.iovecs[idx].iov_base;
    int plen;
    uint32_t sid;
    
    /* 1. Decapsulate: Strip VFAST header and get pointer to inner IP packet */
    uint8_t *ip_pkt = vpn_unpack(base, res, &plen, &sid);
    
    if (likely(ip_pkt != NULL)) {
        struct iphdr *iph = (struct iphdr *)ip_pkt;
        
        // log_warn("Received VFAST packet: SID=%x, Inner IP src=%x dst=%x, payload_len=%d", sid, iph->saddr, iph->daddr, plen);
        /* 2. Update Session: Map Virtual IP to Public UDP Endpoint */
        // char client_ip_str[INET_ADDRSTRLEN];
        // inet_ntop(AF_INET, &data->udp_meta.client_addr.sin_addr, client_ip_str, sizeof(client_ip_str));
        // log_warn("Updating session: Virtual IP %x <-> Client %s:%d", iph->saddr, client_ip_str, ntohs(data->udp_meta.client_addr.sin_port));

        vpn_session_update(iph->saddr, &data->udp_meta.client_addr);
        data->sid = sid;

        /* 3. Forward: Write the inner IP packet to TUN device */
        submit_tun_write(idx, ip_pkt, plen, data);
    } else {
        /* 4. Error Recovery: Drop malformed packet and resume listening */
        log_warn("Dropped invalid VFAST packet from client");
        atomic_fetch_add(&vfastctx.stats.drop_unpack_error, 1);

        data->type = IO_TYPE_SOCK_READ; // Explicitly ensure state
        vpn_iouring_submit_recvmsg(&vfastctx.io_ring, vfastctx.udp->fd, idx, data);
    }
}

static inline void submit_udp_read(int idx, vpn_io_data_t *data) {
    data->type = IO_TYPE_SOCK_READ;
    data->buf_idx = idx;
    /* In high-concurrency, ensure we don't need to re-allocate 'data'. 
     * You are already recycling the 'data' pointer, which is excellent. 
     */
    vpn_iouring_submit_recvmsg(&vfastctx.io_ring, vfastctx.udp->fd, idx, data);
}

static int vfast_clean_server(void) {
    vpn_session_destroy();
    vpn_ip_pool_destroy(&vfastctx.ip_pool);
    if (vfastctx.udp) udp_close(vfastctx.udp);
    vpn_tun_destroy(&vfastctx.tun);
    vpn_iouring_destroy(&vfastctx.io_ring);
    return 0;
}

/**
 * @brief Warm up the I/O ring by pre-submitting initial read requests.
 * This function populates the io_uring submission queue with balanced 
 * requests for both TUN and UDP interfaces. It utilizes the pre-allocated 
 * static object pool (io_data_pool) to avoid heap allocation overhead 
 * during high-performance packet processing.
 *
 * @param ctx Pointer to the global VFAST context instance.
 */
static void vfast_io_warmup(vfast_ctx_t *ctx) {
    /* Balance initial requests between Ingress (TUN) and Egress (UDP) pipelines */
    for (int i = 0; i < IO_BUF_POOL_SIZE / 2; i++) {
        
        /* 1. Initialize Downlink Pipeline (Google -> Server -> Client) 
         * Pop a free buffer index to listen for incoming packets from the TUN device. */
        int idx_t = vfast_buf_pop(ctx);
        if (idx_t != -1) {
            /* Map the buffer index to its corresponding static data structure */
            vpn_io_data_t *d = &ctx->io_data_pool[idx_t];
            memset(d, 0, sizeof(vpn_io_data_t));
            d->buf_idx = idx_t;
            
            /* Start listening for raw IP packets routed into the virtual interface */
            submit_tun_read(idx_t, d);
        }

        /* 2. Initialize Uplink Pipeline (Client -> Server -> Google) 
         * Pop a free buffer index to listen for encapsulated UDP packets from clients. */
        int idx_s = vfast_buf_pop(ctx);
        if (idx_s != -1) {
            /* Map the buffer index to its corresponding static data structure */
            vpn_io_data_t *d = &ctx->io_data_pool[idx_s];
            memset(d, 0, sizeof(vpn_io_data_t));
            d->buf_idx = idx_s;
            
            /* Start listening for VFAST encapsulated traffic on the public UDP port */
            submit_udp_read(idx_s, d);
        }
    }

    /* Perform a single batch flush to sync all SQEs to the kernel's submission queue.
     * This maximizes efficiency, especially when IORING_SETUP_SQPOLL is enabled. */
    vpn_iouring_flush(&ctx->io_ring);
    
    log_info("I/O Pipeline Warmed: %d buffers initialized from the static pool.", IO_BUF_POOL_SIZE);
}

static int vfast_init_server(void) {
    memset(&vfastctx, 0, sizeof(vfast_ctx_t));
    vfastctx.free_top = -1;
    atomic_store(&vfastctx.running, true);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

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

    if (vpn_tun_init(&vfastctx.tun, "tun0", 1) < 0) {
        log_error("Failed to initialize TUN device");
        return -1;
    }
    
    vpn_tun_set_ip(vfastctx.tun.name, "10.0.0.1", "255.255.255.0");
    vpn_tun_set_status(vfastctx.tun.name, VPN_MTU_DEFAULT, 1); /* MTU 1400 to allow header overhead */
    vpn_set_nonblocking(vfastctx.tun.fd);

    vfastctx.udp = udp_init_listener(9999, 20); 
    if (!vfastctx.udp) {
        log_error("Failed to init UDP listener");
        goto cleanup;
    }
    vpn_set_nonblocking(vfastctx.udp->fd);

    for (int i = 0; i < IO_BUF_POOL_SIZE; i++) {
        vfast_buf_push(&vfastctx, i);
    }

    vfastctx.io_data_pool = zmalloc(sizeof(vpn_io_data_t) * IO_BUF_POOL_SIZE);
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
                /* Error: Resubmit based on current state to keep the loop alive */
                if (data->type == IO_TYPE_TUN_READ || data->type == IO_TYPE_SOCK_WRITE)
                    submit_tun_read(idx, data);
                else
                    submit_udp_read(idx, data);
            } else {
                /* Finite State Machine: High-speed packet routing */
                switch (data->type) {
                    case IO_TYPE_TUN_READ: handle_tun_rx(res, idx, data); break;
                    case IO_TYPE_SOCK_WRITE: submit_tun_read(idx, data);  break;
                    case IO_TYPE_SOCK_READ:  handle_udp_rx(res, idx, data); break;
                    case IO_TYPE_TUN_WRITE: submit_udp_read(idx, data);  break;
                }
            }
            io_uring_cqe_seen(&vfastctx.io_ring.ring, cqe);

            last_check_pkt++;
        }

        if (unlikely(last_check_pkt >= 50000)) {
            last_check_pkt = 0;
            vpn_session_clean_timeout(&vfastctx.ip_pool, 60);
            log_info("Periodic cleanup: scan timeout sessions.");
        }

        // vfast_report_performance();
        
        /* Submit all queued SQEs in one single batch to improve SQPOLL efficiency */
        vpn_iouring_flush(&vfastctx.io_ring);
    }

    vfast_clean_server();
    return 0;
}