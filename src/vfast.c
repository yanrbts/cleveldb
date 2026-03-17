/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <signal.h>
#include <linux/ip.h>
#include "log.h"
#include "utils.h"
#include "session.h"
#include "protocol.h"
#include "vfast.h"

/* Global Context Instance */
vfast_ctx_t vfastctx;

/**
 * @brief Periodically reports system throughput and error metrics.
 * * Logic:
 * 1. Calculates delta bytes and delta packets since the last report.
 * 2. Computes PPS (Packets Per Second) and Bandwidth.
 * 3. Automatically scales units (bps, Kbps, Mbps) to ensure visibility 
 * even during low-traffic periods (e.g., ICMP keep-alives).
 */
void vfast_report_performance(void) {
    static uint64_t last_bytes = 0;
    static uint64_t last_pkts = 0;
    static struct timespec last_time = {0}; 
    struct timespec now;
    
    clock_gettime(CLOCK_MONOTONIC, &now);

    /* Initialize baseline on first execution */
    if (unlikely(last_time.tv_sec == 0)) {
        last_time = now;
        last_bytes = atomic_load(&vfastctx.stats.rx_bytes);
        last_pkts = atomic_load(&vfastctx.stats.rx_packets);
        return;
    }

    /* Calculate elapsed time in seconds */
    double seconds = (now.tv_sec - last_time.tv_sec) + 
                     (now.tv_nsec - last_time.tv_nsec) / 1e9;

    /* Report threshold: 1.0 second interval */
    if (seconds >= 1.0) {
        uint64_t curr_bytes = atomic_load(&vfastctx.stats.rx_bytes);
        uint64_t curr_pkts = atomic_load(&vfastctx.stats.rx_packets);
        
        double delta_bytes = (double)(curr_bytes - last_bytes);
        double delta_pkts = (double)(curr_pkts - last_pkts);
        
        /* Calculate bits-per-second and packets-per-second */
        double bps = (delta_bytes * 8.0) / seconds;
        double pps = delta_pkts / seconds;

        /* Adaptive Unit Selection for Bandwidth Display */
        if (bps < 1024.0) {
            log_info("[PERF] BW: %.2f bps | PPS: %.0f | RX: %lu | Miss: %lu | Err: %lu", 
                     bps, pps, curr_pkts,
                     atomic_load(&vfastctx.stats.drop_session_miss),
                     atomic_load(&vfastctx.stats.drop_unpack_error));
        } else if (bps < (1024.0 * 1024.0)) {
            log_info("[PERF] BW: %.2f Kbps | PPS: %.0f | RX: %lu | Miss: %lu | Err: %lu", 
                     bps / 1024.0, pps, curr_pkts,
                     atomic_load(&vfastctx.stats.drop_session_miss),
                     atomic_load(&vfastctx.stats.drop_unpack_error));
        } else {
            log_info("[PERF] BW: %.2f Mbps | PPS: %.0f | RX: %lu | Miss: %lu | Err: %lu", 
                     bps / (1024.0 * 1024.0), pps, curr_pkts,
                     atomic_load(&vfastctx.stats.drop_session_miss),
                     atomic_load(&vfastctx.stats.drop_unpack_error));
        }

        /* Update state for next cycle */
        last_bytes = curr_bytes;
        last_pkts = curr_pkts;
        last_time = now;
    }
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
void vfast_io_warmup(vfast_ctx_t *ctx) {

    for (int i = 0; i < IO_BUF_POOL_SIZE; i++) {
        vfast_buf_push(&vfastctx, i);
    }

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
            vfast_tun_read(idx_t, d);
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
            vfast_udp_read(idx_s, d);
        }
    }

    /* Perform a single batch flush to sync all SQEs to the kernel's submission queue.
     * This maximizes efficiency, especially when IORING_SETUP_SQPOLL is enabled. */
    vpn_iouring_flush(&ctx->io_ring);
    
    log_info("I/O Pipeline Warmed: %d buffers initialized from the static pool.", IO_BUF_POOL_SIZE);
}

void vfast_udp_rx(int res, int idx, vpn_io_data_t *data) {
    atomic_fetch_add(&vfastctx.stats.tx_packets, 1);
    atomic_fetch_add(&vfastctx.stats.tx_bytes, (uint64_t)res);

    uint8_t *base = (uint8_t *)vfastctx.io_ring.iovecs[idx].iov_base;
    int plen;
    uint32_t sid;

    struct msghdr *msg = &data->udp_meta.msg;
    /* [Packet Integrity Validation]
    * Check for truncation flags set by the kernel during the async recvmsg operation.
    * MSG_TRUNC:  Indicates the incoming UDP datagram was larger than the 
    * provided 2048-byte fixed buffer. The trailing data was discarded.
    * MSG_CTRUNC: Indicates that ancillary control data (e.g., IP options or 
    * TTL metadata) was truncated due to insufficient buffer space.
    * If either flag is set, the packet is corrupted or malformed. We must 
    * drop it immediately to prevent the unpacker from processing incomplete data,
    * which could lead to protocol desynchronization or memory errors.
    */
    if (unlikely(msg->msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
        log_warn("Received truncated UDP packet from client, dropping.");
        goto err;
    }

    if (unlikely(res < (int)VPN_TNL_HLEN)) {
        log_warn("Received fragmented or tiny packet from client: %d bytes", res);
        goto err;
    }
    
    /* 1. Decapsulate: Strip VFAST header and get pointer to inner IP packet */
    uint8_t *ip_pkt = vpn_unpack(base, res, &plen, &sid);
    
    if (likely(ip_pkt != NULL)) {
        struct iphdr *iph = (struct iphdr *)ip_pkt;
        
        /* 2. Update Session: Map Virtual IP to Public UDP Endpoint */
        vpn_session_update(iph->saddr, &data->udp_meta.client_addr);
        data->sid = sid;

        /* 3. Forward: Write the inner IP packet to TUN device */
        vfast_tun_write(idx, data);
        return;
    } else {
        log_warn("Failed to unpack VFAST packet from client, dropping.");
        goto err;
    }

err:
    atomic_fetch_add(&vfastctx.stats.drop_unpack_error, 1);
    vfast_udp_read(idx, data);
}

void vfast_tun_rx(int res, int idx, vpn_io_data_t *data) {
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
        vfast_tun_read(idx, data);
        return;
    }

    int tlen = vpn_pack(base, res, IO_BUF_SIZE, VPN_MSG_DATA, data->sid);
    if (unlikely(tlen <= 0)) {
        atomic_fetch_add(&vfastctx.stats.drop_pack_error, 1);
        vfast_tun_read(idx, data);
        return;
    }

    /* Send encapsulated packet to client's UDP endpoint. Use sendmsg so
     * we can specify destination per-packet (the server socket is not
     * connected to a single client). */
    memcpy(&data->udp_meta.client_addr, &remote, sizeof(remote));
    vfast_udp_write(idx, tlen, data);
}

/**
 * vfast_tun_client_rx - High-performance client-side transmission path.
 * * This function handles the "Uplink" process:
 * 1. Consumes a raw IPv4/IPv6 packet read from the TUN interface.
 * 2. Encapsulates the packet with a VFAST header in-place (Zero-copy).
 * 3. Submits an asynchronous fixed-buffer write to the UDP transport.
 *
 * @param res  The number of bytes actually read from the TUN device.
 * @param idx  The index of the pre-registered buffer in the iovecs pool.
 * @param data Pointer to the buffer's metadata for state tracking.
 */
void vfast_tun_client_rx(int res, int idx, vpn_io_data_t *data) {
    /* 1. Telemetry and Statistics Update
     * Using atomic operations to ensure thread-safety for monitoring tools. */
    atomic_fetch_add(&vfastctx.stats.rx_packets, 1);
    atomic_fetch_add(&vfastctx.stats.rx_bytes, (uint64_t)res);

    /* 2. Zero-Copy Encapsulation
     * Access the pre-registered fixed buffer. The protocol expects an 8-byte 
     * headroom at the beginning of the buffer to host the VFAST header. */
    uint8_t *base_ptr = (uint8_t *)vfastctx.io_ring.iovecs[idx].iov_base;

    /* vpn_pack logic:
     * - Writes the header starting at base_ptr[0].
     * - Expects the raw IP packet to already be at base_ptr[8].
     * - Returns: Total length (Header + Payload) or <= 0 on failure. */
    int total_len = vpn_pack(base_ptr, res, IO_BUF_SIZE, VPN_MSG_DATA, data->sid);

    if (unlikely(total_len <= 0)) {
        atomic_fetch_add(&vfastctx.stats.drop_pack_error, 1);
        /* Recycle buffer back to TUN listening state immediately on error. */
        data->type = IO_TYPE_TUN_READ;
        vfast_tun_read(idx, data);
        return;
    }

    /* 3. Asynchronous Submission to io_uring
     * Prepare the state machine for the next stage (Transmission Completion). */
    data->type = IO_TYPE_SOCK_WRITE;
    data->buf_idx = idx;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&vfastctx.io_ring.ring);
    if (unlikely(!sqe)) {
        /* If SQE ring is full, we must drop and recycle to prevent buffer leakage. */
        log_error("SQE pool exhausted during client RX submission");
        atomic_fetch_add(&vfastctx.stats.drop_io_errors, 1);
        
        data->type = IO_TYPE_TUN_READ;
        vfast_tun_read(idx, data);
        return;
    }

    /* 4. Prepare Fixed Buffer Write
     * io_uring_prep_write_fixed provides the highest throughput by avoiding 
     * repetitive page mapping and kernel-to-user memory pinning. */
    io_uring_prep_write_fixed(sqe, 
                              vfastctx.udp->fd, 
                              base_ptr, 
                              (unsigned)total_len, 
                              0,    /* offset: not used for sockets */
                              idx); /* fixed_buf_index */
    
    /* Re-attach metadata to the SQE for context recovery in the completion loop. */
    io_uring_sqe_set_data(sqe, data);

    /* No explicit io_uring_submit() here; it will be flushed by the event loop's 
     * batch submission for better syscall amortization. */
}
