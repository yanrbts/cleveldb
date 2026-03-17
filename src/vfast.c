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

void vfast_report_performance(void) {
    static uint64_t last_bytes = 0;
    static struct timespec last_time = {0}; // 初始化
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    /* 如果是第一次运行，先记录时间并退出 */
    if (last_time.tv_sec == 0) {
        last_time = now;
        last_bytes = atomic_load(&vfastctx.stats.rx_bytes);
        return;
    }

    uint64_t current_bytes = atomic_load(&vfastctx.stats.rx_bytes);
    double seconds = (now.tv_sec - last_time.tv_sec) + 
                     (now.tv_nsec - last_time.tv_nsec) / 1e9;

    /* 只有超过 1 秒才打印 */
    if (seconds >= 1.0) {
        double mbps = ((double)(current_bytes - last_bytes) * 8.0) / (1024 * 1024 * seconds);
        
        log_info("[PERF] Bandwidth: %.2f Mbps | RX: %lu pkts | SessionMiss: %lu | UnpackErr: %lu", 
                 mbps, 
                 atomic_load(&vfastctx.stats.rx_packets),
                 atomic_load(&vfastctx.stats.drop_session_miss),
                 atomic_load(&vfastctx.stats.drop_unpack_error)); // 加上你关心的丢包统计
        
        last_bytes = current_bytes;
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
