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
#include "auth.h"
#include "ippool.h"
#include "vfast.h"

/* Global Context Instance */
vfast_ctx_t vfastctx;

/**
 * vfast_auth_request - Processes HELLO packet and submits a response.
 */
static void vfast_auth_request(int res, int idx, vpn_io_data_t *data) {
    UNUSED(res);

    uint8_t *base = (uint8_t *)vfastctx.io_ring.iovecs[idx].iov_base;
    
    /* 1. Extract Payload (Header is 8 bytes, payload follows) */
    const uint8_t *payload_ptr = base + sizeof(vpn_tunnel_hdr_t);
    
    uint32_t new_sid = 0;
    vpn_auth_t resp_payload;

    /* 2. Invoke our industrial-grade Auth Logic from auth.c */
    /* Note: Using a global token here; in production, fetch from config/DB */
    const uint8_t *expected_token = (const uint8_t *)"VFAST_SECRET_KEY";
    
    if (vfast_auth_verify((vpn_auth_t *)payload_ptr, expected_token) != 0) {
        log_warn("Unauthorized HELLO attempt from %s", inet_ntoa(data->udp_meta.client_addr.sin_addr));
        goto recycle;
    }

    /* 3. Resource Allocation (Decoupled in your Control Plane) */
    uint32_t assigned_vip = vpn_ip_pool_alloc(&vfastctx.ip_pool);
    if (assigned_vip == 0) {
        log_error("IP Pool empty, dropping HELLO from %s", inet_ntoa(data->udp_meta.client_addr.sin_addr));
        goto recycle;
    }

    /* 4. Generate SID and Persist Session */
    new_sid = vpn_generate_sid(assigned_vip);
    vpn_session_update(assigned_vip, new_sid, &data->udp_meta.client_addr);

    /* 5. Construct Response Packet in the SAME buffer (Zero-copy reuse) */
    vpn_tunnel_hdr_t *resp_hdr = (vpn_tunnel_hdr_t *)base;
    resp_hdr->version = VFAST_VERSION;
    resp_hdr->msg_type = VPN_MSG_HELLO; /* Response uses same type or a dedicated ACK type */
    resp_hdr->session_id = new_sid;

    /* Pack the auth response payload */
    vfast_auth_pack(&resp_payload, assigned_vip, expected_token, 0);
    memcpy(base + sizeof(vpn_tunnel_hdr_t), &resp_payload, sizeof(vpn_auth_t));

    /* 6. Submit Async Write back to the Client */
    int resp_len = sizeof(vpn_tunnel_hdr_t) + sizeof(vpn_auth_t);
    vfast_udp_write(idx, resp_len, data);
    
    log_info("Handshake Complete: VIP=%u.%u.%u.%u SID=0x%08x -> %s",
             (assigned_vip & 0xFF), (assigned_vip >> 8) & 0xFF,
             (assigned_vip >> 16) & 0xFF, (assigned_vip >> 24) & 0xFF, 
             new_sid, inet_ntoa(data->udp_meta.client_addr.sin_addr));
    return;

recycle:
    vfast_udp_read(idx, data);
}

/**
 * vfast_udp_forward - Core data plane forwarding logic.
 * Process a valid VFAST DATA packet and forward it to the TUN device.
 */
static void vfast_udp_forward(int res, int idx, vpn_io_data_t *data, uint8_t *base) {
    int plen;
    uint32_t sid;
    struct msghdr *msg = &data->udp_meta.msg;

    /* 1. Packet Integrity Validation */
    if (unlikely(msg->msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
        log_warn("Received truncated UDP packet from client, dropping.");
        goto err;
    }

    /* 2. Decapsulate: Strip VFAST header and get pointer to inner IP packet */
    uint8_t *ip_pkt = vpn_unpack(base, res, &plen, &sid);
    
    if (likely(ip_pkt != NULL)) {
        struct iphdr *iph = (struct iphdr *)ip_pkt;
        
        /* 3. Update Session: Map Virtual IP to Public UDP Endpoint */
        vpn_session_update(iph->saddr, sid, &data->udp_meta.client_addr);
        data->sid = sid;

        /* 4. Forward: Write the inner IP packet to TUN device */
        vfast_tun_write(idx, data);
        return;
    } 

    log_warn("Failed to unpack VFAST packet from client, dropping.");

err:
    atomic_fetch_add(&vfastctx.stats.drop_unpack_error, 1);
    vfast_udp_read(idx, data);
}

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
    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)base;

    /* Basic sanity check: must at least contain the 8-byte header */
    if (unlikely(res < (int)VPN_TNL_HLEN)) {
        atomic_fetch_add(&vfastctx.stats.drop_unpack_error, 1);
        vfast_udp_read(idx, data);
        return;
    }

    switch (hdr->msg_type) {
    case VPN_MSG_DATA:
        vfast_udp_forward(res, idx, data, base);
        break;
    case VPN_MSG_HELLO:
        vfast_auth_request(res, idx, data);
        break;
    case VPN_MSG_KEEPALIVE:
        vfast_keep(res, idx, data);
        break;
    case VPN_MSG_DISCONNECT:
    default:
        log_warn("Unknown msg_type 0x%02x from %s", 
                    hdr->msg_type, inet_ntoa(data->udp_meta.client_addr.sin_addr));
        vfast_udp_read(idx, data);
        break;
    }
}

void vfast_tun_rx(int res, int idx, vpn_io_data_t *data) {
    atomic_fetch_add(&vfastctx.stats.rx_packets, 1);
    atomic_fetch_add(&vfastctx.stats.rx_bytes, (uint64_t)res);

    uint8_t *base = (uint8_t *)vfastctx.io_ring.iovecs[idx].iov_base;
    struct iphdr *iph = (struct iphdr *)(base + VPN_TNL_HLEN);
    struct sockaddr_in remote;

    if (unlikely(!vpn_session_lookup_by_ip(iph->daddr, &remote))) {
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

/**
 * vfast_keep - Process heartbeat and send acknowledgment back to client.
 */
void vfast_keep(int res, int idx, vpn_io_data_t *data) {
    uint8_t *base = (uint8_t *)vfastctx.io_ring.iovecs[idx].iov_base;
    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)base;
    struct sockaddr_in *client_addr = &data->udp_meta.client_addr;

    uint32_t v_ip;
    struct sockaddr_in old_addr;

    /* 1. Session Validation & Update */
    if (likely(vpn_session_lookup_by_sid(hdr->session_id, &v_ip, &old_addr))) {
        
        /* Refresh last_seen and handle potential NAT roaming */
        vpn_session_update(v_ip, hdr->session_id, client_addr);

        /* Log roaming if the public endpoint changed */
        if (unlikely(memcmp(&old_addr, client_addr, sizeof(struct sockaddr_in)) != 0)) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr->sin_addr, ip_str, sizeof(ip_str));
            log_info("ROAM: SID[0x%08x] now at %s:%d", hdr->session_id, ip_str, ntohs(client_addr->sin_port));
        }

        /**
         * 2. Construct Response (Echo back)
         * We reuse the same buffer and same header. 
         * The client will see the same Session ID and MSG_TYPE.
         */
        vpn_auth_t *payload = (vpn_auth_t *)(base + sizeof(vpn_tunnel_hdr_t));
        
        /* Optional: Update the server-side timestamp in the payload */
        payload->ts = (uint64_t)time(NULL);
        payload->vip = v_ip; // Confirm their assigned VIP

        /* 3. Send Acknowledgment via io_uring */
        /* res is the length of the received keepalive packet */
        vfast_udp_write(idx, res, data);

    } else {
        /* Session doesn't exist (possibly expired) */
        log_warn("KEEPALIVE REJECTED: Unknown SID 0x%08x", hdr->session_id);
        /* OPTIONAL: Send a special 'Reset' packet or just drop and let client re-auth */
        vfast_udp_read(idx, data);
    }
}
