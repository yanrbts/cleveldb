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
#include "session.h"
#include "protocol.h"
#include "auth.h"
#include "ippool.h"
#include "fsm.h"
#include "vfast.h"

/* Global Context Instance */
// vfast_ctx_t vfastctx;

/**
 * vfast_auth_request - Processes HELLO packet and submits a response.
 */
static bool vfast_auth_request(vfast_ctx_t *ctx, int res, int idx, vpn_io_data_t *data) {
    UNUSED(res);

    uint8_t *base = (uint8_t *)ctx->io_ring.iovecs[idx].iov_base;
    
    /* 1. Extract Payload (Header is 8 bytes, payload follows) */
    const uint8_t *payload_ptr = base + sizeof(vpn_tunnel_hdr_t);
    
    uint32_t new_sid = 0;
    vpn_auth_t resp_payload;

    /* 2. Invoke our industrial-grade Auth Logic from auth.c */
    /* Note: Using a global token here; in production, fetch from config/DB */
    const uint8_t *expected_token = (const uint8_t *)"VFAST_SECRET";
    
    if (vfast_auth_verify((vpn_auth_t *)payload_ptr, expected_token) != 0) {
        log_warn("Unauthorized HELLO attempt from %s", inet_ntoa(data->udp_meta.client_addr.sin_addr));
        return false;
    }

    /* 3. Resource Allocation (Decoupled in your Control Plane) */
    uint32_t assigned_vip = vpn_ip_pool_alloc(&ctx->ip_pool);
    if (assigned_vip == 0) {
        log_error("IP Pool empty, dropping HELLO from %s", inet_ntoa(data->udp_meta.client_addr.sin_addr));
        return false;
    }

    /* 4. Generate SID and Persist Session */
    new_sid = vpn_generate_sid(assigned_vip);
    vpn_session_update(assigned_vip, new_sid, &data->udp_meta.client_addr);

    /* 5. Construct Response Packet in the SAME buffer (Zero-copy reuse) */
    vpn_tunnel_hdr_t *resp_hdr = (vpn_tunnel_hdr_t *)base;
    resp_hdr->version = VFAST_VERSION;
    resp_hdr->msg_type = VPN_MSG_HELLO; /* Response uses same type or a dedicated ACK type */
    resp_hdr->session_id = htonl(new_sid);

    /* Pack the auth response payload */
    vfast_auth_pack(&resp_payload, assigned_vip, expected_token, 0);
    memcpy(base + VPN_TNL_HLEN, &resp_payload, sizeof(vpn_auth_t));

    /* 6. Submit Async Write back to the Client */
    int resp_len = VPN_TNL_HLEN + sizeof(vpn_auth_t);

    log_info("Handshake Complete: VIP=%u.%u.%u.%u SID=0x%08x -> %s",
             (assigned_vip & 0xFF), (assigned_vip >> 8) & 0xFF,
             (assigned_vip >> 16) & 0xFF, (assigned_vip >> 24) & 0xFF, 
             new_sid, inet_ntoa(data->udp_meta.client_addr.sin_addr));

    return vfast_udp_writemsg(ctx, idx, resp_len, data);
}

/**
 * vfast_udp_forward - Core data plane forwarding logic.
 * Process a valid VFAST DATA packet and forward it to the TUN device.
 */
static bool vfast_udp_forward(vfast_ctx_t *ctx, int res, int idx, vpn_io_data_t *data) {
    int plen;
    uint32_t sid;
    struct msghdr *msg = &data->udp_meta.msg;

    /* 1. Packet Integrity Validation */
    if (unlikely(msg->msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
        log_warn("Received truncated UDP packet from client, dropping.");
        goto err;
    }

    /* 2. Decapsulate: Strip VFAST header and get pointer to inner IP packet */
    uint8_t *base = (uint8_t *)ctx->io_ring.iovecs[idx].iov_base;
    uint8_t *ip_pkt = vpn_unpack(ctx->key, base, res, &plen, &sid);
    
    if (likely(ip_pkt != NULL)) {
        struct iphdr *iph = (struct iphdr *)ip_pkt;
        
        /* 3. Update Session: Map Virtual IP to Public UDP Endpoint */
        vpn_session_update(iph->saddr, sid, &data->udp_meta.client_addr);
        data->sid = sid;

        /* 4. Forward: Write the inner IP packet to TUN device */
        vfast_tun_write(ctx, idx, data);
        return true;
    }

err:
    atomic_fetch_add(&ctx->stats.drop_unpack_error, 1);
    return false;
}

/**
 * @brief Periodically reports system throughput and error metrics.
 * * Logic:
 * 1. Calculates delta bytes and delta packets since the last report.
 * 2. Computes PPS (Packets Per Second) and Bandwidth.
 * 3. Automatically scales units (bps, Kbps, Mbps) to ensure visibility 
 * even during low-traffic periods (e.g., ICMP keep-alives).
 */
void vfast_report_performance(vfast_ctx_t *ctx) {
    static uint64_t last_bytes = 0;
    static uint64_t last_pkts = 0;
    static struct timespec last_time = {0}; 
    struct timespec now;
    
    clock_gettime(CLOCK_MONOTONIC, &now);

    /* Initialize baseline on first execution */
    if (unlikely(last_time.tv_sec == 0)) {
        last_time = now;
        last_bytes = atomic_load(&ctx->stats.rx_bytes);
        last_pkts = atomic_load(&ctx->stats.rx_packets);
        return;
    }

    /* Calculate elapsed time in seconds */
    double seconds = (now.tv_sec - last_time.tv_sec) + 
                     (now.tv_nsec - last_time.tv_nsec) / 1e9;

    /* Report threshold: 1.0 second interval */
    if (seconds >= 1.0) {
        uint64_t curr_bytes = atomic_load(&ctx->stats.rx_bytes);
        uint64_t curr_pkts = atomic_load(&ctx->stats.rx_packets);
        
        double delta_bytes = (double)(curr_bytes - last_bytes);
        double delta_pkts = (double)(curr_pkts - last_pkts);
        
        /* Calculate bits-per-second and packets-per-second */
        double bps = (delta_bytes * 8.0) / seconds;
        double pps = delta_pkts / seconds;

        /* Adaptive Unit Selection for Bandwidth Display */
        if (bps < 1024.0) {
            log_info("[PERF] BW: %.2f bps | PPS: %.0f | RX: %lu | Miss: %lu | Err: %lu", 
                     bps, pps, curr_pkts,
                     atomic_load(&ctx->stats.drop_session_miss),
                     atomic_load(&ctx->stats.drop_unpack_error));
        } else if (bps < (1024.0 * 1024.0)) {
            log_info("[PERF] BW: %.2f Kbps | PPS: %.0f | RX: %lu | Miss: %lu | Err: %lu", 
                     bps / 1024.0, pps, curr_pkts,
                     atomic_load(&ctx->stats.drop_session_miss),
                     atomic_load(&ctx->stats.drop_unpack_error));
        } else {
            log_info("[PERF] BW: %.2f Mbps | PPS: %.0f | RX: %lu | Miss: %lu | Err: %lu", 
                     bps / (1024.0 * 1024.0), pps, curr_pkts,
                     atomic_load(&ctx->stats.drop_session_miss),
                     atomic_load(&ctx->stats.drop_unpack_error));
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
        vpn_io_data_t *d = &ctx->io_data_pool[i];
        memset(d, 0, sizeof(vpn_io_data_t));
        
        d->sid = 0;

        if (i < IO_BUF_POOL_SIZE / 2) {
            /* Google -> Server -> Client */
            d->source = SOURCE_TUN;
            vfast_tun_read(ctx, i, d);
        } else {
            /* Client -> Server -> Google */
            d->source = SOURCE_UDP;
            vfast_udp_read(ctx, i, d);
        }
    }
    vpn_iouring_flush(&ctx->io_ring);
    
    log_info("I/O Pipeline Warmed: [Fixed Pool] TUN_WATCHERS: %d, UDP_WATCHERS: %d", 
             IO_BUF_POOL_SIZE / 2, IO_BUF_POOL_SIZE - (IO_BUF_POOL_SIZE / 2));
}

bool vfast_udp_rx(vfast_ctx_t *ctx, int res, int idx, vpn_io_data_t *data) {
    atomic_fetch_add(&ctx->stats.tx_packets, 1);
    atomic_fetch_add(&ctx->stats.tx_bytes, (uint64_t)res);

    uint8_t *base = (uint8_t *)ctx->io_ring.iovecs[idx].iov_base;
    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)base;

    /* Basic sanity check: must at least contain the 8-byte header */
    if (unlikely(res < (int)VPN_TNL_HLEN)) {
        atomic_fetch_add(&ctx->stats.drop_unpack_error, 1);
        return false;
    }

    switch (hdr->msg_type) {
    case VPN_MSG_DATA:
        return vfast_udp_forward(ctx, res, idx, data);
    case VPN_MSG_HELLO:
        return vfast_auth_request(ctx, res, idx, data);
    case VPN_MSG_KEEPALIVE:
        return vfast_keeplive(ctx, res, idx, data);
    case VPN_MSG_DISCONNECT:
    default:
        log_warn("Unknown msg_type 0x%02x from %s", 
                    hdr->msg_type, inet_ntoa(data->udp_meta.client_addr.sin_addr));
        return false;
    }
    return false;
}

bool vfast_tun_rx(vfast_ctx_t *ctx, int res, int idx, vpn_io_data_t *data) {
    atomic_fetch_add(&ctx->stats.rx_packets, 1);
    atomic_fetch_add(&ctx->stats.rx_bytes, (uint64_t)res);

    uint8_t *base = (uint8_t *)ctx->io_ring.iovecs[idx].iov_base;
    struct iphdr *iph = (struct iphdr *)(base + VPN_TNL_HLEN);
    struct sockaddr_in remote;

    if (unlikely(!vpn_session_lookup_by_ip(iph->daddr, &remote))) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->daddr, ip_str, sizeof(ip_str));
        log_warn("SESSION MISS: Kernel wants to send to %s, but I don't know this client!", ip_str);

        atomic_fetch_add(&ctx->stats.drop_session_miss, 1);
        return false;
    }

    int tlen = vpn_pack(ctx->key, base, res, IO_BUF_SIZE, VPN_MSG_DATA, data->sid);
    if (unlikely(tlen <= 0)) {
        atomic_fetch_add(&ctx->stats.drop_pack_error, 1);
        log_error("Pack failed");
        return false;
    }
    /* Send encapsulated packet to client's UDP endpoint. Use sendmsg so
     * we can specify destination per-packet (the server socket is not
     * connected to a single client). */
    memcpy(&data->udp_meta.client_addr, &remote, sizeof(remote));
    return vfast_udp_writemsg(ctx, idx, tlen, data);
}

bool vfast_udp_client_rx(vfast_ctx_t *ctx, int res, int idx, vpn_io_data_t *data) {
    UNUSED(res);

    uint8_t *base = (uint8_t *)ctx->io_ring.iovecs[idx].iov_base;
    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)base;

    vfast_fsm_update_rx();

    switch (hdr->msg_type) {
    case VPN_MSG_DATA:
        if (vfast_fsm_is_connected()) {
            // return vfast_tun_write(ctx, idx, data);

            int plain_ip_len = 0;
            uint32_t recv_sid = 0;

            /* 1. 解密操作：将 132 字节的加密包还原为 84 字节的明文 IP 包 */
            // 注意：base + VPN_TNL_HLEN 处开始是加密数据，解密后明文也会放在这里
            uint8_t *payload_ptr = vpn_unpack(ctx->key, base, res, &plain_ip_len, &recv_sid);

            if (unlikely(!payload_ptr)) {
                log_warn("Data packet decryption failed or MAC mismatch.");
                return false;
            }

            /* 2. 检查 SID 一致性：防止会话劫持或串扰 */
            // if (unlikely(recv_sid != client_fsm.sid)) {
            //     log_warn("SID mismatch: expected 0x%08x, got 0x%08x", client_fsm.sid, recv_sid);
            //     return false;
            // }

            /* 3. 更新数据长度：告诉 vfast_tun_write 应该写入多少字节 (plain_ip_len) */
            // 如果不更新这个长度，TUN 依然会尝试写入原始的 132 字节，导致内核报错
            data->buf_len = plain_ip_len;

            /* 4. 写入 TUN 设备 */
            return vfast_tun_write(ctx, idx, data);
        }
        break;
    case VPN_MSG_HELLO: {
        vpn_auth_t *auth = (vpn_auth_t *)(base + VPN_TNL_HLEN);
        client_fsm.sid = ntohl(hdr->session_id);
        client_fsm.vip = auth->vip;

        /* 2. Dynamic IP Configuration */
        char ip_str[16];
        struct in_addr in = { .s_addr = auth->vip };
        inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str));
        vpn_tun_set_ip(ctx->tun.name, ip_str, VFAST_BROADCAST);

        atomic_store(&client_fsm.state, ST_CONNECTED);
        log_info("FSM: Authentication Successful. Virtual IP: %s SID: 0x%08x", ip_str, client_fsm.sid);
        break;
    }
    case VPN_MSG_KEEPALIVE:
    default:
        break;
    }
    return false;
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
bool vfast_tun_client_rx(vfast_ctx_t *ctx, int res, int idx, vpn_io_data_t *data) {
    /* 1. Telemetry and Statistics Update
     * Using atomic operations to ensure thread-safety for monitoring tools. */
    atomic_fetch_add(&ctx->stats.rx_packets, 1);
    atomic_fetch_add(&ctx->stats.rx_bytes, (uint64_t)res);

    /* 2. Zero-Copy Encapsulation
     * Access the pre-registered fixed buffer. The protocol expects an 8-byte 
     * headroom at the beginning of the buffer to host the VFAST header. */
    uint8_t *base_ptr = (uint8_t *)ctx->io_ring.iovecs[idx].iov_base;

    /* vpn_pack logic:
     * - Writes the header starting at base_ptr[0].
     * - Expects the raw IP packet to already be at base_ptr[8].
     * - Returns: Total length (Header + Payload) or <= 0 on failure. */
    int total_len = vpn_pack(ctx->key, base_ptr, res, IO_BUF_SIZE, VPN_MSG_DATA, data->sid);

    // log_debug("POST-PACK [idx:%d]: total_len=%d, sid=0x%x", idx, total_len, data->sid);

    if (unlikely(total_len <= 0)) {
        atomic_fetch_add(&ctx->stats.drop_pack_error, 1);
        log_error("Pack failed");
        return false;
    }

    return vfast_udp_write(ctx, idx, total_len, data);
}

/**
 * vfast_keep - Process heartbeat and send acknowledgment back to client.
 */
bool vfast_keeplive(vfast_ctx_t *ctx, int res, int idx, vpn_io_data_t *data) {
    uint8_t *base = (uint8_t *)ctx->io_ring.iovecs[idx].iov_base;
    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)base;
    struct sockaddr_in *client_addr = &data->udp_meta.client_addr;

    uint32_t v_ip;
    struct sockaddr_in old_addr;
    uint32_t hsid = ntohl(hdr->session_id);

    /* 1. Session Validation & Update */
    if (likely(vpn_session_lookup_by_sid(hsid, &v_ip, &old_addr))) {
        
        /* Refresh last_seen and handle potential NAT roaming */
        vpn_session_update(v_ip, hsid, client_addr);

        /* Log roaming if the public endpoint changed */
        if (unlikely(memcmp(&old_addr, client_addr, sizeof(struct sockaddr_in)) != 0)) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr->sin_addr, ip_str, sizeof(ip_str));
            log_info("ROAM: SID[0x%08x] now at %s:%d", hsid, ip_str, ntohs(client_addr->sin_port));
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
        return vfast_udp_writemsg(ctx, idx, res, data);
    } else {
        /* Session doesn't exist (possibly expired) */
        log_warn("KEEPALIVE REJECTED: Unknown SID 0x%08x", hsid);
        /* OPTIONAL: Send a special 'Reset' packet or just drop and let client re-auth */
        return false;
    }
}

/**
 * @brief Loads the 256-bit master key from a binary file.
 * Industrial Security: Checks for file existence and size integrity.
 * @param key_path Path to the key file (e.g., "vfast.key").
 * @param out_key  Buffer to store the 32-byte key.
 * @return 0 on success, -1 on failure.
 */
int vfast_load_key(const char *key_path, uint8_t out_key[CRYPTO_KEY_SIZE]) {
    if (unlikely(!key_path || !out_key)) return -1;

    int fd = open(key_path, O_RDONLY);
    if (fd < 0) {
        log_error("Failed to open key file '%s': %s", key_path, strerror(errno));
        log_error("HINT: Run './vfast_server --keygen' to generate a new key.");
        return -1;
    }
    /* Standard security check: Ensure the file isn't a directory or symlink trickery */
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        log_error("Invalid key file type: %s", key_path);
        close(fd);
        return -1;
    }

    /* Load exactly 32 bytes */
    ssize_t bytes_read = read(fd, out_key, CRYPTO_KEY_SIZE);
    close(fd);

    if (bytes_read != CRYPTO_KEY_SIZE) {
        log_error("Key file '%s' is corrupted (Size: %zd, Expected: %d)", 
                  key_path, bytes_read, CRYPTO_KEY_SIZE);
        vpn_secure_cleanup(out_key, CRYPTO_KEY_SIZE);
        return -1;
    }

    log_info("Master key [%s] loaded into secure memory.", key_path);
    return 0;
}
