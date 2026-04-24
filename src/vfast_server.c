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
#include <locale.h>
#include <liburing.h>

#include "log.h"
#include "utils.h"
#include "auth.h"
#include "session.h"
#include "zmalloc.h"
#include "udp.h"
#include "protocol.h"
#include "option.h"
#include "tun.h"
#include "io.h"
#include "vfast.h"
#include "cmd.h"
#include "cmdengine.h"
#include "logo.h"

struct vfast_server {
    vpn_option_t    opt;
    vfast_io_t      io;
    udp_conn_t     *udp;       /* UDP transport handle */
    vpn_tun_ctx_t   tun;       /* Virtual network interface */
    vpn_ip_pool_t   ip_pool;   /* IP address management */
    pthread_t       cmd_tid;   /* cmd server thread id */
    struct {
        atomic_uint_least64_t rx_pkts;
        atomic_uint_least64_t tx_pkts;
        atomic_uint_least64_t drops;
    } stats;
} vfserver;

/* Simple signal handling for graceful shutdown */
static void signal_handler(int sig) {
    (void)sig;
    atomic_store(&vfserver.io.running, false);
    log_info("Signal received, initiating shutdown...");
}

/**
 * @brief Processes HELLO packet and submits an asynchronous response.
 * Optimization Highlights:
 * 1. Zero-copy Response Construction: Invokes vf_auth_pack directly on the 
 * task buffer to eliminate redundant stack allocation and memcpy.
 * 2. Pre-calculated Offsets: Minimizes pointer arithmetic during the hot path.
 * 3. Atomic Stats Integration: (Optional but recommended) for monitoring.
 * @param io    Pointer to the io_uring engine context.
 * @param s     The session context associated with this request (if any).
 * @param res   Actual bytes received from the CQE.
 * @param buf   Pointer to the specific task's buffer (task->buf).
 * @param src   Source address of the requesting client.
 * @return true if the request was handled successfully, false otherwise.
 */
static bool vfast_handle_hello(vfast_io_t *io, uint8_t *payload, int plen, struct sockaddr_in *src) {
    if (unlikely(plen < (int)sizeof(vpn_auth_t))) {
        log_warn("Malformed HELLO from %s", inet_ntoa(src->sin_addr));
        return false;
    }

    /* 2. Zero-copy mapping of the auth structure */
    vpn_auth_t *auth = (vpn_auth_t *)payload;

    /* 3. Authentication: Validate client token */
    const uint8_t *secret = (const uint8_t *)VFAST_TOKEN;
    if (vf_auth_verify(auth, secret) != 0) {
        log_warn("Auth failed: %s", inet_ntoa(src->sin_addr));
        return false;
    }

    /* 4. IPAM: Allocate Virtual IP from the global address pool */
    uint32_t vip = vf_ip_pool_alloc(&vfserver.ip_pool);
    if (unlikely(vip == 0)) {
        log_error("Resource exhaustion: IP Pool is empty. Rejecting %s", inet_ntoa(src->sin_addr));
        return false;
    }
    /* 5. Session Management: Generate SID and link VIP to physical address */
    uint32_t sid = vf_ss_generate_sid(vip);
    vf_ss_update(vip, sid, src);

    /* 6. Response Construction: Reuse the same buffer for Egress (Zero-copy) */
    vpn_session_t *s = NULL;
    if (!vf_ss_lookup_by_sid(sid, &s)) {
        log_error("Unexpected error: Session not found after creation for SID[0x%08x]", sid);
        return false;
    }

    /**
     * 6. Response Construction: Use vf_pack for the full pipeline.
     * We need to find the base buffer. Assuming payload = buf + VPN_TNL_HLEN.
     */
    uint8_t *base_buf = payload - VPN_TNL_HLEN;

    /* Pack response data into the payload area */
    vf_auth_pack(auth, vip, secret, s->sec_ctx.active_key.id, 
                    s->sec_ctx.active_key.raw, 0);

    /**
     * 7. The Security Pipeline: [Padding] -> [Header] -> [Obfuscation]
     * We call vf_pack with type HELLO. This handles:
     * - Random padding (to hide handshake size)
     * - Header filling (SID/KID)
     * - Header obfuscation (XOR masking)
     */
    int tlen = vf_pack(NULL, base_buf, (int)sizeof(vpn_auth_t), 
                             BUF_SIZE, VPN_MSG_HELLO, sid);

    if (unlikely(tlen < 0)) return false;

    /* 8. Asynchronous Dispatch */
    log_info("Handshake Success | VIP: %u.%u.%u.%u | SID: 0x%08x | To: %s",
             (vip & 0xFF), (vip >> 8) & 0xFF, (vip >> 16) & 0xFF, (vip >> 24) & 0xFF, 
             sid, inet_ntoa(src->sin_addr));

    vfast_submit_write(io, io->udp_fd, OP_UDP_SEND, base_buf, tlen, src);

    return true;
}

/**
 * @brief Processes HEARTBEAT/KEEPALIVE packets and refreshes session state.
 * Optimization Highlights:
 * 1. NAT Roaming Detection: Compares the source address to detect network changes 
 * (e.g., switching from Wi-Fi to 5G) and updates the session routing table.
 * 2. In-place Echo: Reuses the ingress buffer to construct the ACK, updating 
 * only necessary timestamps and VIP fields.
 * 3. Branch Prediction: Uses likely/unlikely hints to optimize the CPU pipeline 
 * for the "hot path" (successful session lookup).
 * @param io    Pointer to the io_uring engine context.
 * @param s     The session context associated with this request.
 * @param res   Number of bytes received (cqe->res).
 * @param buf   Pointer to the task buffer (task->buf).
 * @param src   Physical source address of the client.
 * @return true if the keepalive was processed/ACKed, false otherwise.
 */
static bool vfast_keeplive(vfast_io_t *io, vpn_session_t *s, uint8_t *payload, int plen, struct sockaddr_in *src) {
    UNUSED(plen);
    /* 1. Basic Length Validation */
    if (unlikely(!s)) {
        return false;
    }

    /* 2. NAT Roaming Detection
     * Compare current source address with the known session endpoint.
     * If they differ, the client has likely switched networks or ports.
     */
    if (unlikely(s->remote_addr.sin_addr.s_addr != src->sin_addr.s_addr || 
                 s->remote_addr.sin_port != src->sin_port)) {
        
        char old_ip[INET_ADDRSTRLEN], new_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &s->remote_addr.sin_addr, old_ip, sizeof(old_ip));
        inet_ntop(AF_INET, &src->sin_addr, new_ip, sizeof(new_ip));

        log_info("ROAM: SID[0x%08x] migrated from %s:%d to %s:%d", 
                 s->session_id, old_ip, ntohs(s->remote_addr.sin_port),
                 new_ip, ntohs(src->sin_port));
    }

    /* 3. Session Refresh: Update VIP-SID mapping and 'last_seen' timestamp */
    vf_ss_update(s->virtual_ip, s->session_id, src);

    /* 4. Response Construction (In-place)
     * Update the heartbeat structure with current server-side metadata.
     */
    vpn_auth_t *res = (vpn_auth_t *)payload;
    uint64_t ts = (uint64_t)time(NULL);
    vf_auth_pack(res, s->virtual_ip, (uint8_t *)VFAST_TOKEN, 
                    s->sec_ctx.active_key.id, NULL, ts);

    /**
     * 5. Egress Pipeline: [Padding] -> [Header Fill] -> [Obfuscation]
     * We use vf_pack to re-seal the packet. 
     * Even if KEEPALIVE is plain-text, vf_pack will:
     * - Apply random padding (hiding the fixed heartbeat size).
     * - XOR the header (masking SID and MsgType).
     */
    uint8_t *base_buf = payload - VPN_TNL_HLEN;
    
    /* We use sizeof(vpn_auth_t) to ensure the ACK contains fresh metadata */
    int tlen = vf_pack(&s->sec_ctx, base_buf, (int)sizeof(vpn_auth_t), 
                             BUF_SIZE, VPN_MSG_KEEPALIVE, s->session_id);

    if (unlikely(tlen < 0)) {
        log_error("Failed to pack keepalive ACK for SID: 0x%08x", s->session_id);
        return false;
    }

    /* 6. Asynchronous Submission
     * Hand the re-masked packet back to the network stack via io_uring.
     */
    vfast_submit_write(io, io->udp_fd, OP_UDP_SEND, base_buf, tlen, src);
    
    return true;
}

/**
 * @brief Processes decrypted VPN data packets and forwards them to the TUN interface.
 * * This internal helper handles the decryption, validation, and submission 
 * to the virtual network device.
 */
static inline void vfast_handle_data(vfast_io_t *io, vpn_session_t *s, uint8_t *payload, int plen, struct sockaddr_in *src) {
    UNUSED(s);
    UNUSED(src);

    vfast_submit_write(io, io->tun_fd, OP_TUN_WRITE, payload, plen, NULL);
}

/**
 * @brief Handles Rekey Request: [Verify KID] -> [Load Next Key] -> [ACK] -> [Commit]
 * @param payload Decrypted/Unpadded payload from vf_unpack.
 * @param plen    Length of the decrypted payload.
 */
static inline void vfast_handle_rekey_req(vfast_io_t *io, vpn_session_t *s, 
                                          uint8_t *payload, int plen, struct sockaddr_in *src) {
    /* 1. Validation: Payload should contain [KeyID (4B)][Raw Key (32B)] */
    const int req_size = 4 + REKEY_KEY_SIZE;
    if (unlikely(!payload || plen < req_size || !s)) return;

    /* 2. Parse Key ID and Raw Key from the decrypted payload */
    uint32_t r_kid = ntohl(*(uint32_t *)payload);
    uint8_t *r_key = payload + 4;

    /* 3. Security Validation: Ensure monotonic increase of Key ID */
    if (unlikely(r_kid <= s->sec_ctx.active_key.id)) {
        log_warn("REKEY: Stale KeyID %u (Current: %u) from SID[0x%08x]", 
                 r_kid, s->sec_ctx.active_key.id, s->session_id);
        return;
    }

    /* 4. Stage the next key into the security context */
    memcpy(s->sec_ctx.next_key.raw, r_key, REKEY_KEY_SIZE);
    s->sec_ctx.next_key.id = r_kid;
    s->sec_ctx.next_key.created_at = time(NULL);
    atomic_store(&s->sec_ctx.next_key.bytes_processed, 0);

    /**
     * 5. Acknowledge the client (VPN_MSG_REKEY_ACK)
     * We reuse the incoming buffer area for the response.
     * The ACK payload echoes the received KeyID to confirm receipt.
     */
    uint8_t *base_buf = payload - VPN_TNL_HLEN;
    
    /* Prepare ACK payload: just the 4-byte KeyID */
    *(uint32_t *)payload = htonl(r_kid);

    /* Security Pipeline: Padding + Obfuscation for the ACK */
    int flen = vf_pack(&s->sec_ctx, base_buf, 4, BUF_SIZE, VPN_MSG_REKEY_ACK, s->session_id);

    if (likely(flen > 0)) {
        vfast_submit_write(io, io->udp_fd, OP_UDP_SEND, base_buf, flen, src);
    }

    /**
     * 6. Transition Commitment
     * Promote 'next_key' to 'active_key'. The previous key is kept in a 
     * grace-period slot to handle late-arriving packets from the client.
     */
    vf_rekey_commit(&s->sec_ctx);
    
    log_info("REKEY: Switched to KeyID %u for SID 0x%08x", r_kid, s->session_id);
}

/**
 * @brief Handles a Rekey Acknowledgment from the client (Active Rekey Response).
 * The server previously sent a REQ, and the client has confirmed receipt.
 */
static inline void vfast_handle_rekey_ack(vpn_session_t *s) {
    if (unlikely(!s->sec_ctx.rekey_pending)) {
        log_warn("REKEY: Received unexpected ACK for SID[0x%08x]", s->session_id);
        return;
    }

    /* Client is ready, we can now safely rotate keys */
    vf_rekey_commit(&s->sec_ctx);
    
    log_info("REKEY: Committed for SID[0x%08x] (Server-initiated)", s->session_id);
}

/**
 * @brief Handles Data from UDP (Public Internet -> Virtual Network)
 * Decapsulates the VPN header, decrypts the payload, and writes the 
 * resulting plain IP packet to the TUN device.
 */
static int server_on_udp(vfast_io_t *io, uint8_t *data, int len, struct sockaddr_in *src, void *arg) {
     UNUSED(arg);
     /* 1. Basic Validation: Ensure packet is large enough to contain header */
    if (unlikely(len < (int)sizeof(vpn_tunnel_hdr_t))) {
        atomic_fetch_add(&vfserver.stats.drops, 1);
        cmd_reass_stats_add(0, 0, 1);
        return -1;
    }

    uint32_t sid = 0;
    int plen = 0;
    vpn_session_t *s = NULL;
    uint8_t *payload = NULL;

    /* Handled manually at the entrance for total control. */
    vf_remove_header_obfs(data, (size_t)len);

    /* 1. Map the VPN header to extract session information */
    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)data;

    sid = ntohl(hdr->session_id);
    if (sid != 0) {
        if (!vf_ss_lookup_by_sid(sid, &s)) {
            atomic_fetch_add(&vfserver.stats.drops, 1);
            log_warn("No session found for SID[0x%08x] from %s. Packet dropped.", sid, inet_ntoa(src->sin_addr));
        }
    }

    payload = vf_unpack(s ? &s->sec_ctx : NULL, data, len, &plen);
    if (unlikely(!payload)) {
        log_warn("Ingress: Decryption failed or invalid packet from %s", 
                 inet_ntoa(src->sin_addr));
        atomic_fetch_add(&vfserver.stats.drops, 1);
        cmd_reass_stats_add(0, 0, 1);
        return -1;
    }

    if (s) atomic_fetch_add(&s->sec_ctx.active_key.bytes_processed, (long)len);
    
    /* 3. Dispatch based on message type */
    switch (hdr->msg_type) {
        case VPN_MSG_DATA: 
            vfast_handle_data(io, s, payload, plen, src);
            break;
        case VPN_MSG_HELLO:
            vfast_handle_hello(io, payload, plen, src);
            break;
        case VPN_MSG_KEEPALIVE:
            vfast_keeplive(io, s, payload, plen, src);
            break;
        case VPN_DPD_RESPONSE:
            log_info("Received DPD Response from %s. Session is alive.", inet_ntoa(src->sin_addr));
            vf_ss_update_by_sid(ntohl(hdr->session_id), src);
            break;
        case VPN_MSG_REKEY_ACK:
            vfast_handle_rekey_ack(s);
            break;
        case VPN_MSG_REKEY_REQ:
            vfast_handle_rekey_req(io, s, payload, plen, src);
            break;
        default:
            log_warn("Unknown VPN msg type: 0x%02x", hdr->msg_type);
            break;
    }

    atomic_fetch_add(&vfserver.stats.rx_pkts, 1);
    cmd_reass_stats_add(1, 0, 0);
    return 0;
}

/**
 * @brief Handles Data from TUN (Egress Path: Virtual Network -> Public Internet).
 * * This implementation achieves true Zero-Copy by utilizing pre-allocated header 
 * room in the task buffer. Instead of borrowing a new task and performing 
 * memcpy, we back-calculate the buffer head and pack the VPN encapsulation 
 * directly in-place.
 */
static int server_on_tun(vfast_io_t *io, uint8_t *data, int len, struct sockaddr_in *src, void *arg) {
    UNUSED(src);
    UNUSED(arg);

    /**
     * 1. Fast boundary check: Ensure L3 header is present and buffer has headroom.
     * Fixed: Explicitly cast the capacity calculation to (int) to resolve sign-compare warnings.
     */
    if (unlikely(len < (int)sizeof(struct iphdr) || len > (int)(BUF_SIZE - sizeof(vpn_tunnel_hdr_t)))) {
        atomic_fetch_add(&vfserver.stats.drops, 1);
        cmd_reass_stats_add(0, 0, 1);
        return -1;
    }

    /**
     * 2. Zero-Copy Back-calculation.
     * Since the IO engine reads TUN data with an offset of sizeof(vpn_tunnel_hdr_t),
     * the 'data' pointer passed here is already positioned for in-place packing.
     */
    uint8_t *task_buf_base = data - sizeof(vpn_tunnel_hdr_t);

    /* 3. L3 Header Analysis: Extract Destination Virtual IP (Network Byte Order) */
    const struct iphdr *iph = (const struct iphdr *)data;
    const uint32_t dest_vip = iph->daddr;

    /* 4. Session Lookup: Map VIP to client endpoint and session security context */
    vpn_session_t *s = NULL;
    if (!vf_ss_lookup_by_ip(dest_vip, &s)) {
        atomic_fetch_add(&vfserver.stats.drops, 1);
        cmd_reass_stats_add(0, 0, 1);
        return -1;
    }

    /**
     * 5. In-place AEAD Encryption & Packet Packing.
     * The vf_pack function now writes the header at task_buf_base and encrypts 
     * the payload at 'data' in-situ. This eliminates the need for memcpy.
     */
    int total_len = vf_pack(&s->sec_ctx,  /* Encryption Key */
                             task_buf_base, 
                             len, 
                             BUF_SIZE, 
                             VPN_MSG_DATA, 
                             s->session_id);

    if (likely(total_len > 0)) {
        /**
         * 6. Asynchronous UDP Transmission.
         * We submit the original task buffer, which now contains [Header + Encrypted Payload].
         * CRITICAL: The task's 'in_use' flag must NOT be cleared until the 
         * OP_UDP_SEND completion is reaped in vfast_io_run.
         */
        vfast_submit_write(io, io->udp_fd, OP_UDP_SEND, task_buf_base, total_len, &s->remote_addr);
        
        atomic_fetch_add(&vfserver.stats.tx_pkts, 1);
        cmd_reass_stats_add(0, 1, 0);
        
        /**
         * 7. Signal Task Retention.
         * Returning 1 informs the IO loop that this specific task has been 
         * chained to an outbound write operation and should not be recycled yet.
         */
        return 0; 
    } else {
        log_error("Egress: Packing failed for VIP 0x%08x", ntohl(dest_vip));
        atomic_fetch_add(&vfserver.stats.drops, 1);
        cmd_reass_stats_add(0, 0, 1);
    }

    return -1;
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
    sa.sa_handler = signal_handler;
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
    if (vfserver.udp) {
        udp_close(vfserver.udp);
        vfserver.udp = NULL;
    }

    /* 3. Close the TUN device */
    vf_tun_destroy(&vfserver.tun);

    /* 4. Business logic teardown */
    vf_ss_destroy();
    vf_ip_pool_destroy(&vfserver.ip_pool);

    /* 5. Cleanup io_uring */
    vfast_io_exit(&vfserver.io);
    cmd_server_stop(&vfserver.cmd_tid);
    vf_option_clean(&vfserver.opt);

    log_info("VFAST server halted safely.");
    return 0;
}

static int vfast_init_server(void) {
    memset(&vfserver.io, 0, sizeof(vfast_io_t));
    atomic_store(&vfserver.io.running, true);

    if (vfast_load_key(vfserver.opt.keyfile, vfserver.opt.master_key) < 0) {
        log_error("Failed load key file.");
        return -1;
    }

    /* 1. Setup specialized signal handling */
    if (vfast_setup_signals() < 0) return -1;

    /* Initialize IPAM (The IP Pool) - MUST be before sessions */
    /* Starting from 10.0.0.0 with 65536 addresses (/16) */
    if (vf_ip_pool_init(&vfserver.ip_pool, 
        vfserver.opt.pool_network, vfserver.opt.pool_size) != 0) {
        log_error("Failed to initialize IP Pool");
        return -1;
    }

    if (vf_ss_init() < 0) {
        log_error("Failed to initialize session manager");
        return -1;
    }

    if (vf_tun_init(&vfserver.tun, vfserver.opt.tun_name, 0) < 0) {
        log_error("Failed to initialize TUN device");
        return -1;
    }
    vf_tun_disable_ipv6(vfserver.opt.tun_name);
    vf_tun_set_ip(vfserver.tun.name, vfserver.opt.tun_ip, VFAST_BROADCAST);
    vf_tun_set_status(vfserver.tun.name, vfserver.opt.mtu, 1); /* MTU 1400 to allow header overhead */
    vf_set_nonblocking(vfserver.tun.fd);

    vfserver.udp = udp_init_listener(vfserver.opt.local_port, vfserver.opt.udp_backlog); 
    if (!vfserver.udp) {
        log_error("Failed to init UDP listener");
        goto cleanup;
    }
    vf_set_nonblocking(vfserver.udp->fd);
    
    vfast_ops_t ops = {
        .on_udp_data = server_on_udp,
        .on_tun_data = server_on_tun,
        .ctx = NULL
    };
    vfast_io_init(
        &vfserver.io, 
        vfserver.udp->fd, 
        vfserver.tun.fd, 
        vfserver.opt.io_pool_size, 
        vfserver.opt.io_ring_depth, 
        ops
    );

    vfast_io_set_timer(&vfserver.io, 5000, vfast_server_maintenance, &vfserver.ip_pool);
    vfast_io_set_pmtud_callback(&vfserver.io, vfast_path_mtu_updated, &vfserver.io);

    vfserver.cmd_tid = cmd_start_core();

    return 0;

cleanup:
    vfast_clean_server();
    return -1;
}

static void version(void) {
    printf("vfast server v=%d\n", VFAST_VERSION);
    exit(0);
}

static void usage(void) {
    fprintf(stderr,"Usage: ./vfast_server [/path/to/config.conf]\n");
    fprintf(stderr,"       ./vfast_server -g or --keygen\n");
    fprintf(stderr,"       ./vfast_server -v or --version\n");
    fprintf(stderr,"       ./vfast_server -h or --help\n");
    fprintf(stderr,"Examples:\n");
    fprintf(stderr,"       ./vfast_server (run the server with default conf)\n");
    fprintf(stderr,"       ./vfast_server /etc/vfast_server/config.conf\n");
    exit(1);
}

/* * Core Event Loop - Optimized for Clarity
 */
int main(int argc, char *argv[]) {
    int j;
    /* The setlocale() function is used to set or query the program's current locale.
     * 
     * The function is used to set the current locale of the program and the 
     * collation of the specified locale. Specifically, the LC_COLLATE parameter
     * represents the collation of the region. By setting it to an empty string,
     * the default locale collation is used.*/
    setlocale(LC_COLLATE, "");

    /* The  tzset()  function initializes the tzname variable from the TZ environment variable.  
     * This function is automati‐cally called by the other time conversion functions 
     * that depend on the timezone.*/
    tzset();

    vf_option_init(&vfserver.opt);

    if (argc >= 2) {
        j = 1;
        char *configfile = NULL;
        char *tp = NULL;
        /* Handle special options --help and --version */
        if (strcmp(argv[1], "-v") == 0 ||
            strcmp(argv[1], "--version") == 0) version();
        if (strcmp(argv[1], "--help") == 0 ||
            strcmp(argv[1], "-h") == 0) usage();
        if (strcmp(argv[1], "-g") == 0 || 
            strcmp(argv[1], "--keygen") == 0)
            vfast_cmd_keygen();
        /* First argument is the config file name? */
        if (argv[j][0] != '-' || argv[j][1] != '-') {
            configfile = argv[j];
            if ((tp = (char*)vf_get_absolute_path(configfile)) != NULL) {
                zfree(vfserver.opt.cfile);
                vfserver.opt.cfile = tp;
            } else {
                log_info("Warning: no config file specified, using the default config.");
            }
        }
    }

    vf_option_conf(&vfserver.opt, vfserver.opt.cfile);

    vf_show_random_banner(true, "1.0.1", "yanruibing", vfserver.opt.tun_ip);

    if (vfast_init_server() < 0) return 1;

    log_info("VFAST server is up and running on port %d. Press Ctrl+C to stop.", vfserver.opt.local_port);

    vfast_io_run(&vfserver.io);

    vfast_clean_server();
    return 0;
}