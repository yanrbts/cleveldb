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

struct vfast_server {
    vpn_option_t    opt;
    vfast_io_t      io;
    udp_conn_t     *udp;       /* UDP transport handle */
    vpn_tun_ctx_t   tun;       /* Virtual network interface */
    vpn_ip_pool_t   ip_pool;   /* IP address management */

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
 * 1. Zero-copy Response Construction: Invokes vfast_auth_pack directly on the 
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
static bool vfast_auth_request(vfast_io_t *io, int res, uint8_t *buf, struct sockaddr_in *src) {
    /* 1. Pre-calculate response length and boundary check */
    const int auth_size = (int)sizeof(vpn_auth_t);
    const int head_size = (int)sizeof(vpn_tunnel_hdr_t);
    const int resp_len  = head_size + auth_size;

    /* Validate input length: must accommodate both header and auth payload */
    if (unlikely(res < resp_len)) {
        log_warn("Dropped malformed HELLO packet (size %d) from %s", res, inet_ntoa(src->sin_addr));
        return false;
    }

    /* 2. Direct pointer mapping (Zero-copy) */
    // vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)buf;
    vpn_auth_t *auth_ptr  = (vpn_auth_t *)(buf + head_size);

    /* 3. Authentication: Validate client token using existing logic */
    const uint8_t *expected_token = (const uint8_t *)"VFAST_SECRET"; 
    int ret = vfast_auth_verify(auth_ptr, expected_token);
    if (ret != 0) {
        log_warn("Authentication failed for client: %s %d", inet_ntoa(src->sin_addr), ret);
        return false;
    }

    /* 4. IPAM: Allocate Virtual IP from the global address pool */
    uint32_t assigned_vip = vpn_ip_pool_alloc(&vfserver.ip_pool);
    if (unlikely(assigned_vip == 0)) {
        log_error("Resource exhaustion: IP Pool is empty. Rejecting %s", inet_ntoa(src->sin_addr));
        return false;
    }

    /* 5. Session Management: Generate SID and link VIP to physical address */
    uint32_t new_sid = vpn_generate_sid(assigned_vip);
    vpn_session_update(assigned_vip, new_sid, src);

    /* 6. Response Construction: Reuse the same buffer for Egress (Zero-copy) */
    vpn_session_t *s = NULL;
    if (!vpn_lookup_session_by_sid(new_sid, &s)) {
        log_error("Unexpected error: Session not found after creation for SID[0x%08x]", new_sid);
        return false;
    }

    // /* Update Header Fields */
    // hdr->version    = VFAST_VERSION;
    // hdr->msg_type   = VPN_MSG_HELLO; 
    // hdr->session_id = htonl(new_sid); // Ensure Network Byte Order
    // hdr->flags      = 0;
    // hdr->key_id     = s->sec_ctx.active_key.id; // Include Key ID for client reference

    vpn_fill_header(buf, VPN_MSG_HELLO, new_sid, s->sec_ctx.active_key.id);

    /* 7. Optimized Packing:
     * Directly pack response data into the task buffer.
     * This avoids: 'vpn_auth_t tmp; vfast_auth_pack(&tmp...); memcpy(dest, &tmp...);'
     */
    vfast_auth_pack(
        auth_ptr, 
        assigned_vip, 
        expected_token, 
        s->sec_ctx.active_key.id, 
        s->sec_ctx.active_key.raw,
        0
    );

    /* 8. Asynchronous Dispatch */
    log_info("Handshake assigned VIP %u.%u.%u.%u [SID: 0x%08x] to %s",
             (assigned_vip & 0xFF), (assigned_vip >> 8) & 0xFF,
             (assigned_vip >> 16) & 0xFF, (assigned_vip >> 24) & 0xFF, 
             new_sid, inet_ntoa(src->sin_addr));

    /* Submit the buffer back to the network via io_uring */
    vfast_submit_write(io, io->udp_fd, OP_UDP_SEND, buf, resp_len, src);

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
static bool vfast_keeplive(vfast_io_t *io, vpn_session_t *s, uint8_t *buf, int res , struct sockaddr_in *src) {
    UNUSED(s);

    /* 1. Basic Length Validation */
    if (unlikely(res < (int)sizeof(vpn_tunnel_hdr_t))) {
        return false;
    }

    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)buf;
    uint32_t hsid = ntohl(hdr->session_id);
    uint32_t v_ip;
    struct sockaddr_in old_addr;

    /* 2. Session Validation: Fast lookup in the session table */
    if (likely(vpn_session_lookup_by_sid(hsid, &v_ip, &old_addr))) {
        
        /* 3. Handle NAT Roaming / Endpoint Change
         * If the client's source IP or Port has changed, we log the event 
         * and update the session mapping to ensure downlink traffic finds them.
         */
        if (unlikely(old_addr.sin_addr.s_addr != src->sin_addr.s_addr || 
                     old_addr.sin_port != src->sin_port)) {
            
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src->sin_addr, ip_str, sizeof(ip_str));
            log_info("ROAM: SID[0x%08x] migrated from %s:%d to %s:%d", 
                     hsid, 
                     inet_ntoa(old_addr.sin_addr), ntohs(old_addr.sin_port),
                     ip_str, ntohs(src->sin_port));
        }

        /* 4. Refresh Session: Update 'last_seen' timestamp and endpoint */
        vpn_session_update(v_ip, hsid, src);

        /* 5. Response Construction (Zero-copy Echo)
         * We reuse the header and update the payload with current server state.
         * Note: We assume the packet contains a vpn_auth_t payload for heartbeat.
         */
        if (res >= (int)(sizeof(vpn_tunnel_hdr_t) + sizeof(vpn_auth_t))) {
            vpn_auth_t *payload = (vpn_auth_t *)(buf + sizeof(vpn_tunnel_hdr_t));
            
            /* Update heartbeat metadata */
            payload->ts  = (uint64_t)time(NULL);
            payload->vip = v_ip; 
            payload->magic = htonl(0x56465354); // "VFST"
        }

        /* 6. Submit Asynchronous ACK via io_uring
         * By sending back the same length 'res', we ensure protocol consistency.
         */
        vfast_submit_write(io, io->udp_fd, OP_UDP_SEND, buf, res, src);
        
        return true;

    } else {
        /* Session has likely expired or the client is unauthorized */
        log_warn("KEEPALIVE REJECTED: Session 0x%08x not found for %s", 
                 hsid, inet_ntoa(src->sin_addr));
        
        /* Future expansion: Submit a VPN_MSG_DISCONNECT to force client re-auth */
        return false;
    }
}

/**
 * @brief Processes decrypted VPN data packets and forwards them to the TUN interface.
 * * This internal helper handles the decryption, validation, and submission 
 * to the virtual network device.
 */
static inline void vfast_handle_data_msg(vfast_io_t *io, vpn_session_t *s, uint8_t *data, int len, struct sockaddr_in *src) {
    int plain_len = 0;
    uint32_t recv_sid = 0;

    /**
     * CRITICAL: Decrypt and Unpack.
     * vpn_unpack performs in-place decryption and returns a pointer to the 
     * start of the plain IP packet.
     */
    // uint8_t *payload_ptr = vpn_unpack(vfserver.opt.master_key, data, len, 
    //                                   &plain_len, &recv_sid);

    uint8_t *payload_ptr = vpn_unpack(&s->sec_ctx, data, len, 
                                      &plain_len, &recv_sid);

    if (unlikely(!payload_ptr || plain_len <= 0)) {
        log_warn("Ingress: Decryption failed or invalid packet from %s", 
                 inet_ntoa(src->sin_addr));
        
        atomic_fetch_add(&vfserver.stats.drops, 1);
        return;
    }

    /**
     * Submit to TUN.
     * The kernel will receive a valid, decrypted IPv4/IPv6 packet.
     */
    vfast_submit_write(io, io->tun_fd, OP_TUN_WRITE, payload_ptr, plain_len, NULL);
}

/**
 * @brief Handles a Rekey Request from the client (Passive Rekey).
 * The client has generated a new key and wants the server to switch.
 */
static inline void vfast_handle_rekey_req(vfast_io_t *io, vpn_session_t *s, uint8_t *data, int len, struct sockaddr_in *src) {
    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)data;
    
    /**
     * 1. Extract Payload with Offset.
     * Payload structure: [KeyID (4B)][Raw Key (32B)]
     */
    uint8_t *payload = data + sizeof(vpn_tunnel_hdr_t);
    /* Parse Key ID from the first 4 bytes (Network Byte Order) */
    uint32_t received_kid = ntohl(*(uint32_t *)payload);
    /* Extract the Raw Key after the 4-byte ID */
    uint8_t *new_key_raw = payload + 4;

    /**
     * 2. Security Validation (Industrial Practice).
     * Ensure the received KeyID is strictly greater than the current one 
     * to prevent replay or out-of-order rekeying.
     */
    if (unlikely(received_kid <= s->sec_ctx.active_key.id)) {
        log_warn("REKEY: Ignored stale KeyID %u (Current: %u) from SID[0x%08x]", 
                 received_kid, s->sec_ctx.active_key.id, s->session_id);
        return;
    }

    /* 3. Load into 'next' slot */
    memcpy(s->sec_ctx.next_key.raw, new_key_raw, REKEY_KEY_SIZE);
    s->sec_ctx.next_key.id = received_kid;
    s->sec_ctx.next_key.created_at = time(NULL);
    atomic_store(&s->sec_ctx.next_key.bytes_processed, 0);

    /**
     * 4. Acknowledge the client (VPN_MSG_REKEY_ACK).
     * Reuse the buffer to save allocation overhead.
     */
    hdr->msg_type = VPN_MSG_REKEY_ACK;
    /* ACK payload can be empty or echoing the KeyID. Here we echo the request. */
    vfast_submit_write(io, io->udp_fd, OP_UDP_SEND, data, len, src);

    /**
     * 5. Commit the transition immediately.
     * Server promotes the key as soon as ACK is sent. 
     * The 'previous_key' in sec_ctx handles any inflight packets from client 
     * that haven't received the ACK yet.
     */
    vfast_rekey_commit(&s->sec_ctx);
    
    log_info("REKEY: Committed for SID[0x%08x]. Active KeyID: %u", 
             s->session_id, received_kid);
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
    vfast_rekey_commit(&s->sec_ctx);
    
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
        return -1;
    }

    /* 1. Map the VPN header to extract session information */
    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)data;

    // vpn_debug_print_hdr(data, len);

    if (hdr->msg_type == VPN_MSG_HELLO) {
        return vfast_auth_request(io, len, data, src) ? 0 : -1;
    }

    uint32_t sid = ntohl(hdr->session_id);
    vpn_session_t *s = NULL;
    if (!vpn_lookup_session_by_sid(sid, &s)) {
        atomic_fetch_add(&vfserver.stats.drops, 1);
        log_warn("No session found for SID[0x%08x] from %s. Packet dropped.", sid, inet_ntoa(src->sin_addr));
        return 0;
    }

    atomic_fetch_add(&s->sec_ctx.active_key.bytes_processed, (long)len);
    
    /* 3. Dispatch based on message type */
    switch (hdr->msg_type) {
        case VPN_MSG_DATA: 
            vfast_handle_data_msg(io, s, data, len, src);
            break;
        case VPN_MSG_KEEPALIVE:
            vfast_keeplive(io, s, data, len, src);
            break;
        case VPN_DPD_RESPONSE:
            log_info("Received DPD Response from %s. Session is alive.", inet_ntoa(src->sin_addr));
            vpn_session_update_by_sid(hdr->session_id, src);
            break;
        case VPN_MSG_REKEY_ACK:
            vfast_handle_rekey_ack(s);
            break;
        case VPN_MSG_REKEY_REQ:
            vfast_handle_rekey_req(io, s, data, len, src);
            break;
        default:
            log_warn("Unknown VPN msg type: 0x%02x", hdr->msg_type);
            break;
    }

    atomic_fetch_add(&vfserver.stats.rx_pkts, 1);
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
    if (!vpn_lookup_session_by_ip(dest_vip, &s)) {
        atomic_fetch_add(&vfserver.stats.drops, 1);
        return -1;
    }

    /**
     * 5. In-place AEAD Encryption & Packet Packing.
     * The vpn_pack function now writes the header at task_buf_base and encrypts 
     * the payload at 'data' in-situ. This eliminates the need for memcpy.
     */
    int total_len = vpn_pack(&s->sec_ctx,  /* Encryption Key */
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
        
        /**
         * 7. Signal Task Retention.
         * Returning 1 informs the IO loop that this specific task has been 
         * chained to an outbound write operation and should not be recycled yet.
         */
        return 1; 
    } else {
        log_error("Egress: Packing failed for VIP 0x%08x", ntohl(dest_vip));
        atomic_fetch_add(&vfserver.stats.drops, 1);
    }

    return 0;
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
    vpn_tun_destroy(&vfserver.tun);

    /* 4. Business logic teardown */
    vpn_session_destroy();
    vpn_ip_pool_destroy(&vfserver.ip_pool);

    /* 5. Cleanup io_uring */
    vfast_io_exit(&vfserver.io);

    vpn_option_clean(&vfserver.opt);

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
    if (vpn_ip_pool_init(&vfserver.ip_pool, 
        vfserver.opt.pool_network, vfserver.opt.pool_size) != 0) {
        log_error("Failed to initialize IP Pool");
        return -1;
    }

    if (vpn_session_init() < 0) {
        log_error("Failed to initialize session manager");
        return -1;
    }

    if (vpn_tun_init(&vfserver.tun, vfserver.opt.tun_name, 0) < 0) {
        log_error("Failed to initialize TUN device");
        return -1;
    }
    vpn_tun_disable_ipv6(vfserver.opt.tun_name);
    vpn_tun_set_ip(vfserver.tun.name, vfserver.opt.tun_ip, VFAST_BROADCAST);
    vpn_tun_set_status(vfserver.tun.name, vfserver.opt.mtu, 1); /* MTU 1400 to allow header overhead */
    vpn_set_nonblocking(vfserver.tun.fd);

    vfserver.udp = udp_init_listener(vfserver.opt.local_port, vfserver.opt.udp_backlog); 
    if (!vfserver.udp) {
        log_error("Failed to init UDP listener");
        goto cleanup;
    }
    vpn_set_nonblocking(vfserver.udp->fd);
    
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

    vpn_option_init(&vfserver.opt);

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
            if ((tp = (char*)vpn_get_absolute_path(configfile)) != NULL) {
                zfree(vfserver.opt.cfile);
                vfserver.opt.cfile = tp;
            } else {
                log_info("Warning: no config file specified, using the default config.");
            }
        }
    }

    vpn_option_conf(&vfserver.opt, vfserver.opt.cfile);

    if (vfast_init_server() < 0) return 1;

    log_info("VFAST server is up and running on port %d. Press Ctrl+C to stop.", vfserver.opt.local_port);

    vfast_io_run(&vfserver.io);

    vfast_clean_server();
    return 0;
}