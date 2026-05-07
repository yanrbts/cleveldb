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
#include <pthread.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <sys/uio.h>
#include <locale.h>
#include <liburing.h>

#include "log.h"
#include "utils.h"
#include "fsm.h"
#include "auth.h"
#include "zmalloc.h"
#include "protocol.h"
#include "option.h"
#include "tun.h"
#include "udp.h"
#include "io.h"
#include "key.h"
#include "vfast.h"
#include "logo.h"
#include "error.h"

typedef struct {
    time_t   last_sent;
    int      retry_interval;
    uint32_t poll_ms;
} vfast_rekey_mgr_t;

static vfast_rekey_mgr_t g_rekey_mgr = {
    .last_sent = 0,
    .retry_interval = 2,
    .poll_ms = 1000
};

struct vfast_client {
    vpn_option_t        opt;
    vf_io_t          io;
    udp_conn_t         *udp;       /* UDP transport handle */
    vpn_tun_ctx_t       tun;       /* Virtual network interface */
    _Atomic (vfast_sec_ctx_t *) active_ptr;
    vfast_sec_ctx_t     sec_ctxs[2];
    vfast_fsm_t         fsm;
    struct sockaddr_in  dst_addr;
    uint32_t            vip;
} vfclient;

/**
 * client_signal_handler - Graceful shutdown trigger.
 * Switches the global running state to false to allow clean resource release.
 */
static void client_signal_handler(int sig) {
    (void)sig;
    atomic_store(&vfclient.io.running, false);

    struct io_uring_sqe *sqe = io_uring_get_sqe(&vfclient.io.ring);
    if (sqe) {
        io_uring_prep_nop(sqe);
        io_uring_submit(&vfclient.io.ring);
    }
}

/**
 * vfast_cleanup - Resource teardown.
 * Ensures sockets, rings, and memory are released in reverse order of creation.
 */
static void vfast_cleanup() {
    log_info("Initiating system shutdown and resource cleanup...");
    
    vf_tun_destroy(&vfclient.tun);
    if (vfclient.udp) {
        udp_close(vfclient.udp);
    }
    vf_option_clean(&vfclient.opt);

    log_info("Cleanup complete. Exit.");
}

/**
 * @brief Handles incoming encrypted data packets (VPN_MSG_DATA).
 */
static inline int client_handle_data(vf_io_t *io, uint8_t *payload, int plen) {
    /* Silently drop data packets if the FSM is not in CONNECTED state */
    if (unlikely(!vf_fsm_is_connected(&vfclient.fsm))) {
        return -1; 
    }
    /* Forward decrypted IP packet to TUN device via asynchronous io_uring write */
    vf_io_write(io, io->tun_fd, OP_TUN_WRITE, payload, plen, NULL);
    return 0;
}

/**
 * @brief Handles handshake responses (VPN_MSG_HELLO) from the server.
 */
static inline int client_handle_hello(vf_io_t *io, uint32_t sid, uint8_t *payload, int plen) {
    UNUSED(io);
    UNUSED(sid);

    /* 1. Pre-condition: Only process if we are waiting for HELLO */
    if (atomic_load(&vfclient.fsm.state) != ST_HELLO_WAIT) {
        log_error("State is not ST_HELLO_WAIT");
        return -1; 
    }

    /* 2. Boundary and Integrity Validation */
    if (unlikely(!payload || plen < (int)sizeof(vf_payload_hello_resp_t))) {
        log_error("Ingress: HELLO_ACK payload undersized (len: %d)", plen);
        return -1;
    }

    vf_payload_hello_resp_t *resp = (vf_payload_hello_resp_t *)payload;

    /* 3. Check Server Status */
    uint32_t status = ntohl(resp->status);
    if (unlikely(status != VF_S_OK)) {
        log_error("FSM: Server rejected HELLO. Status Code: %u", status);
        atomic_store(&vfclient.fsm.state, ST_IDLE);
        return -1;
    }

    memcpy(vfclient.fsm.cookie, resp->cookie, sizeof(vfclient.fsm.cookie));
    vfclient.fsm.server_ts = ntohll(resp->server_ts);

    /* 5. State Transition */
    log_info("FSM: HELLO acknowledged. Moving to AUTH phase.");
    atomic_store(&vfclient.fsm.state, ST_AUTH_SEND);

    return 0;
}

/**
 * @brief Handles AUTH response from the server (VF_MSG_AUTH_RESP).
 * Transition: ST_AUTH_WAIT -> ST_CONNECTED
 */
static inline int client_handle_auth(vf_io_t *io, uint32_t sid, uint8_t *payload, int plen) {
    UNUSED(io);
    /* 1. Pre-condition: Only process if we are waiting for AUTH response */
    if (atomic_load(&vfclient.fsm.state) != ST_AUTH_WAIT) {
        log_error("State is not ST_AUTH_WAIT");
        return -1;
    }

    /* 2. Boundary Validation */
    if (unlikely(!payload || plen < (int)sizeof(vf_payload_auth_resp_t))) {
        log_error("Ingress: AUTH_ACK payload undersized (len: %d)", plen);
        return -1;
    }

    vf_payload_auth_resp_t *resp = (vf_payload_auth_resp_t *)payload;

    /* 3. Check Auth Status */
    uint32_t status = ntohl(resp->status);
    if (unlikely(status != VF_S_OK)) {
        log_error("FSM: Authentication failed. Server Status: %u", status);
        atomic_store(&vfclient.fsm.state, ST_IDLE);
        return -1;
    }

    vfast_sec_ctx_t *ctx = atomic_load(&vfclient.active_ptr);

    memcpy(ctx->active_key.raw, resp->init_key, REKEY_KEY_SIZE);
    ctx->active_key.id = ntohl(resp->key_id);
    ctx->active_key.created_at = time(NULL);
    ctx->sid = sid;

    /* Reset stats and state machine flags */
    atomic_store(&ctx->active_key.bytes_processed, 0);
    atomic_store(&ctx->rekey_pending, false);

    /* 4. Session & Security Initialization */
    vfclient.vip = resp->vip;
    vfclient.fsm.sid = sid;
    vfclient.fsm.sec = ctx;

    /* Convert Virtual IP to string for system configuration */
    char ip_str[INET_ADDRSTRLEN];
    ip_ntop(resp->vip, ip_str, sizeof(ip_str));

    /**
     * Synchronous Interface Configuration: transition to 
     * ST_CONNECTED only if the system call succeeds.
     */
    if (vf_tun_set_ip(vfclient.tun.name, ip_str, VFAST_BROADCAST) == 0) {
        atomic_store(&vfclient.fsm.state, ST_CONNECTED);
        log_info("Tunnel Successfully Established: VIP=%s, SID=0x%08x", 
                 ip_str, vfclient.fsm.sid);
        return 0;
    } else {
        log_error("FSM: Failed to configure TUN interface %s with IP %s", 
                  vfclient.tun.name, ip_str);
        return -1;
    }
}

/**
 * @brief Handles incoming Keepalive/DPD messages.
 * If it's a Request, we must respond. If it's a Response, update Liveness.
 */
static inline int client_handle_keepalive(vf_io_t *io, uint32_t sid, uint8_t *payload, int plen) {
    UNUSED(io);
    UNUSED(sid);
    /* 1. Basic Validation */
    if (unlikely(!payload || plen < (int)sizeof(vf_payload_echo_t))) {
        return -1;
    }

    vf_payload_echo_t *echo = (vf_payload_echo_t *)payload;

    /* 3. Logic based on Message Direction (Optional RTT logic) */
    uint64_t sent_ms = ntohll(echo->timestamp);
    uint64_t now_ms = vf_now_ms();

    if (likely(now_ms >= sent_ms)) {
        uint64_t rtt = now_ms - sent_ms;

        if (unlikely(rtt > VF_RTT_THRESHOLD_MS)) {
            log_warn("FSM: High latency detected! RTT: %llu ms (Threshold: %d ms), SID: 0x%08x", 
                     rtt, VF_RTT_THRESHOLD_MS, sid);
        }
    }
    
    return 0;
}

/**
 * @brief Commits the newly negotiated session key using an atomic pointer swap.
 * * This implements a RCU-like (Read-Copy-Update) mechanism. It prepares the 
 * inactive standby buffer, performs the key promotion (Active -> Previous, 
 * Next -> Active), and then atomically swaps the global active pointer.
 * * Note: This function ensures zero-lock synchronization with the data plane.
 */
void vfast_handle_new_key(void) {
    /* Get the currently active context pointer */
    vfast_sec_ctx_t *curr = atomic_load_explicit(&vfclient.active_ptr, memory_order_acquire);
    
    /* Identify the inactive standby buffer (Double Buffering) */
    vfast_sec_ctx_t *next_buf = (curr == &vfclient.sec_ctxs[0]) ? 
                                &vfclient.sec_ctxs[1] : &vfclient.sec_ctxs[0];

    /**
     * Step 1: Prepare the standby buffer.
     * Copy the current state to maintain session continuity (like session_id).
     * We can safely use memcpy because next_buf is guaranteed to be inactive.
     */
    memcpy(next_buf, curr, sizeof(vfast_sec_ctx_t));
    
    /* Move Active Key to Previous, and Promote Next Key to Active */
    vf_rekey_commit(next_buf); 

    /**
     * Step 2: Atomic Pointer Swap.
     * We use 'memory_order_release' to ensure that all previous memory writes 
     * (the memcpy and vf_rekey_commit) are visible to any thread that 
     * performs an 'acquire' load of this pointer.
     */
    atomic_store_explicit(&vfclient.active_ptr, next_buf, memory_order_release);

    /* Step D: ALSO clear the pending flag on the OLD buffer 
     * (To prevent the mgmt thread from seeing 'true' if it somehow hits the old ptr) */
    atomic_store(&curr->rekey_pending, false);

    /**
     * Step 3: Synchronize FSM legacy pointer.
     * Keep the state machine's shortcut pointer in sync with the new buffer's memory.
     */
    vfclient.fsm.sec = next_buf;

    log_info("REKEY: transition successful. Active KeyID: %u, FSM pointer synced.", 
             next_buf->active_key.id);
}

/**
 * @brief Reflects a DPD request back to the server.
 * @param io   The I/O context.
 * @param data Pointer to the received packet buffer (task->buf).
 * @param src  The remote address to reply to.
 */
static inline bool client_handle_dpd(vf_io_t *io, uint8_t *data, struct sockaddr_in *src) {
    if (unlikely(!io || !data || !src)) return false;

    /* 1. Use the macro to find the original task context */
    vf_task_t *task = vfast_data_to_task(data);
    uint32_t sid = vfclient.fsm.sid;

    uint8_t dummy[16];
    for (int i = 0; i < 16; i++) {
        dummy[i] = (uint8_t)(rand() & 0xFF); 
    }
    /**
     * 2. Security Pipeline Integration
     * A DPD response usually carries no payload (plen = 0).
     * vf_pack will:
     * - Wipe the old header.
     * - Fill a new header with VPN_DPD_RESPONSE and current SID.
     * - Apply random padding (1-32 bytes) to erase fixed-size fingerprints.
     * - XOR-obfuscate the header.
     */
    int tlen = vf_pack(vfclient.active_ptr, task->buf, (int)sizeof(dummy), 
                        BUF_SIZE, VPN_DPD_RESPONSE, sid);

    if (unlikely(tlen <= 0)) {
        log_error("DPD: Failed to pack DPD response for SID 0x%08x", sid);
        return false;
    }

    /**
     * 3. Asynchronous Dispatch via io_uring
     * The task remains 'in_use' until the CQE is reaped in the main loop.
     */
    vf_io_write(io, io->udp_fd, OP_UDP_SEND, task->buf, tlen, src);

    log_debug("DPD: Sent masked DPD response (len: %d) to server", tlen);

    return true;
}

/**
 * @brief Unified UDP reception callback for the VFast Client.
 *
 * This function processes all incoming packets from the server. It handles:
 * 1. Handshake responses (VPN_MSG_HELLO) with state-locking to prevent re-entry.
 * 2. Encrypted data packets (VPN_MSG_DATA) for TUN injection.
 * 3. Keep-alive acknowledgments to maintain session state.
 *
 * @param io   Pointer to the io_uring engine context.
 * @param data Received raw buffer from the task pool.
 * @param len  Length of the received data.
 * @param src  Source address (Server).
 * @return 0 on success, -1 on protocol/validation error.
 */
static vf_task_state_t client_on_udp(vf_io_t *io, uint8_t *data, int len, struct sockaddr_in *src, void *arg) {
    UNUSED(arg);

    uint32_t sid = 0;
    int plen = 0;
    uint8_t *payload = NULL;
    bool isuse = false;

    /* 1. Preliminary Boundary Check */
    if (unlikely(len < (int)VPN_TNL_HLEN)) {
        log_warn("Ingress: Packet dropped (too short: %d bytes)", len);
        return IO_TASK_DONE;
    }

    /* 2. PHASE 1: Mandatory De-obfuscation (Peel the shell)
     * Every packet from the modified server is XOR-masked.
     */
    vf_remove_header_obfs(data, (size_t)len);

    /* Direct mapping to inspect the header */
    vf_hdr_t *hdr = (vf_hdr_t *)data;

    sid = ntohl(hdr->session_id);
    /**
     * 3. PHASE 2: Conditional Unpack
     * If it's a HELLO packet, we MUST pass NULL for the security context 
     * because the session isn't fully established or re-keyed yet.
     */
    vfast_sec_ctx_t *sec = (hdr->msg_type == VPN_MSG_HELLO) ? NULL : vfclient.active_ptr;
    
    payload = vf_unpack(sec, data, len, &plen);

    /**
     * 2. Heartbeat Watchdog Update
     * Only update the last receive timestamp for valid protocol message types.
     * This prevents Dead Peer Detection (DPD) from being spoofed by garbage traffic.
     */
    vf_fsm_update(&vfclient.fsm);

    switch (hdr->msg_type) {
    case VPN_MSG_DATA:
        client_handle_data(io, payload, plen);
        break;
    case VPN_MSG_HELLO:
        client_handle_hello(io, sid, payload, plen);
        break;
    case VPN_MSG_KEEPALIVE:
        client_handle_keepalive(io, sid, payload, plen);
        break;
    case VPN_DPD_REQUEST:
        log_info("Received DPD Request from server. Responding with DPD Response.");
        isuse = client_handle_dpd(io, data, src);
        break;
    case VPN_MSG_REKEY_ACK:
        vfast_handle_new_key();
        break;
    case VPN_MSG_AUTH_ACK:
        client_handle_auth(io, sid, payload, plen);
        break;
    default:
        log_warn("Ingress: Unknown message type [0x%02x] received.", hdr->msg_type);
        break;
    }

    return isuse ? IO_TASK_USE : IO_TASK_DONE;
}

/**
 * @brief Processes plain IP packets from TUN, encrypts/packs them, and sends to Server.
 * Path: TUN (Plain) -> vf_pack (Encrypt + Header) -> UDP (Ciphertext)
 * @param io    The io_uring engine context.
 * @param data  The pointer to the plain IP packet (already at task->buf + VPN_TNL_HLEN).
 * @param len   The length of the plain IP packet.
 * @param src   The source address of the packet.
 * @param arg   User-defined argument.
 * @return IO_TASK_USE if the packet was processed and sent, IO_TASK_DONE if it was dropped (e.g. not connected).
 */
static vf_task_state_t client_on_tun(vf_io_t *io, uint8_t *data, int len, struct sockaddr_in *src, void *arg) {
    UNUSED(src);
    UNUSED(arg);
    
    /* 1. Connection Check: Drop packets if not authenticated */
    if (unlikely(!vf_fsm_is_connected(&vfclient.fsm))) {
        return IO_TASK_DONE;
    }
    /* Get the active context instantly via atomic pointer */
    vfast_sec_ctx_t *ctx = atomic_load(&vfclient.active_ptr);
    
    /* 1. Atomic accumulation - O(1) Lock-free operation */
    atomic_fetch_add(&ctx->active_key.bytes_processed, (long)len);
    /**
     * 2. Direct Packing:
     * Your vf_pack expects 'buf' to be the start of the whole VFAST packet.
     * Since 'data' starts at (task->buf + VPN_TNL_HLEN), we pass (data - VPN_TNL_HLEN).
     */
    uint8_t *vfast_packet_base = data - VPN_TNL_HLEN;
    
    /* We use BUF_SIZE to prevent overflows during encryption (+40 bytes) */
    int total_len = vf_pack(ctx, 
                             vfast_packet_base, 
                             len, 
                             BUF_SIZE, 
                             VPN_MSG_DATA, 
                             vfclient.fsm.sid);

    if (unlikely(total_len < 0)) {
        log_error("Failed to pack TUN packet for SID: 0x%08x", vfclient.fsm.sid);
        return IO_TASK_DONE;
    }

    /* 3. Submit Asynchronous UDP Send via io_uring */
    vf_io_write(io, 
                io->udp_fd, 
                OP_UDP_SEND, 
                vfast_packet_base, 
                total_len, 
                &vfclient.fsm.dst_addr);

    return IO_TASK_USE;
}

static int vfast_init_secctx() {
    memset(&vfclient.sec_ctxs[0], 0, sizeof(vfast_sec_ctx_t));
    memset(&vfclient.sec_ctxs[1], 0, sizeof(vfast_sec_ctx_t));

    vf_rekey_init(&vfclient.sec_ctxs[0], 0);

    atomic_init(&vfclient.active_ptr, &vfclient.sec_ctxs[0]);

    log_info("Security Manager: Initialized with sec[0].");
    return 0;
}

/**
 * @brief Professional Rekey Decision Engine (Event-driven)
 * This callback executes within the IO thread context.
 */
static void vfast_rekey_timer_handler(vf_io_t *io, void *arg) {
    vfast_rekey_mgr_t *mgr = (vfast_rekey_mgr_t *)arg;
    
    /* Security Check: FSM state validation */
    if (unlikely(!vf_fsm_is_connected(&vfclient.fsm))) {
        goto reschedule;
    }

    /* Load Security Context (Atomic) */
    vfast_sec_ctx_t *ctx = atomic_load(&vfclient.active_ptr);
    if (unlikely(!ctx)) return;

    uint64_t processed = atomic_load(&ctx->active_key.bytes_processed);
    bool pending       = atomic_load(&ctx->rekey_pending);
    time_t now         = time(NULL);

    /* Evaluation Logic */
    bool expired = (now - ctx->active_key.created_at >= REKEY_TIMEOUT_SEC);
    bool full    = (processed >= REKEY_DATA_THRESHOLD);
    
    bool should_init   = (!pending && (expired || full));
    bool should_retry  = (pending && (now - mgr->last_sent >= mgr->retry_interval));

    if (should_init || should_retry) {
        if (should_init) {
            /* Generate new key material if this is a fresh request */
            if (vf_rekey_prepare_next(ctx) != 0) {
                log_error("REKEY: Crypto entropy failure.");
                goto reschedule;
            }
            mgr->retry_interval = 2; /* Reset exponential backoff */
        }

        /* Buffer Management: Borrow a task object from the IO ring */
        vf_task_t *task = vf_io_task(io);
        if (likely(task)) {
            /* Payload: [NewKeyID: 4B][RawKey: 32B] */
            uint8_t *payload = task->buf + sizeof(vf_hdr_t);
            uint32_t net_kid = htonl(ctx->next_key.id);
            memcpy(payload, &net_kid, 4);
            memcpy(payload + 4, ctx->next_key.raw, REKEY_KEY_SIZE);

            int total_len = vf_pack(vfclient.active_ptr,                /* Use active session key */
                             task->buf,                                 /* Target buffer */
                             4 + REKEY_KEY_SIZE,                        /* Keep-alive has 0-byte payload */
                             BUF_SIZE,                                  /* Buffer capacity */
                             VPN_MSG_REKEY_REQ,                         /* Message type */
                             vfclient.fsm.sid);                         /* Current Session ID */

            vf_io_write(io, io->udp_fd, 
                               OP_UDP_SEND, task->buf, 
                               total_len, &vfclient.fsm.dst_addr);
            
            mgr->last_sent = now;

            /* Exponential Backoff for retries (Max 32s) */
            if (should_retry && mgr->retry_interval < 32) {
                mgr->retry_interval *= 2;
            }

            log_info("REKEY [%s] ID:%u | Trigger: %s | Progress: %.2f%%", 
                     should_init ? "INIT" : "RETRY", 
                     ctx->next_key.id,
                     expired ? "TIME" : "DATA",
                     (double)processed / REKEY_DATA_THRESHOLD * 100.0);
        }
    }

reschedule:
    /* Professional design: If the timer is not multishot, 
     * the infrastructure handles the interval. 
     * Here we just ensure the manager knows it's still alive. */
    return;
}

static inline void vfast_init_sockaddr() {
    vfclient.dst_addr.sin_family = AF_INET;
    vfclient.dst_addr.sin_port = htons(vfclient.opt.remote_port);
    ip_pton(vfclient.opt.remote_host, &vfclient.dst_addr.sin_addr.s_addr);
}

/**
 * vfast_init_server - Pipeline and Environment Setup.
 * Initializes memory, kernel interfaces, and warms up the I/O ring.
 */
static int vfast_init_client() {
    memset(&vfclient.io, 0, sizeof(vf_io_t));
    atomic_store(&vfclient.io.running, true);

    vfast_init_sockaddr();
    vfast_init_secctx();

    if (vfast_load_key(vfclient.opt.keyfile, vfclient.opt.master_key) < 0) {
        log_error("Failed load key file.");
        return -1;
    }

    /* Signal Registration */
    struct sigaction sa = { .sa_handler = client_signal_handler };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    if (vf_tun_init(&vfclient.tun, vfclient.opt.tun_name, 0) < 0) return -1;
    vf_tun_disable_ipv6(vfclient.opt.tun_name);
    vf_tun_set_status(vfclient.tun.name, vfclient.opt.mtu, 1);
    
    vfclient.udp = udp_init_listener(5887, vfclient.opt.udp_backlog);
    if (!vfclient.udp) {
        log_error("Failed to initialize UDP listener.");
        return -1;
    }
    udp_set_connect(vfclient.udp, inet_addr(vfclient.opt.remote_host), vfclient.opt.remote_port);

    vf_ops_t ops = {
        .on_udp_data = client_on_udp,
        .on_tun_data = client_on_tun,
        .ctx = NULL
    };
    vf_io_init(
        &vfclient.io,
        vfclient.udp->fd, 
        vfclient.tun.fd, 
        vfclient.opt.io_pool_size, 
        vfclient.opt.io_ring_depth, 
        ops
    );

    vf_io_set_timer(&vfclient.io, g_rekey_mgr.poll_ms, vfast_rekey_timer_handler, &g_rekey_mgr);
    vf_io_set_pmtud_callback(&vfclient.io, vfast_path_mtu_updated, &vfclient.io);

    log_info("VFAST Client initialized successfully. Connecting to %s...", vfclient.opt.remote_host);
    return 0;
}

static void version(void) {
    printf("vfast client v=%d\n", VFAST_VERSION);
    exit(0);
}

static void usage(void) {
    fprintf(stderr,"Usage: ./vfast_client [/path/to/config.conf]\n");
    fprintf(stderr,"       ./vfast_client -v or --version\n");
    fprintf(stderr,"       ./vfast_client -h or --help\n");
    fprintf(stderr,"Examples:\n");
    fprintf(stderr,"       ./vfast_client (run the client with default conf)\n");
    fprintf(stderr,"       ./vfast_client /etc/vfast_client/config.conf\n");
    exit(1);
}

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

    vf_option_init(&vfclient.opt);

    if (argc >= 2) {
        j = 1;
        char *configfile = NULL;
        char *tp = NULL;
        /* Handle special options --help and --version */
        if (strcmp(argv[1], "-v") == 0 ||
            strcmp(argv[1], "--version") == 0) version();
        if (strcmp(argv[1], "--help") == 0 ||
            strcmp(argv[1], "-h") == 0) usage();
        
        /* First argument is the config file name? */
        if (argv[j][0] != '-' || argv[j][1] != '-') {
            configfile = argv[j];
            if ((tp = (char*)vf_get_absolute_path(configfile)) != NULL) {
                zfree(vfclient.opt.cfile);
                vfclient.opt.cfile = tp;
            } else {
                log_info("Warning: no config file specified, using the default config.");
            }
        }
    }

    vf_option_conf(&vfclient.opt, vfclient.opt.cfile);

    vf_show_random_banner(false, "1.0.1", "yanruibing", vfclient.opt.remote_host);
    
    /* System Bootstrap */
    if (vfast_init_client() < 0) {
        log_error("System initialization failed. Aborting.");
        vfast_cleanup();
        return EXIT_FAILURE;
    }

    vf_fsm_init(
        &vfclient.fsm,
        &vfclient.io,
        vfclient.opt.username,
        vfclient.opt.password,
        vfclient.opt.remote_host, 
        vfclient.opt.remote_port, 
        &vfclient.io.running,
        vfclient.opt.master_key
    );

    vf_io_run(&vfclient.io);

    vf_fsm_pthread_join(&vfclient.fsm);
    vfast_cleanup();
    return EXIT_SUCCESS;
}