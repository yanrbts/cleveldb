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

struct vfast_client {
    vpn_option_t        opt;
    vfast_io_t          io;
    udp_conn_t         *udp;       /* UDP transport handle */
    vpn_tun_ctx_t       tun;       /* Virtual network interface */
    pthread_t           rekey_tid;
    _Atomic (vfast_sec_ctx_t *) active_ptr;
    vfast_sec_ctx_t     sec_ctxs[2];
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

    pthread_join(vfclient.rekey_tid, NULL);
    
    vpn_tun_destroy(&vfclient.tun);
    
    if (vfclient.udp) {
        udp_close(vfclient.udp);
    }
    
    vpn_option_clean(&vfclient.opt);

    log_info("Cleanup complete. Exit.");
}

/**
 * @brief Handles incoming encrypted data packets (VPN_MSG_DATA).
 */
static inline int client_handle_data(vfast_io_t *io, uint8_t *data, int len) {
    /* Silently drop data packets if the FSM is not in CONNECTED state */
    if (unlikely(!vfast_fsm_is_connected())) {
        return 0; 
    }

    int plain_ip_len = 0;
    uint32_t recv_sid = 0;

    /* In-place decryption and unpacking using the session master key */
    uint8_t *payload_ptr = vpn_unpack(vfclient.active_ptr, data, len, 
                                      &plain_ip_len, &recv_sid);

    if (unlikely(!payload_ptr)) {
        log_warn("Ingress: Decryption failed or MAC mismatch.");
        return -1;
    }

    /* Verify Session ID to prevent cross-talk or stale session data */
    if (unlikely(recv_sid != client_fsm.sid)) {
        log_warn("Ingress: SID mismatch (Expected: 0x%08x, Got: 0x%08x)", 
                 client_fsm.sid, recv_sid);
        return 0;
    }

    /* Forward decrypted IP packet to TUN device via asynchronous io_uring write */
    vfast_submit_write(io, io->tun_fd, OP_TUN_WRITE, payload_ptr, plain_ip_len, NULL);
    return 0;
}

/**
 * @brief Handles handshake responses (VPN_MSG_HELLO) from the server.
 */
static inline int client_handle_hello(vfast_io_t *io, uint8_t *data, int len) {
    UNUSED(io);
    UNUSED(len);

    /* State Lock: ignore subsequent HELLO if already established */
    if (vfast_fsm_is_connected()) {
        return 0; 
    }

    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)data;
    vpn_auth_t *auth = (vpn_auth_t *)(data + sizeof(vpn_tunnel_hdr_t));
    
    /* Validate Session ID provided by the server */
    uint32_t new_sid = ntohl(hdr->session_id);
    if (unlikely(new_sid == 0)) {
        log_error("Ingress: Server returned an invalid Session ID (0)");
        return -1;
    }

    /* Persist session parameters */
    client_fsm.sid = new_sid;
    client_fsm.vip = auth->vip;

    vfast_sec_ctx_t *ctx = atomic_load(&vfclient.active_ptr);
    memcpy(ctx->active_key.raw, auth->init_key, REKEY_KEY_SIZE);
    ctx->active_key.id = auth->key_id;
    ctx->active_key.created_at = time(NULL);
    atomic_store(&ctx->active_key.bytes_processed, 0);
    atomic_store(&ctx->rekey_pending, false);

    client_fsm.key = ctx->active_key.raw;
    client_fsm.sec = ctx;
    /* Convert Virtual IP to string for system configuration */
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &auth->vip, ip_str, sizeof(ip_str));
    
    /**
     * Synchronous Interface Configuration: transition to 
     * ST_CONNECTED only if the system call succeeds.
     */
    if (vpn_tun_set_ip(vfclient.tun.name, ip_str, VFAST_BROADCAST) == 0) {
        atomic_store(&client_fsm.state, ST_CONNECTED);
        log_info("Tunnel Successfully Established: VIP=%s, SID=0x%08x", 
                 ip_str, client_fsm.sid);
        return 0;
    } else {
        log_error("FSM: Failed to configure TUN interface %s with IP %s", 
                  vfclient.tun.name, ip_str);
        return -1;
    }
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
    vfast_rekey_commit(next_buf); 

    /**
     * Step 2: Atomic Pointer Swap.
     * We use 'memory_order_release' to ensure that all previous memory writes 
     * (the memcpy and vfast_rekey_commit) are visible to any thread that 
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
    client_fsm.key = next_buf->active_key.raw;
    client_fsm.sec = next_buf;

    log_info("REKEY: Atomic transition successful. Active KeyID: %u, FSM pointer synced.", 
             next_buf->active_key.id);
}

/**
 * @brief Reflects a DPD request back to the server.
 * @param io   The I/O context.
 * @param data Pointer to the received packet buffer (task->buf).
 * @param src  The remote address to reply to.
 */
static inline void client_handle_dpd(vfast_io_t *io, uint8_t *data, struct sockaddr_in *src) {
    if (unlikely(!io || !data || !src)) return;

    /* 1. Use the macro to find the original task context */
    vfast_task_t *task = vfast_data_to_task(data);
    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)task->buf;

    /* 2. Modify header for response */
    hdr->msg_type = VPN_DPD_RESPONSE;

    /**
     * 3. Send back only the header.
     * The task->in_use remains true because this is an OP_UDP_SEND.
     * It will be set to false in the main io_run loop's completion handling.
     */
    vfast_submit_write(io, io->udp_fd, OP_UDP_SEND, 
                      task->buf, (int)sizeof(vpn_tunnel_hdr_t), src);
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
int client_on_udp(vfast_io_t *io, uint8_t *data, int len, struct sockaddr_in *src, void *arg) {
    UNUSED(src);
    UNUSED(arg);

    /* 1. Preliminary Boundary Check */
    if (unlikely(len < (int)sizeof(vpn_tunnel_hdr_t))) {
        log_warn("Ingress: Packet dropped (too short: %d bytes)", len);
        return -1;
    }

    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)data;

    // vpn_debug_print_hdr(data, len);

    /**
     * 2. Heartbeat Watchdog Update
     * Only update the last receive timestamp for valid protocol message types.
     * This prevents Dead Peer Detection (DPD) from being spoofed by garbage traffic.
     */
    if (hdr->msg_type == VPN_MSG_DATA || 
        hdr->msg_type == VPN_MSG_KEEPALIVE || 
        hdr->msg_type == VPN_MSG_HELLO ||
        hdr->msg_type == VPN_DPD_REQUEST) {
        vfast_fsm_update();
    }

    switch (hdr->msg_type) {
    case VPN_MSG_DATA:
        return client_handle_data(io, data, len);
    case VPN_MSG_HELLO:
        return client_handle_hello(io, data, len);
    case VPN_MSG_KEEPALIVE:
        break;
    case VPN_DPD_REQUEST:
        log_info("Received DPD Request from server. Responding with DPD Response.");
        client_handle_dpd(io, data, src);
        break;
    case VPN_MSG_REKEY_ACK:
        vfast_handle_new_key();
        break;
    default:
        log_warn("Ingress: Unknown message type [0x%02x] received.", hdr->msg_type);
        break;
    }

    return 0;
}

/**
 * @brief Processes plain IP packets from TUN, encrypts/packs them, and sends to Server.
 * * Path: TUN (Plain) -> vpn_pack (Encrypt + Header) -> UDP (Ciphertext)
 * @param io    The io_uring engine context.
 * @param data  The pointer to the plain IP packet (already at task->buf + VPN_TNL_HLEN).
 * @param len   The length of the plain IP packet.
 * @param src   The source address of the packet.
 * @param arg   User-defined argument.
 * @return 0 on success, -1 on failure.
 */
int client_on_tun(vfast_io_t *io, uint8_t *data, int len, struct sockaddr_in *src, void *arg) {
    UNUSED(src);
    UNUSED(arg);
    
    /* 1. Connection Check: Drop packets if not authenticated */
    if (unlikely(!vfast_fsm_is_connected())) {
        return 0;
    }
    /* Get the active context instantly via atomic pointer */
    vfast_sec_ctx_t *ctx = atomic_load(&vfclient.active_ptr);
    
    /* 1. Atomic accumulation - O(1) Lock-free operation */
    atomic_fetch_add(&ctx->active_key.bytes_processed, (long)len);
    /**
     * 2. Direct Packing:
     * Your vpn_pack expects 'buf' to be the start of the whole VFAST packet.
     * Since 'data' starts at (task->buf + VPN_TNL_HLEN), we pass (data - VPN_TNL_HLEN).
     */
    uint8_t *vfast_packet_base = data - VPN_TNL_HLEN;
    
    /* We use BUF_SIZE to prevent overflows during encryption (+40 bytes) */
    int total_len = vpn_pack(ctx, 
                             vfast_packet_base, 
                             len, 
                             BUF_SIZE, 
                             VPN_MSG_DATA, 
                             client_fsm.sid);

    if (unlikely(total_len < 0)) {
        log_error("Failed to pack TUN packet for SID: 0x%08x", client_fsm.sid);
        return -1;
    }

    /* 3. Submit Asynchronous UDP Send via io_uring */
    vfast_submit_write(io, 
                       io->udp_fd, 
                       OP_UDP_SEND, 
                       vfast_packet_base, 
                       total_len, 
                       &client_fsm.dst_addr);

    return 0;
}

static int vfast_init_secctx() {
    memset(&vfclient.sec_ctxs[0], 0, sizeof(vfast_sec_ctx_t));
    memset(&vfclient.sec_ctxs[1], 0, sizeof(vfast_sec_ctx_t));

    vfast_rekey_init(&vfclient.sec_ctxs[0]);

    atomic_init(&vfclient.active_ptr, &vfclient.sec_ctxs[0]);

    log_info("Security Manager: Initialized with buffer [0].");
    return 0;
}

/**
 * @brief Rekey Management Thread - 100% Lock-Free Implementation.
 * Uses atomic pointer swapping to ensure zero contention with the data plane.
 */
/**
 * @brief Rekey Management Thread - Lock-Free Lifecycle Control.
 * 100% decoupling between control plane and data plane.
 */
static void* vfast_rekey_mgmt(void *arg) {
    vfast_io_t *io = (vfast_io_t *)arg;
    time_t last_sent = 0;
    int retry_interval = 2;

    log_info("Rekey Manager: Lock-free monitoring active.");

    while (atomic_load(&io->running)) {
        /* High-level polling interval: 1s is sufficient for key management */
        sleep(1);

        if (unlikely(!vfast_fsm_is_connected())) continue;

        /* [Atomic] Load the current pointer used by data plane */
        vfast_sec_ctx_t *ctx = atomic_load(&vfclient.active_ptr);
        
        /* * [Industrial Logic] 
         * We don't call vfast_rekey_needed() directly because we need 
         * atomic-safe reading of 'bytes_processed' and 'rekey_pending'.
         */
        uint64_t processed = atomic_load(&ctx->active_key.bytes_processed);
        bool pending   = atomic_load(&ctx->rekey_pending);
        time_t now     = time(NULL);

        /* Determine if it's time to act */
        bool threshold_hit = (processed >= REKEY_DATA_THRESHOLD) || 
                             ((now - ctx->active_key.created_at) >= REKEY_TIMEOUT_SEC);
        
        bool should_init  = (!pending && threshold_hit);
        bool should_retry = (pending && (now - last_sent >= retry_interval));

        if (should_init || should_retry) {
            /* * Phase 1: Preparation 
             * Only the MGMT thread writes to next_key, so no mutex needed.
             */
            if (should_init) {
                if (vfast_rekey_prepare_next(ctx) != 0) {
                    log_error("REKEY: Crypto failure during preparation.");
                    continue;
                }
                retry_interval = 2; // Reset backoff
            }

            /* Phase 2: Transmission */
            vfast_task_t *task = vfast_borrow_task(io);
            if (task) {
                vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)task->buf;
                hdr->msg_type = VPN_MSG_REKEY_REQ;
                hdr->session_id = htonl(client_fsm.sid);

                /* Key payload: [ID: 4B][Key: 32B] */
                uint8_t *payload = task->buf + sizeof(vpn_tunnel_hdr_t);
                uint32_t net_kid = htonl(ctx->next_key.id);
                memcpy(payload, &net_kid, 4);
                memcpy(payload + 4, ctx->next_key.raw, REKEY_KEY_SIZE);

                /* Async submission to io_uring */
                vfast_submit_write(io, io->udp_fd, OP_UDP_SEND, task->buf, 
                                   sizeof(vpn_tunnel_hdr_t) + 4 + REKEY_KEY_SIZE, 
                                   &client_fsm.dst_addr);
                
                last_sent = now;
                if (should_retry && retry_interval < 32) retry_interval *= 2;

                log_info("REKEY: %s sent (ID: %u, Thr: %ld/%lld)", 
                         should_init ? "Initial REQ" : "Retransmit", 
                         ctx->next_key.id, processed, REKEY_DATA_THRESHOLD);
            }
        }
    }
    return NULL;
}

/**
 * vfast_init_server - Pipeline and Environment Setup.
 * Initializes memory, kernel interfaces, and warms up the I/O ring.
 */
static int vfast_init_client() {
    memset(&vfclient.io, 0, sizeof(vfast_io_t));
    atomic_store(&vfclient.io.running, true);

    vfast_init_secctx();

    if (vfast_load_key(vfclient.opt.keyfile, vfclient.opt.master_key) < 0) {
        log_error("Failed load key file.");
        return -1;
    }

    /* Signal Registration */
    struct sigaction sa = { .sa_handler = client_signal_handler };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    if (vpn_tun_init(&vfclient.tun, vfclient.opt.tun_name, 0) < 0) return -1;
    vpn_tun_disable_ipv6(vfclient.opt.tun_name);
    vpn_tun_set_status(vfclient.tun.name, vfclient.opt.mtu, 1);
    
    vfclient.udp = udp_init_listener(5887, vfclient.opt.udp_backlog);
    if (!vfclient.udp) {
        log_error("Failed to initialize UDP listener.");
        return -1;
    }
    udp_set_connect(vfclient.udp, inet_addr(vfclient.opt.remote_host), vfclient.opt.remote_port);

    vfast_ops_t ops = {
        .on_udp_data = client_on_udp,
        .on_tun_data = client_on_tun,
        .ctx = NULL
    };
    vfast_io_init(
        &vfclient.io,
        vfclient.udp->fd, 
        vfclient.tun.fd, 
        vfclient.opt.io_pool_size, 
        vfclient.opt.io_ring_depth, 
        ops
    );

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

    vpn_option_init(&vfclient.opt);

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
            if ((tp = (char*)vpn_get_absolute_path(configfile)) != NULL) {
                zfree(vfclient.opt.cfile);
                vfclient.opt.cfile = tp;
            } else {
                log_info("Warning: no config file specified, using the default config.");
            }
        }
    }

    vpn_option_conf(&vfclient.opt, vfclient.opt.cfile);
    
    /* System Bootstrap */
    if (vfast_init_client() < 0) {
        log_error("System initialization failed. Aborting.");
        vfast_cleanup();
        return EXIT_FAILURE;
    }

    vfast_fsm_init(
        &vfclient.io,
        vfclient.opt.remote_host, 
        vfclient.opt.remote_port, 
        &vfclient.io.running,
        vfclient.opt.master_key
    );

    if (pthread_create(&vfclient.rekey_tid, NULL, vfast_rekey_mgmt, &vfclient.io) != 0) {
        log_error("Failed to create rekey thread.");
        return -1;
    }

    vfast_io_run(&vfclient.io);

    vfast_fsm_pthread_join();
    vfast_cleanup();
    return EXIT_SUCCESS;
}