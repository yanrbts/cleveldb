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
#include "io.h"
#include "vfast.h"

struct vfast_client {
    vpn_option_t        opt;
    vfast_io_t          io;
    udp_conn_t         *udp;       /* UDP transport handle */
    vpn_tun_ctx_t       tun;       /* Virtual network interface */
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
    
    vpn_tun_destroy(&vfclient.tun);
    
    if (vfclient.udp) {
        udp_close(vfclient.udp);
    }
    
    vpn_option_clean(&vfclient.opt);
    log_info("Cleanup complete. Exit.");
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
int client_on_udp(vfast_io_t *io, uint8_t *data, int len, struct sockaddr_in *src) {
    UNUSED(src);

    /* 1. Preliminary Boundary Check */
    if (unlikely(len < (int)sizeof(vpn_tunnel_hdr_t))) {
        log_warn("Ingress: Packet dropped (too short: %d bytes)", len);
        return -1;
    }

    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)data;

    /**
     * 2. Heartbeat Watchdog Update
     * Only update the last receive timestamp for valid protocol message types.
     * This prevents Dead Peer Detection (DPD) from being spoofed by garbage traffic.
     */
    if (hdr->msg_type == VPN_MSG_DATA || 
        hdr->msg_type == VPN_MSG_KEEPALIVE || 
        hdr->msg_type == VPN_MSG_HELLO) {
        vfast_fsm_update_rx();
    }

    switch (hdr->msg_type) {
    case VPN_MSG_DATA: {
        /**
         * DATA PHASE:
         * Silently drop data packets if the FSM is not in CONNECTED state.
         */
        if (unlikely(!vfast_fsm_is_connected())) {
            return 0; 
        }

        int plain_ip_len = 0;
        uint32_t recv_sid = 0;

        /* In-place decryption and unpacking using the session master key */
        uint8_t *payload_ptr = vpn_unpack(vfclient.opt.master_key, data, len, 
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
        break;
    } 

    case VPN_MSG_HELLO: {
        /**
         * HANDSHAKE RESPONSE (Auth ACK):
         * CRITICAL: Use a State Lock. If the tunnel is already established, 
         * ignore subsequent HELLO responses to prevent redundant interface 
         * configurations and resource exhaustion.
         */
        if (vfast_fsm_is_connected()) {
            return 0; 
        }

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

        /* Convert Virtual IP to string for system configuration */
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &auth->vip, ip_str, sizeof(ip_str));
        
        /**
         * Synchronous Interface Configuration:
         * We set the IP and bring the TUN interface up. Transition to 
         * ST_CONNECTED only if the system call succeeds.
         */
        if (vpn_tun_set_ip(vfclient.tun.name, ip_str, VFAST_BROADCAST) == 0) {
            atomic_store(&client_fsm.state, ST_CONNECTED);
            log_info("Tunnel Successfully Established: VIP=%s, SID=0x%08x", 
                     ip_str, client_fsm.sid);
        } else {
            log_error("FSM: Failed to configure TUN interface %s with IP %s", 
                      vfclient.tun.name, ip_str);
            return -1;
        }
        break;
    }

    case VPN_MSG_KEEPALIVE:
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
 * * @param io    The io_uring engine context.
 * @param data  The pointer to the plain IP packet (already at task->buf + VPN_TNL_HLEN).
 * @param len   The length of the plain IP packet.
 * @return 0 on success, -1 on failure.
 */
int client_on_tun(vfast_io_t *io, uint8_t *data, int len) {
    /* 1. Connection Check: Drop packets if not authenticated */
    if (unlikely(!vfast_fsm_is_connected())) {
        return 0;
    }

    /**
     * 2. Direct Packing:
     * Your vpn_pack expects 'buf' to be the start of the whole VFAST packet.
     * Since 'data' starts at (task->buf + VPN_TNL_HLEN), we pass (data - VPN_TNL_HLEN).
     */
    uint8_t *vfast_packet_base = data - VPN_TNL_HLEN;
    
    /* We use BUF_SIZE to prevent overflows during encryption (+40 bytes) */
    int total_len = vpn_pack(vfclient.opt.master_key, 
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

/**
 * vfast_init_server - Pipeline and Environment Setup.
 * Initializes memory, kernel interfaces, and warms up the I/O ring.
 */
static int vfast_init_client() {
    memset(&vfclient.io, 0, sizeof(vfast_io_t));
    atomic_store(&vfclient.io.running, true);

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
    
    vfclient.udp = udp_init_listener(0, vfclient.opt.udp_backlog);
    if (!vfclient.udp) {
        log_error("Failed to initialize UDP listener.");
        return -1;
    }
    udp_set_connect(vfclient.udp, inet_addr(vfclient.opt.remote_host), vfclient.opt.remote_port);

    vfast_ops_t ops = {
        .on_udp_data = client_on_udp,
        .on_tun_data = client_on_tun
    };
    vfast_io_init(&vfclient.io, vfclient.udp->fd, vfclient.tun.fd, ops);

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

    vfast_io_run(&vfclient.io);

    vfast_fsm_pthread_join();
    vfast_cleanup();
    return EXIT_SUCCESS;
}