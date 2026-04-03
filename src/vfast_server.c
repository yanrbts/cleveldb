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

    struct io_uring_sqe *sqe = io_uring_get_sqe(&vfserver.io.ring);
    if (sqe) {
        io_uring_prep_nop(sqe);
        io_uring_submit(&vfserver.io.ring);
    }
    log_info("Signal received, initiating shutdown...");
}

/**
 * @brief Command: --keygen
 * Generates a 256-bit key and saves it to 'vfast.key' with restricted permissions.
 */
static void vfast_cmd_keygen(void) {
    uint8_t tmp_key[CRYPTO_KEY_SIZE];
    const char *key_file = "vfast.key";
    
    log_info("[ VFAST ] Generating industrial strength key...\n");

    // 1. 获取系统随机数
    if (vpn_generate_key(tmp_key) != 0) {
        log_error("FATAL: Could not gather enough entropy from system.\n");
        exit(1);
    }

    // 2. 打开文件。使用 O_EXCL 确保如果文件已存在则报错，防止意外覆盖旧密钥
    // S_IRUSR | S_IWUSR 设置权限为 0600 (仅所有者可读写)
    int fd = open(key_file, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        if (errno == EEXIST) {
            log_error("ERROR: '%s' already exists. Refusing to overwrite.\n", key_file);
        } else {
            log_error("ERROR: Failed to create key file: %s\n", strerror(errno));
        }
        vpn_secure_cleanup(tmp_key, CRYPTO_KEY_SIZE);
        exit(1);
    }

    // 3. 将 32 字节二进制密钥写入文件
    ssize_t n = write(fd, tmp_key, CRYPTO_KEY_SIZE);
    close(fd);

    if (n != CRYPTO_KEY_SIZE) {
        log_error("ERROR: Partial write to key file. Disk full?\n");
        unlink(key_file); // 删除损坏的不完整文件
        exit(1);
    }

    // 4. 清理并退出
    vpn_secure_cleanup(tmp_key, CRYPTO_KEY_SIZE);
    
    log_info("[ SUCCESS ]: Key securely saved to '%s' (Permissions: 0600).\n", key_file);
    log_info("Keep this file safe. Loss of this file means loss of access.\n");
    exit(0);
}

/**
 * @brief Processes HELLO packet and submits an asynchronous response.
 * Optimization Highlights:
 * 1. Zero-copy Response Construction: Invokes vfast_auth_pack directly on the 
 * task buffer to eliminate redundant stack allocation and memcpy.
 * 2. Pre-calculated Offsets: Minimizes pointer arithmetic during the hot path.
 * 3. Atomic Stats Integration: (Optional but recommended) for monitoring.
 * @param io    Pointer to the io_uring engine context.
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
    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)buf;
    vpn_auth_t *auth_ptr  = (vpn_auth_t *)(buf + head_size);

    /* 3. Authentication: Validate client token using existing logic */
    const uint8_t *expected_token = (const uint8_t *)"VFAST_SECRET"; 
    if (vfast_auth_verify(auth_ptr, expected_token) != 0) {
        log_warn("Authentication failed for client: %s", inet_ntoa(src->sin_addr));
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
    
    /* Update Header Fields */
    hdr->version    = VFAST_VERSION;
    hdr->msg_type   = VPN_MSG_HELLO; 
    hdr->session_id = htonl(new_sid); // Ensure Network Byte Order
    hdr->flags      = 0;

    /* 7. Optimized Packing:
     * Directly pack response data into the task buffer.
     * This avoids: 'vpn_auth_t tmp; vfast_auth_pack(&tmp...); memcpy(dest, &tmp...);'
     */
    vfast_auth_pack(auth_ptr, assigned_vip, expected_token, 0);

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
 * @param res   Number of bytes received (cqe->res).
 * @param buf   Pointer to the task buffer (task->buf).
 * @param src   Physical source address of the client.
 * @return true if the keepalive was processed/ACKed, false otherwise.
 */
static bool vfast_keeplive(vfast_io_t *io, int res, uint8_t *buf, struct sockaddr_in *src) {
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
 * @brief Handles Data from UDP (Public Internet -> Virtual Network)
 * Decapsulates the VPN header and writes the inner IP packet to TUN.
 */
static int server_on_udp(vfast_io_t *io, uint8_t *data, int len, struct sockaddr_in *src) {
    if (unlikely(len < (int)sizeof(vpn_tunnel_hdr_t))) {
        atomic_fetch_add(&vfserver.stats.drops, 1);
        return -1;
    }

    /* 1. Map the VPN header */
    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)data;
    uint8_t *inner_pkt = data + sizeof(vpn_tunnel_hdr_t);
    int inner_len = len - sizeof(vpn_tunnel_hdr_t);

    /* 2. Track the peer (Simple session sticky) */
    memcpy(&io->remote_addr, src, sizeof(struct sockaddr_in));
    
    /* 3. Dispatch based on message type */
    switch (hdr->msg_type) {
        case VPN_MSG_DATA:
            /* Future: Add Decryption here */
            vfast_submit_write(io, io->tun_fd, OP_TUN_WRITE, inner_pkt, inner_len, NULL);
            break;
            
        case VPN_MSG_KEEPALIVE:
            log_debug("Keepalive received from %s", inet_ntoa(src->sin_addr));
            vfast_keeplive(io, len, data, src);
            break;

        case VPN_MSG_HELLO:
            vfast_auth_request(io, len, data, src);
            break;

        default:
            log_warn("Unknown VPN msg type: 0x%02x", hdr->msg_type);
            break;
    }

    atomic_fetch_add(&vfserver.stats.rx_pkts, 1);
    return 0;
}

/**
 * @brief Handles Data from TUN (Virtual Network -> Public Internet)
 * Encapsulates the IP packet with a VPN header and sends it via UDP.
 */
static int server_on_tun(vfast_io_t *io, uint8_t *data, int len) {
    /* To avoid double copy, ideally the vfast_task_t buffer should have 
     * space reserved for the header. For now, we use a simple encapsulation. */
    
    uint8_t encap_buf[BUF_SIZE];
    if (len + sizeof(vpn_tunnel_hdr_t) > BUF_SIZE) return -1;

    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)encap_buf;
    hdr->msg_type = VPN_MSG_DATA;
    // hdr->seq = 0; // Increment this in production

    memcpy(encap_buf + sizeof(vpn_tunnel_hdr_t), data, len);
    int total_len = len + sizeof(vpn_tunnel_hdr_t);

    /* Send to the last known remote peer */
    if (io->remote_addr.sin_port != 0) {
        vfast_submit_write(io, io->udp_fd, OP_UDP_SEND, encap_buf, total_len, &io->remote_addr);
        atomic_fetch_add(&vfserver.stats.tx_pkts, 1);
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
        .on_tun_data = server_on_tun
    };
    vfast_io_init(&vfserver.io, vfserver.udp->fd, vfserver.tun.fd, ops);

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