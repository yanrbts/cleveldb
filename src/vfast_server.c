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

#include "log.h"
#include "utils.h"
#include "vfast.h"
#include "session.h"
#include "iouring.h"
#include "zmalloc.h"
#include "udp.h"
#include "protocol.h"
#include "option.h"

struct vfast_server {
    vpn_option_t opt;
    vfast_ctx_t ctx;
} vfserver;

/* Simple signal handling for graceful shutdown */
static void vfast_signal_handler(int sig) {
    (void)sig;
    atomic_store(&vfserver.ctx.running, false);
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
    sa.sa_handler = vfast_signal_handler;
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
    if (vfserver.ctx.udp) {
        udp_close(vfserver.ctx.udp);
        vfserver.ctx.udp = NULL;
    }

    /* 3. Close the TUN device */
    vpn_tun_destroy(&vfserver.ctx.tun);

    /* 4. Business logic teardown */
    vpn_session_destroy();
    vpn_ip_pool_destroy(&vfserver.ctx.ip_pool);

    /* 2. Destroy the Ring FIRST (The most sensitive resource) */
    /* This will force cancellation of all inflight SQEs */
    vpn_iouring_destroy(&vfserver.ctx.io_ring);

    if (vfserver.ctx.io_data_pool) {
        zfree(vfserver.ctx.io_data_pool);
    }

    vpn_option_clean(&vfserver.opt);

    log_info("VFAST server halted safely.");
    return 0;
}

static int vfast_init_server(void) {
    memset(&vfserver.ctx, 0, sizeof(vfast_ctx_t));
    atomic_store(&vfserver.ctx.running, true);

    if (vfast_load_key(vfserver.opt.keyfile, vfserver.opt.master_key) < 0) {
        log_error("Failed load key file.");
        return -1;
    }
    vfserver.ctx.key = vfserver.opt.master_key;
    /* 1. Setup specialized signal handling */
    if (vfast_setup_signals() < 0) return -1;

    /* Initialize IPAM (The IP Pool) - MUST be before sessions */
    /* Starting from 10.0.0.0 with 65536 addresses (/16) */
    if (vpn_ip_pool_init(&vfserver.ctx.ip_pool, 
        vfserver.opt.pool_network, vfserver.opt.pool_size) != 0) {
        log_error("Failed to initialize IP Pool");
        return -1;
    }

    if (vpn_session_init() < 0) {
        log_error("Failed to initialize session manager");
        return -1;
    }

    if (vpn_iouring_init(
        &vfserver.ctx.io_ring, 
        vfserver.opt.io_ring_depth) < 0) {
        log_error("Init iouring failed");
        return -1;
    }

    if (vpn_tun_init(&vfserver.ctx.tun, vfserver.opt.tun_name, 0) < 0) {
        log_error("Failed to initialize TUN device");
        return -1;
    }
    vpn_tun_disable_ipv6(vfserver.opt.tun_name);
    vpn_tun_set_ip(vfserver.ctx.tun.name, vfserver.opt.tun_ip, VFAST_BROADCAST);
    vpn_tun_set_status(vfserver.ctx.tun.name, vfserver.opt.mtu, 1); /* MTU 1400 to allow header overhead */
    vpn_set_nonblocking(vfserver.ctx.tun.fd);

    vfserver.ctx.udp = udp_init_listener(vfserver.opt.local_port, vfserver.opt.udp_backlog); 
    if (!vfserver.ctx.udp) {
        log_error("Failed to init UDP listener");
        goto cleanup;
    }
    vpn_set_nonblocking(vfserver.ctx.udp->fd);

    vfserver.ctx.io_data_pool = zcalloc(sizeof(vpn_io_data_t) * IO_BUF_POOL_SIZE);
    if (!vfserver.ctx.io_data_pool) goto cleanup;

    vfast_io_warmup(&vfserver.ctx);
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

    struct io_uring_cqe *cqes[16]; // Batch processing array
    static uint64_t last_check_pkt = 0;

    while (atomic_load(&vfserver.ctx.running)) {
        /* Batch-peek completions to minimize synchronization overhead */
        int count = io_uring_peek_batch_cqe(&vfserver.ctx.io_ring.ring, cqes, 16);
        
        /* If no completions, wait for at least one */
        if (count == 0) {
            struct io_uring_cqe *cqe;
            int ret = io_uring_wait_cqe(&vfserver.ctx.io_ring.ring, &cqe);
            if (ret < 0) {
                if (ret == -EINTR) break; /* Normal exit on signal */
                log_error("Fatal io_uring error: %d", ret);
                break;
            }
            cqes[0] = cqe;
            count = 1;
        }

        for (int i = 0; i < count; i++) {
            struct io_uring_cqe *cqe = cqes[i];
            vpn_io_data_t *data = (vpn_io_data_t *)io_uring_cqe_get_data(cqe);
            int res = cqe->res, idx = data->buf_idx;
            data->res = res;

            if (unlikely(res <= 0)) {
                atomic_fetch_add(&vfserver.ctx.stats.drop_io_errors, 1);
                vfast_auto_reschedule(&vfserver.ctx, idx);
            } else {
                /* Finite State Machine: High-speed packet routing */
                switch (data->type) {
                case IO_TYPE_TUN_READ:
                    if (!vfast_tun_rx(&vfserver.ctx, res, idx, data)) {
                        vfast_auto_reschedule(&vfserver.ctx, idx);
                    }
                    break;  // --->SOCK_WRITE
                case IO_TYPE_SOCK_READ: 
                    if (!vfast_udp_rx(&vfserver.ctx, res, idx, data)) {
                        vfast_auto_reschedule(&vfserver.ctx, idx);
                    }
                    break; // --->TUN_WRITE
                case IO_TYPE_SOCK_WRITE:
                case IO_TYPE_TUN_WRITE:
                    vfast_auto_reschedule(&vfserver.ctx, idx);
                    break;
                }
            }
            io_uring_cqe_seen(&vfserver.ctx.io_ring.ring, cqe);

            last_check_pkt++;
        }

        if (unlikely(last_check_pkt >= 50000)) {
            last_check_pkt = 0;
            vpn_session_clean_timeout(&vfserver.ctx.ip_pool, 60);
            log_info("Periodic cleanup: scan timeout sessions.");

            vfast_report_performance(&vfserver.ctx);
        }
        /* Submit all queued SQEs in one single batch to improve SQPOLL efficiency */
        vpn_iouring_flush(&vfserver.ctx.io_ring);
    }

    vfast_clean_server();
    return 0;
}