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

#include "log.h"
#include "utils.h"
#include "vfast.h"
#include "fsm.h"
#include "zmalloc.h"
#include "protocol.h"
#include "iouring.h"
#include "option.h"

struct vfast_client {
    vpn_option_t opt;
    vfast_ctx_t ctx;
} vfclient;

/**
 * client_signal_handler - Graceful shutdown trigger.
 * Switches the global running state to false to allow clean resource release.
 */
static void client_signal_handler(int sig) {
    (void)sig;
    atomic_store(&vfclient.ctx.running, false);
}

/**
 * handle_io_event - FSM Dispatcher for I/O Completion.
 * Refactored to eliminate 'goto' statements for better structured flow.
 */
static void handle_io_event(struct io_uring_cqe *cqe) {
    vpn_io_data_t *data = (vpn_io_data_t *)io_uring_cqe_get_data(cqe);

    if (unlikely(!data)) return;

    int res = cqe->res;
    int idx = data->buf_idx;
    data->sid = client_fsm.sid;

    /* Handle I/O errors (e.g., interface down, buffer overflow) */
    if (unlikely(res <= 0)) {
        if (res < 0 && res != -EAGAIN && res != -ECANCELED) {
            log_error("I/O error at idx %d, type %d: %s", idx, data->type, strerror(-res));

            if (res == -ECONNREFUSED || res == -EPIPE || res == -ECONNRESET) {
                log_warn("FSM: Critical network error detected, forcing reconnection.");
                vfast_fsm_force_reconnect();
            }
        }
        vfast_auto_reschedule(&vfclient.ctx, idx);
        return;
    }
    /* Primary State Transition Logic */
    switch (data->type) {
    case IO_TYPE_TUN_READ:
        if (vfast_fsm_is_connected()) {
            if (!vfast_tun_client_rx(&vfclient.ctx, res, idx, data)) {
                vfast_auto_reschedule(&vfclient.ctx, idx);
            }
        } else {
            vfast_auto_reschedule(&vfclient.ctx, idx);
        }
        break; // --->SOCK_WRITE
    case IO_TYPE_SOCK_READ:
        if (!vfast_udp_client_rx(&vfclient.ctx, res, idx, data)) {
            vfast_auto_reschedule(&vfclient.ctx, idx);
        }
        break; // --->TUN_WRITE
    case IO_TYPE_SOCK_WRITE:
    case IO_TYPE_TUN_WRITE:
        vfast_auto_reschedule(&vfclient.ctx, idx);
        break;
    default:
        log_warn("Undefined state for buffer %d, forcing recycle", idx);
        vfast_auto_reschedule(&vfclient.ctx, idx);
        break;
    }
}

/**
 * vfast_cleanup - Resource teardown.
 * Ensures sockets, rings, and memory are released in reverse order of creation.
 */
static void vfast_cleanup() {
    log_info("Initiating system shutdown and resource cleanup...");
    
    vpn_iouring_destroy(&vfclient.ctx.io_ring);
    vpn_tun_destroy(&vfclient.ctx.tun);
    
    if (vfclient.ctx.udp) {
        udp_close(vfclient.ctx.udp);
    }
    
    if (vfclient.ctx.io_data_pool) {
        zfree(vfclient.ctx.io_data_pool);
    }
    vpn_option_clean(&vfclient.opt);
    log_info("Cleanup complete. Exit.");
}

/**
 * vfast_init_server - Pipeline and Environment Setup.
 * Initializes memory, kernel interfaces, and warms up the I/O ring.
 */
static int vfast_init_client() {
    memset(&vfclient.ctx, 0, sizeof(vfast_ctx_t));
    atomic_store(&vfclient.ctx.running, true);

    if (vfast_load_key(vfclient.opt.keyfile, vfclient.opt.master_key) < 0) {
        log_error("Failed load key file.");
        return -1;
    }
    vfclient.ctx.key = vfclient.opt.master_key;

    /* Signal Registration */
    struct sigaction sa = { .sa_handler = client_signal_handler };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    /* Memory Allocation */
    vfclient.ctx.io_data_pool = (vpn_io_data_t *)zmalloc(IO_BUF_POOL_SIZE * sizeof(vpn_io_data_t));
    if (!vfclient.ctx.io_data_pool) {
        log_error("Critical: Failed to allocate I/O buffer pool.");
        return -1;
    }

    /* Networking Subsystem Initialization */
    if (vpn_iouring_init(&vfclient.ctx.io_ring, vfclient.opt.io_ring_depth) < 0) return -1;

    if (vpn_tun_init(&vfclient.ctx.tun, vfclient.opt.tun_name, 0) < 0) return -1;
    // vpn_tun_set_ip(vfastctx.tun.name, "10.0.0.2", "255.255.255.0");
    vpn_tun_disable_ipv6(vfclient.opt.tun_name);
    vpn_tun_set_status(vfclient.ctx.tun.name, vfclient.opt.mtu, 1);
    
    vfclient.ctx.udp = udp_init_listener(0, vfclient.opt.udp_backlog);
    if (!vfclient.ctx.udp) {
        log_error("Failed to initialize UDP listener.");
        return -1;
    }
    udp_set_connect(vfclient.ctx.udp, inet_addr(vfclient.opt.remote_host), vfclient.opt.remote_port);

    /* Prime the I/O pipelines */
    vfast_io_warmup(&vfclient.ctx);

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
        vfclient.ctx.udp,
        vfclient.opt.remote_host, 
        vfclient.opt.remote_port, 
        &vfclient.ctx.running
    );

    struct io_uring_cqe *cqes[16];
    
    /* Main Event Loop */
    while (likely(atomic_load(&vfclient.ctx.running))) {
        struct io_uring_cqe *cqe_wait;
        
        /* Blocking wait for at least one event */
        int ret = io_uring_wait_cqe(&vfclient.ctx.io_ring.ring, &cqe_wait);
        if (unlikely(ret < 0)) {
            if (ret == -EINTR) continue;
            log_error("io_uring_wait_cqe failed: %s", strerror(-ret));
            break;
        }

        /* Batch processing for high-load efficiency */
        int count = io_uring_peek_batch_cqe(&vfclient.ctx.io_ring.ring, cqes, 16);
        for (int i = 0; i < count; i++) {
            handle_io_event(cqes[i]);
            io_uring_cqe_seen(&vfclient.ctx.io_ring.ring, cqes[i]);
        }
        
        /* Flush all pending SQEs generated in handle_io_event */
        io_uring_submit(&vfclient.ctx.io_ring.ring);
    }
    vfast_fsm_pthread_join();
    vfast_cleanup();
    return EXIT_SUCCESS;
}