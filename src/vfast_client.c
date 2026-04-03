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

int client_on_udp(vfast_io_t *io, uint8_t *data, int len, struct sockaddr_in *src) {
    UNUSED(src);
    vfast_submit_write(io, io->tun_fd, OP_TUN_WRITE, data, len, NULL);
    return 0;
}

int client_on_tun(vfast_io_t *io, uint8_t *data, int len) {
    vfast_submit_write(io, io->udp_fd, OP_UDP_SEND, data, len, &io->remote_addr);
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
    // vpn_tun_set_ip(vfastctx.tun.name, "10.0.0.2", "255.255.255.0");
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
        vfclient.udp,
        vfclient.opt.remote_host, 
        vfclient.opt.remote_port, 
        &vfclient.io.running
    );

    vfast_io_run(&vfclient.io);

    vfast_fsm_pthread_join();
    vfast_cleanup();
    return EXIT_SUCCESS;
}