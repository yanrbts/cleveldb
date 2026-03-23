/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __OPTION_H__
#define __OPTION_H__

#include <stddef.h>
#include <stdbool.h>
#include <net/if.h>
#include "crypto.h"

typedef struct vpn_option_s {
    /* Common Configuration (Shared by Server & Client) */
    char     tun_name[IFNAMSIZ];    /* Name of the virtual TUN interface (e.g., "tun0") */
    int      mtu;                   /* Maximum Transmission Unit for the TUN device (typically 1400-1500) */
    int      io_ring_depth;         /* Submission Queue depth for the io_uring instance */
    int      io_pool_size;          /* Total number of pre-allocated buffers in the I/O pool */
    bool     disable_ipv6;          /* Flag to suppress IPv6 stack on the TUN interface to prevent ghost traffic */
    int      udp_backlog;           /* UDP socket receive buffer size (SO_RCVBUF) in MB */
    bool     daemonize;
    int      log_max_size;
    char     *cfile;
    char     *logfile;
    char     *pidfile;
    char     *keyfile;
    uint8_t  master_key[CRYPTO_KEY_SIZE];
    /* Client-Specific Configuration */
    char     remote_host[64];       /* Remote server IP address or hostname to connect to */
    int      remote_port;           /* Destination port on the remote server (e.g., 9999) */
    
    /* Server-Specific Configuration (Ignored by Client) */
    char     tun_ip[32];            /* Static IP address assigned to the server's TUN interface (e.g., "10.0.0.1") */
    char     pool_network[32];      /* Start of the virtual IP range for client allocation (e.g., "10.0.0.0") */
    int      pool_size;             /* Total capacity of the IP Address Management (IPAM) pool */
    int      local_port;            /* Local UDP port the server will bind to and listen on */
} vpn_option_t;

void vpn_option_init(vpn_option_t *opt);
void vpn_option_conf(vpn_option_t *opt, const char *cfile);
void vpn_option_clean(vpn_option_t *opt);

#endif