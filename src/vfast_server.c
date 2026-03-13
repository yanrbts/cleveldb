/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
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

#include "log.h"
#include "utils.h"
#include "vfast.h"
#include "session.h"
#include "iouring.h"
#include "zmalloc.h"
#include "udp.h"

/* Global Context Instance */
vfast_ctx_t vfastctx;

/* Simple signal handling for graceful shutdown */
static void signal_handler(int sig) {
    (void)sig;
    atomic_store(&vfastctx.running, false);
}

static int vfast_clean_server(void) {
    vpn_session_destroy();
    if (vfastctx.udp) udp_close(vfastctx.udp);
    vpn_tun_destroy(&vfastctx.tun);
    vpn_iouring_destroy(&vfastctx.io_ring);

    return 0;
}

static int vfast_init_server(void) {
    /* 1. Global Context Basic Initialization */
    memset(&vfastctx, 0, sizeof(vfast_ctx_t));
    vfastctx.free_top = -1;
    atomic_store(&vfastctx.running, true);

    /* Register Signals */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* 2. Initialize Session Manager (Industrial Sharded Hash Table) */
    if (vpn_session_init() < 0) {
        log_error("Failed to initialize session manager");
        return -1;
    }

    /* 3. Initialize io_uring with Fixed Buffers */
    if (vpn_iouring_init(&vfastctx.io_ring, IO_RING_DEPTH) < 0) {
        log_error("Init iouring failed");
        return -1;
    }

    /* 4. Initialize TUN Device */
    if (vpn_tun_init(&vfastctx.tun, "tun0", 1) < 0) {
        log_error("Failed to initialize TUN device");
        return -1;
    }
    vpn_tun_set_ip(vfastctx.tun.name, "10.0.0.1", "255.255.255.0");
    vpn_tun_set_status(vfastctx.tun.name, 1500, 1);
    vpn_set_nonblocking(vfastctx.tun.fd);

    /* 5. Initialize UDP Listener */
    vfastctx.udp = udp_init_listener(9999, 20); 
    if (!vfastctx.udp) {
        log_error("Failed to init UDP listener");
        goto cleanup;
    }
    vpn_set_nonblocking(vfastctx.udp->fd);

    /* 6. Populate Buffer Pool */
    for (int i = 0; i < IO_BUF_POOL_SIZE; i++) {
        vfast_buf_push(&vfastctx, i);
    }

    return 0;

cleanup:
    vfast_clean_server();
    return -1;
}

int main(int argc, char *argv[]) {
    UNUSED(argc);
    UNUSED(argv);

    if (vfast_init_server() < 0) {
        log_info("Init VFAST server failed...");
        return EXIT_FAILURE;
    }

    log_info("VFAST Server: TUN_FD=%d, SOCK_FD=%d, DEV=%s", 
             vfastctx.tun.fd, vfastctx.udp->fd, vfastctx.tun.name);

    /* 7. Pre-submit Initial Read Tasks (Asynchronous Pipeline Warm-up) */
    /* We split the pool to balance TUN and Socket read requests */
    for (int i = 0; i < 256; i++) {
        int idx_t = vfast_buf_pop(&vfastctx);
        int idx_s = vfast_buf_pop(&vfastctx);

        if (idx_t != -1) {
            vpn_io_data_t *d = zmalloc(sizeof(vpn_io_data_t));
            memset(d, 0, sizeof(vpn_io_data_t));
            d->type = IO_TYPE_TUN_READ;
            vpn_iouring_submit_read(&vfastctx.io_ring, vfastctx.tun.fd, idx_t, d);
        }
        if (idx_s != -1) {
            vpn_io_data_t *d = zmalloc(sizeof(vpn_io_data_t));
            memset(d, 0, sizeof(vpn_io_data_t));
            d->type = IO_TYPE_SOCK_READ;
            /* Use recvmsg to capture the client's public IP/Port */
            vpn_iouring_submit_recvmsg(&vfastctx.io_ring, vfastctx.udp->fd, idx_s, d);
        }
    }
    vpn_iouring_flush(&vfastctx.io_ring);

    /* 8. Main Event Relay Loop */
    log_info("Entering main relay loop with Session Auto-Learning...");
    while (atomic_load(&vfastctx.running)) {
        struct io_uring_cqe *cqe;
        
        /* Wait for completion event */
        int ret = io_uring_wait_cqe(&vfastctx.io_ring.ring, &cqe);
        if (ret < 0) {
            if (ret == -EINTR) continue;
            break;
        }

        vpn_io_data_t *data = (vpn_io_data_t *)io_uring_cqe_get_data(cqe);
        int res = cqe->res;
        int current_idx = data->buf_idx;

        if (res <= 0) {
            /* Error or EOF: Re-submit read to keep the ring busy */
            if (data->type == IO_TYPE_TUN_READ) {
                vpn_iouring_submit_read(&vfastctx.io_ring, vfastctx.tun.fd, current_idx, data);
            } else if (data->type == IO_TYPE_SOCK_READ) {
                vpn_iouring_submit_recvmsg(&vfastctx.io_ring, vfastctx.udp->fd, current_idx, data);
            } else {
                /* For failed writes, recycle the buffer and free metadata */
                vfast_buf_push(&vfastctx, current_idx);
                zfree(data);
            }
        } else {
            switch (data->type) {
                case IO_TYPE_TUN_READ: {
                    /* INGRESS: Captured a packet from the virtual interface */
                    atomic_fetch_add(&vfastctx.stats.rx_packets, 1);
                    
                    /* Peek at the IP header to find the internal destination */
                    struct iphdr *iph = (struct iphdr *)vfastctx.io_ring.iovecs[current_idx].iov_base;
                    struct sockaddr_in target_remote;

                    /* Perform Session Lookup: Find which public IP owns this internal IP */
                    if (vpn_session_lookup(iph->daddr, &target_remote)) {
                        data->type = IO_TYPE_SOCK_WRITE;
                        /* In a real scenario, you'd use sendmsg/sendto with target_remote. 
                         * For now, we utilize the connected socket or prepared write fixed. 
                         */
                        vpn_iouring_submit_write(&vfastctx.io_ring, vfastctx.udp->fd, current_idx, res, data);
                    } else {
                        /* No session found for this internal IP, drop and re-read TUN */
                        vpn_iouring_submit_read(&vfastctx.io_ring, vfastctx.tun.fd, current_idx, data);
                    }
                    break;
                }

                case IO_TYPE_SOCK_READ: {
                    /* EGRESS: Received an encrypted/tunneled packet from the Internet */
                    atomic_fetch_add(&vfastctx.stats.tx_packets, 1);
                    
                    /* INDUSTRIAL AUTO-LEARNING:
                     * Map the internal Source IP to the physical public address captured by recvmsg.
                     */
                    struct iphdr *iph = (struct iphdr *)vfastctx.io_ring.iovecs[current_idx].iov_base;
                    if (res >= (int)sizeof(struct iphdr)) {
                        vpn_session_update(iph->saddr, &data->udp_meta.client_addr);
                    }

                    /* Forward the payload back into the local system stack via TUN */
                    data->type = IO_TYPE_TUN_WRITE;
                    vpn_iouring_submit_write(&vfastctx.io_ring, vfastctx.tun.fd, current_idx, res, data);
                    break;
                }

                case IO_TYPE_SOCK_WRITE: {
                    /* Write to network complete: Reset to wait for next local packet from TUN */
                    data->type = IO_TYPE_TUN_READ;
                    vpn_iouring_submit_read(&vfastctx.io_ring, vfastctx.tun.fd, current_idx, data);
                    break;
                }

                case IO_TYPE_TUN_WRITE: {
                    /* Write to TUN complete: Reset to wait for next remote packet from Socket */
                    data->type = IO_TYPE_SOCK_READ;
                    vpn_iouring_submit_recvmsg(&vfastctx.io_ring, vfastctx.udp->fd, current_idx, data);
                    break;
                }
            }
        }
        
        /* Mark CQE as processed and flush batched SQEs */
        io_uring_cqe_seen(&vfastctx.io_ring.ring, cqe);
        vpn_iouring_flush(&vfastctx.io_ring);
    }
    
    return 0;
}