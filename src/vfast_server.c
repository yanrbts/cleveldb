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
#include <errno.h>

#include "log.h"
#include "utils.h"
#include "vfast.h"
#include "session.h"
#include "iouring.h"
#include "zmalloc.h"
#include "udp.h"
#include "protocol.h"

/* Global Context Instance */
vfast_ctx_t vfastctx;

/* Simple signal handling for graceful shutdown */
static void signal_handler(int sig) {
    (void)sig;
    atomic_store(&vfastctx.running, false);
}

/* --- Internal Helpers (Short Names) --- */
static void submit_tun_read(int idx, vpn_io_data_t *d) {
    const int off = VPN_TNL_HLEN + sizeof(struct iphdr);
    d->type = IO_TYPE_TUN_READ;
    d->buf_idx = idx;

    void *org_ptr = vfastctx.io_ring.iovecs[idx].iov_base;
    size_t org_len = vfastctx.io_ring.iovecs[idx].iov_len;

    /* Apply zero-copy offset */
    vfastctx.io_ring.iovecs[idx].iov_base = (uint8_t *)org_ptr + off;
    vfastctx.io_ring.iovecs[idx].iov_len = org_len - off;

    vpn_iouring_submit_read(&vfastctx.io_ring, vfastctx.tun.fd, idx, d);

    /* Restore iovec */
    vfastctx.io_ring.iovecs[idx].iov_base = org_ptr;
    vfastctx.io_ring.iovecs[idx].iov_len = org_len;
}

static void submit_tun_write(int idx, uint8_t *ptr, int len, vpn_io_data_t *d) {
    d->type = IO_TYPE_TUN_WRITE;
    d->buf_idx = idx;
    void *org_ptr = vfastctx.io_ring.iovecs[idx].iov_base;
    vfastctx.io_ring.iovecs[idx].iov_base = ptr;

    vpn_iouring_submit_write(&vfastctx.io_ring, vfastctx.tun.fd, idx, len, d);
    vfastctx.io_ring.iovecs[idx].iov_base = org_ptr;
}

/* --- Core Event Handlers --- */

static void handle_tun_rx(int res, int idx, vpn_io_data_t *data) {
    atomic_fetch_add(&vfastctx.stats.rx_packets, 1);
    const int off = VPN_TNL_HLEN + sizeof(struct iphdr);
    uint8_t *base = (uint8_t *)vfastctx.io_ring.iovecs[idx].iov_base;
    struct iphdr *iph = (struct iphdr *)(base + off);
    struct sockaddr_in remote;

    if (vpn_session_lookup(iph->daddr, &remote)) {
        int tlen = vpn_pack(base, res, IO_BUF_SIZE, VPN_MSG_DATA, data->sid, iph->saddr, iph->daddr);
        if (tlen > 0) {
            data->type = IO_TYPE_SOCK_WRITE;
            memcpy(&data->udp_meta.client_addr, &remote, sizeof(remote));
            vpn_iouring_submit_write(&vfastctx.io_ring, vfastctx.udp->fd, idx, tlen, data);
            return;
        }
    }
    submit_tun_read(idx, data);
}

static void handle_udp_rx(int res, int idx, vpn_io_data_t *data) {
    atomic_fetch_add(&vfastctx.stats.tx_packets, 1);
    uint8_t *base = (uint8_t *)vfastctx.io_ring.iovecs[idx].iov_base;
    int plen;
    uint32_t sid;
    
    uint8_t *ip_pkt = vpn_unpack(base, res, &plen, &sid);
    if (ip_pkt) {
        struct iphdr *iph = (struct iphdr *)ip_pkt;
        vpn_session_update(iph->saddr, &data->udp_meta.client_addr);
        data->sid = sid;
        submit_tun_write(idx, ip_pkt, plen, data);
    } else {
        vpn_iouring_submit_recvmsg(&vfastctx.io_ring, vfastctx.udp->fd, idx, data);
    }
}

static int vfast_clean_server(void) {
    vpn_session_destroy();
    if (vfastctx.udp) udp_close(vfastctx.udp);
    vpn_tun_destroy(&vfastctx.tun);
    vpn_iouring_destroy(&vfastctx.io_ring);
    return 0;
}

/**
 * @brief Pre-allocate and submit initial read requests to warm up the I/O ring.
 */
static void vfast_io_warmup(vfast_ctx_t *ctx) {
    for (int i = 0; i < 256; i++) {
        int idx_t = vfast_buf_pop(ctx);
        int idx_s = vfast_buf_pop(ctx);

        /* Submit TUN read request with zero-copy offset */
        if (idx_t != -1) {
            vpn_io_data_t *d = zmalloc(sizeof(vpn_io_data_t));
            if (d) {
                memset(d, 0, sizeof(vpn_io_data_t));
                submit_tun_read(idx_t, d);
            }
        }

        /* Submit UDP Socket read request */
        if (idx_s != -1) {
            vpn_io_data_t *d = zmalloc(sizeof(vpn_io_data_t));
            if (d) {
                memset(d, 0, sizeof(vpn_io_data_t));
                d->buf_idx = idx_s;
                d->type = IO_TYPE_SOCK_READ;
                vpn_iouring_submit_recvmsg(&ctx->io_ring, ctx->udp->fd, idx_s, d);
            }
        }
    }
    vpn_iouring_flush(&ctx->io_ring);
    log_info("I/O Pipeline Warmed: 512 read requests submitted with offsets.");
}

static int vfast_init_server(void) {
    memset(&vfastctx, 0, sizeof(vfast_ctx_t));
    vfastctx.free_top = -1;
    atomic_store(&vfastctx.running, true);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (vpn_session_init() < 0) {
        log_error("Failed to initialize session manager");
        return -1;
    }

    if (vpn_iouring_init(&vfastctx.io_ring, IO_RING_DEPTH) < 0) {
        log_error("Init iouring failed");
        return -1;
    }

    if (vpn_tun_init(&vfastctx.tun, "tun0", 1) < 0) {
        log_error("Failed to initialize TUN device");
        return -1;
    }
    
    vpn_tun_set_ip(vfastctx.tun.name, "10.0.0.1", "255.255.255.0");
    vpn_tun_set_status(vfastctx.tun.name, VPN_MTU_DEFAULT, 1); /* MTU 1400 to allow header overhead */
    vpn_set_nonblocking(vfastctx.tun.fd);

    vfastctx.udp = udp_init_listener(9999, 20); 
    if (!vfastctx.udp) {
        log_error("Failed to init UDP listener");
        goto cleanup;
    }
    vpn_set_nonblocking(vfastctx.udp->fd);

    for (int i = 0; i < IO_BUF_POOL_SIZE; i++) {
        vfast_buf_push(&vfastctx, i);
    }

    vfast_io_warmup(&vfastctx);
    return 0;

cleanup:
    vfast_clean_server();
    return -1;
}

/* * Core Event Loop - Optimized for Clarity
 */
int main(int argc, char *argv[]) {
    UNUSED(argc);
    UNUSED(argv);
    if (vfast_init_server() < 0) return 1;

    while (atomic_load(&vfastctx.running)) {
        struct io_uring_cqe *cqe;
        if (io_uring_wait_cqe(&vfastctx.io_ring.ring, &cqe) < 0) break;

        vpn_io_data_t *data = (vpn_io_data_t *)io_uring_cqe_get_data(cqe);
        int res = cqe->res, idx = data->buf_idx;

        if (unlikely(res <= 0)) {
            /* Error Handling: Resubmit initial state or recycle buffer */
            if (data->type == IO_TYPE_TUN_READ) 
                submit_tun_read(idx, data);
            else if (data->type == IO_TYPE_SOCK_READ) 
                vpn_iouring_submit_recvmsg(&vfastctx.io_ring, vfastctx.udp->fd, idx, data);
            else { 
                vfast_buf_push(&vfastctx, idx); 
                zfree(data); 
            }
        } else {
            /* Finite State Machine (FSM) */
            switch (data->type) {
                case IO_TYPE_TUN_READ:  
                    handle_tun_rx(res, idx, data); 
                    break;

                case IO_TYPE_SOCK_READ: 
                    handle_udp_rx(res, idx, data); 
                    break;

                case IO_TYPE_SOCK_WRITE: 
                    /* UDP Sent -> Wait for next TUN packet */
                    submit_tun_read(idx, data); 
                    break;

                case IO_TYPE_TUN_WRITE: 
                    /* TUN Injected -> Wait for next UDP packet */
                    data->type = IO_TYPE_SOCK_READ;
                    vpn_iouring_submit_recvmsg(&vfastctx.io_ring, vfastctx.udp->fd, idx, data);
                    break;
            }
        }

        io_uring_cqe_seen(&vfastctx.io_ring.ring, cqe);
        vpn_iouring_flush(&vfastctx.io_ring);
    }

    vfast_clean_server();
    return 0;
}