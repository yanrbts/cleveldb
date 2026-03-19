/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __VFAST_H__
#define __VFAST_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <net/if.h>
#include "iouring.h"
#include "tun.h"
#include "udp.h"
#include "ippool.h"

#define VFAST_VERSION 1

/* --- Global Context Structure --- */
typedef struct {
    /* 1. Network & Hardware Interfaces */
    vpn_iouring_ctx_t io_ring;   /* High-performance IO engine */
    vpn_tun_ctx_t     tun;       /* Virtual network interface */
    vpn_ip_pool_t     ip_pool;   /* IP address management */
    udp_conn_t        *udp;      /* UDP transport handle */

    /* 2. Buffer Management (Lock-free pool using stack) */
    int               free_buffers[IO_BUF_POOL_SIZE];
    int               free_top;

    vpn_io_data_t     *io_data_pool;
    
    /* 3. Global Status & Config */
    atomic_bool       running;   /* Control flag for main loop */
    uint16_t          port;      /* Listener/Remote port */
    char              remote_host[256];
    
    /* 4. Statistics (Cache-line aligned for performance) */
    struct {
        atomic_uint_fast64_t tx_packets;
        atomic_uint_fast64_t rx_packets;
        atomic_uint_fast64_t tx_bytes;
        atomic_uint_fast64_t rx_bytes;

        /* Error & Drop counters */
        atomic_uint_fast64_t drop_session_miss;   /* Session lookup failed */
        atomic_uint_fast64_t drop_unpack_error;   /* VFAST protocol unpack failed */
        atomic_uint_fast64_t drop_pack_error;     /* VFAST protocol pack failed */
        atomic_uint_fast64_t drop_io_errors;      /* io_uring completion errors (res <= 0) */
    } stats;

} __attribute__((aligned(64))) vfast_ctx_t;

extern vfast_ctx_t vfastctx;

static inline void vfast_buf_push(vfast_ctx_t *ctx, int idx) {
    if (ctx->free_top < IO_BUF_POOL_SIZE - 1) {
        ctx->free_buffers[++(ctx->free_top)] = idx;
    }
}

static inline int vfast_buf_pop(vfast_ctx_t *ctx) {
    if (ctx->free_top >= 0) {
        return ctx->free_buffers[(ctx->free_top)--];
    }
    return -1;
}

static inline void vfast_udp_read(int idx, vpn_io_data_t *data) {
    vpn_submit_udp_recvmsg(&vfastctx.io_ring, vfastctx.udp->fd, idx, data);
}

static inline void vfast_udp_writemsg(int idx, size_t tlen, vpn_io_data_t *data) {
    vpn_submit_udp_sendmsg(&vfastctx.io_ring, vfastctx.udp->fd, idx, tlen, data);
}

static inline void vfast_tun_read(int idx, vpn_io_data_t *d) {
    vpn_submit_tun_read(&vfastctx.io_ring, vfastctx.tun.fd, idx, d);
}

static inline void vfast_tun_write(int idx, vpn_io_data_t *d) {
    vpn_submit_tun_write(&vfastctx.io_ring, vfastctx.tun.fd, idx, d);
}

static inline void vfast_udp_write(int idx, size_t tlen, vpn_io_data_t *data) {
    int ret = vpn_submit_udp_send(&vfastctx.io_ring, vfastctx.udp->fd, idx, tlen, data);
    if (ret != 0) {
        atomic_fetch_add(&vfastctx.stats.drop_io_errors, 1);
        vfast_tun_read(idx, data);
    }
}

void vfast_report_performance(void);
void vfast_io_warmup(vfast_ctx_t *ctx);
void vfast_udp_rx(int res, int idx, vpn_io_data_t *data);
void vfast_tun_rx(int res, int idx, vpn_io_data_t *data);
void vfast_udp_client_rx(int res, int idx, vpn_io_data_t *data);
void vfast_tun_client_rx(int res, int idx, vpn_io_data_t *data);
void vfast_keep(int res, int idx, vpn_io_data_t *data);
#endif