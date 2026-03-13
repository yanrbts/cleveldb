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

/* --- Global Context Structure --- */
typedef struct {
    /* 1. Network & Hardware Interfaces */
    vpn_iouring_ctx_t io_ring;   /* High-performance IO engine */
    vpn_tun_ctx_t     tun;       /* Virtual network interface */
    udp_conn_t        *udp;      /* UDP transport handle */

    /* 2. Buffer Management (Lock-free pool using stack) */
    int               free_buffers[IO_BUF_POOL_SIZE];
    int               free_top;
    
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

#endif