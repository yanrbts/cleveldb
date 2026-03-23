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
#include "log.h"
#include "utils.h"
#include "crypto.h"

#define VFAST_VERSION       1
#define VFAST_BROADCAST     "255.255.255.0"

/* --- Global Context Structure --- */
typedef struct {
    /* 1. Network & Hardware Interfaces */
    vpn_iouring_ctx_t io_ring;   /* High-performance IO engine */
    vpn_tun_ctx_t     tun;       /* Virtual network interface */
    vpn_ip_pool_t     ip_pool;   /* IP address management */
    udp_conn_t        *udp;      /* UDP transport handle */

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

// extern vfast_ctx_t vfastctx;

static inline bool vfast_udp_read(vfast_ctx_t *ctx, int idx, vpn_io_data_t *data) {
    return vpn_submit_udp_recvmsg(&ctx->io_ring, ctx->udp->fd, idx, data) == 0 ? true : false;
}

static inline bool vfast_udp_writemsg(vfast_ctx_t *ctx, int idx, size_t tlen, vpn_io_data_t *data) {
    return vpn_submit_udp_sendmsg(&ctx->io_ring, ctx->udp->fd, idx, tlen, data) == 0 ? true : false;
}

static inline bool vfast_tun_read(vfast_ctx_t *ctx, int idx, vpn_io_data_t *d) {
    return vpn_submit_tun_read(&ctx->io_ring, ctx->tun.fd, idx, d) == 0 ? true : false;
}

static inline bool vfast_tun_write(vfast_ctx_t *ctx, int idx, vpn_io_data_t *d) {
    return vpn_submit_tun_write(&ctx->io_ring, ctx->tun.fd, idx, d) == 0 ? true : false;
}

static inline bool vfast_udp_write(vfast_ctx_t *ctx, int idx, size_t tlen, vpn_io_data_t *data) {
    int ret = vpn_submit_udp_send(&ctx->io_ring, ctx->udp->fd, idx, tlen, data);
    if (ret != 0) {
        atomic_fetch_add(&ctx->stats.drop_io_errors, 1);
        return false;
    }
    return true;
}

static inline void vfast_auto_reschedule(vfast_ctx_t *ctx, int idx) {
    vpn_io_data_t *d = &ctx->io_data_pool[idx];
    
    d->sid = 0; 

    if (d->source == SOURCE_TUN) {
        vfast_tun_read(ctx, idx, d);
    } else {
        vfast_udp_read(ctx, idx, d);
    }
}

void vfast_report_performance(vfast_ctx_t *ctx);
void vfast_io_warmup(vfast_ctx_t *ctx);
bool vfast_udp_rx(vfast_ctx_t *ctx, int res, int idx, vpn_io_data_t *data);
bool vfast_tun_rx(vfast_ctx_t *ctx, int res, int idx, vpn_io_data_t *data);
bool vfast_udp_client_rx(vfast_ctx_t *ctx, int res, int idx, vpn_io_data_t *data);
bool vfast_tun_client_rx(vfast_ctx_t *ctx, int res, int idx, vpn_io_data_t *data);
bool vfast_keeplive(vfast_ctx_t *ctx, int res, int idx, vpn_io_data_t *data);
int vfast_load_key(const char *key_path, uint8_t out_key[CRYPTO_KEY_SIZE]);

#endif