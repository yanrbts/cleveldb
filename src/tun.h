/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __TUN_H__
#define __TUN_H__

#define _GNU_SOURCE
#include <stddef.h>
#include <net/if.h>
#include <linux/if_tun.h>

typedef struct {
    int fd;
    char name[IFNAMSIZ];
} __attribute__((aligned(8))) vpn_tun_ctx_t;

int vpn_tun_init(vpn_tun_ctx_t *ctx, const char *dev_name, int multi_queue);
int vpn_tun_set_status(const char *dev_name, int mtu, int up);
void vpn_tun_destroy(vpn_tun_ctx_t *ctx);

#endif