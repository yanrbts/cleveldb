/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __SESSION_H__
#define __SESSION_H__

#include <stdint.h>
#include <netinet/in.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include "uthash.h"

typedef struct {
    uint32_t virtual_ip;            /* Key: Network Byte Order */
    struct sockaddr_in remote_addr; /* Value: Client Physical Addr */
    time_t last_seen;
    UT_hash_handle hh;              /* uthash handle */
} __attribute__((aligned(64))) vpn_session_t;

typedef struct {
    vpn_session_t *table;           
    pthread_rwlock_t lock;          
} vpn_session_shard_t;

int vpn_session_init(void);
void vpn_session_destroy(void);
void vpn_session_update(uint32_t vip, const struct sockaddr_in *addr);
bool vpn_session_lookup(uint32_t vip, struct sockaddr_in *out_addr);
void vpn_session_delete(uint32_t vip);
void vpn_session_gc(int timeout_sec);

#endif /* __SESSION_H__ */