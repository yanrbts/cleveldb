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
#include "ippool.h"

typedef struct {
    uint32_t session_id;            /* Unique ID: For UDP -> TUN lookup/validation */
    uint32_t virtual_ip;            /* Key: Network Byte Order */
    struct sockaddr_in remote_addr; /* Value: Client Physical Addr */
    time_t last_seen;
    UT_hash_handle hh_ip;           /* handle for virtual_ip-based lookup */
    UT_hash_handle hh_sid;          /* Handle for SessionID-based lookup */
} __attribute__((aligned(64))) vpn_session_t;

typedef struct {
    uint32_t session_id;
    uint32_t virtual_ip;
    struct sockaddr_in remote_addr;
    int is_dead; // 1: Expired, 0: Active
} vpn_expired_node_t;

typedef struct {
    vpn_session_t *ip_table;        /* Hash head for hh (virtual_ip) */
    vpn_session_t *sid_table;       /* Hash head for hh_sid */           
    pthread_rwlock_t lock;          
} vpn_session_shard_t;

uint32_t vpn_generate_sid(uint32_t vip);
int vpn_session_init(void);
void vpn_session_destroy(void);
void vpn_session_update(uint32_t vip, uint32_t sid, const struct sockaddr_in *addr);
void vpn_session_update_by_sid(uint32_t sid, const struct sockaddr_in *addr);
bool vpn_session_lookup_by_ip(uint32_t vip, uint32_t *out_sid, struct sockaddr_in *out_addr);
bool vpn_session_lookup_by_sid(uint32_t sid, uint32_t *out_vip, struct sockaddr_in *out_addr);
void vpn_session_delete(uint32_t vip);
void vpn_session_clean_timeout(vpn_ip_pool_t *ipp, int timeout_sec);
/**
 * @brief Scans all shards and collects sessions that exceed the given thresholds.
 * @return Number of nodes collected.
 */
int vpn_session_get_expired(vpn_expired_node_t *list, int max_count, 
                             int probe_sec, int dead_sec);

#endif /* __SESSION_H__ */