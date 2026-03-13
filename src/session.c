/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <stdlib.h>
#include <string.h>
#include "session.h"
#include "log.h"
#include "zmalloc.h"

#define VPN_SESSION_SHARD_COUNT 16

static vpn_session_shard_t g_shards[VPN_SESSION_SHARD_COUNT];

static inline uint32_t vpn_get_shard_idx(uint32_t ip) {
    return (ip ^ (ip >> 16)) & (VPN_SESSION_SHARD_COUNT - 1);
}

int vpn_session_init(void) {
    for (int i = 0; i < VPN_SESSION_SHARD_COUNT; i++) {
        g_shards[i].table = NULL;
        if (pthread_rwlock_init(&g_shards[i].lock, NULL) != 0) {
            log_error("VPN_SESSION: Failed to init rwlock %d", i);
            return -1;
        }
    }
    log_info("VPN_SESSION: Industrial Manager initialized (Shards: %d)", VPN_SESSION_SHARD_COUNT);
    return 0;
}

void vpn_session_update(uint32_t v_ip, const struct sockaddr_in *addr) {
    if (!addr) return;

    uint32_t idx = vpn_get_shard_idx(v_ip);
    vpn_session_t *s = NULL;

    pthread_rwlock_wrlock(&g_shards[idx].lock);
    
    HASH_FIND_INT(g_shards[idx].table, &v_ip, s);
    if (!s) {
        s = (vpn_session_t *)zmalloc(sizeof(vpn_session_t));
        if (s) {
            s->virtual_ip = v_ip;
            HASH_ADD_INT(g_shards[idx].table, virtual_ip, s);
        }
    }

    if (s) {
        memcpy(&s->remote_addr, addr, sizeof(struct sockaddr_in));
        s->last_seen = time(NULL);
    }
    
    pthread_rwlock_unlock(&g_shards[idx].lock);
}

bool vpn_session_lookup(uint32_t v_ip, struct sockaddr_in *out_addr) {
    uint32_t idx = vpn_get_shard_idx(v_ip);
    vpn_session_t *s = NULL;
    bool found = false;

    pthread_rwlock_rdlock(&g_shards[idx].lock);
    
    HASH_FIND_INT(g_shards[idx].table, &v_ip, s);
    if (s) {
        if (out_addr) memcpy(out_addr, &s->remote_addr, sizeof(struct sockaddr_in));
        found = true;
    }
    
    pthread_rwlock_unlock(&g_shards[idx].lock);
    return found;
}

void vpn_session_delete(uint32_t v_ip) {
    uint32_t idx = vpn_get_shard_idx(v_ip);
    vpn_session_t *s = NULL;

    pthread_rwlock_wrlock(&g_shards[idx].lock);
    HASH_FIND_INT(g_shards[idx].table, &v_ip, s);
    if (s) {
        HASH_DEL(g_shards[idx].table, s);
        zfree(s);
    }
    pthread_rwlock_unlock(&g_shards[idx].lock);
}

void vpn_session_gc(int timeout_sec) {
    time_t now = time(NULL);
    for (int i = 0; i < VPN_SESSION_SHARD_COUNT; i++) {
        vpn_session_t *s, *tmp;
        
        /* 尝试获取写锁，如果不成功则跳过该分片下次再处理，避免长时间阻塞转发线程 */
        if (pthread_rwlock_trywrlock(&g_shards[i].lock) != 0) continue;

        HASH_ITER(hh, g_shards[i].table, s, tmp) {
            if (difftime(now, s->last_seen) > timeout_sec) {
                HASH_DEL(g_shards[i].table, s);
                zfree(s);
            }
        }
        pthread_rwlock_unlock(&g_shards[i].lock);
    }
}

void vpn_session_destroy(void) {
    for (int i = 0; i < VPN_SESSION_SHARD_COUNT; i++) {
        vpn_session_t *s, *tmp;
        pthread_rwlock_wrlock(&g_shards[i].lock);
        HASH_ITER(hh, g_shards[i].table, s, tmp) {
            HASH_DEL(g_shards[i].table, s);
            zfree(s);
        }
        pthread_rwlock_unlock(&g_shards[i].lock);
        pthread_rwlock_destroy(&g_shards[i].lock);
    }
    log_info("VPN_SESSION: Manager destroyed.");
}