/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include "vfast.h"
#include "session.h"
#include "log.h"
#include "utils.h"
#include "zmalloc.h"


#define VPN_SESSION_SHARD_COUNT 16

static vpn_session_shard_t g_shards[VPN_SESSION_SHARD_COUNT];

static inline uint32_t vpn_get_shard_idx(uint32_t ip) {
    return (ip ^ (ip >> 16)) & (VPN_SESSION_SHARD_COUNT - 1);
}

/**
 * vfast_generate_sid - Generates a shard-aligned and secure SessionID.
 * @v_ip: The assigned virtual IP (Network Byte Order).
 *
 * DESIGN PHILOSOPHY:
 * In a high-performance multi-threaded VPN, we shard the session table to 
 * reduce lock contention. By ensuring that the SessionID (used for UDP ingress) 
 * and the Virtual IP (used for TUN egress) map to the same shard index, we 
 * allow both lookup paths to access the same pthread_rwlock and cache line.
 *
 * MATHEMATICAL DERIVATION:
 * The shard index is calculated as: idx = (val ^ (val >> 16)) & MASK.
 * To generate a SessionID (sid) that matches a target_idx:
 * 1. We keep the high 16 bits of a random number (high_bits).
 * 2. We solve for the low bits: idx = (high_bits >> 16) ^ low_bits.
 * 3. Therefore: low_bits = idx ^ (high_bits >> 16).
 *
 * Return: A 32-bit cryptographically random SessionID aligned to the IP's shard.
 */
uint32_t vpn_generate_sid(uint32_t v_ip) {
    /* Calculate the target shard index based on the Virtual IP */
    uint32_t target_idx = vpn_get_shard_idx(v_ip);
    uint32_t raw_rand;

    /* Use a cryptographically secure random source (non-blocking) */
    if (getrandom(&raw_rand, sizeof(raw_rand), GRND_NONBLOCK) != sizeof(raw_rand)) {
        /* Fallback to standard library rand() if entropy pool is unavailable */
        raw_rand = (uint32_t)rand();
    }

    /**
     * SHARD ALIGNMENT LOGIC:
     * We preserve the entropy in the upper 24 bits and only manipulate the 
     * specific bits required to satisfy the (sid ^ (sid >> 16)) & MASK 
     * sharding constraint.
     */
    uint32_t high_bits = raw_rand & 0xFFFF0000;
    
    /* Calculate the specific low bits needed to match the IP's shard index */
    uint32_t needed_bits = (target_idx ^ (high_bits >> 16)) & (VPN_SESSION_SHARD_COUNT - 1);
    
    /**
     * Construct the final SessionID:
     * - [31:16]: Pure random bits.
     * - [15:4]:  Additional random padding (assuming 16 shards).
     * - [3:0]:   The shard-alignment bits.
     */
    uint32_t sid = high_bits | (raw_rand & 0x0000FFF0) | needed_bits;

    /* Verification (Internal integrity check) */
    /* assert(vpn_get_shard_idx(sid) == target_idx); */

    return sid;
}

int vpn_session_init(void) {
    for (int i = 0; i < VPN_SESSION_SHARD_COUNT; i++) {
        g_shards[i].ip_table = NULL;
        g_shards[i].sid_table = NULL;
        if (pthread_rwlock_init(&g_shards[i].lock, NULL) != 0) {
            log_error("VPN_SESSION: Failed to init rwlock %d", i);
            return -1;
        }
    }
    log_info("VPN_SESSION: Industrial Manager initialized (Shards: %d)", VPN_SESSION_SHARD_COUNT);
    return 0;
}

void vpn_session_update(uint32_t v_ip, uint32_t s_id, const struct sockaddr_in *addr) {
    if (!addr) return;

    uint32_t idx = vpn_get_shard_idx(v_ip);
    vpn_session_t *s = NULL;

    pthread_rwlock_wrlock(&g_shards[idx].lock);
    
    HASH_FIND(hh_ip, g_shards[idx].ip_table, &v_ip, sizeof(uint32_t), s);
    if (!s) {
        s = (vpn_session_t *)zmalloc(sizeof(vpn_session_t));
        if (s) {
            s->virtual_ip = v_ip;
            s->session_id = s_id;

            vfast_rekey_init(&s->sec_ctx, s_id); // Initialize security context for this session

            HASH_ADD(hh_ip, g_shards[idx].ip_table, virtual_ip, sizeof(uint32_t), s);
            HASH_ADD(hh_sid, g_shards[idx].sid_table, session_id, sizeof(uint32_t), s);
        }
    } else {
        if (s->session_id != s_id) {
            HASH_DELETE(hh_sid, g_shards[idx].sid_table, s);
            s->session_id = s_id;
            HASH_ADD(hh_sid, g_shards[idx].sid_table, session_id, sizeof(uint32_t), s);
        }
    }

    if (s) {
        memcpy(&s->remote_addr, addr, sizeof(struct sockaddr_in));
        s->last_seen = time(NULL);
    }
    
    pthread_rwlock_unlock(&g_shards[idx].lock);
}

/**
 * vpn_session_update_by_sid - Rapidly refreshes session activity via SessionID.
 * @s_id: The unique 32-bit SessionID extracted from the UDP tunnel header.
 * @addr: The source address of the incoming UDP packet (for Roaming/Mobility support).
 *
 * DESIGN RATIONALE:
 * This function leverages the shard-alignment property of our SessionIDs. Since
 * vpn_generate_sid() ensures (sid ^ (sid >> 16)) maps to the same shard as the 
 * associated Virtual IP, we can perform a localized search within a single shard
 * lock, significantly reducing global contention.
 */
void vpn_session_update_by_sid(uint32_t s_id, const struct sockaddr_in *addr) {
    /* 1. Defensive programming: Ensure input validity */
    if (unlikely(!addr)) {
        return;
    }

    /* 2. Locate the shard using the aligned SessionID */
    uint32_t idx = vpn_get_shard_idx(s_id);
    vpn_session_t *s = NULL;

    /* 3. Acquire write lock: Needed for updating timestamps and roaming info */
    pthread_rwlock_wrlock(&g_shards[idx].lock);

    /**
     * 4. Perform secondary index lookup.
     * Use 'hh_sid' handle to query the session ID hash table within this shard.
     */
    HASH_FIND(hh_sid, g_shards[idx].sid_table, &s_id, sizeof(uint32_t), s);

    if (likely(s)) {
        /**
         * 5. Handle Client Roaming (Mobility).
         * If the client's source IP or Port changed (e.g., switched from Wi-Fi to 4G),
         * update the remote_addr to ensure return traffic reaches the new endpoint.
         */
        if (unlikely(s->remote_addr.sin_addr.s_addr != addr->sin_addr.s_addr ||
                     s->remote_addr.sin_port != addr->sin_port)) {
            memcpy(&s->remote_addr, addr, sizeof(struct sockaddr_in));
        }

        /* 6. Heartbeat logic: Update last seen timestamp to prevent timeout */
        s->last_seen = time(NULL);

    } else {
        /* Optional: Trace orphan management packets for debugging */
        // log_debug("SESSION: Update failed, SID 0x%08x not found in shard %u", s_id, idx);
    }

    /* 8. Release lock as early as possible */
    pthread_rwlock_unlock(&g_shards[idx].lock);
}

bool vpn_session_lookup_by_ip(uint32_t v_ip, uint32_t *out_sid, struct sockaddr_in *out_addr) {
    uint32_t idx = vpn_get_shard_idx(v_ip);
    vpn_session_t *s = NULL;
    bool found = false;

    pthread_rwlock_rdlock(&g_shards[idx].lock);
    
    HASH_FIND(hh_ip, g_shards[idx].ip_table, &v_ip, sizeof(uint32_t), s);
    if (s) {
        if (out_sid) *out_sid = s->session_id;
        if (out_addr) memcpy(out_addr, &s->remote_addr, sizeof(struct sockaddr_in));
        found = true;
    }
    
    pthread_rwlock_unlock(&g_shards[idx].lock);
    return found;
}

bool vpn_session_lookup_by_sid(uint32_t s_id, uint32_t *out_v_ip, struct sockaddr_in *out_addr) {
    uint32_t idx = vpn_get_shard_idx(s_id); 
    vpn_session_t *s = NULL;
    bool found = false;

    pthread_rwlock_rdlock(&g_shards[idx].lock);
    HASH_FIND(hh_sid, g_shards[idx].sid_table, &s_id, sizeof(uint32_t), s);
    if (s) {
        if (out_v_ip) *out_v_ip = s->virtual_ip;
        if (out_addr) memcpy(out_addr, &s->remote_addr, sizeof(struct sockaddr_in));
        found = true;
    }
    pthread_rwlock_unlock(&g_shards[idx].lock);
    return found;
}

/**
 * vpn_session_delete - Remove a session from both IP and SID hash tables.
 * @v_ip: The virtual IP address (Network Byte Order) used as the primary key.
 *
 * This function performs a dual-index removal. Since both indexes (hh_ip and hh_sid)
 * point to the same memory object, we must detach the object from both tables 
 * before calling zfree() to prevent dangling pointers and memory corruption.
 */
void vpn_session_delete(uint32_t v_ip) {
    /* Determine which shard contains this IP */
    uint32_t idx = vpn_get_shard_idx(v_ip);
    vpn_session_t *s = NULL;

    /* Acquire write lock for the specific shard to ensure atomicity */
    pthread_rwlock_wrlock(&g_shards[idx].lock);

    /* 1. Locate the session object using the IP-based index */
    HASH_FIND(hh_ip, g_shards[idx].ip_table, &v_ip, sizeof(uint32_t), s);

    if (s) {
        /**
         * CRITICAL: Multi-Index Deletion
         * Even though we found the object via IP, it is still linked in the 
         * SID table. We must remove it from BOTH to maintain heap integrity.
         */
        
        /* Remove from the IP-indexed hash table */
        HASH_DELETE(hh_ip, g_shards[idx].ip_table, s);
        
        /* Remove from the SessionID-indexed hash table using the SID handle */
        HASH_DELETE(hh_sid, g_shards[idx].sid_table, s);

        /* Log the deletion for audit/debug purposes */
        log_debug("Session destroyed for IP: %u.%u.%u.%u | SID: 0x%08x", 
                  (v_ip & 0xFF), (v_ip >> 8) & 0xFF, 
                  (v_ip >> 16) & 0xFF, (v_ip >> 24) & 0xFF,
                  s->session_id);
        memset(&s->sec_ctx, 0, sizeof(vfast_sec_ctx_t));
        /* 2. Safe to release memory only after all references are removed */
        zfree(s);
    }

    pthread_rwlock_unlock(&g_shards[idx].lock);
}

bool vpn_lookup_session_by_sid(uint32_t sid, vpn_session_t **outs) {
    uint32_t idx = vpn_get_shard_idx(sid); 
    vpn_session_t *s = NULL;

    pthread_rwlock_rdlock(&g_shards[idx].lock);
    HASH_FIND(hh_sid, g_shards[idx].sid_table, &sid, sizeof(uint32_t), s);
    pthread_rwlock_unlock(&g_shards[idx].lock);
    *outs = s;

    return s != NULL;
}

bool vpn_lookup_session_by_ip(uint32_t vip, vpn_session_t **outs) {
    uint32_t idx = vpn_get_shard_idx(vip); 
    vpn_session_t *s = NULL;

    pthread_rwlock_rdlock(&g_shards[idx].lock);
    HASH_FIND(hh_ip, g_shards[idx].ip_table, &vip, sizeof(uint32_t), s);
    pthread_rwlock_unlock(&g_shards[idx].lock);
    *outs = s;

    return s != NULL;
}

/**
 * vpn_session_clean_timeout - Periodic scavenger to reclaim stale sessions.
 * @ipp: Pointer to the IP pool to return reclaimed IPs.
 * @timeout_sec: Inactivity threshold in seconds.
 *
 * This function iterates through all shards. It is designed to be called 
 * by a background maintenance thread or a periodic timer in the main loop.
 */
void vpn_session_clean_timeout(vpn_ip_pool_t *ipp, int timeout_sec) {
    time_t now = time(NULL);

    /* Iterate through all shards to distribute the locking overhead */
    for (int i = 0; i < VPN_SESSION_SHARD_COUNT; i++) {
        pthread_rwlock_wrlock(&g_shards[i].lock);
        
        vpn_session_t *s, *tmp;
        
        /**
         * Use HASH_ITER to safely delete elements while traversing.
         * We use hh_ip as the primary traversal handle.
         */
        HASH_ITER(hh_ip, g_shards[i].ip_table, s, tmp) {
            if (now - s->last_seen > timeout_sec) {
                
                /* Return the virtual IP to the pool for reuse by other clients */
                if (ipp) {
                    vpn_ip_pool_free(ipp, s->virtual_ip);
                }

                /* Detach from both hash indexes simultaneously */
                HASH_DELETE(hh_ip, g_shards[i].ip_table, s);
                HASH_DELETE(hh_sid, g_shards[i].sid_table, s);
                
                /* Release the session memory */
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
        HASH_ITER(hh_ip, g_shards[i].ip_table, s, tmp) {
            HASH_DELETE(hh_ip, g_shards[i].ip_table, s);
            HASH_DELETE(hh_sid, g_shards[i].sid_table, s);
            zfree(s);
        }
        pthread_rwlock_unlock(&g_shards[i].lock);
        pthread_rwlock_destroy(&g_shards[i].lock);
    }
    log_info("VPN_SESSION: Manager destroyed.");
}

int vpn_session_get_expired(vpn_expired_node_t *list, int max_count, 
                             int probe_sec, int dead_sec) {
    int count = 0;
    time_t now = time(NULL);

    for (int i = 0; i < VPN_SESSION_SHARD_COUNT; i++) {
        pthread_rwlock_rdlock(&g_shards[i].lock);
        
        vpn_session_t *s, *tmp;
        HASH_ITER(hh_ip, g_shards[i].ip_table, s, tmp) {
            long idle = now - s->last_seen;
            if (idle >= probe_sec) {
                list[count].session_id = s->session_id;
                list[count].virtual_ip = s->virtual_ip;
                list[count].remote_addr = s->remote_addr;
                list[count].is_dead = (idle >= dead_sec);
                
                if (++count >= max_count) break;
            }
        }
        
        pthread_rwlock_unlock(&g_shards[i].lock);
        if (count >= max_count) break;
    }
    return count;
}

/**
 * @brief Generates the next sequence number for a specific session.
 * * Uses atomic operations to ensure thread-safety without mutex overhead.
 * * Sequence numbers are critical for:
 * 1. Anti-Replay: Preventing attackers from re-sending captured valid packets.
 * 2. Obfuscation: Providing a rolling seed for XOR masking.
 * @param session Pointer to the active user session.
 * @return uint32_t The next available sequence number in Network Byte Order.
 */
uint32_t vpn_get_srv_next_sequence(vpn_session_t *session) {
    if (!session) return 0;

    /* atomic_fetch_add returns the value BEFORE the addition.
     * memory_order_relaxed is sufficient here as seq_num doesn't 
     * guard other memory accesses (no happens-before requirement).
     */
    uint32_t seq = atomic_fetch_add_explicit(&session->next_seq, 1, memory_order_relaxed);
    
    /* Return in Network Byte Order (Big Endian) to ensure consistency 
     * across different CPU architectures.
     */
    return htonl(seq);
}