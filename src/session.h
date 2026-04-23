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
#include "key.h"

typedef struct {
    uint32_t session_id;            /* Unique ID: For UDP -> TUN lookup/validation */
    uint32_t virtual_ip;            /* Key: Network Byte Order */
    struct sockaddr_in remote_addr; /* Value: Client Physical Addr */
    atomic_uint_fast32_t next_seq;
    vfast_sec_ctx_t sec_ctx;        /* Security context for this session */
    time_t last_seen;

    UT_hash_handle hh_ip;           /* handle for virtual_ip-based lookup */
    UT_hash_handle hh_sid;          /* Handle for SessionID-based lookup */
} __attribute__((aligned(64))) vpn_session_t;

typedef struct {
    uint32_t session_id;
    uint32_t virtual_ip;
    struct sockaddr_in remote_addr;
    int is_dead;                    // 1: Expired, 0: Active
} vpn_expired_node_t;

typedef struct {
    vpn_session_t *ip_table;        /* Hash head for hh (virtual_ip) */
    vpn_session_t *sid_table;       /* Hash head for hh_sid */           
    pthread_rwlock_t lock;          
} vpn_session_shard_t;

/**
 * @brief Generates a unique Session ID (SID) for a given Virtual IP.
 * @param vip The virtual IP assigned to the client (network byte order).
 * @return A unique 32-bit session identifier.
 */
uint32_t vf_ss_generate_sid(uint32_t vip);

/**
 * @brief Initializes the session management module.
 * @details Allocates shard structures and initializes read-write locks.
 * @return 0 on success, non-zero on error.
 */
int vf_ss_init(void);

/**
 * @brief Tears down the session module and releases all resources.
 */
void vf_ss_destroy(void);

/**
 * @brief Removes a session from the tables using the Virtual IP as the key.
 * @param vip The Virtual IP of the session to be reclaimed.
 */
void vf_ss_delete(uint32_t vip);

/**
 * @brief Updates or creates a session mapping for an IP-SID pair.
 * @param vip   Virtual IP (Key).
 * @param sid   Session ID.
 * @param addr  Physical remote address (source IP/port) to associate.
 */
void vf_ss_update(uint32_t vip, uint32_t sid, const struct sockaddr_in *addr);

/**
 * @brief Updates the physical remote address of a session identified by SID.
 * @details Used for handling roaming clients or NAT mapping changes.
 * @param sid   The Session ID (Key).
 * @param addr  New physical remote address.
 */
void vf_ss_update_by_sid(uint32_t sid, const struct sockaddr_in *addr);

/**
 * @brief Performs Garbage Collection (GC) on sessions that have timed out.
 * @param ipp          Pointer to the IP pool to return reclaimed VIPs to.
 * @param timeout_sec  Inactivity threshold in seconds.
 */
void vf_ss_clean_timeout(vpn_ip_pool_t *ipp, int timeout_sec);

/**
 * @brief Locates a session object by its SID.
 * @note Acquires a shard read-lock internally.
 * @param[in]  sid   Session ID to search for.
 * @param[out] outs  Pointer to store the retrieved session object address.
 * @return true if found, false otherwise.
 */
bool vf_ss_lookup_by_sid(uint32_t sid, vpn_session_t **outs);

/**
 * @brief Locates a session object by its Virtual IP.
 * @note Acquires a shard read-lock internally.
 * @param[in]  vip   Virtual IP to search for.
 * @param[out] outs  Pointer to store the retrieved session object address.
 * @return true if found, false otherwise.
 */
bool vf_ss_lookup_by_ip(uint32_t vip, vpn_session_t **outs);

/**
 * @brief Scans all shards and collects sessions that exceed the given thresholds.
 * @return Number of nodes collected.
 */
int vf_ss_get_expired(vpn_expired_node_t *list, int max_count, 
                             int probe_sec, int dead_sec);
/**
 * @brief Retrieves the total number of active sessions across all shards.
 * This function iterates through all memory shards, acquiring a read lock
 * on each to ensure thread safety while querying the uthash structure.
 * @note Complexity: O(N) where N is the number of shards. 
 * The underlying HASH_CNT macro is O(1).
 * @return uint32_t Total count of active sessions.
 */
uint32_t vf_ss_get_total_count(void);

#endif /* __SESSION_H__ */