/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */

#ifndef __IP_POOL_H__
#define __IP_POOL_H__

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <arpa/inet.h>

/**
 * @brief Industrial-grade IP Address Pool Manager.
 * Uses a bitmap for O(1) allocation and memory efficiency.
 * Aligned to 64 bytes to prevent False Sharing with neighboring data.
 */
typedef struct {
    uint32_t start_ip;          /* Network Byte Order */
    uint32_t pool_size;         
    uint8_t *bitmap;            
    uint32_t next_hint;         
    pthread_mutex_t lock;       
} __attribute__((aligned(64))) vpn_ip_pool_t;

/**
 * @brief Initialize the IP pool with industrial exclusion rules.
 * Automatically reserves .0 (Network), .1 (Gateway), and .255 (Broadcast).
 */
int vf_ip_pool_init(vpn_ip_pool_t *pool, const char *cidr_start, uint32_t size);

/**
 * @brief Allocate an IP address from the pool. Thread-safe.
 * @return IP address in Network Byte Order, 0 if pool is exhausted.
 */
uint32_t vf_ip_pool_alloc(vpn_ip_pool_t *pool);

/**
 * @brief Reclaim an IP address. Validates range before marking as free.
 * @param ip IP in Network Byte Order.
 */
void vf_ip_pool_free(vpn_ip_pool_t *pool, uint32_t ip);

/**
 * @brief Thread-safe destruction of the pool resources.
 */
void vf_ip_pool_destroy(vpn_ip_pool_t *pool);

#endif /* VPN_IP_POOL_H */