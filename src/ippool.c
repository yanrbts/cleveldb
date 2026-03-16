/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */


#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "zmalloc.h"
#include "log.h"
#include "utils.h"
#include "ippool.h"

int vpn_ip_pool_init(vpn_ip_pool_t *pool, const char *cidr_start, uint32_t size) {
    if (unlikely(!pool || !cidr_start || size == 0)) {
        return -EINVAL;
    }

    memset(pool, 0, sizeof(vpn_ip_pool_t));
    
    pool->start_ip = inet_addr(cidr_start);
    if (pool->start_ip == INADDR_NONE) return -EINVAL;
    
    pool->pool_size = size;
    uint32_t bitmap_size = (size + 7) / 8;

    pool->bitmap = (uint8_t *)zmalloc(bitmap_size);
    if (unlikely(!pool->bitmap)) {
        log_error("IPAM: Failed to allocate bitmap memory");
        return -ENOMEM;
    }

    memset(pool->bitmap, 0, bitmap_size);
    
    if (unlikely(pthread_mutex_init(&pool->lock, NULL) != 0)) {
        zfree(pool->bitmap);
        return -1;
    }

    /* Feature A: Industrial Exclusion Logic */
    uint32_t start_h = ntohl(pool->start_ip);
    uint32_t excl_count = 0;

    for (uint32_t i = 0; i < size; i++) {
        uint32_t curr_h = start_h + i;
        uint8_t last_byte = curr_h & 0xFF;

        /* Reserve .0, .1, and .255 */
        if (last_byte == 0 || last_byte == 1 || last_byte == 255) {
            pool->bitmap[i >> 3] |= (1 << (i & 7));
            excl_count++;
        }
    }

    log_info("IPAM: Pool initialized. Range: %s, Total: %u, Reserved: %u", 
             cidr_start, size, excl_count);
    return 0;
}

uint32_t vpn_ip_pool_alloc(vpn_ip_pool_t *pool) {
    if (unlikely(!pool || !pool->bitmap)) return 0;

    pthread_mutex_lock(&pool->lock);

    for (uint32_t i = 0; i < pool->pool_size; i++) {
        uint32_t pos = (pool->next_hint + i) % pool->pool_size;
        uint32_t b_idx = pos >> 3;     /* Equivalent to pos / 8 */
        uint8_t mask = 1 << (pos & 7); /* Equivalent to pos % 8 */

        if (!(pool->bitmap[b_idx] & mask)) {
            pool->bitmap[b_idx] |= mask;
            pool->next_hint = (pos + 1) % pool->pool_size;
            pthread_mutex_unlock(&pool->lock);

            return htonl(ntohl(pool->start_ip) + pos);
        }
    }

    pthread_mutex_unlock(&pool->lock);
    log_warn("IPAM: Address pool exhaustion detected");
    return 0;
}

void vpn_ip_pool_free(vpn_ip_pool_t *pool, uint32_t ip) {
    if (unlikely(!pool || !pool->bitmap || ip == 0)) return;

    uint32_t host_ip = ntohl(ip);
    uint32_t host_start = ntohl(pool->start_ip);

    /* Range validation is critical for industrial safety */
    if (unlikely(host_ip < host_start || host_ip >= host_start + pool->pool_size)) {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip, buf, sizeof(buf));
        log_error("IPAM: Out-of-bounds IP release: %s", buf);
        return;
    }

    uint32_t pos = host_ip - host_start;
    pthread_mutex_lock(&pool->lock);
    pool->bitmap[pos >> 3] &= ~(1 << (pos & 7));
    pthread_mutex_unlock(&pool->lock);
}

void vpn_ip_pool_destroy(vpn_ip_pool_t *pool) {
    if (!pool) return;
    
    pthread_mutex_lock(&pool->lock);
    if (pool->bitmap) {
        zfree(pool->bitmap);
        pool->bitmap = NULL;
    }
    pthread_mutex_unlock(&pool->lock);
    pthread_mutex_destroy(&pool->lock);
    log_info("IPAM: Pool manager destroyed safely");
}