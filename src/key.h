/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __KEY_H__
#define __KEY_H__

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/random.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdatomic.h>

#define REKEY_KEY_SIZE          32
#define REKEY_TIMEOUT_SEC       60            /* 1 hour */
#define REKEY_DATA_THRESHOLD    (1ULL << 30)    /* 1GB */

typedef struct {
    uint8_t     raw[REKEY_KEY_SIZE];
    uint32_t    id;
    atomic_ulong bytes_processed;
    time_t      created_at;
} vfast_key_t;

typedef struct {
    vfast_key_t active_key;    /* Current key for encryption/decryption */
    vfast_key_t previous_key;  /* Grace period key for delayed packets */
    vfast_key_t next_key;      /* Negotiated key waiting for activation */
    uint32_t    sid;
    atomic_bool rekey_pending;    /* Handshake in progress */
} vfast_sec_ctx_t;

/* Function prototypes */
void vfast_rekey_init(vfast_sec_ctx_t *ctx, uint32_t sid);
bool vfast_rekey_needed(vfast_sec_ctx_t *ctx);
int vfast_rekey_prepare_next(vfast_sec_ctx_t *ctx);
void vfast_rekey_commit(vfast_sec_ctx_t *ctx);

static inline const uint8_t* 
vfast_rekey_get_key(const vfast_sec_ctx_t *ctx) {
    return ctx->active_key.raw;
}
static inline uint32_t 
vfast_rekey_get_key_id(const vfast_sec_ctx_t *ctx) {
    return ctx->active_key.id;
}

/**
 * @brief Selects the appropriate decryption key based on the truncated Key ID.
 * * This function handles the "Generation Gap" caused by asynchronous I/O 
 * (io_uring). It matches the 8-bit Key ID from the packet header against 
 * the 8-bit LSB (Least Significant Byte) of the internal 32-bit Key IDs.
 *
 * @param ctx      The security context containing active and previous keys.
 * @param wire_kid The 8-bit Key ID extracted from the tunnel header.
 * @return const uint8_t* Pointer to the raw key, or NULL if no match.
 */
static inline const uint8_t*
vfast_rekey_get_decrypt_key(const vfast_sec_ctx_t *ctx, uint8_t wire_kid) {
    /* 1. Check against the Active Key (Current Generation) */
    if (wire_kid == (uint8_t)(ctx->active_key.id & 0xFF)) {
        return ctx->active_key.raw;
    } 
    
    /* 2. Check against the Previous Key (Last Generation - handling queue lag) */
    /* Ensure previous_key.id is initialized (non-zero) to avoid false matches */
    if (ctx->previous_key.id != 0 && 
        wire_kid == (uint8_t)(ctx->previous_key.id & 0xFF)) {
        return ctx->previous_key.raw;
    }

    /* 3. No match: Possible replay attack or extremely delayed packet */
    return NULL;
}

#endif