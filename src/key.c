/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <stdio.h>
#include "key.h"

/**
 * CSPRNG: Cryptographically Secure Pseudo-Random Number Generator
 * Uses Linux getrandom(2) to ensure high-quality entropy without OpenSSL.
 */
static int vfast_crypto_fill_random(void *buf, size_t len) {
    uint8_t *ptr = (uint8_t *)buf;
    size_t left = len;

    while (left > 0) {
        ssize_t ret = getrandom(ptr, left, 0);
        if (ret < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        ptr += ret;
        left -= ret;
    }
    return 0;
}

void vfast_rekey_init(vfast_sec_ctx_t *ctx) {
    memset(ctx, 0, sizeof(vfast_sec_ctx_t));
    
    if (vfast_crypto_fill_random(ctx->active_key.raw, REKEY_KEY_SIZE) == 0) {
        ctx->active_key.id = 1;
        ctx->active_key.created_at = time(NULL);
        ctx->active_key.bytes_processed = 0;
    }
    atomic_store(&ctx->rekey_pending, false);
}

/**
 * Check if the active key has expired based on time or throughput.
 */
bool vfast_rekey_needed(vfast_sec_ctx_t *ctx) {
    if (ctx->rekey_pending) return false;

    time_t now = time(NULL);
    if (now - ctx->active_key.created_at >= REKEY_TIMEOUT_SEC) return true;
    if (ctx->active_key.bytes_processed >= REKEY_DATA_THRESHOLD) return true;

    return false;
}

/**
 * Phase 1: Generate a new key and mark the session as 'rekeying'.
 * This key should be sent to the peer via the control plane.
 */
int vfast_rekey_prepare_next(vfast_sec_ctx_t *ctx) {
    memset(&ctx->next_key, 0, sizeof(vfast_key_t));
    
    if (vfast_crypto_fill_random(ctx->next_key.raw, REKEY_KEY_SIZE) != 0) {
        return -1;
    }

    ctx->next_key.id = ctx->active_key.id + 1;
    ctx->next_key.created_at = time(NULL);
    ctx->next_key.bytes_processed = 0;
    atomic_store(&ctx->rekey_pending, true);
    return 0;
}

/**
 * Phase 2: Smooth Transition (The "Double Buffering" trick)
 * Move Active -> Previous, and Next -> Active.
 */
void vfast_rekey_commit(vfast_sec_ctx_t *ctx) {
    /* Store current active key as previous to handle out-of-order packets */
    memcpy(&ctx->previous_key, &ctx->active_key, sizeof(vfast_key_t));

    /* Promote next key to active */
    memcpy(&ctx->active_key, &ctx->next_key, sizeof(vfast_key_t));

    /* Clear next key and reset pending flag */
    memset(&ctx->next_key, 0, sizeof(vfast_key_t));
    atomic_store(&ctx->rekey_pending, false);
}