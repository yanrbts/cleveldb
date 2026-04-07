/*
 * Copyright (c) 2026-2026, vfast.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <string.h>
#include <time.h>
#include "log.h"
#include "auth.h"

void vfast_auth_pack(vpn_auth_t *auth, uint32_t vip, const uint8_t *token, uint64_t ts) {
    if (!auth) return;

    /* Initialize memory to zero to prevent information leakage from stack/heap padding */
    memset(auth, 0, sizeof(vpn_auth_t));

    auth->magic = VFAST_MAGIC;
    auth->vip   = vip;
    auth->ts    = (ts != 0) ? ts : (uint64_t)time(NULL);

    if (token) {
        memcpy(auth->token, token, 12);
    }
}

int vfast_auth_verify(const vpn_auth_t *auth, const uint8_t *expected_token) {
    if (!auth) return -1;

    /* Check magic first to quickly drop irrelevant network noise */
    if (auth->magic != VFAST_MAGIC) {
        return -2;
    }

    /* Verify credentials if a reference token is supplied */
    if (expected_token) {
        /* memcmp is efficient for 16-byte fixed-length comparisons */
        if (memcmp(auth->token, expected_token, 12) != 0) {
            return -3;
        }
    }

    return 0;
}

void vfast_auth_parse(const vpn_auth_t *auth, uint32_t *vip, uint64_t *ts) {
    if (!auth) return;

    if (vip) *vip = auth->vip;
    if (ts) *ts  = auth->ts;
}