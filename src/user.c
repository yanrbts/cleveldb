/*
 * Copyright (c) 2026-2026, vfast.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "utils.h"
#include "log.h"
#include "uthash.h"
#include "zmalloc.h"
#include "user.h"

#define VF_USER_TOKEN_INTER     3600
#define VF_USER_TOKEN_MIN       900

/* Internal Cache Node: Persistent Account Data */
typedef struct {
    vf_user_auth_t auth;    /* Contains base info + password + static_vip */
    UT_hash_handle hh;
} vf_db_node_t;

/* Internal Session Node: Volatile Active Tokens */
typedef struct {
    uint8_t token[16];      /* Key */
    vf_identity_t identity; /* Snapshot including assigned VIP */
    time_t expire;
    UT_hash_handle hh;
} vf_token_node_t;

/* Global Manager Singleton */
static struct {
    int urandom_fd;
    vf_db_node_t    *db_cache;     /* Lazy-loaded user credentials */
    vf_token_node_t *token_cache;  /* Active sessions */
    pthread_rwlock_t lock;
    vf_user_fetch_cb fetch_cb;     /* Customer-defined data source */
} g_user_mgr;

/* Internal IP Allocator (Placeholder for actual IP pool module) */
static uint32_t _internal_ip_alloc(void) {
    static uint32_t dyn_pool = 0x0A08000A; // Starts at 10.8.0.10
    return dyn_pool++;
}

/**
 * Register the external database hook
 */
void vf_user_register_datasource(vf_user_fetch_cb cb) {
    pthread_rwlock_wrlock(&g_user_mgr.lock);
    g_user_mgr.fetch_cb = cb;
    pthread_rwlock_unlock(&g_user_mgr.lock);
}

bool vf_user_init(const char *db_conn) {
    (void)db_conn;
    memset(&g_user_mgr, 0, sizeof(g_user_mgr));

    if (pthread_rwlock_init(&g_user_mgr.lock, NULL) != 0) {
        return false;
    }

    g_user_mgr.urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (g_user_mgr.urandom_fd < 0) {
        pthread_rwlock_destroy(&g_user_mgr.lock);
        return false;
    }

    return true;
}

static vf_db_node_t* vf_sync_user(const char *username) {
    if (!g_user_mgr.fetch_cb) return NULL;

    vf_user_auth_t ext_auth;
    if (g_user_mgr.fetch_cb(username, &ext_auth)) {
        vf_db_node_t *node = (vf_db_node_t *)zcalloc(sizeof(vf_db_node_t));
        if (node) {
            node->auth = ext_auth; // Structural copy
            HASH_ADD(hh, g_user_mgr.db_cache, auth.base.name, 
                     strlen(node->auth.base.name), node);
            return node;
        }
    }
    return NULL;
}

int vf_user_login(const char *user, const char *pass, uint8_t tk_out[16]) {
    if (unlikely(!user || !pass || !tk_out)) return -3;

    vf_db_node_t *u = NULL;
    
    /* Step 1: Cache Lookup with Lazy Loading */
    pthread_rwlock_rdlock(&g_user_mgr.lock);
    HASH_FIND_STR(g_user_mgr.db_cache, user, u);
    pthread_rwlock_unlock(&g_user_mgr.lock);

    if (!u) {
        pthread_rwlock_wrlock(&g_user_mgr.lock);
        HASH_FIND_STR(g_user_mgr.db_cache, user, u); /* Double check */
        if (!u) u = vf_sync_user(user);
        pthread_rwlock_unlock(&g_user_mgr.lock);
    }

    if (unlikely(!u)) {
        log_error("Login failed: User '%s' not found.", user);
        return -1;
    }

    /* Step 2: Credential Verification */
    if (strcmp(pass, u->auth.pass_hash) != 0) {
        log_error("Login failed: Password mismatch for user '%s'.", user);
        return -2;
    }

    /* Step 3: Token & Session Initialization */
    if (read(g_user_mgr.urandom_fd, tk_out, 16) != 16) return -3;

    vf_token_node_t *session = (vf_token_node_t *)zcalloc(sizeof(vf_token_node_t));
    if (unlikely(!session)) return -3;

    memcpy(session->token, tk_out, 16);
    
    /* Resolve VIP Logic: Static from DB takes priority over Pool */
    session->identity.base = u->auth.base;
    session->identity.vip  = (u->auth.static_vip != 0) ? 
                             u->auth.static_vip : _internal_ip_alloc();
    
    session->expire = time(NULL) + VF_USER_TOKEN_INTER;

    pthread_rwlock_wrlock(&g_user_mgr.lock);
    HASH_ADD(hh, g_user_mgr.token_cache, token, 16, session);
    pthread_rwlock_unlock(&g_user_mgr.lock);

    log_info("User '%s' authenticated. VIP: %u", user, session->identity.vip);
    return 0;
}

bool vf_user_verify_pkt(const vpn_auth_t *pkt, vf_identity_t *info) {
    if (unlikely(!pkt || pkt->magic != VFAST_MAGIC)) return false;

    time_t now = time(NULL);
    bool valid = false;

    pthread_rwlock_rdlock(&g_user_mgr.lock);
    vf_token_node_t *session = NULL;
    HASH_FIND(hh, g_user_mgr.token_cache, pkt->token, 16, session);

    if (likely(session && now <= session->expire)) {
        if (info) {
            /* Zero-redundancy structural copy to data-plane buffer */
            *info = session->identity;
        }
        valid = true;

        /* Sliding Window: TTL Extension */
        if (session->expire - now < VF_USER_TOKEN_MIN) {
            session->expire = now + VF_USER_TOKEN_INTER;
        }
    }
    pthread_rwlock_unlock(&g_user_mgr.lock);

    return valid;
}

int vf_user_logout(const uint8_t token[16]) {
    if (unlikely(!token)) return -1;

    pthread_rwlock_wrlock(&g_user_mgr.lock);
    vf_token_node_t *session = NULL;
    HASH_FIND(hh, g_user_mgr.token_cache, token, 16, session);
    if (session) {
        HASH_DEL(g_user_mgr.token_cache, session);
        free(session);
        pthread_rwlock_unlock(&g_user_mgr.lock);
        return 0;
    }
    pthread_rwlock_unlock(&g_user_mgr.lock);
    return -1;
}

void vf_user_cron_clean(void) {
    vf_token_node_t *curr, *tmp;
    time_t now = time(NULL);

    pthread_rwlock_wrlock(&g_user_mgr.lock);
    HASH_ITER(hh, g_user_mgr.token_cache, curr, tmp) {
        if (now > curr->expire) {
            HASH_DEL(g_user_mgr.token_cache, curr);
            free(curr);
        }
    }
    pthread_rwlock_unlock(&g_user_mgr.lock);
}

void vf_user_uninit(void) {
    pthread_rwlock_wrlock(&g_user_mgr.lock);

    if (g_user_mgr.urandom_fd >= 0) close(g_user_mgr.urandom_fd);

    /* Flush Active Sessions */
    vf_token_node_t *tk, *tk_tmp;
    HASH_ITER(hh, g_user_mgr.token_cache, tk, tk_tmp) {
        HASH_DEL(g_user_mgr.token_cache, tk);
        free(tk);
    }

    /* Flush DB Cache */
    vf_db_node_t *u, *u_tmp;
    HASH_ITER(hh, g_user_mgr.db_cache, u, u_tmp) {
        HASH_DEL(g_user_mgr.db_cache, u);
        free(u);
    }

    pthread_rwlock_unlock(&g_user_mgr.lock);
    pthread_rwlock_destroy(&g_user_mgr.lock);
}