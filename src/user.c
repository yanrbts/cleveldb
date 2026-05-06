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
#include <radcli/radcli.h>

#include "utils.h"
#include "log.h"
#include "uthash.h"
#include "error.h"
#include "zmalloc.h"
#include "ippool.h"
#include "user.h"

#define VF_USER_TOKEN_INTER     3600
#define VF_USER_TOKEN_MIN       900
#define VF_USER_RADCLI_CONF     "./radcli.conf"

/* Internal Cache Node: Persistent Account Data */
typedef struct {
    vf_user_auth_t auth;    /* Contains base info + password + static_vip */
    UT_hash_handle hh;
} vf_db_node_t;

/* Internal Session Node: Volatile Active Tokens */
typedef struct {
    uint8_t token[VF_TOKEN_LEN];      /* Key */
    vf_identity_t identity; /* Snapshot including assigned VIP */
    time_t expire;
    UT_hash_handle hh;
} vf_token_node_t;

/* Global Manager Singleton */
static struct {
    int urandom_fd;
    vf_token_node_t *token_cache;  /* Active sessions */
    pthread_rwlock_t lock;
    vf_user_fetch_cb fetch_cb;     /* Customer-defined data source */
} g_user_mgr;

static rc_handle *g_rh = NULL;

// static vf_db_node_t* vf_sync_user(const char *username) {
//     if (!g_user_mgr.fetch_cb) return NULL;

//     vf_user_auth_t ext_auth;
//     if (g_user_mgr.fetch_cb(username, &ext_auth)) {
//         vf_db_node_t *node = (vf_db_node_t *)zcalloc(sizeof(vf_db_node_t));
//         if (node) {
//             node->auth = ext_auth; // Structural copy
//             HASH_ADD(hh, g_user_mgr.db_cache, auth.base.name, 
//                      strlen(node->auth.base.name), node);
//             return node;
//         }
//     }
//     return NULL;
// }

/**
 * @brief Authenticates a user against the RADIUS server.
 * * This function constructs a RADIUS Access-Request packet. 
 * Includes Message-Authenticator (Attribute 80) to support modern 
 * FreeRADIUS security requirements (mitigating BLAST RADIUS).
 *
 * @param user The username string.
 * @param pass The password string.
 * @return int VF_OK on success, or specific VF_ERR code on failure.
 */
static int vf_radius_authenticate(const char *user, const char *pass) {
    /* 1. Basic sanity check for the RADIUS handle */
    if (unlikely(!g_rh)) {
        return VF_ERR_CONFIG;
    }

    /* Correct structure type for radcli is VALUE_PAIR */
    VALUE_PAIR *send = NULL, *received = NULL;
    int ret = VF_ERR_GENERIC;
    uint32_t service = 1;  /* Standard Service-Type: Login-User (1) */
    
    /* 2. Build the Attribute-Value Pair (AVP) list */

    /* Add User-Name (Attribute 1) */
    if (rc_avpair_add(g_rh, &send, PW_USER_NAME, (void*)user, -1, 0) == NULL) {
        return VF_ERR_SYSTEM;
    }

    /* Add User-Password (Attribute 2) */
    if (rc_avpair_add(g_rh, &send, PW_USER_PASSWORD, (void*)pass, -1, 0) == NULL) {
        rc_avpair_free(send);
        return VF_ERR_SYSTEM;
    }

    /* Add Service-Type (Attribute 6) - Pass address of the integer */
    if (rc_avpair_add(g_rh, &send, PW_SERVICE_TYPE, &service, -1, 0) == NULL) {
        rc_avpair_free(send);
        return VF_ERR_SYSTEM;
    }

    /* 4. Perform the RADIUS Authentication
     * The second argument '0' is the NAS-Port. 
     * 'msg' will capture any Reply-Message from the server.
     */
    char msg[PW_MAX_MSG_SIZE] = {0};
    int result = rc_auth(g_rh, 0, send, &received, msg);
    
    /* Clean up the allocated AVP list */
    if (send) rc_avpair_free(send);
    if (received) rc_avpair_free(received);

    /* 5. Process RADIUS return codes */
    switch (result) {
    case OK_RC:
        /* Access-Accept received */
        ret = VF_OK;
        log_info("RADIUS: User '%s' %s", user, msg[0] ? msg : "Authenticated");
        break;
    case BADRESP_RC:
    case REJECT_RC:
        /* Access-Reject received or invalid packet signature */
        log_warn("RADIUS: Auth rejected for user '%s': %s", 
                    user, msg[0] ? msg : "No reason");
        ret = VF_ERR_AUTH_DENIED;
        break;
    case TIMEOUT_RC:
        /* No response. Common causes: Wrong Secret, IP not in clients.conf */
        log_error("RADIUS: Timeout for user '%s'. Check connectivity/secret.", user);
        ret = VF_ERR_AUTH_TIMEOUT;
        break;
    default:
        log_error("RADIUS: Unexpected error %d for user '%s'", result, user);
        ret = VF_ERR_GENERIC;
        break;
    }

    return ret; 
}

/**
 * Register the external database hook
 */
void vf_user_register_datasource(vf_user_fetch_cb cb) {
    pthread_rwlock_wrlock(&g_user_mgr.lock);
    g_user_mgr.fetch_cb = cb;
    pthread_rwlock_unlock(&g_user_mgr.lock);
}

bool vf_user_init(void) {
    memset(&g_user_mgr, 0, sizeof(g_user_mgr));

    if (pthread_rwlock_init(&g_user_mgr.lock, NULL) != 0) {
        return false;
    }
    rc_openlog("my-prog-name");
    /* Initialize RADIUS (libradcli) */
    /* Using db_conn as the path to radiusclient.conf if provided */
    const char *apath = vf_get_absolute_path(VF_USER_RADCLI_CONF);
    g_rh = rc_read_config(apath);
    if (!g_rh) {
        log_error("Failed to read radcli config [%s]: %s (errno: %d)", 
              apath, strerror(errno), errno);
        pthread_rwlock_destroy(&g_user_mgr.lock);
        return false;
    }

    if (rc_read_dictionary(g_rh, rc_conf_str(g_rh, "dictionary")) != 0) {
        log_error("Failed to read RADIUS dictionary.");
        rc_destroy(g_rh);
        pthread_rwlock_destroy(&g_user_mgr.lock);
        return false;
    }

    g_user_mgr.urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (g_user_mgr.urandom_fd < 0) {
        pthread_rwlock_destroy(&g_user_mgr.lock);
        return false;
    }

    zfree((void*)apath);

    return true;
}

int vf_user_login(uint32_t vip, const char *user, const char *pass, uint8_t tk_out[VF_TOKEN_LEN]) {
    if (unlikely(!user || !pass || !tk_out)) return -3;

    /* Step 1: RADIUS Authentication (Primary) */
    if (vf_radius_authenticate(user, pass) != 0) {
        return -2;
    }

    /* Step 3: Token & Session Initialization */
    if (read(g_user_mgr.urandom_fd, tk_out, VF_TOKEN_LEN) != VF_TOKEN_LEN)
        return -3;

    vf_token_node_t *session = (vf_token_node_t *)zcalloc(sizeof(vf_token_node_t));
    if (unlikely(!session)) return -3;

    memcpy(session->token, tk_out, VF_TOKEN_LEN);
    /* Resolve VIP Logic: Static from DB takes priority over Pool */
    strncpy(session->identity.base.name, user, sizeof(session->identity.base.name) - 1);
    session->identity.base.name[sizeof(session->identity.base.name) - 1] = '\0';
    session->identity.base.role = VF_ROLE_USER; // Default role; can be extended to

    session->identity.vip  = vip;
    session->expire = time(NULL) + VF_USER_TOKEN_INTER;

    pthread_rwlock_wrlock(&g_user_mgr.lock);
    HASH_ADD(hh, g_user_mgr.token_cache, token, VF_TOKEN_LEN, session);
    pthread_rwlock_unlock(&g_user_mgr.lock);

    return 0;
}

bool vf_user_verify_pkt(const vpn_auth_t *pkt, vf_identity_t *info) {
    if (unlikely(!pkt || pkt->magic != VFAST_MAGIC)) return false;

    time_t now = time(NULL);
    bool valid = false;

    pthread_rwlock_rdlock(&g_user_mgr.lock);
    vf_token_node_t *session = NULL;
    HASH_FIND(hh, g_user_mgr.token_cache, pkt->token, VF_TOKEN_LEN, session);

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

int vf_user_logout(const uint8_t token[VF_TOKEN_LEN]) {
    if (unlikely(!token)) return -1;

    pthread_rwlock_wrlock(&g_user_mgr.lock);
    vf_token_node_t *session = NULL;
    HASH_FIND(hh, g_user_mgr.token_cache, token, VF_TOKEN_LEN, session);
    if (session) {
        HASH_DEL(g_user_mgr.token_cache, session);
        zfree(session);
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

    /* Clean RADIUS handle */
    if (g_rh) {
        rc_destroy(g_rh);
        g_rh = NULL;
    }

    /* Flush Active Sessions */
    vf_token_node_t *tk, *tk_tmp;
    HASH_ITER(hh, g_user_mgr.token_cache, tk, tk_tmp) {
        HASH_DEL(g_user_mgr.token_cache, tk);
        free(tk);
    }

    /* Flush DB Cache */
    // vf_db_node_t *u, *u_tmp;
    // HASH_ITER(hh, g_user_mgr.db_cache, u, u_tmp) {
    //     HASH_DEL(g_user_mgr.db_cache, u);
    //     free(u);
    // }

    pthread_rwlock_unlock(&g_user_mgr.lock);
    pthread_rwlock_destroy(&g_user_mgr.lock);
}