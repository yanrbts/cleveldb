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
#include "session.h"
#include "user.h"

#define VF_USER_TOKEN_INTER     3600
#define VF_USER_TOKEN_MIN       900
#define VF_USER_RADCLI_CONF     "./radcli.conf"

/* Internal Session Node: Volatile Active Tokens */
typedef struct {
    uint8_t token[VF_TOKEN_LEN];        /* Key */
    vf_user_t user;             /* Snapshot including assigned VIP */
    time_t expire;
    UT_hash_handle hh;
} vf_node_t;

/* Global Manager Singleton */
static struct {
    int urandom_fd;
    rc_handle *rh;                  /* RADIUS handle */
    vf_node_t *user_node;   /* Active sessions */
    pthread_rwlock_t lock;
} g_user_mgr;

/**
 * @brief Authenticates a user against the RADIUS server.
 * This function constructs a RADIUS Access-Request packet. 
 * Includes Message-Authenticator (Attribute 80) to support modern 
 * FreeRADIUS security requirements (mitigating BLAST RADIUS).
 *
 * @param user The username string.
 * @param pass The password string.
 * @return int VF_OK on success, or specific VF_ERR code on failure.
 */
static int vf_radius_authenticate(const char *user, const char *pass) {
    /* 1. Basic sanity check for the RADIUS handle */
    if (unlikely(!g_user_mgr.rh)) {
        return VF_ERR_CONFIG;
    }

    /* Correct structure type for radcli is VALUE_PAIR */
    VALUE_PAIR *send = NULL, *received = NULL;
    int ret = VF_ERR_GENERIC;
    uint32_t service = 1;  /* Standard Service-Type: Login-User (1) */
    
    /* 2. Build the Attribute-Value Pair (AVP) list */

    /* Add User-Name (Attribute 1) */
    if (rc_avpair_add(g_user_mgr.rh, &send, PW_USER_NAME, (void*)user, -1, 0) == NULL) {
        return VF_ERR_SYSTEM;
    }

    /* Add User-Password (Attribute 2) */
    if (rc_avpair_add(g_user_mgr.rh, &send, PW_USER_PASSWORD, (void*)pass, -1, 0) == NULL) {
        rc_avpair_free(send);
        return VF_ERR_SYSTEM;
    }

    /* Add Service-Type (Attribute 6) - Pass address of the integer */
    if (rc_avpair_add(g_user_mgr.rh, &send, PW_SERVICE_TYPE, &service, -1, 0) == NULL) {
        rc_avpair_free(send);
        return VF_ERR_SYSTEM;
    }

    /* 4. Perform the RADIUS Authentication
     * The second argument '0' is the NAS-Port. 
     * 'msg' will capture any Reply-Message from the server.
     */
    char msg[PW_MAX_MSG_SIZE] = {0};
    int result = rc_auth(g_user_mgr.rh, 0, send, &received, msg);
    
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

bool vf_user_init(void) {
    memset(&g_user_mgr, 0, sizeof(g_user_mgr));

    if (pthread_rwlock_init(&g_user_mgr.lock, NULL) != 0) {
        return false;
    }

    rc_openlog("vfast-server");
    /* Initialize RADIUS (libradcli)
     * Using db_conn as the path to radiusclient.conf if provided */
    const char *apath = vf_get_absolute_path(VF_USER_RADCLI_CONF);
    g_user_mgr.rh = rc_read_config(apath);
    if (!g_user_mgr.rh) {
        log_error("Failed to read radcli config [%s]: %s (errno: %d)", 
              apath, strerror(errno), errno);
        pthread_rwlock_destroy(&g_user_mgr.lock);
        return false;
    }

    if (rc_read_dictionary(g_user_mgr.rh, rc_conf_str(g_user_mgr.rh, "dictionary")) != 0) {
        log_error("Failed to read RADIUS dictionary.");
        rc_destroy(g_user_mgr.rh);
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

int vf_user_login(const char *user, const char *pass, uint8_t tk_out[VF_TOKEN_LEN]) {
    if (unlikely(!user || !pass || !tk_out)) return -3;

    /* Step 1: RADIUS Authentication (Primary) */
    if (vf_radius_authenticate(user, pass) != 0) {
        return -2;
    }

    /* Step 3: Token & Session Initialization */
    if (read(g_user_mgr.urandom_fd, tk_out, VF_TOKEN_LEN) != VF_TOKEN_LEN)
        return -3;

    vf_node_t *n = (vf_node_t *)zcalloc(sizeof(vf_node_t));
    if (unlikely(!n)) return -3;

    memcpy(n->token, tk_out, VF_TOKEN_LEN);
    /* Resolve VIP Logic: Static from DB takes priority over Pool */
    strncpy(n->user.name, user, sizeof(n->user.name) - 1);
    n->user.name[sizeof(n->user.name) - 1] = '\0';
    n->user.role = VF_ROLE_USER; // Default role; can be extended to
    n->expire = time(NULL) + VF_USER_TOKEN_INTER;

    pthread_rwlock_wrlock(&g_user_mgr.lock);
    HASH_ADD(hh, g_user_mgr.user_node, token, VF_TOKEN_LEN, n);
    pthread_rwlock_unlock(&g_user_mgr.lock);

    return 0;
}

bool vf_user_verify_pkt(const vpn_auth_t *pkt, vf_user_t *info) {
    if (unlikely(!pkt || pkt->magic != VFAST_MAGIC)) return false;

    time_t now = time(NULL);
    bool valid = false;

    pthread_rwlock_rdlock(&g_user_mgr.lock);
    vf_node_t *session = NULL;
    HASH_FIND(hh, g_user_mgr.user_node, pkt->token, VF_TOKEN_LEN, session);

    if (likely(session && now <= session->expire)) {
        if (info) {
            /* Zero-redundancy structural copy to data-plane buffer */
            *info = session->user;
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
    vf_node_t *session = NULL;
    HASH_FIND(hh, g_user_mgr.user_node, token, VF_TOKEN_LEN, session);
    if (session) {
        HASH_DEL(g_user_mgr.user_node, session);
        zfree(session);
        pthread_rwlock_unlock(&g_user_mgr.lock);
        return 0;
    }
    pthread_rwlock_unlock(&g_user_mgr.lock);
    return -1;
}

void vf_user_clean_expired(void) {
    vf_node_t *curr, *tmp;
    time_t now = time(NULL);

    pthread_rwlock_wrlock(&g_user_mgr.lock);
    HASH_ITER(hh, g_user_mgr.user_node, curr, tmp) {
        if (now > curr->expire) {
            HASH_DEL(g_user_mgr.user_node, curr);
            free(curr);
        }
    }
    pthread_rwlock_unlock(&g_user_mgr.lock);
}

void vf_user_uninit(void) {
    pthread_rwlock_wrlock(&g_user_mgr.lock);

    if (g_user_mgr.urandom_fd >= 0) close(g_user_mgr.urandom_fd);

    /* Clean RADIUS handle */
    if (g_user_mgr.rh) {
        rc_destroy(g_user_mgr.rh);
        g_user_mgr.rh = NULL;
    }

    /* Flush Active Sessions */
    vf_node_t *tk, *tk_tmp;
    HASH_ITER(hh, g_user_mgr.user_node, tk, tk_tmp) {
        HASH_DEL(g_user_mgr.user_node, tk);
        free(tk);
    }

    pthread_rwlock_unlock(&g_user_mgr.lock);
    pthread_rwlock_destroy(&g_user_mgr.lock);
}