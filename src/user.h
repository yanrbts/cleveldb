#ifndef __USER_H__
#define __USER_H__

#include <stdint.h>
#include <stdbool.h>
#include "auth.h"
#include "ippool.h"

#define VF_TOKEN_LEN    16

/* Role definitions for Access Control */
typedef enum {
    VF_ROLE_GUEST = 0,
    VF_ROLE_USER,
    VF_ROLE_ADMIN
} vf_role_t;

typedef struct {
    char name[32];
    vf_role_t role;
} vf_user_base_t;

typedef struct {
    vf_user_base_t base;
    uint32_t vip;
} vf_identity_t;

/* Authentication data retrieved from external sources (DB/LDAP/API) */
typedef struct {
    vf_user_base_t base;
    char pass_hash[64];
    uint32_t static_vip;   /* Pre-assigned IP from DB; 0 if dynamic allocation required */
} vf_user_auth_t;

/**
 * vf_user_fetch_cb - Callback to fetch user data from external systems.
 * @param username: The username to look up.
 * @param out_auth: Buffer to store the retrieved authentication and base data.
 * @return true if user exists, false otherwise.
 */
typedef bool (*vf_user_fetch_cb)(const char *username, vf_user_auth_t *out_auth);

bool vf_user_init(void);
void vf_user_uninit(void);
void vf_user_register_datasource(vf_user_fetch_cb cb);
int vf_user_login(uint32_t vip, const char *user, const char *pass, uint8_t tk_out[VF_TOKEN_LEN]);
bool vf_user_verify_pkt(const vpn_auth_t *pkt, vf_identity_t *info);
int vf_user_logout(const uint8_t token[VF_TOKEN_LEN]);
void vf_user_clean_expired(void);

#endif /* __USER_H__ */