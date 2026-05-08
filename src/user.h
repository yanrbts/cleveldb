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
} vf_user_t;

bool vf_user_init(void);
void vf_user_uninit(void);
int vf_user_login(const char *user, const char *pass, uint8_t tk_out[VF_TOKEN_LEN]);
bool vf_user_verify_pkt(const vpn_auth_t *pkt, vf_user_t *info);
int vf_user_logout(const uint8_t token[VF_TOKEN_LEN]);
void vf_user_clean_expired(void);

#endif /* __USER_H__ */