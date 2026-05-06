/* * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 */
#ifndef __FSM_H__
#define __FSM_H__

#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h> // Required for sockaddr_in
#include "io.h"         // Required for vf_io_t
#include "key.h"        // Required for vfast_sec_ctx_t

typedef enum {
    ST_IDLE = 0,
    ST_HELLO_WAIT,      /* 已发送 HELLO，等待服务端回应确认链路通畅 */
    ST_AUTH_SEND,       /* 链路通了，准备发送登录请求 (VPN_MSG_AUTH_REQ) */
    ST_AUTH_WAIT,       /* 已发送登录请求，等待 RADIUS 认证结果 */
    ST_CONNECTED,
    ST_RECONNECTING
} vfast_state_t;

typedef struct {
    atomic_int      state;         
    uint32_t        sid;             
    atomic_long     last_rx_time;
    time_t          last_tx_hello;  
    time_t          last_tx_auth;  
    time_t          last_tx_keep;  
    pthread_t       thread_id;
    char            server_ip[64];
    uint16_t        server_port;
    struct sockaddr_in dst_addr;   /* Pre-calculated server address */
    vf_io_t     *io;            /* Unified IO Engine */
    atomic_bool    *running;
    const uint8_t  *key;          /* Pointer to the session key (set after auth) */
    vfast_sec_ctx_t *sec;         /* Pointer to the security context */
    atomic_uint_fast32_t next_seq;
    const char     *pass_word;
    const char     *user_name;
    uint8_t         cookie[16];
    uint64_t        server_ts;
} vfast_fsm_t;

/* Signature updated to accept vf_io_t */
int vf_fsm_init(vfast_fsm_t *fsm, vf_io_t *io, const char *username, const char *pwd, 
    const char *sip, uint16_t sport, atomic_bool *running, const uint8_t *key);
void vf_fsm_update(vfast_fsm_t *fsm);
int vf_fsm_is_connected(vfast_fsm_t *fsm);
void vf_fsm_force_reconnect(vfast_fsm_t *fsm);
void vf_fsm_pthread_join(vfast_fsm_t *fsm);

#endif