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
#include "io.h"         // Required for vfast_io_t
#include "key.h"        // Required for vfast_sec_ctx_t

typedef enum {
    ST_IDLE = 0,
    ST_WAIT_AUTH,
    ST_CONNECTED,
    ST_RECONNECTING
} vfast_state_t;

typedef struct {
    atomic_int      state;         
    uint32_t        sid;           
    uint32_t        vip;           
    atomic_long     last_rx_time;  
    time_t          last_tx_auth;  
    time_t          last_tx_keep;  
    pthread_t       thread_id;
    char            server_ip[64];
    uint16_t        server_port;
    struct sockaddr_in dst_addr;   /* Pre-calculated server address */
    vfast_io_t     *io;            /* Unified IO Engine */
    atomic_bool    *running;
    const uint8_t  *key;          /* Pointer to the session key (set after auth) */
    vfast_sec_ctx_t *sec;         /* Pointer to the security context */
    atomic_uint_fast32_t next_seq;
} vfast_fsm_t;

/* Signature updated to accept vfast_io_t */
int vfast_fsm_init(vfast_fsm_t *fsm, vfast_io_t *io, const char *sip, uint16_t sport, atomic_bool *running, const uint8_t *key);
void vfast_fsm_update(vfast_fsm_t *fsm);
int vfast_fsm_is_connected(vfast_fsm_t *fsm);
void vfast_fsm_force_reconnect(vfast_fsm_t *fsm);
void vfast_fsm_pthread_join(vfast_fsm_t *fsm);

#endif