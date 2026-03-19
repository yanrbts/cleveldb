/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __FSM_H__
#define __FSM_H__

#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
#include "udp.h"

typedef enum {
    ST_IDLE = 0,
    ST_WAIT_AUTH,
    ST_CONNECTED,
    ST_RECONNECTING
} vfast_state_t;

typedef struct {
    atomic_int    state;         
    uint32_t      sid;           
    uint32_t      vip;           
    atomic_long   last_rx_time;  
    time_t        last_tx_auth;  
    time_t        last_tx_keep;  
    pthread_t     thread_id;
    char          server_ip[64];
    uint16_t      server_port;
    udp_conn_t    *udp;
} vfast_fsm_t;

extern vfast_fsm_t client_fsm;

int  vfast_fsm_init(const udp_conn_t *udp, const char *sip, uint16_t sport);
void vfast_fsm_update_rx();
int  vfast_fsm_is_connected();

#endif