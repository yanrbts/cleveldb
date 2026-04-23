/* * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 */

#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include "protocol.h"
#include "log.h"
#include "auth.h"
#include "utils.h"
#include "fsm.h"
#include "vfast.h"

#define FSM_TICK        1    
#define FSM_AUTH_RETRY  5    
#define FSM_KEEPALIVE   10   
#define FSM_TIMEOUT     30

/**
 * @brief Constructs and dispatches FSM control packets (Handshake/Keep-alive) using io_uring.
 *
 * This function implements a zero-copy workflow by borrowing a buffer directly from the 
 * global task pool. It differentiates between unencrypted handshake packets (VPN_MSG_HELLO) 
 * and encrypted session maintenance packets (VPN_MSG_KEEPALIVE).
 *
 * @param type The VFAST protocol message type (e.g., VPN_MSG_HELLO, VPN_MSG_KEEPALIVE).
 */
static void fsm_send_pkt(vfast_fsm_t *fsm, uint8_t type) {
    /* 1. Acquire a pre-allocated task buffer from the IO engine's pool.
     * This ensures the data resides in a registered memory region for io_uring,
     * allowing for true zero-copy transmission in vfast_submit_write. */
    vfast_task_t *task = vfast_borrow_task(fsm->io);
    if (unlikely(!task)) {
        log_error("FSM: Task pool exhaustion. Cannot dispatch control packet (type: %d)", type);
        return;
    }

    int total_len = 0;

    /* 2. Protocol Encapsulation Path */
    if (type == VPN_MSG_HELLO) {
        /**
         * HANDSHAKE PHASE:
         * At this stage, no session key is negotiated. vf_pack will skip 
         * encryption and perform plain-text encapsulation.
         */
        vpn_auth_t *auth = (vpn_auth_t *)(task->buf + VPN_TNL_HLEN);
        
        /* Populate authentication credentials directly into the reserved payload offset */
        vf_auth_pack(auth, fsm->vip, (uint8_t *)VFAST_TOKEN, 0, NULL, 0);

        total_len = vf_pack(NULL,                 /* No key available yet */
                             task->buf,            /* Target buffer */
                             sizeof(vpn_auth_t),   /* Payload length */
                             BUF_SIZE,             /* Buffer capacity */
                             VPN_MSG_HELLO,        /* Message type */
                             fsm->sid);                   /* Session ID (N/A) */
    } else if (type == VPN_MSG_KEEPALIVE) {
        /**
         * ESTABLISHED PHASE:
         * Keep-alive packets are encrypted using the negotiated session key to
         * obscure traffic patterns and prevent protocol fingerprinting.
         */
        total_len = vf_pack(fsm->sec,   /* Use active session key */
                             task->buf,            /* Target buffer */
                             0,                    /* Keep-alive has 0-byte payload */
                             BUF_SIZE,             /* Buffer capacity */
                             VPN_MSG_KEEPALIVE,    /* Message type */
                             fsm->sid);      /* Current Session ID */
    }

    /* 3. Asynchronous Submission */
    if (likely(total_len > 0)) {
        /**
         * Since 'task->buf' is guaranteed to be within the task pool, 
         * vfast_submit_write will skip internal memcpy and submit the 
         * raw pointer directly to the io_uring SQ.
         */
        vfast_submit_write(fsm->io, 
                           fsm->io->udp_fd, 
                           OP_UDP_SEND, 
                           task->buf, 
                           total_len, 
                           &fsm->dst_addr);
        
        io_uring_submit(&fsm->io->ring);
    } else {
        /* Rollback: Release the task if encapsulation failed to prevent pool leakage */
        task->in_use = false;
        log_error("FSM: Packet encapsulation failed for type %d", type);
    }
}
/**
 * @brief FSM Background Worker Thread (Logic remains consistent).
 */
static void *fsm_worker(void *arg) {
    (void)arg;
    vfast_fsm_t *fsm = (vfast_fsm_t *)arg;
    log_info("FSM: Unified background worker initiated.");

    while (likely(atomic_load(fsm->running))) {
        time_t now = time(NULL);
        int state = atomic_load(&fsm->state);
        long last_rx = atomic_load(&fsm->last_rx_time);

        switch (state) {
            case ST_IDLE:
            case ST_RECONNECTING:
                fsm_send_pkt(fsm, VPN_MSG_HELLO);
                fsm->last_tx_auth = now;
                atomic_store(&fsm->state, ST_WAIT_AUTH);
                log_info("FSM: HELLO submitted to %s:%d", 
                         fsm->server_ip, fsm->server_port);
                break;

            case ST_WAIT_AUTH:
                if (now - fsm->last_tx_auth >= FSM_AUTH_RETRY) {
                    log_warn("FSM: Auth timeout, retrying...");
                    atomic_store(&fsm->state, ST_IDLE);
                }
                break;

            case ST_CONNECTED:
                if (now - fsm->last_tx_keep >= FSM_KEEPALIVE) {
                    fsm_send_pkt(fsm, VPN_MSG_KEEPALIVE);
                    fsm->last_tx_keep = now;
                }

                if (now - last_rx >= FSM_TIMEOUT) {
                    log_error("FSM: Connection timeout (DPD). Reconnecting...");
                    atomic_store(&fsm->state, ST_RECONNECTING);
                }
                break;
        }
        sleep(FSM_TICK);
    }
    return NULL;
}

/**
 * @brief Initializes the FSM with io_uring support.
 */
int vf_fsm_init(vfast_fsm_t *fsm, vfast_io_t *io, const char *sip, uint16_t sport, atomic_bool *running, const uint8_t *key) {
    if (!io || !sip) return -1;

    memset(fsm, 0, sizeof(vfast_fsm_t));
    fsm->io = io;
    fsm->server_port = sport;
    fsm->sec = NULL; 
    fsm->sid = 0;
    fsm->running = running;
    fsm->key = key;
    strncpy(fsm->server_ip, sip, sizeof(fsm->server_ip) - 1);
    
    /* Pre-calculate sockaddr_in for io_uring performance */
    fsm->dst_addr.sin_family = AF_INET;
    fsm->dst_addr.sin_port = htons(sport);
    inet_pton(AF_INET, sip, &fsm->dst_addr.sin_addr);
    
    atomic_store(&fsm->last_rx_time, time(NULL));
    atomic_store(&fsm->state, ST_IDLE);
    
    return pthread_create(&fsm->thread_id, NULL, fsm_worker, (void *)fsm);
}

/* Remaining functions vfast_fsm_update_rx, etc., stay unchanged */
void vf_fsm_update(vfast_fsm_t *fsm) { 
    atomic_store(&fsm->last_rx_time, time(NULL));
}

int vf_fsm_is_connected(vfast_fsm_t *fsm) { 
    return atomic_load(&fsm->state) == ST_CONNECTED; 
}

void vf_fsm_force_reconnect(vfast_fsm_t *fsm) {
    atomic_store(&fsm->state, ST_IDLE);
    atomic_store(&fsm->sid, 0); 
}

void vf_fsm_pthread_join(vfast_fsm_t *fsm) {
    pthread_join(fsm->thread_id, NULL);
}