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

vfast_fsm_t client_fsm = {0};

/**
 * @brief Constructs and dispatches FSM control packets (Handshake/Keep-alive) using io_uring.
 *
 * This function implements a zero-copy workflow by borrowing a buffer directly from the 
 * global task pool. It differentiates between unencrypted handshake packets (VPN_MSG_HELLO) 
 * and encrypted session maintenance packets (VPN_MSG_KEEPALIVE).
 *
 * @param type The VFAST protocol message type (e.g., VPN_MSG_HELLO, VPN_MSG_KEEPALIVE).
 */
static void fsm_send_pkt(uint8_t type) {
    /* 1. Acquire a pre-allocated task buffer from the IO engine's pool.
     * This ensures the data resides in a registered memory region for io_uring,
     * allowing for true zero-copy transmission in vfast_submit_write. */
    vfast_task_t *task = vfast_borrow_task();
    if (unlikely(!task)) {
        log_error("FSM: Task pool exhaustion. Cannot dispatch control packet (type: %d)", type);
        return;
    }

    int total_len = 0;

    /* 2. Protocol Encapsulation Path */
    if (type == VPN_MSG_HELLO) {
        /**
         * HANDSHAKE PHASE:
         * At this stage, no session key is negotiated. vpn_pack will skip 
         * encryption and perform plain-text encapsulation.
         */
        vpn_auth_t *auth = (vpn_auth_t *)(task->buf + VPN_TNL_HLEN);
        
        /* Populate authentication credentials directly into the reserved payload offset */
        vfast_auth_pack(auth, client_fsm.vip, (uint8_t *)"VFAST_SECRET", 0);

        total_len = vpn_pack(NULL,                 /* No key available yet */
                             task->buf,            /* Target buffer */
                             sizeof(vpn_auth_t),   /* Payload length */
                             BUF_SIZE,             /* Buffer capacity */
                             VPN_MSG_HELLO,        /* Message type */
                             0);                   /* Session ID (N/A) */
    } else if (type == VPN_MSG_KEEPALIVE) {
        /**
         * ESTABLISHED PHASE:
         * Keep-alive packets are encrypted using the negotiated session key to
         * obscure traffic patterns and prevent protocol fingerprinting.
         */
        total_len = vpn_pack(client_fsm.key,   /* Use active session key */
                             task->buf,            /* Target buffer */
                             0,                    /* Keep-alive has 0-byte payload */
                             BUF_SIZE,             /* Buffer capacity */
                             VPN_MSG_KEEPALIVE,    /* Message type */
                             client_fsm.sid);      /* Current Session ID */
    }

    /* 3. Asynchronous Submission */
    if (likely(total_len > 0)) {
        /**
         * Since 'task->buf' is guaranteed to be within the task pool, 
         * vfast_submit_write will skip internal memcpy and submit the 
         * raw pointer directly to the io_uring SQ.
         */
        task->in_use = false;
        vfast_submit_write(client_fsm.io, 
                           client_fsm.io->udp_fd, 
                           OP_UDP_SEND, 
                           task->buf, 
                           total_len, 
                           &client_fsm.dst_addr);
        
        io_uring_submit(&client_fsm.io->ring);
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
    log_info("FSM: Unified io_uring background worker initiated.");

    while (likely(atomic_load(client_fsm.running))) {
        time_t now = time(NULL);
        int state = atomic_load(&client_fsm.state);
        long last_rx = atomic_load(&client_fsm.last_rx_time);

        switch (state) {
            case ST_IDLE:
            case ST_RECONNECTING:
                fsm_send_pkt(VPN_MSG_HELLO);
                client_fsm.last_tx_auth = now;
                atomic_store(&client_fsm.state, ST_WAIT_AUTH);
                log_info("FSM: HELLO submitted via io_uring to %s:%d", 
                         client_fsm.server_ip, client_fsm.server_port);
                break;

            case ST_WAIT_AUTH:
                if (now - client_fsm.last_tx_auth >= FSM_AUTH_RETRY) {
                    log_warn("FSM: Auth timeout, retrying...");
                    atomic_store(&client_fsm.state, ST_IDLE);
                }
                break;

            case ST_CONNECTED:
                if (now - client_fsm.last_tx_keep >= FSM_KEEPALIVE) {
                    fsm_send_pkt(VPN_MSG_KEEPALIVE);
                    client_fsm.last_tx_keep = now;
                }

                if (now - last_rx >= FSM_TIMEOUT) {
                    log_error("FSM: Connection timeout (DPD). Reconnecting...");
                    atomic_store(&client_fsm.state, ST_RECONNECTING);
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
int vfast_fsm_init(vfast_io_t *io, const char *sip, uint16_t sport, atomic_bool *rig, const uint8_t *key) {
    if (!io || !sip) return -1;

    memset(&client_fsm, 0, sizeof(vfast_fsm_t));
    client_fsm.io = io;
    client_fsm.server_port = sport;
    strncpy(client_fsm.server_ip, sip, sizeof(client_fsm.server_ip) - 1);
    
    /* Pre-calculate sockaddr_in for io_uring performance */
    client_fsm.dst_addr.sin_family = AF_INET;
    client_fsm.dst_addr.sin_port = htons(sport);
    inet_pton(AF_INET, sip, &client_fsm.dst_addr.sin_addr);
    
    atomic_store(&client_fsm.last_rx_time, time(NULL));
    client_fsm.running = rig;
    atomic_store(&client_fsm.state, ST_IDLE);
    client_fsm.key = key;

    return pthread_create(&client_fsm.thread_id, NULL, fsm_worker, NULL);
}

/* Remaining functions vfast_fsm_update_rx, etc., stay unchanged */
void vfast_fsm_update_rx() { 
    atomic_store(&client_fsm.last_rx_time, time(NULL));
}

int vfast_fsm_is_connected() { 
    return atomic_load(&client_fsm.state) == ST_CONNECTED; 
}

void vfast_fsm_force_reconnect() {
    atomic_store(&client_fsm.state, ST_IDLE);
    atomic_store(&client_fsm.sid, 0); 
}

void vfast_fsm_pthread_join() {
    pthread_join(client_fsm.thread_id, NULL);
}