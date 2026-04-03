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
 * @brief Constructs and sends an FSM control packet via io_uring.
 * Optimization: Uses the unified vfast_submit_write for non-blocking I/O.
 */
static void fsm_send_pkt(uint8_t type) {
    /* Use a static buffer or task-pool allocated buffer for io_uring safety.
     * Since FSM is low-frequency, we can afford a small dedicated buffer. */
    static uint8_t fsm_buf[256]; 
    memset(fsm_buf, 0, sizeof(fsm_buf));

    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)fsm_buf;
    
    hdr->version = VFAST_VERSION;
    hdr->msg_type = type;
    /* Network Byte Order for SID */
    hdr->session_id = (type == VPN_MSG_HELLO) ? 0 : htonl(client_fsm.sid);
    hdr->flags = 0;

    vpn_auth_t *auth = (vpn_auth_t *)(fsm_buf + sizeof(vpn_tunnel_hdr_t));
    /* Pack authentication payload */
    vfast_auth_pack(auth, client_fsm.vip, (uint8_t *)"VFAST_SECRET", 0);

    size_t len = sizeof(vpn_tunnel_hdr_t) + sizeof(vpn_auth_t);
    
    /**
     * Unified Submission:
     * This replaces udp_send_raw. vfast_submit_write is thread-safe 
     * (ensure you have a mutex around io_uring_get_sqe if calling from multiple threads).
     */
    vfast_submit_write(client_fsm.io, client_fsm.io->udp_fd, OP_UDP_SEND, 
                       fsm_buf, (int)len, &client_fsm.dst_addr);
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
int vfast_fsm_init(vfast_io_t *io, const char *sip, uint16_t sport, atomic_bool *rig) {
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