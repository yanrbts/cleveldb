/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
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

/* FSM timing configuration (seconds) */
#define FSM_TICK        1    /* Polling interval for the FSM thread */
#define FSM_AUTH_RETRY  5    /* Wait time before retrying HELLO if no ACK */
#define FSM_KEEPALIVE   10   /* Interval between heartbeat packets */
#define FSM_TIMEOUT     30   /* Dead Peer Detection (DPD) threshold */

vfast_fsm_t client_fsm = {0};

/**
 * @brief Constructs and sends an FSM control packet (HELLO/KEEPALIVE).
 * * @param type The VFAST message type (VPN_MSG_HELLO or VPN_MSG_KEEPALIVE).
 */
static void send_fsm_pkt(uint8_t type) {
    uint8_t buf[128] = {0};
    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)buf;
    
    hdr->version = VPN_VERSION;
    hdr->msg_type = type;
    /* HELLO packets use SID 0; subsequent packets use the assigned SID */
    hdr->session_id = (type == VPN_MSG_HELLO) ? 0 : htonl(client_fsm.sid);

    vpn_auth_t *auth = (vpn_auth_t *)(buf + VPN_TNL_HLEN);
    /* Pack authentication payload with virtual IP and secret key */
    vfast_auth_pack(auth, client_fsm.vip, (uint8_t *)"VFAST_SECRET", 0);

    size_t len = VPN_TNL_HLEN + sizeof(vpn_auth_t);
    
    /* Send via raw UDP wrapper */
    udp_send_raw(client_fsm.udp, client_fsm.server_ip, client_fsm.server_port, buf, len);
}

/**
 * @brief FSM Background Worker Thread.
 * Monitors connection health and manages state transitions.
 */
static void *fsm_worker(void *arg) {
    (void)arg;
    log_info("FSM: Background worker thread initiated.");

    while (likely(atomic_load(&vfastctx.running))) {
        time_t now = time(NULL);
        int state = atomic_load(&client_fsm.state);
        long last_rx = atomic_load(&client_fsm.last_rx_time);

        switch (state) {
            case ST_IDLE:
            case ST_RECONNECTING:
                /* Trigger initial handshake */
                send_fsm_pkt(VPN_MSG_HELLO);
                client_fsm.last_tx_auth = now;
                atomic_store(&client_fsm.state, ST_WAIT_AUTH);
                log_info("FSM: HELLO sent to %s:%d", 
                         client_fsm.server_ip, client_fsm.server_port);
                break;

            case ST_WAIT_AUTH:
                /* Check for handshake timeout */
                if (now - client_fsm.last_tx_auth >= FSM_AUTH_RETRY) {
                    log_warn("FSM: Auth response timeout (%ds), retrying...", FSM_AUTH_RETRY);
                    atomic_store(&client_fsm.state, ST_IDLE);
                }
                break;

            case ST_CONNECTED:
                /* 1. Send periodic Keep-alive/Heartbeat */
                if (now - client_fsm.last_tx_keep >= FSM_KEEPALIVE) {
                    send_fsm_pkt(VPN_MSG_KEEPALIVE);
                    client_fsm.last_tx_keep = now;
                }

                /* 2. Dead Peer Detection (DPD) based on last received packet */
                if (now - last_rx >= FSM_TIMEOUT) {
                    log_error("FSM: Connection timeout (No RX for %ds). Reconnecting...", FSM_TIMEOUT);
                    atomic_store(&client_fsm.state, ST_RECONNECTING);
                }
                break;

            default:
                break;
        }

        /* Sleep to prevent CPU spinning */
        sleep(FSM_TICK);
    }
    
    log_info("FSM: Worker thread terminating.");
    return NULL;
}

/**
 * @brief Initializes the FSM and spawns the management thread.
 */
int vfast_fsm_init(const udp_conn_t *udp, const char *sip, uint16_t sport) {
    if (!udp || !sip) return -1;

    memset(&client_fsm, 0, sizeof(vfast_fsm_t));
    client_fsm.udp = (udp_conn_t*)udp;
    client_fsm.server_port = sport;
    strncpy(client_fsm.server_ip, sip, sizeof(client_fsm.server_ip) - 1);
    
    /* Initialize activity timers to current time to prevent instant timeout */
    time_t now = time(NULL);
    atomic_store(&client_fsm.last_rx_time, now);
    client_fsm.last_tx_auth = 0;
    client_fsm.last_tx_keep = 0;

    atomic_store(&client_fsm.state, ST_IDLE);

    /* Launch the worker thread */
    return pthread_create(&client_fsm.thread_id, NULL, fsm_worker, NULL);
}

/**
 * @brief Updates the last received packet timestamp.
 * Should be called whenever io_uring receives a valid UDP packet from the server.
 */
void vfast_fsm_update_rx() { 
    atomic_store(&client_fsm.last_rx_time, time(NULL));
}

/**
 * @brief Thread-safe check if the client is fully authenticated and connected.
 */
int vfast_fsm_is_connected() { 
    return atomic_load(&client_fsm.state) == ST_CONNECTED; 
}