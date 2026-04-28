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

    /* Clear the entire buffer to prevent information leakage from previous tasks */
    memset(task->buf, 0, BUF_SIZE);

    int payload_len = 0;
    uint8_t *payload_ptr = task->buf + VPN_TNL_HLEN;

    /* 2. Fill Payloads based on Type */
    switch (type) {
        case VPN_MSG_HELLO: {
            vf_payload_hello_req_t *hello = (vf_payload_hello_req_t *)payload_ptr;
            hello->timestamp = htonll((uint64_t)time(NULL));
            payload_len = sizeof(vf_payload_hello_req_t);
            break;
        }

        case VPN_MSG_AUTH_REQ: {
            vf_payload_auth_req_t *auth = (vf_payload_auth_req_t *)payload_ptr;
            /* Anti-replay & credentials */
            auth->timestamp = htonll(fsm->server_ts);
            memcpy(auth->cookie, fsm->cookie, sizeof(auth->cookie));
            strncpy(auth->username, fsm->user_name, sizeof(auth->username) - 1);
            auth->username[sizeof(auth->username) - 1] = '\0';
            strncpy(auth->password, fsm->pass_word, sizeof(auth->password) - 1);
            auth->password[sizeof(auth->password) - 1] = '\0';
            
            /* If we received a cookie from HELLO_ACK, attach it here for DDOS protection */
            payload_len = sizeof(vf_payload_auth_req_t);
            break;
        }

        case VPN_MSG_KEEPALIVE: {
            vf_payload_echo_t *echo = (vf_payload_echo_t *)payload_ptr;
            uint32_t seq = (uint32_t)atomic_fetch_add(&fsm->next_seq, 1);

            echo->echo_id = htonll((uint64_t)seq);
            echo->timestamp = htonll((uint64_t)time(NULL));
            payload_len = sizeof(vf_payload_echo_t);
            break;
        }

        default:
            log_error("FSM: Unsupported control packet type: %u", type);
            goto rollback;
    }

    /* 3. Encapsulation */
    /* Only KEEPALIVE uses the security context (sec). 
     * HELLO and AUTH_REQ are sent before the session key is established. */
    void *sec_ctx = (type == VPN_MSG_KEEPALIVE || type == VPN_MSG_HELLO) ? NULL : fsm->sec;

    int total_len = vf_pack(sec_ctx, 
                            task->buf, 
                            payload_len, 
                            BUF_SIZE, 
                            type, 
                            fsm->sid);

    if (unlikely(total_len <= 0)) {
        log_error("FSM: Encapsulation failed for type %u", type);
        goto rollback;
    }

    /* 4. Submission to io_uring */
    vfast_submit_write(fsm->io, 
                        fsm->io->udp_fd, 
                        OP_UDP_SEND, 
                        task->buf, 
                        total_len, 
                        &fsm->dst_addr);

    /* Force the kernel to process the SQE immediately */
    io_uring_submit(&fsm->io->ring);
    return;

rollback:
    /* Critical: Prevent memory leak in the task pool */
    task->in_use = false;
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
                /* 第一步：敲门 (HELLO) */
                fsm_send_pkt(fsm, VPN_MSG_HELLO);
                fsm->last_tx_hello = now;
                atomic_store(&fsm->state, ST_HELLO_WAIT);
                log_info("FSM: HELLO submitted to %s:%d", 
                         fsm->server_ip, fsm->server_port);
                break;
            
            case ST_HELLO_WAIT:
                /* 等待 HELLO_ACK。如果超时没收到，说明路不通，回到 IDLE 重试 */
                if (now - fsm->last_tx_hello >= FSM_AUTH_RETRY) {
                    log_warn("FSM: HELLO timeout, server unreachable. Retrying...");
                    atomic_store(&fsm->state, ST_IDLE);
                }
                break;
            
            case ST_AUTH_SEND:
                /* 第二步：递交身份证 (AUTH) */
                fsm_send_pkt(fsm, VPN_MSG_AUTH_REQ);
                fsm->last_tx_auth = now;
                atomic_store(&fsm->state, ST_AUTH_WAIT);
                log_info("FSM: Sending AUTH_REQ for user: %s", fsm->user_name);
                break;
            
            case ST_AUTH_WAIT:
                /* 等待 AUTH_RESP (包含 VIP 和 Token) */
                if (now - fsm->last_tx_auth >= FSM_AUTH_RETRY) {
                    log_warn("FSM: Auth request timeout. Returning to HELLO...");
                    atomic_store(&fsm->state, ST_IDLE);
                }
                break;

            case ST_CONNECTED:
                /* 第三步：维持连接 (KEEPALIVE) */
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
int vf_fsm_init(vfast_fsm_t *fsm, vfast_io_t *io, const char *username, const char *pwd, 
    const char *sip, uint16_t sport, atomic_bool *running, const uint8_t *key) {
    if (!io || !sip) return -1;

    memset(fsm, 0, sizeof(vfast_fsm_t));
    fsm->io = io;
    fsm->server_port = sport;
    fsm->sec = NULL; 
    fsm->sid = 0;
    fsm->running = running;
    fsm->key = key;
    fsm->user_name = username;
    fsm->pass_word = pwd;
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