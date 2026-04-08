/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <signal.h>
#include <linux/ip.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "utils.h"
#include "log.h"
#include "session.h"
#include "protocol.h"
#include "vfast.h"

/**
 * @brief Loads the 256-bit master key from a binary file.
 * Industrial Security: Checks for file existence and size integrity.
 * @param key_path Path to the key file (e.g., "vfast.key").
 * @param out_key  Buffer to store the 32-byte key.
 * @return 0 on success, -1 on failure.
 */
int vfast_load_key(const char *key_path, uint8_t out_key[CRYPTO_KEY_SIZE]) {
    if (unlikely(!key_path || !out_key)) return -1;

    int fd = open(key_path, O_RDONLY);
    if (fd < 0) {
        log_error("Failed to open key file '%s': %s", key_path, strerror(errno));
        log_error("HINT: Run './vfast_server --keygen' to generate a new key.");
        return -1;
    }
    /* Standard security check: Ensure the file isn't a directory or symlink trickery */
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        log_error("Invalid key file type: %s", key_path);
        close(fd);
        return -1;
    }

    /* Load exactly 32 bytes */
    ssize_t bytes_read = read(fd, out_key, CRYPTO_KEY_SIZE);
    close(fd);

    if (bytes_read != CRYPTO_KEY_SIZE) {
        log_error("Key file '%s' is corrupted (Size: %zd, Expected: %d)", 
                  key_path, bytes_read, CRYPTO_KEY_SIZE);
        vpn_secure_cleanup(out_key, CRYPTO_KEY_SIZE);
        return -1;
    }

    log_info("Master key [%s] loaded into secure memory.", key_path);
    return 0;
}

/**
 * @brief Periodic maintenance orchestrator for session lifecycle management.
 * @details 
 * This function implements the policy layer:
 * 1. Queries the session module for expired/suspicious nodes (Mechanism).
 * 2. Decides whether to reclaim resources or probe remote peers (Policy).
 * 3. Bridges the gap between session logic, IP pooling, and io_uring.
 * @param io  Pointer to the VFast I/O engine.
 * @param ipp Pointer to the IP address pool.
 */
void vfast_server_maintenance(vfast_io_t *io, void *data) {
    if (unlikely(!io || !data)) return;

    vpn_ip_pool_t *ipp = (vpn_ip_pool_t *)data;
    /* Snapshot list of sessions requiring attention */
    vpn_expired_node_t expired_list[64];
    const int PROBE_SEC = 15;
    const int DEAD_SEC  = 30;

    /**
     * STAGE 1: Information Gathering
     * Fetch a batch of session metadata that exceeds inactivity thresholds.
     * The session module remains "clean" as it only performs read-only scanning here.
     */
    int count = vpn_session_get_expired(expired_list, 64, PROBE_SEC, DEAD_SEC);
    if (count <= 0) return;

    /**
     * STAGE 2: Action Execution
     * Iterate through the collected candidates and execute the appropriate strategy.
     */
    for (int i = 0; i < count; i++) {
        vpn_expired_node_t *node = &expired_list[i];

        if (node->is_dead) {
            /* Strategy A: Final Reclamation */
            log_info("DPD: Session 0x%08x confirmed dead. Reclaiming VIP %u", 
                     node->session_id, node->virtual_ip);
            
            /* Physical deletion from session internal sharded tables */
            // vpn_session_delete_by_sid(node->session_id);
            vpn_session_delete(node->virtual_ip);
            
            /* Release the virtual IP back to the pool for reuse */
            vpn_ip_pool_free(ipp, node->virtual_ip);
        } else {
            /* Strategy B: Active Probing (Keep-alive) */
            vfast_task_t *task = vfast_borrow_task(io);
            if (unlikely(!task)) {
                /* System backpressure: Skip probe if task pool is saturated */
                continue; 
            }

            /* Overlay the protocol header onto the task's pre-allocated buffer */
            vpn_tunnel_hdr_t *hb = (vpn_tunnel_hdr_t *)task->buf;
            hb->msg_type = VPN_DPD_REQUEST;
            hb->session_id = htonl(node->session_id);

            /* Submit asynchronous UDP sendto via io_uring */
            vfast_submit_write(io, io->udp_fd, OP_UDP_SEND, (uint8_t *)hb, 
                               sizeof(*hb), &node->remote_addr);
            
            log_debug("DPD: Sent probe to session 0x%08x at %s:%d", 
                      node->session_id, inet_ntoa(node->remote_addr.sin_addr), 
                      ntohs(node->remote_addr.sin_port));
        }
    }
}
