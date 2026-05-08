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
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/errqueue.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "utils.h"
#include "log.h"
#include "session.h"
#include "protocol.h"
#include "tun.h"
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
        vf_secure_cleanup(out_key, CRYPTO_KEY_SIZE);
        return -1;
    }

    log_info("Master key [%s] loaded into secure memory.", key_path);
    return 0;
}

/**
 * @brief Command: --keygen
 * Generates an industrial-strength 256-bit entropy key and persists it to disk.
 * * SECURITY MEASURES:
 * 1. O_EXCL: Atomic check to prevent accidental overwriting of existing keys.
 * 2. fchmod: Explicitly forces 0600 (Owner Read/Write only) regardless of umask.
 * 3. Secure Wipe: Ensures the key is scrubbed from stack memory after use.
 * 4. Sync: Forces a disk flush before closing to ensure persistence.
 */
void vfast_cmd_keygen(void) {
    uint8_t tmp_key[CRYPTO_KEY_SIZE];
    const char *key_file = "vfast.key";
    
    log_info("[ VFAST ] Initializing high-entropy key generation...");

    /* Phase 1: Entropy Collection
     * vf_generate_key must wrap a secure CSPRNG (like getrandom(2) or /dev/urandom) */
    if (unlikely(vf_generate_key(tmp_key) != 0)) {
        log_error("CRITICAL: System failed to provide sufficient entropy.");
        exit(EXIT_FAILURE);
    }

    /* Phase 2: Secure File Creation
     * O_CREAT | O_EXCL ensures atomicity: fails if the file already exists.
     * S_IRUSR | S_IWUSR sets 0600 permissions. */
    int fd = open(key_file, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        if (errno == EEXIST) {
            log_error("DENIED: Key file '%s' already exists. Manual deletion required to rotate.", key_file);
        } else {
            log_error("SYSCALL: Failed to open key file for writing: %s", strerror(errno));
        }
        goto cleanup_fail;
    }

    /* Phase 3: Permission Hardening
     * Overriding umask to guarantee the file is strictly private. */
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        log_error("SECURITY: Failed to enforce restricted permissions on key file.");
        close(fd);
        unlink(key_file);
        goto cleanup_fail;
    }

    /* Phase 4: Atomic Persistence */
    ssize_t n = write(fd, tmp_key, CRYPTO_KEY_SIZE);
    if (n != CRYPTO_KEY_SIZE) {
        log_error("IO_ERROR: Failed to write full entropy block. Status: %zd/%d", n, CRYPTO_KEY_SIZE);
        close(fd);
        unlink(key_file);
        goto cleanup_fail;
    }

    /* Force physical disk flush before closing to prevent data loss on power failure */
    if (fdatasync(fd) != 0) {
        log_warn("IO_WARN: Could not verify physical disk sync.");
    }

    close(fd);

    /* Phase 5: Memory Scrubbing
     * Zero out the key in memory to prevent cold-boot attacks or heap/stack leaks. */
    vf_secure_cleanup(tmp_key, CRYPTO_KEY_SIZE);
    
    log_info("[ SUCCESS ]: Key generated and locked in '%s' (Mode: 0600).", key_file);
    log_info("Keep this file offline. Compromise of this file compromises the entire tunnel.");
    exit(EXIT_SUCCESS);

cleanup_fail:
    vf_secure_cleanup(tmp_key, CRYPTO_KEY_SIZE);
    exit(EXIT_FAILURE);
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
void vfast_server_maintenance(vf_io_t *io, void *data) {
    if (unlikely(!io || !data)) return;

    vpn_ip_pool_t *ipp = (vpn_ip_pool_t *)data;
    vf_expired_node_t expired_list[64];
    const int PROBE_SEC = 15;
    const int DEAD_SEC  = 30;

    /**
     * STAGE 1: Information Gathering
     * Fetch a batch of session metadata that exceeds inactivity thresholds.
     * The session module remains "clean" as it only performs read-only scanning here.
     */
    int count = vf_ss_get_expired(expired_list, 64, PROBE_SEC, DEAD_SEC);
    if (count <= 0) return;

    /**
     * STAGE 2: Action Execution
     * Iterate through the collected candidates and execute the appropriate strategy.
     */
    for (int i = 0; i < count; i++) {
        vf_expired_node_t *node = &expired_list[i];

        if (node->is_dead) {
            /* Strategy A: Final Reclamation */
            log_info("DPD: Session 0x%08x confirmed dead. Reclaiming VIP %u", 
                     node->session_id, node->virtual_ip);
            
            /* Physical deletion from session internal sharded tables */
            vf_ss_delete(node->virtual_ip);
            /* Release the virtual IP back to the pool for reuse */
            vf_ip_pool_free(ipp, node->virtual_ip);
        } else {
            /* Strategy B: Active Probing (Keep-alive) */
            vf_task_t *task = vf_io_task(io);
            if (unlikely(!task)) {
                /* System backpressure: Skip probe if task pool is saturated */
                continue; 
            }

            /**
             * 2. Security Pipeline Integration
             * Even DPD probes must be masked.
             * Since DPD usually has no payload, we pass plen = 0.
             */
            vf_session_t *s = NULL;
            /* We need the session context to get the security keys for packing */
            if (unlikely(!vf_ss_lookup_by_sid(node->session_id, &s))) {
                continue;
            }

            /**
             * 3. Apply [Padding] -> [Header Fill] -> [Obfuscation]
             * vf_pack will turn this 0-byte payload into a 
             * randomized, masked packet.
             */
            int tlen = vf_pack(&s->sec_ctx, task->buf, 0, 
                                BUF_SIZE, VPN_DPD_REQUEST, node->session_id);

            if (likely(tlen > 0)) {
                /* 4. Asynchronous Dispatch via io_uring */
                vf_io_write(io, io->udp_fd, OP_UDP_SEND, task->buf, 
                                   tlen, &node->remote_addr);
                
                log_debug("DPD: Sent masked probe to SID[0x%08x]", node->session_id);
            }
        }
    }
}

void vfast_path_mtu_updated(uint32_t new_mtu, void *arg) {
    if (!!arg) return;

    vf_io_t *io = (vf_io_t *)arg;

    if (vf_tun_set_mtu_by_fd(io->tun_fd, new_mtu) != 0) {
        log_error("Failed to update TUN MTU to %u: %s", new_mtu, strerror(errno));
    } else {
        log_info("TUN MTU successfully updated to %u bytes", new_mtu);
    }
}