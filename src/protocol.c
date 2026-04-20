/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include "log.h"
#include "utils.h"
#include "protocol.h"
#include "crypto.h"

/**
 * @brief Calculate Internet Checksum (RFC 1071)
 * @param buf Pointer to the data
 * @param len Length of the data in bytes
 * @return 16-bit one's complement sum
 */
static inline uint16_t _calculate_checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t *)buf;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

/**
 * @brief Industrial-grade encapsulation with mandatory AEAD encryption.
 * 1. For HELLO: Skips encryption to allow initial handshake.
 * 2. For others: Performs in-place AEAD encryption.
 * 3. Safety: Strict boundary checks and error logging included.
 * 
 * @param sec          Pointer to the session context.
 * @param buf          Buffer base (Payload MUST start at buf + VPN_TNL_HLEN).
 * @param payload_len  Length of the raw payload (e.g., IP packet or Control data).
 * @param max_buf_size Total capacity of the allocated buffer.
 * @param type         VFAST message type (DATA, HEARTBEAT, CONTROL, etc.).
 * @param sid          Session ID for routing.
 * @return Total bytes to send over UDP, or -1 on error.
 */
int vpn_pack(const vfast_sec_ctx_t *sec, uint8_t *buf, int payload_len, 
    int max_buf_size, vpn_msg_t type, uint32_t sid) {
    /* 1. Basic Pointer Check */
    if (unlikely(!buf || (!sec && type != VPN_MSG_HELLO))) 
        return -1;

    /* 2. Locate Payload: Assumes zero-copy placement at offset 8 */
    uint8_t *payload_ptr = buf + VPN_TNL_HLEN;
    size_t crypto_out_len = 0;
    uint32_t kid = 0; /* Default Key ID for HELLO (no encryption) */
    

    /* 3. Encryption Logic Branching with Strict Validation */
    if (type == VPN_MSG_HELLO || type == VPN_MSG_KEEPALIVE) {
        /**
         * HANDSHAKE PHASE:
         * No session key is available. Payload remains plain-text.
         */
        crypto_out_len = (size_t)payload_len;
    } else {
        const uint8_t *key = vfast_rekey_get_key(sec);
        kid = vfast_rekey_get_key_id(sec);
        /**
         * ESTABLISHED PHASE:
         * Encrypt in-place. Requires a valid session key.
         */
        if (unlikely(!key)) {
            log_error("Encryption failed: Missing session key for SID: 0x%08x", sid);
            return -1;
        }

        if (unlikely(vpn_encrypt(key, payload_ptr, (size_t)payload_len, payload_ptr, &crypto_out_len) != 0)) {
            log_error("Encryption failed for SID: 0x%08x, Type: %d", sid, type);
            return -1;
        }
    }

    /* 4. Final Safety Check: Header + (Encrypted or Plain) Payload vs Capacity */
    const int total_len = VPN_TNL_HLEN + (int)crypto_out_len;
    if (unlikely(total_len > max_buf_size)) {
        log_error("Buffer overflow: needed %d, capacity %d (SID: 0x%08x)", total_len, max_buf_size, sid);
        return -1;
    }

    /* 5. Fill Tunnel Header (Standard Wire Format) */
    vpn_fill_header(buf, (uint8_t)type, sid, kid);

    return total_len;
}

/**
 * @brief Decapsulates VFAST header and decrypts payload in-place.
 * @return Pointer to the decrypted plain IP packet, or NULL on failure.
 */
uint8_t* vpn_unpack(const vfast_sec_ctx_t *sec, uint8_t *buf, int res, int *out_plain_len, uint32_t *out_sid) {
    /* 1. Basic sanity check for header size and context validity */
    if (unlikely(!sec || !buf || res < (int)sizeof(vpn_tunnel_hdr_t))) {
        return NULL;
    }

    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)buf;

    /**
     * 2. Key Selection Logic.
     * Attempt to find a matching key (Active or Previous) based on the 8-bit Key ID.
     * This is critical for handling packets still in the io_uring queue during rekeying.
     */
    const uint8_t *key = vfast_rekey_get_decrypt_key(sec, hdr->key_id);
    if (unlikely(!key)) {
        /* No valid key found for the generation ID provided in the header */
        return NULL;
    }

    /* 3. Metadata Extraction */
    if (out_sid) {
        *out_sid = ntohl(hdr->session_id);
    }

    /**
     * 4. Ciphertext Decryption.
     * Decrypt the payload in-place. The ciphertext starts immediately after the header.
     * Note: vpn_decrypt must handle AEAD tag verification internally.
     */
    uint8_t *ciphertext_ptr = buf + sizeof(vpn_tunnel_hdr_t);
    size_t ciphertext_len   = (size_t)(res - sizeof(vpn_tunnel_hdr_t));
    size_t plain_len = 0;

    if (unlikely(vpn_decrypt(key, ciphertext_ptr, ciphertext_len, ciphertext_ptr, &plain_len) != 0)) {
        /* Decryption failed: possible tampering, corruption, or wrong key */
        return NULL;
    }

    /* 5. Final Output Assignment */
    if (out_plain_len) {
        *out_plain_len = (int)plain_len;
    }

    return ciphertext_ptr; /* Return the start of the decrypted IP packet */
}

/**
 * @brief Fast pseudo-random number generator (Xorshift algorithm).
 * Standard rand() is avoided in high-performance VPNs due to global lock contention
 * and poor distribution. Xorshift provides high entropy with minimal CPU cycles.
 * @param seed Pointer to a thread-local or state-specific seed.
 * @return uint32_t A pseudo-random 32-bit integer.
 */
static inline uint32_t vpn_fast_rand(uint32_t *seed) {
    uint32_t x = *seed;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return *seed = x;
}

/**
 * @brief Appends random noise to the packet to obfuscate traffic length patterns.
 * This counters Traffic Analysis attacks where firewalls identify protocols based 
 * on packet size sequences (e.g., handshake vs. keepalive signatures).
 * @param task The task structure containing the buffer and iovec length.
 * @param max_pad Maximum number of bytes to append.
 */
void vpn_apply_padding(vfast_task_t *task, uint8_t max_pad) {
    if (!task || task->iov.iov_len < sizeof(vpn_tunnel_hdr_t)) return;

    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)task->buf;
    /* Thread-local storage ensures lock-free random generation for high-concurrency IO */
    static __thread uint32_t seed = 0x12345678; 

    size_t curr_len = task->iov.iov_len;
    int spare = BUF_SIZE - curr_len;
    if (spare <= 0) return;

    /* Determine padding length without exceeding buffer capacity or user-defined limit */
    uint8_t p_len = (uint8_t)(vpn_fast_rand(&seed) % (spare > max_pad ? max_pad : spare));
    if (p_len == 0) return;

    /* Fill the padding area with noise. Using 32-bit batches for faster memory writes. */
    uint8_t *p_ptr = (uint8_t *)task->buf + curr_len;
    uint32_t noise = vpn_fast_rand(&seed);
    for (int i = 0; i < p_len; i++) {
        if ((i & 3) == 0) noise = vpn_fast_rand(&seed); // Refresh entropy every 4 bytes
        p_ptr[i] = (uint8_t)(noise >> ((i & 3) << 3));
    }

    hdr->padding_len = p_len;
    hdr->flags |= 0x01; // Set PADDING_PRESENT flag
    task->iov.iov_len = curr_len + p_len;
}

/**
 * @brief Removes appended noise from the packet and restores original payload length.
 * Includes strict boundary checks to prevent memory corruption or integer underflow
 * from malformed or malicious packets.
 */
void vpn_remove_padding(vfast_task_t *task) {
    if (!task || task->iov.iov_len < sizeof(vpn_tunnel_hdr_t)) return;

    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)task->buf;
    if (hdr->flags & 0x01) {
        uint8_t p_len = hdr->padding_len;
        /* Critical Safety Check: Ensure the reported padding doesn't exceed received data */
        if (task->iov.iov_len >= (size_t)p_len + sizeof(vpn_tunnel_hdr_t)) {
            task->iov.iov_len -= p_len;
        }
        hdr->flags &= ~0x01; // Clear flag after processing
    }
}

/**
 * @brief Obfuscates the payload using a symmetric XOR mask to remove binary signatures.
 * Uses 64-bit word-sized operations to maximize throughput on modern CPUs.
 * The mask is derived from session_id and seq_num to ensure each packet has a unique 
 * binary representation, even if the plaintext is identical.
 */
void vpn_apply_obfs(vfast_task_t *task) {
    if (!task || task->iov.iov_len <= sizeof(vpn_tunnel_hdr_t)) return;

    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)task->buf;
    
    /* Construct 64-bit mask by duplicating the 32-bit derived key */
    uint64_t mask32 = (uint32_t)(hdr->session_id ^ hdr->seq_num);
    uint64_t mask64 = (mask32 << 32) | mask32;

    uint8_t *payload = (uint8_t *)task->buf + sizeof(vpn_tunnel_hdr_t);
    size_t len = task->iov.iov_len - sizeof(vpn_tunnel_hdr_t);

    /* Phase 1: High-speed 8-byte block XOR processing */
    uint64_t *p64 = (uint64_t *)payload;
    size_t blocks = len / 8;
    for (size_t i = 0; i < blocks; i++) {
        p64[i] ^= mask64;
    }

    /* Phase 2: Process trailing bytes (1-7 bytes) to ensure complete obfuscation */
    for (size_t i = blocks * 8; i < len; i++) {
        payload[i] ^= (uint8_t)(mask64 >> ((i & 7) << 3));
    }

    hdr->flags |= 0x02; // Set OBFS_ACTIVE flag
}

/**
 * @brief Reverses the XOR obfuscation to restore the original encrypted/plain payload.
 * Since XOR is its own inverse, the logic follows vpn_apply_obfs identically.
 */
void vfast_remove_obfs(vfast_task_t *task) {
    if (!task || task->iov.iov_len <= sizeof(vpn_tunnel_hdr_t)) return;

    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)task->buf;
    if (!(hdr->flags & 0x02)) return;

    /* Regenerate identical mask to reverse the transformation */
    uint64_t mask32 = (uint32_t)(hdr->session_id ^ hdr->seq_num);
    uint64_t mask64 = (mask32 << 32) | mask32;

    uint8_t *payload = (uint8_t *)task->buf + sizeof(vpn_tunnel_hdr_t);
    size_t len = task->iov.iov_len - sizeof(vpn_tunnel_hdr_t);

    uint64_t *p64 = (uint64_t *)payload;
    size_t blocks = len / 8;
    for (size_t i = 0; i < blocks; i++) {
        p64[i] ^= mask64;
    }

    for (size_t i = blocks * 8; i < len; i++) {
        payload[i] ^= (uint8_t)(mask64 >> ((i & 7) << 3));
    }
    
    hdr->flags &= ~0x02; // Clear flag after de-obfuscation
}

/**
 * @brief Prepares a packet for transmission by applying multi-layer obfuscation.
 * Execution Order: 
 * 1. Encryption (assumed done) 
 * 2. Padding (randomizes size)
 * 3. Obfuscation (XOR masking)
 * 4. Mimicry (header camouflage)
 * @param task The task object to be processed.
 * @param seq The sequence number for the current packet.
 */
void vpn_outbound_process(vfast_task_t *task, uint32_t seq) {
    if (!task) return;
    
    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)task->buf;
    
    /* 1. Set the sequence number first as it's the entropy source for OBFS */
    hdr->seq_num = seq;

    /* 2. Layer 1: Apply random padding (Target: Traffic Analysis / Packet Size Fingerprinting) */
    vpn_apply_padding(task, 64);

    /* 3. Layer 2: Apply XOR obfuscation (Target: Entropy Analysis / Binary Pattern Matching) */
    vpn_apply_obfs(task);

    /* 4. Layer 3: Apply Protocol Mimicry (Target: Deep Packet Inspection / Protocol Filtering) */
    /* 0x43 is the first byte of a QUIC Short Header, making it look like HTTP/3 traffic */
    // hdr->version = 0x43; 
}

/**
 * @brief Restores a received packet to its original state for business logic processing.
 * Execution Order (Strict Reverse):
 * 1. Mimicry Removal (restore version)
 * 2. Obfuscation Removal (reverse XOR)
 * 3. Padding Removal (trim trailing noise)
 * 4. Decryption (to be done after)
 */
void vpn_inbound_process(vfast_task_t *task) {
    if (!task || task->iov.iov_len < sizeof(vpn_tunnel_hdr_t)) return;

    /* 1. Layer 3: Restore the real protocol version (e.g., 0x01) */
    /* This must be done before logic checks or obfs removal if version is part of the mask */
    // vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)task->buf;
    // hdr->version = 0x01; 

    /* 2. Layer 2: Reverse XOR obfuscation based on the flags */
    vfast_remove_obfs(task);

    /* 3. Layer 1: Trim random padding to restore original payload length */
    vpn_remove_padding(task);
}

/**
 * @brief Diagnostic tool to inspect the VPN Tunnel Header and raw memory.
 * * Use this to identify alignment shifts or endianness issues.
 */
void vpn_debug_print_hdr(const void *buf, int len) {
    if (!buf || len < (int)sizeof(vpn_tunnel_hdr_t)) {
        return;
    }

    const vpn_tunnel_hdr_t *hdr = (const vpn_tunnel_hdr_t *)buf;
    const uint8_t *raw = (const uint8_t *)buf;

    printf("--- [] VPN HEADER DEBUG ---\n");
    
    /* 1. Print Fields (Interpreted) */
    printf("  Version:    0x%02x\n", hdr->version);
    printf("  MsgType:    0x%02x\n", hdr->msg_type);
    printf("  KeyID:      0x%02x\n", hdr->key_id);
    printf("  Flags:      0x%02x\n", hdr->flags);
    printf("  SessionID:  0x%08x (Host Order: 0x%08x)\n", 
            hdr->session_id, ntohl(hdr->session_id));
    
    /* 2. Print Header Memory Size */
    printf("  Header Sz:  %zu bytes\n", sizeof(vpn_tunnel_hdr_t));

    /* 3. Hex Dump of the first 16 bytes (Raw Memory) */
    printf("  Raw Hex:    ");
    for (int i = 0; i < 16 && i < len; i++) {
        printf("%02x ", raw[i]);
        if (i == sizeof(vpn_tunnel_hdr_t) - 1) printf("| "); // 分隔符：头结束位置
    }
    printf("\n-----------------------------\n");
}