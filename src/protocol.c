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
 * @brief Encapsulates the tunnel header with protocol-specific metadata.
 * * In high-performance asynchronous I/O (like io_uring), packets may remain 
 * in the kernel queue during a rekeying event. Including the 'kid' (Key ID) 
 * in every header allows the receiver to perform a "Lockless Key Lookup," 
 * matching the packet to either the 'Active' or 'Previous' key accurately.
 *
 * @param buf  Pointer to the start of the transmission buffer.
 * @param type The message type (e.g., VPN_MSG_DATA, VPN_MSG_KEEPALIVE).
 * @param sid  The Session ID assigned during the HELLO exchange.
 * @param kid  The Key ID currently active in the security context.
 */
void vpn_fill_header(void *buf, uint8_t type, uint32_t sid, uint32_t kid) {
    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)buf;

    hdr->version  = VPN_VERSION;
    hdr->msg_type = type;

    /**
     * Store the truncated Key ID. 
     * Using (kid & 0xFF) allows the receiver to distinguish between 
     * consecutive rekeying generations (e.g., Gen 2 vs Gen 3).
     */
    hdr->key_id   = (uint8_t)(kid & 0xFF);
    hdr->flags    = 0;
    hdr->session_id = (type == VPN_MSG_HELLO) ? 0 : htonl(sid);
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