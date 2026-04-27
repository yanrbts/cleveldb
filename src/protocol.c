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
 * @brief Industrial Encapsulation: [Padding] -> [Branching Encryption] -> [Obfuscation]
 * Pipeline ensures all packets, including plain-text control messages, are masked.
 * @param sec      Session security context.
 * @param buf      Buffer base (Header starts at buf, Payload at buf + HLEN).
 * @param plen     Length of the raw L3/Control payload.
 * @param max_size Capacity of the buffer to prevent overflows.
 * @param type     VFAST message type (DATA, HELLO, KEEPALIVE, etc.).
 * @param sid      Session ID for routing.
 * @return Total bytes for wire transmission, or -1 on error.
 */
int vf_pack(const vfast_sec_ctx_t *sec, uint8_t *buf, int plen, 
             int max_size, vf_msg_t type, uint32_t sid) {
    
    if (unlikely(!buf)) return -1;

    uint8_t *ptr = buf + VPN_TNL_HLEN;
    size_t out_len = 0;
    uint32_t kid = 0; 

    /* 1. Mandatory Padding: Add noise to hide packet size signatures */
    int i_plen = vf_apply_padding(buf, plen, 32);

    /**
     * 2. Encryption Branching: 
     * HELLO and KEEPALIVE bypass AEAD to maintain handshake availability.
     */
    if (sec == NULL || type == VPN_MSG_HELLO || type == VPN_MSG_KEEPALIVE) {
        out_len = (size_t)i_plen;
    } else {
        // if (unlikely(!sec)) return -1;
        
        const uint8_t *key = vf_rekey_get_key(sec);
        kid = vf_rekey_get_keyid(sec);

        if (unlikely(!key || vf_encrypt(key, ptr, (size_t)i_plen, ptr, &out_len) != 0)) {
            log_error("Cipher error | SID: 0x%08x", sid);
            return -1;
        }
    }
    int tlen = VPN_TNL_HLEN + (int)out_len;

    /* 3. Header Construction & Boundary Validation */
    vf_fill_header(buf, tlen, (uint8_t)type, sid, kid);

    if (unlikely(tlen > max_size)) return -1;

    /* 4. Mandatory Obfuscation: Mask header to bypass DPI pattern matching */
    vf_apply_header_obfs(buf, (size_t)tlen);

    return tlen;
}

/**
 * @brief Decapsulation: [De-obfuscate] -> [Branching Decryption] -> [Unpadding]
 * Restores the original IP packet from the masked UDP stream.
 * * @return Pointer to decrypted payload, or NULL on integrity/format failure.
 */
uint8_t* vf_unpack(const vfast_sec_ctx_t *sec, uint8_t *buf, int res, int *out_plen) {
    
    if (unlikely(!buf || res < (int)sizeof(vf_hdr_t))) return NULL;

    vf_hdr_t *hdr = (vf_hdr_t *)buf;
    // if (out_sid) *out_sid = ntohl(hdr->session_id);

    uint8_t *ptr = buf + sizeof(vf_hdr_t);
    size_t rlen = (size_t)(res - sizeof(vf_hdr_t));
    size_t dlen = 0;

    /**
     * 2. Decryption Branching: Matches the logic in vf_pack.
     */
    if (hdr->msg_type == VPN_MSG_HELLO || hdr->msg_type == VPN_MSG_KEEPALIVE) {
        dlen = rlen;
    } else {
        if (unlikely(!sec)) return NULL;
        const uint8_t *key = vf_rekey_get_decrypt_key(sec, hdr->key_id);
        
        if (unlikely(!key || vf_decrypt(key, ptr, rlen, ptr, &dlen) != 0)) {
            return NULL; /* Auth failure or decryption error */
        }
    }

    /* 3. Mandatory Unpadding: Restore exact length regardless of encryption state */
    size_t tlen = dlen + sizeof(vf_hdr_t);
    if (unlikely(vf_remove_padding(buf, &tlen) != 0)) return NULL;

    if (out_plen) *out_plen = (int)(tlen - sizeof(vf_hdr_t));

    return ptr;
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
 * @brief Appends high-entropy padding to eliminate packet size signatures.
 * * This function implements "Inner Padding" (pre-encryption). By placing 
 * the padding inside the AEAD-protected payload, the noise becomes 
 * cryptographically indistinguishable from the actual IP packet, 
 * effectively countering Traffic Analysis (VBR-to-CBR mitigation).
 * @param buf    Pointer to the I/O task container.
 * @param raw_len The size of the L3 IP packet read from the TUN device.
 * @param max_pad The upper bound for random padding (to control overhead).
 * @return int    The updated payload length (raw_len + padding_len).
 */
int vf_apply_padding(uint8_t *buf, int raw_len, uint8_t max_pad) {
    /* Fast path for invalid inputs */
    if (unlikely(!buf || raw_len <= 0)) {
        return raw_len;
    }

    /* 1. Locate the encapsulation header at the buffer base */
    vf_hdr_t *hdr = (vf_hdr_t *)buf;
    
    /* Use thread-local seed to avoid cache contention in multi-threaded I/O */
    static __thread uint32_t local_seed = 0x5EED5EED; 

    /* 2. Calculate current occupancy: Header (HLEN) + L3 Payload (raw_len) */
    const size_t consumed = VPN_TNL_HLEN + raw_len;
    
    /**
     * 3. Capacity Guard: 
     * We must ensure space for: Header + Payload + Padding + AEAD Auth Tag.
     * 32 bytes is a safe margin for most AEAD tags (e.g., Poly1305/GCM Tag).
     */
    const int spare = (int)BUF_SIZE - (int)consumed - 32;
    if (unlikely(spare <= 0)) {
        hdr->padding_len = 0;
        return raw_len;
    }

    /* 4. Determine padding size: random value between 1 and min(max_pad, spare) */
    uint8_t p_len = (uint8_t)(vpn_fast_rand(&local_seed) % 
                    (spare > max_pad ? max_pad : spare));
    
    if (p_len == 0) {
        hdr->padding_len = 0;
        return raw_len;
    }

    /**
     * 5. Entropy Generation & Write:
     * We fill the trailing buffer space with high-entropy noise.
     * Optimization: Refresh entropy in 32-bit blocks but write byte-wise 
     * to handle unaligned padding lengths without complex tail-logic.
     */
    uint8_t *p_ptr = (uint8_t *)buf + consumed;
    uint32_t noise_block = 0;

    for (int i = 0; i < p_len; i++) {
        if ((i & 3) == 0) {
            noise_block = vpn_fast_rand(&local_seed);
        }
        p_ptr[i] = (uint8_t)(noise_block >> ((i & 3) << 3));
    }

    /* 6. Commit Metadata to Header */
    hdr->padding_len = p_len;
    hdr->flags |= VPN_HDR_FLAG_PADDING; /* 0x01: Signal padding presence to peer */

    return raw_len + p_len;
}

/**
 * @brief Strips trailing noise and restores the original IP packet length.
 * DESIGN PRINCIPLE:
 * This function operates on a raw memory buffer to maintain maximum portability.
 * It must be called AFTER successful decryption but BEFORE routing to the TUN device.
 * @param buf     Pointer to the decrypted VFAST packet (including header).
 * @param p_len   Pointer to the current packet length. This value will be 
 * updated (decremented) if padding is removed.
 * @return int    Returns 0 on success, -1 if the packet is malformed.
 */
int vf_remove_padding(uint8_t *buf, size_t *p_len) {
    /* 1. Basic sanity check */
    if (unlikely(!buf || !p_len || *p_len < VPN_TNL_HLEN)) {
        return -1;
    }

    vf_hdr_t *hdr = (vf_hdr_t *)buf;

    /* 2. Check if the PADDING_PRESENT flag (0x01) is active */
    if (hdr->flags & VPN_HDR_FLAG_PADDING) {
        uint8_t padding_val = hdr->padding_len;

        /**
         * 3. Boundary & Underflow Protection:
         * We ensure that the data actually received is enough to cover the 
         * header and the claimed padding. This is a critical security check 
         * against length-truncation attacks.
         */
        if (likely(*p_len >= (size_t)padding_val + VPN_TNL_HLEN)) {
            /* Update the external length variable */
            *p_len -= padding_val;
            
            /* 4. Cleanup: Clear the flag to signify the packet is now 'clean' */
            hdr->flags &= ~VPN_HDR_FLAG_PADDING;
        } else {
            /**
             * 5. Anomaly Handling:
             * If padding_len claims to be more than the packet itself, 
             * it's either a corrupted packet or a malicious attempt 
             * to cause a buffer underflow.
             */
            return -1; 
        }
    }

    return 0;
}

/**
 * @brief Obfuscates the tunnel header to prevent protocol fingerprinting.
 * Rationale: AEAD payloads are already high-entropy (random-looking). 
 * The vulnerability lies in the static header fields (SID, Version, Flags). 
 * This function masks the header using a rolling key derived from the 
 * Sequence Number, ensuring every packet header is unique.
 * @param buf      Pointer to the start of the VFAST packet (task->buf).
 * @param wire_len The total length of the packet to be transmitted.
 */
void vf_apply_header_obfs(uint8_t *buf, size_t wire_len) {
    if (unlikely(!buf || wire_len < VPN_TNL_HLEN)) {
        return;
    }

    vf_hdr_t *hdr = (vf_hdr_t *)buf;

    /**
     * 1. Key Derivation:
     * We use the Network-Byte-Order Sequence Number as the entropy source.
     * The mask is generated by mixing the Seq with a fixed protocol salt.
     */
    uint32_t rolling_seq = hdr->seq_num; // Already in Network Byte Order
    uint32_t obfs_key = rolling_seq ^ 0xDEADBEEF; // Static salt for protocol unique-ness

    /**
     * 2. Targeted Masking:
     * We do NOT mask the SeqNum itself (the peer needs it to de-obfuscate).
     * We mask the SessionID and the Version/Flags byte.
     */
    hdr->session_id ^= obfs_key;
    
    uint32_t head_block;
    memcpy(&head_block, buf, sizeof(uint32_t));
    head_block ^= (obfs_key << 8) | (obfs_key >> 24);
    memcpy(buf, &head_block, sizeof(uint32_t));
    /**
     * 3. Metadata Update:
     * Signal to the peer that this header is masked.
     * Note: In a true "stealth" mode, we don't set a flag; the peer 
     * simply tries to de-obfuscate by default.
     */
    // hdr->flags |= VPN_HDR_FLAG_OBFS; // Optional: 0x02
}

/**
 * @brief Restores the tunnel header by reversing the XOR mask.
 * * This MUST be the very first function called upon receiving a UDP packet.
 * It restores the SessionID and other metadata so the server can identify 
 * the user and retrieve the correct decryption keys.
 * @param buf      Pointer to the received raw UDP payload (task->buf).
 * @param wire_len Total bytes received from the socket.
 */
void vf_remove_header_obfs(uint8_t *buf, size_t wire_len) {
    /* 1. Basic sanity check: ensure we have at least a full header */
    if (unlikely(!buf || wire_len < VPN_TNL_HLEN)) {
        return;
    }

    /* Use a temporary pointer for structured access */
    vf_hdr_t *hdr = (vf_hdr_t *)buf;

    /**
     * 2. Key Extraction:
     * The Sequence Number was left in plaintext by the sender.
     * We use it now to re-generate the exact same mask used during encryption.
     */
    uint32_t rolling_seq = hdr->seq_num; 
    uint32_t obfs_key = rolling_seq ^ 0xDEADBEEF; 

    /**
     * 3. Mask Reversal:
     * XOR is its own inverse ( (A ^ B) ^ B = A ).
     * We follow the exact same bitwise operations as vf_apply_header_obfs.
     */
    
    /* Restore the first 4 bytes (Version, MsgType, Flags, PaddingLen) */
    uint32_t head_block;
    memcpy(&head_block, buf, sizeof(uint32_t));
    head_block ^= (obfs_key << 8) | (obfs_key >> 24);
    memcpy(buf, &head_block, sizeof(uint32_t));

    /* Restore the SessionID (4 bytes) */
    hdr->session_id ^= obfs_key;

    /* Now hdr->session_id and hdr->flags are back to their original values */
}

/**
 * @brief Diagnostic tool to inspect the VPN Tunnel Header and raw memory.
 * * Use this to identify alignment shifts or endianness issues.
 */
void vpn_debug_print_hdr(const void *buf, int len) {
    if (!buf || len < (int)sizeof(vf_hdr_t)) {
        return;
    }

    const vf_hdr_t *hdr = (const vf_hdr_t *)buf;
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
    printf("  Header Sz:  %zu bytes\n", sizeof(vf_hdr_t));

    /* 3. Hex Dump of the first 16 bytes (Raw Memory) */
    printf("  Raw Hex:    ");
    for (int i = 0; i < 16 && i < len; i++) {
        printf("%02x ", raw[i]);
        if (i == sizeof(vf_hdr_t) - 1) printf("| "); // 分隔符：头结束位置
    }
    printf("\n-----------------------------\n");
}