/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */

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
 * @param key          32-byte session key.
 * @param buf          Buffer base (Payload MUST start at buf + VPN_TNL_HLEN).
 * @param payload_len  Length of the raw payload (e.g., IP packet or Control data).
 * @param max_buf_size Total capacity of the allocated buffer.
 * @param type         VFAST message type (DATA, HEARTBEAT, CONTROL, etc.).
 * @param sid          Session ID for routing.
 * @return Total bytes to send over UDP, or -1 on error.
 */
int vpn_pack(const uint8_t *key, uint8_t *buf, int payload_len, int max_buf_size, vpn_msg_t type, uint32_t sid) {
    if (unlikely(!buf || !key)) return -1;

    /* 1. Locate Payload: Assumes zero-copy placement at offset 8 */
    uint8_t *payload_ptr = buf + VPN_TNL_HLEN;
    size_t crypto_out_len = 0;

    /* 2. Full Encryption: All packet types are encrypted to protect 
     * metadata (like allocated IPs in handshake) and evade basic DPI.
     */
    if (unlikely(vpn_encrypt(key, payload_ptr, (size_t)payload_len, payload_ptr, &crypto_out_len) != 0)) {
        log_error("Encryption failed for SID: 0x%08x", sid);
        return -1;
    }

    const int total_len = VPN_TNL_HLEN + (int)crypto_out_len;

    /* 3. Safety Check: 48 bytes (Nonce+Tag+Hdr) + original payload */
    if (unlikely(total_len > max_buf_size)) {
        log_error("Buffer overflow: needed %d, have %d", total_len, max_buf_size);
        return -1;
    }

    /* 4. Fill Tunnel Header (Sent in plaintext for now) */
    vpn_tunnel_hdr_t *tnl = (vpn_tunnel_hdr_t *)buf;
    tnl->version    = VPN_VERSION;
    tnl->msg_type   = (uint8_t)type;
    tnl->flags      = 0;
    tnl->session_id = htonl(sid);

    return total_len;
}

/**
 * @brief Decapsulates VFAST header and decrypts payload in-place.
 * @return Pointer to the decrypted plain IP packet, or NULL on failure.
 */
uint8_t* vpn_unpack(const uint8_t *key, uint8_t *buf, int res, int *out_plain_len, uint32_t *out_sid) {
    if (unlikely(res < (int)sizeof(vpn_tunnel_hdr_t))) return NULL;

    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)buf;
    *out_sid = ntohl(hdr->session_id);

    /* Locate Ciphertext: Header (8B) + [Nonce + Payload + Tag] */
    uint8_t *ciphertext_ptr = buf + sizeof(vpn_tunnel_hdr_t);
    size_t ciphertext_len   = (size_t)(res - sizeof(vpn_tunnel_hdr_t));

    /* Decrypt directly back into the same buffer area */
    size_t plain_len = 0;
    if (vpn_decrypt(key, ciphertext_ptr, ciphertext_len, ciphertext_ptr, &plain_len) != 0) {
        return NULL;
    }

    *out_plain_len = (int)plain_len;
    return ciphertext_ptr; // This is the start of the Plain IP Packet
}