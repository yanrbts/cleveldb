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

// /**
//  * @brief Industrial-grade zero-copy encapsulation.
//  * @param buf          The base address of the memory block (buffer start).
//  * @param payload_len  The length of the actual payload currently in the buffer.
//  * @param max_buf_size Total capacity of the buffer.
//  * @param sid          Session ID.
//  * @param src_ip       Source virtual IP (Network Order).
//  * @param dst_ip       Destination virtual IP (Network Order).
//  * @note To achieve zero-copy, the caller MUST have placed the payload at 
//  * offset (VPN_TNL_HLEN + sizeof(struct iphdr)) within the buffer.
//  * @return Total packet length on success, -1 on failure.
//  */
// int vpn_pack(const uint8_t *key, uint8_t *buf, int payload_len, int max_buf_size, vpn_msg_t type, uint32_t sid) {
//     UNUSED(key);
    
//     // const int ip_hlen = sizeof(struct iphdr);
//     // const int required_head = VPN_TNL_HLEN + ip_hlen;
//     const int total_len = VPN_TNL_HLEN + payload_len;

//     /* 1. Defensive Check: Ensure the total packet fits in the provided buffer */
//     if (buf == NULL || total_len > max_buf_size) {
//         log_error("Buffer overflow risk: required %d bytes, but max is %d", total_len, max_buf_size);
//         return -1;
//     }

//     /* [ZERO-COPY LOGIC]
//      * Instead of shifting data with memmove, we assume the payload is already
//      * at buf + required_head. We simply fill the headers in the gap.
//      */

//     /* 2. Setup Tunnel Header at the very beginning of the buffer */
//     vpn_tunnel_hdr_t *tnl = (vpn_tunnel_hdr_t *)buf;
//     tnl->version    = VPN_VERSION;
//     tnl->msg_type   = (uint8_t)type;
//     tnl->flags      = 0;
//     tnl->session_id = htonl(sid);

//     /* 3. Setup Internal IP Header immediately following the tunnel header */
//     // struct iphdr *ip = (struct iphdr *)(buf + VPN_TNL_HLEN);
//     // _init_ip_header(ip, payload_len, src_ip, dst_ip);

//     /* The entire packet now resides contiguously from 'buf' to 'buf + total_len' */
//     return total_len;
// }


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

// /**
//  * @brief Decapsulates and validates incoming VFAST tunnel packets
//  */
// uint8_t* vpn_unpack(const uint8_t *key, uint8_t *buf, int received_len, int *out_ip_len, uint32_t *out_sid) {
//     UNUSED(key);
    
//     const int min_header_len = VPN_TNL_HLEN + sizeof(struct iphdr);

//     /* 1. Basic length validation */
//     if (buf == NULL || received_len < min_header_len) {
//         log_error("Received packet too short: %d bytes (minimum %d)", received_len, min_header_len);
//         return NULL;
//     }

//     /* 2. Validate Tunnel Header */
//     vpn_tunnel_hdr_t *tnl = (vpn_tunnel_hdr_t *)buf;
//     if (tnl->version != VPN_VERSION) {
//         log_error("Unsupported VPN version: %d", tnl->version);
//         return NULL;
//     }

//     /* 3. Validate Internal IP Header Sanity */
//     struct iphdr *ip = (struct iphdr *)(buf + VPN_TNL_HLEN);
//     if (ip->version != 4 || ip->ihl < 5) {
//         log_error("Invalid IP header: version %d, IHL %d", ip->version, ip->ihl);
//         return NULL;
//     }

//     /* 4. Industrial Check: Cross-verify advertised length with actual received length 
//      * This prevents processing of malformed packets or memory disclosure.
//      */
//     int inner_ip_tot_len = ntohs(ip->tot_len);
//     if (inner_ip_tot_len > (received_len - (int)VPN_TNL_HLEN)) {
//         log_error("Inner IP total length %d exceeds available data %d", inner_ip_tot_len, received_len - (int)VPN_TNL_HLEN);
//         return NULL;
//     }

//     /* 5. Extract Metadata */
//     *out_sid = ntohl(tnl->session_id);
//     // *out_ip_len = received_len - VPN_TNL_HLEN;
//     *out_ip_len = inner_ip_tot_len;

//     /* Return pointer to start of Internal IP Header for TUN write */
//     return (buf + VPN_TNL_HLEN);
// }

/**
 * @brief Decapsulates and decrypts incoming VFAST packets.
 * @return Pointer to the decrypted plaintext, or NULL on authentication failure.
 */
uint8_t* vpn_unpack(const uint8_t *key, uint8_t *buf, int received_len, int *out_ip_len, uint32_t *out_sid) {
    /* 1. Basic length check (Header 8 + Nonce 24 + Tag 16 = 48 bytes) */
    if (unlikely(!buf || !key)) {
        return NULL;
    }

    /* 2. Header Validation */
    vpn_tunnel_hdr_t *tnl = (vpn_tunnel_hdr_t *)buf;
    if (unlikely(tnl->version != VPN_VERSION)) {
        return NULL;
    }

    /* 3. Extract Metadata */
    *out_sid = ntohl(tnl->session_id);
    uint8_t *crypto_ptr = buf + VPN_TNL_HLEN;
    size_t crypto_len   = (size_t)(received_len - VPN_TNL_HLEN);
    size_t plain_len    = 0;

    /* 4. Authenticated Decryption (In-place) */
    // This handles DATA, HEARTBEAT, and Handshake responses.
    if (unlikely(vpn_decrypt(key, crypto_ptr, crypto_len, crypto_ptr, &plain_len) != 0)) {
        log_warn("MAC Authentication failed for SID: 0x%08x", *out_sid);
        return NULL;
    }

    /* 5. Payload-Specific Validation */
    if (tnl->msg_type == VPN_MSG_DATA) {
        if (unlikely(plain_len < sizeof(struct iphdr))) return NULL;

        struct iphdr *ip = (struct iphdr *)crypto_ptr;
        // Verify IPv4 Sanity
        if (unlikely(ip->version != 4 || ip->ihl < 5)) {
            log_error("Decrypted data is not a valid IPv4 packet");
            return NULL;
        }

        // Cross-verify IP total length with decrypted size
        int inner_ip_tot_len = ntohs(ip->tot_len);
        if (unlikely(inner_ip_tot_len > (int)plain_len)) {
            log_error("IP length mismatch: tot_len %d, plain %zu", inner_ip_tot_len, plain_len);
            return NULL;
        }
        *out_ip_len = inner_ip_tot_len;
    } else {
        // For control/heartbeat, return the full decrypted length
        *out_ip_len = (int)plain_len;
    }

    return crypto_ptr;
}