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
#include "protocol.h"

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
 * @brief Initialize a standard IPv4 header
 * @note This is a internal static helper to ensure consistent IP state
 */
static void _init_ip_header(struct iphdr *ip, int total_payload_len, uint32_t src_ip, uint32_t dst_ip) {
    ip->version  = 4;
    ip->ihl      = 5; // Standard 20 bytes
    ip->tos      = 0;
    ip->tot_len  = htons(sizeof(struct iphdr) + total_payload_len);
    ip->id       = 0; 
    ip->frag_off = htons(IP_DF); // Don't Fragment
    ip->ttl      = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr    = src_ip;
    ip->daddr    = dst_ip;
    ip->check    = 0;
    /* Industrial grade checksum calculation */
    ip->check    = _calculate_checksum((uint16_t *)ip, sizeof(struct iphdr));
}

/**
 * @brief Industrial-grade zero-copy encapsulation.
 * @param buf          The base address of the memory block (buffer start).
 * @param payload_len  The length of the actual payload currently in the buffer.
 * @param max_buf_size Total capacity of the buffer.
 * @param sid          Session ID.
 * @param src_ip       Source virtual IP (Network Order).
 * @param dst_ip       Destination virtual IP (Network Order).
 * @note To achieve zero-copy, the caller MUST have placed the payload at 
 * offset (VPN_TNL_HLEN + sizeof(struct iphdr)) within the buffer.
 * @return Total packet length on success, -1 on failure.
 */
int vpn_pack(uint8_t *buf, int payload_len, int max_buf_size, vpn_msg_t type,
             uint32_t sid, uint32_t src_ip, uint32_t dst_ip) {
    
    const int ip_hlen = sizeof(struct iphdr);
    const int required_head = VPN_TNL_HLEN + ip_hlen;
    const int total_len = required_head + payload_len;

    /* 1. Defensive Check: Ensure the total packet fits in the provided buffer */
    if (buf == NULL || total_len > max_buf_size) {
        log_error("Buffer overflow risk: required %d bytes, but max is %d", total_len, max_buf_size);
        return -1;
    }

    /* [ZERO-COPY LOGIC]
     * Instead of shifting data with memmove, we assume the payload is already
     * at buf + required_head. We simply fill the headers in the gap.
     */

    /* 2. Setup Tunnel Header at the very beginning of the buffer */
    vpn_tunnel_hdr_t *tnl = (vpn_tunnel_hdr_t *)buf;
    tnl->version    = VPN_VERSION;
    tnl->msg_type   = (uint8_t)type;
    tnl->flags      = 0;
    tnl->session_id = htonl(sid);

    /* 3. Setup Internal IP Header immediately following the tunnel header */
    struct iphdr *ip = (struct iphdr *)(buf + VPN_TNL_HLEN);
    _init_ip_header(ip, payload_len, src_ip, dst_ip);

    /* The entire packet now resides contiguously from 'buf' to 'buf + total_len' */
    return total_len;
}

/**
 * @brief Decapsulates and validates incoming VFAST tunnel packets
 */
uint8_t* vpn_unpack(uint8_t *buf, int received_len, int *out_ip_len, uint32_t *out_sid) {
    
    const int min_header_len = VPN_TNL_HLEN + sizeof(struct iphdr);

    /* 1. Basic length validation */
    if (buf == NULL || received_len < min_header_len) {
        log_error("Received packet too short: %d bytes (minimum %d)", received_len, min_header_len);
        return NULL;
    }

    /* 2. Validate Tunnel Header */
    vpn_tunnel_hdr_t *tnl = (vpn_tunnel_hdr_t *)buf;
    if (tnl->version != VPN_VERSION) {
        log_error("Unsupported VPN version: %d", tnl->version);
        return NULL;
    }

    /* 3. Validate Internal IP Header Sanity */
    struct iphdr *ip = (struct iphdr *)(buf + VPN_TNL_HLEN);
    if (ip->version != 4 || ip->ihl < 5) {
        log_error("Invalid IP header: version %d, IHL %d", ip->version, ip->ihl);
        return NULL;
    }

    /* 4. Industrial Check: Cross-verify advertised length with actual received length 
     * This prevents processing of malformed packets or memory disclosure.
     */
    int inner_ip_tot_len = ntohs(ip->tot_len);
    if (inner_ip_tot_len > (received_len - (int)VPN_TNL_HLEN)) {
        log_error("Inner IP total length %d exceeds available data %d", inner_ip_tot_len, received_len - (int)VPN_TNL_HLEN);
        return NULL;
    }

    /* 5. Extract Metadata */
    *out_sid = ntohl(tnl->session_id);
    *out_ip_len = received_len - VPN_TNL_HLEN;

    /* Return pointer to start of Internal IP Header for TUN write */
    return (buf + VPN_TNL_HLEN);
}