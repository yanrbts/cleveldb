/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 * 
 * +-----------------------------------------------------------------------+
 * |              外部 IP 首部 (External IP Header)                         |
 * |  源地址: 客户端公网 IP (如 112.95.x.x)                                  |
 * |  目的地址: VPN 服务端公网 IP (如 47.x.x.x)                              |
 * +-----------------------------------------------------------------------+
 * |              UDP 首部 (External UDP Header)                           |
 * |  源端口: 随机 (如 5678)  目的端口: 9999 (你的 VFAST 端口)                |
 * +-----------------------------------------------------------------------+
 * |              VFAST 协议头 (可选，用于加密/校验)                         |
 * |        [ Session ID ] [ Packet Type ] [ Flags ]                       |
 * +-----------------------------------------------------------------------+
 * |              负载数据 (Payload) <--- 核心：这是被封装的内层包            |
 * |  +-----------------------------------------------------------------+  |
 * |  |         内部 IP 首部 (Internal IP Header)                        |  |
 * |  |源地址: 虚拟 IP (10.0.0.2)                                        |  |
 * |  |目的地址: 目标服务器 IP (如 Google 8.8.8.8)                        |  |
 * |  +-----------------------------------------------------------------+  |
 * |  |         传输层首部 (TCP/UDP Header)                              |  |
 * |  |  源端口: 4433        目的端口: 443 (HTTPS)                       |  |
 * |  +-----------------------------------------------------------------+  |
 * |  |           应用层数据 (HTTP Get / Data)                           |  |
 * |  +-----------------------------------------------------------------+  |
 * +-----------------------------------------------------------------------+
 * 
 * 
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |Version|  IHL  |Type of Service|          Total Length         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         Identification        |Flags|      Fragment Offset    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  Time to Live |    Protocol   |         Header Checksum       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                       Source Address (10.0.0.2)               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Destination Address (8.8.8.8)              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   |                    Payload (TCP/UDP Data...)                  |
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#include <stdint.h>

/* Protocol Constants */
#define VPN_VERSION       1
#define VPN_MTU_DEFAULT   1400  /* Standard MTU for tunnel interfaces */

/* Message Types */
typedef enum {
    VPN_MSG_DATA      = 0x01,
    VPN_MSG_HELLO     = 0x02,
    VPN_MSG_KEEPALIVE = 0x03,
    VPN_MSG_DISCONNECT= 0x04
} vpn_msg_t;

/* * Packed Structure for Network Transmission
 * Total size: 8 bytes (64-bit aligned for optimal CPU access)
 */
typedef struct {
    uint8_t  version;      /* Protocol version */
    uint8_t  msg_type;     /* Message type from vfast_msg_t */
    uint16_t flags;        /* Reserved for future flags (e.g. compression, encryption type) */
    uint32_t session_id;   /* Unique session identifier (Network Byte Order) */
} __attribute__((packed)) vpn_tunnel_hdr_t;

#define VPN_TNL_HLEN sizeof(vpn_tunnel_hdr_t)

/**
 * @brief Encapsulates payload into VFAST + IPv4 tunnel
 * @param buf The buffer containing raw payload. Must be large enough for headers.
 * @param payload_len Length of the data currently in buf
 * @param max_buf_size Total capacity of buf to prevent overflow
 * @param type The VFAST message type (DATA, HELLO, KEEPALIVE, etc.)
 * @param sid Session ID for the tunnel
 * @param src_ip Source Virtual IP (Network Order)
 * @param dst_ip Destination Virtual IP (Network Order)
 * @return Total packet length on success, -1 on buffer overflow
 */
int vpn_pack(uint8_t *buf, int payload_len, 
             int max_buf_size, vpn_msg_t type, uint32_t sid,
             uint32_t src_ip, uint32_t dst_ip);

/**
 * @brief Decapsulates and validates incoming VFAST tunnel packets
 * @param buf Pointer to the received data
 * @param received_len Length of data received from socket
 * @param out_ip_len Output parameter for the internal IP packet length
 * @param out_sid Output parameter for the session ID
 * @return Pointer to the start of the internal IP packet, or NULL if invalid
 */
uint8_t* vpn_unpack(uint8_t *buf, int received_len, int *out_ip_len, uint32_t *out_sid);

#endif /* __PROTOCOL_H__ */