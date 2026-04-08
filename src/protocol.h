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
    VPN_MSG_DISCONNECT= 0x04,
    VPN_DPD_REQUEST   = 0x05, /* Dead Peer Detection Request */
    VPN_DPD_RESPONSE  = 0x06  /* Dead Peer Detection Response */
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
 * @brief Encapsulates and encrypts a VFAST tunnel packet.
 *
 * This function handles the full lifecycle of a VFAST packet creation, including
 * mandatory AEAD encryption (ChaCha20-Poly1305) and header construction.
 * @section Architecture Zero-Copy Logic
 * To achieve maximum performance, this function performs in-place encryption. 
 * The caller MUST ensure the raw payload is already positioned at:
 * [buf + VPN_TNL_HLEN] (typically offset 8).
 *
 * @param[in]     key          A 32-byte symmetric encryption key.
 * @param[in,out] buf          The base address of the buffer. Encrypts in-place.
 * @param[in]     payload_len  The original length of the raw payload (e.g., IP packet).
 * @param[in]     max_buf_size Total capacity of buf to prevent overflow after encryption expansion (+40B).
 * @param[in]     type         VFAST message type (e.g., VPN_MSG_DATA, VPN_MSG_HEARTBEAT).
 * @param[in]     sid          Session ID (Host Order; converted to Network Order internally).
 *
 * @return Total packet length (Header + Nonce + Cipher + Tag) on success; -1 on failure.
 *
 * @note Memory Layout Transition:
 * Before: [8B Gap] [Payload(N)]
 * After:  [Header(8B)] [Nonce(24B)] [Cipher(N)] [Tag(16B)]
 */
int vpn_pack(const uint8_t *key, uint8_t *buf, int payload_len, int max_buf_size, vpn_msg_t type, uint32_t sid);

/**
 * @brief Decapsulates, authenticates, and decrypts incoming VFAST packets.
 *
 * Performs strict validation and full AEAD decryption. This is a fail-safe function
 * that prioritizes security: it authenticates the data before any protocol parsing.
 *
 * @section Security Protocol
 * 1. Length Check: Discards any fragments smaller than 48 bytes.
 * 2. Authentication: Verifies the AEAD Tag. Fails if the key is wrong or data is tampered.
 * 3. Validation: For DATA packets, performs deep inspection of the inner IPv4 header.
 *
 * @param[in]  key          A 32-byte symmetric encryption key.
 * @param[in]  buf          Base address of the received UDP packet.
 * @param[in]  received_len Total bytes received from the network.
 * @param[out] out_ip_len   Pointer to store the decrypted payload length.
 * @param[out] out_sid      Pointer to store the extracted Session ID (Host Order).
 *
 * @return Pointer to the decrypted plaintext (at buf + VPN_TNL_HLEN) on success; 
 * NULL if decryption fails, version mismatches, or IP header is malformed.
 *
 * @warning This function modifies the buffer in-place during decryption.
 */
uint8_t* vpn_unpack(const uint8_t *key, uint8_t *buf, int received_len, int *out_ip_len, uint32_t *out_sid);

#endif /* __PROTOCOL_H__ */