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
#include "key.h"
#include "io.h"

/* Protocol Constants */
#define VPN_VERSION             1
#define VPN_MTU_DEFAULT         1400  /* Standard MTU for tunnel interfaces */
#define VPN_HDR_FLAG_PADDING    0x01

/* Message Types */
typedef enum {
    VPN_MSG_DATA       = 0x01,
    VPN_MSG_HELLO      = 0x02,
    VPN_MSG_KEEPALIVE  = 0x03,
    VPN_MSG_DISCONNECT = 0x04,
    VPN_DPD_REQUEST    = 0x05,  /* Dead Peer Detection Request */
    VPN_DPD_RESPONSE   = 0x06,  /* Dead Peer Detection Response */
    VPN_MSG_REKEY_REQ  = 0x07,  /* Triggered by vfast_rekey_needed */
    VPN_MSG_REKEY_ACK  = 0x08   /* Confirmation to call vfast_rekey_commit */
} vpn_msg_t;

/* * Packed Structure for Network Transmission
 * Total size: 8 bytes (64-bit aligned for optimal CPU access)
 */
typedef struct {
    uint8_t  version;      /* Protocol version */
    uint8_t  msg_type;     /* Message type from vfast_msg_t */
    uint8_t  key_id;       /* Key ID for encryption (0 for HELLO, n for active session key) */
    uint8_t  flags;        /* Reserved for future flags (e.g. compression, encryption type) */
    uint32_t session_id;   /* Unique session identifier (Network Byte Order) */

    uint8_t  padding_len;  /* Length of padding bytes */
    uint8_t  reserved[3];  /* keep 4-byte alignment */
    uint32_t seq_num;
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
int vpn_pack(const vfast_sec_ctx_t *sec, uint8_t *buf, int payload_len, int max_buf_size, vpn_msg_t type, uint32_t sid);

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
 * @param[in]  sec          Security context containing the encryption key.
 * @param[in]  buf          Base address of the received UDP packet.
 * @param[in]  received_len Total bytes received from the network.
 * @param[out] out_ip_len   Pointer to store the decrypted payload length.
 *
 * @return Pointer to the decrypted plaintext (at buf + VPN_TNL_HLEN) on success; 
 * NULL if decryption fails, version mismatches, or IP header is malformed.
 *
 * @warning This function modifies the buffer in-place during decryption.
 */
uint8_t* vpn_unpack(const vfast_sec_ctx_t *sec, uint8_t *buf, int received_len, int *out_ip_len);

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
static inline void vpn_fill_header(void *buf, uint8_t type, uint32_t sid, uint32_t kid) {
    vpn_tunnel_hdr_t *hdr = (vpn_tunnel_hdr_t *)buf;

    hdr->version  = VPN_VERSION;
    hdr->msg_type = type;

    /**
     * Store the truncated Key ID. 
     * Using (kid & 0xFF) allows the receiver to distinguish between 
     * consecutive rekeying generations (e.g., Gen 2 vs Gen 3).
     */
    hdr->key_id = (uint8_t)(kid & 0xFF);
    hdr->flags = 0;
    hdr->session_id = htonl(sid);
}

/**
 * @brief Applies random padding to the packet to obfuscate traffic patterns.
 * This function adds a random amount of padding (up to max_pad) to the end
 * of the payload. The padding length is stored in the header for proper removal.
 * Note: The caller must ensure that the total packet size (Header + Payload + Padding)
 * does not exceed the maximum buffer size or MTU.
 * @param task    The task structure containing the buffer and current payload length.
 * @param max_pad The maximum number of padding bytes to add (e.g., 0-255).
 */
int vpn_apply_padding(uint8_t *buf, int raw_len, uint8_t max_pad);

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
int vpn_remove_padding(uint8_t *buf, size_t *p_len);

/**
 * @brief Obfuscates the tunnel header to prevent protocol fingerprinting.
 * Rationale: AEAD payloads are already high-entropy (random-looking). 
 * The vulnerability lies in the static header fields (SID, Version, Flags). 
 * This function masks the header using a rolling key derived from the 
 * Sequence Number, ensuring every packet header is unique.
 * @param buf      Pointer to the start of the VFAST packet (task->buf).
 * @param wire_len The total length of the packet to be transmitted.
 */
void vpn_apply_header_obfs(uint8_t *buf, size_t wire_len);

/**
 * @brief Restores the tunnel header by reversing the XOR mask.
 * This MUST be the very first function called upon receiving a UDP packet.
 * It restores the SessionID and other metadata so the server can identify 
 * the user and retrieve the correct decryption keys.
 * @param buf      Pointer to the received raw UDP payload (task->buf).
 * @param wire_len Total bytes received from the socket.
 */
void vpn_remove_header_obfs(uint8_t *buf, size_t wire_len);


void vpn_debug_print_hdr(const void *buf, int len);

#endif /* __PROTOCOL_H__ */