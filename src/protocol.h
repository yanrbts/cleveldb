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
#include "log.h"
#include "key.h"
#include "io.h"
#include "utils.h"
#include "error.h"

/* Protocol Constants */
#define VPN_VERSION             1
#define VPN_HDR_FLAG_PADDING    0x01
#define VF_MAGIC                0x5646 /* "VF" in Little-Endian */
#define VF_RTT_THRESHOLD_MS     200
#define VF_DEFAULT_CAPS         0x0001

typedef enum {
    /* 0xx: Success */
    VF_S_OK         = 0,   /* Success: Proceed to AUTH */
    /* 1xx: Client-Side Errors (Requests) */
    VF_S_VER_ERR    = 101, /* Version mismatch: Upgrade client */
    VF_S_CAP_ERR    = 102, /* Unsupported capabilities */
    VF_S_COOKIE_ERR = 103, /* Invalid or expired cookie */
    /* 2xx: Server-Side Errors (Resources) */
    VF_S_BUSY       = 201, /* Server busy: Resource exhausted */
    VF_S_MAINT      = 202, /* Server maintenance in progress */
    VF_S_DENY       = 203, /* Policy denied: Access restricted */
    /* 3xx: System Failures */
    VF_S_SYS_ERR    = 301  /* Internal server error */
} vf_status_t;

/* Message Types */
typedef enum {
    VPN_MSG_DATA       = 0x01,
    VPN_MSG_HELLO      = 0x02,
    VPN_MSG_KEEPALIVE  = 0x03,
    VPN_MSG_DISCONNECT = 0x04,
    VPN_DPD_REQUEST    = 0x05,  /* Dead Peer Detection Request */
    VPN_DPD_RESPONSE   = 0x06,  /* Dead Peer Detection Response */
    VPN_MSG_REKEY_REQ  = 0x07,  /* Triggered by vf_rekey_needed */
    VPN_MSG_REKEY_ACK  = 0x08,  /* Confirmation to call vf_rekey_commit */
    VPN_MSG_AUTH_REQ   = 0x09, 
    VPN_MSG_AUTH_ACK   = 0x0A,
    VPN_MSG_LOGOUT     = 0x0B
} vf_msg_t;

/* Packed Structure for Network Transmission
 * Total size: 8 bytes (64-bit aligned for optimal CPU access)
 */
typedef struct {
    uint16_t magic;
    uint8_t  version;      /* Protocol version */
    uint8_t  msg_type;     /* Message type from vfast_msg_t */

    uint16_t total_len;    /* Length of Header + Payload + Padding */
    uint8_t  key_id;       /* Key ID for encryption (0 for HELLO, n for active session key) */
    uint8_t  flags;        /* Reserved for future flags (e.g. compression, encryption type) */
    uint32_t session_id;   /* Unique session identifier (Network Byte Order) */
    uint32_t seq_num;

    uint8_t  padding_len;  /* Length of padding bytes */
    uint8_t  reserved[3];  /* keep 4-byte alignment */
} __attribute__((packed)) vf_hdr_t;

#define VPN_TNL_HLEN sizeof(vf_hdr_t)

/**
 * Hello Request Payload (Client -> Server)
 * Total Size: 24 Bytes (8-byte aligned)
 */
typedef struct {
    uint64_t timestamp;      /* 8 bytes: Client local time */
    uint8_t  random_pad[14]; /* 14 bytes: Padding to reach 24-byte boundary */
} __attribute__((packed)) vf_payload_hello_req_t;

/**
 * Hello Response Payload (Server -> Client)
 * Total Size: 32 Bytes (8-byte aligned)
 */
typedef struct {
    uint64_t server_ts;      /* 8 bytes: Server local time */
    uint32_t status;         /* 4 bytes: OK/Busy/Mismatch */
    uint16_t selected_caps;  /* 2 bytes: Final features */
    uint8_t  cookie[18];     /* 18 bytes: Cookie + Padding to 32-byte boundary */
} __attribute__((packed)) vf_payload_hello_resp_t;

/**
 * Auth Request Payload (Client -> Server)
 * Used with VF_MSG_AUTH_REQ.
 */
typedef struct {
    char     username[64];
    char     password[64];  /* Raw password or Hash */
    uint64_t timestamp;     /* Anti-replay & latency measurement */
    uint8_t  nonce[16];     /* Random bytes for session key derivation */
} __attribute__((packed)) vf_payload_auth_req_t;

/**
 * Auth Response Payload (Server -> Client)
 * Used with VF_MSG_AUTH_RESP.
 */
typedef struct {
    uint32_t status;        /* 0 for success, non-zero for error codes */
    uint32_t vip;           /* Virtual IP for TUN interface (Network Order) */
    uint8_t  token[16];     /* Session token for subsequent messages */
    uint32_t key_id;
    uint32_t keepalive_int;  /* 4 bytes: Heartbeat interval (Moved here to align) */
    uint8_t  init_key[32];   /* 32 bytes: Initial Session Key */
} __attribute__((packed)) vf_payload_auth_resp_t;

/**
 * Data Payload (Encapsulated IP Traffic)
 * Used with VF_MSG_DATA.
 * The payload follows the header directly.
 */
typedef struct {
    uint8_t  ip_version;    /* Hint: 4 for IPv4, 6 for IPv6 */
    uint8_t  protocol;      /* Original protocol (TCP/UDP/ICMP) */
    uint8_t  data[];        /* Raw IP packet starting from IP header */
} __attribute__((packed)) vf_payload_data_t;

/**
 * Heartbeat & DPD Payload
 * Used with VF_MSG_KEEPALIVE, VF_MSG_DPD_REQ/RESP.
 */
typedef struct {
    uint64_t echo_id;       /* Random ID to match REQ and RESP */
    uint64_t timestamp;     /* RTT calculation */
} __attribute__((packed)) vf_payload_echo_t;

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
int vf_pack(const vfast_sec_ctx_t *sec, uint8_t *buf, int payload_len, int max_buf_size, vf_msg_t type, uint32_t sid);

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
uint8_t* vf_unpack(const vfast_sec_ctx_t *sec, uint8_t *buf, int received_len, int *out_ip_len);

/**
 * @brief Safely fills the VPN tunnel header with boundary checks.
 * @param buf      Pointer to the message buffer.
 * @param buf_sz   The actual allocated size of buf (for safety check).
 * @param total_sz The logical total length of the packet (Header + Payload).
 * @param type     Message type (vf_msg_t).
 * @param sid      Session ID.
 * @param kid      Key ID.
 * @return int     VF_OK (0) on success, VF_ERR_INVALID_PARAM (-6) on overflow.
 */
static inline int vf_fill_header(void *buf, uint64_t total_sz, 
                                 uint8_t type, uint32_t sid, uint32_t kid) {
    /* 1. Boundary Check: Ensure buffer can at least hold the header */
    if (unlikely(!buf)) {
        return VF_ERR_INVALID_PARAM;
    }

    /* 2. Range Check: total_sz must fit into uint16_t total_len field */
    if (unlikely(total_sz > BUF_SIZE)) {
        log_error("Packet too large: %lu bytes", total_sz);
        return VF_ERR_INVALID_PARAM;
    }

    vf_hdr_t *hdr = (vf_hdr_t *)buf;

    /* 3. Fill Fields with Network Byte Order */
    hdr->magic    = htons(VF_MAGIC); /* Using the optimized 16-bit magic */
    hdr->version  = VPN_VERSION;
    hdr->msg_type = type;
    hdr->total_len = htons((uint16_t)total_sz);

    hdr->key_id     = (uint8_t)(kid & 0xFF);
    hdr->flags      = 0;
    hdr->session_id = htonl(sid);
    
    /* 4. Sequence Number (Should be managed by a global/session counter) 
     * Note: In a real scenario, don't forget to increment this.
     */
    // hdr->seq_num = htonl(next_seq); 

    return VF_OK;
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
int vf_apply_padding(uint8_t *buf, int raw_len, uint8_t max_pad);

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
int vf_remove_padding(uint8_t *buf, size_t *p_len);

/**
 * @brief Obfuscates the tunnel header to prevent protocol fingerprinting.
 * Rationale: AEAD payloads are already high-entropy (random-looking). 
 * The vulnerability lies in the static header fields (SID, Version, Flags). 
 * This function masks the header using a rolling key derived from the 
 * Sequence Number, ensuring every packet header is unique.
 * @param buf      Pointer to the start of the VFAST packet (task->buf).
 * @param wire_len The total length of the packet to be transmitted.
 */
void vf_apply_header_obfs(uint8_t *buf, size_t wire_len);

/**
 * @brief Restores the tunnel header by reversing the XOR mask.
 * This MUST be the very first function called upon receiving a UDP packet.
 * It restores the SessionID and other metadata so the server can identify 
 * the user and retrieve the correct decryption keys.
 * @param buf      Pointer to the received raw UDP payload (task->buf).
 * @param wire_len Total bytes received from the socket.
 */
void vf_remove_header_obfs(uint8_t *buf, size_t wire_len);


void vpn_debug_print_hdr(const void *buf, int len);

#endif /* __PROTOCOL_H__ */