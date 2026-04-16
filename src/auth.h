/*
 * Copyright (c) 2026-2026, vfast.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __AUTH_H__
#define __AUTH_H__

#include <stdint.h>
#include <stdbool.h>

#define VFAST_MAGIC 0x54534146 /* "FAST" in Little-Endian */

/**
 * struct vfast_auth_t - Wire-format authentication and control payload.
 * @magic: Protocol identifier used to filter out malformed or alien packets.
 * @vip:   The internal virtual IP. 0 in client requests; assigned by server in responses.
 * @token: 128-bit pre-shared key or session token for identity verification.
 * @ts:    64-bit timestamp used for anti-replay protection and latency measurement.
 *
 * Note: This structure is marked as 'packed' to ensure identical memory 
 * layout across different architectures and compilers during network transmission.
 */
typedef struct {
    uint32_t magic;
    uint32_t vip;
    uint8_t  token[16];
    uint64_t ts;
    uint32_t key_id;
    uint8_t  init_key[32];
} __attribute__((packed)) vpn_auth_t;

/**
 * vfast_auth_pack - Serializes parameters into a wire-ready auth structure.
 * @param auth:  Pointer to the destination vpn_auth_t structure.
 * @param vip:   Virtual IP to be encoded.
 * @param token: Pointer to a 16-byte buffer containing the auth token.
 * @param key_id: The ID of the key to be used for authentication.
 * @param init_key: Pointer to a 32-byte buffer containing the initial key.
 * @param ts:    Timestamp. If 0, the function will use the current system time.
 *
 * This function guarantees a clean memory state by zero-initializing 
 * the structure before assignment, preventing sensitive data leakage.
 */
void vfast_auth_pack(vpn_auth_t *auth, uint32_t vip, const uint8_t *token, 
    uint32_t key_id, const uint8_t *init_key, uint64_t ts);

/**
 * vfast_auth_verify - Validates the integrity and authenticity of the payload.
 * @param auth:           The received auth structure to validate.
 * @param  expected_token: The reference token to compare against (16 bytes).
 *
 * Returns:
 * 0: Success.
 * -1: NULL pointer provided.
 * -2: Magic mismatch (Packet not belonging to VFAST protocol).
 * -3: Token mismatch (Unauthorized access or invalid credentials).
 */
int vfast_auth_verify(const vpn_auth_t *auth, const uint8_t *expected_token);

/**
 * vfast_auth_parse - Safe data extraction helper.
 * @param auth: Pointer to the validated vpn_auth_t structure.
 * @param vip:  Output pointer for the Virtual IP (optional, can be NULL).
 * @param ts:   Output pointer for the Timestamp (optional, can be NULL).
 *
 * Decouples field access from the logic, allowing for future changes in 
 * internal structure representation without breaking API consumers.
 */
void vfast_auth_parse(const vpn_auth_t *auth, uint32_t *vip, uint64_t *ts);

#endif /* __AUTH_H__ */