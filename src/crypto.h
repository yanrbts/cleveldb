/*
 * Copyright (c) 2026-2026, vfast.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>
#include <stddef.h>

#define CRYPTO_KEY_SIZE   32  // 256-bit key
#define CRYPTO_NONCE_SIZE 24  // XChaCha20 nonce size
#define CRYPTO_TAG_SIZE   16  // MAC tag size

/*：[Nonce (24B)] + [Ciphertext (NB)] + [Tag (16B)] */

/**
 * @brief Encrypts plaintext using XChaCha20-Poly1305 AEAD.
 * Packet Layout: [Nonce (24B)] [Ciphertext (NB)] [MAC Tag (16B)]
 * @param key The 32-byte symmetric secret key.
 * @param plain Input buffer containing raw data.
 * @param len Length of the plaintext.
 * @param out_packet Output buffer (Size must be >= len + 40 bytes).
 * @param out_len Pointer to store the resulting total packet size.
 * @return int 0 on success.
 */
int vf_encrypt(const uint8_t key[CRYPTO_KEY_SIZE], 
                const uint8_t *plain, size_t len, 
                uint8_t *out_packet, size_t *out_len);

/**
 * @brief Decrypts and authenticates a VFAST packet.
 * @param key The 32-byte symmetric secret key.
 * @param packet Incoming buffer from the network.
 * @param packet_len Total length of the received UDP payload.
 * @param out_plain Buffer to store the decrypted plaintext.
 * @param out_len Pointer to store the decrypted data length.
 * @return int 0 on success, -1 on invalid length, -2 on authentication failure.
 */
int vf_decrypt(const uint8_t key[CRYPTO_KEY_SIZE], 
                const uint8_t *packet, size_t packet_len, 
                uint8_t *out_plain, size_t *out_len);

/**
 * @brief Generates a 256-bit key using the Linux getrandom syscall.
 * This is the modern industrial standard. It is blocking until the 
 * kernel entropy pool is initialized, ensuring high-quality randomness.
 * @param out_key 32-byte buffer for the key.
 * @return int 0 on success, -1 on failure.
 */
int vf_generate_key(uint8_t out_key[CRYPTO_KEY_SIZE]);

/**
 * @brief Securely erases sensitive data.
 * Call this in your session cleanup logic.
 */
void vf_secure_cleanup(uint8_t *key, size_t size);

#endif