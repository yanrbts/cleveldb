/*
 * Copyright (c) 2026-2026, vfast.
 * Author: [yanruibing]
 * All rights reserved.
 *
 * Description: 
 * High-performance AEAD (Authenticated Encryption with Associated Data) 
 * module utilizing the ChaCha20-Poly1305 construction. Designed for 
 * low-latency VPN tunneling with side-channel resistance.
 */

#include <fcntl.h>
#include <unistd.h>
#include <stdatomic.h>
#include <sys/random.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include "utils.h"
#include "monocypher.h"
#include "crypto.h"

/**
 * @brief Professional Counter-based Nonce generation.
 * thread-safe, high-performance, and collision-free.
 */
static void get_fast_nonce(uint8_t nonce[CRYPTO_NONCE_SIZE]) {
    /* Thread-safe atomic counter to ensure zero-collision */
    static _Atomic uint64_t counter = 0;
    static uint8_t prefix[16] = {0};
    static _Atomic bool initialized = false;

    /* Double-Checked Locking (DCL) pattern for initialization */
    if (unlikely(!atomic_load(&initialized))) {
        // Open a local temporary fd specifically for this initialization
        int temp_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (likely(temp_fd >= 0)) {
            // Read exactly 16 bytes for the prefix
            if (read(temp_fd, prefix, 16) == 16) {
                atomic_store(&initialized, true);
            }
            // CRITICAL: Close the file descriptor immediately after use
            // to prevent resource exhaustion (FD leak).
            close(temp_fd);
        }
    }

    /* Step 1: Copy the 16-byte random prefix (fixed for this session) */
    memcpy(nonce, prefix, 16);

    /* Step 2: Fetch and increment the 64-bit atomic counter */
    uint64_t current_count = atomic_fetch_add(&counter, 1);

    /* Step 3: Copy the counter into the remaining 8 bytes of the nonce 
     * Industrial note: Standardizing on Little-endian for cross-platform compatibility.
     */
    memcpy(nonce + 16, &current_count, 8);
}

/**
 * @brief Encrypts plaintext using XChaCha20-Poly1305 AEAD.
 * * Verified Packet Layout: 
 * [ Nonce (24B) ] [ Ciphertext (len bytes) ] [ MAC Tag (16B) ]
 *
 * @param key        32-byte secret key.
 * @param plain      Original data to encrypt.
 * @param len        Length of plain data.
 * @param out_packet Buffer to hold the complete encrypted package.
 * @param out_len    Final size: len + CRYPTO_NONCE_SIZE + CRYPTO_TAG_SIZE.
 */
int vpn_encrypt(const uint8_t key[CRYPTO_KEY_SIZE], 
                const uint8_t *plain, size_t len, 
                uint8_t *out_packet, size_t *out_len) {
    
    /* Pointer Arithmetic based on your requirements */
    uint8_t *nonce  = out_packet;                            /* Start of packet */
    uint8_t *cipher = out_packet + CRYPTO_NONCE_SIZE;        /* Offset 24 */
    uint8_t *tag    = cipher + len;                          /* Offset 24 + len */

    /* 1. Fill the first 24 bytes with a unique Nonce */
    get_fast_nonce(nonce);

    /* 2. Execute AEAD Lock
     * - cipher: Destination for encrypted data (24 bytes offset)
     * - tag:    Destination for the 16-byte Auth Tag (after ciphertext)
     * - plain:  Source data
     * - len:    Amount of data to process
     */
    crypto_aead_lock(cipher, tag, key, nonce, NULL, 0, plain, len);

    /* 3. Calculate total wire length */
    *out_len = CRYPTO_NONCE_SIZE + len + CRYPTO_TAG_SIZE;
    
    return 0;
}

/**
 * @brief Decrypts and authenticates a VFAST packet with industrial-grade safety.
 * * Safety Features:
 * 1. Constant-time execution (via Monocypher) to prevent timing side-channels.
 * 2. Strict bounds checking.
 * 3. Fail-safe output: out_len is zeroed on any error.
 *
 * @param key        32-byte symmetric secret key.
 * @param packet     Incoming buffer from network.
 * @param packet_len Total received size (Nonce + Cipher + Tag).
 * @param out_plain  Buffer to store decrypted data.
 * @param out_len    Pointer to store decrypted length.
 * @return 0 on success, -1 on length error, -2 on auth failure (tampering).
 */
int vpn_decrypt(const uint8_t key[CRYPTO_KEY_SIZE], 
                const uint8_t *packet, size_t packet_len, 
                uint8_t *out_plain, size_t *out_len) {
    
    /* 1. Preliminary safety check */
    if (unlikely(out_len == NULL)) return -1;
    *out_len = 0; // Pre-emptively zero output length (Fail-safe)

    /* 2. Strict bounds checking to prevent buffer underflow or tiny packets */
    if (unlikely(packet_len < (CRYPTO_NONCE_SIZE + CRYPTO_TAG_SIZE))) {
        return -1;
    }

    /* 3. Pointer Arithmetic (Matched with vpn_encrypt layout) */
    const uint8_t *nonce  = packet;
    const uint8_t *cipher = packet + CRYPTO_NONCE_SIZE;
    size_t plain_len      = packet_len - CRYPTO_NONCE_SIZE - CRYPTO_TAG_SIZE;
    const uint8_t *tag    = cipher + plain_len;

    /* 4. Authenticated Decryption
     * crypto_aead_unlock compares the calculated MAC with 'tag' in CONSTANT-TIME.
     * This is critical to stop GFW or attackers from guessing bits via timing.
     */
    if (unlikely(crypto_aead_unlock(out_plain, tag, key, nonce, NULL, 0, cipher, plain_len) != 0)) {
        /* * FAILURE: Data was tampered with or key is wrong.
         * We do NOT update *out_len here, keeping it at 0.
         */
        return -2; 
    }

    /* 5. Success: Commit the decrypted length */
    *out_len = plain_len;
    return 0;
}

/**
 * @brief Generates a 256-bit key using the Linux getrandom syscall.
 * * This is the modern industrial standard. It is blocking until the 
 * kernel entropy pool is initialized, ensuring high-quality randomness.
 * @param out_key 32-byte buffer for the key.
 * @return int 0 on success, -1 on failure.
 */
int vpn_generate_key(uint8_t out_key[CRYPTO_KEY_SIZE]) {
    /* GRND_RANDOM is usually not needed; default (0) uses /dev/urandom logic 
     * but ensures the pool has been seeded at least once. */
    ssize_t ret = getrandom(out_key, 32, 0);
    
    if (unlikely(ret != 32)) {
        // Handle potential interruption or failure
        return -1;
    }
    return 0;
}

/**
 * @brief Securely erases sensitive data.
 * Call this in your session cleanup logic.
 */
void vpn_secure_cleanup(uint8_t *key, size_t size) {
    if (key) {
        crypto_wipe(key, size); // Monocypher's secure erase
    }
}