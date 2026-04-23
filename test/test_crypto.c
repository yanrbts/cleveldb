/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 */
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include "crypto.h"

// 模拟 VPN 协议头长度
#define VPN_TNL_HLEN 8

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main() {
    printf("=== VFAST Crypto Module Test ===\n");

    // 1. 密钥生成测试
    uint8_t key[CRYPTO_KEY_SIZE];
    if (vf_generate_key(key) != 0) {
        printf("[FAIL] Key generation failed\n");
        return -1;
    }
    print_hex("Generated Key", key, CRYPTO_KEY_SIZE);

    // 2. 模拟原始数据 (IP Packet)
    const char *raw_data = "Hello, VFAST VPN! This is a secure packet.";
    size_t raw_len = strlen(raw_data) + 1; // 包含 \0
    
    // 3. 准备缓冲区 (模拟 io_uring 的 fixed buffer)
    // 布局: [Header(8B)] [Crypto_Data(Nonce + Cipher + Tag)]
    uint8_t buffer[2048];
    memset(buffer, 0, sizeof(buffer));
    
    // 填充模拟 Header (例如 Session ID = 0x12345678)
    buffer[0] = 0x12; buffer[1] = 0x34; buffer[2] = 0x56; buffer[3] = 0x78; 
    
    // 将明文复制到 Header 之后的位置，准备“原地加密”
    uint8_t *payload_ptr = buffer + VPN_TNL_HLEN;
    memcpy(payload_ptr, raw_data, raw_len);
    
    printf("\n[Step 1] Plaintext initialized at offset %d\n", VPN_TNL_HLEN);
    printf("Original Data: %s\n", (char *)payload_ptr);

    // 4. 加密测试 (原地加密)
    size_t encrypted_packet_len = 0;
    // 注意：输入是 payload_ptr，输出也是 payload_ptr (原地覆盖)
    int enc_ret = vf_encrypt(key, payload_ptr, raw_len, payload_ptr, &encrypted_packet_len);
    
    if (enc_ret != 0) {
        printf("[FAIL] Encryption failed with code: %d\n", enc_ret);
        return -1;
    }

    printf("\n[Step 2] Encryption Success\n");
    printf("Encrypted Packet Len: %zu (Expected: %zu)\n", 
            encrypted_packet_len, raw_len + CRYPTO_NONCE_SIZE + CRYPTO_TAG_SIZE);
    print_hex("Encrypted Data (Nonce+Cipher+Tag)", payload_ptr, encrypted_packet_len);

    // 5. 解密测试 (原地解密)
    uint8_t decrypted_data[1024];
    size_t decrypted_len = 0;
    
    // 模拟从网络收到数据后进行解密
    // 输入: payload_ptr (包含 Nonce+Cipher+Tag)
    // 输出: decrypted_data
    int dec_ret = vf_decrypt(key, payload_ptr, encrypted_packet_len, decrypted_data, &decrypted_len);

    if (dec_ret != 0) {
        printf("\n[FAIL] Decryption failed with code: %d\n", dec_ret);
        if (dec_ret == -2) printf("Reason: Authentication Failure (MAC Tag mismatch)\n");
        return -1;
    }

    printf("\n[Step 3] Decryption Success\n");
    printf("Decrypted Len: %zu\n", decrypted_len);
    printf("Decrypted Data: %s\n", (char *)decrypted_data);

    // 6. 验证数据一致性
    if (decrypted_len == raw_len && memcmp(raw_data, decrypted_data, raw_len) == 0) {
        printf("\n[RESULT] Integrity Check: PASSED\n");
    } else {
        printf("\n[RESULT] Integrity Check: FAILED\n");
        return -1;
    }

    // 7. 篡改测试 (验证安全认证)
    printf("\n[Step 4] Tamper Test (Modifying 1 byte of ciphertext...)\n");
    payload_ptr[CRYPTO_NONCE_SIZE + 1] ^= 0xFF; // 修改密文中的一个字节
    
    dec_ret = vf_decrypt(key, payload_ptr, encrypted_packet_len, decrypted_data, &decrypted_len);
    if (dec_ret == -2) {
        printf("[SUCCESS] Tamper detected! Decryption blocked.\n");
    } else {
        printf("[CRITICAL FAIL] Tamper NOT detected!\n");
        return -1;
    }

    vf_secure_cleanup(key, CRYPTO_KEY_SIZE);
    printf("\n=== All Tests Passed ===\n");
    return 0;
}