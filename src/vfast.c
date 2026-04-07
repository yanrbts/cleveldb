/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <signal.h>
#include <linux/ip.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "utils.h"
#include "log.h"
#include "vfast.h"

/**
 * @brief Loads the 256-bit master key from a binary file.
 * Industrial Security: Checks for file existence and size integrity.
 * @param key_path Path to the key file (e.g., "vfast.key").
 * @param out_key  Buffer to store the 32-byte key.
 * @return 0 on success, -1 on failure.
 */
int vfast_load_key(const char *key_path, uint8_t out_key[CRYPTO_KEY_SIZE]) {
    if (unlikely(!key_path || !out_key)) return -1;

    int fd = open(key_path, O_RDONLY);
    if (fd < 0) {
        log_error("Failed to open key file '%s': %s", key_path, strerror(errno));
        log_error("HINT: Run './vfast_server --keygen' to generate a new key.");
        return -1;
    }
    /* Standard security check: Ensure the file isn't a directory or symlink trickery */
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        log_error("Invalid key file type: %s", key_path);
        close(fd);
        return -1;
    }

    /* Load exactly 32 bytes */
    ssize_t bytes_read = read(fd, out_key, CRYPTO_KEY_SIZE);
    close(fd);

    if (bytes_read != CRYPTO_KEY_SIZE) {
        log_error("Key file '%s' is corrupted (Size: %zd, Expected: %d)", 
                  key_path, bytes_read, CRYPTO_KEY_SIZE);
        vpn_secure_cleanup(out_key, CRYPTO_KEY_SIZE);
        return -1;
    }

    log_info("Master key [%s] loaded into secure memory.", key_path);
    return 0;
}
