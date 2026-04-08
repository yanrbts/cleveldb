/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __VFAST_H__
#define __VFAST_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <net/if.h>
#include "io.h"
#include "ippool.h"
#include "crypto.h"

#define VFAST_VERSION       1
#define VFAST_BROADCAST     "255.255.255.0"

int vfast_load_key(const char *key_path, uint8_t out_key[CRYPTO_KEY_SIZE]);
void vfast_server_maintenance(vfast_io_t *io, void *data);

#endif