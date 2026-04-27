/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdint.h>
#include <stdatomic.h>
#include <endian.h>
#include <stdint.h>

#define UNUSED(x)       (void)(x)
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htonll(x)       __builtin_bswap64(x)
#define ntohll(x)       __builtin_bswap64(x)
#else
#define htonll(x)       (x)
#define ntohll(x)       (x)
#endif

int vf_set_nonblocking(int fd);
const char *vf_get_absolute_path(char *filename);
uint64_t vf_now_ms(void);
int ip_pton(const char *ip_str, uint32_t *out_ip);
int ip_ntop(uint32_t ip_bin, char *out_str, size_t size);
uint32_t vf_get_next_sequence(atomic_uint_fast32_t *nextsq);

#endif