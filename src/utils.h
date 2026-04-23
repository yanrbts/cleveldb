/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdint.h>
#include <stdatomic.h>

#define UNUSED(x)       (void)(x)
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

int vf_set_nonblocking(int fd);
const char *vf_get_absolute_path(char *filename);
uint64_t vf_now_ms(void);
int ip_pton(const char *ip_str, uint32_t *out_ip);
int ip_ntop(uint32_t ip_bin, char *out_str, size_t size);
uint32_t vf_get_next_sequence(atomic_uint_fast32_t *nextsq);

#endif