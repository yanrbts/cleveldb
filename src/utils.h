/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __UTILS_H__
#define __UTILS_H__

#define UNUSED(x)       (void)(x)
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

int vpn_set_nonblocking(int fd);

#endif