/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __ARRAY_H__
#define __ARRAY_H__

#include <stddef.h>
#include <stdint.h>

typedef struct ldb_array_s {
    uint64_t *items;
    size_t length;
    size_t alloc;
} ldb_array_t;

void ldb_array_init(ldb_array_t *z);
void ldb_array_clear(ldb_array_t *z);
void ldb_array_reset(ldb_array_t *z);
void ldb_array_grow(ldb_array_t *z, size_t zn);
void ldb_array_push(ldb_array_t *z, uint64_t x);
uint64_t ldb_array_pop(ldb_array_t *z);
uint64_t ldb_array_top(const ldb_array_t *z);
void ldb_array_resize(ldb_array_t *z, size_t zn);
void ldb_array_copy(ldb_array_t *z, const ldb_array_t *x);
void ldb_array_swap(ldb_array_t *x, ldb_array_t *y);
void ldb_array_sort(ldb_array_t *z, int (*cmp)(uint64_t, uint64_t));

#endif