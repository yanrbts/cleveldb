/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "zmalloc.h"

#define MALLOC_MIN_SIZE(x) ((x) > 0 ? (x) : sizeof(long))

static void zmalloc_default_oom(size_t size) {
    fprintf(stderr, "zmalloc: Out of memory trying to allocate %zu bytes\n", size);
    fflush(stderr);
    abort();
}

static void (*zmalloc_oom_handler)(size_t) = zmalloc_default_oom;

void *zmalloc(size_t size) {
    void *ptr = malloc(MALLOC_MIN_SIZE(size));
    if (!ptr) zmalloc_oom_handler(size);
    return ptr;
}

void *zcalloc(size_t size) {
    void *ptr = calloc(1, MALLOC_MIN_SIZE(size));
    if (!ptr) zmalloc_oom_handler(size);
    return ptr;
}

void *zrealloc(void *ptr, size_t size) {
    if (size == 0 && ptr != NULL) {
        free(ptr);
        return NULL;
    }
    if (ptr == NULL) return zmalloc(size);
    
    void *newptr = realloc(ptr, size);
    if (!newptr) zmalloc_oom_handler(size);
    return newptr;
}

void zfree(void *ptr) {
    if (ptr == NULL) return;
    free(ptr);
}

char *zstrdup(const char *s) {
    size_t l = strlen(s) + 1;
    char *p = zmalloc(l);
    memcpy(p, s, l);
    return p;
}

size_t zmalloc_used_memory(void) {
    return 0;
}

void zmalloc_set_oom_handler(void (*oom_handler)(size_t)) {
    zmalloc_oom_handler = oom_handler;
}