/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __ZMALLOC_H__
#define __ZMALLOC_H__

#include <stddef.h>

#if defined(_MSC_VER)
    #define __Z_MALLOC_ATTR 
    #define __Z_CALLOC_ATTR 
    #define __Z_REALLOC_ATTR 
    #define __Z_STRDUP_ATTR 
#elif defined(__GNUC__) || defined(__clang__)
    #define __Z_MALLOC_ATTR  __attribute__((malloc, alloc_size(1), noinline))
    #define __Z_CALLOC_ATTR  __attribute__((malloc, alloc_size(1), noinline))
    #define __Z_REALLOC_ATTR __attribute__((alloc_size(2), noinline))
    #define __Z_STRDUP_ATTR  __attribute__((malloc))
#else
    #define __Z_MALLOC_ATTR
    #define __Z_CALLOC_ATTR
    #define __Z_REALLOC_ATTR
    #define __Z_STRDUP_ATTR
#endif

__Z_MALLOC_ATTR  void *zmalloc(size_t size);
__Z_CALLOC_ATTR  void *zcalloc(size_t size);
__Z_REALLOC_ATTR void *zrealloc(void *ptr, size_t size);
__Z_STRDUP_ATTR char *zstrdup(const char *s);
void zfree(void *ptr);
void zmalloc_set_oom_handler(void (*oom_handler)(size_t));
size_t zmalloc_used_memory(void);

#endif /* __ZMALLOC_H__ */