/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __EXTERN_H__
#define __EXTERN_H__

#ifdef LDB_EXPORT
#  if defined(__EMSCRIPTEN__)
#    include <emscripten.h>
#    define LDB_EXTERN EMSCRIPTEN_KEEPALIVE
#  elif defined(__wasm__)
#    define LDB_EXTERN __attribute__((visibility("default")))
#  elif defined(_WIN32)
#    define LDB_EXTERN __declspec(dllexport)
#  elif defined(__GNUC__) && __GNUC__ >= 4
#    define LDB_EXTERN __attribute__((visibility("default")))
#  endif
#endif

#ifndef LDB_EXTERN
#  define LDB_EXTERN
#endif

#endif /* LDB_EXTERN_H */