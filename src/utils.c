/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h> /* Essential for socket functions */
#include <net/if.h>     /* Essential for IFNAMSIZ and struct ifreq */
#include <arpa/inet.h>
#include <time.h>
#include "log.h"
#include "zmalloc.h"
#include "utils.h"

int vf_set_nonblocking(int fd) {
    if (fd < 0) return -EINVAL;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -errno;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -errno;
    }

    return 0;
}

/* Given the filename, return the absolute path as an SDS string, or NULL
 * if it fails for some reason. Note that "filename" may be an absolute path
 * already, this will be detected and handled correctly.
 *
 * The function does not try to normalize everything, but only the obvious
 * case of one or more "../" appearning at the start of "filename"
 * relative path. */
const char *vf_get_absolute_path(char *filename) {
    char *ptr = NULL;
    char absolute_path[PATH_MAX];
    struct stat st;

    if (stat(filename, &st) != 0) {
        log_error("Error resolving file information");
        return NULL;
    }

    if (!S_ISREG(st.st_mode)) {
        log_info("%s is neither a regular file nor a directory.", filename);
        return NULL;
    }

    if (realpath(filename, absolute_path) != NULL) {
        ptr = zstrdup(absolute_path);
        return ptr;
    } else {
        log_error("Error resolving absolute path");
        return NULL;
    }
}

/* Internal helper to get monotonic time in milliseconds */
uint64_t vf_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

int ip_pton(const char *ip_str, uint32_t *out_ip) {
    if (!ip_str || !out_ip) return -1;
    
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        return -1;
    }
    
    *out_ip = addr.s_addr;
    return 0;
}

int ip_ntop(uint32_t ip_bin, char *out_str, size_t size) {
    if (!out_str || size < INET_ADDRSTRLEN) return -1;

    struct in_addr addr;
    addr.s_addr = ip_bin;

    if (inet_ntop(AF_INET, &addr, out_str, size) == NULL) {
        return -1;
    }

    return 0;
}

/**
 * @brief Thread-safe sequence generator.
 * Optimized for high-concurrency IO workers.
 */
uint32_t vf_get_next_sequence(atomic_uint_fast32_t *nextsq) {
    if (unlikely(!nextsq)) return 0;

    /**
     * atomic_fetch_add is a CPU-level atomic instruction (e.g., LOCK XADD on x86).
     * memory_order_relaxed:
     * We only care about the atomicity of the counter itself. 
     * Since this seq_num doesn't act as a memory barrier for other data 
     * structures, relaxed ordering offers the best performance by avoiding 
     * unnecessary CPU cache flushes.
     */
    uint32_t seq = atomic_fetch_add_explicit(nextsq, 1, memory_order_relaxed);
    
    /* Ensure big-endian format for wire transmission */
    return htonl(seq);
}