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
#include <time.h>
#include "log.h"
#include "zmalloc.h"
#include "utils.h"

int vpn_set_nonblocking(int fd) {
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
const char *vpn_get_absolute_path(char *filename) {
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
uint64_t vpn_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}