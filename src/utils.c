/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "utils.h"

int vpn_set_nonblocking(int fd) {
    if (fd < 0) return -EINVAL;

    // 1. 获取当前的文件状态标志
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -errno;
    }

    // 2. 添加非阻塞标志位 O_NONBLOCK
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -errno;
    }

    return 0;
}