/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <liburing.h>
#include <errno.h>
#include "iouring.h"

#define PORT 9999

/* Buffer index management */
static int free_stack[IO_BUF_POOL_SIZE];
static int top = -1;

void push_index(int idx) {
    if (top < IO_BUF_POOL_SIZE - 1) {
        free_stack[++top] = idx;
    }
}

int pop_index() {
    return (top >= 0) ? free_stack[top--] : -1;
}

int main() {
    vpn_iouring_ctx_t ctx;
    int ret;

    /* 1. Initialize io_uring with Fixed Buffers */
    if (vpn_iouring_init(&ctx, IO_RING_DEPTH) < 0) {
        fprintf(stderr, "Failed to init io_uring: %s\n", strerror(errno));
        return 1;
    }

    /* Initialize free index stack */
    for (int i = 0; i < IO_BUF_POOL_SIZE; i++) {
        push_index(i);
    }

    /* 2. Create UDP Socket */
    int sock_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    printf("Industrial Server (Fixed Buffers + Batching) listening on port %d...\n", PORT);

    /* 3. Pre-fill the ring with multiple Read tasks to maximize throughput */
    // Initial batch of reads (e.g., fill 1/4 of the pool)
    for (int i = 0; i < 256; i++) {
        int idx = pop_index();
        if (idx == -1) break;

        // Allocate tracking data (In production, use another mempool for this)
        vpn_io_data_t *io_data = malloc(sizeof(vpn_io_data_t));
        io_data->fd = sock_fd;
        io_data->type = IO_TYPE_SOCK_READ;
        io_data->buf_idx = idx; // Important: track which buffer we used

        vpn_iouring_submit_read(&ctx, sock_fd, idx, io_data);
    }
    vpn_iouring_flush(&ctx); // Ensure initial batch is submitted

    /* 4. Event Loop */
    while (1) {
        struct io_uring_cqe *cqe;
        
        /* Wait for events. For high throughput, we could use io_uring_wait_cqes 
           to wait for multiple events at once. */
        ret = io_uring_wait_cqe(&ctx.ring, &cqe);
        if (ret < 0) break;

        vpn_io_data_t *completed_data = (vpn_io_data_t *)io_uring_cqe_get_data(cqe);

        if (cqe->res < 0) {
            if (cqe->res != -EAGAIN) {
                fprintf(stderr, "Async Error: %s\n", strerror(-cqe->res));
            }
        } else if (cqe->res > 0) {
            /* Accessing the fixed buffer via index */
            char *ptr = (char *)ctx.iovecs[completed_data->buf_idx].iov_base;
            (void)ptr; // In production, you'd process the data here
            // Industrial tip: avoid printf in high-speed loops. Using it here for testing only.
            printf("Received %d bytes via Fixed Buffer [%d]\n", cqe->res, completed_data->buf_idx);

            /* RE-SUBMIT: Keep the pipeline full */
            // In a real VPN, you'd send this to TUN here.
            vpn_iouring_submit_read(&ctx, sock_fd, completed_data->buf_idx, completed_data);
        } else {
            // EOF or empty packet
            push_index(completed_data->buf_idx);
            free(completed_data);
        }

        io_uring_cqe_seen(&ctx.ring, cqe);
        
        /* Flush remaining batch if no new events are pending */
        vpn_iouring_flush(&ctx);
    }

    vpn_iouring_destroy(&ctx);
    return 0;
}