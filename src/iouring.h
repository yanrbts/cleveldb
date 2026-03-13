/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 * 
 * 方向 A: [内网 -> 外网] (Ingress)
       -----------------------------------------------------------
       [ TUN 设备 ]                                [ UDP 物理网卡 ]
            |                                            ^
            | (1) IO_TYPE_TUN_READ                       | (2) IO_TYPE_SOCK_WRITE
            v                                            |
      +----------+        转换 (Transition)         +------------+
      |  读完网卡 | ------------------------------> |  准备发给 UDP |
      +----------+                                  +------------+
            |                                            |
            + <----------- 重置 (Reset) <---------------- +
             (3) 重新挂载 TUN_READ，循环开始


       方向 B: [外网 -> 内网] (Egress)
       -----------------------------------------------------------
       [ TUN 设备 ]                                [ UDP 物理网卡 ]
            ^                                            |
            | (2) IO_TYPE_TUN_WRITE                      | (1) IO_TYPE_SOCK_READ
            |                                            v
      +----------+        转换 (Transition)         +------------+
      | 准备写回内核| <------------------------------ | 读完物理网络 |
      +----------+                                  +------------+
            |                                            |
            + -----------> 重置 (Reset) -----------> +
             (3) 重新挂载 SOCK_READ，循环开始
 */
#ifndef __IOURING_H__
#define __IOURING_H__

#include <liburing.h>
#include <stdint.h>
#include <netinet/in.h>

#define IO_RING_DEPTH       4096  /* Depth of the completion queue */
#define IO_MAX_BATCH_SIZE   32
#define IO_BUF_POOL_SIZE    1024  /* Total buffers in pool */
#define IO_BUF_SIZE         2048  /* Size of each buffer, aligned to 4KB */

/* Task types to identify the completion event */
typedef enum {
    IO_TYPE_TUN_READ,       // (读完网卡)  ──转换──>  IO_TYPE_SOCK_WRITE (准备发给 UDP)
    IO_TYPE_TUN_WRITE,      // (读完网络)  ──转换──>  IO_TYPE_TUN_WRITE (准备发给网卡)
    IO_TYPE_SOCK_READ,      // (发完了)   ──重置──>  IO_TYPE_TUN_READ (回到网卡继续等下一个包)
    IO_TYPE_SOCK_WRITE      // (写进去了)  ──重置──>  IO_TYPE_SOCK_READ (回到网络继续等下一个包)
} io_type_t;

/* Structure passed into SQE user_data to track async operations */
typedef struct {
    int fd;
    io_type_t type;
    uint32_t session_id; /* Used to find the client in your hash table */
    int buf_idx;         /* 新增：记录 Fixed Buffer 的索引，必须！ */
    size_t buf_len;

    struct {
        struct sockaddr_in client_addr; 
        struct iovec iov;               
        struct msghdr msg;              
    } udp_meta;
} vpn_io_data_t;

typedef struct {
    struct io_uring ring;
    struct iovec iovecs[IO_BUF_POOL_SIZE];  // Used for Fixed Buffers
    void *buffer_base;                      // Base pointer for memory alignment
    int pending_sqes;                       // Counter for batching
} vpn_iouring_ctx_t;

/* Function Prototypes */
int vpn_iouring_init(vpn_iouring_ctx_t *ctx, uint32_t entries);
void vpn_iouring_destroy(vpn_iouring_ctx_t *ctx);
/* Helper to submit a read request */
int vpn_iouring_submit_read(vpn_iouring_ctx_t *ctx, int fd, int buf_idx, vpn_io_data_t *io_data);
/* Helper to submit a write request */
int vpn_iouring_submit_write(vpn_iouring_ctx_t *ctx, int fd, int buf_idx, size_t len, vpn_io_data_t *io_data);
int vpn_iouring_submit_recvmsg(vpn_iouring_ctx_t *ctx, int fd, int buf_idx, vpn_io_data_t *io_data);
void vpn_iouring_flush(vpn_iouring_ctx_t *ctx);

#endif /* __IOURING_H__ */