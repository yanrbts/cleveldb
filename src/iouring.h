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
#define IO_BUF_POOL_SIZE    16  /* Total buffers in pool */
#define IO_BUF_SIZE         2048  /* Size of each buffer, aligned to 4KB */

/* Task types to identify the completion event */
typedef enum {
    IO_TYPE_TUN_READ,       // (读完网卡)  ──转换──>  IO_TYPE_SOCK_WRITE (准备发给 UDP)
    IO_TYPE_TUN_WRITE,      // (读完网络)  ──转换──>  IO_TYPE_TUN_WRITE (准备发给网卡)
    IO_TYPE_SOCK_READ,      // (发完了)   ──重置──>  IO_TYPE_TUN_READ (回到网卡继续等下一个包)
    IO_TYPE_SOCK_WRITE,      // (写进去了)  ──重置──>  IO_TYPE_SOCK_READ (回到网络继续等下一个包)
} io_type_t;

typedef enum {
    SOURCE_TUN = 0,
    SOURCE_UDP = 1
} io_source_t;

/* Structure passed into SQE user_data to track async operations */
typedef struct {
    int fd;
    io_type_t type;
    io_source_t source;  /* 职责来源：活干完了该回 TUN 还是 UDP */
    uint32_t sid;        /* Used to find the client in your hash table */
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

int vpn_iouring_init(vpn_iouring_ctx_t *ctx, uint32_t entries);
void vpn_iouring_destroy(vpn_iouring_ctx_t *ctx);
void vpn_iouring_flush(vpn_iouring_ctx_t *ctx);

/**
 * @brief Submits an asynchronous UDP receive request using the io_uring engine.
 *
 * This function prepares a recvmsg SQE (Submission Queue Entry) to capture incoming 
 * UDP datagrams. It leverages the pre-registered fixed buffer pool to achieve 
 * zero-copy data transfer from the kernel to the user-space VPN engine.
 *
 * @param ctx      Pointer to the initialized vpn_iouring_ctx_t context.
 * @param fd       The UDP socket file descriptor (typically the physical interface).
 * @param buf_idx  Index of the fixed buffer allocated from the pool for this operation.
 * @param io_data  Pointer to the state tracking structure. 
 * Must have `buf_idx` and `type` (IO_TYPE_SOCK_READ) initialized.
 *
 * @return 0 on successful submission, -EBUSY if the SQ is full and cannot be flushed.
 *
 * @note [Industrial Logic]
 * 1. ZERO-COPY: Uses ctx->iovecs[buf_idx] as the destination, bypassing standard copy_to_user.
 * 2. PEER-DISCOVERY: Automatically populates io_data->udp_meta.client_addr with the 
 * sender's IP/Port, which is essential for dynamic session mapping and Direction B routing.
 * 3. BATCHING: Increments ctx->pending_sqes and performs an automatic io_uring_submit() 
 * if the IO_MAX_BATCH_SIZE threshold is reached to optimize syscall frequency.
 * 4. BUFFER ALIGNMENT: The datagram is stored starting at the absolute base of the 
 * fixed buffer, as the VFAST header is part of the incoming wire data.
 */
int vpn_submit_udp_recvmsg(vpn_iouring_ctx_t *ctx, int fd, int buf_idx, vpn_io_data_t *io_data);

/**
 * @brief Submits a zero-copy sendmsg request for UDP transmission.
 * This function prepares a sendmsg SQE to transmit encapsulated packets to the client.
 * It uses the fixed buffer pool for zero-copy transmission and allows per-packet
 * destination specification via msghdr.
 * @param ctx      Pointer to the initialized vpn_iouring_ctx_t context.
 * @param fd       The UDP socket file descriptor (physical interface).
 * @param buf_idx  Index of the fixed buffer containing the data to send.
 * @param len      The length of the data to send (must be <= IO_BUF_SIZE).
 * @param io_data  Pointer to the state tracking structure. Must have `buf_idx` and `type` (IO_TYPE_SOCK_WRITE) initialized, 
 * and `udp_meta.client_addr` populated with the destination address.
 * @return 0 on success, -EBUSY if the SQ is full and cannot be flushed, or -EMSGSIZE if the length exceeds the buffer size.
 * @note [Industrial Logic]
 * 1. ZERO-COPY: Directly uses the fixed buffer registered in ctx->iovecs[buf_idx] for transmission, eliminating extra copy overhead.
 * 2. PER-PACKET DESTINATION: Configures the msghdr structure to specify the client's address for each packet, which is crucial 
 * for a UDP-based VPN where the server socket is not connected to a single client.
 */
int vpn_submit_udp_sendmsg(vpn_iouring_ctx_t *ctx, int fd, int buf_idx, size_t len, vpn_io_data_t *io_data);

int vpn_submit_udp_send(vpn_iouring_ctx_t *ctx, int fd, int buf_idx, size_t len, vpn_io_data_t *io_data);

/**
 * @brief Submits a zero-copy read request to the TUN device.
 * @param ctx The io_uring context.
 * @param tun_fd File descriptor of the TUN device.
 * @param buf_idx Index of the pre-registered fixed buffer.
 * @param d User data associated with this IO operation.
 * @return 0 on success, or negative error code.
 */
int vpn_submit_tun_read(vpn_iouring_ctx_t *ctx, int tun_fd, int buf_idx, vpn_io_data_t *d);
/**
 * vpn_submit_tun_write - Submits a TUN write request with automatic offset calculation.
 * @param ctx     : The io_uring context containing registered buffers.
 * @param tun_fd  : File descriptor for the TUN device.
 * @param buf_idx : The index of the pre-registered fixed buffer.
 * @param len     : The length of the inner IP packet (excluding the 8-byte VFAST header).
 * @param d       : User data for state tracking.
 * NOTE: This function automatically skips the VFAST header (VPN_TNL_HLEN).
 */
int vpn_submit_tun_write(vpn_iouring_ctx_t *ctx, int tun_fd, int buf_idx, vpn_io_data_t *d);

#endif /* __IOURING_H__ */