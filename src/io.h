/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */

#ifndef __IO_H__
#define __IO_H__

#include <liburing.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>

#define IO_BUF_COUNT     4096    /**< Buffer Ring 中的缓冲区数量 */
#define IO_BUF_SIZE      4096    /**< 单个缓冲区大小 (4KB，适配标准页大小) */
#define IO_RING_DEPTH    8192    /**< io_uring 提交/完成队列深度 */

#define IDX_UDP          0       /**< 注册文件集中的 UDP Socket 索引 */
#define IDX_TUN          1       /**< 注册文件集中的 TUN 设备索引 */
#define BR_GROUP_ID      0       /**< Provided Buffer Group ID */

/**
 * @brief 异步操作类型枚举
 * @details 用于在 io_uring 完成队列 (CQE) 中识别请求的上下文状态。
 */
typedef enum {
    OP_TYPE_UDP_RECV        = 1, /**< UDP Multishot 接收 */
    OP_TYPE_TUN_READ        = 2, /**< 从 TUN 设备异步读取 IP 包 */
    OP_TYPE_TUN_WRITE_ASYNC = 3, /**< 异步向 TUN 设备写入数据完成 */
    OP_TYPE_SEND_BACK       = 4  /**< 异步向 UDP 发送加密包完成 */
} op_type_t;

/* 前置声明，解决回调函数循环依赖 */
typedef struct vfast_vpn vfast_vpn_t;
typedef struct vfast_ioctx vfast_ioctx_t;

/**
 * @brief IO 上下文结构体
 * @details 每个 Buffer 对应一个上下文，管理该缓冲区当前的 IO 状态。
 */
struct vfast_ioctx {
    op_type_t           op;      /**< 当前正在进行的异步操作类型 */
    uint32_t            bid;     /**< Buffer ID (与 Buffer Ring 索引对应) */
    struct msghdr       msg;     /**< 用于 sendmsg/recvmsg 的消息头 */
    struct iovec        iov;     /**< 数据向量，指向关联的物理缓冲区 */
    struct sockaddr_in  addr;    /**< UDP 对端地址信息 (Src/Dst) */
    void               *priv;    /**< 业务自定义私有数据指针 (如 Session 信息) */
};

/**
 * @brief UDP 接收回调函数指针
 * @param vpn 引擎实例指针
 * @param data [in,out] 指向数据缓冲区的指针。业务层可修改此指针实现零拷贝剥离头部。
 * @param len 接收到的原始数据长度
 * @param ctx 关联的 IO 上下文
 * @return 处理后的有效数据长度。返回 <= 0 则丢弃该包并回收缓冲区。
 */
typedef int (*vfast_on_udp_recv_cb)(vfast_vpn_t *vpn, uint8_t **data, int len, vfast_ioctx_t *ctx);

/**
 * @brief TUN 读取回调函数指针
 * @param vpn 引擎实例指针
 * @param data [in,out] 指向数据缓冲区的指针。业务层可在此缓冲区前部预留空间添加协议头。
 * @param len 从 TUN 读到的原始包长度
 * @param ctx 关联的 IO 上下文
 * @return 处理后的总包长度 (包含协议头)。返回 <= 0 则丢弃该包。
 */
typedef int (*vfast_on_tun_read_cb)(vfast_vpn_t *vpn, uint8_t **data, int len, vfast_ioctx_t *ctx);

/**
 * @brief VFast VPN 核心引擎结构体
 */
struct vfast_vpn {
    struct io_uring      ring;     /**< io_uring 实例句柄 */
    struct io_uring_buf_ring *br;  /**< 注册的 Buffer Ring 指针 */
    void                *buf_base; /**< 缓冲区内存基地址 (4KB 对齐) */
    vfast_ioctx_t       *ctx_pool; /**< 上下文池，数组索引即为 bid */
    vfast_on_udp_recv_cb  on_udp_recv; /**< 解密、解压及协议头校验逻辑 */
    vfast_on_tun_read_cb  on_tun_read; /**< 路由查找、加解密及封包逻辑 */
};

/**
 * @brief 初始化 VPN 引擎
 * @param vpn 引擎指针
 * @param udp_fd 已经 bind 好的 UDP 套接字描述符
 * @param tun_fd 已经打开并配置好的 TUN 设备描述符
 * @return 0 成功，-1 失败 (可通过 errno 或 stderr 观察错误原因)
 */
int  vfast_vpn_init(vfast_vpn_t *vpn, int udp_fd, int tun_fd);

/**
 * @brief 运行引擎主循环
 * @details 该函数内部会阻塞运行，使用 io_uring_submit_and_wait 驱动事件。
 * @param vpn 引擎指针
 */
void vfast_vpn_run(vfast_vpn_t *vpn);

/**
 * @brief 销毁引擎并释放资源
 * @details 负责注销 Buffer Ring、关闭 io_uring 实例及释放池内存。
 * @param vpn 引擎指针
 */
void vfast_vpn_destroy(vfast_vpn_t *vpn);

#endif
