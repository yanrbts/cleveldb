/* common.h */
#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>

#define VFAST_HLEN 24          /* 协议头长度 */
#define VFAST_HEADROOM 64      /* 预留给协议头的起始偏移 */
#define SERVER_PORT 8888       /* 服务器 UDP 监听端口 */

/* 简单的自定义协议头 */
typedef struct {
    uint64_t session_id;
    uint32_t seq;
    uint16_t packet_len;       /* 原始 IP 包长度 */
    uint8_t  reserved[10];
} vfast_hdr_t;

/* TUN 辅助函数声明 */
int alloc_tun22(char *dev);
int tun_set_addr(const char *dev, const char *addr_str, const char *mask_str);

#endif