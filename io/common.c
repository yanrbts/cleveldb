#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <sys/socket.h>
#include <linux/if.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>

#include "common.h"

/**
 * @brief 分配并配置一个 TUN 虚拟网卡
 * @param dev 建议的设备名（如 "vfast0"），若传入空字符串或已存在同名设备，内核会自动分配
 * @return 成功返回文件描述符 fd，失败返回 -1
 */
int alloc_tun22(char *dev) {
    struct ifreq ifr;
    int fd, err;
    const char *clonedev = "/dev/net/tun";

    /* 1. 打开 TUN 字符设备 */
    if ((fd = open(clonedev, O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return fd;
    }

    /* 2. 配置 ifreq 结构体 */
    memset(&ifr, 0, sizeof(ifr));

    /* IFF_TUN: 创建一个点对点 IP 层设备（无以太网帧头）
     * IFF_NO_PI: 不包含额外的 Packet Information 头部（4字节），
     * 这让读写的数据直接就是原始 IP 包，方便我们处理。 */
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    /* 如果指定了设备名，则拷贝到结构体中 */
    if (dev && *dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    /* 3. 通过 ioctl 注册网卡 */
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    /* 4. 将内核实际分配的设备名写回 dev 指针（如果用户没指定，内核会生成 tun0, tun1 等） */
    if (dev) {
        strcpy(dev, ifr.ifr_name);
    }

    return fd;
}

/**
 * @brief 纯 C 代码设置网卡 IP 地址并激活 (UP)
 * @param dev 网卡名称 (如 "vfast_srv")
 * @param addr_str IP 地址字符串 (如 "10.0.0.1")
 * @param mask_str 子网掩码 (如 "255.255.255.0")
 * @return 0 成功, -1 失败
 */
int tun_set_addr(const char *dev, const char *addr_str, const char *mask_str) {
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in *sin;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    /* 1. 设置 IP 地址 */
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, addr_str, &sin->sin_addr);
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl SIOCSIFADDR");
        goto err;
    }

    /* 2. 设置子网掩码 */
    inet_pton(AF_INET, mask_str, &sin->sin_addr);
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCSIFNETMASK");
        goto err;
    }

    /* 3. 激活网卡 (UP & RUNNING) */
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) goto err;
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        goto err;
    }

    close(sockfd);
    return 0;

err:
    close(sockfd);
    return -1;
}