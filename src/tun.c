/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include "log.h"
#include "utils.h"
#include "tun.h"

#define VPN_TUN_DEVICE "/dev/net/tun"

/**
 * vpn_tun_init - Initialize a Linux TUN device with high-performance flags.
 * @ctx: Context structure to store the file descriptor and device name.
 * @dev_name: Desired interface name (e.g., "tun%d" for auto).
 * @multi_queue: Enable IFF_MULTI_QUEUE for parallel processing with io_uring.
 * @return Returns: 0 on success, negative error code on failure.
 */
int vpn_tun_init(vpn_tun_ctx_t *ctx, const char *dev_name, int multi_queue) {
    struct ifreq ifr;
    int fd = -1;
    int ret = 0;

    /* 1. Basic validation of input parameters */
    if (!ctx) {
        return -EINVAL;
    }

    /* 2. Open the TUN/TAP clone device */
    if ((fd = open(VPN_TUN_DEVICE, O_RDWR | O_CLOEXEC)) < 0) {
        ret = -errno;
        log_error("Failed to open %s: %s", VPN_TUN_DEVICE, strerror(errno));
        return ret;
    }

    /* 3. Prepare the interface request structure */
    memset(&ifr, 0, sizeof(ifr));
    
    /* IFF_TUN   : Packets are Layer 3 (IP).
     * IFF_NO_PI : Do not provide packet information header (saves 4 bytes/packet).
     */
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    /* Enable Multi-Queue to allow multiple FDs to attach to the same interface */
    if (multi_queue) {
        ifr.ifr_flags |= IFF_MULTI_QUEUE;
    }

    /* Set the interface name if provided, otherwise kernel picks one */
    if (dev_name && *dev_name) {
        if (strlen(dev_name) >= IFNAMSIZ) {
            log_error("Device name '%s' is too long", dev_name);
            ret = -ENAMETOOLONG;
            goto error_cleanup;
        }
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0'; // Ensure null-termination
    }

    /* 4. Register the device with the kernel via IOCTL */
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        ret = -errno;
        log_error("IOCTL TUNSETIFF failed for '%s': %s", ifr.ifr_name, strerror(errno));
        goto error_cleanup;
    }

    /* 5. Set Non-Blocking mode for io_uring compatibility */
    ret = vpn_set_nonblocking(fd);
    if (ret < 0) {
        log_error("Failed to set O_NONBLOCK on %s: %d", ifr.ifr_name, ret);
        goto error_cleanup;
    }

    /* 6. Populate context on success */
    ctx->fd = fd;
    strncpy(ctx->name, ifr.ifr_name, IFNAMSIZ - 1);
    ctx->name[IFNAMSIZ - 1] = '\0';

    log_info("Successfully initialized TUN device: %s (fd: %d)", ctx->name, ctx->fd);
    return 0;

error_cleanup:
    if (fd >= 0) {
        close(fd);
    }
    return ret;
}

/**
 * vpn_tun_set_status - Configure interface MTU and administrative state (UP/DOWN).
 * @dev_name: The name of the interface (e.g., "tun0").
 * @mtu: The Maximum Transmission Unit size. If <= 0, MTU is not changed.
 * @up: Boolean flag; 1 to bring the interface UP, 0 to bring it DOWN.
 *
 * @return Returns: 0 on success, or a negative error code (e.g., -errno).
 */
int vpn_tun_set_status(const char *dev_name, int mtu, int up) {
    int sock = -1;
    struct ifreq ifr;
    int ret = 0;

    if (!dev_name || strnlen(dev_name, IFNAMSIZ) >= IFNAMSIZ) {
        return -EINVAL;
    }

    /* Create a dummy UDP socket for ioctl operations.
     * SOCK_CLOEXEC ensures the socket is not inherited by child processes. 
     */
    sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        log_error("Failed to create control socket: %s", strerror(errno));
        return -errno;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);

    /* 1. Set MTU if specified */
    if (mtu > 0) {
        ifr.ifr_mtu = mtu;
        if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
            ret = -errno;
            log_error("Failed to set MTU %d for %s: %s", mtu, dev_name, strerror(errno));
            goto cleanup;
        }
    }

    /* 2. Retrieve current interface flags */
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        ret = -errno;
        log_error("Failed to get flags for %s: %s", dev_name, strerror(errno));
        goto cleanup;
    }

    /* 3. Modify administrative state flags */
    if (up) {
        /* IFF_UP: Administrative up. IFF_RUNNING: Resources are allocated. */
        ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    } else {
        ifr.ifr_flags &= ~IFF_UP;
    }

    /* 4. Apply the updated flags to the interface */
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        ret = -errno;
        log_error("Failed to set flags (up=%d) for %s: %s", up, dev_name, strerror(errno));
        goto cleanup;
    }

cleanup:
    if (sock >= 0) {
        close(sock);
    }
    return ret;
}

/**
 * vpn_tun_set_ip - Assign an IPv4 address and netmask to the TUN interface.
 * @dev_name: The name of the interface (e.g., "tun0").
 * @ip_addr:  IPv4 address string (e.g., "10.0.0.1").
 * @netmask:  IPv4 netmask string (e.g., "255.255.255.0").
 *
 * @return Returns: 0 on success, or a negative error code.
 */
int vpn_tun_set_ip(const char *dev_name, const char *ip_addr, const char *netmask) {
    int sock = -1;
    struct ifreq ifr;
    struct sockaddr_in addr;
    int ret = 0;

    if (!dev_name || !ip_addr || strnlen(dev_name, IFNAMSIZ) >= IFNAMSIZ) {
        return -EINVAL;
    }

    sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        log_error("CRITICAL: Failed to create control socket (errno: %d)", errno);
        return -errno;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;

    // 1. Set IP
    if (inet_pton(AF_INET, ip_addr, &addr.sin_addr) <= 0) {
        log_error("Config Error: Invalid IP format '%s'", ip_addr);
        ret = -EINVAL;
        goto cleanup;
    }
    memcpy(&ifr.ifr_addr, &addr, sizeof(struct sockaddr));
    
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        ret = -errno;
        log_error("Kernel Error: SIOCSIFADDR failed for %s: %s", dev_name, strerror(errno));
        goto cleanup;
    }

    // 2. Set Netmask
    if (netmask) {
        if (inet_pton(AF_INET, netmask, &addr.sin_addr) <= 0) {
            log_error("Config Error: Invalid Netmask format '%s'", netmask);
            ret = -EINVAL;
            goto cleanup;
        }
        memcpy(&ifr.ifr_netmask, &addr, sizeof(struct sockaddr));
        
        if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
            ret = -errno;
            log_error("Kernel Error: SIOCSIFNETMASK failed for %s: %s", dev_name, strerror(errno));
            goto cleanup;
        }
    }

    log_info("Interface %s configured: IP=%s Mask=%s", dev_name, ip_addr, netmask ? netmask : "default");

cleanup:
    if (sock >= 0) close(sock);
    return ret;
}

/**
 * vpn_tun_destroy - Close the TUN device and clear context.
 * @ctx: Pointer to the TUN context structure.
 *
 * Note: Closing the file descriptor normally triggers the kernel to 
 * destroy the virtual interface unless 'persist' mode was specifically enabled.
 */
void vpn_tun_destroy(vpn_tun_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->fd >= 0) {
        /* Closing the FD sends a signal to the kernel TUN driver to tear down 
         * the interface associated with this instance.
         */
        if (close(ctx->fd) < 0) {
            log_error("Error closing TUN fd %d: %s", ctx->fd, strerror(errno));
        }
        ctx->fd = -1;
    }

    /* Zero out the device name to prevent accidental reuse of a stale name */
    memset(ctx->name, 0, sizeof(ctx->name));
    
    log_info("TUN context destroyed and interface closed.");
}

/**
 * @brief Sets the MTU for a specific network interface.
 * @param dev_name Name of the device (e.g., "tun0").
 * @param mtu Desired MTU value.
 * @return 0 on success, -errno on failure.
 */
int vpn_tun_set_mtu(const char *dev_name, int mtu) {
    /* Parameter Validation: RFC 791 requires minimum IPv4 MTU of 68 */
    if (!dev_name || mtu < 68) {
        return -EINVAL;
    }

    /* Create a temporary control socket */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -errno;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    /* Safe string copy to prevent buffer overflow in interface name */
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    
    ifr.ifr_mtu = mtu;

    /* Execute the IOCTL to modify MTU */
    int result = 0;
    if (ioctl(sockfd, SIOCSIFMTU, &ifr) < 0) {
        result = -errno;
    }

    /* Clean up socket descriptor */
    close(sockfd);

    return result;
}