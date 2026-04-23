/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __TUN_H__
#define __TUN_H__

#include <stddef.h>
#include <linux/if_tun.h>

typedef struct {
    int fd;
    char name[IFNAMSIZ];
} __attribute__((aligned(8))) vpn_tun_ctx_t;

/**
 * @brief Initializes a TUN/TAP interface and opens the character device.
 * @details Handles the allocation of the virtual interface via /dev/net/tun.
 * @param[out] ctx         Pointer to the tunnel context to be initialized.
 * @param[in]  dev_name    Requested interface name (e.g., "tun%d" for auto).
 * @param[in]  multi_queue Boolean flag to enable multiqueue support (IFF_MULTI_QUEUE).
 * @return 0 on success, or a negative error code on failure.
 */
int vf_tun_init(vpn_tun_ctx_t *ctx, const char *dev_name, int multi_queue);

/**
 * @brief Releases resources associated with the tunnel context.
 * @details Closes all associated file descriptors and deallocates context memory.
 * @param[in] ctx Pointer to the tunnel context to destroy.
 */
void vf_tun_destroy(vpn_tun_ctx_t *ctx);

/**
 * @brief Configures the operational status and MTU of the interface.
 * @param[in] dev_name Interface name.
 * @param[in] mtu      Maximum Transmission Unit size.
 * @param[in] up       Status flag (1 to bring the interface UP, 0 for DOWN).
 * @return 0 on success, or a negative error code on failure.
 */
int vf_tun_set_status(const char *dev_name, int mtu, int up);

/**
 * @brief Assigns an IPv4 address and netmask to the virtual interface.
 * @details Typically implemented via SIOCSIFADDR and SIOCSIFNETMASK ioctls.
 * @param[in] dev_name Interface name.
 * @param[in] ip_addr  IPv4 address string (dotted decimal).
 * @param[in] netmask  Netmask string (dotted decimal).
 * @return 0 on success, or a negative error code on failure.
 */
int vf_tun_set_ip(const char *dev_name, const char *ip_addr, const char *netmask);

/**
 * @brief Sets the Maximum Transmission Unit (MTU) for a named network interface.
 * @param[in] dev_name Name of the interface (e.g., "tun0").
 * @param[in] mtu      Desired MTU value (e.g., 1500).
 * @return 0 on success, or -errno on failure.
 */
int vf_tun_set_mtu_by_name(const char *dev_name, int mtu);

/**
 * @brief Sets the MTU for an interface using its open file descriptor.
 * @details More efficient than name-based lookup if the FD is already held.
 * @param[in] tun_fd Open file descriptor of the TUN device.
 * @param[in] mtu    Desired MTU value.
 * @return 0 on success, or a negative error code on failure.
 */
int vf_tun_set_mtu_by_fd(int tun_fd, int mtu);

/**
 * @brief Disables IPv6 processing for the specific virtual interface.
 * @details Prevents the kernel from automatically assigning link-local 
 * addresses or responding to RAs on the tunnel, reducing noise.
 * @param[in] dev_name Interface name.
 */
void vf_tun_disable_ipv6(const char *dev_name);

#endif