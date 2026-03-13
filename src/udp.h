/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __UDP_H__
#define __UDP_H__

#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <net/if.h>       // For struct ifreq, SIOCGIFINDEX, IFNAMSIZ

/**
 * @brief Maximum theoretical size of a UDP datagram (including headers).
 * Useful for allocating receive buffers that can handle jumbo frames or 
 * large fragmented IP packets.
 */
#define UDP_MAX_PKT_SIZE 65535

/**
 * @struct udp_conn_t
 * @brief Simple handle for a UDP socket connection.
 */
typedef struct {
    int fd;                 /* Socket file descriptor */
    uint16_t port;          /* Bound port number */
    int current_timeout;
} udp_conn_t;

typedef struct {
    int sockfd;
    int if_index;
    char if_name[IFNAMSIZ];
} raw_sock_t;

/**
 * @brief Initializes a UDP socket as a listener on a specific port.
 * * This function creates a socket, binds it to all available interfaces, 
 * and configures the kernel receive buffer. Increasing the receive buffer 
 * is critical for high-throughput isolation gateways to prevent packet drops.
 *
 * @param port        The local port to listen on.
 * @param recv_buf_mb Desired kernel receive buffer size in Megabytes (MB).
 * @return udp_conn_t* Pointer to the initialized connection handle, or NULL on failure.
 */
udp_conn_t* udp_init_listener(uint16_t port, int recv_buf_mb);

/**
 * @brief Sends a raw binary payload to a specific destination.
 * @param conn     The socket handle descriptor.
 * @param dst_ip   Destination IPv4 address string (e.g., "192.168.1.1").
 * @param dst_port Destination UDP port (Host Order).
 * @param data     Pointer to the binary data buffer to transmit.
 * @param len      Size of the data in bytes.
 * @return ssize_t Number of bytes sent on success, or -1 on error.
 */
ssize_t udp_send_raw(udp_conn_t *conn, const char *dst_ip, uint16_t dst_port, const void *data, size_t len);

/**
 * @brief Receives binary data with an optional timeout.
 * * This function wraps recvfrom with a socket timeout (SO_RCVTIMEO). 
 * For large datagrams (e.g., > 20KB), ensure the buffer provided is large enough 
 * to prevent truncation.
 *
 * @param conn         The socket handle descriptor.
 * @param buf          Buffer to store the received data.
 * @param buf_size     Size of the provided buffer.
 * @param client_addr  Output: Structure populated with sender's address details.
 * @param timeout_ms   Wait timeout in milliseconds (0 for infinite blocking).
 * @return ssize_t     Number of bytes received, 0 on timeout, or -1 on error.
 */
ssize_t udp_recv_raw(udp_conn_t *conn, void *buf, size_t buf_size, struct sockaddr_in *client_addr, int timeout_ms);

/**
 * @brief Closes the socket and releases the connection handle memory.
 * @param conn Pointer to the udp_conn_t handle to be destroyed.
 */
void udp_close(udp_conn_t *conn);

/**
 * @brief Enable or disable broadcast capability on a UDP socket.
 * @param conn Pointer to the initialized udp_conn_t handle.
 * @param enable 1 to enable, 0 to disable.
 * @return 0 on success, -1 on failure.
 */
int udp_set_broadcast(udp_conn_t *conn, int enable);

/**
 * @brief Establishes a default remote address for the UDP socket.
 * * This allows the use of send() and recv() instead of sendto() and recvfrom().
 *
 * @param conn     The socket handle descriptor.
 * @param dst_ip_n   Destination IPv4 address in network byte order (e.g., 0xC0A80101 for 192.168.1.1).
 * @param dst_port Destination UDP port (Host Order).
 * @return 0 on success, -1 on failure.
 * @warning This modifies the socket state; use with caution in multi-destination scenarios.
 */
int udp_set_connect(udp_conn_t *conn, uint32_t dst_ip_n, uint16_t dst_port);

/**
 * @brief Resets the UDP socket connection to an unconnected state.
 * * This reverts the socket back to using sendto() and recvfrom().
 *
 * @param conn The socket handle descriptor.
 * @return 0 on success, -1 on failure.
 */
int udp_reset_connect(udp_conn_t *conn);

/**
 * @brief Initializes a Link-Layer Raw Socket (AF_PACKET).
 * Creates a raw socket bound to a specific network interface. This allows
 * sending and receiving packets at the Ethernet layer.
 *
 * @param if_name Name of the network interface (e.g., "eth0", "wwan0").
 * @return raw_sock_t* Pointer to the socket handle on success, NULL on failure.
 */
raw_sock_t *raw_sock_open(const char *if_name);

/**
 * @brief Generic Link-Layer Raw Data Transmission Interface.
 * Sends a raw buffer directly to the network interface. The data must
 * typically include the Ethernet header.
 *
 * @param ctx Pointer to the initialized raw_sock_t handle.
 * @param dst_mac Destination MAC address (6 bytes). If NULL, the first 6 bytes 
 * of 'data' are used as the destination address.
 * @param data Buffer containing the raw binary stream (including Ethernet header).
 * @param data_len Total length of the data to be sent.
 * @return ssize_t Number of bytes sent on success, -1 on failure.
 */
ssize_t raw_sock_send(raw_sock_t *ctx, const uint8_t *dst_mac, const void *data, size_t data_len);

/**
 * @brief Closes the Raw Socket and releases allocated resources.
 * @param ctx Pointer to the raw_sock_t handle to be closed.
 */
void raw_sock_close(raw_sock_t *ctx);

#endif