/*
 * Copyright (c) 2026-2026, CLI
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __CMD_ENGINE_H__
#define __CMD_ENGINE_H__

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>

/**
 * @brief Initializes the command table and launches the management server thread.
 * @return pthread_t The thread ID of the management server on success, 
 * or 0 if the table registration or thread creation fails.
 */
pthread_t cmd_start_core(void);

/**
 * @brief Checks if xdp raw packet logging is currently enabled.
 * @return true if logging is enabled, false otherwise.
 */
bool cmd_islogpkt_enabled(void);

/**
 * @brief Checks if debug mode is currently enabled.
 * @return true if debug mode is enabled, false otherwise.
 */
bool cmd_isdebug_enabled(void);

/**
 * @brief Increments the reassembly statistics counters in a thread-safe manner.
 * This function can be called from the XDP packet parser to update the engine's
 * internal metrics related to IP fragment reassembly.
 * @param rx_pkts Number of successfully reassembled datagrams to add.
 * @param tx_pkts Number of reassembly attempts that timed out to add.
 * @param drops Number of reassembly errors to add.
 */
void cmd_reass_stats_add(int rx_pkts, int tx_pkts, int drops);

/**
 * @brief Sets the task pool configuration for pre-allocated buffers.
 * This allows the management plane to inform the data plane about how many
 * buffers are available for different types of tasks, which can help with
 * load management and backpressure signaling.
 * @param total Total number of pre-allocated task buffers.
 * @param count Number of currently allocated task buffers.
 * @param r_tun Number of buffers allocated for reading from the TUN interface.
 * @param r_udp Number of buffers allocated for reading from the UDP socket.
 * @param w_tun Number of buffers allocated for writing to the TUN interface.
 * @param w_udp Number of buffers allocated for writing to the UDP socket.
 */
void cmd_task_pool_set(int total, int count, int r_tun, int r_udp, int w_tun, int w_udp);

#endif