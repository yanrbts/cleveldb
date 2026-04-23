/*
 * Copyright (c) 2026-2026, CLI
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __CMD_H__
#define __CMD_H__

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <pthread.h>

#define C_DIM     "\001\033[2m\002"   
#define C_BOLD    "\001\033[1m\002"
#define C_GRAY    "\001\033[90m\002"
#define C_YELLOW  "\001\033[1;33m\002"
#define C_RESET   "\001\033[0m\002"
#define C_GREEN   "\001\033[92m\002"   /* "Running", "Active", "Normal" */
#define C_BLUE    "\001\033[94m\002"   /* "Info", "Processing", "System" */
#define C_MAGENTA "\001\033[95m\002"   /* "Config", "Settings", "Metadata" */
#define C_CYAN    "\001\033[96m\002"   /* "Metric", "Value", "Counter" */
#define C_RED     "\001\033[91m\002"   /* "Error", "Critical", "Stopped" */
#define C_ORANGE  "\001\033[38;5;208m\002" /* "Warning", "High Usage" */

#define AFUINX_MAGIC    0x56465354
#define MAX_ARG_COUNT   16
#define MAX_RESP_BUF    4096
#define AFUINX_VERSION  1
#define SOCKET_PATH     "/tmp/vfast.sock"

/* Standard Industrial Header */
typedef struct {
    uint32_t magic;
    uint16_t type;
    uint16_t version;
    uint32_t length;
} __attribute__((packed)) afuinx_header_t;

/**
 * @brief Response buffer wrapper to prevent overflows during string concatenation.
 */
typedef struct {
    char *buf;
    size_t size;
    size_t offset;
} cmd_resp_t;

/**
 * @brief Professional Handler Signature
 * @param ctx  User-defined context (e.g., global engine pointer)
 * @param argc Argument count
 * @param argv Argument vector
 * @param resp Safe response buffer object
 */
typedef int (*cmd_handler_t)(void *ctx, int argc, char **argv, cmd_resp_t *resp);

typedef struct {
    const char *group;
    const char *name;
    const char *help;
    const char *usage;
    int min_argc;
    cmd_handler_t handler;
} cmd_entry_t;

/**
 * @brief Initializes and binds an AF_UNIX stream socket for management listening.
 * This function handles the clean-up of existing socket files, creates the socket,
 * binds it to the specified path, and begins listening for incoming connections.
 * @param path   Filesystem path for the AF_UNIX socket.
 * @return int   The listening socket file descriptor on success, -1 on failure.
 */
int cmd_transport_listen(const char *path);

/**
 * @brief Connects to a remote management server via AF_UNIX socket.
 * @param path   Filesystem path to the server's socket.
 * @return int   The connected socket file descriptor on success, -1 on failure.
 */
int cmd_transport_connect(const char *path);

/**
 * @brief Receives a protocol-compliant packet from a peer.
 * Implements a robust reception logic that reads the fixed-size header first to
 * determine the payload size, then allocates memory for the body. Includes
 * timeout protection and buffer overflow guards.
 * @param fd       Connected socket descriptor.
 * @param hdr      Pointer to a header structure to be populated.
 * @param payload  Double pointer; will be assigned to a heap-allocated buffer. 
 * Caller is responsible for calling free().
 * @return int     0 on success, -1 on protocol error or connection drop.
 */
int cmd_transport_recv(int fd, afuinx_header_t *hdr, char **payload);

/**
 * @brief Encapsulates and transmits data using the VFast framing protocol.
 * Sends the header and payload as a single atomic-like logical unit. 
 * Uses MSG_NOSIGNAL to prevent process termination on broken pipes.
 * @param fd     Connected socket descriptor.
 * @param type   Protocol message type (e.g., Command vs. Response).
 * @param data   Pointer to the payload data.
 * @param len    Length of the payload in bytes.
 * @return int   0 on success, -1 on transmission failure.
 */
int cmd_transport_send(int fd, uint16_t type, const char *data, uint32_t len);

/**
 * @brief Dispatches a raw input string to the corresponding business handler.
 * Performs argument tokenization (Redis-style), command table lookup, 
 * argument count validation, and executes the associated callback function.
 * @param ctx      User-defined context (the engine object to be modified).
 * @param input    The raw null-terminated command string.
 * @param output   Pointer to the buffer where the response will be written.
 * @param max_len  Size of the output buffer.
 * @return int     Handler return code, or -1 if the command is unknown/malformed.
 */
int cmd_dispatch(void *ctx, char *input, char *output, size_t max_len);

/**
 * @brief Binds a static command registry to the framework's internal dispatcher.
 * @param table  Pointer to a NULL-terminated array of cmd_entry_t.
 */
void cmd_register_table(const cmd_entry_t *table);

/**
 * @brief Thread-safe formatted printing into the response context.
 * Appends formatted text to the internal response buffer while ensuring 
 * no memory overflow occurs beyond the buffer's capacity.
 * @param r      Pointer to the command response context.
 * @param fmt    Printf-style format string.
 * @param ...    Variable arguments.
 */
void cmd_resp_printf(cmd_resp_t *r, const char *fmt, ...);

/**
 * @brief Specialized response function for error messages (Red color).
 * This function wraps the formatted message with ANSI escape codes to 
 * produce red-colored output in compatible terminals. It ensures that the
 * color codes do not interfere with the buffer limits.
 * @param r      Pointer to the command response context.
 * @param fmt    Printf-style format string for the error message.
 * @param ...    Variable arguments.
 */
void cmd_resp_red(cmd_resp_t *r, const char *fmt, ...);

/**
 * @brief Specialized response function for success messages (Green color).
 * Similar to cmd_resp_red but uses green coloring to indicate positive status.
 * @param r      Pointer to the command response context.
 * @param fmt    Printf-style format string for the success message.
 * @param ...    Variable arguments.
 */
void cmd_resp_green(cmd_resp_t *r, const char *fmt, ...);

/**
 * @brief Specialized response function for informational messages (Cyan color).
 * Uses cyan coloring to differentiate informational output from errors and successes.
 * @param r      Pointer to the command response context.
 * @param fmt    Printf-style format string for the informational message.
 * @param ...    Variable arguments.
 */
void cmd_resp_cyan(cmd_resp_t *r, const char *fmt, ...);

/**
 * @brief Generates a formatted help message for a specific command group.
 * Filters the registered command table by the 'group' field. If group is NULL,
 * it displays top-level (root) commands.
 * @param group  Group name filter. NULL for root commands.
 * @param resp   Pointer to the response context.
 * @return int   0 on success, -1 on failure.
 */
int cmd_group_help(const char *group, cmd_resp_t *resp);

/**
 * @brief Standard handler for the 'HELP' command.
 * Supports both general help (HELP) and group-specific help (HELP <group>).
 */
int cmd_handle_help(void *ctx, int argc, char **argv, cmd_resp_t *resp);

/**
 * @brief Spawns a background management thread to handle CLI requests.
 * This is a "fire-and-forget" function. It allocates the necessary thread 
 * arguments on the heap, creates a detached pthread, and starts the 
 * socket accept loop.
 * @param user_ctx  Pointer to the main application's state/data structure.
 * @return pthread_t The created Thread ID on success, or 0 on failure.
 * @note: The caller is responsible for calling cmd_server_stop() 
 * with the returned thread ID to ensure proper cleanup.
 */
pthread_t cmd_server_start(void *user_ctx);

/**
 * @brief Gracefully terminates the CLI server thread.
 * @param ptid Pointer to the thread ID to be joined and reset.
 */
void cmd_server_stop(pthread_t *ptid);

#endif