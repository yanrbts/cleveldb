/**
 * @file io.h
 * @brief High-performance Asynchronous Network Core based on io_uring.
 * This framework implements a proactive I/O model (Proactor) optimized for 
 * VPN and Tunneling services. It minimizes context switches through 
 * registered files and batched SQE submissions.
 * @author yanruibing
 * @date 2026-04-03
 */

#ifndef __IO_H__
#define __IO_H__

#include <liburing.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

#define BUF_SIZE        2048        /**< MTU-aligned buffer size (including overhead) */

/**
 * @brief Retrieves the parent vfast_task_t pointer from a buffer pointer.
 * @details Since 'buf' is a member of 'vfast_task_t', we subtract the offset 
 * of 'buf' from the current data pointer to get the structure's base address.
 */
#define vfast_data_to_task(d) \
    ((vfast_task_t *)((uint8_t *)(d) - offsetof(vfast_task_t, buf)))

struct vfast_io;
typedef struct vfast_io vfast_io_t;

/**
 * @brief Async state machine operation codes.
 */
enum {
    OP_TUN_READ  = 1,               /**< Async read from TUN device */
    OP_TUN_WRITE = 2,               /**< Async write to TUN device */
    OP_UDP_RECV  = 3,               /**< Async recvmsg from UDP socket */
    OP_UDP_SEND  = 4                /**< Async sendmsg to UDP socket */
};

/**
 * @brief Functional interface for business logic callbacks.
 * These are invoked upon successful completion of asynchronous read operations.
 */
typedef int (*on_data_cb)(vfast_io_t *io, uint8_t *buf, int len, struct sockaddr_in *addr, void *arg);
typedef void (*on_timer_cb)(vfast_io_t *io, void *arg);

/**
 * @brief Dispatch table for network event handling.
 */
typedef struct {
    on_data_cb on_udp_data;        /**< Triggered on UDP RX completion */
    on_data_cb on_tun_data;        /**< Triggered on TUN/TAP read completion */
    void *ctx;                    /**< User-defined context passed to callbacks */
} vfast_ops_t;

/**
 * @brief Per-operation context (Task) used for tracking async state.
 * This structure is mapped to the 'user_data' field in SQEs.
 * It encapsulates buffers and metadata to ensure zero-copy pathing 
 * within the event loop.
 */
typedef struct {
    int                 op;             /**< Operation type (OP_XXX) */
    uint8_t             buf[BUF_SIZE];  /**< Static packet buffer */
    struct iovec        iov;            /**< Vector for scatter/gather I/O */
    struct msghdr       msg;            /**< Header for recvmsg/sendmsg ops */
    struct sockaddr_in  addr;           /**< Source/Dest address storage */
    socklen_t           addr_len;       /**< Length of sockaddr */
    bool                in_use;         /**< Spin-lock style usage flag for pool safety */
} vfast_task_t;

/**
 * @brief The primary I/O context holding the io_uring instance and state.
 */
struct vfast_io {
    struct io_uring     ring;           /**< The core io_uring structure */
    int                 udp_fd;         /**< Bound UDP socket file descriptor */
    int                 tun_fd;         /**< TUN/TAP device file descriptor */
    vfast_ops_t         ops;            /**< Registered callback handlers */
    struct sockaddr_in  remote_addr;    /**< Pre-calculated remote peer address */
    bool                is_server;      /**< Operation mode (Server vs Client) */
    atomic_bool         running;

    vfast_task_t       *task_pool;
    atomic_int          pool_idx;
    int                 pool_size;

    on_timer_cb         timer_cb;           /**< Optional timer callback for periodic tasks */  
    void               *timer_arg;          /**< User-defined argument for timer callback */
    uint32_t            timer_interval_ms;  /**< Timer interval in milliseconds */
};

/**
 * @brief Initializes the vfast_io context and io_uring subsystem.
 * @return 0 on success, negative error code on failure.
 */
int vfast_io_init(vfast_io_t *io, int udp_fd, int tun_fd, int pool_size, vfast_ops_t ops);

/**
 * @brief Starts the infinite event loop (blocking).
 */
void vfast_io_run(vfast_io_t *io);

/**
 * @brief Gracefully terminates the I/O engine and releases resources.
 */
void vfast_io_exit(vfast_io_t *io);

/**
 * @brief Posts an asynchronous read or receive request to the Submission Queue (SQ).
 * Prepares a task from the pool and submits a read/recvmsg operation. The actual 
 * data processing occurs in the registered callbacks within @ref vfast_ops_t.
 *
 * @param io    Pointer to the initialized vfast_io_t context.
 * @param fd    The raw file descriptor (UDP or TUN).
 * @param op    Operation type: @ref OP_TUN_READ or @ref OP_UDP_RECV.
 */
void vfast_submit_read(vfast_io_t *io, int fd, int op);

/**
 * @brief Posts an asynchronous write or send request to the Submission Queue (SQ).
 * This function handles both TUN device writes and UDP socket sends. It incorporates 
 * an internal batching mechanism defined by SUBMIT_THRESHOLD to balance throughput 
 * and per-packet latency.
 *
 * @param io    Pointer to the initialized vfast_io_t context.
 * @param fd    The raw file descriptor (used to determine the registered file index).
 * @param op    Operation type: @ref OP_TUN_WRITE or @ref OP_UDP_SEND.
 * @param data  Pointer to the payload. If this points to a buffer within the 
 * internal task pool, a zero-copy (in-place) path is taken.
 * @param len   Length of the data to be written (capped at @ref BUF_SIZE).
 * @param dest  Destination address (mandatory for @ref OP_UDP_SEND, 
 * ignored for @ref OP_TUN_WRITE).
 */
void vfast_submit_write(vfast_io_t *io, int fd, int op, uint8_t *data, int len, struct sockaddr_in *dest);

/**
 * @brief Submits a raw buffer for asynchronous transmission, bypassing the task pool.
 * @note The 'data' buffer must remain valid until the CQE is reaped (e.g., session member).
 */
void vfast_submit_raw(vfast_io_t *io, int fd, void *data, size_t len, struct sockaddr_in *dst);

/**
 * @brief Borrows a task from the pre-allocated pool for external use.
 * This allows business logic to acquire a buffer for preparing outbound responses
 * without directly managing the pool. The returned task is marked as 'in use' and
 * must be released back to the pool by setting 'in_use' to false after use.
 */
vfast_task_t* vfast_borrow_task(vfast_io_t *io);

/**
 * @brief Configures a periodic timer callback for the I/O event loop.
 * @details 
 * This implements the Dependency Injection pattern, allowing the I/O core 
 * to trigger external logic (like session maintenance) without having 
 * a direct compile-time dependency on those modules.
 * @param io       Pointer to the initialized vfast_io_t context.
 * @param ms       Interval in milliseconds. If 0, the timer is disabled.
 * @param cb       The callback function to execute on every tick.
 * @param arg      User-defined context passed back to the callback.
 */
void vfast_io_set_timer(vfast_io_t *io, uint32_t ms, on_timer_cb cb, void *arg);

#endif /* VFAST_CORE_H */