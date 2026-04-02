#ifndef VFAST_CORE_H
#define VFAST_CORE_H

#include <liburing.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>

#define BUF_SIZE 2048
#define CQ_RING_DEPTH 256

// Forward declaration
struct vfast_io;
typedef struct vfast_io vfast_io_t;

/**
 * Callbacks for data events
 * @param src: The source address (relevant for UDP reception)
 */
typedef int (*udp_data_cb)(vfast_io_t *io, uint8_t *data, int len, struct sockaddr_in *src);
typedef int (*tun_data_cb)(vfast_io_t *io, uint8_t *data, int len);

typedef struct {
    udp_data_cb on_udp_data;
    tun_data_cb on_tun_data;
} vfast_ops_t;

struct vfast_io {
    struct io_uring ring;
    int udp_fd;
    int tun_fd;
    vfast_ops_t ops;
    struct sockaddr_in remote_addr; // Target for client; tracked peer for server
    bool is_server;
};

// Operation types for the async state machine
enum {
    OP_TUN_READ = 1,
    OP_TUN_WRITE,
    OP_UDP_RECV,
    OP_UDP_SEND
};

// Task context used to track async operations in the CQE
typedef struct {
    int op;
    uint8_t buf[BUF_SIZE];
    struct iovec iov;
    struct msghdr msg;
    struct sockaddr_in addr;
    socklen_t addr_len;
} vfast_task_t;

int vfast_io_init(vfast_io_t *io, int udp_fd, int tun_fd, vfast_ops_t ops);
void vfast_io_run(vfast_io_t *io);
void vfast_submit_read(vfast_io_t *io, int fd, int op);
void vfast_submit_write(vfast_io_t *io, int fd, int op, uint8_t *data, int len, struct sockaddr_in *dest);
int vfast_setup_tun(char *dev, char *ip);

#endif