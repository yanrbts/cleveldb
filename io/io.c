#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <string.h>
#include "io.h"

#define TASK_POOL_SIZE      (CQ_RING_DEPTH * 2)

static vfast_task_t g_task_pool[TASK_POOL_SIZE];
static int g_pool_idx = 0;

static vfast_task_t* get_task_from_pool() {
    int idx = __sync_fetch_and_add(&g_pool_idx, 1) % TASK_POOL_SIZE;
    vfast_task_t* task = &g_task_pool[idx];
    memset(task, 0, sizeof(vfast_task_t));
    return task;
}

int vfast_io_init(vfast_io_t *io, int udp_fd, int tun_fd, vfast_ops_t ops) {
    io->udp_fd = udp_fd;
    io->tun_fd = tun_fd;
    io->ops = ops;
    g_pool_idx = 0;
    return io_uring_queue_init(CQ_RING_DEPTH, &io->ring, 0);
}

void vfast_submit_read(vfast_io_t *io, int fd, int op) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);

    vfast_task_t *task = get_task_from_pool();
    task->op = op;

    if (op == OP_UDP_RECV) {
        task->addr_len = sizeof(struct sockaddr_in);
        task->iov.iov_base = task->buf;
        task->iov.iov_len = BUF_SIZE;
        task->msg.msg_name = &task->addr;
        task->msg.msg_namelen = task->addr_len;
        task->msg.msg_iov = &task->iov;
        task->msg.msg_iovlen = 1;
        io_uring_prep_recvmsg(sqe, fd, &task->msg, 0);
    } else {
        io_uring_prep_read(sqe, fd, task->buf, BUF_SIZE, 0);
    }
    io_uring_sqe_set_data(sqe, task);
}

void vfast_submit_write(vfast_io_t *io, int fd, int op, uint8_t *data, int len, struct sockaddr_in *dest) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (!sqe) return;

    vfast_task_t *task = get_task_from_pool();
    task->op = op;
    int write_len = (len > BUF_SIZE) ? BUF_SIZE : len;
    memcpy(task->buf, data, write_len);

    if (op == OP_UDP_SEND) {
        task->iov.iov_base = task->buf;
        task->iov.iov_len = len;
        task->msg.msg_name = dest;
        task->msg.msg_namelen = sizeof(struct sockaddr_in);
        task->msg.msg_iov = &task->iov;
        task->msg.msg_iovlen = 1;
        io_uring_prep_sendmsg(sqe, fd, &task->msg, 0);
    } else {
        io_uring_prep_write(sqe, fd, task->buf, len, 0);
    }
    io_uring_sqe_set_data(sqe, task);
}

void vfast_io_run(vfast_io_t *io) {
    struct io_uring_cqe *cqe;
    unsigned head;
    uint32_t count = 0;

    // 1. 预挂载多个读请求，让内核“流水线”跑起来
    // 增加初始请求数量，防止内核因为没有 SQE 而空转
    for (int i = 0; i < 16; i++) {
        vfast_submit_read(io, io->tun_fd, OP_TUN_READ);
        vfast_submit_read(io, io->udp_fd, OP_UDP_RECV);
    }
    io_uring_submit(&io->ring);

    while (1) {
        // 2. 批量等待：至少等待 1 个完成，但尝试收割所有完成的 CQE
        // 这一步会陷入内核，直到至少有一个包到达
        int ret = io_uring_wait_cqe(&io->ring, &cqe);
        if (ret < 0) continue;

        count = 0;
        // 3. 遍历当前所有已经完成的 CQE（无需多次进入内核）
        io_uring_for_each_cqe(&io->ring, head, cqe) {
            count++;
            vfast_task_t *task = (vfast_task_t *)io_uring_cqe_get_data(cqe);
            int res = cqe->res;

            if (res > 0) {
                switch (task->op) {
                    case OP_TUN_READ:
                        io->ops.on_tun_data(io, task->buf, res);
                        // 读完立刻补一个读请求到 SQ 队列
                        vfast_submit_read(io, io->tun_fd, OP_TUN_READ);
                        break;
                    case OP_UDP_RECV:
                        io->ops.on_udp_data(io, task->buf, res, &task->addr);
                        // 读完立刻补一个读请求到 SQ 队列
                        vfast_submit_read(io, io->udp_fd, OP_UDP_RECV);
                        break;
                    case OP_TUN_WRITE:
                    case OP_UDP_SEND:
                        // 写操作完成，无需特殊处理，任务会自动回到池中复用
                        break;
                }
            } else if (res < 0) {
                // 忽略一些非致命错误，如 EAGAIN
                // fprintf(stderr, "Op %d error: %s\n", task->op, strerror(-res));
            }
        }

        // 4. 统一更新 CQ 队列头部，告知内核我们已经处理了这 count 个包
        if (count > 0) {
            io_uring_cq_advance(&io->ring, count);
            // 5. 关键：一次性提交所有新挂载的读写请求
            // 这样多个 vfast_submit_read/write 只产生一次系统调用
            io_uring_submit(&io->ring);
        }
    }
}

int vfast_setup_tun(char *dev, char *ip) {
    struct ifreq ifr;
    int fd, sock;

    // 1. 创建 TUN 设备
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) return -1;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) { close(fd); return -1; }

    // 2. 创建一个临时 Socket 用于配置网络
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return -1;

    // 设置 IP 地址
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &addr->sin_addr);
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) { close(sock); return -1; }

    // 设置子网掩码 (255.255.255.0)
    inet_pton(AF_INET, "255.255.255.0", &addr->sin_addr);
    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) { close(sock); return -1; }

    // 激活网卡 (UP & RUNNING)
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) return -1;
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) return -1;

    close(sock);
    return fd;
}