#include <time.h>
#include "vfast.h"
#include "log.h"

void vfast_report_performance(void) {
    static uint64_t last_bytes = 0;
    static struct timespec last_time = {0}; // 初始化
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    /* 如果是第一次运行，先记录时间并退出 */
    if (last_time.tv_sec == 0) {
        last_time = now;
        last_bytes = atomic_load(&vfastctx.stats.rx_bytes);
        return;
    }

    uint64_t current_bytes = atomic_load(&vfastctx.stats.rx_bytes);
    double seconds = (now.tv_sec - last_time.tv_sec) + 
                     (now.tv_nsec - last_time.tv_nsec) / 1e9;

    /* 只有超过 1 秒才打印 */
    if (seconds >= 1.0) {
        double mbps = ((double)(current_bytes - last_bytes) * 8.0) / (1024 * 1024 * seconds);
        
        log_info("[PERF] Bandwidth: %.2f Mbps | RX: %lu pkts | SessionMiss: %lu | UnpackErr: %lu", 
                 mbps, 
                 atomic_load(&vfastctx.stats.rx_packets),
                 atomic_load(&vfastctx.stats.drop_session_miss),
                 atomic_load(&vfastctx.stats.drop_unpack_error)); // 加上你关心的丢包统计
        
        last_bytes = current_bytes;
        last_time = now;
    }
}
