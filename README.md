# libtinytun - High-Performance C VPN Library

A lightweight, industrial-grade VPN core library built with C and `io_uring` for extreme concurrency.

## Features
- **Zero-Copy Architecture**: Powered by Linux `io_uring` for low-latency packet processing.
- **Multi-Queue Support**: Parallel TUN device handling for multi-core scalability.
- **High Concurrency**: Designed to handle 10,000+ simultaneous sessions.
- **Minimalist Core**: Stripped-down implementation focusing on speed and security.

## Prerequisites
- **OS**: Linux Kernel 5.10+ (Recommended for stable io_uring support).
- **Library**: `liburing` (v2.0 or higher).
- **Permissions**: `CAP_NET_ADMIN` (Required for TUN device manipulation).

## Installation

### 1. Install Dependencies
```bash
sudo apt update && sudo apt install -y liburing-dev build-essential
```

### 2 MSS
```bash
# -t mangle 专门用于修改包头
# --clamp-mss-to-pmtu 自动根据当前路径 MTU 计算最佳 MSS
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```