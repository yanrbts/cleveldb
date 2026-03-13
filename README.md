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