docker 配置服务kanidm ```bash

```markdown
# libtinytun - High-Performance C VPN Library

sudo mkdir -p /etc/systemd/system/docker.service.d
sudo vim /etc/systemd/system/docker.service.d/http-proxy.conf

[Service]
Environment="HTTP_PROXY=http://127.0.0.1:7890"
Environment="HTTPS_PROXY=http://127.0.0.1:7890"
Environment="NO_PROXY=localhost,127.0.0.1,::1"
```

### 2. Build & Install

```bash
make && sudo make install
```

## Server-Side Gateway Configuration

To allow clients to access the internet or target resources through the VPN server, the host must be configured as a Layer 3 gateway.

### 1. Enable IP Forwarding

```bash
# Enable packet forwarding between interfaces immediately
sudo sysctl -w net.ipv4.ip_forward=1

# Make it permanent across reboots
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
```

### 2. Configure NAT & Forwarding (iptables)

The server performs Source NAT (Masquerade) to mask client 10.0.0.x IPs behind the server's physical IP.

> **Note**: Replace `eth0` with your actual WAN interface name.

```bash
# Enable Masquerade for the VPN subnet
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE

# Allow traffic forwarding through the TUN device
sudo iptables -A FORWARD -i tun0 -j ACCEPT
sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
```

### 3. TCP MSS Clamping (MTU Optimization)

Essential for preventing packet fragmentation and "stuck" connections during HTTPS/TCP handshakes caused by VPN encapsulation overhead.

```bash
# -t mangle handles packet header modification
# --clamp-mss-to-pmtu automatically calculates the best MSS based on Path MTU
sudo iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

### 4. Disable Reverse Path Filtering (Troubleshooting)

In virtualized or complex routing environments, disable rp_filter to prevent the kernel from dropping "asymmetric" packets.

```bash
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.tun0.rp_filter=0
```

## Client-Side Route Configuration

After the client connects and is assigned a Virtual IP (e.g., 10.0.0.2), you must update the routing table to direct traffic into the tunnel.

### 1. Route Specific Target via VPN

```bash
# Example: Only redirect traffic for 8.8.8.8 into the tunnel
sudo ip route add 8.8.8.8 dev tun0
```

### 2. Full Tunnel (Global VPN)

```bash
# Step 1: Keep VPN control traffic (UDP) on the physical gateway to avoid loops
# Replace <SERVER_PUBLIC_IP> and <LOCAL_GATEWAY_IP> accordingly
sudo ip route add <SERVER_PUBLIC_IP> via <LOCAL_GATEWAY_IP>

# Step 2: Set VPN as the default gateway
sudo ip route add 0.0.0.0/0 dev tun0
```

## Verification & Debugging

### Core Logic: VIP-to-Endpoint Mapping

libtinytun operates by maintaining a dynamic mapping table in memory:

- **Inbound (Client → Server)**: Server records the client's Public IP:Port when a UDP packet with a specific VIP (10.0.0.x) is received.
- **Outbound (Server → Client)**: When the tun0 interface receives a packet destined for 10.0.0.x, the server looks up the physical address and forwards the packet via sendto.

### Testing with tcpdump

Run these on the Server VM to verify successful routing and NAT:

```bash
# Monitor the virtual tunnel interface (check if client packets arrive)
sudo tcpdump -i tun0 -n

# Monitor the physical interface (check if NAT is masking the source)
sudo tcpdump -i eth0 -n host 8.8.8.8
```

## License

This project is licensed under the **GPL v2 License**.