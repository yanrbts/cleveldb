#!/bin/bash
set -e

# ================= 配置区 =================
# 1. 自动获取 WSL 的真实 IP (不要写 0.0.0.0)
REAL_IP=$(ip addr show ens33 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
# 2. 定义伪域名
FAKE_DOMAIN="idm.vfast.local"
# 工作目录
WORK_DIR=~/kanidm
# ==========================================

echo "检测到 WSL IP 为: ${REAL_IP}"
mkdir -p "$WORK_DIR" && cd "$WORK_DIR"

# 1. 创建自签名证书
mkdir -p certs
echo "生成自签名 TLS 证书..."
openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout certs/key.pem \
    -out certs/cert.pem \
    -days 365 \
    -subj "/CN=${FAKE_DOMAIN}" \
    -addext "subjectAltName = IP:${REAL_IP}, IP:127.0.0.1, DNS:${FAKE_DOMAIN}"

# 2. 创建数据目录
mkdir -p data

# 3. 生成 Docker Compose 文件
cat > docker-compose.yml << EOF
version: '3.8'
services:
  kanidm:
    image: kanidm/server:latest
    container_name: kanidm
    restart: unless-stopped
    ports:
      - "8443:8443"
      - "3636:3636"
    extra_hosts:
      - "${FAKE_DOMAIN}:127.0.0.1"
    volumes:
      - ./data:/data
      - ./certs:/certs
    environment:
      - KANIDM_DOMAIN=${FAKE_DOMAIN}
      - KANIDM_ORIGIN=https://${FAKE_DOMAIN}:8443
      - KANIDM_BINDADDRESS=0.0.0.0:8443
      - KANIDM_TLS_CHAIN=/certs/cert.pem
      - KANIDM_TLS_KEY=/certs/key.pem
      - KANIDM_DB_PATH=/data/kanidm.db
EOF

# 4. 彻底清理脏数据 (由于之前 Sqlite 报错，这一步必须执行)
echo "正在深度清理旧数据..."
docker compose down -v || true
rm -rf ./data/*

# 5. 启动
echo "启动容器..."
docker compose up -d

# 6. 等待并执行恢复
echo "等待初始化..."
MAX_WAIT=10
WAITED=0
while [ ! -S ./data/kanidmd.sock ] && [ $WAITED -lt $MAX_WAIT ]; do
    sleep 3
    WAITED=$((WAITED + 3))
done

if [ -S ./data/kanidmd.sock ]; then
    echo "--------------------------------------------------"
    echo "Kanidm 启动成功！"
    docker exec -it kanidm kanidmd recover-account admin
    echo "--------------------------------------------------"
else
    echo "初始化失败，查看日志："
    docker logs kanidm
    exit 1
fi

echo "=================================================="
echo "Windows 访问关键步骤："
echo "1. 请在 Windows 的 hosts 文件中添加以下内容："
echo "   ${REAL_IP}  ${FAKE_DOMAIN}"
echo ""
echo "2. 访问地址: https://${FAKE_DOMAIN}:8443"
echo "3. 如果提示证书不安全，直接在网页空白处盲打输入：thisisunsafe"
echo "=================================================="