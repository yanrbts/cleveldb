#!/bin/bash
set -e

# ================= 配置区 =================
# 设置你的服务器真实 IP
REAL_IP="0.0.0.0"
# 定义一个合法的、以字母开头的伪域名
FAKE_DOMAIN="idm.vfast.local"
# 工作目录
WORK_DIR=~/kanidm
# ==========================================

mkdir -p "$WORK_DIR" && cd "$WORK_DIR"

# 1. 创建自签名证书 (同时包含伪域名和真实 IP)
mkdir -p certs
echo "生成自签名 TLS 证书..."
openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout certs/key.pem \
    -out certs/cert.pem \
    -days 365 \
    -subj "/CN=${FAKE_DOMAIN}" \
    -addext "subjectAltName = IP:${REAL_IP}, DNS:${FAKE_DOMAIN}"

# 2. 创建数据目录
mkdir -p data

# 3. 生成 Docker Compose 文件
# 核心点：将 ORIGIN 改为伪域名，并在容器内通过 extra_hosts 映射回自己
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
      - "${FAKE_DOMAIN}:${REAL_IP}"
    volumes:
      - ./data:/data
      - ./certs:/certs
    environment:
      - KANIDM_DOMAIN=${FAKE_DOMAIN}
      - KANIDM_ORIGIN=https://${FAKE_DOMAIN}:8443
      - KANIDM_TLS_CHAIN=/certs/cert.pem
      - KANIDM_TLS_KEY=/certs/key.pem
      - KANIDM_DB_PATH=/data/kanidm.db
EOF

# 4. 彻底清理（Kanidm 初始化非常固执，必须删干净）
echo "正在深度清理旧数据..."
docker compose down -v || true
rm -rf ./data/*

# 5. 启动
echo "启动容器..."
docker compose up -d

# 6. 等待并执行恢复
echo "等待初始化 (约 15-30 秒)..."
MAX_WAIT=60
WAITED=0
while [ ! -S ./data/kanidmd.sock ] && [ $WAITED -lt $MAX_WAIT ]; do
    sleep 3
    WAITED=$((WAITED + 3))
    echo "已等待 ${WAITED}s..."
done

if [ -S ./data/kanidmd.sock ]; then
    echo "--------------------------------------------------"
    echo "Kanidm 启动成功！"
    docker exec -it kanidm kanidmd recover-account admin
    echo "--------------------------------------------------"
else
    echo "初始化超时，查看错误详情："
    docker logs kanidm | tail -n 20
    exit 1
fi

echo "=================================================="
echo "提示：由于使用了伪域名 ${FAKE_DOMAIN}"
echo "你需要修改你本地电脑（访问者）的 hosts 文件才能正常登录 UI："
echo "Windows: C:\Windows\System32\drivers\etc\hosts"
echo "Linux/Mac: /etc/hosts"
echo "添加一行: ${REAL_IP}  ${FAKE_DOMAIN}"
echo ""
echo "访问地址: https://${FAKE_DOMAIN}:8443"
echo "=================================================="