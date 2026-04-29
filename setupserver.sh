#!/bin/bash
set -e

# ================= 配置区 (可自行修改) =================
BASE_DIR=~/radius-vpn-stack
DOMAIN="vfast.local"
LDAP_ADMIN_PASS="admin123"
RADIUS_SECRET="vpnsecret123"
# =====================================================

mkdir -p $BASE_DIR/{freeradius/sites-enabled,freeradius/mods-enabled,ldap/data,ldap/config}
cd $BASE_DIR

echo "[1/4] 生成 Docker Compose 文件..."
cat > docker-compose.yml <<EOF
version: '3.8'

services:
  keycloak:
    image: quay.io/keycloak/keycloak:24.0
    container_name: keycloak
    command: start-dev
    environment:
      KC_HOSTNAME_STRICT: "false"
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin123
    ports:
      - "8080:8080"
    depends_on:
      - openldap

  openldap:
    image: osixia/openldap:latest
    container_name: openldap
    environment:
      LDAP_ORGANISATION: "VFast VPN"
      LDAP_DOMAIN: "${DOMAIN}"
      LDAP_ADMIN_PASSWORD: "${LDAP_ADMIN_PASS}"
    ports:
      - "389:389"
    volumes:
      - ./ldap/data:/var/lib/ldap
      - ./ldap/config:/etc/ldap/slapd.d

  freeradius:
    image: freeradius/freeradius-server:latest
    container_name: freeradius
    ports:
      - "1812:1812/udp"
      - "1813:1813/udp"
    volumes:
      - ./freeradius/clients.conf:/etc/raddb/clients.conf
      - ./freeradius/mods-enabled/ldap:/etc/raddb/mods-enabled/ldap
      - ./freeradius/sites-enabled/default:/etc/raddb/sites-enabled/default
    depends_on:
      - openldap
EOF

echo "[2/4] 生成 FreeRADIUS 配置文件..."

# 1. Clients 配置
cat > freeradius/clients.conf <<EOF
client vpn_gateway {
    ipaddr = 0.0.0.0/0
    secret = ${RADIUS_SECRET}
}
EOF

# 2. LDAP 模块配置 (dc 转换)
DC_STR="dc=${DOMAIN//./,dc=}"
cat > freeradius/mods-enabled/ldap <<EOF
ldap {
    server = "openldap"
    identity = "cn=admin,${DC_STR}"
    password = ${LDAP_ADMIN_PASS}
    base_dn = "${DC_STR}"
    user {
        base_dn = "ou=users,${DC_STR}"
        filter = "(uid=%{User-Name})"
    }
}
EOF

# 3. 极简 Site 配置
cat > freeradius/sites-enabled/default <<EOF
server default {
    listen {
        type = auth
        ipaddr = *
        port = 1812
    }

    authorize {
        preprocess
        suffix
        files
        ldap
        # 关键：如果 ldap 模块返回 ok（找到了用户），强制指定 Auth-Type 为 LDAP
        if (ok) {
            update control {
                Auth-Type := LDAP
            }
        }
    }

    authenticate {
        # 处理被标记为 Auth-Type LDAP 的请求
        Auth-Type LDAP {
            ldap
        }
    }

    post-auth {
        # 记录日志，方便调试
        Post-Auth-Type REJECT {
            attr_filter.access_reject
        }
    }
}
EOF

echo "[3/4] 修正权限并启动容器..."
sudo chown -R 100:101 freeradius/
docker compose down -v || true
docker compose up -d

echo "[4/4] 初始化 LDAP 结构 & 等待服务..."
# 给 OpenLDAP 一点启动时间，否则 ldapadd 会连不上
sleep 10

# 自动创建 OU (使用变量防止硬编码错误)
cat > create_ou.ldif <<EOF
dn: ou=users,${DC_STR}
objectClass: organizationalUnit
ou: users
EOF

# 执行导入，如果已存在则不会中断脚本
docker exec -i openldap ldapadd -x -D "cn=admin,${DC_STR}" -w ${LDAP_ADMIN_PASS} < create_ou.ldif || echo "OU 已存在，跳过..."

echo "=================================================="
echo "🚀 部署完成！"
echo "=================================================="
echo "1. LDAP 目录 'ou=users' 已自动创建。"
echo "2. Keycloak 管理后台: http://$(hostname -I | awk '{print $1}'):8080"
echo "   账号: admin / 密码: admin123"
echo ""
echo "3. 【提醒】最后一步仍需在 Keycloak 网页配置 LDAP Federation:"
echo "   - Connection URL: ldap://openldap:389"
echo "   - Users DN: ou=users,${DC_STR}"
echo "   - Bind DN: cn=admin,${DC_STR}"
echo "   - Bind Password: ${LDAP_ADMIN_PASS}"
echo "   - Edit Mode: WRITABLE"
echo "4. 测试命令 (宿主机运行):"
echo "   sudo apt install freeradius-utils -y"
echo "   echo \"User-Name=YOUR_USER,User-Password=YOUR_PASS\" | radclient -x 127.0.0.1:1812 auth ${RADIUS_SECRET}"
echo "=================================================="