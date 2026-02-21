#!/bin/bash
#===============================================================================
# 单 VPS 多公网 IP + SOCKS5 一键脚本 (CentOS 7, 0.5G 内存)
# 公网 IP: 自动从网卡获取，若无则用下方 FALLBACK 列表并尝试绑定
# 流程: 检测/绑定公网 IP -> 内核与防火墙 -> SOCKS5 -> 自检连通性 -> 输出代理列表
# 使用: chmod +x vps-socks5-setup.sh && bash vps-socks5-setup.sh
#===============================================================================

set -e

# ---------- 配置 ----------
SOCKS_USER="FaCai"
SOCKS_PASS="One99"
SOCKS_PORT=40001
EXPIRE_DATE=$(date -d "+45 days" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || date -v+45d "+%Y-%m-%d %H:%M:%S" 2>/dev/null)
OUTPUT_FILE="/root/proxy_list.txt"
# 未自动检测到公网 IP 时使用的列表（如云厂商未把公网 IP 绑到网卡，可在此写死并绑定）
FALLBACK_PUBLIC_IPS=( "47.242.215.214" "47.243.85.225" "8.217.67.31" )

# ---------- 网卡 ----------
IFACE=$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}' || echo "eth0")

# ---------- 公网 IP 自动检测：从网卡取非内网 IPv4 ----------
is_private_ip() {
    local ip="$1"
    [[ "$ip" =~ ^127\. ]] && return 0
    [[ "$ip" =~ ^10\. ]] && return 0
    [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
    [[ "$ip" =~ ^192\.168\. ]] && return 0
    return 1
}
get_public_ips_auto() {
    local list=()
    while read -r line; do
        if [[ "$line" =~ inet[^6]\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/ ]]; then
            ip="${BASH_REMATCH[1]}"
            is_private_ip "$ip" || list+=( "$ip" )
        fi
    done < <(ip -4 addr show dev "$IFACE" 2>/dev/null)
    echo "${list[@]}"
}

# 决定最终使用的公网 IP 列表
AUTO_IPS=( $(get_public_ips_auto) )
if [ ${#AUTO_IPS[@]} -gt 0 ]; then
    PUBLIC_IPS=( "${AUTO_IPS[@]}" )
    echo "[0] 已从网卡 $IFACE 自动检测到公网 IP: ${PUBLIC_IPS[*]}"
else
    PUBLIC_IPS=( "${FALLBACK_PUBLIC_IPS[@]}" )
    echo "[0] 未检测到公网 IP，使用配置列表并尝试绑定: ${PUBLIC_IPS[*]}"
fi

# ---------- 1. 绑定公网 IP（仅 FALLBACK 场景：未在网卡上的才执行 add） ----------
echo "[1/4] 绑定/确认公网 IP 到 $IFACE"
for ip in "${PUBLIC_IPS[@]}"; do
    if ip addr show "$IFACE" 2>/dev/null | grep -qF "$ip"; then
        echo "  已存在 $ip"
    else
        ip addr add "$ip/32" dev "$IFACE" 2>/dev/null && echo "  已添加 $ip" || echo "  添加 $ip 失败(无权限或该 IP 未归属本机)"
    fi
done

# ---------- 2. 游戏/长连接/防封 内核优化 ----------
echo "[2/4] 内核参数优化（延迟低、不掉线、行为像正常 TCP）"
cat > /etc/sysctl.d/99-game-socks.conf << 'SYSCTL'
# 保活与断线检测
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 20
net.ipv4.tcp_keepalive_probes = 6
# 快速回收，减少半连接占用
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
# 连接队列与稳定性
net.core.netdev_max_backlog = 4096
net.ipv4.tcp_max_syn_backlog = 4096
# 避免空闲一段时间后变慢
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
# 正常 TCP 行为，利于过墙/防封
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_sack = 1
# 内存
vm.min_free_kbytes = 65536
SYSCTL
sysctl -p /etc/sysctl.d/99-game-socks.conf 2>/dev/null || true

# ---------- 防火墙：确保 40001 入站放行（连通性关键） ----------
echo "  放行端口 $SOCKS_PORT (firewalld + iptables)"
if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null 2>/dev/null; then
    firewall-cmd --permanent --add-port=${SOCKS_PORT}/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
fi
# iptables 直接放行（多数 CentOS 7 生效）
iptables -D INPUT -p tcp --dport $SOCKS_PORT -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p tcp --dport $SOCKS_PORT -j ACCEPT
echo "  提示: 若外网仍连不上，请在云控制台 安全组/ACL 中放行 TCP $SOCKS_PORT 入站"

# ---------- 3. 启动 SOCKS5（单进程 0.0.0.0，省资源） ----------
echo "[3/4] 启动 SOCKS5 (端口 $SOCKS_PORT, 监听 0.0.0.0)"

start_3proxy() {
    cat > /etc/3proxy.cfg << EOF
nserver 8.8.8.8
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
daemon
auth strong
users ${SOCKS_USER}:CL:${SOCKS_PASS}
allow ${SOCKS_USER}
proxy -p${SOCKS_PORT} -i0.0.0.0 -e0.0.0.0
EOF
    pkill 3proxy 2>/dev/null || true
    sleep 1
    3proxy /etc/3proxy.cfg && echo "  已启动: 3proxy"
}

start_python_socks() {
    PY=$(command -v python3 || command -v python)
    [ -z "$PY" ] && { echo "  错误: 需安装 python3: yum install -y python3"; exit 1; }
    pkill -f "socks5_oneshot" 2>/dev/null || true
    sleep 1
    nohup $PY - "$SOCKS_PORT" "$SOCKS_USER" "$SOCKS_PASS" << 'PYCODE' >> /var/log/socks5.log 2>&1 &
import socket, threading, struct, sys
def auth_connect(conn, user, pwd):
    conn.sendall(b'\x05\x02\x00\x02')
    ver, ulen = struct.unpack('BB', conn.recv(2))
    u, plen = conn.recv(ulen), struct.unpack('B', conn.recv(1))[0]
    p = conn.recv(plen)
    if u.decode() == user and p.decode() == pwd:
        conn.sendall(b'\x05\x00')
        return True
    conn.sendall(b'\x05\x01')
    return False
def handle(c, user, pwd):
    try:
        if not auth_connect(c, user, pwd): c.close(); return
        ver, cmd, _, atype = struct.unpack('BBBB', c.recv(4))
        if atype == 1: addr = socket.inet_ntoa(c.recv(4))
        elif atype == 3: addr = c.recv(struct.unpack('B', c.recv(1))[0]).decode()
        else: c.close(); return
        port, = struct.unpack('>H', c.recv(2))
        r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        r.settimeout(60)
        r.connect((addr, port))
        c.sendall(b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack('>H', 0))
        def fd(a, b):
            try:
                while True:
                    d = a.recv(8192)
                    if not d: break
                    b.sendall(d)
            except: pass
            try: a.close(); b.close()
            except: pass
        for t in [threading.Thread(target=fd, args=(c,r)), threading.Thread(target=fd, args=(r,c))]:
            t.daemon = True
            t.start()
    except: pass
    try: c.close()
    except: pass
def main():
    port, user, pwd = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))
    s.listen(256)
    while True:
        c, _ = s.accept()
        c.settimeout(300)
        threading.Thread(target=handle, args=(c, user, pwd), daemon=True).start()
main()
PYCODE
    echo "  已启动: Python SOCKS5"
}

if command -v 3proxy &>/dev/null; then
    start_3proxy
elif command -v yum &>/dev/null && yum install -y 3proxy 2>/dev/null; then
    start_3proxy
else
    start_python_socks
fi

# 等待服务就绪
sleep 2

# ---------- 4. 连通性自检（本机） ----------
echo "[4/4] 连通性自检"
check_local() {
    # 用 curl 走 SOCKS5 测本机
    if command -v curl &>/dev/null; then
        if curl -s -x "socks5://${SOCKS_USER}:${SOCKS_PASS}@127.0.0.1:${SOCKS_PORT}" --connect-timeout 5 -o /dev/null -w "%{http_code}" "https://www.gstatic.com/generate_204" 2>/dev/null | grep -q 204; then
            echo "  本机 SOCKS5 连通: 正常 (curl 经代理访问外网成功)"
            return 0
        fi
    fi
    # 无 curl 或失败时用 nc 测端口
    if command -v nc &>/dev/null; then
        if nc -z -w2 127.0.0.1 $SOCKS_PORT 2>/dev/null; then
            echo "  本机 SOCKS5 端口: 已监听 (建议用 curl 或客户端再测一次认证)"
            return 0
        fi
    fi
    echo "  本机自检: 端口或代理未就绪，请检查 /var/log/socks5.log 或 3proxy 进程"
    return 1
}
check_local || true

# ---------- 5. 生成代理列表并保存 ----------
mkdir -p "$(dirname "$OUTPUT_FILE")"
: > "$OUTPUT_FILE"
for ip in "${PUBLIC_IPS[@]}"; do
    echo "${ip}|${SOCKS_PORT}|${SOCKS_USER}|${SOCKS_PASS}|${EXPIRE_DATE}" >> "$OUTPUT_FILE"
done

echo ""
echo "========== 代理列表（已保存到 VPS: $OUTPUT_FILE）=========="
cat "$OUTPUT_FILE"
echo "=========================================================="
echo "格式: IP|端口|账号|密码|过期时间"
echo ""
echo "--- 若外网连不上，请逐项检查 ---"
echo "  1. 云控制台 安全组/防火墙 是否放行 TCP $SOCKS_PORT 入站"
echo "  2. 本机端口: ss -tlnp | grep $SOCKS_PORT  应看到 0.0.0.0:$SOCKS_PORT"
echo "  3. 本机测试: curl -x socks5://${SOCKS_USER}:***@127.0.0.1:${SOCKS_PORT} https://www.gstatic.com/generate_204"
echo ""
echo "--- 下载到您的电脑 ---"
echo "  scp root@<任一公网IP>:$OUTPUT_FILE ."
echo ""
