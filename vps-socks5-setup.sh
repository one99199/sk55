#!/bin/bash
#===============================================================================
# 单 VPS 三公网 IP 绑定 + SOCKS5 一键脚本 (CentOS 7, 0.5G 内存)
# 流程: 绑定 3 个公网 IP -> 内核优化 -> 单进程 SOCKS5(省资源) -> 输出并保存代理列表
# 使用: chmod +x vps-socks5-setup.sh && bash vps-socks5-setup.sh
#===============================================================================

set -e

# ---------- 直接配置（改这里即可） ----------
PUBLIC_IPS=( "47.242.215.214" "47.243.85.225" "8.217.67.31" )
SOCKS_USER="FaCai"
SOCKS_PASS="One99"
SOCKS_PORT=40001
# 过期: 今日 + 45 天
EXPIRE_DATE=$(date -d "+45 days" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || date -v+45d "+%Y-%m-%d %H:%M:%S" 2>/dev/null)
# 代理列表保存路径（脚本结束后可从本机 scp 下载）
OUTPUT_FILE="/root/proxy_list.txt"

# ---------- 网卡 ----------
IFACE=$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}' || echo "eth0")

echo "[1/4] 绑定 ${#PUBLIC_IPS[@]} 个公网 IP 到 $IFACE"

# ---------- 1. 绑定全部公网 IP ----------
for ip in "${PUBLIC_IPS[@]}"; do
    if ip addr show "$IFACE" 2>/dev/null | grep -q "$ip"; then
        echo "  已存在 $ip"
    else
        ip addr add "$ip/32" dev "$IFACE" 2>/dev/null && echo "  已添加 $ip" || echo "  添加 $ip 失败(可能已存在)"
    fi
done

# ---------- 2. 游戏/长连接优化（不重复追加） ----------
echo "[2/4] 内核参数优化"
cat > /etc/sysctl.d/99-game-socks.conf << 'SYSCTL'
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.core.netdev_max_backlog = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_syncookies = 1
vm.min_free_kbytes = 65536
SYSCTL
sysctl -p /etc/sysctl.d/99-game-socks.conf 2>/dev/null || true

# 放行端口
if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null 2>/dev/null; then
    firewall-cmd -q --permanent --add-port=${SOCKS_PORT}/tcp 2>/dev/null && firewall-cmd --reload 2>/dev/null || true
fi
iptables -C INPUT -p tcp --dport $SOCKS_PORT -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport $SOCKS_PORT -j ACCEPT 2>/dev/null || true

# ---------- 3. 轻量稳定 SOCKS5（单进程监听 0.0.0.0，三个 IP 共用一端口） ----------
echo "[3/4] 启动 SOCKS5 (端口 $SOCKS_PORT)"

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
    3proxy /etc/3proxy.cfg && echo "  使用 3proxy 已启动"
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
    echo "  使用 Python SOCKS5 已启动"
}

if command -v 3proxy &>/dev/null; then
    start_3proxy
elif command -v yum &>/dev/null && yum install -y 3proxy 2>/dev/null; then
    start_3proxy
else
    start_python_socks
fi

# ---------- 4. 生成代理列表并输出到终端 + 保存到文件（便于下载到本机） ----------
echo "[4/4] 生成代理列表"
mkdir -p "$(dirname "$OUTPUT_FILE")"
: > "$OUTPUT_FILE"
for ip in "${PUBLIC_IPS[@]}"; do
    line="${ip}|${SOCKS_PORT}|${SOCKS_USER}|${SOCKS_PASS}|${EXPIRE_DATE}"
    echo "$line" >> "$OUTPUT_FILE"
done

echo ""
echo "========== 代理列表（已保存到 VPS: $OUTPUT_FILE）=========="
cat "$OUTPUT_FILE"
echo "=========================================================="
echo "格式: IP|端口|账号|密码|过期时间"
echo ""
echo "--- 下载到您的电脑 ---"
echo "在您电脑 PowerShell 或 CMD 中执行（把下面的 VPS主IP 换成 47.242.215.214 等任意一个可连的 IP）："
echo "  scp root@47.242.215.214:$OUTPUT_FILE ."
echo "下载后当前目录会得到 proxy_list.txt，可直接使用。"
echo ""
