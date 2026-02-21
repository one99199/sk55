#!/bin/bash
#===============================================================================
# 单 VPS 三公网 IP + SOCKS5 一键脚本 (CentOS 7, 0.5G 内存)
# 使用: chmod +x vps-socks5-setup.sh && bash vps-socks5-setup.sh
#===============================================================================

set -e

SOCKS_USER="FaCai"
SOCKS_PASS="One99"
SOCKS_PORT=40001
EXPIRE_DATE=$(date -d "+45 days" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || date -v+45d "+%Y-%m-%d %H:%M:%S" 2>/dev/null)
OUTPUT_FILE="/root/proxy_list.txt"
IP_FILE="/root/public_ips.txt"
LOG_FILE="/root/log.txt"
USE_PYTHON_SOCKS=0
DEFAULT_IFACE=$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}' || echo "eth0")

# ---------- 日志：同时输出到终端并追加到 /root/log.txt ----------
log_msg() {
    local ts=$(date "+%Y-%m-%d %H:%M:%S")
    echo "$@"
    echo "[$ts] $*" >> "$LOG_FILE"
}

# ---------- 初始化日志（每次运行追加一条分隔与开始时间） ----------
echo "" >> "$LOG_FILE"
echo "========== $(date '+%Y-%m-%d %H:%M:%S') 脚本开始 ==========" >> "$LOG_FILE"
log_msg "日志文件: $LOG_FILE"

# ---------- 在 /root 下建立公网 IP 记录文件并赋予权限 ----------
touch "$IP_FILE"
chmod 644 "$IP_FILE"

# ---------- 运行中提示输入 3 个公网 IP（一行一个），并写入文件 ----------
saved=()
[ -s "$IP_FILE" ] && mapfile -t saved < "$IP_FILE"
echo ""
echo "请输入 3 个公网 IP 地址，一行一个（共三行）："
[ ${#saved[@]} -ge 3 ] && echo "（当前已保存: ${saved[0]}, ${saved[1]}, ${saved[2]}  直接回车使用，或重新输入三行覆盖）"
read -r -p "第 1 个: " ip1
read -r -p "第 2 个: " ip2
read -r -p "第 3 个: " ip3
if [ -z "$ip1" ] || [ -z "$ip2" ] || [ -z "$ip3" ]; then
    if [ -s "$IP_FILE" ] && [ ${#saved[@]} -ge 3 ]; then
        ip1="${saved[0]}"
        ip2="${saved[1]}"
        ip3="${saved[2]}"
        echo "使用已保存的 IP: $ip1, $ip2, $ip3"
    else
        echo "错误: 必须输入 3 个公网 IP，或保证 $IP_FILE 内已有 3 行。"
        exit 1
    fi
else
    printf '%s\n%s\n%s\n' "$ip1" "$ip2" "$ip3" > "$IP_FILE"
    chmod 644 "$IP_FILE"
    echo "已写入 $IP_FILE"
fi
PUBLIC_IPS=( "$ip1" "$ip2" "$ip3" )

# ---------- 绑定公网 IP 到网卡（修复：多网卡时按接口一一绑定，避免只有主 IP 通） ----------
log_msg "[1/4] 公网 IP 与网卡绑定"
{ echo "--- ip addr show ---"; ip addr show; echo "--- ip route show ---"; ip route show; } >> "$LOG_FILE" 2>&1 || true

# 获取所有具有 IPv4 地址的接口（排除 lo），按名称排序，保证顺序稳定
IFACES=()
while IFS= read -r iface; do
    [ -z "$iface" ] && continue
    [[ "$iface" == "lo" ]] && continue
    IFACES+=( "$iface" )
done < <(ip -4 -o addr show scope global 2>/dev/null | awk -F: '{print $2}' | awk '{print $1}' | sort -u)

# 若上面没有拿到 3 个接口，再尝试列出所有非 lo 的物理接口（部分云先有网卡后配 IP）
if [ ${#IFACES[@]} -lt 3 ]; then
    IFACES=()
    while IFS= read -r iface; do
        iface=$(echo "$iface" | tr -d ' ')
        [ -z "$iface" ] && continue
        [[ "$iface" == "lo" ]] && continue
        IFACES+=( "$iface" )
    done < <(ip link show 2>/dev/null | awk -F: '/^[0-9]+:/{print $2}' | sort -u)
fi

log_msg "  检测到接口列表: ${IFACES[*]:-无}"
log_msg "  默认出口网卡: $DEFAULT_IFACE"

if [ ${#IFACES[@]} -ge 3 ]; then
    # 三网卡（或更多）：第 i 个公网 IP 绑定到第 i 个网卡，保证每个 EIP 对应其接收流量的网卡
    log_msg "  使用多网卡一一绑定: 公网IP1->${IFACES[0]}, 公网IP2->${IFACES[1]}, 公网IP3->${IFACES[2]}"
    for i in 0 1 2; do
        pub="${PUBLIC_IPS[$i]}"
        iface="${IFACES[$i]}"
        if ip addr show "$iface" 2>/dev/null | grep -qF "$pub"; then
            log_msg "  $pub 已在 $iface 上存在"
        else
            if ip addr add "$pub/32" dev "$iface" 2>>"$LOG_FILE"; then
                log_msg "  已绑定 $pub -> $iface"
            else
                log_msg "  绑定 $pub -> $iface 失败 (见 $LOG_FILE)"
            fi
        fi
    done
elif [ ${#IFACES[@]} -eq 2 ]; then
    # 双网卡：公网IP1->网卡0，公网IP2/3->网卡1（常见于 1 主 + 1 辅网卡）
    log_msg "  使用双网卡绑定: ${PUBLIC_IPS[0]}->${IFACES[0]}, ${PUBLIC_IPS[1]}/${PUBLIC_IPS[2]}->${IFACES[1]}"
    for i in 0 1 2; do
        pub="${PUBLIC_IPS[$i]}"
        iface="${IFACES[$(( i > 0 ? 1 : 0 ))]}"
        if ip addr show "$iface" 2>/dev/null | grep -qF "$pub"; then
            log_msg "  $pub 已在 $iface 上存在"
        else
            if ip addr add "$pub/32" dev "$iface" 2>>"$LOG_FILE"; then
                log_msg "  已绑定 $pub -> $iface"
            else
                log_msg "  绑定 $pub -> $iface 失败 (见 $LOG_FILE)"
            fi
        fi
    done
else
    # 单网卡：全部绑定到默认出口网卡
    log_msg "  使用单网卡绑定: 所有公网 IP 绑定到 $DEFAULT_IFACE"
    for pub in "${PUBLIC_IPS[@]}"; do
        if ip addr show "$DEFAULT_IFACE" 2>/dev/null | grep -qF "$pub"; then
            log_msg "  $pub 已存在"
        else
            if ip addr add "$pub/32" dev "$DEFAULT_IFACE" 2>>"$LOG_FILE"; then
                log_msg "  已绑定 $pub -> $DEFAULT_IFACE"
            else
                log_msg "  绑定 $pub -> $DEFAULT_IFACE 失败 (见 $LOG_FILE)"
            fi
        fi
    done
fi
log_msg "  公网 IP 列表: ${PUBLIC_IPS[*]}"

# ---------- 2. 游戏/长连接/防封 内核优化 ----------
log_msg "[2/4] 内核参数优化（延迟低、不掉线、行为像正常 TCP）"
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
log_msg "  放行端口 $SOCKS_PORT (firewalld + iptables)"
if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null 2>/dev/null; then
    firewall-cmd --permanent --add-port=${SOCKS_PORT}/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
fi
# iptables 直接放行（多数 CentOS 7 生效）
iptables -D INPUT -p tcp --dport $SOCKS_PORT -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p tcp --dport $SOCKS_PORT -j ACCEPT
echo "  提示: 若外网仍连不上，请在云控制台 安全组/ACL 中放行 TCP $SOCKS_PORT 入站"

# ---------- 3. 启动 SOCKS5（单进程 0.0.0.0，省资源） ----------
log_msg "[3/4] 启动 SOCKS5 (端口 $SOCKS_PORT, 监听 0.0.0.0)"

start_3proxy() {
    cat > /etc/3proxy.cfg << EOF
nserver 8.8.8.8
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
daemon
auth strong
users ${SOCKS_USER}:CL:${SOCKS_PASS}
allow ${SOCKS_USER}
socks -p${SOCKS_PORT} -i0.0.0.0 -e0.0.0.0 -u2
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
    USE_PYTHON_SOCKS=1
    start_python_socks
fi

# 等待端口就绪（3proxy 以 daemon 启动需稍等）
wait_for_port() {
    local i=0
    while [ $i -lt 10 ]; do
        if ss -tlnp 2>/dev/null | grep -q ":${SOCKS_PORT} "; then
            return 0
        fi
        sleep 1
        i=$((i+1))
    done
    return 1
}
wait_for_port && echo "  端口 $SOCKS_PORT 已监听" || echo "  等待端口超时，请稍后执行: ss -tlnp | grep $SOCKS_PORT"

# ---------- 4. 连通性自检（本机） ----------
log_msg "[4/4] 连通性自检"
check_local() {
    if ss -tlnp 2>/dev/null | grep -q ":${SOCKS_PORT} "; then
        echo "  本机端口 $SOCKS_PORT: 已监听"
    else
        echo "  本机端口 $SOCKS_PORT: 未监听 (请检查 3proxy 是否运行: ps aux | grep 3proxy)"
        return 1
    fi
    if command -v curl &>/dev/null; then
        if curl -s -x "socks5://${SOCKS_USER}:${SOCKS_PASS}@127.0.0.1:${SOCKS_PORT}" --connect-timeout 8 -o /dev/null -w "%{http_code}" "https://www.gstatic.com/generate_204" 2>/dev/null | grep -q 204; then
            echo "  本机 SOCKS5 代理: 正常 (curl 经代理访问外网成功)"
            return 0
        fi
        echo "  本机 SOCKS5 代理: curl 测试未通过 (请检查账号密码或 3proxy 配置)"
    fi
    if [ "$USE_PYTHON_SOCKS" = 1 ]; then
        echo "  若异常可查看: /var/log/socks5.log"
    fi
    return 1
}
check_local || true

# ---------- 5. 生成代理列表并保存 ----------
log_msg "生成代理列表: $OUTPUT_FILE"
mkdir -p "$(dirname "$OUTPUT_FILE")"
: > "$OUTPUT_FILE"
for ip in "${PUBLIC_IPS[@]}"; do
    echo "${ip}|${SOCKS_PORT}|${SOCKS_USER}|${SOCKS_PASS}|${EXPIRE_DATE}" >> "$OUTPUT_FILE"
done
echo "========== $(date '+%Y-%m-%d %H:%M:%S') 脚本结束 ==========" >> "$LOG_FILE"

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
echo "--- 维护日志 ---"
echo "  查看/排查: cat $LOG_FILE  或  tail -f $LOG_FILE"
echo ""
