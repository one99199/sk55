#!/bin/bash

echo "###############################################################"
echo "# 欢迎使用多IP一键安装脚本（修复版） #"
echo "# 脚本支持系统: CentOS 7+ #"
echo "###############################################################"
echo ""
echo "请选择操作："
echo "1. IP 网卡配置绑定（多IP服务器使用，需搭配 ip.txt 文件）"
echo "2. 安装/配置 sk5 多IP SOCKS5（游戏优化版）"
echo "3. 安装 l2tp"
read -p "请输入选项 (1/2/3): " choice

case $choice in
1)
 echo "======================================================="
 echo "【第 1 步：绑定内网 IP 对应公网 IP】"
 echo "本步骤会下载并运行 bind.sh，实际绑定逻辑在 bind.sh 里完成。"
 echo "======================================================="
 echo ""
 echo "正在下载并运行 IP 网卡配置绑定脚本 bind.sh..."
 BIND_SCRIPT_URL="https://github.com/55620/bot/raw/refs/heads/main/bangdingip/bind.sh"
 wget -O bind.sh "$BIND_SCRIPT_URL"
 if [[ $? -eq 0 ]]; then
 chmod +x bind.sh
 echo "运行 bind.sh 脚本中，请根据脚本提示完成网卡/IP 绑定..."
 ./bind.sh
 echo "IP 网卡配置绑定脚本运行完成！"
 else
 echo "下载 bind.sh 失败，请检查下载链接是否正确！"
 fi

 # ======= 自动生成 /root/ip.txt 模板 =======
 IP_FILE="/root/ip.txt"
 echo "正在生成 /root/ip.txt 公网 IP 配置模板..."

 cat > "$IP_FILE" << 'EOF'
# 每行填写一个【公网 IP】，不要带端口、不要带空格，例如：
# 8.218.210.30
# 47.242.93.101
# 8.217.2.105
#
# 最多写 3 行，多于 3 行只会取前 3 个。
#
# 填写完毕后，请运行:
# ./multi_sk5.sh
# 选择 2 安装/配置 sk5 多IP SOCKS5。
EOF

 # 在文件最后附上当前检测到的本机 IP（仅供参考，通常是内网 IP）
 {
 echo ""
 echo "# 当前检测到的本机 IP（一般是内网 IP，仅作参考，不一定是公网）："
 hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^127\.' | grep -v '^$' | sort -u | sed 's/^/# /'
 } >> "$IP_FILE"

 echo "已生成 /root/ip.txt，请用你自己的【公网 IP】覆盖文件中的示例行。"
 echo "示例："
 echo " 8.218.210.30"
 echo " 47.242.93.101"
 echo " 8.217.2.105"
 echo "然后运行 ./multi_sk5.sh 选择 2 完成 Socks5 安装。"
 ;;

2)
 echo "正在安装/配置 sk5（游戏优化版，多IP SOCKS5）..."

 # ========== 1. 安装 sk5 主程序 ==========
 SK5_FILE_URL="https://github.com/55620/bot/raw/refs/heads/main/bangdingip/sk5"
 mkdir -p /usr/local/bin
 echo "下载 sk5 主程序到 /usr/local/bin/sk5 ..."
 wget -O /usr/local/bin/sk5 "$SK5_FILE_URL"
 if [[ $? -ne 0 ]]; then
 echo "下载 sk5 主程序失败，请检查网络或下载链接！"
 exit 1
 fi
 chmod +x /usr/local/bin/sk5
 echo "sk5 主程序已安装到 /usr/local/bin/sk5"

 # ========== 2. 内核网络优化（适合长时间打游戏 / 挂机） ==========
 SOCKS_USER="FaCai"
 SOCKS_PASS="One99"

 add_sysctl_if_missing() {
 local key="$1" value="$2"
 grep -q "^${key}\s*=" /etc/sysctl.conf 2>/dev/null || echo "${key}=${value}" >> /etc/sysctl.conf
 }

 # 大缓冲，减少丢包
 add_sysctl_if_missing "net.core.rmem_max" "67108864"
 add_sysctl_if_missing "net.core.wmem_max" "67108864"
 add_sysctl_if_missing "net.core.rmem_default" "262144"
 add_sysctl_if_missing "net.core.wmem_default" "262144"
 add_sysctl_if_missing "net.core.netdev_max_backlog" "250000"
 add_sysctl_if_missing "net.core.somaxconn" "65535"

 # TCP 低延迟
 add_sysctl_if_missing "net.ipv4.tcp_fastopen" "3"
 add_sysctl_if_missing "net.ipv4.tcp_slow_start_after_idle" "0"
 add_sysctl_if_missing "net.ipv4.tcp_mtu_probing" "1"
 add_sysctl_if_missing "net.ipv4.tcp_sack" "1"
 add_sysctl_if_missing "net.ipv4.tcp_timestamps" "1"
 add_sysctl_if_missing "net.ipv4.ip_forward" "1"

 # 长连接保活（2 小时）
 add_sysctl_if_missing "net.ipv4.tcp_keepalive_time" "7200"
 add_sysctl_if_missing "net.ipv4.tcp_keepalive_intvl" "75"
 add_sysctl_if_missing "net.ipv4.tcp_keepalive_probes" "9"

 # BBR（如果内核支持就打开）
 if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr; then
 add_sysctl_if_missing "net.core.default_qdisc" "fq"
 add_sysctl_if_missing "net.ipv4.tcp_congestion_control" "bbr"
 fi

 sysctl -p >/dev/null 2>&1 || true
 echo "内核网络参数优化完成。"

 # ========== 3. 从 /root/ip.txt 读取公网 IP ==========
 IP_FILE="/root/ip.txt"
 if [ ! -f "$IP_FILE" ]; then
 echo "未找到 $IP_FILE，请先运行选项 1，或手动创建 /root/ip.txt："
 echo "每行写一个公网 IP，例如："
 echo "8.218.210.30"
 echo "47.242.93.101"
 echo "8.217.2.105"
 exit 1
 fi

 # 去掉 \r，过滤注释和空行
 mapfile -t pub_ips < <(sed 's/\r$//' "$IP_FILE" | grep -vE '^\s*#|^\s*$')

 if [ ${#pub_ips[@]} -eq 0 ]; then
 echo "$IP_FILE 中没有有效公网 IP，每行写一个，例如：8.218.210.30"
 exit 1
 fi

 # 只取前 3 个公网 IP
 if [ ${#pub_ips[@]} -gt 3 ]; then
 echo "提示：ip.txt 中有 ${#pub_ips[@]} 个 IP，仅使用前 3 个：${pub_ips[@]:0:3}"
 pub_ips=("${pub_ips[@]:0:3}")
 fi

 echo "将为以下公网 IP 生成 Socks5：${pub_ips[*]}"

 # ========== 4. 使用固定端口 48664 ==========
 PORT=48664
 echo "使用固定端口：$PORT"

 # 检查端口是否被占用
 if command -v ss >/dev/null 2>&1; then
 if ss -tuln | grep -q ":$PORT "; then
 echo "警告：端口 $PORT 已被占用，正在检查占用进程..."
 OCCUPIED_PROC=$(ss -tulnp | grep ":$PORT ")
 echo "$OCCUPIED_PROC"
 echo "请手动释放该端口或修改脚本中的PORT变量"
 fi
 elif command -v netstat >/dev/null 2>&1; then
 if netstat -tuln | grep -q ":$PORT "; then
 echo "警告：端口 $PORT 已被占用，正在检查占用进程..."
 OCCUPIED_PROC=$(netstat -tulnp | grep ":$PORT ")
 echo "$OCCUPIED_PROC"
 echo "请手动释放该端口或修改脚本中的PORT变量"
 fi
 fi

 # ========== 5. 写 systemd 服务（修复：确保服务正确启动，支持多种配置格式） ==========
 # 创建启动脚本，优先使用JSON格式（Xray标准格式）
 cat >/usr/local/bin/sk5-start.sh <<'SK5START'
#!/bin/bash
CONFIG_JSON="/etc/sk5/config.json"
CONFIG_TOML="/etc/sk5/serve.toml"

# 优先使用JSON格式（Xray标准格式，更可靠）
if [ -f "$CONFIG_JSON" ]; then
    echo "使用JSON配置文件：$CONFIG_JSON"
    /usr/local/bin/sk5 -c "$CONFIG_JSON"
# 如果JSON不存在，尝试TOML格式
elif [ -f "$CONFIG_TOML" ]; then
    echo "使用TOML配置文件：$CONFIG_TOML"
    /usr/local/bin/sk5 -c "$CONFIG_TOML"
else
    echo "错误：未找到配置文件！"
    echo "请检查 /etc/sk5/ 目录"
    exit 1
fi
SK5START

 chmod +x /usr/local/bin/sk5-start.sh

 cat >/etc/systemd/system/sk5.service <<EOF
[Unit]
Description=SOCKS5 Proxy Server (sk5)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sk5-start.sh
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

 systemctl daemon-reload
 echo "systemd 服务配置已更新（支持自动检测配置格式）。"

 # ========== 6. 生成 sk5 配置（优先使用JSON格式，确保端口正确监听） ==========
 mkdir -p /etc/sk5
 
 # 创建Xray标准JSON格式配置（主要配置）
 cat >/etc/sk5/config.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": $PORT,
      "protocol": "socks",
      "settings": {
        "auth": "password",
        "accounts": [
          {
            "user": "$SOCKS_USER",
            "pass": "$SOCKS_PASS"
          }
        ],
        "udp": true,
        "ip": "0.0.0.0"
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF

 # 同时创建TOML格式（作为备用）
 cat >/etc/sk5/serve.toml <<EOF
[server]
listen = "0.0.0.0:$PORT"
udp_enable = true

[users]
"$SOCKS_USER" = "$SOCKS_PASS"
EOF

 echo "sk5 配置文件已生成："
 echo "1. JSON格式（主要）：/etc/sk5/config.json"
 echo "2. TOML格式（备用）：/etc/sk5/serve.toml"
 echo ""
 echo "JSON配置内容："
 cat /etc/sk5/config.json
 echo ""
 echo "TOML配置内容："
 cat /etc/sk5/serve.toml
 echo ""
 
 # 验证配置文件是否存在且可读
 if [ ! -f /etc/sk5/config.json ]; then
 echo "错误：JSON配置文件创建失败！"
 exit 1
 fi
 
 if [ ! -f /etc/sk5/serve.toml ]; then
 echo "警告：TOML配置文件创建失败！"
 fi
 
 # 验证JSON格式是否正确
 if command -v python3 >/dev/null 2>&1; then
 if python3 -m json.tool /etc/sk5/config.json >/dev/null 2>&1; then
 echo "✓ JSON配置文件格式验证通过"
 else
 echo "✗ 错误：JSON配置文件格式不正确！"
 exit 1
 fi
 elif command -v python >/dev/null 2>&1; then
 if python -m json.tool /etc/sk5/config.json >/dev/null 2>&1; then
 echo "✓ JSON配置文件格式验证通过"
 else
 echo "✗ 错误：JSON配置文件格式不正确！"
 exit 1
 fi
 else
 echo "⚠ 无法验证JSON格式（未安装python），请手动检查"
 fi
 
 # 验证配置文件中是否包含正确的端口
 if ! grep -q "\"port\": $PORT" /etc/sk5/config.json; then
 echo "✗ 错误：JSON配置文件中端口不正确！"
 exit 1
 fi
 
 if ! grep -q "listen = \"0.0.0.0:$PORT\"" /etc/sk5/serve.toml; then
 echo "⚠ 警告：TOML配置文件中端口可能不正确"
 fi
 
 echo "✓ 配置文件验证完成"

 # ========== 7. 防火墙规则（完整配置，确保规则正确添加和持久化） ==========
 echo "=========================================="
 echo "配置防火墙规则（端口：$PORT）..."
 echo "=========================================="

 # 检测防火墙类型并配置
 if systemctl is-active --quiet firewalld 2>/dev/null || systemctl is-enabled --quiet firewalld 2>/dev/null; then
 echo "检测到 firewalld，添加防火墙规则..."
 
 # 添加TCP端口
 if firewall-cmd --permanent --add-port=$PORT/tcp 2>/dev/null; then
 echo "  ✓ TCP 端口 $PORT 已添加到 firewalld"
 else
 echo "  ⚠ TCP 端口 $PORT 添加失败或已存在"
 fi
 
 # 添加UDP端口
 if firewall-cmd --permanent --add-port=$PORT/udp 2>/dev/null; then
 echo "  ✓ UDP 端口 $PORT 已添加到 firewalld"
 else
 echo "  ⚠ UDP 端口 $PORT 添加失败或已存在"
 fi
 
 # 重新加载防火墙
 if firewall-cmd --reload 2>/dev/null; then
 echo "  ✓ firewalld 规则已重新加载"
 else
 echo "  ⚠ firewalld 重新加载失败"
 fi
 
 # 验证规则
 if firewall-cmd --list-ports 2>/dev/null | grep -q "$PORT/tcp"; then
 echo "  ✓ 验证：TCP 端口 $PORT 规则已生效"
 else
 echo "  ✗ 警告：TCP 端口 $PORT 规则未生效"
 fi
 
 if firewall-cmd --list-ports 2>/dev/null | grep -q "$PORT/udp"; then
 echo "  ✓ 验证：UDP 端口 $PORT 规则已生效"
 else
 echo "  ✗ 警告：UDP 端口 $PORT 规则未生效"
 fi

 elif command -v ufw >/dev/null 2>&1 && (systemctl is-active --quiet ufw 2>/dev/null || ufw status | grep -q "Status: active"); then
 echo "检测到 ufw，添加防火墙规则..."
 
 # 添加TCP端口
 if ufw allow $PORT/tcp 2>/dev/null; then
 echo "  ✓ TCP 端口 $PORT 已添加到 ufw"
 else
 echo "  ⚠ TCP 端口 $PORT 添加失败或已存在"
 fi
 
 # 添加UDP端口
 if ufw allow $PORT/udp 2>/dev/null; then
 echo "  ✓ UDP 端口 $PORT 已添加到 ufw"
 else
 echo "  ⚠ UDP 端口 $PORT 添加失败或已存在"
 fi
 
 # 验证规则
 if ufw status | grep -q "$PORT/tcp"; then
 echo "  ✓ 验证：TCP 端口 $PORT 规则已生效"
 else
 echo "  ✗ 警告：TCP 端口 $PORT 规则未生效"
 fi
 
 if ufw status | grep -q "$PORT/udp"; then
 echo "  ✓ 验证：UDP 端口 $PORT 规则已生效"
 else
 echo "  ✗ 警告：UDP 端口 $PORT 规则未生效"
 fi

 else
 echo "使用 iptables 添加规则..."
 
 # 添加TCP规则
 if iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null; then
 echo "  ✓ TCP 端口 $PORT 规则已存在"
 else
 if iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null; then
 echo "  ✓ TCP 端口 $PORT 规则已添加"
 else
 echo "  ✗ TCP 端口 $PORT 规则添加失败"
 fi
 fi
 
 # 添加UDP规则
 if iptables -C INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null; then
 echo "  ✓ UDP 端口 $PORT 规则已存在"
 else
 if iptables -I INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null; then
 echo "  ✓ UDP 端口 $PORT 规则已添加"
 else
 echo "  ✗ UDP 端口 $PORT 规则添加失败"
 fi
 fi
 
 # 保存 iptables 规则（多种方式尝试）
 if command -v iptables-save >/dev/null 2>&1; then
 # CentOS/RHEL 7+
 if [ -f /etc/redhat-release ]; then
 if command -v netfilter-persistent >/dev/null 2>&1; then
 netfilter-persistent save 2>/dev/null || true
 fi
 # 保存到文件
 iptables-save > /etc/sysconfig/iptables 2>/dev/null || \
 iptables-save > /etc/iptables.rules 2>/dev/null || true
 echo "  ✓ iptables 规则已保存"
 fi
 
 # Debian/Ubuntu
 if [ -f /etc/debian_version ]; then
 if command -v netfilter-persistent >/dev/null 2>&1; then
 netfilter-persistent save 2>/dev/null || true
 echo "  ✓ iptables 规则已通过 netfilter-persistent 保存"
 else
 # 安装 iptables-persistent 或手动保存
 iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
 iptables-save > /etc/iptables.rules 2>/dev/null || true
 echo "  ✓ iptables 规则已保存到文件"
 fi
 fi
 fi
 
 # 验证规则
 if iptables -L INPUT -n | grep -q "tcp dpt:$PORT"; then
 echo "  ✓ 验证：TCP 端口 $PORT 规则已生效"
 else
 echo "  ✗ 警告：TCP 端口 $PORT 规则未生效"
 fi
 
 if iptables -L INPUT -n | grep -q "udp dpt:$PORT"; then
 echo "  ✓ 验证：UDP 端口 $PORT 规则已生效"
 else
 echo "  ✗ 警告：UDP 端口 $PORT 规则未生效"
 fi
 fi

 echo "=========================================="
 echo "防火墙规则配置完成"
 echo "=========================================="

 # ========== 8. 启动 sk5 服务（优化：增强启动检查，自动诊断和修复） ==========
 echo "=========================================="
 echo "启动 sk5 服务"
 echo "=========================================="
 
 echo "停止旧服务（如果存在）..."
 systemctl stop sk5 >/dev/null 2>&1 || true
 sleep 3

 # 检查端口是否被其他进程占用
 echo "检查端口 $PORT 是否被占用..."
 if command -v ss >/dev/null 2>&1; then
 PORT_OCCUPIED=$(ss -tulnp | grep ":$PORT " | head -1)
 elif command -v netstat >/dev/null 2>&1; then
 PORT_OCCUPIED=$(netstat -tulnp | grep ":$PORT " | head -1)
 fi
 
 if [ -n "$PORT_OCCUPIED" ]; then
 echo "警告：端口 $PORT 已被占用："
 echo "$PORT_OCCUPIED"
 echo "尝试释放端口..."
 # 尝试杀死占用端口的进程（谨慎操作）
 PID=$(echo "$PORT_OCCUPIED" | grep -oP '\d+(?=/\w+$)' | head -1)
 if [ -n "$PID" ] && [ "$PID" != "$$" ]; then
 echo "发现占用端口的进程 PID: $PID"
 read -t 5 -p "是否杀死该进程？(y/N，5秒后自动跳过): " KILL_PROC || KILL_PROC="n"
 if [ "$KILL_PROC" = "y" ] || [ "$KILL_PROC" = "Y" ]; then
 kill -9 "$PID" 2>/dev/null && echo "已杀死进程 $PID" || echo "无法杀死进程 $PID"
 sleep 2
 fi
 fi
 fi

 echo "启动 sk5 服务（使用JSON配置）..."
 systemctl start sk5

 echo "等待服务启动（最多等待20秒）..."
 
 # 等待服务启动，最多等待20秒
 service_started=false
 for i in {1..20}; do
 if systemctl is-active --quiet sk5; then
 echo "✓ sk5 服务进程已启动（等待 $i 秒）"
 service_started=true
 break
 fi
 sleep 1
 done

 # 检查服务状态
 if [ "$service_started" = true ]; then
 echo "✓ sk5 服务已成功启动"
 
 # 检查进程是否真的在运行
 if pgrep -f "sk5.*config.json" >/dev/null 2>&1 || pgrep -f "sk5.*serve.toml" >/dev/null 2>&1; then
 echo "✓ sk5 进程确认运行中"
 else
 echo "⚠ 警告：systemd显示服务运行，但未找到sk5进程"
 fi
 else
 echo "✗ sk5 服务启动失败，查看日志："
 systemctl status sk5 --no-pager -l | head -30
 echo ""
 echo "最近的服务日志："
 journalctl -u sk5 -n 50 --no-pager | tail -30
 echo ""
 echo "尝试手动测试sk5程序..."
 
 # 尝试手动运行sk5测试配置
 if [ -f /usr/local/bin/sk5 ]; then
 echo "测试JSON配置："
 timeout 3 /usr/local/bin/sk5 -c /etc/sk5/config.json -test 2>&1 | head -10 || \
 timeout 3 /usr/local/bin/sk5 -c /etc/sk5/config.json 2>&1 | head -10 &
 TEST_PID=$!
 sleep 2
 kill $TEST_PID 2>/dev/null || true
 fi
 fi

 # 等待端口监听（最多等待30秒，因为服务可能需要时间初始化）
 echo ""
 echo "等待端口 $PORT 开始监听（最多等待30秒）..."
 port_listening=false
 for i in {1..30}; do
 if command -v ss >/dev/null 2>&1; then
 PORT_CHECK=$(ss -tulnp | grep ":$PORT ")
 if [ -n "$PORT_CHECK" ]; then
 # 检查是否是sk5或xray进程
 if echo "$PORT_CHECK" | grep -qE "sk5|xray"; then
 echo "✓ 端口 $PORT 已开始监听（等待 $i 秒）"
 echo "  监听信息：$PORT_CHECK"
 port_listening=true
 break
 else
 # 即使不是sk5进程，也显示端口被占用
 echo "⚠ 端口 $PORT 被占用，但不是sk5进程（等待 $i 秒）"
 echo "  占用信息：$PORT_CHECK"
 fi
 fi
 elif command -v netstat >/dev/null 2>&1; then
 PORT_CHECK=$(netstat -tulnp | grep ":$PORT ")
 if [ -n "$PORT_CHECK" ]; then
 if echo "$PORT_CHECK" | grep -qE "sk5|xray"; then
 echo "✓ 端口 $PORT 已开始监听（等待 $i 秒）"
 echo "  监听信息：$PORT_CHECK"
 port_listening=true
 break
 else
 echo "⚠ 端口 $PORT 被占用，但不是sk5进程（等待 $i 秒）"
 echo "  占用信息：$PORT_CHECK"
 fi
 fi
 fi
 sleep 1
 done

 # 最终检查端口监听状态
 echo ""
 echo "=========================================="
 echo "最终端口检查"
 echo "=========================================="
 if command -v ss >/dev/null 2>&1; then
 PORT_INFO=$(ss -tulnp | grep ":$PORT ")
 elif command -v netstat >/dev/null 2>&1; then
 PORT_INFO=$(netstat -tulnp | grep ":$PORT ")
 fi
 
 if [ -n "$PORT_INFO" ]; then
 echo "✓ 端口 $PORT 正在监听："
 echo "$PORT_INFO"
 port_listening=true
 else
 echo "✗ 警告：未检测到端口 $PORT 监听"
 port_listening=false
 fi

 # 如果端口未监听，显示详细诊断信息
 if [ "$port_listening" = false ]; then
 echo ""
 echo "=========================================="
 echo "详细诊断信息"
 echo "=========================================="
 echo "1. 服务状态："
 systemctl status sk5 --no-pager -l | head -25
 echo ""
 echo "2. 配置文件（TOML）："
 if [ -f /etc/sk5/serve.toml ]; then
 cat /etc/sk5/serve.toml
 else
 echo "TOML配置文件不存在"
 fi
 echo ""
 echo "3. 配置文件（JSON）："
 if [ -f /etc/sk5/config.json ]; then
 cat /etc/sk5/config.json
 else
 echo "JSON配置文件不存在"
 fi
 echo ""
 echo "4. 服务进程："
 ps aux | grep -E "sk5|xray" | grep -v grep || echo "未找到sk5/xray进程"
 echo ""
 echo "5. 所有监听端口："
 if command -v ss >/dev/null 2>&1; then
 ss -tulnp | head -30
 else
 netstat -tulnp | head -30
 fi
 echo ""
 echo "6. 最近的服务日志（最后50行）："
 journalctl -u sk5 -n 50 --no-pager
 echo ""
 echo "=========================================="
 echo "建议的修复步骤："
 echo "=========================================="
 echo "1. 检查sk5程序是否支持JSON配置格式："
 echo "   /usr/local/bin/sk5 --help"
 echo ""
 echo "2. 尝试手动运行JSON配置（前台运行，查看输出）："
 echo "   /usr/local/bin/sk5 -c /etc/sk5/config.json"
 echo ""
 echo "3. 如果JSON格式不支持，尝试TOML格式："
 echo "   /usr/local/bin/sk5 -c /etc/sk5/serve.toml"
 echo ""
 echo "4. 查看实时服务日志："
 echo "   journalctl -u sk5 -f"
 echo ""
 echo "5. 检查配置文件中的端口是否正确："
 echo "   grep -E 'port|PORT' /etc/sk5/config.json"
 echo ""
 echo "6. 如果sk5不支持JSON，可能需要修改启动脚本使用TOML："
 echo "   vi /usr/local/bin/sk5-start.sh"
 echo "   将JSON和TOML的顺序调换"
 echo "=========================================="
 else
 echo ""
 echo "✓ 端口监听正常，服务运行正常！"
 fi

 # ========== 9. 测试每个IP的连通性（优化：更准确的测试方法） ==========
 echo ""
 echo "=========================================="
 echo "测试各IP的连通性"
 echo "=========================================="
 
 # 首先检查本地端口是否监听
 LOCAL_LISTEN=false
 if command -v ss >/dev/null 2>&1; then
 if ss -tuln | grep -q "0.0.0.0:$PORT " || ss -tuln | grep -q ":::$PORT "; then
 LOCAL_LISTEN=true
 fi
 elif command -v netstat >/dev/null 2>&1; then
 if netstat -tuln | grep -q "0.0.0.0:$PORT "; then
 LOCAL_LISTEN=true
 fi
 fi
 
 if [ "$LOCAL_LISTEN" = false ]; then
 echo "⚠ 警告：本地端口 $PORT 未监听，无法进行连通性测试"
 echo "请先确保服务正常运行并监听端口"
 else
 echo "✓ 本地端口 $PORT 正在监听，开始测试外部IP连通性..."
 echo ""
 
 for ip in "${pub_ips[@]}"; do
 echo -n "测试 $ip:$PORT ... "
 
 # 方法1: 使用bash内置TCP测试
 if timeout 3 bash -c "echo > /dev/tcp/$ip/$PORT" 2>/dev/null; then
 echo "✓ 连接成功"
 continue
 fi
 
 # 方法2: 使用nc (netcat) 测试
 if command -v nc >/dev/null 2>&1; then
 if timeout 3 nc -z -v "$ip" "$PORT" 2>&1 | grep -q "succeeded\|open"; then
 echo "✓ 连接成功（使用nc测试）"
 continue
 fi
 fi
 
 # 方法3: 使用telnet测试
 if command -v telnet >/dev/null 2>&1; then
 if timeout 3 bash -c "echo 'quit' | telnet $ip $PORT 2>&1" | grep -q "Connected\|Escape"; then
 echo "✓ 连接成功（使用telnet测试）"
 continue
 fi
 fi
 
 # 如果所有方法都失败
 echo "✗ 连接失败"
 echo "  可能原因："
 echo "    - 云服务商安全组未开放端口 $PORT"
 echo "    - 服务器防火墙未开放端口 $PORT"
 echo "    - 服务未绑定到该IP地址"
 echo "    - 网络路由问题"
 done
 fi

 # ========== 10. 最终输出：公网IP|统一端口|FaCai|One99 ==========
 echo ""
 echo "=========== SOCKS5 列表（用于游戏加速 / 挂机）==========="
 echo "格式：IP|端口|用户名|密码"
 for ip in "${pub_ips[@]}"; do
 echo "$ip|$PORT|$SOCKS_USER|$SOCKS_PASS"
 done
 echo "======================================================="
 echo ""
 echo "如果某些IP无法连接，请检查："
 echo "1. 服务器防火墙是否开放端口 $PORT"
 echo "2. 云服务商安全组是否开放端口 $PORT"
 echo "3. 服务是否成功启动：systemctl status sk5"
 echo "4. 查看服务日志：journalctl -u sk5 -f"
 ;;

3)
 echo "正在安装 l2tp..."
 L2TP_SCRIPT_URL="https://github.com/55620/bot/raw/refs/heads/main/bangdingip/1.sh"

 echo "下载并运行 l2tp 安装脚本..."
 wget -O 1.sh "$L2TP_SCRIPT_URL"
 if [[ $? -eq 0 ]]; then
 chmod +x 1.sh
 echo "运行 1.sh 脚本中，请稍候..."
 ./1.sh
 echo "l2tp 安装完成！"
 else
 echo "下载 1.sh 文件失败，请检查下载链接是否正确！"
 fi
 ;;

*)
 echo "无效的选项，请输入 1、2 或 3！"
 ;;
esac
