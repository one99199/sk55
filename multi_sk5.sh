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

 # ========== 4. 生成随机端口（40000-65000，范围25000个端口） ==========
 random_port() {
 # 40000-65000 之间随机，共25000个端口可选
 echo $((40000 + RANDOM % 25000))
 }

 # 检查端口是否被占用
 check_port_available() {
 local port=$1
 if command -v netstat >/dev/null 2>&1; then
 netstat -tuln | grep -q ":$port " && return 1
 elif command -v ss >/dev/null 2>&1; then
 ss -tuln | grep -q ":$port " && return 1
 fi
 return 0
 }

 # 生成随机端口，如果被占用则重新生成（最多尝试20次）
 PORT=$(random_port)
 max_attempts=20
 attempt=0
 while ! check_port_available "$PORT" && [ $attempt -lt $max_attempts ]; do
 echo "端口 $PORT 已被占用，重新生成随机端口..."
 PORT=$(random_port)
 attempt=$((attempt + 1))
 done

 if [ $attempt -eq $max_attempts ]; then
 echo "警告：尝试 $max_attempts 次后仍无法找到可用端口，使用端口：$PORT"
 echo "如果端口被占用，请手动检查或释放该端口"
 else
 echo "使用随机端口：$PORT（40000-65000范围，共25000个端口可选）"
 fi

 # ========== 5. 写 systemd 服务（修复：确保服务正确启动） ==========
 cat >/etc/systemd/system/sk5.service <<EOF
[Unit]
Description=SOCKS5 Proxy Server (sk5)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sk5 -c /etc/sk5/serve.toml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

 systemctl daemon-reload
 echo "systemd 服务配置已更新。"

 # ========== 6. 生成 sk5 配置（监听 0.0.0.0:PORT，支持 UDP，修复：确保绑定所有IP） ==========
 mkdir -p /etc/sk5
 cat >/etc/sk5/serve.toml <<EOF
[server]
listen = "0.0.0.0:$PORT"
udp_enable = true

[users]
"$SOCKS_USER" = "$SOCKS_PASS"
EOF

 echo "sk5 配置文件已生成：/etc/sk5/serve.toml"
 echo "配置内容："
 cat /etc/sk5/serve.toml

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

 # ========== 8. 启动 sk5 服务（修复：增加启动检查和重试） ==========
 systemctl stop sk5 >/dev/null 2>&1 || true
 sleep 2
 systemctl start sk5

 echo "等待服务启动..."
 sleep 3

 # 检查服务状态
 if systemctl is-active --quiet sk5; then
 echo "✓ sk5 服务已成功启动"
 else
 echo "✗ sk5 服务启动失败，查看日志："
 systemctl status sk5 --no-pager -l
 echo ""
 echo "尝试查看详细错误："
 journalctl -u sk5 -n 20 --no-pager
 exit 1
 fi

 # 检查端口监听
 echo "检查端口监听状态..."
 if command -v netstat >/dev/null 2>&1; then
 netstat -tuln | grep ":$PORT " || echo "警告：未检测到端口 $PORT 监听"
 elif command -v ss >/dev/null 2>&1; then
 ss -tuln | grep ":$PORT " || echo "警告：未检测到端口 $PORT 监听"
 fi

 # ========== 9. 测试每个IP的连通性 ==========
 echo ""
 echo "测试各IP的连通性..."
 for ip in "${pub_ips[@]}"; do
 echo -n "测试 $ip:$PORT ... "
 if timeout 3 bash -c "echo > /dev/tcp/$ip/$PORT" 2>/dev/null; then
 echo "✓ 连接成功"
 else
 echo "✗ 连接失败（可能防火墙未开放或服务未绑定该IP）"
 fi
 done

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
