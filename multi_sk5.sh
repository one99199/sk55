#!/bin/bash

echo "###############################################################"
echo "#           欢迎使用多IP一键安装脚本                         #"
echo "#           脚本支持系统: CentOS 7+                          #"
echo "###############################################################"
echo ""
echo "请选择操作："
echo "1. IP 网卡配置绑定（多 IP 服务器使用，需搭配 ip.txt 文件）"
echo "2. 安装/配置 sk5 多 IP SOCKS5（游戏优化版）"
echo "3. 安装 l2tp"
read -p "请输入选项 (1/2/3): " choice

case $choice in
1)
    echo "======================================================="
    echo "【第 1 步：绑定内网 IP 对应公网 IP】"
    echo "本步骤会下载并运行 bind.sh，实际绑定逻辑在 bind.sh 里完成。"
    echo "绑定脚本会使用 ip.txt 文件，请按照 bind.sh 的提示把【公网 IP】"
    echo "写入 ip.txt（通常在 /root/ip.txt 或脚本当前目录）。"
    echo "======================================================="
    echo ""
    echo "正在下载并运行 IP 网卡配置绑定脚本 bind.sh..."
    BIND_SCRIPT_URL="https://github.com/55620/bot/raw/refs/heads/main/bangdingip/bind.sh"
    wget -O bind.sh "$BIND_SCRIPT_URL"
    if [[ $? -eq 0 ]]; then
        chmod +x bind.sh
        echo "运行 bind.sh 脚本中，请根据脚本提示填写 ip.txt 里的公网 IP ..."
        ./bind.sh
        echo "IP 网卡配置绑定脚本运行完成！"
        echo "如需修改公网 IP，请重新编辑 bind.sh 同目录下的 ip.txt，然后再运行本脚本第 2 项。"
    else
        echo "下载 bind.sh 失败，请检查下载链接是否正确！"
    fi
    ;;

2)
    echo "正在安装/配置 sk5（游戏优化版，多 IP SOCKS5）..."

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

    # BBR（如果内核支持就打开，不支持就跳过）
    if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr; then
        add_sysctl_if_missing "net.core.default_qdisc" "fq"
        add_sysctl_if_missing "net.ipv4.tcp_congestion_control" "bbr"
    fi

    sysctl -p >/dev/null 2>&1 || true
    echo "内核网络参数优化完成。"

    # ========== 3. 获取本机 IP（多网卡 / 多 IP） ==========
    # 这里会拿到经过 bind.sh 绑定后的本机 IP，一般就是你的公网 IP
    mapfile -t ips < <(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^127\.' | grep -v '^$' | sort -u)

    if [ ${#ips[@]} -eq 0 ]; then
        echo "未检测到任何有效 IP，退出。"
        exit 1
    fi

    echo "检测到本机 IP 列表：${ips[*]}"

    # 最多只使用前 3 个 IP（你是 3 个公网 IP 的场景）
    if [ ${#ips[@]} -gt 3 ]; then
        echo "提示：检测到 ${#ips[@]} 个 IP，仅使用前 3 个：${ips[@]:0:3}"
        ips=("${ips[@]:0:3}")
    fi

    # ========== 4. 为每个 IP 生成不重复的随机端口 ==========
    random_port() {
        # 20000–65000 之间随机（>10000 符合你要求）
        echo $((20000 + RANDOM % 45000))
    }

    declare -A IP_PORT
    USED_PORTS=()

    for ip in "${ips[@]}"; do
        while true; do
            port=$(random_port)
            used=0
            for p in "${USED_PORTS[@]}"; do
                if [ "$p" = "$port" ]; then
                    used=1
                    break
                fi
            done
            [ $used -eq 0 ] && break
        done
        IP_PORT["$ip"]=$port
        USED_PORTS+=("$port")
    done

    # ========== 5. 写 systemd 服务 ==========
    cat >/etc/systemd/system/sk5.service <<EOF
[Unit]
Description=The sk5 Proxy Server
After=network-online.target

[Service]
ExecStart=/usr/local/bin/sk5 -c /etc/sk5/serve.toml
ExecStop=/bin/kill -s QUIT \$MAINPID
Restart=always
RestartSec=10s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable sk5 >/dev/null 2>&1 || true

    # ========== 6. 生成 sk5 配置（每个 IP 一条 SOCKS5，支持 UDP） ==========
    mkdir -p /etc/sk5
    : > /etc/sk5/serve.toml

    idx=0
    for ip in "${ips[@]}"; do
        idx=$((idx + 1))
        port="${IP_PORT[$ip]}"

        cat >> /etc/sk5/serve.toml <<EOF
[[inbounds]]
listen = "$ip"
port = $port
protocol = "socks"
tag = "in-$idx"

[inbounds.settings]
auth = "password"
udp = true
ip = "$ip"

[[inbounds.settings.accounts]]
user = "$SOCKS_USER"
pass = "$SOCKS_PASS"

[[routing.rules]]
type = "field"
inboundTag = "in-$idx"
outboundTag = "out-$idx"

[[outbounds]]
sendThrough = "$ip"
protocol = "freedom"
tag = "out-$idx"

EOF
    done

    # ========== 7. iptables 放行端口（TCP+UDP） ==========
    for ip in "${ips[@]}"; do
        port="${IP_PORT[$ip]}"
        iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true

        iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
    done

    # ========== 8. 启动 sk5 服务 ==========
    systemctl stop sk5 >/dev/null 2>&1 || true
    systemctl start sk5

    sleep 1
    if systemctl is-active --quiet sk5; then
        echo "sk5 服务已启动。"
    else
        echo "警告：sk5 服务未成功启动，请用 'systemctl status sk5' 查看原因。"
    fi

    # ========== 9. 最终输出：IP|端口|用户名|密码 ==========
    echo ""
    echo "=========== SOCKS5 列表（用于游戏加速 / 挂机）==========="
    echo "格式：IP|端口|用户名|密码"
    for ip in "${ips[@]}"; do
        echo "$ip|${IP_PORT[$ip]}|$SOCKS_USER|$SOCKS_PASS"
    done
    echo "======================================================="
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
