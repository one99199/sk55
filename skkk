#!/bin/bash

echo "###############################################################"
echo "#           欢迎使用作者多IP一键安装脚本                     #"
echo "#           脚本支持系统: CentOS                             #"
echo "###############################################################"
echo ""
echo "请选择操作："
echo "1. IP网卡配置绑定（多IP服务器使用，需要搭配ip.txt文件）"
echo "2. 安装sk5"
echo "3. 安装l2tp"
read -p "请输入选项 (1/2/3): " choice

case $choice in
1)
    echo "正在下载并运行 IP 网卡配置绑定脚本 bind.sh..."
    BIND_SCRIPT_URL="https://github.com/one99199/sk55/raw/refs/heads/main/bind.sh"
    wget -O bind.sh $BIND_SCRIPT_URL
    if [[ $? -eq 0 ]]; then
        chmod +x bind.sh
        echo "运行 bind.sh 脚本中，请稍候..."
        ./bind.sh
        echo "IP 网卡配置绑定脚本运行完成！"
    else
        echo "下载 bind.sh 失败，请检查下载链接是否正确！"
    fi
    ;;
2)
    echo "正在安装 sk5..."
    SK5_FILE_URL="https://github.com/one99199/sk55/raw/refs/heads/main/sk5"
    SK5_SCRIPT_URL="https://github.com/one99199/sk55/raw/refs/heads/main/sk55.sh"

    echo "下载 sk5 主文件到 /usr/local/bin..."
    wget -O /usr/local/bin/sk5 $SK5_FILE_URL
    if [[ $? -eq 0 ]]; then
        chmod +x /usr/local/bin/sk5
        echo "sk5 主文件已安装到 /usr/local/bin 目录！"
    else
        echo "下载 sk5 主文件失败，请检查下载链接是否正确！"
        exit 1
    fi

    echo "下载并运行 sk5 安装脚本..."
    wget -O sk5.sh $SK5_SCRIPT_URL
    if [[ $? -eq 0 ]]; then
        chmod +x sk5.sh
        echo "运行 sk5.sh 脚本中，请稍候..."
        ./sk5.sh
        echo "sk5 安装脚本已运行完成！"
    else
        echo "下载 sk5.sh 文件失败，请检查下载链接是否正确！"
    fi
    ;;
3)
    echo "正在安装 l2tp..."
    L2TP_SCRIPT_URL="https://github.com/55620/bot/raw/refs/heads/main/bangdingip/1.sh"

    echo "下载并运行 l2tp 安装脚本..."
    wget -O 1.sh $L2TP_SCRIPT_URL
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
