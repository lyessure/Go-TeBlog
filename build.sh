#!/bin/bash
set -e

# 检查是否为 root 用户
if [ "$EUID" -ne 0 ]; then
  echo "错误: 请使用 root 权限运行此脚本 (例如: sudo ./build.sh)"
  exit 1
fi

# 获取脚本所在目录的绝对路径
CUR_DIR=$(cd $(dirname $0); pwd)

echo "工作目录: $CUR_DIR"
cd "$CUR_DIR"

# 编译前执行依赖整理
echo "执行 go mod tidy..."
go mod tidy

# 检查是否为新安装并获取初始配置
IS_NEW_INSTALL=0
if [ ! -f "$CUR_DIR/blog.sqlite" ]; then
    IS_NEW_INSTALL=1
    echo "===================================================="
    echo "       🚀 首次安装：请配置您的管理员信息"
    echo "===================================================="
    printf "请输入管理员用户名 (默认 admin): "
    read INIT_USER
    INIT_USER=${INIT_USER:-admin}
    
    printf "请输入管理员密码: "
    stty -echo
    read INIT_PASS
    stty echo
    printf "\n"
    
    if [ -z "$INIT_PASS" ]; then
        echo "错误: 密码不能为空。"
        exit 1
    fi
fi

# 编译前台
if [ -f "$CUR_DIR/main.go" ]; then
    echo "开始编译前台服务 (main.go)..."
    go build -o "$CUR_DIR/blog_app" "$CUR_DIR/main.go"
    echo "前台服务编译成功"
elif [ -f "$CUR_DIR/blog_app" ]; then
    echo "未发现 main.go，将使用现有的二进制文件 blog_app"
else
    echo "错误: 未发现 main.go 且不存在 blog_app 二进制文件"
    exit 1
fi

# 编译后台
if [ -f "$CUR_DIR/admin.go" ]; then
    echo "开始编译后台服务 (admin.go)..."
    go build -o "$CUR_DIR/admin_app" "$CUR_DIR/admin.go"
    echo "后台服务编译成功"
elif [ -f "$CUR_DIR/admin_app" ]; then
    echo "未发现 admin.go，将使用现有的二进制文件 admin_app"
else
    echo "错误: 未发现 admin.go 且不存在 admin_app 二进制文件"
    exit 1
fi

# 如果是新安装，执行初始化命令
if [ $IS_NEW_INSTALL -eq 1 ]; then
    echo "正在初始化管理员账户..."
    "$CUR_DIR/admin_app" --init-user="$INIT_USER" --init-pass="$INIT_PASS"
fi

# 检查并创建服务文件的函数
setup_service() {
    local service_name=$1
    local description=$2
    local exec_path=$3
    local service_file="/etc/systemd/system/${service_name}.service"

    if [ ! -f "$service_file" ]; then
        echo "正在创建服务文件: $service_file"
        cat <<EOF > "$service_file"
[Unit]
Description=$description
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$CUR_DIR
ExecStart=$exec_path
Restart=always
RestartSec=5
Environment=GIN_MODE=release

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable "$service_name"
    fi
}

# 确保服务存在并重启
setup_service "blog" "Go Blog Frontend Service" "$CUR_DIR/blog_app"
setup_service "blogadmin" "Go Blog Admin Service" "$CUR_DIR/admin_app"

echo "---------------------------------------"
echo "全部编译完成！"
echo "重启服务..."
systemctl restart blog
systemctl restart blogadmin
echo "全部重启完成！"

if [ $IS_NEW_INSTALL -eq 1 ]; then
    echo ""
    echo "===================================================="
    echo "       🚀 欢迎使用 Go-TeBlog 极速博客系统"
    echo "===================================================="
    echo "您的站点已成功初始化！"
    echo ""
    echo "1. 后台管理地址: http://您的域名/admin"
    echo "2. 管理员账号: $INIT_USER"
    echo "3. 管理员密码: (您在安装时设置的密码)"
    echo ""
    echo "📋 [运维建议]"
    echo "- 建议反向代理您的前端域名到 8190 端口即可。"
    echo "- 进阶设置可在后台 [系统设置] 中进行微调。"
    echo "===================================================="
fi
