#!/bin/bash


set -e

# 配置变量
SERVICE_NAME="rarp-consumer"
INSTALL_PATH="/usr/local/bin"
SERVICE_PATH="/etc/systemd/system"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否为root用户
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Please run this script as root or with sudo"
        exit 1
    fi
}

# 检查systemd支持
check_systemd() {
    print_status "Checking systemd support..."
    
    if ! command -v systemctl >/dev/null 2>&1; then
        print_error "systemctl not found. This system doesn't support systemd"
        exit 1
    fi
    
    if ! systemctl --version >/dev/null 2>&1; then
        print_error "systemd is not running or not functional"
        exit 1
    fi
    
    print_success "systemd is supported and running"
}

# 检测架构并选择合适的二进制文件
select_binary() {
    print_status "Detecting system architecture..."
    
    local arch=$(uname -m)
    print_status "Detected architecture: $arch"
    
    # 架构映射和优先级
    case $arch in
        "x86_64")
            BINARY_CANDIDATES=("rarp_consumer_x86_64_static" "rarp_consumer_static")
            ;;
        "aarch64")
            BINARY_CANDIDATES=("rarp_consumer_arm64_static" "rarp_consumer_static")
            ;;
        "armv7l")
            BINARY_CANDIDATES=("rarp_consumer_arm_static" "rarp_consumer_static")
            ;;
        "i386"|"i686")
            BINARY_CANDIDATES=("rarp_consumer_i386_static" "rarp_consumer_static")
            ;;
        *)
            BINARY_CANDIDATES=("rarp_consumer_static")
            print_warning "Unknown architecture, trying generic binary"
            ;;
    esac
    
    # 查找可用的二进制文件
    SELECTED_BINARY=""
    for candidate in "${BINARY_CANDIDATES[@]}"; do
        if [ -f "$candidate" ]; then
            SELECTED_BINARY="$candidate"
            print_success "Selected binary: $SELECTED_BINARY"
            break
        fi
    done
    
    if [ -z "$SELECTED_BINARY" ]; then
        print_error "No compatible binary found for architecture $arch"
        print_error "Available files: $(ls -1 rarp_consumer* 2>/dev/null || echo 'none')"
        exit 1
    fi
}

# 检查文件是否存在
check_files() {
    print_status "Checking required files..."
    
    select_binary
    
    if [ ! -f "$SERVICE_NAME.service" ]; then
        print_error "Service file $SERVICE_NAME.service not found in current directory"
        exit 1
    fi
    
    print_success "Required files found"
}

# 停止现有服务
stop_existing_service() {
    print_status "Stopping existing service if running..."
    
    systemctl stop $SERVICE_NAME 2>/dev/null || true
    systemctl disable $SERVICE_NAME 2>/dev/null || true
    
    print_success "Existing service stopped"
}

# 安装二进制文件
install_binary() {
    print_status "Installing binary..."
    
    mkdir -p $INSTALL_PATH
    cp "$SELECTED_BINARY" "$INSTALL_PATH/rarp_consumer_static"
    chmod +x "$INSTALL_PATH/rarp_consumer_static"
    chown root:root "$INSTALL_PATH/rarp_consumer_static"
    
    print_success "Binary installed: $INSTALL_PATH/rarp_consumer_static (from $SELECTED_BINARY)"
}

# 安装服务文件
install_service() {
    print_status "Installing service file..."
    
    cp "$SERVICE_NAME.service" "$SERVICE_PATH/$SERVICE_NAME.service"
    chown root:root "$SERVICE_PATH/$SERVICE_NAME.service"
    chmod 644 "$SERVICE_PATH/$SERVICE_NAME.service"
    
    print_success "Service file installed"
}

# 启用并启动服务
enable_service() {
    print_status "Enabling and starting service..."
    
    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    systemctl start $SERVICE_NAME
    
    print_success "Service enabled and started"
}

# 创建管理脚本
create_management_script() {
    print_status "Creating management script..."
    
    cat > /usr/local/bin/rarp-consumer-ctl << 'EOF'
#!/bin/bash
# RARP Consumer Service Management Script

SERVICE_NAME="rarp-consumer"

case "$1" in
    start)
        sudo systemctl start $SERVICE_NAME
        ;;
    stop)
        sudo systemctl stop $SERVICE_NAME
        ;;
    restart)
        sudo systemctl restart $SERVICE_NAME
        ;;
    status)
        sudo systemctl status $SERVICE_NAME
        ;;
    logs)
        sudo journalctl -u $SERVICE_NAME -f
        ;;
    enable)
        sudo systemctl enable $SERVICE_NAME
        ;;
    disable)
        sudo systemctl disable $SERVICE_NAME
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|enable|disable}"
        exit 1
        ;;
esac
EOF

    chmod +x /usr/local/bin/rarp-consumer-ctl
    chown root:root /usr/local/bin/rarp-consumer-ctl
    
    print_success "Management script created: /usr/local/bin/rarp-consumer-ctl"
}

# 检查服务状态
check_service_status() {
    print_status "Checking service status..."
    
    if systemctl is-active $SERVICE_NAME >/dev/null 2>&1; then
        print_success "Service is running"
        echo "=== Service Status ==="
        systemctl status $SERVICE_NAME --no-pager || true
    else
        print_error "Service is not running"
        echo "=== Service Status ==="
        systemctl status $SERVICE_NAME --no-pager || true
        echo "=== Recent Logs ==="
        journalctl -u $SERVICE_NAME --no-pager -n 10 || true
        exit 1
    fi
}

# 主函数
main() {
    echo "=========================================="
    echo "RARP Consumer Local Installation Script"
    echo "=========================================="
    echo
    
    check_root
    check_systemd
    check_files
    stop_existing_service
    install_binary
    install_service
    enable_service
    create_management_script
    
    echo
    print_success "Installation completed successfully!"
    echo
    
    check_service_status
    
    echo
    echo "Service management commands:"
    echo "  systemctl status rarp-consumer    # Check service status"
    echo "  systemctl start rarp-consumer     # Start service"
    echo "  systemctl stop rarp-consumer      # Stop service"
    echo "  systemctl restart rarp-consumer   # Restart service"
    echo "  journalctl -u rarp-consumer -f    # View logs"
    echo "  rarp-consumer-ctl status           # Using management script"
}

# 执行主函数
main "$@" 