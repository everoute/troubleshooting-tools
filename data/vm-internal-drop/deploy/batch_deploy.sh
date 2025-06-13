#!/bin/bash


set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 日志函数
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_debug() { echo -e "${PURPLE}[DEBUG]${NC} $1"; }

# 全局变量
CONFIG_FILE=""
BINARIES_DIR=""
DRY_RUN=false
REPORT_FILE=""
TOTAL_NODES=0
SUCCESS_COUNT=0
FAIL_COUNT=0

# 配置变量
SERVICE_NAME=""
SERVICE_FILE=""
INSTALL_SCRIPT=""

# 节点数组
declare -a NODES_DATA=()

# 架构映射
declare -A ARCH_MAPPING
ARCH_MAPPING["x86_64"]="rarp_consumer_x86_64_static rarp_consumer_static"
ARCH_MAPPING["aarch64"]="rarp_consumer_arm64_static rarp_consumer_static"
ARCH_MAPPING["armv7l"]="rarp_consumer_arm_static rarp_consumer_static"
ARCH_MAPPING["i386"]="rarp_consumer_i386_static rarp_consumer_static"
ARCH_MAPPING["i686"]="rarp_consumer_i386_static rarp_consumer_static"

# 检查依赖
check_dependencies() {
    log_info "Checking dependencies..."
    
    # 检查ssh和scp
    if ! command -v ssh >/dev/null 2>&1; then
        log_error "ssh is required but not installed"
        exit 1
    fi
    
    if ! command -v scp >/dev/null 2>&1; then
        log_error "scp is required but not installed"
        exit 1
    fi
    
    # 检查sshpass（用于密码认证）
    if ! command -v sshpass >/dev/null 2>&1; then
        log_warning "sshpass not found. Password authentication may not work."
        log_warning "Install with: sudo apt-get install sshpass"
    fi
    
    log_success "Dependencies check passed"
}

# 解析配置文件
parse_config() {
    log_info "Parsing configuration file: $CONFIG_FILE"
    
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi
    
    local stage=""
    local service_config_count=0
    local node_count=0
    
    while IFS= read -r line; do
        # 去除前后空格
        line=$(echo "$line" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
        
        # 跳过空行和注释行（但保留stage标记）
        if [ -z "$line" ]; then
            continue
        fi
        
        # 检查stage标记
        if [ "$line" = "# stage1" ]; then
            stage="service"
            continue
        elif [ "$line" = "# stage2" ]; then
            stage="nodes"
            continue
        fi
        
        # 跳过其他注释行
        if echo "$line" | grep -q "^#"; then
            continue
        fi
        
        # 解析service配置（stage1后的3行）
        if [ "$stage" = "service" ] && [ $service_config_count -lt 3 ]; then
            if echo "$line" | grep -q "="; then
                local key=$(echo "$line" | cut -d'=' -f1)
                local value=$(echo "$line" | cut -d'=' -f2- | sed 's/^"\(.*\)"$/\1/')
                
                case "$key" in
                    "service_name") SERVICE_NAME="$value" ;;
                    "service_file") SERVICE_FILE="$value" ;;
                    "install_script") INSTALL_SCRIPT="$value" ;;
                esac
                service_config_count=$((service_config_count + 1))
            fi
        fi
        
        # 解析VM配置（stage2后的所有行）
        if [ "$stage" = "nodes" ]; then
            if echo "$line" | grep -q ","; then
                NODES_DATA+=("$line")
                node_count=$((node_count + 1))
            fi
        fi
    done < "$CONFIG_FILE"
    
    TOTAL_NODES=$node_count
    
    # 验证必要配置
    if [ -z "$SERVICE_NAME" ] || [ -z "$SERVICE_FILE" ] || [ -z "$INSTALL_SCRIPT" ]; then
        log_error "Missing deployment configuration. Required: service_name, service_file, install_script"
        exit 1
    fi
    
    if [ "$TOTAL_NODES" -eq 0 ]; then
        log_error "No nodes found in configuration file"
        exit 1
    fi
    
    log_success "Configuration parsing completed"
    log_info "Found $TOTAL_NODES nodes to deploy"
    log_info "Service: $SERVICE_NAME, Script: $INSTALL_SCRIPT, Service file: $SERVICE_FILE"
}

# 验证本地文件
validate_local_files() {
    log_info "Validating local files..."
    
    # 检查二进制目录
    if [ ! -d "$BINARIES_DIR" ]; then
        log_error "Binaries directory not found: $BINARIES_DIR"
        exit 1
    fi
    
    # 检查是否有二进制文件
    if [ -z "$(ls -A "$BINARIES_DIR"/rarp_consumer* 2>/dev/null)" ]; then
        log_error "No binary files found in $BINARIES_DIR"
        exit 1
    fi
    
    # 检查必需的脚本文件
    if [ ! -f "$INSTALL_SCRIPT" ]; then
        log_error "Install script not found: $INSTALL_SCRIPT"
        exit 1
    fi
    
    # 检查服务文件
    if [ ! -f "$SERVICE_FILE" ]; then
        log_error "Service file not found: $SERVICE_FILE"
        exit 1
    fi
    
    log_success "Local files validation passed"
    log_info "Available binaries: $(ls -1 "$BINARIES_DIR"/rarp_consumer* | xargs -n1 basename | tr '\n' ' ')"
}

# SSH连接函数
ssh_connect() {
    local host="$1"
    local port="$2"
    local username="$3"
    local password="$4"
    local command="$5"
    
    if command -v sshpass >/dev/null 2>&1; then
        sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=30 -p "$port" "$username@$host" "$command"
    else
        # 假设已经配置了SSH密钥
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=30 -p "$port" "$username@$host" "$command"
    fi
}

# SCP文件传输函数
scp_upload() {
    local host="$1"
    local port="$2"
    local username="$3"
    local password="$4"
    local local_file="$5"
    local remote_path="$6"
    
    if command -v sshpass >/dev/null 2>&1; then
        sshpass -p "$password" scp -o StrictHostKeyChecking=no -P "$port" "$local_file" "$username@$host:$remote_path"
    else
        scp -o StrictHostKeyChecking=no -P "$port" "$local_file" "$username@$host:$remote_path"
    fi
}

# 检查systemd支持
check_systemd_support() {
    local host="$1"
    local port="$2"
    local username="$3"
    local password="$4"
    
    log_debug "Checking systemd support on $host" >&2
    
    # 检查systemctl命令
    if ! ssh_connect "$host" "$port" "$username" "$password" "which systemctl" >/dev/null 2>&1; then
        echo "systemctl command not found"
        return 1
    fi
    
    # 检查systemd版本
    local version_info
    version_info=$(ssh_connect "$host" "$port" "$username" "$password" "systemctl --version 2>/dev/null | head -1" 2>/dev/null)
    
    if [ -z "$version_info" ]; then
        echo "systemd not functional"
        return 1
    fi
    
    echo "$version_info"
    return 0
}

# 检测架构
detect_architecture() {
    local host="$1"
    local port="$2"
    local username="$3"
    local password="$4"
    
    log_debug "Detecting architecture on $host" >&2
    
    local arch
    arch=$(ssh_connect "$host" "$port" "$username" "$password" "uname -m" 2>/dev/null)
    
    if [ -z "$arch" ]; then
        return 1
    fi
    
    echo "$arch"
    return 0
}

# 选择合适的二进制文件
select_binary_for_arch() {
    local arch="$1"
    
    local candidates="${ARCH_MAPPING[$arch]:-rarp_consumer_static}"
    
    for candidate in $candidates; do
        if [ -f "$BINARIES_DIR/$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    
    return 1
}

# 上传文件
upload_files() {
    local host="$1"
    local port="$2"
    local username="$3"
    local password="$4"
    local binary_name="$5"
    
    log_debug "Uploading files to $host" >&2
    
    # 上传安装脚本
    if ! scp_upload "$host" "$port" "$username" "$password" "$INSTALL_SCRIPT" "/tmp/"; then
        return 1
    fi
    
    # 上传服务文件
    if ! scp_upload "$host" "$port" "$username" "$password" "$SERVICE_FILE" "/tmp/"; then
        return 1
    fi
    
    # 上传二进制文件
    if ! scp_upload "$host" "$port" "$username" "$password" "$BINARIES_DIR/$binary_name" "/tmp/"; then
        return 1
    fi
    
    # 设置脚本执行权限
    if ! ssh_connect "$host" "$port" "$username" "$password" "chmod +x /tmp/$INSTALL_SCRIPT"; then
        return 1
    fi
    
    return 0
}

# 执行部署
execute_deployment() {
    local host="$1"
    local port="$2"
    local username="$3"
    local password="$4"
    
    log_debug "Executing deployment on $host" >&2
    
    # 执行安装脚本
    if ssh_connect "$host" "$port" "$username" "$password" "cd /tmp && sudo ./$INSTALL_SCRIPT" 2>&1; then
        return 0
    else
        return 1
    fi
}

# 检查服务状态
check_service_status() {
    local host="$1"
    local port="$2"
    local username="$3"
    local password="$4"
    
    log_debug "Checking service status on $host" >&2
    
    if ssh_connect "$host" "$port" "$username" "$password" "sudo systemctl is-active $SERVICE_NAME" >/dev/null 2>&1; then
        echo "active"
        return 0
    else
        # 获取详细状态
        local status
        status=$(ssh_connect "$host" "$port" "$username" "$password" "sudo systemctl status $SERVICE_NAME --no-pager" 2>&1)
        echo "$status"
        return 1
    fi
}

# 部署到单个节点
deploy_to_node() {
    local node_index="$1"
    local node_data="$2"
    
    # 解析节点数据 (格式: ip,username,password)
    local host=$(echo "$node_data" | cut -d',' -f1)
    local username=$(echo "$node_data" | cut -d',' -f2)
    local password=$(echo "$node_data" | cut -d',' -f3)
    local port=22  # 默认端口
    local node_name="$host"  # 使用IP作为节点名
    
    local start_time=$(date +%s)
    local steps_completed=""
    local architecture=""
    local systemd_version=""
    local service_status=""
    local error_message=""
    local success=false
    
    log_info "Starting deployment to $node_name ($host)"
    
    # 1. 检查systemd支持
    if systemd_info=$(check_systemd_support "$host" "$port" "$username" "$password"); then
        systemd_version="$systemd_info"
        steps_completed="$steps_completed,systemd_support_confirmed"
        log_debug "systemd support confirmed: $systemd_version"
    else
        error_message="systemd not supported: $systemd_info"
        write_node_result "$node_index" "$node_name" "$host" "$success" "$error_message" "$steps_completed" "$architecture" "$systemd_version" "$service_status" "$start_time"
        return 1
    fi
    
    # 2. 检测架构
    if architecture=$(detect_architecture "$host" "$port" "$username" "$password"); then
        steps_completed="$steps_completed,architecture_detected"
        log_debug "Architecture detected: $architecture"
    else
        error_message="Architecture detection failed"
        write_node_result "$node_index" "$node_name" "$host" "$success" "$error_message" "$steps_completed" "$architecture" "$systemd_version" "$service_status" "$start_time"
        return 1
    fi
    
    # 3. 选择合适的二进制文件
    if binary_name=$(select_binary_for_arch "$architecture"); then
        steps_completed="$steps_completed,binary_selected"
        log_debug "Binary selected: $binary_name"
    else
        error_message="No suitable binary found for architecture $architecture"
        write_node_result "$node_index" "$node_name" "$host" "$success" "$error_message" "$steps_completed" "$architecture" "$systemd_version" "$service_status" "$start_time"
        return 1
    fi
    
    # 4. 上传文件
    if upload_files "$host" "$port" "$username" "$password" "$binary_name"; then
        steps_completed="$steps_completed,files_uploaded"
        log_debug "Files uploaded successfully"
    else
        error_message="File upload failed"
        write_node_result "$node_index" "$node_name" "$host" "$success" "$error_message" "$steps_completed" "$architecture" "$systemd_version" "$service_status" "$start_time"
        return 1
    fi
    
    # 5. 执行部署（如果不是dry-run模式）
    if [ "$DRY_RUN" = true ]; then
        steps_completed="$steps_completed,dry_run_completed"
        service_status="dry-run mode"
        success=true
        log_success "Dry-run completed for $node_name"
    else
        if execute_deployment "$host" "$port" "$username" "$password"; then
            steps_completed="$steps_completed,deployment_executed"
            log_debug "Deployment script executed"
            
            # 6. 检查服务状态
            if service_status=$(check_service_status "$host" "$port" "$username" "$password"); then
                if [ "$service_status" = "active" ]; then
                    steps_completed="$steps_completed,service_running"
                    success=true
                    log_success "Deployment to $node_name completed successfully"
                else
                    error_message="Service not running"
                fi
            else
                error_message="Service status check failed: $service_status"
            fi
        else
            error_message="Deployment execution failed"
        fi
    fi
    
    write_node_result "$node_index" "$node_name" "$host" "$success" "$error_message" "$steps_completed" "$architecture" "$systemd_version" "$service_status" "$start_time"
    
    if [ "$success" = true ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        return 0
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 1
    fi
}

# 写入节点结果到报告文件
write_node_result() {
    local node_index="$1"
    local node_name="$2"
    local host="$3"
    local success="$4"
    local error_message="$5"
    local steps_completed="$6"
    local architecture="$7"
    local systemd_version="$8"
    local service_status="$9"
    local start_time="${10}"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # 清理steps_completed（移除前导逗号）
    steps_completed="${steps_completed#,}"
    
    # 写入结果到临时文件（文本格式）
    cat >> "$REPORT_FILE.tmp" << EOF
Node: $node_name ($host)
Status: $([ "$success" = "true" ] && echo "SUCCESS" || echo "FAILED")
Architecture: $architecture
systemd Version: $systemd_version
Service Status: $service_status
Duration: ${duration}s
Steps Completed: $steps_completed
$([ -n "$error_message" ] && echo "Error: $error_message")
Start Time: $(date -d @$start_time --iso-8601=seconds)
End Time: $(date -d @$end_time --iso-8601=seconds)
----------------------------------------
EOF
}

# 部署到所有节点
deploy_all() {
    log_info "Starting batch deployment..."
    echo "============================================================"
    
    # 初始化报告文件
    REPORT_FILE="deployment_report_$(date +'%Y%m%d_%H%M%S')"
    > "$REPORT_FILE.tmp"
    
    SUCCESS_COUNT=0
    FAIL_COUNT=0
    
    # 遍历所有节点
    for i in "${!NODES_DATA[@]}"; do
        local node_data="${NODES_DATA[$i]}"
        local host=$(echo "$node_data" | cut -d',' -f1)
        
        log_info "Processing node $((i+1))/$TOTAL_NODES: $host"
        
        deploy_to_node "$i" "$node_data" || true
        
        echo "----------------------------------------"
        sleep 1  # 短暂延迟避免过快连接
    done
    
    generate_final_report
    print_summary
}

# 生成最终报告
generate_final_report() {
    local deployment_time=$(date --iso-8601=seconds)
    
    # 创建文本格式的部署报告
    cat > "$REPORT_FILE.txt" << EOF
========================================
RARP Consumer Deployment Report
========================================
Deployment Time: $deployment_time
Total Nodes: $TOTAL_NODES
Successful: $SUCCESS_COUNT
Failed: $FAIL_COUNT

========================================
Deployment Details
========================================
EOF
    
    # 添加所有节点结果
    cat "$REPORT_FILE.tmp" >> "$REPORT_FILE.txt"
    
    # 添加摘要
    cat >> "$REPORT_FILE.txt" << EOF

========================================
Summary
========================================
EOF
    
    if [ $SUCCESS_COUNT -gt 0 ]; then
        echo "✓ SUCCESSFUL DEPLOYMENTS: $SUCCESS_COUNT" >> "$REPORT_FILE.txt"
        grep -A 10 "Status: SUCCESS" "$REPORT_FILE.tmp" | grep "Node:" | sed 's/Node: /  • /' >> "$REPORT_FILE.txt"
    fi
    
    if [ $FAIL_COUNT -gt 0 ]; then
        echo "" >> "$REPORT_FILE.txt"
        echo "✗ FAILED DEPLOYMENTS: $FAIL_COUNT" >> "$REPORT_FILE.txt"
        grep -A 10 "Status: FAILED" "$REPORT_FILE.tmp" | grep "Node:" | sed 's/Node: /  • /' >> "$REPORT_FILE.txt"
    fi
    
    cat >> "$REPORT_FILE.txt" << EOF

========================================
Log Commands
========================================
View service logs:
  journalctl -u $SERVICE_NAME -f

Service management:
  systemctl status $SERVICE_NAME
  systemctl start $SERVICE_NAME
  systemctl stop $SERVICE_NAME
  systemctl restart $SERVICE_NAME
EOF
    
    # 清理临时文件
    rm -f "$REPORT_FILE.tmp"
    
    log_success "Detailed report saved to $REPORT_FILE.txt"
}

# 打印摘要
print_summary() {
    echo
    echo "============================================================"
    echo "DEPLOYMENT SUMMARY"
    echo "============================================================"
    
    log_info "Total nodes: $TOTAL_NODES"
    log_success "Successful: $SUCCESS_COUNT"
    log_error "Failed: $FAIL_COUNT"
    
    # 直接从变量显示结果
    if [ $SUCCESS_COUNT -gt 0 ]; then
        echo
        echo -e "${GREEN}✓ SUCCESSFUL DEPLOYMENTS:${NC}"
        echo "  All $SUCCESS_COUNT nodes deployed successfully"
        echo "  Services are running and enabled for auto-start"
        echo
        echo "  View logs with:"
        echo "    journalctl -u $SERVICE_NAME -f"
    fi
    
    if [ $FAIL_COUNT -gt 0 ]; then
        echo
        echo -e "${RED}✗ FAILED DEPLOYMENTS:${NC}"
        echo "  $FAIL_COUNT node(s) failed to deploy"
        echo "  Check the detailed report for error information"
    fi
    
    echo
    echo "Detailed report: $REPORT_FILE.txt"
}

# 显示帮助信息
show_help() {
    cat << EOF
RARP Consumer Batch Deployment Tool (Shell Version - No jq)

Usage: $0 <config_file> <binaries_dir> [options]

Arguments:
  config_file    配置文件路径
  binaries_dir   二进制文件目录

Options:
  --dry-run      仅验证配置，不执行部署
  -h, --help     显示帮助信息

配置文件格式:
  # 部署配置段
  service_name="rarp-consumer"
  service_file="rarp-consumer.service"
  install_script="deploy_service.sh"
  
  # 节点配置段 (ip,username,password)
  192.168.79.23,root,echken9527
  192.168.72.171,root,echken9527

Examples:
  $0 nodes_config.txt ./binaries/
  $0 nodes_config.txt ./binaries/ --dry-run

Dependencies:
  - ssh, scp (SSH tools)
  - sshpass (for password authentication, optional)

Install dependencies:
  Ubuntu/Debian: sudo apt-get install sshpass
  CentOS/RHEL:   sudo yum install sshpass

EOF
}

# 主函数
main() {
    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                if [ -z "$CONFIG_FILE" ]; then
                    CONFIG_FILE="$1"
                elif [ -z "$BINARIES_DIR" ]; then
                    BINARIES_DIR="$1"
                else
                    log_error "Too many arguments"
                    show_help
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # 检查必需参数
    if [ -z "$CONFIG_FILE" ] || [ -z "$BINARIES_DIR" ]; then
        log_error "Missing required arguments"
        show_help
        exit 1
    fi
    
    echo "========================================"
    echo "RARP Consumer Batch Deployment Tool"
    echo "========================================"
    echo
    
    if [ "$DRY_RUN" = true ]; then
        log_info "Running in dry-run mode - validating configuration only"
    fi
    
    # 执行部署流程
    check_dependencies
    parse_config
    validate_local_files
    
    if [ "$DRY_RUN" = true ]; then
        log_success "Configuration validation passed"
        exit 0
    fi
    
    deploy_all
}

# 执行主函数
main "$@" 