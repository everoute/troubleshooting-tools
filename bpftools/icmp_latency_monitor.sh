#!/bin/bash

# 功能：
# 1. 启动 icmp_rtt_latency.py 监控ICMP延迟
# 2. 当检测到延迟超过阈值的输出时，立即对 ovs-vswitchd 进行 perf 采样
# 3. 将 perf 结果保存到带时间戳的文件中
# 修复：使用文件锁确保perf间隔控制，添加可选report生成

set -e

ICMP_SCRIPT="./icmp_rtt_latency.py"
PERF_DURATION=5
OUTPUT_DIR="./perf_results"
LOG_FILE=""
MIN_PERF_INTERVAL=10
OVS_PID=""
PERF_TIME_FILE="/tmp/icmp_monitor_perf_time_$$"
GENERATE_REPORT=true  # 新增：是否生成perf report

ICMP_PID=""
declare -a PERF_PIDS=()

usage() {
    cat << EOF
ICMP延迟监控器 - Shell版本 (修复版)

使用方法:
  $0 --src-ip IP --dst-ip IP --phy-iface1 IFACE [选项]

必需参数:
  --src-ip IP              本地主机的主要IP地址
  --dst-ip IP              远程主机的IP地址
  --phy-iface1 IFACE       第一个物理接口

可选参数:
  --phy-iface2 IFACE       第二个物理接口
  --latency-ms NUM         延迟阈值(毫秒，默认0表示监控所有包)
  --direction DIR          ICMP跟踪方向(outgoing|incoming，默认outgoing)
  --disable-kernel-stacks  禁用内核栈跟踪
  --icmp-script PATH       icmp_rtt_latency.py脚本路径(默认$ICMP_SCRIPT)
  --perf-duration NUM      perf采样持续时间(秒，默认$PERF_DURATION)
  --perf-interval NUM      perf采样最小间隔(秒，默认$MIN_PERF_INTERVAL)
  --output-dir DIR         perf结果保存目录(默认$OUTPUT_DIR)
  --log-file FILE          ICMP监控日志文件路径(默认不保存日志)
  --no-report              不生成perf report文本文件(默认生成)
  --help                   显示此帮助信息

修复说明:
  - 使用文件锁确保perf间隔控制的原子性
  - 新增 --perf-interval 参数自定义采样间隔
  - 新增 --no-report 选项控制是否生成perf report

示例:
  sudo $0 --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \\
          --phy-iface1 eth0 --phy-iface2 eth1 \\
          --latency-ms 10 --direction outgoing \\
          --perf-duration 5 --perf-interval 15 \\
          --output-dir ./perf_results \\
          --log-file ./icmp_monitor.log --no-report
EOF
}

log() {
    echo "[$(date '+%H:%M:%S')] $1"
}

log_error() {
    echo "[$(date '+%H:%M:%S')] ERROR: $1" >&2
}

find_ovs_pid() {
    local pid
    pid=$(pgrep -f "ovs-vswitchd" 2>/dev/null | head -1)
    if [[ -n "$pid" ]]; then
        local cmdline
        cmdline=$(ps -p "$pid" -o args --no-headers 2>/dev/null)
        echo "找到 ovs-vswitchd 进程: PID=$pid, 命令行=$cmdline" >&2
        echo "$pid"
    else
        echo "警告: 未找到 ovs-vswitchd 进程，将进行系统级采样" >&2
        echo ""
    fi
}

generate_timestamp() {
    date '+%Y%m%d_%H%M%S'
}

is_high_latency_event() {
    local line="$1"
    if [[ "$line" == *"=== ICMP RTT Trace:"* ]]; then
        return 0
    fi
    return 1
}

# 使用文件锁确保 perf 间隔控制的原子性
can_run_perf() {
    local current_time
    current_time=$(date +%s)
    local lock_file="${PERF_TIME_FILE}.lock"
    
    # 使用 flock 确保原子性
    exec 200>"$lock_file"
    if ! flock -n 200; then
        return 1  # 无法获取锁，可能其他进程正在运行perf
    fi
    
    local last_perf_time=0
    if [[ -f "$PERF_TIME_FILE" ]]; then
        last_perf_time=$(cat "$PERF_TIME_FILE" 2>/dev/null || echo "0")
    fi
    
    local elapsed=$((current_time - last_perf_time))
    
    if [[ $elapsed -ge $MIN_PERF_INTERVAL ]]; then
        echo "$current_time" > "$PERF_TIME_FILE"
        exec 200>&-  # 释放锁
        return 0
    else
        exec 200>&-  # 释放锁
        return 1
    fi
}

run_perf_sampling() {
    local trigger_time="$1"
    local timestamp
    timestamp=$(generate_timestamp)
    
    local perf_cmd
    local data_file
    
    if [[ -n "$OVS_PID" ]]; then
        data_file="$OUTPUT_DIR/perf_ovs_${timestamp}.data"
        perf_cmd=(
            "perf" "record"
            "-p" "$OVS_PID"
            "-g"
            "--call-graph=dwarf"
            "-F" "1000"
            "--output" "$data_file"
            "sleep" "$PERF_DURATION"
        )
    else
        data_file="$OUTPUT_DIR/perf_system_${timestamp}.data"
        perf_cmd=(
            "perf" "record"
            "-a"
            "-g"
            "--call-graph=dwarf"
            "-F" "1000"
            "--output" "$data_file"
            "sleep" "$PERF_DURATION"
        )
    fi
    
    (
        local temp_error="/tmp/perf_error_$$"
        
        if [[ -n "$OVS_PID" ]]; then
            if ! kill -0 "$OVS_PID" 2>/dev/null; then
                return 1
            fi
        fi
        
        if "${perf_cmd[@]}" 2>"$temp_error"; then
            # 根据选项决定是否生成report
            if [[ "$GENERATE_REPORT" == "true" ]]; then
                local report_file="${data_file%.data}_report.txt"
                perf report -i "$data_file" --stdio > "$report_file" 2>/dev/null
            fi
        fi
        
        rm -f "$temp_error"
    ) &
    
    local perf_pid=$!
    PERF_PIDS+=("$perf_pid")
    
    cleanup_completed_perf_processes
}

cleanup_completed_perf_processes() {
    local new_pids=()
    for pid in "${PERF_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            new_pids+=("$pid")
        fi
    done
    PERF_PIDS=("${new_pids[@]}")
}

cleanup_processes() {
    if [[ -n "$ICMP_PID" ]] && kill -0 "$ICMP_PID" 2>/dev/null; then
        kill -TERM "$ICMP_PID" 2>/dev/null || true
        
        local count=0
        while kill -0 "$ICMP_PID" 2>/dev/null && [[ $count -lt 10 ]]; do
            sleep 0.5
            ((count++))
        done
        
        if kill -0 "$ICMP_PID" 2>/dev/null; then
            kill -KILL "$ICMP_PID" 2>/dev/null || true
        fi
    fi
    
    for pid in "${PERF_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    
    sleep 2
    for pid in "${PERF_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done
    
    PERF_PIDS=()
    
    rm -f "$PERF_TIME_FILE" "${PERF_TIME_FILE}.lock"
}

signal_handler() {
    cleanup_processes
    exit 0
}

main() {
    for arg in "$@"; do
        if [[ "$arg" == "--help" ]]; then
            usage
            exit 0
        fi
    done
    
    if [[ $EUID -ne 0 ]]; then
        echo "此程序必须以 root 权限运行" >&2
        exit 1
    fi
    
    local src_ip="" dst_ip="" phy_iface1="" phy_iface2=""
    local latency_ms="0" direction="outgoing" disable_kernel_stacks=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --src-ip)
                src_ip="$2"
                shift 2
                ;;
            --dst-ip)
                dst_ip="$2"
                shift 2
                ;;
            --phy-iface1)
                phy_iface1="$2"
                shift 2
                ;;
            --phy-iface2)
                phy_iface2="$2"
                shift 2
                ;;
            --latency-ms)
                latency_ms="$2"
                shift 2
                ;;
            --direction)
                direction="$2"
                shift 2
                ;;
            --disable-kernel-stacks)
                disable_kernel_stacks="--disable-kernel-stacks"
                shift
                ;;
            --icmp-script)
                ICMP_SCRIPT="$2"
                shift 2
                ;;
            --perf-duration)
                PERF_DURATION="$2"
                shift 2
                ;;
            --perf-interval)
                MIN_PERF_INTERVAL="$2"
                shift 2
                ;;
            --output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --log-file)
                LOG_FILE="$2"
                shift 2
                ;;
            --no-report)
                GENERATE_REPORT=false
                shift
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                echo "未知参数: $1" >&2
                usage >&2
                exit 1
                ;;
        esac
    done
    
    if [[ -z "$src_ip" || -z "$dst_ip" || -z "$phy_iface1" ]]; then
        echo "缺少必需参数" >&2
        usage >&2
        exit 1
    fi
    
    if [[ ! -f "$ICMP_SCRIPT" ]]; then
        echo "错误: 找不到 ICMP 监控脚本: $ICMP_SCRIPT" >&2
        exit 1
    fi
    
    mkdir -p "$OUTPUT_DIR"
    
    OVS_PID=$(find_ovs_pid)
    
    trap 'signal_handler' INT TERM
    
    local icmp_args=(
        "--src-ip" "$src_ip"
        "--dst-ip" "$dst_ip"
        "--phy-iface1" "$phy_iface1"
        "--latency-ms" "$latency_ms"
        "--direction" "$direction"
    )
    
    if [[ -n "$phy_iface2" ]]; then
        icmp_args+=("--phy-iface2" "$phy_iface2")
    fi
    
    if [[ -n "$disable_kernel_stacks" ]]; then
        icmp_args+=("$disable_kernel_stacks")
    fi
    
    echo "=== ICMP 延迟监控器 (修复版) ==="
    echo "ICMP 监控命令: python2 $ICMP_SCRIPT ${icmp_args[*]}"
    echo "Perf 采样时长: $PERF_DURATION 秒"
    echo "Perf 采样间隔: $MIN_PERF_INTERVAL 秒"
    echo "结果保存目录: $OUTPUT_DIR"
    if [[ -n "$LOG_FILE" ]]; then
        echo "日志文件: $LOG_FILE"
    else
        echo "日志文件: 不保存日志"
    fi
    if [[ -n "$OVS_PID" ]]; then
        echo "监控进程: ovs-vswitchd (PID: $OVS_PID)"
    else
        echo "监控范围: 系统级"
    fi
    echo "生成 Report: $GENERATE_REPORT"
    echo "=================================================="
    
    if [[ -n "$LOG_FILE" ]]; then
        > "$LOG_FILE"
    fi
    
    # 使用 tee 实现实时监控和日志保存
    if [[ -n "$LOG_FILE" ]]; then
        python2 "$ICMP_SCRIPT" "${icmp_args[@]}" 2>&1 | tee "$LOG_FILE" | while IFS= read -r line; do
            if is_high_latency_event "$line"; then
                if can_run_perf; then
                    run_perf_sampling "$(date)"
                fi
            fi
        done &
    else
        python2 "$ICMP_SCRIPT" "${icmp_args[@]}" 2>&1 | while IFS= read -r line; do
            echo "$line"
            
            if is_high_latency_event "$line"; then
                if can_run_perf; then
                    run_perf_sampling "$(date)"
                fi
            fi
        done &
    fi
    
    ICMP_PID=$!
    wait $ICMP_PID
    cleanup_processes
}

main "$@" 