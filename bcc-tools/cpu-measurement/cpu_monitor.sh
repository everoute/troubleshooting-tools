#!/bin/bash

# CPU 监控器 - 监控指定 CPU 及其超线程组的利用率和进程信息

# 默认参数
DEFAULT_INTERVAL=5
DEFAULT_LOG_ENABLED=false
DEFAULT_PERF_THRESHOLD=0          # 默认关闭 perf 功能

# 全局变量
TARGET_CPUS=""
MONITOR_CPUS=""
INTERVAL=$DEFAULT_INTERVAL
LOG_ENABLED=$DEFAULT_LOG_ENABLED
LOG_FILE=""
PERF_THRESHOLD=$DEFAULT_PERF_THRESHOLD
PERF_OUTPUT_DIR=""

# 监控常量
MAX_PROCESSES_PER_CPU=5       # 每个CPU显示的最大进程数

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# perf 相关变量 - 使用文件存储状态以避免关联数组问题
PERF_STATE_DIR="/tmp/cpu_monitor_$$"

# 显示帮助信息
show_help() {
    cat << EOF
CPU 监控器 - 监控指定 CPU 及其超线程组的利用率和进程信息

用法: $0 [选项]

选项:
  -c, --cpus CPUS           要监控的 CPU 列表（必需），支持格式: 0,1,2 或 0-3,8-11
  -i, --interval INTERVAL   监控间隔（秒），默认 5 秒
  -l, --log                 输出到日志文件，文件名为启动时间戳
  --log-file FILE           指定日志文件路径
  -t, --threshold PERCENT   CPU 使用率阈值（%），超过时保留 perf 采样，0 表示关闭，默认 0
  --perf-output DIR         perf 输出目录，默认为 /tmp/cpu_monitor_perf
  -h, --help                显示此帮助信息

示例用法:
  $0 -c 0,1,2 -i 5
  $0 -c 0-3,8-11 -i 10 -l
  $0 -c 0,2,4,6 -i 2 --log-file cpu_monitor.log
  $0 -c 0,1 -i 5 -t 80     # CPU 使用率超过 80% 时保留并行 perf 采样结果

说明:
  - 所有CPU利用率计算均基于用户指定的监控间隔的平均值
  - 指定的目标CPU显示进程详情，超线程组其他CPU只显示整体利用率
  - 显示指定CPU上平均CPU利用率最高的前 ${MAX_PROCESSES_PER_CPU} 个进程/线程
  - 当启用 perf 功能时，每个监控周期都会并行进行 perf 采样
  - perf 采样与 CPU 监控时间完全同步，只有当周期内 CPU 使用率超过阈值时才保留结果
  - perf 采样需要 root 权限或适当的内核参数设置

EOF
}

# 日志记录函数
log_message() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_line="[$timestamp] $message"
    
    if [ "$LOG_ENABLED" = true ] && [ -n "$LOG_FILE" ]; then
        echo "$log_line" >> "$LOG_FILE"
    else
        echo "$log_line"
    fi
}

# 错误处理函数
error_exit() {
    echo -e "${RED}错误: $1${NC}" >&2
    exit 1
}

# 检查 perf 是否可用
check_perf_available() {
    if ! command -v perf >/dev/null 2>&1; then
        error_exit "perf 命令未找到，请安装 linux-perf 或 perf 包"
    fi
    
    # 检查权限
    if [ "$EUID" -ne 0 ]; then
        local paranoid_level=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "3")
        if [ "$paranoid_level" -gt 1 ]; then
            log_message "${YELLOW}警告: perf 可能需要 root 权限或调整 /proc/sys/kernel/perf_event_paranoid${NC}"
        fi
    fi
}

# 创建 perf 输出目录
create_perf_output_dir() {
    if [ -z "$PERF_OUTPUT_DIR" ]; then
        PERF_OUTPUT_DIR="/tmp/cpu_monitor_perf_$(date '+%Y%m%d_%H%M%S')"
    fi
    
    if [ ! -d "$PERF_OUTPUT_DIR" ]; then
        mkdir -p "$PERF_OUTPUT_DIR" || error_exit "无法创建 perf 输出目录: $PERF_OUTPUT_DIR"
    fi
}

# 创建状态目录
create_perf_state_dir() {
    mkdir -p "$PERF_STATE_DIR" || error_exit "无法创建状态目录: $PERF_STATE_DIR"
}

# 这些函数在新的并行采样模式下不再需要，保留空实现以防其他地方调用
is_cpu_perf_running() {
    return 1  # 始终返回false，因为我们不再维护运行状态
}

set_cpu_perf_running() {
    return 0  # 空实现，不做任何操作
}

# 启动并行 perf 采样（返回进程ID以便等待）
start_parallel_perf_sampling() {
    local cpu_id="$1"
    local duration="$2"
    local timestamp="$3"
    
    local perf_output_file="$PERF_OUTPUT_DIR/perf_cpu${cpu_id}_${timestamp}.data"
    
    # 后台启动 perf 采样，返回进程ID
    (
        # perf 采样命令 - 使用 DWARF 调用图以获得更好的符号解析
        # --call-graph dwarf: 使用DWARF调试信息重建调用栈，比fp更准确
        # -F 1000: 设置采样频率为1000Hz，平衡精度和性能
        # --buildid-all: 收集所有进程的build-id，改善符号解析
        sudo perf record --call-graph fp -F 1000 --buildid-all -C "$cpu_id" -o "$perf_output_file" -- sleep "$duration" >/dev/null 2>&1
    ) &
    
    echo $!  # 返回后台进程ID
}

# 处理 perf 采样结果（保留或删除）
process_perf_results() {
    local cpu_id="$1"
    local timestamp="$2"
    local cpu_usage="$3"
    local perf_pid="$4"
    
    local perf_output_file="$PERF_OUTPUT_DIR/perf_cpu${cpu_id}_${timestamp}.data"
    local perf_report_file="$PERF_OUTPUT_DIR/perf_cpu${cpu_id}_${timestamp}.txt"
    
    # 等待 perf 采样完成
    wait "$perf_pid" 2>/dev/null
    
    # 转换为浮点数进行比较
    local usage_float=$(echo "$cpu_usage" | sed 's/,/./g')
    
    # 检查是否超过阈值
    if awk "BEGIN {exit !($usage_float >= $PERF_THRESHOLD)}"; then
        # CPU 使用率超过阈值，保留 perf 结果并生成报告
        if [ -f "$perf_output_file" ]; then
            {
                echo "======== CPU $cpu_id Performance Report - $(date) ========"
                echo "监控周期 CPU 使用率: ${cpu_usage}% (阈值: ${PERF_THRESHOLD}%)"
                echo "采样时间: ${INTERVAL} 秒"
                echo "数据文件: $perf_output_file"
                echo ""
                echo "======== Top Functions ========"
                perf report -i "$perf_output_file" --stdio --sort=overhead,symbol -n --no-demangle --show-nr-samples 2>/dev/null | head -30
                echo ""
                echo "======== Call Graph (Top 10) ========"
                perf report -i "$perf_output_file" --stdio -g --sort=overhead --no-demangle --call-graph=graph,0.5,caller 2>/dev/null | head -50
                echo ""
                echo "======== Detailed Call Graph with Source Info ========"
                perf report -i "$perf_output_file" --stdio -g --sort=overhead,srcline --call-graph=fractal,0.5 --no-demangle 2>/dev/null | head -30
            } > "$perf_report_file"
            
            log_message "${GREEN}✅ CPU $cpu_id 使用率 ${cpu_usage}% 超过阈值，perf 结果已保存: $perf_report_file${NC}"
        else
            log_message "${RED}❌ CPU $cpu_id perf 采样数据文件不存在${NC}"
        fi
    else
        # CPU 使用率未超过阈值，删除 perf 结果
        rm -f "$perf_output_file" 2>/dev/null
        log_message "${BLUE}🗑️ CPU $cpu_id 使用率 ${cpu_usage}% 未超过阈值 ${PERF_THRESHOLD}%，已删除 perf 数据${NC}"
    fi
}

# 检查是否需要对指定CPU进行perf采样（仅针对目标CPU）
should_perf_cpu() {
    local cpu_id="$1"
    
    # 如果未启用 perf 功能，返回false
    if [ "$PERF_THRESHOLD" -eq 0 ]; then
        return 1
    fi
    
    # 只对用户明确指定的目标CPU进行 perf 采样
    if echo " $TARGET_CPUS " | grep -q " $cpu_id "; then
        return 0
    else
        return 1
    fi
}

# 清理状态目录
cleanup_perf_state() {
    if [ -n "$PERF_STATE_DIR" ] && [ -d "$PERF_STATE_DIR" ]; then
        rm -rf "$PERF_STATE_DIR"
    fi
}

# 解析 CPU 列表
parse_cpu_list() {
    local cpu_str="$1"
    local cpus=""
    
    # 替换逗号为空格
    cpu_str=${cpu_str//,/ }
    
    for part in $cpu_str; do
        if [[ "$part" == *-* ]]; then
            # 处理范围，如 0-3
            local start_cpu=${part%-*}
            local end_cpu=${part#*-}
            for ((i=start_cpu; i<=end_cpu; i++)); do
                cpus="$cpus $i"
            done
        else
            # 单个 CPU
            cpus="$cpus $part"
        fi
    done
    
    echo "$cpus"
}

# 获取系统 CPU 数量
get_cpu_count() {
    # 尝试多种方法获取 CPU 数量，取最大值
    local cpu_count=0
    
    # 方法1: 使用 nproc
    if command -v nproc >/dev/null 2>&1; then
        local nproc_count=$(nproc 2>/dev/null || echo "0")
        [ "$nproc_count" -gt "$cpu_count" ] && cpu_count=$nproc_count
    fi
    
    # 方法2: 从 /proc/cpuinfo 计算
    if [ -f /proc/cpuinfo ]; then
        local cpuinfo_count=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null || echo "0")
        [ "$cpuinfo_count" -gt "$cpu_count" ] && cpu_count=$cpuinfo_count
    fi
    
    # 方法3: 使用 lscpu
    if command -v lscpu >/dev/null 2>&1; then
        local lscpu_count=$(lscpu 2>/dev/null | grep "^CPU(s):" | awk '{print $2}' || echo "0")
        [ "$lscpu_count" -gt "$cpu_count" ] && cpu_count=$lscpu_count
    fi
    
    # 方法4: 检查 /sys/devices/system/cpu/ 目录
    if [ -d /sys/devices/system/cpu ]; then
        local sys_count=$(ls -1d /sys/devices/system/cpu/cpu[0-9]* 2>/dev/null | wc -l || echo "0")
        [ "$sys_count" -gt "$cpu_count" ] && cpu_count=$sys_count
    fi
    
    # 如果所有方法都失败，默认返回 1
    [ "$cpu_count" -eq 0 ] && cpu_count=1
    
    echo "$cpu_count"
}

# 验证 CPU 编号
validate_cpus() {
    local cpus="$1"
    local max_cpu=$(($(get_cpu_count) - 1))
    
    for cpu in $cpus; do
        if ! [[ "$cpu" =~ ^[0-9]+$ ]] || [ "$cpu" -lt 0 ] || [ "$cpu" -gt "$max_cpu" ]; then
            error_exit "无效的 CPU 编号 $cpu，系统 CPU 范围: 0-$max_cpu"
        fi
    done
}

# 获取 CPU 拓扑信息
get_cpu_topology() {
    local target_cpus="$1"
    local monitored_cpus=""
    
    # 为每个目标 CPU 找到其超线程兄弟
    for cpu in $target_cpus; do
        local siblings_file="/sys/devices/system/cpu/cpu${cpu}/topology/thread_siblings_list"
        if [ -f "$siblings_file" ]; then
            local siblings=$(cat "$siblings_file" 2>/dev/null)
            if [ -n "$siblings" ]; then
                # 解析兄弟线程列表
                local sibling_cpus=$(parse_cpu_list "$siblings")
                monitored_cpus="$monitored_cpus $sibling_cpus"
            else
                monitored_cpus="$monitored_cpus $cpu"
            fi
        else
            monitored_cpus="$monitored_cpus $cpu"
        fi
    done
    
    # 去重并排序
    echo "$monitored_cpus" | tr ' ' '\n' | sort -n | uniq | tr '\n' ' '
}

# 读取 CPU 统计信息
read_cpu_stats() {
    local cpu_id="$1"
    
    if [ "$cpu_id" = "all" ]; then
        grep "^cpu " /proc/stat | awk '{print $2, $3, $4, $5, $6, $7, $8}'
    else
        grep "^cpu${cpu_id} " /proc/stat | awk '{print $2, $3, $4, $5, $6, $7, $8}'
    fi
}

# 计算 CPU 使用率
calculate_cpu_usage() {
    local prev_stats="$1"
    local curr_stats="$2"
    
    if [ -z "$prev_stats" ] || [ -z "$curr_stats" ]; then
        echo "0.00"
        return
    fi
    
    # 解析统计数据
    read -r prev_user prev_nice prev_system prev_idle prev_iowait prev_irq prev_softirq <<< "$prev_stats"
    read -r curr_user curr_nice curr_system curr_idle curr_iowait curr_irq curr_softirq <<< "$curr_stats"
    
    # 计算差值
    local prev_idle_total=$((prev_idle + prev_iowait))
    local curr_idle_total=$((curr_idle + curr_iowait))
    
    local prev_non_idle=$((prev_user + prev_nice + prev_system + prev_irq + prev_softirq))
    local curr_non_idle=$((curr_user + curr_nice + curr_system + curr_irq + curr_softirq))
    
    local prev_total=$((prev_idle_total + prev_non_idle))
    local curr_total=$((curr_idle_total + curr_non_idle))
    
    local total_diff=$((curr_total - prev_total))
    local idle_diff=$((curr_idle_total - prev_idle_total))
    
    if [ "$total_diff" -eq 0 ]; then
        echo "0.00"
    else
        echo "$total_diff $idle_diff" | awk '{printf "%.2f", 100 * ($1 - $2) / $1}'
    fi
}

# 读取进程的CPU时间统计信息
read_process_cpu_time() {
    local pid="$1"
    local tid="$2"
    
    # 如果是线程，读取线程的stat文件
    local stat_file="/proc/$pid/stat"
    if [ "$tid" != "$pid" ] && [ -f "/proc/$pid/task/$tid/stat" ]; then
        stat_file="/proc/$pid/task/$tid/stat"
    fi
    
    if [ ! -f "$stat_file" ]; then
        echo ""
        return
    fi
    
    # 读取第14和15字段：utime和stime（用户态和内核态CPU时间，单位：jiffies）
    awk '{print $14, $15}' "$stat_file" 2>/dev/null
}

# 获取系统时钟频率
get_system_hz() {
    # 尝试从getconf获取，如果失败则使用默认值100
    getconf CLK_TCK 2>/dev/null || echo "100"
}

# 计算进程在时间间隔内的CPU使用率
calculate_process_cpu_usage() {
    local prev_cpu_time="$1"
    local curr_cpu_time="$2"
    local time_interval="$3"  # 秒
    
    if [ -z "$prev_cpu_time" ] || [ -z "$curr_cpu_time" ] || [ -z "$time_interval" ]; then
        echo "0.00"
        return
    fi
    
    read -r prev_utime prev_stime <<< "$prev_cpu_time"
    read -r curr_utime curr_stime <<< "$curr_cpu_time"
    
    # 计算CPU时间差值（jiffies）
    local utime_diff=$((curr_utime - prev_utime))
    local stime_diff=$((curr_stime - prev_stime))
    local total_time_diff=$((utime_diff + stime_diff))
    
    # 如果时间差值为0或负数，返回0
    if [ "$total_time_diff" -le 0 ]; then
        echo "0.00"
        return
    fi
    
    # 获取系统时钟频率
    local hz=$(get_system_hz)
    
    # 计算CPU使用率：(进程CPU时间差 / 系统时钟频率) / 时间间隔 * 100
    echo "$total_time_diff $hz $time_interval" | awk '{printf "%.2f", ($1 / $2) / $3 * 100}'
}

# 获取运行在指定CPU上的进程数据（第一次采样）
collect_processes_on_cpu_start() {
    local target_cpu="$1"
    local temp_file="/tmp/cpu_monitor_$$_${target_cpu}_start"
    
    # 第一次采样：获取当前运行在指定CPU上的进程/线程
    local process_list_1=$(ps -eLo pid,tid,psr,comm --no-headers | awk -v cpu="$target_cpu" '$3 == cpu {print $1, $2, $4}')
    
    if [ -z "$process_list_1" ]; then
        return
    fi
    
    # 记录第一次CPU时间
    > "$temp_file"  # 清空文件
    
    while read -r pid tid comm; do
        local cpu_time=$(read_process_cpu_time "$pid" "$tid")
        if [ -n "$cpu_time" ]; then
            # 获取真实的进程名称
            local real_comm="$comm"
            if [ "$comm" = "CPU" ] || [ "$comm" = "kworker" ] || [[ "$comm" =~ ^kworker ]]; then
                if [ -f "/proc/$pid/cmdline" ]; then
                    local cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | head -c 30)
                    if [ -n "$cmdline" ] && [ "$cmdline" != " " ]; then
                        local main_cmd=$(echo "$cmdline" | awk '{print $1}' | sed 's/.*\///')
                        if [ -n "$main_cmd" ] && [ "$main_cmd" != "" ]; then
                            real_comm="$main_cmd"
                        fi
                    fi
                fi
            fi
            echo "${pid}|${tid}|${cpu_time}|${real_comm}" >> "$temp_file"
        fi
    done <<< "$process_list_1"
}

# 获取运行在指定CPU上的进程并计算瞬时CPU利用率（第二次采样）
calculate_processes_on_cpu_end() {
    local target_cpu="$1"
    local count=${2:-$MAX_PROCESSES_PER_CPU}
    local time_interval=${3:-$INTERVAL}
    local temp_file="/tmp/cpu_monitor_$$_${target_cpu}_start"
    
    # 检查第一次采样数据是否存在
    if [ ! -f "$temp_file" ]; then
        return
    fi
    
    # 第二次计算并输出结果
    local results=""
    while IFS='|' read -r pid tid prev_cpu_time comm; do
        # 读取第二次CPU时间
        local curr_cpu_time=$(read_process_cpu_time "$pid" "$tid")
        if [ -n "$curr_cpu_time" ] && [ -n "$prev_cpu_time" ]; then
            local cpu_usage=$(calculate_process_cpu_usage "$prev_cpu_time" "$curr_cpu_time" "$time_interval")
            # 只显示CPU使用率大于0.1%且小于等于100%的进程/线程
            if [ -n "$cpu_usage" ] && awk "BEGIN {exit !($cpu_usage > 0.1 && $cpu_usage <= 100)}"; then
                results="${results}${cpu_usage} $pid $tid $comm"$'\n'
            fi
        fi
    done < "$temp_file"
    
    # 清理临时文件
    rm -f "$temp_file"
    
    # 排序并显示前N个
    if [ -n "$results" ]; then
        echo "$results" | sort -nr | head -n "$count" | while read -r cpu_usage pid tid comm; do
            printf "%6d %6d %3d %5.1f%% %-20s\n" "$pid" "$tid" "$target_cpu" "$cpu_usage" "$comm"
        done
    fi
}

# 计算系统总 CPU 使用率（使用预采集数据）
calculate_total_cpu_usage() {
    local prev_total_stats="$1"
    local curr_total_stats="$2"
    
    local total_cpu_usage=$(calculate_cpu_usage "$prev_total_stats" "$curr_total_stats")
    echo "$total_cpu_usage"
}

# 格式化输出报告（并行perf采样版本）
format_report() {
    local monitored_cpus="$1"
    local -A cpu_usage
    local -A perf_pids  # 存储perf进程ID
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    
    # 收集所有 CPU 的使用率数据
    declare -A prev_stats curr_stats
    
    # 第一次读取（包括总CPU）
    local prev_total_stats=$(read_cpu_stats "all")
    for cpu in $monitored_cpus; do
        prev_stats[$cpu]=$(read_cpu_stats "$cpu")
    done
    
    # 为所有监控的CPU收集进程数据
    for cpu in $monitored_cpus; do
        collect_processes_on_cpu_start "$cpu"
    done
    
    # 为目标CPU启动并行perf采样（如果启用）
    if [ "$PERF_THRESHOLD" -gt 0 ]; then
        log_message "${YELLOW}🔍 开始为目标CPU并行 perf 采样 (${INTERVAL}s)${NC}"
        for cpu in $monitored_cpus; do
            if should_perf_cpu "$cpu"; then
                local perf_pid=$(start_parallel_perf_sampling "$cpu" "$INTERVAL" "$timestamp")
                perf_pids[$cpu]="$perf_pid"
            fi
        done
    fi
    
    # 等待用户指定的监控间隔
    sleep "$INTERVAL"
    
    # 第二次读取并计算使用率（包括总CPU）
    local curr_total_stats=$(read_cpu_stats "all")
    for cpu in $monitored_cpus; do
        curr_stats[$cpu]=$(read_cpu_stats "$cpu")
        cpu_usage[$cpu]=$(calculate_cpu_usage "${prev_stats[$cpu]}" "${curr_stats[$cpu]}")
    done
    
    # 处理perf采样结果（保留或删除）
    if [ "$PERF_THRESHOLD" -gt 0 ]; then
        for cpu in $monitored_cpus; do
            if should_perf_cpu "$cpu" && [ -n "${perf_pids[$cpu]}" ]; then
                process_perf_results "$cpu" "$timestamp" "${cpu_usage[$cpu]}" "${perf_pids[$cpu]}"
            fi
        done
    fi
    
    # 计算总 CPU 使用率
    local total_cpu_usage=$(calculate_total_cpu_usage "$prev_total_stats" "$curr_total_stats")
    
    echo "======== CPU 监控 - $(date '+%H:%M:%S') ========"
    
    # 显示总 CPU 使用率
    printf "总 CPU 使用率: %.1f%%\n" "$total_cpu_usage"
    echo ""
    
    # 为每个目标 CPU 及其超线程组显示详细信息
    for target_cpu in $TARGET_CPUS; do
        # 获取该 CPU 的超线程组
        local cpu_group="$target_cpu"
        local siblings_file="/sys/devices/system/cpu/cpu${target_cpu}/topology/thread_siblings_list"
        if [ -f "$siblings_file" ]; then
            local siblings=$(cat "$siblings_file" 2>/dev/null)
            if [ -n "$siblings" ]; then
                cpu_group=$(parse_cpu_list "$siblings")
            fi
        fi
        
        echo "目标 CPU $target_cpu 及其超线程组 [$cpu_group]:"
        
        for cpu in $cpu_group; do
            local usage="${cpu_usage[$cpu]:-0.00}"
            
            # 标识目标CPU和perf采样状态
            local cpu_label=""
            local perf_indicator=""
            if echo " $TARGET_CPUS " | grep -q " $cpu "; then
                cpu_label=" ${GREEN}[目标]${NC}"
                if [ "$PERF_THRESHOLD" -gt 0 ]; then
                    # 检查是否超过阈值以显示相应状态
                    local usage_float=$(echo "$usage" | sed 's/,/./g')
                    if awk "BEGIN {exit !($usage_float >= $PERF_THRESHOLD)}"; then
                        perf_indicator=" ${GREEN}[PERF已保留]${NC}"
                    else
                        perf_indicator=" ${BLUE}[PERF已删除]${NC}"
                    fi
                fi
            fi
            
            # 所有CPU都显示进程详情
            printf "  CPU %2d: %6.1f%%%s%s - 运行的进程/线程 (${INTERVAL}s平均CPU利用率):\n" "$cpu" "$usage" "$perf_indicator" "$cpu_label"
            printf "    %6s %6s %3s %5s %-20s\n" "PID" "TID" "CPU" "%CPU" "COMMAND"
            printf "    %6s %6s %3s %5s %-20s\n" "------" "------" "---" "-----" "--------------------"
            
            local process_list=$(calculate_processes_on_cpu_end "$cpu" "$MAX_PROCESSES_PER_CPU" "$INTERVAL")
            if [ -n "$process_list" ]; then
                echo "$process_list" | sed 's/^/    /'
            else
                echo "    无活跃进程"
            fi
            echo ""
        done
    done
}

# 执行一次监控周期
monitor_cycle() {
    local monitored_cpus="$1"
    local report=$(format_report "$monitored_cpus")
    log_message "$report"
}

# 开始监控
start_monitoring() {
    local monitored_cpus="$1"
    
    log_message "================================================================================"
    log_message "CPU 监控器启动"
    log_message "目标 CPU: [$(echo $TARGET_CPUS | tr ' ' ',')]"
    log_message "监控 CPU: [$(echo $monitored_cpus | tr ' ' ',')]"
    log_message "监控间隔: $INTERVAL 秒"
    log_message "CPU利用率计算间隔: $INTERVAL 秒"
    log_message "每CPU最大显示进程数: $MAX_PROCESSES_PER_CPU"
    if [ "$LOG_ENABLED" = true ] && [ -n "$LOG_FILE" ]; then
        log_message "日志文件: $LOG_FILE"
    fi
    if [ "$PERF_THRESHOLD" -gt 0 ]; then
        log_message "Perf 采样阈值: $PERF_THRESHOLD%"
        log_message "Perf 输出目录: $PERF_OUTPUT_DIR"
        log_message "✅ Perf 采样策略: 每个周期并行采样，超过阈值保留结果，仅对目标CPU采样"
    else
        log_message "Perf 采样: 已禁用"
    fi
    log_message "================================================================================"
    
    # 信号处理
    trap 'log_message ""; log_message "收到中断信号，停止监控..."; cleanup_perf_state; log_message "CPU 监控器已停止"; exit 0' INT TERM
    
    # 主监控循环
    while true; do
        local start_time=$(date +%s)
        
        monitor_cycle "$monitored_cpus"
        
        # 计算下次监控的等待时间
        local elapsed=$(($(date +%s) - start_time))
        local sleep_time=$((INTERVAL - elapsed))
        
        if [ "$sleep_time" -gt 0 ]; then
            sleep "$sleep_time"
        fi
    done
}

# 主函数
main() {
    # 检查是否支持 getopt
    if ! command -v getopt >/dev/null 2>&1; then
        error_exit "系统不支持 getopt 命令"
    fi
    
    local parsed_args
    parsed_args=$(getopt -o c:i:lt:h --long cpus:,interval:,log,log-file:,threshold:,perf-output:,help -n "$0" -- "$@" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        show_help
        exit 1
    fi
    
    eval set -- "$parsed_args"
    
    while true; do
        case "$1" in
            -c|--cpus)
                TARGET_CPUS=$(parse_cpu_list "$2")
                shift 2
                ;;
            -i|--interval)
                INTERVAL="$2"
                shift 2
                ;;
            -l|--log)
                LOG_ENABLED=true
                shift
                ;;
            --log-file)
                LOG_ENABLED=true
                LOG_FILE="$2"
                shift 2
                ;;
            -t|--threshold)
                PERF_THRESHOLD="$2"
                shift 2
                ;;
            --perf-output)
                PERF_OUTPUT_DIR="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            --)
                shift
                break
                ;;
            *)
                error_exit "未知参数: $1"
                ;;
        esac
    done
    
    # 验证必需参数
    if [ -z "$TARGET_CPUS" ]; then
        error_exit "必须指定要监控的 CPU 列表 (-c 选项)"
    fi
    
    # 验证间隔时间
    if ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] || [ "$INTERVAL" -lt 1 ]; then
        error_exit "监控间隔必须是正整数"
    fi
    
    # 验证 perf 阈值
    if ! [[ "$PERF_THRESHOLD" =~ ^[0-9]+$ ]] || [ "$PERF_THRESHOLD" -lt 0 ] || [ "$PERF_THRESHOLD" -gt 100 ]; then
        error_exit "perf 阈值必须是 0-100 之间的整数"
    fi
    
    # 验证 CPU 编号
    validate_cpus "$TARGET_CPUS"
    
    # 设置日志文件
    if [ "$LOG_ENABLED" = true ] && [ -z "$LOG_FILE" ]; then
        LOG_FILE="cpu_monitor_$(date '+%Y%m%d_%H%M%S').log"
    fi
    
    # 如果启用了 perf 功能，进行相关初始化
    if [ "$PERF_THRESHOLD" -gt 0 ]; then
        check_perf_available
        create_perf_output_dir
        create_perf_state_dir
    fi
    
    # 获取要监控的所有 CPU（包括超线程兄弟）
    MONITOR_CPUS=$(get_cpu_topology "$TARGET_CPUS")
    
    # 开始监控
    start_monitoring "$MONITOR_CPUS"
}

# 执行主函数
main "$@" 