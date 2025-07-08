#!/bin/bash

# 用途：双进程模式确保连续测量调度延迟
# 采样进程：严格按间隔启动perf记录
# 处理进程：独立处理已完成的perf数据

# 默认配置
DEFAULT_PROCESS="ovs-vswitchd"
DEFAULT_INTERVAL=1  # 默认1秒间隔
DEFAULT_LOG_FILE="sched_latency.log"
DEFAULT_MEASUREMENT_PERIOD=1  # 默认测量周期1秒
DEFAULT_VERBOSE=false  # 默认静默运行
DEFAULT_WORK_DIR="/tmp/sched_monitor_$$"  # 工作目录

# 函数：显示使用帮助
show_help() {
    echo "调度延迟监控脚本 V2 (双进程连续采样模式)"
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -p, --process PROCESS    目标进程名 (默认: $DEFAULT_PROCESS)"
    echo "  -t, --period SECONDS     测量周期长度，即每次perf运行时间 (默认: $DEFAULT_MEASUREMENT_PERIOD)"
    echo "  -i, --interval SECONDS   采样间隔秒数 (默认: $DEFAULT_INTERVAL)"
    echo "  -l, --log FILE          日志文件路径 (默认: $DEFAULT_LOG_FILE)"
    echo "  -v, --verbose           显示详细输出信息 (默认: 静默运行)"
    echo "  -h, --help              显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 -p ovs-vswitchd -t 1 -i 1    # 每1秒采样，记录1秒"
    echo "  $0 --process qemu-kvm --period 2 --interval 1  # 每1秒采样，记录2秒"
    echo "  $0 -t 1 -i 0.5 -v               # 每0.5秒采样，记录1秒，显示详细输出"
    exit 0
}

# 函数：记录带时间戳的日志
log_with_timestamp() {
    local message="$1"
    local to_stdout="${2:-false}"
    local log_line="[$(date '+%Y-%m-%d %H:%M:%S.%3N')] $message"
    
    if [ "$to_stdout" = "true" ]; then
        echo "$log_line"
    fi
}

# 函数：检查进程是否存在
check_process_exists() {
    local process_name="$1"
    local verbose="$2"
    local pid=$(pidof "$process_name")
    if [ -z "$pid" ]; then
        log_with_timestamp "错误: 进程 '$process_name' 未找到" "$verbose"
        return 1
    else
        log_with_timestamp "找到进程 '$process_name', PID: $pid" "$verbose"
        return 0
    fi
}

# 函数：检查perf命令是否可用
check_perf_available() {
    local verbose="$1"
    if ! command -v perf >/dev/null 2>&1; then
        log_with_timestamp "错误: perf命令不可用，请安装linux-tools包" "$verbose"
        exit 1
    fi
    
    # 检查perf权限
    if ! sudo perf --version >/dev/null 2>&1; then
        log_with_timestamp "错误: 无法以sudo权限运行perf命令" "$verbose"
        exit 1
    fi
}

# 函数：采样进程 - 严格按间隔启动perf记录
sampling_process() {
    local process_name="$1"
    local interval="$2"
    local measurement_period="$3"
    local work_dir="$4"
    local verbose="$5"
    
    local sample_count=0
    local next_time=$(date +%s.%N)
    
    log_with_timestamp "采样进程启动: 间隔=${interval}秒, 周期=${measurement_period}秒" "$verbose"
    
    while [ -f "$work_dir/run_flag" ]; do
        sample_count=$((sample_count + 1))
        
        # 检查进程是否存在
        if ! check_process_exists "$process_name" false; then
            log_with_timestamp "目标进程消失，采样进程退出" "$verbose"
            break
        fi
        
        local pid=$(pidof "$process_name")
        local timestamp=$(date '+%Y%m%d_%H%M%S_%3N')
        local start_epoch=$(date +%s.%N)
        local perf_data_file="$work_dir/perf_${timestamp}_${pid}_${sample_count}.data"
        local meta_file="${perf_data_file}.meta"
        
        # 创建元数据文件
        {
            echo "timestamp=$timestamp"
            echo "start_epoch=$start_epoch"
            echo "process_name=$process_name"
            echo "pid=$pid"
            echo "sample_count=$sample_count"
            echo "measurement_period=$measurement_period"
            echo "status=recording"
        } > "$meta_file"
        
        log_with_timestamp "启动第${sample_count}次采样 -> $perf_data_file" "$verbose"
        
        # 在后台启动perf记录
        {
            if sudo perf sched record -p "$pid" -o "$perf_data_file" -- sleep "$measurement_period" 2>/dev/null; then
                # 更新元数据状态为完成
                sed -i 's/status=recording/status=completed/' "$meta_file"
                log_with_timestamp "采样${sample_count}完成" "$verbose"
            else
                # 标记为失败
                sed -i 's/status=recording/status=failed/' "$meta_file"
                log_with_timestamp "采样${sample_count}失败" "$verbose"
            fi
        } &
        
        # 计算下次采样时间
        next_time=$(echo "$next_time + $interval" | bc -l)
        local current_time=$(date +%s.%N)
        local sleep_time=$(echo "$next_time - $current_time" | bc -l)
        
        # 如果需要等待，则等待到精确时间
        if (( $(echo "$sleep_time > 0" | bc -l) )); then
            sleep "$sleep_time"
        else
            log_with_timestamp "警告: 采样${sample_count}延迟了$(echo "0 - $sleep_time" | bc -l)秒" "$verbose"
            # 重新同步到下一个整数时间点
            next_time=$(date +%s.%N)
        fi
    done
    
    log_with_timestamp "采样进程退出，等待后台perf任务完成..." "$verbose"
    wait  # 等待所有后台perf任务完成
}

# 函数：处理进程 - 处理已完成的perf数据
processing_process() {
    local log_file="$1"
    local work_dir="$2"
    local verbose="$3"
    local delay_cycles="$4"
    
    log_with_timestamp "处理进程启动，延迟${delay_cycles}个周期后开始处理" "$verbose"
    
    # 等待指定的延迟周期
    sleep "$delay_cycles"
    
    # 创建日志文件头部信息
    {
        echo "# 调度延迟监控日志 V2 (连续采样模式)"
        echo "# 开始时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# 采样模式: 连续采样"
        echo "#"
    } >> "$log_file"
    
    local processed_count=0
    
    while [ -f "$work_dir/run_flag" ] || [ -n "$(find "$work_dir" -name "*.meta" -type f 2>/dev/null)" ]; do
        local found_file=false
        
        # 查找已完成的perf数据文件
        shopt -s nullglob
        for meta_file in "$work_dir"/*.meta; do
            [ -f "$meta_file" ] || continue
            
            local status=$(grep "status=" "$meta_file" | cut -d'=' -f2)
            
            if [ "$status" = "completed" ]; then
                local data_file="${meta_file%.meta}"
                
                if [ -f "$data_file" ]; then
                    found_file=true
                    processed_count=$((processed_count + 1))
                    
                    # 读取元数据
                    local timestamp=$(grep "timestamp=" "$meta_file" | cut -d'=' -f2)
                    local process_name=$(grep "process_name=" "$meta_file" | cut -d'=' -f2)
                    local pid=$(grep "pid=" "$meta_file" | cut -d'=' -f2)
                    local sample_count=$(grep "sample_count=" "$meta_file" | cut -d'=' -f2)
                    local measurement_period=$(grep "measurement_period=" "$meta_file" | cut -d'=' -f2)
                    local start_epoch=$(grep "start_epoch=" "$meta_file" | cut -d'=' -f2)
                    
                    # 格式化时间戳
                    local formatted_time=$(echo "$timestamp" | sed 's/\([0-9]\{4\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)_\([0-9]\{2\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)_\([0-9]\{3\}\)/\1-\2-\3 \4:\5:\6.\7/')
                    
                    log_with_timestamp "处理第${processed_count}个数据文件: $data_file" "$verbose"
                    
                    # 写入分割符和时间戳到日志文件
                    {
                        echo ""
                        echo "==================== 调度延迟监控周期 #${sample_count} ===================="
                        echo "时间戳: $formatted_time"
                        echo "进程名: $process_name"
                        echo "进程PID: $pid"
                        echo "测量周期: ${measurement_period}秒"
                        echo "采样序号: $sample_count"
                        echo "=============================================================="
                        echo ""
                    } >> "$log_file"
                    
                    # 执行perf sched latency并追加到日志文件
                    if sudo perf sched latency -i "$data_file" >> "$log_file" 2>/dev/null; then
                        log_with_timestamp "数据处理完成: 样本${sample_count}" "$verbose"
                    else
                        log_with_timestamp "警告: perf sched latency解析失败: 样本${sample_count}" "$verbose"
                        echo "注意: 此周期的perf sched latency解析失败" >> "$log_file"
                    fi
                    
                    # 添加周期结束标记
                    {
                        echo ""
                        echo "==================== 周期 #${sample_count} 结束 =========================="
                        echo ""
                    } >> "$log_file"
                    
                    # 删除原始文件
                    rm -f "$data_file" "$meta_file"
                    
                fi
            elif [ "$status" = "failed" ]; then
                # 清理失败的文件
                local data_file="${meta_file%.meta}"
                rm -f "$data_file" "$meta_file"
                log_with_timestamp "清理失败的采样文件" "$verbose"
            fi
        done
        
        # 如果没有找到可处理的文件，稍等一下
        if [ "$found_file" = "false" ]; then
            sleep 0.1
        fi
    done
    
    log_with_timestamp "处理进程退出，共处理${processed_count}个样本" "$verbose"
}

# 函数：信号处理
cleanup_and_exit() {
    local work_dir="$1"
    local verbose="$2"
    
    log_with_timestamp "收到停止信号，正在清理..." "$verbose"
    
    # 删除运行标志
    rm -f "$work_dir/run_flag"
    
    # 等待子进程结束
    log_with_timestamp "等待子进程结束..." "$verbose"
    wait
    
    # 清理工作目录
    if [ -d "$work_dir" ]; then
        rm -rf "$work_dir"
        log_with_timestamp "清理工作目录: $work_dir" "$verbose"
    fi
    
    log_with_timestamp "调度延迟监控已停止" "$verbose"
    exit 0
}

# 主程序开始
main() {
    # 设置默认值
    local process_name="$DEFAULT_PROCESS"
    local interval="$DEFAULT_INTERVAL"
    local log_file="$DEFAULT_LOG_FILE"
    local measurement_period="$DEFAULT_MEASUREMENT_PERIOD"
    local verbose="$DEFAULT_VERBOSE"
    local work_dir="$DEFAULT_WORK_DIR"
    
    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--process)
                process_name="$2"
                shift 2
                ;;
            -t|--period)
                measurement_period="$2"
                shift 2
                ;;
            -i|--interval)
                interval="$2"
                shift 2
                ;;
            -l|--log)
                log_file="$2"
                shift 2
                ;;
            -v|--verbose)
                verbose="true"
                shift
                ;;
            -h|--help)
                show_help
                ;;
            *)
                echo "未知选项: $1"
                echo "使用 $0 --help 查看帮助信息"
                exit 1
                ;;
        esac
    done
    
    # 验证参数
    if ! command -v bc >/dev/null 2>&1; then
        echo "错误: 需要bc命令进行精确时间计算，请安装bc包"
        exit 1
    fi
    
    if ! [[ "$interval" =~ ^[0-9]*\.?[0-9]+$ ]]; then
        echo "错误: 采样间隔必须是正数"
        exit 1
    fi
    
    if ! [[ "$measurement_period" =~ ^[0-9]*\.?[0-9]+$ ]]; then
        echo "错误: 测量周期必须是正数"
        exit 1
    fi
    
    # 检查先决条件
    check_perf_available "$verbose"
    
    # 创建工作目录
    mkdir -p "$work_dir"
    if [ ! -d "$work_dir" ]; then
        log_with_timestamp "错误: 无法创建工作目录 $work_dir" "$verbose"
        exit 1
    fi
    
    # 创建运行标志
    touch "$work_dir/run_flag"
    
    # 设置信号处理
    trap "cleanup_and_exit '$work_dir' '$verbose'" SIGINT SIGTERM
    
    log_with_timestamp "开始调度延迟连续监控" "$verbose"
    log_with_timestamp "目标进程: $process_name" "$verbose"
    log_with_timestamp "采样间隔: ${interval}秒" "$verbose"
    log_with_timestamp "测量周期: ${measurement_period}秒" "$verbose"
    log_with_timestamp "日志文件: $log_file" "$verbose"
    log_with_timestamp "工作目录: $work_dir" "$verbose"
    log_with_timestamp "按 Ctrl+C 停止监控" "$verbose"
    
    # 计算处理进程延迟周期数（确保至少延迟1.5个测量周期）
    local delay_cycles=$(echo "$measurement_period * 1.5" | bc -l)
    
    # 启动处理进程（后台）
    processing_process "$log_file" "$work_dir" "$verbose" "$delay_cycles" &
    local processor_pid=$!
    
    # 启动采样进程（前台）
    sampling_process "$process_name" "$interval" "$measurement_period" "$work_dir" "$verbose"
    
    # 等待处理进程完成
    wait $processor_pid
    
    # 清理
    cleanup_and_exit "$work_dir" "$verbose"
}

# 执行主程序
main "$@" 