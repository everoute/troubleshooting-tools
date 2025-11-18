#!/bin/bash
#
# Fast CPU Monitor - Optimized for High Performance
#
# Features:
# - Single ps call for all CPUs
# - Minimal /proc reads
# - Efficient data structures
# - Fast Top-K selection
#
# Usage: ./fast_cpu_monitor.sh -c <cpus> -i <interval> [-k <topk>]
#

set -e

# Default values
INTERVAL=2
TOPK=5
TARGET_CPUS=""
LOG_ENABLED=false
LOG_FILE=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

show_help() {
    cat << EOF
Fast CPU Monitor - High Performance CPU Usage Monitoring

Usage: $0 -c <cpus> -i <interval> [-k <topk>] [-l] [--log-file <file>]

Options:
  -c, --cpus <cpus>      Target CPUs (comma-separated), e.g., 50,51,52
  -i, --interval <sec>   Monitoring interval in seconds (default: 2)
  -k, --topk <num>       Number of top processes to show (default: 5)
  -l, --log              Enable logging
  --log-file <file>      Log file path
  -h, --help             Show this help

Examples:
  $0 -c 50,51,52 -i 2 -k 5
  $0 -c 0-3 -i 5 -k 10 -l

Performance:
  - Single ps call per monitoring cycle (not per CPU)
  - Minimal /proc file system reads
  - Optimized for systems with many processes
  - Typical overhead: 1-2 seconds for 6 CPUs with 1500+ processes

EOF
}

log_message() {
    local msg="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local line="[$timestamp] $msg"

    if [ "$LOG_ENABLED" = true ] && [ -n "$LOG_FILE" ]; then
        echo "$line" >> "$LOG_FILE"
    else
        echo "$line"
    fi
}

parse_cpu_list() {
    local cpu_str="$1"
    local cpus=""

    cpu_str=${cpu_str//,/ }

    for part in $cpu_str; do
        if [[ "$part" == *-* ]]; then
            local start_cpu=${part%-*}
            local end_cpu=${part#*-}
            for ((i=start_cpu; i<=end_cpu; i++)); do
                cpus="$cpus $i"
            done
        else
            cpus="$cpus $part"
        fi
    done

    echo "$cpus"
}

# Read CPU stats from /proc/stat
read_cpu_stats() {
    local cpu_id="$1"
    grep "^cpu${cpu_id} " /proc/stat | awk '{print $2, $3, $4, $5, $6, $7, $8}'
}

# Calculate CPU usage percentage
calculate_cpu_usage() {
    local prev_stats="$1"
    local curr_stats="$2"

    if [ -z "$prev_stats" ] || [ -z "$curr_stats" ]; then
        echo "0.0"
        return
    fi

    read -r prev_user prev_nice prev_system prev_idle prev_iowait prev_irq prev_softirq <<< "$prev_stats"
    read -r curr_user curr_nice curr_system curr_idle curr_iowait curr_irq curr_softirq <<< "$curr_stats"

    local prev_idle_total=$((prev_idle + prev_iowait))
    local curr_idle_total=$((curr_idle + curr_iowait))

    local prev_non_idle=$((prev_user + prev_nice + prev_system + prev_irq + prev_softirq))
    local curr_non_idle=$((curr_user + curr_nice + curr_system + curr_irq + curr_softirq))

    local prev_total=$((prev_idle_total + prev_non_idle))
    local curr_total=$((curr_idle_total + curr_non_idle))

    local total_diff=$((curr_total - prev_total))
    local idle_diff=$((curr_idle_total - prev_idle_total))

    if [ "$total_diff" -eq 0 ]; then
        echo "0.0"
    else
        echo "$total_diff $idle_diff" | awk '{printf "%.1f", 100 * ($1 - $2) / $1}'
    fi
}

# Fast Top-K process collection using single ps call
collect_topk_processes() {
    local target_cpus="$1"
    local topk="$2"
    local interval="$3"
    local cache_file="/tmp/fast_cpu_monitor_$$_cache"

    # Create CPU list for awk
    local cpu_list=$(echo "$target_cpus" | tr ' ' '|')

    # Single ps call - capture ALL processes once
    # Format: PID TID CPU %CPU COMMAND
    ps -eLo pid,tid,psr,%cpu,comm --no-headers > "$cache_file" 2>/dev/null

    # Process data for each CPU using awk (much faster than bash loops)
    for cpu in $target_cpus; do
        # Filter and sort by CPU usage in one awk call
        awk -v cpu="$cpu" -v topk="$topk" '
            $3 == cpu && $4 > 0.1 {
                printf "%6d %6d %3d %6.1f %-20s\n", $1, $2, $3, $4, $5
            }
        ' "$cache_file" | sort -k4 -rn | head -n "$topk" > "/tmp/fast_cpu_monitor_$$_cpu${cpu}"
    done

    rm -f "$cache_file"
}

# Format and display report
format_report() {
    local target_cpus="$1"
    local topk="$2"
    local interval="$3"

    declare -A prev_stats curr_stats cpu_usage

    # Read initial CPU stats (fast - just read /proc/stat)
    for cpu in $target_cpus; do
        prev_stats[$cpu]=$(read_cpu_stats "$cpu")
    done

    # Start timer
    local start_time=$(date +%s.%N)

    # Collect top-k processes (single ps call for all CPUs)
    collect_topk_processes "$target_cpus" "$topk" "$interval"

    local collect_time=$(date +%s.%N)
    local collect_duration=$(echo "$collect_time - $start_time" | bc)

    # Sleep for remaining interval time
    local sleep_time=$(echo "$interval - $collect_duration" | bc)
    if (( $(echo "$sleep_time > 0" | bc -l) )); then
        sleep "$sleep_time"
    fi

    # Read final CPU stats
    for cpu in $target_cpus; do
        curr_stats[$cpu]=$(read_cpu_stats "$cpu")
        cpu_usage[$cpu]=$(calculate_cpu_usage "${prev_stats[$cpu]}" "${curr_stats[$cpu]}")
    done

    # Calculate total monitoring time
    local end_time=$(date +%s.%N)
    local total_duration=$(echo "$end_time - $start_time" | bc)

    # Display report
    echo "======== CPU Usage Report - $(date '+%H:%M:%S') ========"
    printf "Monitoring: %d CPUs, Interval: %.1fs, Collection Time: %.2fs\n" \
        $(echo "$target_cpus" | wc -w) "$interval" "$collect_duration"
    echo ""

    for cpu in $target_cpus; do
        local usage="${cpu_usage[$cpu]}"

        # Color code based on usage
        local color="$NC"
        if (( $(echo "$usage > 80" | bc -l) )); then
            color="$RED"
        elif (( $(echo "$usage > 50" | bc -l) )); then
            color="$YELLOW"
        else
            color="$GREEN"
        fi

        printf "${color}CPU %3d: %6.1f%%${NC}\n" "$cpu" "$usage"

        # Display top-k processes
        local process_file="/tmp/fast_cpu_monitor_$$_cpu${cpu}"
        if [ -f "$process_file" ] && [ -s "$process_file" ]; then
            printf "  %6s %6s %3s %6s %-20s\n" "PID" "TID" "CPU" "%CPU" "COMMAND"
            printf "  %6s %6s %3s %6s %-20s\n" "------" "------" "---" "------" "--------------------"
            cat "$process_file" | sed 's/^/  /'
        else
            echo "  No significant CPU usage"
        fi
        echo ""

        rm -f "$process_file"
    done

    echo "========================================================================"
}

# Main monitoring loop
start_monitoring() {
    local target_cpus="$1"
    local topk="$2"
    local interval="$3"

    log_message "========================================================================"
    log_message "Fast CPU Monitor Started"
    log_message "Target CPUs: [$(echo $target_cpus | tr ' ' ',')]"
    log_message "Interval: ${interval}s, Top-K: ${topk}"
    log_message "========================================================================"
    echo ""

    trap 'echo ""; log_message "Stopping monitor..."; cleanup; log_message "Monitor stopped"; exit 0' INT TERM

    while true; do
        format_report "$target_cpus" "$topk" "$interval" | while IFS= read -r line; do
            log_message "$line"
        done
        echo ""
    done
}

cleanup() {
    rm -f /tmp/fast_cpu_monitor_$$_*
}

# Parse arguments
main() {
    local parsed_args
    parsed_args=$(getopt -o c:i:k:lh --long cpus:,interval:,topk:,log,log-file:,help -n "$0" -- "$@" 2>/dev/null)

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
            -k|--topk)
                TOPK="$2"
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
            -h|--help)
                show_help
                exit 0
                ;;
            --)
                shift
                break
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Validate inputs
    if [ -z "$TARGET_CPUS" ]; then
        echo "Error: Must specify target CPUs (-c option)"
        show_help
        exit 1
    fi

    if ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] || [ "$INTERVAL" -lt 1 ]; then
        echo "Error: Invalid interval"
        exit 1
    fi

    if ! [[ "$TOPK" =~ ^[0-9]+$ ]] || [ "$TOPK" -lt 1 ]; then
        echo "Error: Invalid top-k value"
        exit 1
    fi

    if [ "$LOG_ENABLED" = true ] && [ -z "$LOG_FILE" ]; then
        LOG_FILE="fast_cpu_monitor_$(date '+%Y%m%d_%H%M%S').log"
    fi

    start_monitoring "$TARGET_CPUS" "$TOPK" "$INTERVAL"
}

main "$@"
