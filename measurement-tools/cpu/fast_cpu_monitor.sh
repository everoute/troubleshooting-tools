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
PERF_THRESHOLD=0  # CPU utilization threshold, 0 means always show

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

show_help() {
    cat << EOF
Fast CPU Monitor - High Performance CPU Usage Monitoring

Usage: $0 -c <cpus> -i <interval> [-k <topk>] [-t <threshold>] [-l] [--log-file <file>]

Options:
  -c, --cpus <cpus>      Target CPUs (comma-separated), e.g., 50,51,52
  -i, --interval <sec>   Monitoring interval in seconds (default: 2)
  -k, --topk <num>       Number of top processes to show (default: 5)
  -t, --threshold <pct>  CPU utilization threshold (default: 0, always show processes)
  -l, --log              Enable logging
  --log-file <file>      Log file path
  -h, --help             Show this help

Examples:
  $0 -c 50,51,52 -i 2 -k 5
  $0 -c 0-3 -i 5 -k 10 -t 80  # Only show processes when CPU > 80%
  $0 -c 0-3 -i 2 -k 5 -l

Implementation:
  - Uses mpstat for accurate CPU utilization measurement
  - Uses pidstat for per-process CPU usage monitoring
  - Filters processes by CPU column
  - Real-time monitoring with interval-based averaging
  - Conditional process output based on CPU utilization threshold

Dependencies:
  - mpstat (from sysstat package)
  - pidstat (from sysstat package)
  - bc (for calculations)

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

# Check if required commands are available
check_dependencies() {
    if ! command -v mpstat >/dev/null 2>&1; then
        echo -e "${RED}Error: mpstat not found. Please install sysstat package.${NC}"
        exit 1
    fi

    if ! command -v pidstat >/dev/null 2>&1; then
        echo -e "${RED}Error: pidstat not found. Please install sysstat package.${NC}"
        exit 1
    fi

    if ! command -v bc >/dev/null 2>&1; then
        echo -e "${RED}Error: bc (calculator) not found. Please install bc package.${NC}"
        exit 1
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

# Read CPU usage using mpstat
get_cpu_usage_with_mpstat() {
    local target_cpus="$1"
    local interval="$2"

    # Use mpstat to get CPU usage for specific CPUs
    # Format CPU list for mpstat: 3,5,7,9 or 0-3
    local cpu_list=$(echo "$target_cpus" | tr ' ' ',')

    declare -A cpu_usage_map

    # Run mpstat ONCE for all target CPUs
    # mpstat -P 3,5,7,9 2 1 will monitor all specified CPUs for 2 seconds
    local mpstat_output=$(mpstat -P "$cpu_list" "$interval" 1 2>/dev/null | grep -E "^[0-9]+" | grep -v "^CPU$")

    while read -r line; do
        if [ -n "$line" ]; then
            # Extract CPU number and idle percentage
            local cpu_num=$(echo "$line" | awk '{print $2}')
            local idle=$(echo "$line" | awk '{print $NF}')

            if [ -n "$cpu_num" ] && [ -n "$idle" ] && [[ "$idle" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
                # Calculate CPU usage as 100 - idle%
                local usage=$(echo "100 - $idle" | bc -l)
                cpu_usage_map[$cpu_num]=$(echo "$usage" | awk '{printf "%.1f", $1}')
            fi
        fi
    done <<< "$mpstat_output"

    # Return the associative array as a string
    for cpu in $target_cpus; do
        printf "%s:%s " "$cpu" "${cpu_usage_map[$cpu]:-0.0}"
    done
}

# Process pidstat output to extract top-K processes for each CPU
process_pidstat_output() {
    local target_cpus="$1"
    local topk="$2"
    local threshold="$3"
    local mpstat_result="$4"
    local pidstat_output_file="$5"

    # Process each CPU separately
    for cpu in $target_cpus; do
        # Get CPU usage from mpstat result for this CPU
        local cpu_usage=$(echo "$mpstat_result" | awk -F" |:" '{for(i=1;i<=NF;i++) if ($i == "'"$cpu"'") {print $(i+1); exit}}' || echo "0.0")

        # Skip if CPU usage is below threshold (unless threshold is 0)
        if [ -n "$threshold" ] && [[ "$threshold" =~ ^[0-9]+([.][0-9]+)?$ ]] && [ "$(echo "$threshold > 0" | bc -l | tr -d '\n')" -eq 1 ] && [ "$(echo "$cpu_usage < $threshold" | bc -l | tr -d '\n')" -eq 1 ]; then
            # Create empty file (so the script knows we processed this CPU)
            > "/tmp/fast_cpu_monitor_$$_cpu${cpu}"
            continue
        fi

        # Filter lines for this CPU, with improved column detection
        # Different pidstat versions have different output formats:
        # Format 1 (el7, 4.19.90): Time UID PID %usr %system %guest    %CPU CPU Command
        # Format 2 (oe1, 5.10.0): Time UID PID %usr %system %guest %wait %CPU CPU Command
        # The key difference is the %wait column which appears in newer kernels
        # Strategy: Scan header line to find column positions by name
        awk -v target_cpu="$cpu" -v topk="$topk" '
        BEGIN {
            count = 0
            cpu_col = 0
            cpu_usage_col = 0
            pid_col = 0
            command_col = 0
            uid_col = 0
            format_detected = 0
        }
        {
            # Auto-detect format based on header line (look for UID and Command)
            if ($0 ~ /UID/ && $0 ~ /Command/ && !format_detected) {
                # Find column positions by scanning header fields for exact column names
                for (i = 1; i <= NF; i++) {
                    if ($i == "UID") uid_col = i
                    if ($i == "PID") pid_col = i
                    if ($i == "%CPU") cpu_usage_col = i
                    if ($i == "CPU") cpu_col = i
                    if ($i == "Command") command_col = i
                }

                format_detected = 1
                next  # Skip header line
            }

            # Skip if format not detected yet
            if (!format_detected) {
                next
            }

            # Skip non-process lines (UID must be numeric, skip average lines, etc.)
            if ($(uid_col) !~ /^[0-9]+$/ || NF < 8) {
                next
            }

            # Extract values from detected column positions
            pid = $(pid_col)
            cpu_usage = $(cpu_usage_col) + 0
            cpu_num = $(cpu_col)

            # Build command string (combine all remaining fields from command_col)
            # Command may contain spaces, so we need to rebuild it properly
            command = $(command_col)
            for (i = command_col + 1; i <= NF; i++) {
                command = command " " $i
            }

            # Remove trailing spaces from command
            gsub(/^[ \t]+|[ \t]+$/, "", command)
            gsub(/  +/, " ", command)

            # Only process if this process is on target CPU and has significant CPU usage
            # Also validate that cpu_num is numeric
            if (cpu_num == target_cpu && cpu_usage > 0.1) {
                # Store in arrays for sorting
                pids[count] = pid
                cpu_usages[count] = cpu_usage
                commands[count] = command
                cpu_nums[count] = cpu_num
                count++
            }
        }
        END {
            # Sort by CPU usage (descending) and print top-K
            for (i = 0; i < count; i++) {
                for (j = i + 1; j < count; j++) {
                    if (cpu_usages[j] > cpu_usages[i]) {
                        # Swap CPU usage
                        temp_usage = cpu_usages[i]
                        cpu_usages[i] = cpu_usages[j]
                        cpu_usages[j] = temp_usage

                        # Swap PID
                        temp_pid = pids[i]
                        pids[i] = pids[j]
                        pids[j] = temp_pid

                        # Swap command
                        temp_cmd = commands[i]
                        commands[i] = commands[j]
                        commands[j] = temp_cmd

                        # Swap CPU num
                        temp_cpu = cpu_nums[i]
                        cpu_nums[i] = cpu_nums[j]
                        cpu_nums[j] = temp_cpu
                    }
                }
            }

            # Print top-K
            limit = (count < topk) ? count : topk
            for (i = 0; i < limit; i++) {
                tid = pids[i]  # pidstat doesn show TID by default, use PID as TID
                printf "%6d %6d %3d %6.1f %-20s\n", pids[i], tid, cpu_nums[i], cpu_usages[i], commands[i]
            }
        }' "$pidstat_output_file" > "/tmp/fast_cpu_monitor_$$_cpu${cpu}"
    done
}

# Display the final report
display_report() {
    local target_cpus="$1"
    local mpstat_result="$2"
    local topk
    topk="${3:-5}"
    local threshold
    threshold="${4:-0}"
    local collection_duration="$5"

    # Parse mpstat results into associative array
    declare -A cpu_usage
    for result in $mpstat_result; do
        IFS=':' read -r cpu usage <<< "$result"
        cpu_usage[$cpu]="$usage"
    done

    # Display report header
    local current_time=$(date '+%H:%M:%S')
    echo "======== CPU Usage Report - $current_time ========"
    printf "Monitoring: %d CPUs, Interval: %.1fs, Collection Time: %.2fs" \
        $(echo "$target_cpus" | wc -w) "$interval" "$collection_duration"

    # Show threshold if set
    if [ "$(echo "$threshold > 0" | bc -l | tr -d '\n')" -eq 1 ]; then
        printf ", Threshold: %.0f%%" "$threshold"
    fi
    echo ""
    echo ""

    # Display CPU usages and conditional process details
    for cpu in $target_cpus; do
        local usage="${cpu_usage[$cpu]:-0.0}"

        # Color code based on usage
        local color="$NC"
        if [ "$(echo "$usage > 80" | bc -l | tr -d '\n')" -eq 1 ]; then
            color="$RED"
        elif [ "$(echo "$usage > 50" | bc -l | tr -d '\n')" -eq 1 ]; then
            color="$YELLOW"
        else
            color="$GREEN"
        fi

        printf "${color}CPU %3d: %6.1f%%${NC}\n" "$cpu" "$usage"

        # Only show processes if threshold is exceeded or threshold is 0
        local show_processes=true
        if [ "$(echo "$threshold > 0" | bc -l | tr -d '\n')" -eq 1 ] && [ "$(echo "$usage < $threshold" | bc -l | tr -d '\n')" -eq 1 ]; then
            show_processes=false
        fi

        # Display top-k processes if conditions met
        local process_file="/tmp/fast_cpu_monitor_$$_cpu${cpu}"
        if [ "$show_processes" = true ] && [ -f "$process_file" ] && [ -s "$process_file" ]; then
            printf "  %6s %6s %3s %6s %-20s\n" "PID" "TID" "CPU" "%CPU" "COMMAND"
            printf "  %6s %6s %3s %6s %-20s\n" "-----" "------" "---" "------" "--------------------"
            cat "$process_file" | sed 's/^/  /'
            echo ""
        else
            echo ""
        fi

        rm -f "$process_file"
    done

    echo "========================================================================"
}

# Main monitoring loop
start_monitoring() {
    local target_cpus="$1"
    local topk="$2"
    local interval="$3"
    local threshold="$4"

    log_message "========================================================================"
    log_message "Fast CPU Monitor Started"
    log_message "Target CPUs: [$(echo $target_cpus | tr ' ' ',')]"
    log_message "Interval: ${interval}s, Top-K: ${topk}, Threshold: ${threshold}%"
    log_message "========================================================================"
    echo ""

    trap 'echo ""; log_message "Stopping monitor..."; cleanup; log_message "Monitor stopped"; exit 0' INT TERM

    # Start monitoring loop
    while true; do
        # Record cycle start time
        local cycle_start=$(date +%s.%N)

        # Convert target_cpus list to comma-separated for mpstat
        local cpu_list=$(echo "$target_cpus" | tr ' ' ',')

        # Run mpstat and pidstat in parallel (both will run for the interval)
        local mpstat_output_file="/tmp/fast_cpu_monitor_$$_mpstat"
        local pidstat_output_file="/tmp/fast_cpu_monitor_$$_pidstat"

        # Directly execute mpstat for specified CPUs (not ALL)
        # Filter: skip header lines
        mpstat -P "$cpu_list" "$interval" 1 2>/dev/null | grep -E "^((Average:)?[[:space:]]+[0-9]+|^[0-9]{2}:[0-9]{2}:[0-9]{2})" > "$mpstat_output_file" &
        local mpstat_pid=$!

        # Directly execute pidstat (no change, still ALL processes)
        pidstat -p ALL "$interval" 1 > "$pidstat_output_file" 2>/dev/null &
        local pidstat_pid=$!

        # Wait for both commands to complete
        wait $mpstat_pid
        wait $pidstat_pid

        # Parse mpstat results using awk (compatible with both output formats)
        local mpstat_result=$(awk -v target_cpus="$cpu_list" '
        BEGIN {
            # Build regex pattern for target CPUs
            pattern = "^(" target_cpus ")$"
            gsub(/,/, "|", pattern)
        }
        {
            # Detect format: if $2 is a time marker (contains ":" or "PM" or "AM"), then CPU is $3, idle is $13
            # Otherwise, CPU is $2, idle is $12 (newer format)
            if ($2 ~ /:+/ || $2 ~ /PM/ || $2 ~ /AM/) {
                # Old format: time is split across $1 and $2
                cpu_col = 3
                idle_col = 13
            } else {
                # New format: time is $1 only, CPU is $2
                cpu_col = 2
                idle_col = 12
            }

            # Check if this line contains a CPU we care about
            if ($cpu_col ~ pattern && $idle_col ~ /^[0-9]+([.][0-9]+)?$/) {
                cpu_num = $cpu_col
                idle = $idle_col
                usage = 100 - idle
                printf "%s:%.1f ", cpu_num, usage
            }
        }
        ' "$mpstat_output_file")
        # Remove trailing space
        mpstat_result="${mpstat_result% }"

        # Process pidstat output to get top-K processes
        process_pidstat_output "$target_cpus" "$topk" "$threshold" "$mpstat_result" "$pidstat_output_file"

        # Display report
        display_report "$target_cpus" "$mpstat_result" "$topk" "$threshold" "$interval"

        rm -f "$mpstat_output_file" "$pidstat_output_file"

        # Sleep to maintain interval timing
        local cycle_end=$(date +%s.%N)
        local elapsed=$(echo "$cycle_end - $cycle_start" | bc)
        local sleep_needed=$(echo "$interval - $elapsed" | bc)
        if [ "$(echo "$sleep_needed > 0" | bc -l | tr -d '\n')" -eq 1 ]; then
            sleep "$sleep_needed"
        fi
    done
}

cleanup() {
    rm -f /tmp/fast_cpu_monitor_$$_*
}

# Parse arguments
main() {
    # Check dependencies first
    check_dependencies

    local parsed_args
    parsed_args=$(getopt -o c:i:k:t:lh --long cpus:,interval:,topk:,threshold:,log,log-file:,help -n "$0" -- "$@" 2>/dev/null)

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
            -t|--threshold)
                PERF_THRESHOLD="$2"
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

    if ! [[ "$PERF_THRESHOLD" =~ ^[0-9]+([.][0-9]+)?$ ]] || [ "$PERF_THRESHOLD" -lt 0 ] || [ "$PERF_THRESHOLD" -gt 100 ]; then
        echo "Error: Invalid threshold (must be 0-100)"
        exit 1
    fi

    if [ "$LOG_ENABLED" = true ] && [ -z "$LOG_FILE" ]; then
        LOG_FILE="fast_cpu_monitor_$(date '+%Y%m%d_%H%M%S').log"
    fi

    start_monitoring "$TARGET_CPUS" "$TOPK" "$INTERVAL" "$PERF_THRESHOLD"
}

main "$@"
