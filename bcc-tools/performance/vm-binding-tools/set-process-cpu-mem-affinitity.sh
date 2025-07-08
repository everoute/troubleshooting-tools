#!/bin/bash

# 使用方法说明
usage() {
    echo "Usage: $0 [-p pattern] [-g guest_uuid] (-n node | -c cpu_list) [-h]"
    echo "Options:"
    echo "  -p pattern    Process pattern to match (e.g., vhost-1234)"
    echo "  -g guest_uuid Guest UUID (will lookup qemu process and derive vhost pattern)"
    echo "  -n node      NUMA node number (0 or 1). When provided, the script will"
    echo "               dynamically compute the available CPUs from machine.slice"
    echo "               on that NUMA node that are not used exclusively by a VM."
    echo "  -c cpu_list   Explicit CPU list to set (e.g., '0,2,4,6')."
    echo "  -h           Show help"
    echo
    echo "Examples:"
    echo "  $0 -p vhost-3355256 -n 1"
    echo "  $0 -p vhost-3355256 -c 1,3,5,7,9,11,13,15"
    echo "  $0 -g 55927405-c0ca-4bf1-b40f-f79c5c1a4bb2 -n 0"
    exit 1
}

# ----------- Helper function: expand_cpuset ------------
# This helper expands a cpuset string (e.g., "0,7,9,11-48,50-95") into individual CPU numbers.
expand_cpuset() {
    local cpuset_str="$1"
    local result=()
    local IFS=","
    for item in $cpuset_str; do
        if [[ "$item" == *"-"* ]]; then
            IFS="-" read -r start end <<< "$item"
            for ((i=start; i<=end; i++)); do
                result+=("$i")
            done
        else
            result+=("$item")
        fi
    done
    echo "${result[@]}"
}

# ----------- New helper: hex_to_cpu_list ------------
# This function receives a hexadecimal CPU mask (as output by taskset)
# and converts it to a comma-separated list of CPU numbers.
hex_to_cpu_list() {
    local hexmask="$1"
    # Remove any leading "0x" if present.
    hexmask=${hexmask/#0x/}
    local decimal_mask=$((16#$hexmask))
    local cpus=()
    for ((i=0; i<64; i++)); do
        if (( decimal_mask & (1 << i) )); then
            cpus+=("$i")
        fi
    done
    # Join the CPU numbers with commas.
    local result
    IFS=, result="${cpus[*]}"
    echo "$result"
}

# ----------- Default values and argument parsing ------------
PATTERN=""
GUEST_UUID=""
NODE=""
CPU_LIST=""

while getopts "p:g:n:c:h" opt; do
    case $opt in
        p)
            PATTERN="$OPTARG"
            ;;
        g)
            GUEST_UUID="$OPTARG"
            ;;
        n)
            NODE="$OPTARG"
            # Only accept 0 or 1 for NUMA node
            if [[ ! "$NODE" =~ ^[0-1]$ ]]; then
                echo "Error: NUMA node must be 0 or 1"
                exit 1
            fi
            ;;
        c)
            CPU_LIST="$OPTARG"
            ;;
        h)
            usage
            ;;
        \?)
            usage
            ;;
    esac
done

# ----------- Parameter verification ------------
if [ -z "$PATTERN" ] && [ -z "$GUEST_UUID" ]; then
    echo "Error: Either process pattern (-p) or guest_uuid (-g) is required."
    usage
fi

if [ -z "$NODE" ] && [ -z "$CPU_LIST" ]; then
    echo "Error: Either NUMA node (-n) or cpu_list (-c) must be specified."
    usage
fi

if [ -n "$NODE" ] && [ -n "$CPU_LIST" ]; then
    echo "Error: Cannot specify both NUMA node (-n) and cpu_list (-c)."
    usage
fi

# ----------- If guest_uuid is provided, derive the process pattern ------------
if [ -n "$GUEST_UUID" ]; then
    QEMU_PID=$(ps -ef | grep "guest=$GUEST_UUID" | grep -v pts | awk '{print $2}')
    if [ -z "$QEMU_PID" ]; then
        echo "Error: No QEMU process found for guest UUID: $GUEST_UUID"
        exit 1
    fi
    PATTERN="vhost-$QEMU_PID"
    echo "Found QEMU PID: $QEMU_PID"
    echo "Derived vhost pattern: $PATTERN"
fi

# ----------- Calculate CPU_LIST dynamically if NUMA node is specified ------------
if [ -n "$NODE" ]; then
    # Read machine.slice allowed CPUs
    MACHINE_CPUSET_FILE="/sys/fs/cgroup/cpuset/machine.slice/cpuset.cpus"
    if [ ! -f "$MACHINE_CPUSET_FILE" ]; then
        echo "Error: Cannot read $MACHINE_CPUSET_FILE"
        exit 1
    fi
    machine_cpus_str=$(cat "$MACHINE_CPUSET_FILE")
    machine_cpus=($(expand_cpuset "$machine_cpus_str"))
    
    # Traverse /sys/fs/cgroup/cpuset/machine.slice/machine-qemu* to locate VMs with exclusive CPU binding.
    declare -A exclusive_cpus
    for vm in /sys/fs/cgroup/cpuset/machine.slice/machine-qemu*; do
        if [ -d "$vm" ]; then
            vcpu0_file="$vm/vcpu0/cpuset.cpus"
            if [ -f "$vcpu0_file" ]; then
                vcpu0_cpuset=$(cat "$vcpu0_file")
                # If vcpu0's cpuset lacks a comma, assume the VM is exclusively bound to a CPU.
                if [[ "$vcpu0_cpuset" != *","* ]]; then
                    for vcpu in "$vm"/vcpu*; do
                        if [ -f "$vcpu/cpuset.cpus" ]; then
                            cpus=$(cat "$vcpu/cpuset.cpus")
                            for cpu in $(expand_cpuset "$cpus"); do
                                exclusive_cpus["$cpu"]=1
                            done
                        fi
                    done
                fi
            fi
        fi
    done

    # From machine.slice CPUs, remove those that are exclusively used 
    available=()
    for cpu in "${machine_cpus[@]}"; do
        if [ -z "${exclusive_cpus[$cpu]}" ]; then
            available+=("$cpu")
        fi
    done

    # Read the cpulist for the specified NUMA node
    NODE_FILE="/sys/devices/system/node/node${NODE}/cpulist"
    if [ ! -f "$NODE_FILE" ]; then
        echo "Error: NUMA node cpulist file $NODE_FILE does not exist"
        exit 1
    fi
    node_cpus_str=$(cat "$NODE_FILE")
    node_cpus=($(expand_cpuset "$node_cpus_str"))
    
    # Calculate the intersection of available CPUs and the CPUs of the specified NUMA node.
    intersection=()
    for cpu in "${node_cpus[@]}"; do
        for avail in "${available[@]}"; do
            if [ "$cpu" -eq "$avail" ]; then
                intersection+=("$cpu")
            fi
        done
    done

    if [ ${#intersection[@]} -eq 0 ]; then
        echo "Error: No available CPU in NUMA node $NODE"
        exit 1
    fi

    # Sort the intersection numerically and convert to a comma-separated list.
    sorted_list=$(printf "%s\n" "${intersection[@]}" | sort -n | tr '\n' ',' | sed 's/,$//')
    CPU_LIST="$sorted_list"
    
    echo "Available CPUs on NUMA node $NODE: $CPU_LIST"
fi

# ----------- Process matching and affinity setting ------------
echo "Looking for processes matching pattern: $PATTERN"
if [ -n "$NODE" ]; then
    echo "Setting affinity to NUMA node $NODE using CPUs: $CPU_LIST"
else
    echo "Setting affinity to provided CPUs: $CPU_LIST"
fi
echo "-------------------"

# Locate PIDs matching the pattern.
pids=$(ps -eo pid,cmd | grep "$PATTERN" | grep -v grep | grep -v "$0" | awk '{print $1}')

if [ -z "$pids" ]; then
    echo "No matching processes found."
    exit 1
fi

for pid in $pids; do
    cmd=$(ps -p $pid -o cmd=)
    echo "Found process: $cmd (PID: $pid)"
    
    # Verify the process is still active.
    #if ! kill -0 $pid 2>/dev/null; then
    #    echo "Process $pid no longer exists, skipping..."
    #    continue
    #fi
    
    echo "Original affinity:"
    orig_mask=$(taskset -p $pid | awk '{print $NF}')
    orig_list=$(hex_to_cpu_list "$orig_mask")
    echo "pid $pid's current affinity list: $orig_list"
    echo "pid $pid's current affinity mask: $orig_mask"
    
    echo "Setting new CPU affinity..."
    if ! taskset -pc $CPU_LIST $pid; then
        echo "Failed to set CPU affinity for PID $pid"
        continue
    fi
    
    # If a NUMA node was specified, adjust the NUMA memory policy.
    
    echo "New affinity:"
    new_mask=$(taskset -p $pid | awk '{print $NF}')
    new_list=$(hex_to_cpu_list "$new_mask")
    echo "pid $pid's new affinity list: $new_list"
    echo "pid $pid's new affinity mask: $new_mask"
    echo "-------------------"
done

