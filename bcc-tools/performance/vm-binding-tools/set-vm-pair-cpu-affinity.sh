#!/usr/bin/env bash

#set -euo pipefail
# 上面命令若导致unbound variable可暂时注释 -u
set -eo pipefail

# This script allocates exclusive CPUs for test pairs of VMs.
# Requirements:
# - All available CPUs come from machine.slice cpuset.
# - Each VM is to be allocated 4 CPUs exclusively (8 CPUs per pair).
# - Globally, at least 5 CPU cores must be reserved for other tasks.
#
# Additional requirement for each pair:
#   - vm1 -> node0, vm2 -> node1
#   - Each VM's 4 CPU prefer 2 physical cores with 2 hyperthreads each.

##########################################################################
# Global data structures
##########################################################################

# vm_allocations[vm_uuid] => "comma,separated,CPUs"
declare -A vm_allocations

# vm_numa_nodes[vm_uuid] => "0" or "1"
declare -A vm_numa_nodes

# leftover unallocated info (for vhost usage)
declare -A remaining_unallocated

# store node => free CPU list
declare -A numa_free

# sibling group maps for node0, node1
declare -A ht0=()
declare -A ht1=()

##########################################################################
# Basic Utility
##########################################################################

# expand_cpuset: e.g. "0,2,4-6" => 0 2 4 5 6
expand_cpuset() {
    local s="$1"
    local result=()
    local IFS=","
    for part in $s; do
        if [[ "$part" == *"-"* ]]; then
            local range_start range_end
            IFS="-" read -r range_start range_end <<< "$part"
            for ((i=range_start; i<=range_end; i++)); do
                result+=( "$i" )
            done
        else
            result+=( "$part" )
        fi
    done
    echo "${result[@]}"
}

# in_array val arr...
in_array() {
    local needle="$1"
    shift
    for x in "$@"; do
        if [ "$x" = "$needle" ]; then
            return 0
        fi
    done
    return 1
}

##########################################################################
# build_htgroups node assoc_array
#   - 读取 numa_free[node]，构造 "physcore" => "cA,cB" 的映射
#   - 存储到指定的关联数组（例如 ht0 或 ht1）
##########################################################################
build_htgroups() {
    local node="$1"
    local assoc_array_name="$2"

    local free_str="${numa_free[$node]:-}"
    [ -z "$free_str" ] && return
    local free_arr=( $free_str )

    # 创建全局关联数组
    eval "declare -g -A $assoc_array_name"

    for cpu in "${free_arr[@]}"; do
        local topo_file="/sys/devices/system/cpu/cpu${cpu}/topology/thread_siblings_list"
        local group_key
        if [ ! -f "$topo_file" ]; then
            # 单线程
            group_key="$cpu"
        else
            local sib_str
            sib_str=$(cat "$topo_file")
            local sib_arr=()
            # 展开类似 "0,2,4-6" 的 CPU 集合
            sib_arr=( $(expand_cpuset "$sib_str") )
            local grp=()
            for s in "${sib_arr[@]}"; do
                in_array "$s" "${free_arr[@]}" && grp+=( "$s" )
            done
            # 将 grp 数组排序，避免排序时使用内联 IFS（这会导致局部变量声明出错）
            local sorted=( $(printf "%s\n" "${grp[@]}" | sort -n) )
            group_key=$(echo "${sorted[*]}" | tr ' ' ',')
        fi

        # 先声明 exists，再通过 eval 从关联数组中取出值
        local exists
        eval "exists=\${$assoc_array_name[\"\$group_key\"]+x}"
        if [ -z "$exists" ]; then
            eval "$assoc_array_name[\"\$group_key\"]=\$cpu"
        fi
    done
}

##########################################################################
# get_sibling_pairs_for_node node => echo "cA-cB cX-cY ..."
#   each cA-cB is a 2-thread physical core
##########################################################################
get_sibling_pairs_for_node() {
    local node="$1"
    local free_str="${numa_free[$node]:-}"
    [ -z "$free_str" ] && { echo ""; return; }
    local free_arr=( $free_str )
    # quick lookup
    declare -A free_lookup=()
    for c in "${free_arr[@]}"; do
        free_lookup["$c"]=1
    done

    local pairs=()
    if [ "$node" = "0" ]; then
        [ "${#ht0[@]}" -eq 0 ] && { echo ""; return; }
        for key in "${!ht0[@]}"; do
            IFS=',' read -ra grp <<< "$key"
            if [ "${#grp[@]}" -eq 2 ]; then
                local cA="${grp[0]}"
                local cB="${grp[1]}"
                if [[ -n "${free_lookup[$cA]:-}" && -n "${free_lookup[$cB]:-}" ]]; then
                    pairs+=( "$cA-$cB" )
                fi
            fi
        done
    else
        [ "${#ht1[@]}" -eq 0 ] && { echo ""; return; }
        for key in "${!ht1[@]}"; do
            IFS=',' read -ra grp <<< "$key"
            if [ "${#grp[@]}" -eq 2 ]; then
                local cA="${grp[0]}"
                local cB="${grp[1]}"
                if [[ -n "${free_lookup[$cA]:-}" && -n "${free_lookup[$cB]:-}" ]]; then
                    pairs+=( "$cA-$cB" )
                fi
            fi
        done
    fi

    echo "${pairs[@]}"
}

##########################################################################
# allocate_2_cores_on_node node => tries to pick 2 sibling pairs => 4 CPU
#   if not enough, fallback pick any 4 from numa_free[node]
# returns via global array TEMP_ALLOC4
##########################################################################
declare -a TEMP_ALLOC4=()

allocate_2_cores_on_node() {
    local node="$1"

    TEMP_ALLOC4=()  # clear

    local pairs_str
    pairs_str=$(get_sibling_pairs_for_node "$node")
    if [ -n "$pairs_str" ]; then
        # convert to array
        local pairs=()
        # shellcheck disable=SC2206
        pairs=( $pairs_str )
        if [ "${#pairs[@]}" -ge 2 ]; then
            # pick first 2 => 4 CPU
            local selected=( "${pairs[@]:0:2}" )
            local cpus=()
            for core in "${selected[@]}"; do
                local cA="${core%-*}"
                local cB="${core#*-}"
                cpus+=( "$cA" "$cB" )
            done
            # remove them from numa_free[node]
            local free_str="${numa_free[$node]:-}"
            [ -z "$free_str" ] && return 1
            local arr=( $free_str )
            local updated=()
            for c in "${arr[@]}"; do
                local skip=0
                for x in "${cpus[@]}"; do
                    if [ "$c" = "$x" ]; then
                        skip=1
                        break
                    fi
                done
                [ "$skip" -eq 0 ] && updated+=( "$c" )
            done
            numa_free["$node"]="${updated[*]}"
            TEMP_ALLOC4=( "${cpus[@]}" )
            return 0
        fi
    fi

    # fallback => pick any 4 CPU from free
    local free_str="${numa_free[$node]:-}"
    [ -z "$free_str" ] && return 1
    local arr=( $free_str )
    if [ "${#arr[@]}" -lt 4 ]; then
        return 1
    fi
    TEMP_ALLOC4=( "${arr[@]:0:4}" )
    local leftover=( "${arr[@]:4}" )
    numa_free["$node"]="${leftover[*]}"
    return 0
}

##########################################################################
# allocate_pair => each pair => vm1 -> node0, vm2 -> node1
#   each needs 4 CPU => call allocate_2_cores_on_node
##########################################################################
allocate_pair() {
    local line="$1"
    local idx="$2"
    local total="$3"

    read -r vm1 vm2 <<< "$line"

    echo "------------------------------------------------------"
    echo "VM Pair: $vm1 and $vm2 (Pair $idx/$total)"
    echo "  -> vm1 on node0, vm2 on node1 (4 CPU each, 2-core preference)"

    # allocate 4 CPU for vm1 from node0
    if ! allocate_2_cores_on_node 0; then
        echo "Error: Not enough CPU on node0 for VM $vm1" >&2
        exit 1
    fi
    local vm1_cpus=( "${TEMP_ALLOC4[@]}" )

    # allocate 4 CPU for vm2 from node1
    if ! allocate_2_cores_on_node 1; then
        echo "Error: Not enough CPU on node1 for VM $vm2" >&2
        exit 1
    fi
    local vm2_cpus=( "${TEMP_ALLOC4[@]}" )

    echo "  $vm1 => ${vm1_cpus[*]}"
    echo "  $vm2 => ${vm2_cpus[*]}"

    # store
    local s1; s1=$(IFS=,; echo "${vm1_cpus[*]}")
    local s2; s2=$(IFS=,; echo "${vm2_cpus[*]}")
    vm_allocations["$vm1"]="$s1"
    vm_allocations["$vm2"]="$s2"
    vm_numa_nodes["$vm1"]="0"
    vm_numa_nodes["$vm2"]="1"
}

##########################################################################
# allocate_pair_same_node => each pair => both VMs on same node
#   each needs 4 CPU => call allocate_2_cores_on_node twice on same node
#   different pairs alternate between node0 and node1
##########################################################################
allocate_pair_same_node() {
    local line="$1"
    local idx="$2"
    local total="$3"
    
    # 根据idx决定使用哪个NUMA节点，偶数idx用node0，奇数idx用node1
    local node=$((idx % 2))

    read -r vm1 vm2 <<< "$line"

    echo "------------------------------------------------------"
    echo "VM Pair: $vm1 and $vm2 (Pair $((idx+1))/$total)"
    echo "  -> Both VMs on node$node (4 CPU each, 2-core preference)"

    # allocate 4 CPU for vm1 from specified node
    if ! allocate_2_cores_on_node "$node"; then
        echo "Error: Not enough CPU on node$node for VM $vm1" >&2
        exit 1
    fi
    local vm1_cpus=( "${TEMP_ALLOC4[@]}" )

    # allocate 4 CPU for vm2 from same node
    if ! allocate_2_cores_on_node "$node"; then
        echo "Error: Not enough CPU on node$node for VM $vm2" >&2
        exit 1
    fi
    local vm2_cpus=( "${TEMP_ALLOC4[@]}" )

    echo "  $vm1 => ${vm1_cpus[*]}"
    echo "  $vm2 => ${vm2_cpus[*]}"

    # store
    local s1; s1=$(IFS=,; echo "${vm1_cpus[*]}")
    local s2; s2=$(IFS=,; echo "${vm2_cpus[*]}")
    vm_allocations["$vm1"]="$s1"
    vm_allocations["$vm2"]="$s2"
    vm_numa_nodes["$vm1"]="$node"
    vm_numa_nodes["$vm2"]="$node"
}

##########################################################################
# execute_bindings: example
##########################################################################
execute_bindings() {
    echo ""
    echo "Starting CPU binding operations..."
    echo ""

    local max_retries=3
    local retry_delay=0.5

    for vm_uuid in "${!vm_allocations[@]}"; do
        local cpus="${vm_allocations[$vm_uuid]}"
        local node="${vm_numa_nodes[$vm_uuid]}"
        local attempt=1
        local success=false

        echo "Binding VM: $vm_uuid"
        echo "  CPUs: $cpus"
        echo "  NUMA node: $node"

        while [ $attempt -le $max_retries ] && [ "$success" = false ]; do
            if [ $attempt -gt 1 ]; then
                echo "  Retry attempt $attempt/$max_retries after ${retry_delay}s"
                sleep "$retry_delay"
            fi

            echo "Executing binding command..."
            if ./binding.py --vm_uuid "$vm_uuid" --cpus "$cpus" --mem_numa_node "$node" --cpu_mode exclusive; then
                echo "  Binding successful"
                success=true
            else
                echo "  Binding failed"
                if [ $attempt -eq $max_retries ]; then
                    echo "  All attempts failed for $vm_uuid"
                fi
                ((attempt++))
            fi
        done
        echo
    done
}

##########################################################################
# get_vm_to_vnet_mappings: Get VM to vnet mappings directly using virsh
# returns space-separated lines of "vm_uuid vnet_interface"
##########################################################################
get_vm_to_vnet_mappings() {
    # We already have the VM pairs in our script, so we can use them directly
    local all_vms=()
    
    # Extract all VMs from the pairs array
    for pair in "${pairs[@]}"; do
        read -r vm1 vm2 <<< "$pair"
        all_vms+=("$vm1" "$vm2")
    done
    
    # For each VM, get its vnet interface
    for vm in "${all_vms[@]}"; do
        # Use virsh and xmllint to extract the vnet interface connected to vpcbr
        local vnet
        vnet=$(virsh dumpxml "$vm" | xmllint --xpath "//interface[@type='bridge'][source/@bridge='vpcbr']/target/@dev" - 2>/dev/null | sed 's/dev=//g' | tr '"' ' ' | xargs)
        
        # If vnet is found, output the mapping
        if [ -n "$vnet" ]; then
            echo "$vm $vnet"
        fi
    done
}

##########################################################################
# cpu_list_to_hex_mask: Convert a comma-separated list of CPUs to hex bitmask
# format required by the rps_cpus and xps_cpus files
##########################################################################
cpu_list_to_hex_mask() {
    local cpu_list="$1"
    
    # If the list is empty, return 0
    if [ -z "$cpu_list" ]; then
        echo "00000000"
        return
    fi
    
    # Get the highest CPU number to determine how many hex digits we need
    local highest_cpu=0
    IFS=',' read -ra cpus <<< "$cpu_list"
    for cpu in "${cpus[@]}"; do
        if (( cpu > highest_cpu )); then
            highest_cpu="$cpu"
        fi
    done
    
    # Calculate number of 32-bit words needed
    local num_words=$(( (highest_cpu / 32) + 1 ))
    
    # Initialize an array of zeros
    local -a mask=()
    for (( i=0; i<num_words; i++ )); do
        mask[i]=0
    done
    
    # Set the bits for each CPU
    for cpu in "${cpus[@]}"; do
        local word_idx=$(( cpu / 32 ))
        local bit_pos=$(( cpu % 32 ))
        local bit_val=$(( 1 << bit_pos ))
        mask[word_idx]=$(( mask[word_idx] | bit_val ))
    done
    
    # Convert to hex representation
    local result=""
    for (( i=num_words-1; i>=0; i-- )); do
        # Format with leading zeros and ensure 8 hex digits
        local hex_val=$(printf "%08x" "${mask[i]}")
        result+="$hex_val"
        if (( i > 0 )); then
            result+=","
        fi
    done
    
    echo "$result"
}

##########################################################################
# set_vm_net_cpu_affinity: Set RPS and XPS for a VM's vnet interface
##########################################################################
set_vm_net_cpu_affinity() {
    local vm="$1"
    local vnet="$2"
    local cpu_list="$3"
    
    echo "Setting RPS/XPS CPUs for VM $vm (vnet: $vnet) => $cpu_list"
    
    # Check if vnet interface exists
    if [ ! -d "/sys/class/net/$vnet" ]; then
        echo "  ERROR: vnet interface $vnet does not exist!"
        return 1
    fi
    
    # Convert CPU list to hex bitmask
    local hex_mask
    hex_mask=$(cpu_list_to_hex_mask "$cpu_list")
    
    echo "  CPU mask: $hex_mask"
    
    # Set RPS for all receive queues
    local rx_queues=(/sys/class/net/"$vnet"/queues/rx-*)
    if [ ${#rx_queues[@]} -gt 0 ] && [ -e "${rx_queues[0]}" ]; then
        echo "  Found ${#rx_queues[@]} RX queues for $vnet"
        for queue in "${rx_queues[@]}"; do
            if [ -f "$queue/rps_cpus" ]; then
                echo "  Setting RPS for $queue"
                local before=$(cat "$queue/rps_cpus" 2>/dev/null)
                echo "    Before: $before"
                if ! echo "$hex_mask" > "$queue/rps_cpus" 2>/dev/null; then
                    echo "    ERROR: Failed to set RPS for $queue"
                else
                    local after=$(cat "$queue/rps_cpus" 2>/dev/null)
                    echo "    After: $after"
                fi
            else
                echo "  No rps_cpus file found for $queue"
            fi
        done
    else
        echo "  No RX queues found for $vnet"
    fi
    
    # Set XPS for all transmit queues
    local tx_queues=(/sys/class/net/"$vnet"/queues/tx-*)
    if [ ${#tx_queues[@]} -gt 0 ] && [ -e "${tx_queues[0]}" ]; then
        echo "  Found ${#tx_queues[@]} TX queues for $vnet"
        for queue in "${tx_queues[@]}"; do
            if [ -f "$queue/xps_cpus" ]; then
                echo "  Setting XPS for $queue"
                local before=$(cat "$queue/xps_cpus" 2>/dev/null)
                echo "    Before: $before"
                if ! echo "$hex_mask" > "$queue/xps_cpus" 2>/dev/null; then
                    echo "    ERROR: Failed to set XPS for $queue"
                else
                    local after=$(cat "$queue/xps_cpus" 2>/dev/null)
                    echo "    After: $after"
                fi
            else
                echo "  No xps_cpus file found for $queue"
            fi
        done
    else
        echo "  No TX queues found for $vnet"
    fi
}

##########################################################################
# main
##########################################################################
main() {
    # read machine.slice
    local f="/sys/fs/cgroup/cpuset/machine.slice/cpuset.cpus"
    if [ ! -f "$f" ]; then
        echo "Error: $f not found." >&2
        exit 1
    fi
    local mc_str=$(cat "$f")
    local mc_arr=($(expand_cpuset "$mc_str"))
    local total_mc=${#mc_arr[@]}
    echo "machine.slice configured CPUs: $mc_str (Total: $total_mc)"

    if [ $# -lt 1 ]; then
      echo "Usage: $0 vm_pairs.txt [--same-node]"
      exit 1
    fi
    local vm_file="$1"
    if [ ! -f "$vm_file" ]; then
      echo "Error: $vm_file not found"
      exit 1
    fi
    
    # 检查是否使用同一节点模式
    local use_same_node=false
    if [ $# -ge 2 ] && [ "$2" = "--same-node" ]; then
        use_same_node=true
        echo "Using same-node mode: each VM pair will be allocated on the same NUMA node"
        echo "Different pairs will alternate between node0 and node1"
    fi
    
    local pairs=()
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        pairs+=( "$line" )
    done < "$vm_file"

    local num_pairs=${#pairs[@]}
    echo "Number of VM pairs to process: $num_pairs"

    local needed=$((num_pairs * 8))
    # reserve at least 4 => total_mc -4 < needed =>fail
    if (( total_mc - 4 < needed )); then
      echo "Error: Not enough CPU in machine.slice"
      exit 1
    fi

    # partition by node
    for nd in 0 1; do
      local nf="/sys/devices/system/node/node${nd}/cpulist"
      if [ ! -f "$nf" ]; then
        echo "Warning: $nf not found, skip node $nd"
        numa_free["$nd"]=""
        continue
      fi
      local node_str; node_str=$(cat "$nf")
      local node_arr=($(expand_cpuset "$node_str"))
      local free_list=()
      for c in "${node_arr[@]}"; do
        in_array "$c" "${mc_arr[@]}" && free_list+=( "$c" )
      done
      numa_free["$nd"]="${free_list[*]}"
      echo "NUMA node $nd available CPUs: ${free_list[*]}"
    done

    # build sibling groups
    build_htgroups 0 ht0
    build_htgroups 1 ht1

    echo
    echo "Starting CPU allocation for each VM pair..."
    echo
    local i
    for i in "${!pairs[@]}"; do
      if [ "$use_same_node" = true ]; then
        allocate_pair_same_node "${pairs[$i]}" "$i" "$num_pairs"
      else
        allocate_pair "${pairs[$i]}" "$((i+1))" "$num_pairs"
      fi
    done

    echo "------------------------------------------------------"
    echo "Remaining unallocated CPUs:"
    # gather allocated
    declare -a all_alloc=()
    for vm in "${!vm_allocations[@]}"; do
      IFS=',' read -ra arr <<< "${vm_allocations[$vm]}"
      all_alloc+=( "${arr[@]}" )
    done

    for nd in 0 1; do
      echo "NUMA node $nd:"
      local s="${numa_free[$nd]:-}"
      if [ -z "$s" ]; then
        echo "  No unallocated CPU"
        remaining_unallocated["$nd"]=""
        continue
      fi
      local arr=( $s )
      local truly=()
      for c in "${arr[@]}"; do
        local used=0
        for x in "${all_alloc[@]}"; do
          if [ "$c" = "$x" ]; then
            used=1
            break
          fi
        done
        [ "$used" -eq 0 ] && truly+=( "$c" )
      done
      if [ ${#truly[@]} -eq 0 ]; then
        echo "  No unallocated CPU"
        remaining_unallocated["$nd"]=""
      else
        local sorted
        sorted=$(printf "%s\n" "${truly[@]}" | sort -n | tr '\n' ',' | sed 's/,$//')
        echo "  CPUs: $sorted"
        remaining_unallocated["$nd"]="$sorted"
      fi
    done

    echo "------------------------------------------------------"
    echo "CPU allocation plan complete."
    echo

    read -rp "Proceed with CPU binding? (y/n): " ans
    if [[ $ans =~ ^[Yy]$ ]]; then
      execute_bindings
      echo "All CPU binding done."
    else
      echo "skip binding"
    fi

    echo "------------------------------------------------------"
    read -rp "Do you want to proceed with VHOST CPU binding? (y/n): " ans2
    if [[ $ans2 =~ ^[Yy]$ ]]; then
      for vm in "${!vm_allocations[@]}"; do
        local nd="${vm_numa_nodes[$vm]}"
        local leftover="${remaining_unallocated[$nd]:-}"
        if [ -z "$leftover" ]; then
          echo "No leftover CPU on node $nd for $vm"
        else
          echo "Setting vhost CPU for $vm => $leftover"
          ./set-process-cpu-mem-affinitity.sh -g "$vm" -c "$leftover"
        fi
      done
    fi
    
    echo "------------------------------------------------------"
    read -rp "Do you want to configure RPS/XPS for VM network interfaces? (y/n): " ans3
    if [[ $ans3 =~ ^[Yy]$ ]]; then
        echo "Getting VM to vnet mappings directly from virsh..."
        
        # Get mappings directly using virsh
        declare -A vm_to_vnet
        while IFS=" " read -r vm vnet; do
            # Only store if both values are non-empty
            if [[ -n "$vm" && -n "$vnet" ]]; then
                vm_to_vnet["$vm"]="$vnet"
                echo "  Mapped: VM $vm -> $vnet"
            fi
        done < <(get_vm_to_vnet_mappings)
        
        # Check if we got any mappings
        if [ ${#vm_to_vnet[@]} -eq 0 ]; then
            echo "Error: No VM to vnet mappings found. Cannot configure RPS/XPS."
            echo "Please check if VMs have interfaces connected to vpcbr bridge."
            exit 1
        fi
        
        echo "Found ${#vm_to_vnet[@]} VM-to-vnet mappings"
        
        echo "Configuring RPS/XPS for each VM's network interface..."
        for vm in "${!vm_allocations[@]}"; do
            local nd="${vm_numa_nodes[$vm]}"
            local leftover="${remaining_unallocated[$nd]:-}"
            local vnet="${vm_to_vnet[$vm]:-}"
            
            if [ -z "$vnet" ]; then
                echo "No vnet found for VM $vm, skipping"
                continue
            fi
            
            if [ -z "$leftover" ]; then
                echo "No leftover CPU on node $nd for VM $vm, skipping RPS/XPS configuration"
            else
                set_vm_net_cpu_affinity "$vm" "$vnet" "$leftover"
            fi
        done
        echo "RPS/XPS configuration complete."
    fi
}

main "$@"

