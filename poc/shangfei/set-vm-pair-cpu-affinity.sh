#!/bin/bash

# This script allocates exclusive CPUs for test pairs of VMs.
# Requirements:
# - All available CPUs come from machine.slice cpuset.
# - Each VM is to be allocated 4 CPUs exclusively (8 CPUs per pair).
# - Globally, at least 5 CPU cores must be reserved for other tasks.

set -euo pipefail

# Storage for VM allocations
declare -A vm_allocations
declare -A vm_numa_nodes

# Declare global associative array
declare -A remaining_unallocated

# Function to expand a cpuset string (e.g., "0,7,9,11-48,50-95") into individual CPU numbers.
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

# Check if an integer exists in an array
in_array() {
    local needle="$1"
    shift
    local element
    for element; do
        if [ "$element" = "$needle" ]; then
            return 0
        fi
    done
    return 1
}

# Remove a value from an array
remove_from_array() {
    local remove_val="$1"
    shift
    local new_array=()
    local elem
    for elem in "$@"; do
        if [[ "$elem" -ne "$remove_val" ]]; then
            new_array+=("$elem")
        fi
    done
    echo "${new_array[@]}"
}

# Build hyper-thread sibling groups for a given NUMA node
build_htgroups() {
    local node="$1"
    local assoc_array_name="$2"
    local free_list=(${numa_free[$node]})
    
    # Initialize associative array
    eval "declare -A $assoc_array_name"
    
    local cpu
    for cpu in "${free_list[@]}"; do
        local topo_file="/sys/devices/system/cpu/cpu${cpu}/topology/thread_siblings_list"
        local group_key
        if [ ! -f "$topo_file" ]; then
            group_key="$cpu"
        else
            local siblings_str
            siblings_str=$(cat "$topo_file")
            local siblings=($(expand_cpuset "$siblings_str"))
            local group=()
            local s
            for s in "${siblings[@]}"; do
                if in_array "$s" "${free_list[@]}"; then
                    group+=("$s")
                fi
            done
            IFS=$'\n' sorted=($(sort -n <<<"${group[*]}"))
            unset IFS
            group_key=$(echo "${sorted[*]}" | tr ' ' ',')
        fi
        
        # Check if key exists and add if not
        eval "local exists=\${$assoc_array_name[$group_key]+x}"
        if [ -z "$exists" ]; then
            eval "$assoc_array_name[$group_key]=$cpu"
        fi
    done
}

# get_sibling_pairs_for_node(node):
#   returns a list of "cA-cB" each representing a physical core's 2 hyperthreads
get_sibling_pairs_for_node() {
    local node="$1"
    local pairs=()

    local free_str="${numa_free[$node]:-}"
    [ -z "$free_str" ] && { echo ""; return; }
    local free_arr=( $free_str )

    # quick lookup
    declare -A free_lookup=()
    for c in "${free_arr[@]}"; do
        free_lookup["$c"]=1
    done

    # pick from either ht0 or ht1
    local keys=()
    if [ "$node" = "0" ]; then
        if [ "${#ht0[@]}" -eq 0 ]; then
            echo ""
            return
        fi
        keys=( "${!ht0[@]}" )
    else
        if [ "${#ht1[@]}" -eq 0 ]; then
            echo ""
            return
        fi
        keys=( "${!ht1[@]}" )
    fi

    for key in "${keys[@]}"; do
        # key like "36,84"
        IFS=',' read -ra grp <<< "$key"
        if [ "${#grp[@]}" -eq 2 ]; then
            local cA="${grp[0]}"
            local cB="${grp[1]}"
            if [[ -n "${free_lookup[$cA]:-}" && -n "${free_lookup[$cB]:-}" ]]; then
                pairs+=( "$cA-$cB" )
            fi
        fi
    done

    echo "${pairs[@]}"
}


# Allocate CPUs for one VM pair: one pair of vms allocated from two different NUMA nodes
#allocate_pair() {
#    local pair_line="$1"
#    local pair_index="$2"
#    local total_pairs="$3"
#    read -r vm1 vm2 <<< "$pair_line"
#
#    # Allocate 4 CPUs for vm1 from NUMA node 0
#    local free_list0=(${numa_free[0]})
#    if [ "${#free_list0[@]}" -lt 4 ]; then
#        echo "Error: Not enough free CPUs in NUMA node 0 for vm $vm1" >&2
#        exit 1
#    fi
#    local alloc_vm1=("${free_list0[@]:0:4}")
#    local updated_list0=("${free_list0[@]:4}")
#    numa_free["0"]="${updated_list0[*]}"
#    local node_vm1="0"
#
#    # Allocate 4 CPUs for vm2 from NUMA node 1
#    local free_list1=(${numa_free[1]})
#    if [ "${#free_list1[@]}" -lt 4 ]; then
#        echo "Error: Not enough free CPUs in NUMA node 1 for vm $vm2" >&2
#        exit 1
#    fi
#    local alloc_vm2=("${free_list1[@]:0:4}")
#    local updated_list1=("${free_list1[@]:4}")
#    numa_free["1"]="${updated_list1[*]}"
#    local node_vm2="1"
#
#    echo "------------------------------------------------------"
#    echo "VM Pair: $vm1 and $vm2 (Pair ${pair_index}/${total_pairs})"
#    echo "Allocation:"
#    echo "  $vm1 allocated CPUs: ${alloc_vm1[*]} from NUMA node $node_vm1"
#    echo "  $vm2 allocated CPUs: ${alloc_vm2[*]} from NUMA node $node_vm2"
#
#    # Store allocation results
#    local cpus_vm1
#    cpus_vm1=$(IFS=,; echo "${alloc_vm1[*]}")
#    local cpus_vm2
#    cpus_vm2=$(IFS=,; echo "${alloc_vm2[*]}")
#    vm_allocations["$vm1"]="$cpus_vm1"
#    vm_allocations["$vm2"]="$cpus_vm2"
#    vm_numa_nodes["$vm1"]="$node_vm1"
#    vm_numa_nodes["$vm2"]="$node_vm2"
#}

# allocate_pair():
#   1) read <vm1, vm2> from pair_line
#   2) vm1 -> node0, vm2 -> node1
#   3) each needs 4 CPU, prefer 2 physical cores => 2 pairs => 4 CPU
#   4) if not enough pairs => fallback pick any 4 from free_list.
#   5) store results & print logs
allocate_pair() {
    local pair_line="$1"
    local pair_index="$2"
    local total_pairs="$3"

    read -r vm1 vm2 <<< "$pair_line"

    # We'll define helper function for "allocate 2 cores(=4CPU) on one node"
    # either from sibling pairs or fallback to single-CPU picking
    allocate_2_cores_on_node() {
        local node="$1"
        local -n out_array="$2"  # reference to some local array name

        # 1) get sibling pairs
        local pairs_str
        pairs_str=$(get_sibling_pairs_for_node "$node")
        if [ -z "$pairs_str" ]; then
            # fallback to single-CPU pick if we have >=4
            local arr_str="${numa_free[$node]:-}"
            [ -z "$arr_str" ] && return 1
            local arr=( $arr_str )
            if [ "${#arr[@]}" -lt 4 ]; then
                return 1
            fi
            out_array=( "${arr[@]:0:4}" )
            # remove them
            local updated=( "${arr[@]:4}" )
            numa_free["$node"]="${updated[*]}"
            return 0
        fi

        local pairs=()
        # shellcheck disable=SC2206
        pairs=( $pairs_str )

        # need at least 2 pairs => 4 CPU
        if [ "${#pairs[@]}" -ge 2 ]; then
            # pick first 2
            local selected=( "${pairs[@]:0:2}" )
            # convert them to 4 CPU
            local temp4=()
            for core in "${selected[@]}"; do
                local cA="${core%-*}"
                local cB="${core#*-}"
                temp4+=( "$cA" "$cB" )
            done
            # remove these from numa_free[node]
            local free_str="${numa_free[$node]:-}"
            [ -z "$free_str" ] && return 1
            local arr=( $free_str )
            local updated=()
            for c in "${arr[@]}"; do
                local skip=0
                for x in "${temp4[@]}"; do
                    if [ "$c" = "$x" ]; then
                        skip=1
                        break
                    fi
                done
                [ "$skip" -eq 0 ] && updated+=( "$c" )
            done
            numa_free["$node"]="${updated[*]}"
            out_array=( "${temp4[@]}" )
            return 0
        else
            # fallback: if not enough pairs => pick any 4 CPU
            local arr_str="${numa_free[$node]:-}"
            [ -z "$arr_str" ] && return 1
            local arr=( $arr_str )
            if [ "${#arr[@]}" -lt 4 ]; then
                return 1
            fi
            out_array=( "${arr[@]:0:4}" )
            local leftover=( "${arr[@]:4}" )
            numa_free["$node"]="${leftover[*]}"
            return 0
        fi
    }

    echo "------------------------------------------------------"
    echo "VM Pair: $vm1 and $vm2 (Pair ${pair_index}/${total_pairs})"
    echo "Allocation: Each VM gets 4 CPU => from node0, node1 (respectively) with 2-core preference"
    
    # 2) for vm1 => node0
    local -a alloc_vm1=()
    if ! allocate_2_cores_on_node 0 alloc_vm1; then
        echo "Error: Not enough CPU on node0 to allocate 4 CPU for $vm1" >&2
        exit 1
    fi

    # 3) for vm2 => node1
    local -a alloc_vm2=()
    if ! allocate_2_cores_on_node 1 alloc_vm2; then
        echo "Error: Not enough CPU on node1 to allocate 4 CPU for $vm2" >&2
        exit 1
    fi

    # success => store
    echo "  $vm1 allocated CPUs: ${alloc_vm1[*]} (node0)"
    echo "  $vm2 allocated CPUs: ${alloc_vm2[*]} (node1)"

    local cpus_vm1
    cpus_vm1=$(IFS=,; echo "${alloc_vm1[*]}")
    local cpus_vm2
    cpus_vm2=$(IFS=,; echo "${alloc_vm2[*]}")
    vm_allocations["$vm1"]="$cpus_vm1"
    vm_allocations["$vm2"]="$cpus_vm2"
    vm_numa_nodes["$vm1"]="0"
    vm_numa_nodes["$vm2"]="1"
}




## Allocate CPUs for one VM pair: one numa-node-per pair，hyper-thread group binding, last odd pair, split it to different numa-node
#allocate_pair() {
#    local pair_line="$1"
#    local pair_index="$2"
#    local total_pairs="$3"
#    read -r vm1 vm2 <<< "$pair_line"
#    local alloc_method="paired"
#    local alloc_vm1=()
#    local alloc_vm2=()
#    local used_node_for_pair=""
#    local node_vm1=""
#    local node_vm2=""
#
#    # Function to count VMs allocated to a NUMA node
#    count_vms_on_node() {
#        local target_node="$1"
#        local count=0
#        for node in "${vm_numa_nodes[@]}"; do
#            if [ "$node" = "$target_node" ]; then
#                ((count++))
#            fi
#        done
#        echo "$count"
#    }
#
#    # Function to get free CPU count on a NUMA node
#    get_free_cpu_count() {
#        local node="$1"
#        local free_list=( ${numa_free[$node]} )
#        echo "${#free_list[@]}"
#    }
#
#    # Determine if this is the last pair in an odd total
#    local is_last_odd_pair=false
#    if [ "$((total_pairs % 2))" -eq 1 ] && [ "$((pair_index + 1))" -eq "$total_pairs" ]; then
#        is_last_odd_pair=true
#    fi
#
#    # Try paired allocation from a single NUMA node
#    local preferred_nodes=()
#    if [ "$is_last_odd_pair" = true ]; then
#        # For last pair in odd total, check both nodes based on load
#        for node in 0 1; do
#            local free_count=$(get_free_cpu_count "$node")
#            if [ "$free_count" -ge 8 ]; then
#                local vm_count=$(count_vms_on_node "$node")
#                if [ "$((vm_count * 2))" -lt "$free_count" ]; then
#                    preferred_nodes+=("$node")
#                fi
#            fi
#        done
#        # If no suitable node found, default to split allocation
#        if [ ${#preferred_nodes[@]} -eq 0 ]; then
#            preferred_nodes=(0 1)
#            alloc_method="separate"
#        fi
#    else
#        # Round-robin for non-last pairs
#        if [ "$((pair_index % 2))" -eq 0 ]; then
#            preferred_nodes=(0 1)
#        else
#            preferred_nodes=(1 0)
#        fi
#    fi
#
#    # Try allocation on preferred nodes
#    for node in "${preferred_nodes[@]}"; do
#        local free_list=( ${numa_free[$node]} )
#        if [ "${#free_list[@]}" -ge 8 ] && [ "$alloc_method" = "paired" ]; then
#            used_node_for_pair="$node"
#            alloc_vm1=( "${free_list[@]:0:4}" )
#            alloc_vm2=( "${free_list[@]:4:4}" )
#            local updated_list=( "${free_list[@]:8}" )
#            numa_free["$node"]="${updated_list[*]}"
#            node_vm1="$node"
#            node_vm2="$node"
#            break
#        elif [ "$alloc_method" = "separate" ] && [ "${#free_list[@]}" -ge 4 ]; then
#            if [ -z "$node_vm1" ]; then
#                node_vm1="$node"
#                alloc_vm1=( "${free_list[@]:0:4}" )
#                local updated_vm1=( "${free_list[@]:4}" )
#                numa_free["$node"]="${updated_vm1[*]}"
#            elif [ -z "$node_vm2" ]; then
#                node_vm2="$node"
#                alloc_vm2=( "${free_list[@]:0:4}" )
#                local updated_vm2=( "${free_list[@]:4}" )
#                numa_free["$node"]="${updated_vm2[*]}"
#            fi
#        fi
#    done
#
#    # Check if allocation was successful
#    if [ -z "$node_vm1" ] || [ -z "$node_vm2" ] || [ ${#alloc_vm1[@]} -ne 4 ] || [ ${#alloc_vm2[@]} -ne 4 ]; then
#        echo "Error: Unable to allocate 4 CPUs for vm ($vm1) or vm ($vm2)" >&2
#        exit 1
#    fi
#
#    echo "------------------------------------------------------"
#    echo "VM Pair: $vm1 and $vm2 (Pair ${pair_index}/${total_pairs})"
#    if [ "$alloc_method" = "paired" ]; then
#        echo "Allocation using paired method from NUMA node $used_node_for_pair"
#    else
#        echo "Separate allocation: vm $vm1 from NUMA node ${node_vm1}, vm $vm2 from NUMA node ${node_vm2}"
#    fi
#    echo "  $vm1 allocated CPUs: ${alloc_vm1[*]}"
#    echo "  $vm2 allocated CPUs: ${alloc_vm2[*]}"
#
#    # Store allocation results
#    local cpus_vm1=$(IFS=,; echo "${alloc_vm1[*]}")
#    local cpus_vm2=$(IFS=,; echo "${alloc_vm2[*]}")
#    vm_allocations["$vm1"]="$cpus_vm1"
#    vm_allocations["$vm2"]="$cpus_vm2"
#    vm_numa_nodes["$vm1"]="$node_vm1"
#    vm_numa_nodes["$vm2"]="$node_vm2"
#}

# Execute CPU binding operations with retry
execute_bindings() {
    echo ""
    echo "Starting CPU binding operations..."
    echo ""
    
    local max_retries=3
    local retry_delay=0.5  # seconds
    
    for vm_uuid in "${!vm_allocations[@]}"; do
        local cpus="${vm_allocations[$vm_uuid]}"
        local numa_node="${vm_numa_nodes[$vm_uuid]}"
        local success=false
        local attempt=1
        
        echo "Binding VM: $vm_uuid"
        echo "  CPUs: $cpus"
        echo "  NUMA node: $numa_node"
        
        while [ $attempt -le $max_retries ] && [ "$success" = false ]; do
            if [ $attempt -gt 1 ]; then
                echo "  Retry attempt $attempt/$max_retries after ${retry_delay} seconds..."
                sleep $retry_delay
            fi
            
            echo "Executing binding command..."
            if ./binding.py --vm_uuid "$vm_uuid" --cpus "$cpus" --mem_numa_node "$numa_node" --cpu_mode exclusive; then
                echo "  Binding successful"
                success=true
            else
                echo "  Binding failed"
                if [ $attempt -eq $max_retries ]; then
                    echo "  Warning: All retry attempts failed for VM $vm_uuid"
                fi
                ((attempt++))
            fi
        done
        echo ""
    done
}

# Main execution flow
main() {
    # Get all available CPUs from machine.slice
    machine_cpuset_file="/sys/fs/cgroup/cpuset/machine.slice/cpuset.cpus"
    if [ ! -f "$machine_cpuset_file" ]; then
        echo "Error: $machine_cpuset_file does not exist" >&2
        exit 1
    fi
    machine_cpus_str=$(cat "$machine_cpuset_file")
    machine_cpus=($(expand_cpuset "$machine_cpus_str"))
    total_machine_cpus=${#machine_cpus[@]}
    echo "machine.slice configured CPUs: $machine_cpus_str  (Total: $total_machine_cpus)"

    # Read VM pairs from input file
    if [ "$#" -lt 1 ]; then
        echo "Usage: $0 vm_pairs.txt" >&2
        exit 1
    fi

    vm_pairs_file="$1"
    if [ ! -f "$vm_pairs_file" ]; then
        echo "Error: file $vm_pairs_file does not exist." >&2
        exit 1
    fi

    vm_pairs=()
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        vm_pairs+=("$line")
    done < "$vm_pairs_file"

    num_pairs=${#vm_pairs[@]}
    echo "Number of VM pairs to process: $num_pairs"

    # Check if enough CPUs are available
    required_cpus=$(( num_pairs * 8 ))
    if (( total_machine_cpus - 4 < required_cpus )); then
        echo "Error: Not enough CPUs available in machine.slice" >&2
        exit 1
    fi

    # Partition available CPUs by NUMA node
    declare -A numa_free
    for node in 0 1; do
        node_file="/sys/devices/system/node/node${node}/cpulist"
        if [ ! -f "$node_file" ]; then
            echo "Warning: $node_file not found. Skipping NUMA node $node."
            numa_free["$node"]=""
            continue
        fi
        node_cpus_str=$(cat "$node_file")
        node_cpus=($(expand_cpuset "$node_cpus_str"))
        free_in_node=()
        for cpu in "${node_cpus[@]}"; do
            if in_array "$cpu" "${machine_cpus[@]}"; then
                free_in_node+=("$cpu")
            fi
        done
        numa_free["$node"]="${free_in_node[*]}"
        echo "NUMA node $node available CPUs: ${free_in_node[*]}"
    done

    # Build hyper-thread sibling groups
    declare -A ht0
    declare -A ht1
    build_htgroups 0 ht0
    build_htgroups 1 ht1

    echo ""
    echo "Starting CPU allocation for each VM pair..."
    echo ""

    # Perform allocation
    for i in "${!vm_pairs[@]}"; do
        allocate_pair "${vm_pairs[$i]}" "$i" "${#vm_pairs[@]}"
    done

    # Display remaining unallocated CPUs
    echo "------------------------------------------------------"
    echo "Remaining unallocated CPUs (grouped by NUMA node):"

    # First, collect all allocated CPUs into a single array
    declare -a all_allocated_cpus=()
    for vm_uuid in "${!vm_allocations[@]}"; do
        IFS=',' read -ra cpu_array <<< "${vm_allocations[$vm_uuid]}"
        all_allocated_cpus+=("${cpu_array[@]}")
    done

    # Process each NUMA node
    for node in 0 1; do
        echo "NUMA node $node:"
        
        node_file="/sys/devices/system/node/node${node}/cpulist"
        if [ ! -f "$node_file" ]; then
            echo "  (No cpulist file for node $node)"
            continue
        fi
        
        node_cpus=($(expand_cpuset "$(cat "$node_file")"))
        declare -a unallocated_cpus=()
        
        for cpu in "${node_cpus[@]}"; do
            in_machine_slice=0
            for mcpu in "${machine_cpus[@]}"; do
                if [ "$cpu" = "$mcpu" ]; then
                    in_machine_slice=1
                    break
                fi
            done
            [ "$in_machine_slice" = "0" ] && continue
            
            is_allocated=0
            for allocated_cpu in "${all_allocated_cpus[@]}"; do
                if [ "$cpu" = "$allocated_cpu" ]; then
                    is_allocated=1
                    break
                fi
            done
            
            if [ "$is_allocated" = "0" ]; then
                unallocated_cpus+=("$cpu")
            fi
        done
        
        if [ ${#unallocated_cpus[@]} -eq 0 ]; then
            echo "  No unallocated CPUs"
            remaining_unallocated["$node"]=""
        else
            sorted_list=$(printf "%s\n" "${unallocated_cpus[@]}" | sort -n | tr '\n' ',' | sed 's/,$//')
            echo "  CPUs: $sorted_list"
            echo "  Thread groups:"
            for cpu in "${unallocated_cpus[@]}"; do
                topo_file="/sys/devices/system/cpu/cpu${cpu}/topology/thread_siblings_list"
                if [ -f "$topo_file" ]; then
                    group=$(head -n1 "$topo_file" | cut -d',' -f1)
                    echo "    Group $group: CPU $cpu"
                fi
            done
            remaining_unallocated["$node"]="$sorted_list"
        fi
    done

    echo "------------------------------------------------------"
    echo "CPU allocation plan complete."
    echo ""
    
    # Ask for confirmation before binding
    read -p "Do you want to proceed with CPU binding operations? (y/n): " proceed
    if [[ $proceed =~ ^[Yy]$ ]]; then
        execute_bindings
        echo "All CPU binding operations completed."
    else
        echo "CPU binding operations skipped."
    fi

    echo "------------------------------------------------------"
    read -p "Do you want to proceed with VHOST CPU binding? (Note: This step is independent from VM CPU binding, and it is recommended to run it separately after VM binding, as VM restart may change vhost processes) (y/n): " proceed_vhost
    if [[ $proceed_vhost =~ ^[Yy]$ ]]; then
        for vm in "${!vm_allocations[@]}"; do
            node_for_vm="${vm_numa_nodes[$vm]}"
            cpulist_for_vhost="${remaining_unallocated[$node_for_vm]:-}"
            
            if [ -z "$cpulist_for_vhost" ]; then
                echo "Warning: No remaining CPUs available on NUMA node $node_for_vm for VM $vm; skipping vhost binding."
            else
                echo "Setting VHOST CPU binding for VM $vm using CPUs: $cpulist_for_vhost"
                ./set-process-cpu-mem-affinitity.sh -g "$vm" -c "$cpulist_for_vhost"
            fi
        done
    fi
}

# Execute main function
main "$@"

