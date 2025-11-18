#!/usr/bin/env bash
# Print IRQ, CPU, and NUMA node mapping for a given network interface.

set -euo pipefail

usage() {
  echo "Usage: $0 <net-interface>" >&2
  exit 1
}

get_numa_node() {
  local cpu="$1"
  local node_file="/sys/devices/system/cpu/cpu${cpu}/numa_node"

  if [[ -f "$node_file" ]]; then
    cat "$node_file"
    return
  fi

  local node_path
  node_path=$(ls -d /sys/devices/system/cpu/cpu"${cpu}"/node* 2>/dev/null | head -n1 || true)
  if [[ -n "$node_path" ]]; then
    basename "$node_path" | sed 's/node//'
  else
    echo "NA"
  fi
}

print_mapping() {
  local irq="$1"
  local cpu="$2"
  local node

  node=$(get_numa_node "$cpu")
  printf "IRQ %s -> CPU %s\tNUMA %s\n" "$irq" "$cpu" "$node"
}

[[ $# -eq 1 ]] || usage

iface="$1"
irq_dir="/sys/class/net/${iface}/device/msi_irqs"

if [[ ! -d "$irq_dir" ]]; then
  echo "No MSI IRQs directory found for interface: ${iface}" >&2
  exit 1
fi

for irq in $(ls "$irq_dir"); do
  smp_list=$(<"/proc/irq/${irq}/smp_affinity_list")
  IFS=',' read -ra entries <<<"$smp_list"
  for entry in "${entries[@]}"; do
    if [[ "$entry" == *"-"* ]]; then
      start=${entry%-*}
      end=${entry#*-}
      for cpu in $(seq "$start" "$end"); do
        print_mapping "$irq" "$cpu"
      done
    else
      print_mapping "$irq" "$entry"
    fi
  done
done
