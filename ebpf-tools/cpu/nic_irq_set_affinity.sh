#!/usr/bin/env bash
# Set IRQ smp_affinity_list for a network interface to a given CPU list.

set -euo pipefail

usage() {
  echo "Usage: $0 <net-interface> <cpu-list>" >&2
  echo "Example: $0 ens43f0np0 40-43,48" >&2
  exit 1
}

[[ $# -eq 2 ]] || usage

iface="$1"
cpu_list="$2"
irq_dir="/sys/class/net/${iface}/device/msi_irqs"

if [[ ! -d "$irq_dir" ]]; then
  echo "No MSI IRQs directory found for interface: ${iface}" >&2
  exit 1
fi

for irq in $(ls "$irq_dir"); do
  path="/proc/irq/${irq}/smp_affinity_list"
  if [[ ! -w "$path" ]]; then
    echo "Cannot write to $path (need sudo?)" >&2
    exit 1
  fi
  echo "$cpu_list" > "$path"
  printf "Updated IRQ %s -> %s\n" "$irq" "$cpu_list"
done
