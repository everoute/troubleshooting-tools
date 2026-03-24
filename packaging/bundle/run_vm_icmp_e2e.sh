#!/bin/bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGG="${BASE_DIR}/measurement-tools/performance/vm-network/vm_icmp_e2e_latency_aggregator.py"

if [[ ! -f "${AGG}" ]]; then
    echo "[ERROR] Aggregator not found: ${AGG}" >&2
    exit 1
fi

if [[ $# -eq 0 ]]; then
    echo "Usage:"
    echo "  ./run_vm_icmp_e2e.sh --src-ip <SRC_IP> --dst-ip <DST_IP> --src-iface <SRC_IF> --dst-iface <DST_IF> [other options]"
    echo ""
    echo "Try:"
    echo "  ./run_vm_icmp_e2e.sh --help"
    exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
    exec sudo -E python3 "${AGG}" "$@"
else
    exec python3 "${AGG}" "$@"
fi

