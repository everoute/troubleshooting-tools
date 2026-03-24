#!/bin/bash
#
# Build a portable bundle for VM ICMP E2E latency troubleshooting.
#
# The bundle contains:
# - vm_icmp_e2e_latency_aggregator.py
# - icmp_path_tracer.py
# - kvm_vhost_tun_latency_no_discovery_details.py
# - tun_tx_to_kvm_irq.py
# - run_vm_icmp_e2e.sh (entrypoint)
# - README.md
#
# Usage:
#   ./build-vm-icmp-e2e-bundle.sh [OPTIONS]
#
# Options:
#   -v, --version VERSION   Bundle version suffix (default: yyyymmdd)
#   -o, --output DIR        Output directory (default: ./output)
#   -h, --help              Show this help
#
# Example:
#   ./build-vm-icmp-e2e-bundle.sh -v 20260324 -o /tmp

set -euo pipefail

VERSION="$(date +%Y%m%d)"
OUTPUT_DIR="./output"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

usage() {
    head -35 "$0" | grep -E "^#" | sed 's/^# \?//'
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--version)
            VERSION="${2:-}"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Unknown option: $1"
            ;;
    esac
done

[[ -n "${VERSION}" ]] || die "version cannot be empty"

BUNDLE_NAME="vm-icmp-e2e-tools"
PKG_DIR="${BUNDLE_NAME}-${VERSION}"

AGG="${REPO_ROOT}/measurement-tools/performance/vm-network/vm_icmp_e2e_latency_aggregator.py"
ICMP="${REPO_ROOT}/measurement-tools/boundary-detection/vm-network/icmp_path_tracer.py"
VHOST="${REPO_ROOT}/measurement-tools/kvm-virt-network/kvm/kvm_vhost_tun_latency_no_discovery_details.py"
IRQ="${REPO_ROOT}/measurement-tools/kvm-virt-network/tun/tun_tx_to_kvm_irq.py"
ENTRY="${SCRIPT_DIR}/run_vm_icmp_e2e.sh"
README="${SCRIPT_DIR}/README.vm-icmp-e2e-bundle.md"

for f in "$AGG" "$ICMP" "$VHOST" "$IRQ" "$ENTRY" "$README"; do
    [[ -f "$f" ]] || die "Required file not found: $f"
done

mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR_ABS="$(cd "${OUTPUT_DIR}" && pwd)"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

TARGET_ROOT="${WORK_DIR}/${PKG_DIR}"
mkdir -p "${TARGET_ROOT}/measurement-tools/performance/vm-network"
mkdir -p "${TARGET_ROOT}/measurement-tools/boundary-detection/vm-network"
mkdir -p "${TARGET_ROOT}/measurement-tools/kvm-virt-network/kvm"
mkdir -p "${TARGET_ROOT}/measurement-tools/kvm-virt-network/tun"

install -m 755 "$AGG" "${TARGET_ROOT}/measurement-tools/performance/vm-network/"
install -m 755 "$ICMP" "${TARGET_ROOT}/measurement-tools/boundary-detection/vm-network/"
install -m 755 "$VHOST" "${TARGET_ROOT}/measurement-tools/kvm-virt-network/kvm/"
install -m 644 "$IRQ" "${TARGET_ROOT}/measurement-tools/kvm-virt-network/tun/"
install -m 755 "$ENTRY" "${TARGET_ROOT}/run_vm_icmp_e2e.sh"
install -m 644 "$README" "${TARGET_ROOT}/README.md"

tar -C "${WORK_DIR}" -czf "${OUTPUT_DIR_ABS}/${PKG_DIR}.tar.gz" "${PKG_DIR}"

log "Bundle created:"
log "  ${OUTPUT_DIR_ABS}/${PKG_DIR}.tar.gz"
log "Quick start:"
log "  scp ${OUTPUT_DIR_ABS}/${PKG_DIR}.tar.gz <user>@<host>:/tmp/"
log "  ssh <user>@<host> 'cd /tmp && tar xzf ${PKG_DIR}.tar.gz && cd ${PKG_DIR} && ./run_vm_icmp_e2e.sh --help'"

