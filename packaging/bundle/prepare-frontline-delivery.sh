#!/bin/bash
#
# Prepare frontline delivery package for VM ICMP E2E troubleshooting.
#
# Output package contains one runnable directory:
# - tools (already extracted)
# - frontline playbook
# - command template
# - delivery README
#
# Usage:
#   ./prepare-frontline-delivery.sh [OPTIONS]
#
# Options:
#   -v, --version VERSION   Version suffix (default: yyyymmdd)
#   -o, --output DIR        Output dir (default: /tmp/frontline-delivery)
#   -h, --help              Show help

set -euo pipefail

VERSION="$(date +%Y%m%d)"
OUTPUT_DIR="/tmp/frontline-delivery"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

BUILD_BUNDLE="${SCRIPT_DIR}/build-vm-icmp-e2e-bundle.sh"
PLAYBOOK="${REPO_ROOT}/docs/frontline-vm-icmp-e2e-playbook.md"
CMD_TEMPLATE="${SCRIPT_DIR}/frontline-command-template.sh"

usage() {
    head -30 "$0" | grep -E "^#" | sed 's/^# \?//'
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

[[ -x "${BUILD_BUNDLE}" ]] || die "Missing executable: ${BUILD_BUNDLE}"
[[ -f "${PLAYBOOK}" ]] || die "Missing file: ${PLAYBOOK}"
[[ -f "${CMD_TEMPLATE}" ]] || die "Missing file: ${CMD_TEMPLATE}"

mkdir -p "${OUTPUT_DIR}"
OUT_ABS="$(cd "${OUTPUT_DIR}" && pwd)"

"${BUILD_BUNDLE}" -v "${VERSION}" -o "${OUT_ABS}"

BUNDLE_FILE="${OUT_ABS}/vm-icmp-e2e-tools-${VERSION}.tar.gz"
[[ -f "${BUNDLE_FILE}" ]] || die "Bundle not found: ${BUNDLE_FILE}"

DELIVER_DIR="${OUT_ABS}/vm-icmp-e2e-frontline-${VERSION}"
rm -rf "${DELIVER_DIR}"
mkdir -p "${DELIVER_DIR}"

# Extract tools bundle and flatten into delivery root so frontline only needs:
#   1) one tar extraction
#   2) one cd
tar -xzf "${BUNDLE_FILE}" -C "${DELIVER_DIR}"
TOOLS_DIR="${DELIVER_DIR}/vm-icmp-e2e-tools-${VERSION}"
[[ -d "${TOOLS_DIR}" ]] || die "Extracted tools dir not found: ${TOOLS_DIR}"
cp -a "${TOOLS_DIR}/." "${DELIVER_DIR}/"
rm -rf "${TOOLS_DIR}"

cp -f "${PLAYBOOK}" "${DELIVER_DIR}/frontline-playbook.md"
cp -f "${CMD_TEMPLATE}" "${DELIVER_DIR}/frontline-command-template.sh"
chmod +x "${DELIVER_DIR}/frontline-command-template.sh"

cat > "${DELIVER_DIR}/README.delivery.md" <<EOF
# Frontline Delivery - VM ICMP E2E

## Included files

- run_vm_icmp_e2e.sh
- measurement-tools/...
- frontline-playbook.md
- frontline-command-template.sh

## Delivery steps

1. Copy this folder to target host or bastion.
2. Extract once and enter directory once:

\`\`\`bash
tar xzf vm-icmp-e2e-frontline-${VERSION}.tar.gz
cd vm-icmp-e2e-frontline-${VERSION}
\`\`\`

3. Run with template:

\`\`\`bash
SRC_IP=<src_vm_ip> DST_IP=<dst_vm_ip> SRC_IFACE=<src_vnet> DST_IFACE=<dst_vnet> \\
bash ./frontline-command-template.sh
\`\`\`

4. Return files:
- *.log
- *.per_packet.csv
EOF

tar -C "${OUT_ABS}" -czf "${OUT_ABS}/vm-icmp-e2e-frontline-${VERSION}.tar.gz" \
    "vm-icmp-e2e-frontline-${VERSION}"

log "Frontline delivery prepared:"
log "  ${OUT_ABS}/vm-icmp-e2e-frontline-${VERSION}"
log "  ${OUT_ABS}/vm-icmp-e2e-frontline-${VERSION}.tar.gz"
