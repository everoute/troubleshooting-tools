#!/bin/bash
# Frontline command template
#
# Replace placeholders first:
#   SRC_IP, DST_IP, SRC_IFACE, DST_IFACE, DURATION
#
# Example:
#   SRC_IP=192.168.66.31 DST_IP=192.168.69.32 \
#   SRC_IFACE=vnet7 DST_IFACE=vnet207 DURATION=60 \
#   bash frontline-command-template.sh

set -euo pipefail

SRC_IP="${SRC_IP:-REPLACE_SRC_IP}"
DST_IP="${DST_IP:-REPLACE_DST_IP}"
SRC_IFACE="${SRC_IFACE:-REPLACE_SRC_IFACE}"
DST_IFACE="${DST_IFACE:-REPLACE_DST_IFACE}"
DURATION="${DURATION:-60}"
INTERVAL="${INTERVAL:-10}"

if [[ "${SRC_IP}" == REPLACE_* ]] || [[ "${DST_IP}" == REPLACE_* ]] || \
   [[ "${SRC_IFACE}" == REPLACE_* ]] || [[ "${DST_IFACE}" == REPLACE_* ]]; then
    echo "[ERROR] Please set SRC_IP/DST_IP/SRC_IFACE/DST_IFACE before running."
    exit 1
fi

LOG_FILE="vm_icmp_e2e_${SRC_IP//./_}_to_${DST_IP//./_}_$(date +%Y%m%d_%H%M%S).log"

sudo ./run_vm_icmp_e2e.sh \
  --src-ip "${SRC_IP}" --dst-ip "${DST_IP}" \
  --src-iface "${SRC_IFACE}" --dst-iface "${DST_IFACE}" \
  --packet-table --packet-table-limit 200 \
  --interval "${INTERVAL}" --duration "${DURATION}" | tee "${LOG_FILE}"

grep -E '^[0-9]+,[0-9]+' "${LOG_FILE}" > "${LOG_FILE%.log}.per_packet.csv" || true

echo ""
echo "Saved log: ${LOG_FILE}"
echo "Saved per-packet csv: ${LOG_FILE%.log}.per_packet.csv"

