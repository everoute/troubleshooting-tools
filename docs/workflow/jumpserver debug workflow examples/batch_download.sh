#!/bin/bash
#
# Batch Download Results from File Transfer Host
# Usage: ./batch_download.sh [pattern]
#

set -e

# Configuration
FILE_JUMP_HOST="192.168.17.20"
FILE_JUMP_USER="root"
FILE_JUMP_DIR="/root/lcc"
LOCAL_DIR="./downloaded_results"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================================================"
echo "Batch Download Results from File Transfer Host"
echo "========================================================================"
echo "Source: ${FILE_JUMP_USER}@${FILE_JUMP_HOST}:${FILE_JUMP_DIR}/"
echo "Local:  ${LOCAL_DIR}/"
echo "========================================================================"
echo ""

# Create local directory
mkdir -p "$LOCAL_DIR"

# Get pattern from argument or use default
PATTERN="${1:-test_results_*.txt}"

# List remote files matching pattern
echo "Searching for files matching: $PATTERN"
echo ""

remote_files=$(ssh ${FILE_JUMP_USER}@${FILE_JUMP_HOST} \
    "cd ${FILE_JUMP_DIR} && ls -1 ${PATTERN} 2>/dev/null" || echo "")

if [ -z "$remote_files" ]; then
    echo -e "${YELLOW}No files found matching pattern: $PATTERN${NC}"
    exit 0
fi

# Show files to download
echo "Found files:"
echo "$remote_files" | while read file; do
    echo "  - $file"
done
echo ""

# Confirm download
read -p "Download these files? [Y/n] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ ! -z $REPLY ]]; then
    echo "Cancelled."
    exit 0
fi

# Download files
success_count=0
fail_count=0

echo ""
echo "Downloading..."

echo "$remote_files" | while read file; do
    echo -n "  $(basename $file) ... "

    if scp "${FILE_JUMP_USER}@${FILE_JUMP_HOST}:${FILE_JUMP_DIR}/${file}" "$LOCAL_DIR/"; then
        echo -e "${GREEN}✓${NC}"
        ((success_count++))
    else
        echo -e "${RED}✗${NC}"
        ((fail_count++))
    fi
done

echo ""
echo "========================================================================"
echo "Download complete"
echo "========================================================================"
echo ""
echo "Downloaded files in: $LOCAL_DIR/"
ls -lh "$LOCAL_DIR/" | tail -10

# Optionally view latest file
latest_file=$(ls -t "$LOCAL_DIR"/*.txt 2>/dev/null | head -1)
if [ -n "$latest_file" ]; then
    echo ""
    read -p "View latest result file? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo "========================================================================"
        echo "Content of: $(basename $latest_file)"
        echo "========================================================================"
        cat "$latest_file"
    fi
fi
