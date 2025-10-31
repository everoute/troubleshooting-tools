#!/bin/bash
#
# Batch Upload Files to File Transfer Host
# Usage: ./batch_upload.sh [file1] [file2] ...
#

set -e

# Configuration
FILE_JUMP_HOST="192.168.17.20"
FILE_JUMP_USER="root"
FILE_JUMP_DIR="/root/lcc"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================================================"
echo "Batch File Upload to File Transfer Host"
echo "========================================================================"
echo "Target: ${FILE_JUMP_USER}@${FILE_JUMP_HOST}:${FILE_JUMP_DIR}/"
echo "========================================================================"
echo ""

# Check if files provided
if [ $# -eq 0 ]; then
    echo -e "${YELLOW}No files specified. Usage: $0 [file1] [file2] ...${NC}"
    echo ""
    echo "Example:"
    echo "  $0 /tmp/test_script.sh /tmp/another_script.sh"
    echo "  $0 *.sh"
    exit 1
fi

# Check connection
echo -n "Testing connection to file transfer host... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes ${FILE_JUMP_USER}@${FILE_JUMP_HOST} exit 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}Warning: Cannot connect (may need password)${NC}"
fi

echo ""

# Upload files
success_count=0
fail_count=0

for file in "$@"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}✗${NC} Skipping: $file (not found)"
        ((fail_count++))
        continue
    fi

    echo -n "Uploading: $(basename $file) ... "

    if scp "$file" "${FILE_JUMP_USER}@${FILE_JUMP_HOST}:${FILE_JUMP_DIR}/"; then
        echo -e "${GREEN}✓${NC}"
        ((success_count++))
    else
        echo -e "${RED}✗${NC}"
        ((fail_count++))
    fi
done

echo ""
echo "========================================================================"
echo -e "Upload Summary: ${GREEN}${success_count} succeeded${NC}, ${RED}${fail_count} failed${NC}"
echo "========================================================================"

# List uploaded files
echo ""
echo "Files on remote host:"
ssh ${FILE_JUMP_USER}@${FILE_JUMP_HOST} "ls -lh ${FILE_JUMP_DIR}/ | tail -10"

exit $fail_count
