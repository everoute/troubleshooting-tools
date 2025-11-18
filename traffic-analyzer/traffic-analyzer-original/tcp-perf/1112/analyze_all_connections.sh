#!/bin/bash

echo "================================================================================"
echo "四连接 TCP Socket 测量数据分析"
echo "================================================================================"
echo ""

ANALYZER="/Users/admin/workspace/troubleshooting-tools/test/pcap-analyzer/parse_tcp_analyzer_data.py"
BASE_DIR="/Users/admin/workspace/troubleshooting-tools/test/pcap-analyzer/1112/iperf1112"

echo "### 客户端连接分析 ###"
echo ""

for i in 1 2 3 4; do
    echo "----------------------------------------"
    echo "客户端连接 $i"
    echo "----------------------------------------"
    python3 "$ANALYZER" "$BASE_DIR/client/client.$i" 2>&1 | sed -n '/Connection:/,/Latest/p' | head -20
    echo ""
done

echo ""
echo "### 服务器端连接分析 ###"
echo ""

for i in 1 2 3 4; do
    echo "----------------------------------------"
    echo "服务器端连接 $i"
    echo "----------------------------------------"
    python3 "$ANALYZER" "$BASE_DIR/server/server.$i" 2>&1 | sed -n '/Connection:/,/Latest/p' | head -20
    echo ""
done
