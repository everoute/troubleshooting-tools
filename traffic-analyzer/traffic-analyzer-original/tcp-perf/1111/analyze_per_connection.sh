#!/bin/bash

CLIENT_PCAP="/Users/admin/workspace/troubleshooting-tools/test/pcap-analyzer/tcpdump1111/client"
SERVER_PCAP="/Users/admin/workspace/troubleshooting-tools/test/pcap-analyzer/tcpdump1111/server"

echo "=== iperf3 每个连接的详细分析 ==="
echo ""
echo "控制连接 (端口 35994):"
echo "---------------------"
total=$(tshark -r "$CLIENT_PCAP" -Y "tcp.srcport==35994 || tcp.dstport==35994" 2>/dev/null | wc -l | tr -d ' ')
retrans=$(tshark -r "$CLIENT_PCAP" -Y "(tcp.srcport==35994 || tcp.dstport==35994) && tcp.analysis.retransmission" 2>/dev/null | wc -l | tr -d ' ')
echo "客户端视角: 总包数=$total, 重传=$retrans"

total_srv=$(tshark -r "$SERVER_PCAP" -Y "tcp.srcport==35994 || tcp.dstport==35994" 2>/dev/null | wc -l | tr -d ' ')
retrans_srv=$(tshark -r "$SERVER_PCAP" -Y "(tcp.srcport==35994 || tcp.dstport==35994) && tcp.analysis.retransmission" 2>/dev/null | wc -l | tr -d ' ')
echo "服务端视角: 总包数=$total_srv, 重传=$retrans_srv"

echo ""
echo "数据连接分析 (16个并发流):"
echo "---------------------"
printf "%-8s | %-12s | %-8s | %-10s | %-12s | %-8s | %-10s\n" "端口" "客户端总包" "客户端重传" "重传率%" "服务端总包" "服务端重传" "重传率%"
printf "%s\n" "-----------------------------------------------------------------------------------------"

for port in 35996 35998 36000 36002 36004 36006 36008 36010 36012 36014 36016 36018 36020 36022 36024 36026; do
    total=$(tshark -r "$CLIENT_PCAP" -Y "tcp.srcport==$port || tcp.dstport==$port" 2>/dev/null | wc -l | tr -d ' ')
    retrans=$(tshark -r "$CLIENT_PCAP" -Y "(tcp.srcport==$port || tcp.dstport==$port) && tcp.analysis.retransmission" 2>/dev/null | wc -l | tr -d ' ')

    total_srv=$(tshark -r "$SERVER_PCAP" -Y "tcp.srcport==$port || tcp.dstport==$port" 2>/dev/null | wc -l | tr -d ' ')
    retrans_srv=$(tshark -r "$SERVER_PCAP" -Y "(tcp.srcport==$port || tcp.dstport==$port) && tcp.analysis.retransmission" 2>/dev/null | wc -l | tr -d ' ')

    if [ "$total" -gt 0 ]; then
        rate=$(echo "scale=2; $retrans * 100 / $total" | bc)
    else
        rate="0"
    fi

    if [ "$total_srv" -gt 0 ]; then
        rate_srv=$(echo "scale=2; $retrans_srv * 100 / $total_srv" | bc)
    else
        rate_srv="0"
    fi

    printf "%-8s | %-12s | %-8s | %-10s | %-12s | %-8s | %-10s\n" "$port" "$total" "$retrans" "$rate" "$total_srv" "$retrans_srv" "$rate_srv"
done
