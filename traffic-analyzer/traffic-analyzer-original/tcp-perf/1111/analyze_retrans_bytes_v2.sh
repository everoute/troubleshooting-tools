#!/bin/bash

CLIENT_PCAP="/Users/admin/workspace/troubleshooting-tools/test/pcap-analyzer/tcpdump1111/client"
SERVER_PCAP="/Users/admin/workspace/troubleshooting-tools/test/pcap-analyzer/tcpdump1111/server"

echo "=== 重传字节数分析 (客户端上传数据给服务端) ==="
echo ""
echo "客户端视角 - 客户端发送的数据:"
echo "--------------------------------"

# 客户端发送的总数据字节
total_bytes=$(tshark -r "$CLIENT_PCAP" -Y "tcp.port==5001 && tcp.len > 0 && ip.src==100.100.103.205" -T fields -e tcp.len 2>/dev/null | awk '{sum+=$1} END {print sum}')
echo "客户端发送的总 TCP payload 字节: $total_bytes"

# 客户端重传的数据字节
retrans_bytes=$(tshark -r "$CLIENT_PCAP" -Y "tcp.port==5001 && tcp.analysis.retransmission && tcp.len > 0 && ip.src==100.100.103.205" -T fields -e tcp.len 2>/dev/null | awk '{sum+=$1} END {print sum}')
echo "客户端重传的 TCP payload 字节: $retrans_bytes"

if [ -n "$total_bytes" ] && [ -n "$retrans_bytes" ] && [ "$total_bytes" -gt 0 ]; then
    rate=$(echo "scale=2; $retrans_bytes * 100 / $total_bytes" | bc)
    echo "数据字节重传率: ${rate}%"

    # 计算有效数据传输
    effective=$(echo "$total_bytes - $retrans_bytes" | bc)
    echo "有效传输的数据字节: $effective"
    echo "  转换为 MB: $(echo "scale=2; $effective / 1024 / 1024" | bc) MB"

    # 计算带宽浪费
    if [ "$effective" -gt 0 ]; then
        overhead=$(echo "scale=2; $retrans_bytes * 100 / $effective" | bc)
        echo "重传带来的额外开销: ${overhead}% (相对于有效数据)"
    fi
fi

echo ""
echo "服务端视角 - 客户端发送的数据:"
echo "--------------------------------"

# 服务端收到的总数据字节
total_bytes_srv=$(tshark -r "$SERVER_PCAP" -Y "tcp.port==5001 && tcp.len > 0 && ip.src==100.100.103.205" -T fields -e tcp.len 2>/dev/null | awk '{sum+=$1} END {print sum}')
echo "服务端收到的总 TCP payload 字节: $total_bytes_srv"

# 服务端看到的重传数据字节
retrans_bytes_srv=$(tshark -r "$SERVER_PCAP" -Y "tcp.port==5001 && tcp.analysis.retransmission && tcp.len > 0 && ip.src==100.100.103.205" -T fields -e tcp.len 2>/dev/null | awk '{sum+=$1} END {print sum}')
echo "服务端看到的重传 TCP payload 字节: $retrans_bytes_srv"

if [ -n "$total_bytes_srv" ] && [ -n "$retrans_bytes_srv" ] && [ "$total_bytes_srv" -gt 0 ]; then
    rate_srv=$(echo "scale=2; $retrans_bytes_srv * 100 / $total_bytes_srv" | bc)
    echo "数据字节重传率: ${rate_srv}%"

    # 计算有效数据传输
    effective_srv=$(echo "$total_bytes_srv - $retrans_bytes_srv" | bc)
    echo "有效传输的数据字节: $effective_srv"
    echo "  转换为 MB: $(echo "scale=2; $effective_srv / 1024 / 1024" | bc) MB"

    # 计算带宽浪费
    if [ "$effective_srv" -gt 0 ]; then
        overhead_srv=$(echo "scale=2; $retrans_bytes_srv * 100 / $effective_srv" | bc)
        echo "重传带来的额外开销: ${overhead_srv}% (相对于有效数据)"
    fi
fi

echo ""
echo "=== 统计数据传输方向 ==="
echo ""
# 客户端发送 vs 服务端发送
client_to_server=$(tshark -r "$CLIENT_PCAP" -Y "tcp.port==5001 && tcp.len > 0 && ip.src==100.100.103.205" -T fields -e tcp.len 2>/dev/null | awk '{sum+=$1} END {print sum}')
server_to_client=$(tshark -r "$CLIENT_PCAP" -Y "tcp.port==5001 && tcp.len > 0 && ip.src==100.100.103.201" -T fields -e tcp.len 2>/dev/null | awk '{sum+=$1} END {print sum}')

echo "客户端 -> 服务端: $(echo "scale=2; $client_to_server / 1024 / 1024" | bc) MB"
echo "服务端 -> 客户端: $(echo "scale=2; $server_to_client / 1024 / 1024" | bc) MB"
echo ""
echo "=> 这是一个 iperf3 上传测试 (客户端上传数据到服务端)"
