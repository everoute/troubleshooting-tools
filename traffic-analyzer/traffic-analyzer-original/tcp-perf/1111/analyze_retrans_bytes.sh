#!/bin/bash

CLIENT_PCAP="/Users/admin/workspace/troubleshooting-tools/test/pcap-analyzer/tcpdump1111/client"
SERVER_PCAP="/Users/admin/workspace/troubleshooting-tools/test/pcap-analyzer/tcpdump1111/server"

echo "=== 重传字节数分析 (数据包层面) ==="
echo ""
echo "客户端视角 - 服务端发送的数据:"
echo "--------------------------------"

# 服务端发送的总数据字节 (从客户端pcap看)
total_bytes=$(tshark -r "$CLIENT_PCAP" -Y "tcp.port==5001 && tcp.len > 0 && ip.src==100.100.103.201" -T fields -e tcp.len 2>/dev/null | awk '{sum+=$1} END {print sum}')
echo "服务端发送的总 TCP payload 字节: $total_bytes"

# 服务端重传的数据字节 (从客户端pcap看)
retrans_bytes=$(tshark -r "$CLIENT_PCAP" -Y "tcp.port==5001 && tcp.analysis.retransmission && tcp.len > 0 && ip.src==100.100.103.201" -T fields -e tcp.len 2>/dev/null | awk '{sum+=$1} END {print sum}')
echo "服务端重传的 TCP payload 字节: $retrans_bytes"

if [ -n "$total_bytes" ] && [ -n "$retrans_bytes" ] && [ "$total_bytes" -gt 0 ]; then
    rate=$(echo "scale=2; $retrans_bytes * 100 / $total_bytes" | bc)
    echo "数据字节重传率: ${rate}%"

    # 计算有效数据传输
    effective=$(echo "$total_bytes - $retrans_bytes" | bc)
    echo "有效传输的数据字节: $effective"

    # 计算带宽浪费
    overhead=$(echo "scale=2; $retrans_bytes * 100 / $effective" | bc)
    echo "重传带来的额外开销: ${overhead}%"
fi

echo ""
echo "服务端视角 - 服务端发送的数据:"
echo "--------------------------------"

# 服务端发送的总数据字节 (从服务端pcap看)
total_bytes_srv=$(tshark -r "$SERVER_PCAP" -Y "tcp.port==5001 && tcp.len > 0 && ip.src==100.100.103.201" -T fields -e tcp.len 2>/dev/null | awk '{sum+=$1} END {print sum}')
echo "服务端发送的总 TCP payload 字节: $total_bytes_srv"

# 服务端重传的数据字节 (从服务端pcap看)
retrans_bytes_srv=$(tshark -r "$SERVER_PCAP" -Y "tcp.port==5001 && tcp.analysis.retransmission && tcp.len > 0 && ip.src==100.100.103.201" -T fields -e tcp.len 2>/dev/null | awk '{sum+=$1} END {print sum}')
echo "服务端重传的 TCP payload 字节: $retrans_bytes_srv"

if [ -n "$total_bytes_srv" ] && [ -n "$retrans_bytes_srv" ] && [ "$total_bytes_srv" -gt 0 ]; then
    rate_srv=$(echo "scale=2; $retrans_bytes_srv * 100 / $total_bytes_srv" | bc)
    echo "数据字节重传率: ${rate_srv}%"

    # 计算有效数据传输
    effective_srv=$(echo "$total_bytes_srv - $retrans_bytes_srv" | bc)
    echo "有效传输的数据字节: $effective_srv"

    # 计算带宽浪费
    overhead_srv=$(echo "scale=2; $retrans_bytes_srv * 100 / $effective_srv" | bc)
    echo "重传带来的额外开销: ${overhead_srv}%"
fi

echo ""
echo "=== 重传包中有多少是纯 ACK (无数据) ==="
echo ""
echo "客户端:"
total_retrans=$(tshark -r "$CLIENT_PCAP" -Y "tcp.port==5001 && tcp.analysis.retransmission" 2>/dev/null | wc -l | tr -d ' ')
zero_len_retrans=$(tshark -r "$CLIENT_PCAP" -Y "tcp.port==5001 && tcp.analysis.retransmission && tcp.len==0" 2>/dev/null | wc -l | tr -d ' ')
echo "总重传包数: $total_retrans"
echo "其中 tcp.len=0 的包: $zero_len_retrans"
data_retrans=$(echo "$total_retrans - $zero_len_retrans" | bc)
echo "真正的数据重传: $data_retrans"

echo ""
echo "服务端:"
total_retrans_srv=$(tshark -r "$SERVER_PCAP" -Y "tcp.port==5001 && tcp.analysis.retransmission" 2>/dev/null | wc -l | tr -d ' ')
zero_len_retrans_srv=$(tshark -r "$SERVER_PCAP" -Y "tcp.port==5001 && tcp.analysis.retransmission && tcp.len==0" 2>/dev/null | wc -l | tr -d ' ')
echo "总重传包数: $total_retrans_srv"
echo "其中 tcp.len=0 的包: $zero_len_retrans_srv"
data_retrans_srv=$(echo "$total_retrans_srv - $zero_len_retrans_srv" | bc)
echo "真正的数据重传: $data_retrans_srv"
