#!/bin/bash

PCAP=$1
SIDE=$2

if [ -z "$PCAP" ] || [ -z "$SIDE" ]; then
    echo "Usage: $0 <pcap_file> <client|server>"
    exit 1
fi

echo "================================================================================"
echo "TCP Retransmission Type Analysis - $SIDE side"
echo "PCAP: $PCAP"
echo "================================================================================"
echo ""

PORTS=(48266 48264 48270 48268)

for PORT in "${PORTS[@]}"; do
    echo "================================================================================"
    echo "Connection: :$PORT"
    echo "================================================================================"

    # Total retransmissions
    TOTAL_RETRANS=$(tshark -r "$PCAP" -Y "(tcp.srcport==$PORT or tcp.dstport==$PORT) and tcp.analysis.retransmission" 2>/dev/null | wc -l)

    # Fast retransmissions
    FAST_RETRANS=$(tshark -r "$PCAP" -Y "(tcp.srcport==$PORT or tcp.dstport==$PORT) and tcp.analysis.fast_retransmission" 2>/dev/null | wc -l)

    # Spurious retransmissions
    SPUR_RETRANS=$(tshark -r "$PCAP" -Y "(tcp.srcport==$PORT or tcp.dstport==$PORT) and tcp.analysis.spurious_retransmission" 2>/dev/null | wc -l)

    # RTO retransmissions (timeout-based)
    # RTO retrans = Total retrans - Fast retrans - Spurious retrans (approximate)
    RTO_RETRANS=$((TOTAL_RETRANS - FAST_RETRANS - SPUR_RETRANS))

    echo "总重传数: $TOTAL_RETRANS"
    echo ""
    echo "重传类型分布:"
    echo "  快速重传 (Fast Retransmission):  $FAST_RETRANS"
    echo "  超时重传 (RTO):                  $RTO_RETRANS"
    echo "  虚假重传 (Spurious):             $SPUR_RETRANS"
    echo ""

    # Calculate percentages
    if [ $TOTAL_RETRANS -gt 0 ]; then
        FAST_PCT=$(echo "scale=1; $FAST_RETRANS * 100 / $TOTAL_RETRANS" | bc)
        RTO_PCT=$(echo "scale=1; $RTO_RETRANS * 100 / $TOTAL_RETRANS" | bc)
        SPUR_PCT=$(echo "scale=1; $SPUR_RETRANS * 100 / $TOTAL_RETRANS" | bc)

        echo "百分比:"
        echo "  快速重传: ${FAST_PCT}%"
        echo "  超时重传: ${RTO_PCT}%"
        echo "  虚假重传: ${SPUR_PCT}%"
    fi

    # DupACK count
    DUPACK=$(tshark -r "$PCAP" -Y "(tcp.srcport==$PORT or tcp.dstport==$PORT) and tcp.analysis.duplicate_ack" 2>/dev/null | wc -l)
    echo ""
    echo "DupACK 数量: $DUPACK"

    # Calculate DupACK to Fast Retransmission ratio
    if [ $FAST_RETRANS -gt 0 ]; then
        RATIO=$(echo "scale=2; $DUPACK / $FAST_RETRANS" | bc)
        echo "DupACK/快速重传比率: $RATIO (理论值 ≥ 3.0)"
    fi

    echo ""
done

echo "================================================================================"
echo "重传类型说明"
echo "================================================================================"
echo ""
echo "1. 快速重传 (Fast Retransmission):"
echo "   - 触发条件: 收到 3 个 DupACK"
echo "   - 特点: 不等待 RTO 超时，立即重传"
echo "   - 表明: 接收端检测到乱序/丢包"
echo ""
echo "2. 超时重传 (RTO Retransmission):"
echo "   - 触发条件: RTO (Retransmission Timeout) 超时"
echo "   - 特点: 等待超时才重传"
echo "   - 表明: 严重丢包，连续多个包丢失"
echo ""
echo "3. 虚假重传 (Spurious Retransmission):"
echo "   - 触发条件: 原始数据已被 ACK，但仍然重传"
echo "   - 特点: 不必要的重传"
echo "   - 表明: RTO 估计不准确或网络延迟抖动大"
echo ""
