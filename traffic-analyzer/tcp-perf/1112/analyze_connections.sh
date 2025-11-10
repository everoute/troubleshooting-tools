#!/bin/bash

PCAP=$1
SIDE=$2

if [ -z "$PCAP" ] || [ -z "$SIDE" ]; then
    echo "Usage: $0 <pcap_file> <client|server>"
    exit 1
fi

echo "================================================================================"
echo "TCP Connection Analysis - $SIDE side"
echo "PCAP: $PCAP"
echo "================================================================================"
echo ""

# Get list of connections
PORTS=(48266 48264 48270 48268)

for PORT in "${PORTS[@]}"; do
    echo "================================================================================
Connection: 100.100.103.205:$PORT <-> 100.100.103.201:5001
================================================================================"

    # Basic statistics
    echo "### Basic Statistics ###"
    tshark -r "$PCAP" -Y "tcp.srcport==$PORT or tcp.dstport==$PORT" -q -z "io,stat,0" 2>/dev/null | grep -A 2 "Interval"

    echo ""
    echo "### Retransmissions ###"
    RETRANS=$(tshark -r "$PCAP" -Y "(tcp.srcport==$PORT or tcp.dstport==$PORT) and tcp.analysis.retransmission" 2>/dev/null | wc -l)
    echo "Total retransmissions: $RETRANS"

    # Fast retransmissions
    FAST_RETRANS=$(tshark -r "$PCAP" -Y "(tcp.srcport==$PORT or tcp.dstport==$PORT) and tcp.analysis.fast_retransmission" 2>/dev/null | wc -l)
    echo "Fast retransmissions: $FAST_RETRANS"

    # Spurious retransmissions
    SPUR_RETRANS=$(tshark -r "$PCAP" -Y "(tcp.srcport==$PORT or tcp.dstport==$PORT) and tcp.analysis.spurious_retransmission" 2>/dev/null | wc -l)
    echo "Spurious retransmissions: $SPUR_RETRANS"

    # Out-of-order
    OOO=$(tshark -r "$PCAP" -Y "(tcp.srcport==$PORT or tcp.dstport==$PORT) and tcp.analysis.out_of_order" 2>/dev/null | wc -l)
    echo "Out-of-order packets: $OOO"

    # Duplicate ACKs
    DUP_ACK=$(tshark -r "$PCAP" -Y "(tcp.srcport==$PORT or tcp.dstport==$PORT) and tcp.analysis.duplicate_ack" 2>/dev/null | wc -l)
    echo "Duplicate ACKs: $DUP_ACK"

    # Zero window
    ZERO_WIN=$(tshark -r "$PCAP" -Y "(tcp.srcport==$PORT or tcp.dstport==$PORT) and tcp.analysis.zero_window" 2>/dev/null | wc -l)
    echo "Zero window: $ZERO_WIN"

    echo ""
    echo "### Throughput ###"
    TOTAL_FRAMES=$(tshark -r "$PCAP" -Y "tcp.srcport==$PORT or tcp.dstport==$PORT" 2>/dev/null | wc -l)
    TOTAL_BYTES=$(tshark -r "$PCAP" -Y "tcp.srcport==$PORT or tcp.dstport==$PORT" -T fields -e frame.len 2>/dev/null | awk '{sum+=$1} END {print sum}')
    DURATION=$(tshark -r "$PCAP" -Y "tcp.srcport==$PORT or tcp.dstport==$PORT" -T fields -e frame.time_relative 2>/dev/null | tail -1)

    if [ ! -z "$DURATION" ] && [ ! -z "$TOTAL_BYTES" ]; then
        THROUGHPUT=$(echo "scale=2; $TOTAL_BYTES * 8 / $DURATION / 1000000000" | bc)
        echo "Duration: ${DURATION}s"
        echo "Total frames: $TOTAL_FRAMES"
        echo "Total bytes: $TOTAL_BYTES"
        echo "Average throughput: ${THROUGHPUT} Gbps"
    fi

    echo ""
done
