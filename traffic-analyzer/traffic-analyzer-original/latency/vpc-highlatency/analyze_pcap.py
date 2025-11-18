#!/usr/bin/env python3
"""
PCAP analysis script for analyzing 02.pcap connections to 10.10.216.21:443
"""

import subprocess
import re
from collections import defaultdict
from datetime import datetime

def run_tcpdump(pcap_file, filter_expr=""):
    """Run tcpdump and return output lines"""
    cmd = ["tcpdump", "-r", pcap_file, "-nn", "-tt"]
    if filter_expr:
        cmd.append(filter_expr)

    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return result.stdout.strip().split('\n') if result.stdout else []

def parse_packet(line):
    """Parse tcpdump output line"""
    # Format: timestamp IP src.port > dst.port: Flags [...], ...
    match = re.match(
        r'^(\d+\.\d+)\s+IP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+Flags\s+\[([^\]]+)\]',
        line
    )
    if match:
        src_ip = match.group(2)
        dst_ip = match.group(4)
        src_port = int(match.group(3))
        dst_port = int(match.group(5))

        # Determine direction and connection port
        if src_ip == '10.10.64.28' and dst_ip == '10.10.216.21':
            direction = 'outbound'
            conn_port = src_port
        elif src_ip == '10.10.216.21' and dst_ip == '10.10.64.28':
            direction = 'inbound'
            conn_port = dst_port
        else:
            return None

        return {
            'timestamp': float(match.group(1)),
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'flags': match.group(6),
            'direction': direction,
            'conn_port': conn_port
        }
    return None

def analyze_connections(pcap_file):
    """Analyze all connections in the pcap file"""
    print(f"Analyzing {pcap_file}...")

    # Get all packets for the target
    lines = run_tcpdump(pcap_file, 'host 10.10.216.21 and port 443')

    connections = defaultdict(lambda: {
        'packets': [],
        'syn_time': None,
        'syn_ack_time': None,
        'established_time': None,
        'fin_time': None,
        'rst_time': None,
        'retransmissions': 0,
        'bytes_sent': 0,
        'bytes_recv': 0,
        'flags_seen': set()
    })

    # Parse all packets
    for line in lines:
        if not line.strip():
            continue

        pkt = parse_packet(line)
        if not pkt:
            continue

        # Connection key: client_port
        conn_key = pkt['conn_port']
        conn = connections[conn_key]
        conn['packets'].append(pkt)
        conn['flags_seen'].add(pkt['flags'])

        # Track connection state
        flags = pkt['flags']

        # SYN packet (outbound, no ACK)
        if ('S' in flags or 'SEW' in flags) and '.' not in flags and pkt['direction'] == 'outbound':
            if not conn['syn_time']:
                conn['syn_time'] = pkt['timestamp']

        # SYN-ACK packet (inbound, has both S and .)
        elif 'S.' in flags and pkt['direction'] == 'inbound':
            if not conn['syn_ack_time']:
                conn['syn_ack_time'] = pkt['timestamp']

        # First ACK after SYN-ACK (completing 3-way handshake)
        elif flags == '.' and pkt['direction'] == 'outbound' and conn['syn_ack_time'] and not conn['established_time']:
            conn['established_time'] = pkt['timestamp']

        # FIN packet
        if 'F' in flags:
            if not conn['fin_time']:
                conn['fin_time'] = pkt['timestamp']

        # RST packet
        if 'R' in flags:
            if not conn['rst_time']:
                conn['rst_time'] = pkt['timestamp']

    return connections

def print_connection_summary(connections):
    """Print summary statistics"""
    total = len(connections)
    completed = 0
    with_syn = 0
    with_syn_ack = 0
    with_fin = 0
    with_rst = 0
    avg_rtt = []

    for port, conn in connections.items():
        if conn['syn_time']:
            with_syn += 1
        if conn['syn_ack_time']:
            with_syn_ack += 1
            if conn['syn_time']:
                rtt = (conn['syn_ack_time'] - conn['syn_time']) * 1000  # ms
                avg_rtt.append(rtt)
        if conn['fin_time']:
            with_fin += 1
        if conn['rst_time']:
            with_rst += 1
        if conn['syn_time'] and conn['syn_ack_time'] and conn['fin_time']:
            completed += 1

    print("\n" + "="*70)
    print("CONNECTION SUMMARY")
    print("="*70)
    print(f"Total connections: {total}")
    print(f"Connections with SYN: {with_syn}")
    print(f"Connections with SYN-ACK: {with_syn_ack}")
    print(f"Connections with FIN: {with_fin}")
    print(f"Connections with RST: {with_rst}")
    print(f"Completed connections (SYN->SYN-ACK->FIN): {completed}")

    if avg_rtt:
        print(f"\nRTT Statistics (ms):")
        print(f"  Min: {min(avg_rtt):.3f}")
        print(f"  Max: {max(avg_rtt):.3f}")
        print(f"  Avg: {sum(avg_rtt)/len(avg_rtt):.3f}")
        print(f"  Median: {sorted(avg_rtt)[len(avg_rtt)//2]:.3f}")

    # Find anomalies
    print("\n" + "="*70)
    print("ANOMALY DETECTION")
    print("="*70)

    slow_handshakes = [(p, rtt) for p, rtt in enumerate(avg_rtt) if rtt > 100]
    if slow_handshakes:
        print(f"Slow handshakes (>100ms): {len(slow_handshakes)}")

    incomplete = total - completed
    if incomplete:
        print(f"Incomplete connections: {incomplete}")

    if with_rst:
        print(f"Connections with RST: {with_rst}")

def analyze_sample_connections(connections, sample_size=10):
    """Analyze a few sample connections in detail"""
    print("\n" + "="*70)
    print(f"SAMPLE CONNECTION DETAILS (first {sample_size})")
    print("="*70)

    count = 0
    for port in sorted(connections.keys()):
        if count >= sample_size:
            break

        conn = connections[port]
        print(f"\nConnection Port {port}:")
        print(f"  Packets: {len(conn['packets'])}")
        print(f"  Flags seen: {', '.join(sorted(conn['flags_seen']))}")

        if conn['syn_time'] and conn['syn_ack_time']:
            rtt = (conn['syn_ack_time'] - conn['syn_time']) * 1000
            print(f"  Handshake RTT: {rtt:.3f} ms")

        if conn['syn_time'] and conn['fin_time']:
            duration = conn['fin_time'] - conn['syn_time']
            print(f"  Connection duration: {duration:.3f} s")

        # Show first few packets
        print(f"  First 5 packets:")
        for i, pkt in enumerate(conn['packets'][:5]):
            print(f"    [{i}] {pkt['direction']:>8} Flags=[{pkt['flags']}] @ {pkt['timestamp']:.6f}")

        count += 1

if __name__ == "__main__":
    pcap_file = "/Users/admin/workspace/troubleshooting-tools/tmp/02.pcap"

    connections = analyze_connections(pcap_file)
    print_connection_summary(connections)
    analyze_sample_connections(connections, sample_size=10)

    print("\n" + "="*70)
    print("Analysis complete!")
    print("="*70)
