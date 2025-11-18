#!/usr/bin/env python3
"""
Detailed PCAP analysis for 10.10.216.21:443 connections
Analyzes retransmissions, delays, window sizes, and anomalies
"""

import subprocess
import re
from collections import defaultdict
import json

def run_tcpdump_verbose(pcap_file, filter_expr=""):
    """Run tcpdump with verbose output"""
    cmd = ["tcpdump", "-r", pcap_file, "-nn", "-tt", "-v"]
    if filter_expr:
        cmd.append(filter_expr)

    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return result.stdout.strip().split('\n') if result.stdout else []

def parse_packet_detailed(line):
    """Parse tcpdump verbose output"""
    # Pattern for TCP packets with sequence numbers
    match = re.match(
        r'^(\d+\.\d+)\s+IP.*?(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+Flags\s+\[([^\]]+)\]'
        r'(?:.*?seq\s+(\d+)(?::(\d+))?)?(?:.*?ack\s+(\d+))?(?:.*?win\s+(\d+))?(?:.*?length\s+(\d+))?',
        line, re.IGNORECASE
    )

    if match:
        src_ip = match.group(2)
        dst_ip = match.group(4)
        src_port = int(match.group(3))
        dst_port = int(match.group(5))

        if src_ip == '10.10.64.28' and dst_ip == '10.10.216.21':
            direction = 'outbound'
            conn_port = src_port
        elif src_ip == '10.10.216.21' and dst_ip == '10.10.64.28':
            direction = 'inbound'
            conn_port = dst_port
        else:
            return None

        pkt = {
            'timestamp': float(match.group(1)),
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'flags': match.group(6),
            'direction': direction,
            'conn_port': conn_port,
        }

        # Add sequence numbers if present
        if match.group(7):
            pkt['seq_start'] = int(match.group(7))
            if match.group(8):
                pkt['seq_end'] = int(match.group(8))
            else:
                pkt['seq_end'] = pkt['seq_start']

        if match.group(9):
            pkt['ack'] = int(match.group(9))
        if match.group(10):
            pkt['win'] = int(match.group(10))
        if match.group(11):
            pkt['length'] = int(match.group(11))
        else:
            pkt['length'] = 0

        return pkt
    return None

def analyze_detailed(pcap_file):
    """Detailed connection analysis"""
    print(f"Performing detailed analysis of {pcap_file}...")

    lines = run_tcpdump_verbose(pcap_file, 'host 10.10.216.21 and port 443')

    connections = defaultdict(lambda: {
        'packets': [],
        'seq_seen': set(),  # Track sequence numbers for retransmission detection
        'retransmissions': [],
        'out_of_order': [],
        'delays': [],  # Packet to ACK delays
        'handshake_rtt': None,
        'data_rtts': [],
        'window_sizes': [],
        'anomalies': []
    })

    # Parse packets
    for line in lines:
        if not line.strip():
            continue
        pkt = parse_packet_detailed(line)
        if pkt:
            conn = connections[pkt['conn_port']]
            conn['packets'].append(pkt)

    # Analyze each connection
    for port, conn in connections.items():
        packets = conn['packets']

        # Detect retransmissions
        outbound_seqs = {}
        for i, pkt in enumerate(packets):
            if pkt['direction'] == 'outbound' and 'seq_start' in pkt and pkt['length'] > 0:
                seq_key = (pkt['seq_start'], pkt['length'])
                if seq_key in outbound_seqs:
                    # Retransmission detected
                    original_idx = outbound_seqs[seq_key]
                    delay = pkt['timestamp'] - packets[original_idx]['timestamp']
                    conn['retransmissions'].append({
                        'seq': pkt['seq_start'],
                        'length': pkt['length'],
                        'original_time': packets[original_idx]['timestamp'],
                        'retrans_time': pkt['timestamp'],
                        'delay': delay
                    })
                else:
                    outbound_seqs[seq_key] = i

        # Calculate handshake RTT
        syn_pkt = None
        syn_ack_pkt = None
        for pkt in packets:
            if not syn_pkt and 'SEW' in pkt['flags'] and pkt['direction'] == 'outbound':
                syn_pkt = pkt
            elif syn_pkt and not syn_ack_pkt and 'S.' in pkt['flags'] and pkt['direction'] == 'inbound':
                syn_ack_pkt = pkt
                conn['handshake_rtt'] = (syn_ack_pkt['timestamp'] - syn_pkt['timestamp']) * 1000
                break

        # Calculate data RTTs (outbound data packet to inbound ACK)
        for i, pkt in enumerate(packets):
            if pkt['direction'] == 'outbound' and pkt['length'] > 0 and 'seq_end' in pkt:
                expected_ack = pkt['seq_end']
                # Find corresponding ACK
                for j in range(i+1, min(i+10, len(packets))):  # Look ahead up to 10 packets
                    ack_pkt = packets[j]
                    if ack_pkt['direction'] == 'inbound' and 'ack' in ack_pkt:
                        if ack_pkt['ack'] >= expected_ack:
                            rtt = (ack_pkt['timestamp'] - pkt['timestamp']) * 1000
                            conn['data_rtts'].append(rtt)
                            conn['delays'].append({
                                'pkt_time': pkt['timestamp'],
                                'ack_time': ack_pkt['timestamp'],
                                'rtt_ms': rtt
                            })
                            break

        # Track window sizes
        for pkt in packets:
            if 'win' in pkt:
                conn['window_sizes'].append({
                    'time': pkt['timestamp'],
                    'direction': pkt['direction'],
                    'size': pkt['win']
                })

        # Detect anomalies
        if conn['retransmissions']:
            conn['anomalies'].append(f"{len(conn['retransmissions'])} retransmissions detected")

        if 'R' in [p['flags'] for p in packets]:
            conn['anomalies'].append("Connection reset (RST) detected")

        if conn['data_rtts']:
            avg_rtt = sum(conn['data_rtts']) / len(conn['data_rtts'])
            max_rtt = max(conn['data_rtts'])
            if max_rtt > avg_rtt * 5:
                conn['anomalies'].append(f"High RTT variance detected (max: {max_rtt:.2f}ms, avg: {avg_rtt:.2f}ms)")

    return connections

def print_detailed_report(connections):
    """Print comprehensive analysis report"""
    print("\n" + "="*80)
    print("COMPREHENSIVE PCAP ANALYSIS REPORT")
    print("Target: 10.10.216.21:443")
    print("="*80)

    total_conns = len(connections)
    total_packets = sum(len(conn['packets']) for conn in connections.values())
    total_retrans = sum(len(conn['retransmissions']) for conn in connections.values())

    print(f"\n### OVERALL STATISTICS ###")
    print(f"Total Connections: {total_conns}")
    print(f"Total Packets: {total_packets}")
    print(f"Total Retransmissions: {total_retrans}")
    if total_packets > 0:
        print(f"Retransmission Rate: {(total_retrans/total_packets)*100:.2f}%")

    # Handshake RTT summary
    handshake_rtts = [conn['handshake_rtt'] for conn in connections.values() if conn['handshake_rtt']]
    if handshake_rtts:
        print(f"\n### HANDSHAKE RTT (3-way) ###")
        print(f"Min: {min(handshake_rtts):.3f} ms")
        print(f"Max: {max(handshake_rtts):.3f} ms")
        print(f"Avg: {sum(handshake_rtts)/len(handshake_rtts):.3f} ms")

    # Data RTT summary
    all_data_rtts = []
    for conn in connections.values():
        all_data_rtts.extend(conn['data_rtts'])

    if all_data_rtts:
        print(f"\n### DATA TRANSMISSION RTT ###")
        print(f"Samples: {len(all_data_rtts)}")
        print(f"Min: {min(all_data_rtts):.3f} ms")
        print(f"Max: {max(all_data_rtts):.3f} ms")
        print(f"Avg: {sum(all_data_rtts)/len(all_data_rtts):.3f} ms")
        sorted_rtts = sorted(all_data_rtts)
        print(f"Median: {sorted_rtts[len(sorted_rtts)//2]:.3f} ms")
        print(f"95th percentile: {sorted_rtts[int(len(sorted_rtts)*0.95)]:.3f} ms")

    # Per-connection details
    print(f"\n{'='*80}")
    print("PER-CONNECTION ANALYSIS")
    print(f"{'='*80}")

    for port in sorted(connections.keys()):
        conn = connections[port]
        packets = conn['packets']

        print(f"\n### Connection Port {port} ###")
        print(f"Total Packets: {len(packets)}")
        print(f"Duration: {(packets[-1]['timestamp'] - packets[0]['timestamp']):.3f} s")

        if conn['handshake_rtt']:
            print(f"Handshake RTT: {conn['handshake_rtt']:.3f} ms")

        if conn['data_rtts']:
            print(f"Data RTT - Min: {min(conn['data_rtts']):.3f} ms, "
                  f"Max: {max(conn['data_rtts']):.3f} ms, "
                  f"Avg: {sum(conn['data_rtts'])/len(conn['data_rtts']):.3f} ms")

        if conn['retransmissions']:
            print(f"Retransmissions: {len(conn['retransmissions'])}")
            for retrans in conn['retransmissions'][:3]:  # Show first 3
                print(f"  - Seq {retrans['seq']}, delay: {retrans['delay']*1000:.2f} ms")

        if conn['anomalies']:
            print(f"Anomalies:")
            for anomaly in conn['anomalies']:
                print(f"  - {anomaly}")

        # Check for slow connections (if active connection lasted > 1s)
        if len(packets) > 10:
            first_time = packets[0]['timestamp']
            last_time = packets[-1]['timestamp']
            if last_time - first_time > 1.0:
                throughput_estimate = sum(p.get('length', 0) for p in packets if p['direction'] == 'inbound')
                throughput_mbps = (throughput_estimate * 8) / (last_time - first_time) / 1000000
                print(f"Approximate throughput: {throughput_mbps:.2f} Mbps")

    print(f"\n{'='*80}")
    print("ANALYSIS COMPLETE")
    print(f"{'='*80}\n")

if __name__ == "__main__":
    pcap_file = "/Users/admin/workspace/troubleshooting-tools/tmp/02.pcap"
    connections = analyze_detailed(pcap_file)
    print_detailed_report(connections)
