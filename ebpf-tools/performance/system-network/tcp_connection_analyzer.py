#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TCP Connection Analyzer

Collects and analyzes TCP connection details for performance troubleshooting.
Supports both client and server side analysis with bottleneck detection.

Features:
- Collect detailed TCP connection metrics using ss/netstat
- Calculate bandwidth-delay product (BDP) and recommended buffer sizes
- Detect performance bottlenecks (rwnd_limited, cwnd_limited, etc.)
- Provide actionable recommendations
- Support both single connection and continuous monitoring

Usage:
    # Analyze specific connection (client side)
    sudo python3 tcp_connection_analyzer.py --remote-ip 1.1.1.5 --remote-port 5201 --role client

    # Analyze specific connection (server side)
    sudo python3 tcp_connection_analyzer.py --local-port 5201 --role server

    # Continuous monitoring
    sudo python3 tcp_connection_analyzer.py --remote-ip 1.1.1.5 --remote-port 5201 --role client --interval 2

    # Monitor all connections to a port
    sudo python3 tcp_connection_analyzer.py --remote-port 5201 --role client --all
"""

import subprocess
import re
import sys
import argparse
import time
import json
from datetime import datetime
from collections import defaultdict


class TCPConnectionInfo:
    """Store TCP connection information"""

    def __init__(self):
        # Connection tuple
        self.local_addr = ""
        self.local_port = 0
        self.remote_addr = ""
        self.remote_port = 0
        self.state = ""

        # Queue status
        self.recv_q = 0
        self.send_q = 0

        # RTT metrics
        self.rtt = 0.0
        self.rttvar = 0.0
        self.rto = 0

        # Congestion control
        self.cwnd = 0
        self.ssthresh = 0
        self.ca_state = ""

        # Window sizes
        self.rcv_space = 0
        self.rcv_ssthresh = 0
        self.snd_wnd = 0

        # Rate metrics
        self.send_rate = 0
        self.pacing_rate = 0
        self.delivery_rate = 0

        # Retransmission
        self.retrans = 0
        self.retrans_total = 0
        self.lost = 0

        # Time limited statistics
        self.busy_time = 0
        self.rwnd_limited_time = 0
        self.rwnd_limited_ratio = 0.0
        self.sndbuf_limited_time = 0
        self.sndbuf_limited_ratio = 0.0
        self.cwnd_limited_time = 0
        self.cwnd_limited_ratio = 0.0

        # Bytes statistics
        self.bytes_sent = 0
        self.bytes_acked = 0
        self.bytes_received = 0

        # Other metrics
        self.mss = 0
        self.pmtu = 0
        self.wscale = ""
        self.minrtt = 0.0

        # Timestamp
        self.timestamp = datetime.now()


class TCPConnectionAnalyzer:
    """Analyze TCP connection performance"""

    def __init__(self, args):
        self.args = args
        self.system_config = {}
        self._load_system_config()

    def _load_system_config(self):
        """Load system TCP configuration"""
        configs = [
            'net.core.rmem_max',
            'net.core.wmem_max',
            'net.ipv4.tcp_rmem',
            'net.ipv4.tcp_wmem',
            'net.ipv4.tcp_moderate_rcvbuf',
            'net.ipv4.tcp_window_scaling',
            'net.ipv4.tcp_congestion_control',
            'net.ipv4.tcp_mem'
        ]

        for config in configs:
            try:
                result = subprocess.run(
                    ['sysctl', '-n', config],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    self.system_config[config] = result.stdout.strip()
            except Exception:
                pass

    def collect_connection_info(self):
        """Collect TCP connection information using ss"""
        connections = []

        # Build ss filter
        if self.args.role == 'client':
            if self.args.remote_ip and self.args.remote_port:
                ss_filter = f"dst {self.args.remote_ip} and dport = :{self.args.remote_port}"
            elif self.args.remote_port:
                ss_filter = f"dport = :{self.args.remote_port}"
            else:
                print("Error: client role requires --remote-port")
                return connections
        else:  # server
            if self.args.local_port:
                ss_filter = f"sport = :{self.args.local_port}"
            else:
                print("Error: server role requires --local-port")
                return connections

        # Add state filter
        if not self.args.all:
            ss_filter += " state established"

        # Execute ss command
        cmd = ['ss', '-tinopm', ss_filter]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                print(f"Error executing ss: {result.stderr}")
                return connections

            # Parse ss output
            connections = self._parse_ss_output(result.stdout)

        except subprocess.TimeoutExpired:
            print("Error: ss command timeout")
        except Exception as e:
            print(f"Error executing ss: {e}")

        return connections

    def _parse_ss_output(self, output):
        """Parse ss command output"""
        connections = []
        lines = output.strip().split('\n')

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Skip header and empty lines
            if not line or line.startswith('State') or line.startswith('Netid'):
                i += 1
                continue

            # Parse connection line
            conn = TCPConnectionInfo()

            # First line: State Recv-Q Send-Q Local Remote
            parts = line.split()
            if len(parts) >= 5:
                conn.state = parts[0]
                conn.recv_q = int(parts[1])
                conn.send_q = int(parts[2])

                # Parse local address
                local_parts = parts[3].rsplit(':', 1)
                if len(local_parts) == 2:
                    conn.local_addr = local_parts[0].strip('[]')
                    conn.local_port = int(local_parts[1])

                # Parse remote address
                remote_parts = parts[4].rsplit(':', 1)
                if len(remote_parts) == 2:
                    conn.remote_addr = remote_parts[0].strip('[]')
                    conn.remote_port = int(remote_parts[1])

            # Parse subsequent lines with metrics
            i += 1
            while i < len(lines) and not lines[i].strip().split()[0].isupper():
                metric_line = lines[i].strip()
                self._parse_metrics(conn, metric_line)
                i += 1

            connections.append(conn)

        return connections

    def _parse_metrics(self, conn, line):
        """Parse metrics from ss output line"""

        # RTT: rtt:0.078/0.036
        match = re.search(r'rtt:([\d.]+)/([\d.]+)', line)
        if match:
            conn.rtt = float(match.group(1))
            conn.rttvar = float(match.group(2))

        # RTO: rto:201
        match = re.search(r'rto:(\d+)', line)
        if match:
            conn.rto = int(match.group(1))

        # CWND: cwnd:10
        match = re.search(r'cwnd:(\d+)', line)
        if match:
            conn.cwnd = int(match.group(1))

        # SSTHRESH: ssthresh:285
        match = re.search(r'ssthresh:(\d+)', line)
        if match:
            conn.ssthresh = int(match.group(1))

        # MSS: mss:1448
        match = re.search(r'mss:(\d+)', line)
        if match:
            conn.mss = int(match.group(1))

        # PMTU: pmtu:1500
        match = re.search(r'pmtu:(\d+)', line)
        if match:
            conn.pmtu = int(match.group(1))

        # Window scale: wscale:9,9
        match = re.search(r'wscale:([\d,]+)', line)
        if match:
            conn.wscale = match.group(1)

        # Send rate: send 148512820bps
        match = re.search(r'send ([\d.]+)([KMG]?)bps', line)
        if match:
            conn.send_rate = self._parse_rate(match.group(1), match.group(2))

        # Pacing rate: pacing_rate 257809520bps
        match = re.search(r'pacing_rate ([\d.]+)([KMG]?)bps', line)
        if match:
            conn.pacing_rate = self._parse_rate(match.group(1), match.group(2))

        # Delivery rate: delivery_rate 3200000000bps
        match = re.search(r'delivery_rate ([\d.]+)([KMG]?)bps', line)
        if match:
            conn.delivery_rate = self._parse_rate(match.group(1), match.group(2))

        # Retransmissions: retrans:0/1195
        match = re.search(r'retrans:(\d+)/(\d+)', line)
        if match:
            conn.retrans = int(match.group(1))
            conn.retrans_total = int(match.group(2))

        # Lost packets: lost:5
        match = re.search(r'lost:(\d+)', line)
        if match:
            conn.lost = int(match.group(1))

        # Receive space: rcv_space:14480
        match = re.search(r'rcv_space:(\d+)', line)
        if match:
            conn.rcv_space = int(match.group(1))

        # Receive ssthresh: rcv_ssthresh:65535
        match = re.search(r'rcv_ssthresh:(\d+)', line)
        if match:
            conn.rcv_ssthresh = int(match.group(1))

        # Min RTT: minrtt:0.042
        match = re.search(r'minrtt:([\d.]+)', line)
        if match:
            conn.minrtt = float(match.group(1))

        # Busy time: busy:60000ms
        match = re.search(r'busy:(\d+)ms', line)
        if match:
            conn.busy_time = int(match.group(1))

        # rwnd_limited: rwnd_limited:157971ms(95.6%)
        match = re.search(r'rwnd_limited:(\d+)ms\(([\d.]+)%\)', line)
        if match:
            conn.rwnd_limited_time = int(match.group(1))
            conn.rwnd_limited_ratio = float(match.group(2))

        # sndbuf_limited: sndbuf_limited:1000ms(5.0%)
        match = re.search(r'sndbuf_limited:(\d+)ms\(([\d.]+)%\)', line)
        if match:
            conn.sndbuf_limited_time = int(match.group(1))
            conn.sndbuf_limited_ratio = float(match.group(2))

        # cwnd_limited: cwnd_limited:500ms(2.5%)
        match = re.search(r'cwnd_limited:(\d+)ms\(([\d.]+)%\)', line)
        if match:
            conn.cwnd_limited_time = int(match.group(1))
            conn.cwnd_limited_ratio = float(match.group(2))

        # Bytes sent: bytes_sent:189
        match = re.search(r'bytes_sent:(\d+)', line)
        if match:
            conn.bytes_sent = int(match.group(1))

        # Bytes acked: bytes_acked:190
        match = re.search(r'bytes_acked:(\d+)', line)
        if match:
            conn.bytes_acked = int(match.group(1))

        # Bytes received: bytes_received:4
        match = re.search(r'bytes_received:(\d+)', line)
        if match:
            conn.bytes_received = int(match.group(1))

    def _parse_rate(self, value, unit):
        """Parse rate value with unit (K/M/G)"""
        value = float(value)
        if unit == 'K':
            return int(value * 1000)
        elif unit == 'M':
            return int(value * 1000000)
        elif unit == 'G':
            return int(value * 1000000000)
        else:
            return int(value)

    def analyze_connection(self, conn):
        """Analyze connection and detect bottlenecks"""
        analysis = {
            'connection': f"{conn.local_addr}:{conn.local_port} -> {conn.remote_addr}:{conn.remote_port}",
            'state': conn.state,
            'timestamp': conn.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'metrics': {},
            'bottlenecks': [],
            'recommendations': []
        }

        # Basic metrics
        analysis['metrics']['recv_q'] = conn.recv_q
        analysis['metrics']['send_q'] = conn.send_q
        analysis['metrics']['rtt'] = f"{conn.rtt:.3f} ms"
        analysis['metrics']['rttvar'] = f"{conn.rttvar:.3f} ms"
        analysis['metrics']['cwnd'] = conn.cwnd
        analysis['metrics']['ssthresh'] = conn.ssthresh
        analysis['metrics']['rcv_space'] = f"{conn.rcv_space} bytes ({conn.rcv_space/1024:.1f} KB)"
        analysis['metrics']['mss'] = conn.mss
        analysis['metrics']['pmtu'] = conn.pmtu

        # Rate metrics
        if conn.send_rate > 0:
            analysis['metrics']['send_rate'] = f"{conn.send_rate/1000000000:.2f} Gbps"
        if conn.pacing_rate > 0:
            analysis['metrics']['pacing_rate'] = f"{conn.pacing_rate/1000000000:.2f} Gbps"
        if conn.delivery_rate > 0:
            analysis['metrics']['delivery_rate'] = f"{conn.delivery_rate/1000000000:.2f} Gbps"

        # Retransmission
        analysis['metrics']['retrans'] = f"{conn.retrans}/{conn.retrans_total}"
        if conn.lost > 0:
            analysis['metrics']['lost'] = conn.lost

        # Calculate BDP and recommended window
        if conn.rtt > 0:
            bdp_bytes = self._calculate_bdp(conn.rtt / 1000, self.args.target_bandwidth)
            analysis['metrics']['bdp'] = f"{bdp_bytes} bytes ({bdp_bytes/1024:.1f} KB)"
            analysis['metrics']['recommended_window'] = f"{bdp_bytes * 4} bytes ({bdp_bytes * 4 / 1024:.1f} KB)"

        # Bottleneck detection
        self._detect_bottlenecks(conn, analysis)

        return analysis

    def _calculate_bdp(self, rtt_sec, bandwidth_bps):
        """Calculate Bandwidth-Delay Product"""
        return int(bandwidth_bps * rtt_sec / 8)

    def _detect_bottlenecks(self, conn, analysis):
        """Detect performance bottlenecks"""

        # Check rwnd_limited
        if conn.rwnd_limited_ratio > 50:
            severity = 'CRITICAL' if conn.rwnd_limited_ratio > 80 else 'WARNING'
            analysis['bottlenecks'].append({
                'type': 'rwnd_limited',
                'severity': severity,
                'value': f"{conn.rwnd_limited_ratio:.1f}%",
                'description': f"Receive window limited for {conn.rwnd_limited_ratio:.1f}% of the time"
            })

            # Get recommended buffer size
            if conn.rtt > 0:
                bdp = self._calculate_bdp(conn.rtt / 1000, self.args.target_bandwidth)
                recommended = bdp * 4

                analysis['recommendations'].append({
                    'issue': 'Receive window too small',
                    'current': f"rcv_space = {conn.rcv_space} bytes ({conn.rcv_space/1024:.1f} KB)",
                    'recommended': f"{recommended} bytes ({recommended/1024:.1f} KB, {recommended/1024/1024:.1f} MB)",
                    'action': 'Increase tcp_rmem on the receiver side',
                    'commands': [
                        f"sudo sysctl -w net.core.rmem_max={recommended * 2}",
                        f"sudo sysctl -w net.ipv4.tcp_rmem=\"4096 131072 {recommended * 2}\""
                    ]
                })

        # Check cwnd_limited
        if conn.cwnd_limited_ratio > 50:
            severity = 'CRITICAL' if conn.cwnd_limited_ratio > 80 else 'WARNING'
            analysis['bottlenecks'].append({
                'type': 'cwnd_limited',
                'severity': severity,
                'value': f"{conn.cwnd_limited_ratio:.1f}%",
                'description': f"Congestion window limited for {conn.cwnd_limited_ratio:.1f}% of the time"
            })

            analysis['recommendations'].append({
                'issue': 'Congestion window limiting throughput',
                'current': f"cwnd = {conn.cwnd}",
                'action': 'Check for packet loss and network congestion',
                'commands': [
                    "ethtool -S <interface> | grep -E 'drop|error'",
                    "netstat -s | grep -i retrans"
                ]
            })

        # Check sndbuf_limited
        if conn.sndbuf_limited_ratio > 50:
            severity = 'CRITICAL' if conn.sndbuf_limited_ratio > 80 else 'WARNING'
            analysis['bottlenecks'].append({
                'type': 'sndbuf_limited',
                'severity': severity,
                'value': f"{conn.sndbuf_limited_ratio:.1f}%",
                'description': f"Send buffer limited for {conn.sndbuf_limited_ratio:.1f}% of the time"
            })

            analysis['recommendations'].append({
                'issue': 'Send buffer too small',
                'action': 'Increase tcp_wmem on the sender side',
                'commands': [
                    "sudo sysctl -w net.core.wmem_max=268435456",
                    "sudo sysctl -w net.ipv4.tcp_wmem=\"4096 65536 268435456\""
                ]
            })

        # Check small cwnd
        if conn.cwnd < 100 and conn.cwnd > 0:
            analysis['bottlenecks'].append({
                'type': 'small_cwnd',
                'severity': 'WARNING',
                'value': conn.cwnd,
                'description': f"Congestion window very small ({conn.cwnd}), possibly in slow start or recovery"
            })

        # Check retransmissions
        if conn.retrans_total > 100:
            analysis['bottlenecks'].append({
                'type': 'high_retransmissions',
                'severity': 'WARNING',
                'value': conn.retrans_total,
                'description': f"High retransmission count ({conn.retrans_total})"
            })

            analysis['recommendations'].append({
                'issue': 'High retransmissions detected',
                'action': 'Investigate packet loss',
                'commands': [
                    "ethtool -S <interface> | grep drop",
                    "Use eBPF tools to trace packet drops"
                ]
            })

        # Check Recv-Q
        if conn.recv_q > 0:
            analysis['bottlenecks'].append({
                'type': 'recv_queue_backlog',
                'severity': 'WARNING',
                'value': conn.recv_q,
                'description': f"Receive queue has backlog ({conn.recv_q} bytes), application may be slow"
            })

        # Check Send-Q
        if conn.send_q > conn.mss * 10:
            analysis['bottlenecks'].append({
                'type': 'send_queue_backlog',
                'severity': 'INFO',
                'value': conn.send_q,
                'description': f"Send queue has backlog ({conn.send_q} bytes)"
            })

        # Check pacing rate vs target bandwidth
        if conn.pacing_rate > 0 and self.args.target_bandwidth > 0:
            ratio = conn.pacing_rate / self.args.target_bandwidth
            if ratio < 0.5:
                analysis['bottlenecks'].append({
                    'type': 'low_pacing_rate',
                    'severity': 'WARNING',
                    'value': f"{conn.pacing_rate/1000000000:.2f} Gbps",
                    'description': f"Pacing rate ({conn.pacing_rate/1000000000:.2f} Gbps) much lower than target ({self.args.target_bandwidth/1000000000:.1f} Gbps)"
                })

    def print_analysis(self, analysis):
        """Print analysis results"""
        print(f"\n{'='*80}")
        print(f"TCP Connection Analysis - {analysis['timestamp']}")
        print(f"{'='*80}")
        print(f"Connection: {analysis['connection']}")
        print(f"State: {analysis['state']}")
        print()

        # Print metrics
        print("Metrics:")
        print("-" * 80)
        for key, value in analysis['metrics'].items():
            print(f"  {key:25s}: {value}")
        print()

        # Print bottlenecks
        if analysis['bottlenecks']:
            print("Bottlenecks Detected:")
            print("-" * 80)
            for bottleneck in analysis['bottlenecks']:
                severity_symbol = '🔴' if bottleneck['severity'] == 'CRITICAL' else '⚠️' if bottleneck['severity'] == 'WARNING' else 'ℹ️'
                print(f"  {severity_symbol} [{bottleneck['severity']}] {bottleneck['type']}")
                print(f"     Value: {bottleneck['value']}")
                print(f"     {bottleneck['description']}")
                print()
        else:
            print("✅ No obvious bottlenecks detected")
            print()

        # Print recommendations
        if analysis['recommendations']:
            print("Recommendations:")
            print("-" * 80)
            for i, rec in enumerate(analysis['recommendations'], 1):
                print(f"  {i}. Issue: {rec['issue']}")
                if 'current' in rec:
                    print(f"     Current: {rec['current']}")
                if 'recommended' in rec:
                    print(f"     Recommended: {rec['recommended']}")
                print(f"     Action: {rec['action']}")
                if 'commands' in rec:
                    print(f"     Commands:")
                    for cmd in rec['commands']:
                        print(f"       {cmd}")
                print()

        print(f"{'='*80}\n")

    def print_system_config(self):
        """Print system TCP configuration"""
        print(f"\n{'='*80}")
        print("System TCP Configuration")
        print(f"{'='*80}")

        for key, value in self.system_config.items():
            print(f"  {key:40s}: {value}")

        # Parse and highlight important values
        if 'net.ipv4.tcp_rmem' in self.system_config:
            values = self.system_config['net.ipv4.tcp_rmem'].split()
            if len(values) == 3:
                max_bytes = int(values[2])
                print(f"\n  TCP Receive Buffer Max: {max_bytes} bytes ({max_bytes/1024/1024:.1f} MB)")

        if 'net.ipv4.tcp_wmem' in self.system_config:
            values = self.system_config['net.ipv4.tcp_wmem'].split()
            if len(values) == 3:
                max_bytes = int(values[2])
                print(f"  TCP Send Buffer Max: {max_bytes} bytes ({max_bytes/1024/1024:.1f} MB)")

        print(f"{'='*80}\n")

    def run(self):
        """Main execution"""

        # Print system configuration
        if self.args.show_config:
            self.print_system_config()

        if self.args.interval > 0:
            # Continuous monitoring
            print(f"Starting continuous monitoring (interval: {self.args.interval}s)")
            print("Press Ctrl+C to stop...")

            try:
                while True:
                    connections = self.collect_connection_info()

                    if not connections:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] No connections found")
                    else:
                        for conn in connections:
                            analysis = self.analyze_connection(conn)
                            self.print_analysis(analysis)

                    time.sleep(self.args.interval)

            except KeyboardInterrupt:
                print("\nStopped by user")
        else:
            # Single shot
            connections = self.collect_connection_info()

            if not connections:
                print("No connections found matching the criteria")
                return

            for conn in connections:
                analysis = self.analyze_connection(conn)
                self.print_analysis(analysis)


def main():
    parser = argparse.ArgumentParser(
        description='TCP Connection Analyzer - Collect and analyze TCP connection performance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze client-side connection to iperf3 server
  %(prog)s --remote-ip 1.1.1.5 --remote-port 5201 --role client

  # Analyze server-side connections
  %(prog)s --local-port 5201 --role server

  # Continuous monitoring every 2 seconds
  %(prog)s --remote-ip 1.1.1.5 --remote-port 5201 --role client --interval 2

  # Monitor all connections to a port
  %(prog)s --remote-port 5201 --role client --all

  # Show system TCP configuration
  %(prog)s --show-config
        """
    )

    parser.add_argument('--role', type=str, choices=['client', 'server'],
                        required=True,
                        help='Role: client (initiator) or server (listener)')
    parser.add_argument('--remote-ip', type=str,
                        help='Remote IP address (for client role)')
    parser.add_argument('--remote-port', type=int,
                        help='Remote port number')
    parser.add_argument('--local-port', type=int,
                        help='Local port number (for server role)')
    parser.add_argument('--interval', type=int, default=0,
                        help='Monitoring interval in seconds (0 = single shot)')
    parser.add_argument('--all', action='store_true',
                        help='Monitor all connections (not just ESTABLISHED)')
    parser.add_argument('--target-bandwidth', type=float, default=25,
                        help='Target bandwidth in Gbps (default: 25)')
    parser.add_argument('--show-config', action='store_true',
                        help='Show system TCP configuration')
    parser.add_argument('--json', action='store_true',
                        help='Output in JSON format')

    args = parser.parse_args()

    # Convert bandwidth to bps
    args.target_bandwidth = int(args.target_bandwidth * 1000000000)

    # Create analyzer
    analyzer = TCPConnectionAnalyzer(args)

    # Run analysis
    analyzer.run()


if __name__ == '__main__':
    main()
