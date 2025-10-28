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
    # Analyze client-side connection to iperf3 server
    sudo python3 tcp_connection_analyzer.py --remote-ip 1.1.1.5 --remote-port 5201 --role client

    # Analyze server-side connections on port 5201
    sudo python3 tcp_connection_analyzer.py --local-port 5201 --role server

    # Filter by specific local IP (multi-homed hosts)
    sudo python3 tcp_connection_analyzer.py --local-ip 70.0.0.31 --local-port 2181 --role server

    # Filter both local and remote endpoints
    sudo python3 tcp_connection_analyzer.py --local-ip 70.0.0.31 --remote-ip 70.0.0.32 --local-port 2181 --role server

    # Continuous monitoring
    sudo python3 tcp_connection_analyzer.py --remote-ip 1.1.1.5 --remote-port 5201 --role client --interval 2
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
        self.system_stats = {}
        self._load_system_config()
        # Don't load stats in __init__, load on-demand in run() for freshness

    def _find_ss_command(self):
        """Find ss command path"""
        # Try common paths
        possible_paths = [
            '/usr/sbin/ss',
            '/sbin/ss',
            '/usr/bin/ss',
            '/bin/ss',
            'ss'  # Try PATH
        ]

        for path in possible_paths:
            try:
                result = subprocess.run(
                    [path, '-V'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    timeout=2
                )
                if result.returncode == 0:
                    return path
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        return None

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
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    timeout=5
                )
                if result.returncode == 0:
                    self.system_config[config] = result.stdout.strip()
            except Exception:
                pass

    def _load_system_stats(self):
        """Load system-wide TCP statistics from netstat -s"""
        try:
            result = subprocess.run(
                ['netstat', '-s'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=10
            )
            if result.returncode == 0:
                self._parse_netstat_stats(result.stdout)
        except Exception as e:
            # netstat not available, skip
            pass

    def _parse_netstat_stats(self, output):
        """Parse netstat -s output for TCP statistics"""
        lines = output.split('\n')
        in_tcp_section = False

        # Key statistics to extract
        stats_patterns = {
            # === Retransmission Type Breakdown ===
            'segments_retransmitted': r'(\d+) segments retransmit',
            'fast_retransmits': r'(\d+) fast retransmits',
            'retrans_in_slowstart': r'(\d+) retransmits in slow start',
            'tcp_loss_probes': r'TCPLossProbes:\s*(\d+)',
            'tcp_loss_probe_recovery': r'TCPLossProbeRecovery:\s*(\d+)',
            'tcp_lost_retransmit': r'TCPLostRetransmit:\s*(\d+)',
            'tcp_spurious_rtos': r'TCPSpuriousRTOs:\s*(\d+)',
            'tcp_syn_retrans': r'TCPSynRetrans:\s*(\d+)',

            # === Timeout Types ===
            'timeout_after_sack': r'(\d+) timeouts after SACK recovery',
            'timeout_in_loss': r'(\d+) timeouts in loss state',
            'other_tcp_timeouts': r'(\d+) other TCP timeouts',

            # === Stack Packet Drops ===
            'rcv_pruned': r'(\d+) packets pruned from receive queue because of socket buffer overrun',
            'rcv_collapsed': r'(\d+) packets collapsed in receive queue due to low socket buffer',
            'tcp_backlog_drop': r'TCPBacklogDrop:\s*(\d+)',
            'listen_overflows': r'(\d+) times the listen queue of a socket overflowed',
            'listen_drops': r'(\d+) SYNs to LISTEN sockets dropped',
            'sack_retrans_fail': r'(\d+) SACK retransmits failed',

            # === SACK & Reordering ===
            'sack_recovery': r'(\d+) times recovered from packet loss by selective acknowledgements',
            'sack_reordering': r'Detected reordering (\d+) times using SACK',
            'reordering_ts': r'Detected reordering (\d+) times using time stamp',

            # === Congestion Window Recovery ===
            'tcp_full_undo': r'(\d+) congestion windows fully recovered without slow start',
            'tcp_partial_undo': r'(\d+) congestion windows partially recovered using Hoe heuristic',
            'tcp_dsack_undo': r'(\d+) congestion windows recovered without slow start by DSACK',

            # === Connection Issues ===
            'failed_connection_attempts': r'(\d+) failed connection attempts',
            'connection_resets_received': r'(\d+) connection resets received',
            'connection_resets_sent': r'(\d+) resets sent',
            'reset_due_to_unexpected_data': r'(\d+) connections reset due to unexpected data',
            'reset_due_to_early_close': r'(\d+) connections reset due to early user close',
            'abort_on_timeout': r'(\d+) connections aborted due to timeout',

            # === Basic Counters ===
            'segments_sent': r'(\d+) segments s[e]?nd out',
            'segments_received': r'(\d+) segments received',
            'bad_segments': r'(\d+) bad segments received',
            'delayed_acks_sent': r'(\d+) delayed acks sent',
        }

        for line in lines:
            line_stripped = line.strip()

            # Detect TCP or TcpExt section
            if 'Tcp:' in line_stripped or 'TCP:' in line_stripped or 'TcpExt:' in line_stripped:
                in_tcp_section = True
                continue
            elif line_stripped and len(line_stripped) > 0 and line_stripped[0].isupper() and ':' in line_stripped and 'TCP' not in line_stripped:
                # New section started (e.g., "Udp:", "Ip:")
                # But don't exit if it's a TCP* counter like "TCPLossProbes:"
                in_tcp_section = False
                continue

            if in_tcp_section:
                # Try to match patterns
                for key, pattern in stats_patterns.items():
                    match = re.search(pattern, line_stripped, re.IGNORECASE)
                    if match:
                        self.system_stats[key] = int(match.group(1))
                        break

    def collect_connection_info(self):
        """Collect TCP connection information using ss"""
        connections = []

        # Determine ss command path
        ss_cmd = self._find_ss_command()
        if not ss_cmd:
            print("Error: ss command not found. Please install iproute/iproute2 package.")
            return connections

        # Build ss filter expression (in parentheses for older ss versions)
        # Build filter conditions list
        conditions = []

        if self.args.local_ip:
            conditions.append(f"src {self.args.local_ip}")
        if self.args.local_port:
            conditions.append(f"sport = :{self.args.local_port}")
        if self.args.remote_ip:
            conditions.append(f"dst {self.args.remote_ip}")
        if self.args.remote_port:
            conditions.append(f"dport = :{self.args.remote_port}")

        # Role-based validation and defaults
        if self.args.role == 'client':
            # Client role: typically filter by destination
            if not self.args.remote_port and not self.args.remote_ip:
                print("Error: client role requires at least --remote-port or --remote-ip")
                return connections
        else:  # server
            # Server role: typically filter by source port (local listening port)
            if not self.args.local_port and not self.args.local_ip:
                print("Error: server role requires at least --local-port or --local-ip")
                return connections

        # Combine conditions
        if not conditions:
            print("Error: no filter conditions specified")
            return connections

        filter_expr = "( " + " and ".join(conditions) + " )"

        # Build complete ss command
        # Format: ss -tinopm [state STATE] 'filter_expression'
        if self.args.all:
            cmd = [ss_cmd, '-tinopm', filter_expr]
        else:
            cmd = [ss_cmd, '-tinopm', 'state', 'established', filter_expr]

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
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
            if not line or line.startswith('State') or line.startswith('Netid') or line.startswith('Recv-Q'):
                i += 1
                continue

            # Parse connection line
            conn = TCPConnectionInfo()

            # First line: Recv-Q Send-Q Local Remote (or State Recv-Q Send-Q Local Remote)
            parts = line.split()
            if len(parts) < 4:
                i += 1
                continue

            # Try to parse based on whether first column is numeric (Recv-Q) or text (State)
            try:
                # Old format: Recv-Q Send-Q Local Remote
                conn.recv_q = int(parts[0])
                conn.send_q = int(parts[1])
                conn.state = "ESTAB"  # Default state
                local_idx = 2
                remote_idx = 3
            except ValueError:
                # Newer format: State Recv-Q Send-Q Local Remote
                if len(parts) < 5:
                    i += 1
                    continue
                conn.state = parts[0]
                try:
                    conn.recv_q = int(parts[1])
                    conn.send_q = int(parts[2])
                except ValueError:
                    # Skip malformed lines
                    i += 1
                    continue
                local_idx = 3
                remote_idx = 4

            if len(parts) > remote_idx:
                # Parse local address
                local_parts = parts[local_idx].rsplit(':', 1)
                if len(local_parts) == 2:
                    conn.local_addr = local_parts[0].strip('[]')
                    try:
                        conn.local_port = int(local_parts[1])
                    except ValueError:
                        pass

                # Parse remote address
                remote_parts = parts[remote_idx].rsplit(':', 1)
                if len(remote_parts) == 2:
                    conn.remote_addr = remote_parts[0].strip('[]')
                    try:
                        conn.remote_port = int(remote_parts[1])
                    except ValueError:
                        pass

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

        # Check small cwnd (only for client/sender role)
        # Server-side only sends ACKs, small cwnd is normal
        if self.args.role == 'client' and conn.cwnd < 100 and conn.cwnd > 0:
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

            # Analyze retransmission causes from system stats
            retrans_analysis = []
            if self.system_stats:
                total_retrans = self.system_stats.get('segments_retransmitted', 0)

                # Retransmission type analysis
                if 'tcp_loss_probes' in self.system_stats and self.system_stats['tcp_loss_probes'] > 0:
                    tlp_count = self.system_stats['tcp_loss_probes']
                    tlp_pct = (tlp_count / total_retrans * 100) if total_retrans > 0 else 0
                    retrans_analysis.append(
                        f"TLP probe retrans: {tlp_count:,} ({tlp_pct:.1f}%) - Window too small (rwnd/cwnd), cannot trigger fast retransmit"
                    )

                if 'fast_retransmits' in self.system_stats and self.system_stats['fast_retransmits'] > 0:
                    fast_count = self.system_stats['fast_retransmits']
                    fast_pct = (fast_count / total_retrans * 100) if total_retrans > 0 else 0
                    retrans_analysis.append(
                        f"Fast retransmits: {fast_count:,} ({fast_pct:.1f}%) - Network packet loss or reordering"
                    )

                if 'retrans_in_slowstart' in self.system_stats and self.system_stats['retrans_in_slowstart'] > 0:
                    slow_count = self.system_stats['retrans_in_slowstart']
                    slow_pct = (slow_count / total_retrans * 100) if total_retrans > 0 else 0
                    retrans_analysis.append(
                        f"Retrans in slow start: {slow_count:,} ({slow_pct:.1f}%) - Initial congestion window is small"
                    )

                if 'tcp_lost_retransmit' in self.system_stats and self.system_stats['tcp_lost_retransmit'] > 0:
                    lost_retrans = self.system_stats['tcp_lost_retransmit']
                    retrans_analysis.append(
                        f"WARNING: Retransmitted packets lost again: {lost_retrans:,} - Severe congestion or poor path quality"
                    )

                if 'tcp_spurious_rtos' in self.system_stats and self.system_stats['tcp_spurious_rtos'] > 0:
                    spurious = self.system_stats['tcp_spurious_rtos']
                    retrans_analysis.append(
                        f"Spurious RTOs: {spurious:,} - False positives, likely due to high RTT variance"
                    )

                # Timeout related
                timeout_total = (self.system_stats.get('timeout_after_sack', 0) +
                               self.system_stats.get('timeout_in_loss', 0) +
                               self.system_stats.get('other_tcp_timeouts', 0))
                if timeout_total > 0:
                    retrans_analysis.append(
                        f"Timeout retrans: {timeout_total:,} - After SACK recovery/loss state/other timeouts"
                    )

            recommendation = {
                'issue': 'High retransmissions detected',
                'action': 'Investigate retransmission causes',
                'commands': [
                    "# Check system-wide retrans breakdown:",
                    "netstat -s | grep -iE 'retrans|loss probe|spurious'",
                    "",
                    "# Check NIC drops:",
                    "ethtool -S <interface> | grep -E 'drop|error|miss'",
                    "",
                    "# Use eBPF tools for detailed tracing:",
                    "# sudo python3 ebpf-tools/linux-network-stack/packet-drop/*.py"
                ]
            }

            if retrans_analysis:
                recommendation['likely_causes'] = retrans_analysis

            analysis['recommendations'].append(recommendation)

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
                if 'likely_causes' in rec:
                    print(f"     Likely Causes:")
                    for cause in rec['likely_causes']:
                        print(f"       - {cause}")
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

    def print_system_stats(self):
        """Print system-wide TCP statistics from netstat -s"""
        if not self.system_stats:
            return

        print(f"\n{'='*80}")
        print("System TCP Statistics (netstat -s)")
        print(f"{'='*80}")

        # Group statistics by category
        categories = {
            '=== Retransmission Type Breakdown ===': [
                'segments_retransmitted',
                'fast_retransmits',
                'retrans_in_slowstart',
                'tcp_loss_probes',
                'tcp_loss_probe_recovery',
                'tcp_lost_retransmit',
                'tcp_spurious_rtos',
                'tcp_syn_retrans'
            ],
            '=== Timeout Types ===': [
                'timeout_after_sack',
                'timeout_in_loss',
                'other_tcp_timeouts'
            ],
            '=== Stack Packet Drops ===': [
                'rcv_pruned',
                'rcv_collapsed',
                'tcp_backlog_drop',
                'listen_overflows',
                'listen_drops',
                'sack_retrans_fail'
            ],
            '=== SACK & Reordering ===': [
                'sack_recovery',
                'sack_reordering',
                'reordering_ts'
            ],
            '=== Congestion Window Recovery ===': [
                'tcp_full_undo',
                'tcp_partial_undo',
                'tcp_dsack_undo'
            ],
            '=== Connection Issues ===': [
                'failed_connection_attempts',
                'connection_resets_received',
                'connection_resets_sent',
                'reset_due_to_unexpected_data',
                'reset_due_to_early_close',
                'abort_on_timeout'
            ],
            '=== Basic Counters ===': [
                'segments_sent',
                'segments_received',
                'bad_segments',
                'delayed_acks_sent'
            ]
        }

        # Descriptions for statistics
        descriptions = {
            # Retransmission types
            'segments_retransmitted': 'Total retransmitted segments (all causes)',
            'fast_retransmits': 'Fast retransmits (packet loss/reordering, 3 DupACKs)',
            'retrans_in_slowstart': 'Retrans during slow start (initial cwnd small)',
            'tcp_loss_probes': 'TLP probe retrans (window too small for fast retransmit)',
            'tcp_loss_probe_recovery': 'TLP probe successful recovery',
            'tcp_lost_retransmit': 'Retransmitted packet lost again (severe congestion or path issue)',
            'tcp_spurious_rtos': 'Spurious RTO (false positive, high RTT variance)',
            'tcp_syn_retrans': 'SYN retransmits (during connection establishment)',

            # Timeout types
            'timeout_after_sack': 'Timeout after SACK recovery (packets still lost)',
            'timeout_in_loss': 'Timeout in loss state (persistent congestion)',
            'other_tcp_timeouts': 'Other TCP timeouts',

            # Stack packet drops
            'rcv_pruned': 'Rcv queue pruned (socket buffer overflow)',
            'rcv_collapsed': 'Rcv queue collapsed (memory pressure)',
            'tcp_backlog_drop': 'Backlog queue drop (processing overload)',
            'listen_overflows': 'Listen queue overflow count',
            'listen_drops': 'SYN dropped (listen queue full)',
            'sack_retrans_fail': 'SACK retransmit failed',

            # SACK and reordering
            'sack_recovery': 'SACK recovery count (recovered from loss)',
            'sack_reordering': 'SACK detected reordering',
            'reordering_ts': 'Timestamp detected reordering',

            # Congestion window recovery
            'tcp_full_undo': 'Cwnd fully recovered (undo slow start)',
            'tcp_partial_undo': 'Cwnd partially recovered (Hoe heuristic)',
            'tcp_dsack_undo': 'DSACK undo cwnd reduction',

            # Connection issues
            'failed_connection_attempts': 'Failed connection attempts',
            'connection_resets_received': 'RST received',
            'connection_resets_sent': 'RST sent',
            'reset_due_to_unexpected_data': 'RST (unexpected data received)',
            'reset_due_to_early_close': 'RST (early close)',
            'abort_on_timeout': 'Connection aborted on timeout',

            # Basic counters
            'segments_sent': 'Total segments sent',
            'segments_received': 'Total segments received',
            'bad_segments': 'Bad segments (checksum error, etc.)',
            'delayed_acks_sent': 'Delayed ACKs sent'
        }

        for category, stats in categories.items():
            # Check if any stat in this category exists
            has_data = any(stat in self.system_stats for stat in stats)
            if not has_data:
                continue

            print(f"\n{category}:")
            print("-" * 80)

            for stat in stats:
                if stat in self.system_stats:
                    value = self.system_stats[stat]
                    desc = descriptions.get(stat, '')
                    print(f"  {stat:35s}: {value:12d}  # {desc}")

        # ========== Intelligent Analysis Section ==========
        print(f"\n{'='*80}")
        print("=== Intelligent Analysis ===")
        print(f"{'='*80}")

        # 1. Retransmission ratio and breakdown
        if 'segments_retransmitted' in self.system_stats and 'segments_sent' in self.system_stats:
            total_retrans = self.system_stats['segments_retransmitted']
            total_sent = self.system_stats['segments_sent']
            if total_sent > 0:
                retrans_ratio = (total_retrans / total_sent) * 100
                print(f"\nRetransmission Ratio: {retrans_ratio:.4f}% ({total_retrans:,} / {total_sent:,})")

                # Retransmission type breakdown analysis
                print(f"\nRetransmission Type Breakdown:")
                retrans_breakdown = []

                tlp = self.system_stats.get('tcp_loss_probes', 0)
                if tlp > 0:
                    tlp_pct = (tlp / total_retrans * 100)
                    retrans_breakdown.append(('TLP probe retrans', tlp, tlp_pct, 'Window too small'))

                fast = self.system_stats.get('fast_retransmits', 0)
                if fast > 0:
                    fast_pct = (fast / total_retrans * 100)
                    retrans_breakdown.append(('Fast retransmit', fast, fast_pct, 'Packet loss/reordering'))

                slow = self.system_stats.get('retrans_in_slowstart', 0)
                if slow > 0:
                    slow_pct = (slow / total_retrans * 100)
                    retrans_breakdown.append(('Slow start retrans', slow, slow_pct, 'Small cwnd'))

                lost = self.system_stats.get('tcp_lost_retransmit', 0)
                if lost > 0:
                    lost_pct = (lost / total_retrans * 100)
                    retrans_breakdown.append(('Retrans pkt lost', lost, lost_pct, 'Severe congestion WARNING'))

                for name, count, pct, reason in retrans_breakdown:
                    print(f"  {name:20s}: {count:12,}  ({pct:5.1f}%)  - {reason}")

        # 2. Stack packet drop analysis
        stack_drops = []
        pruned = self.system_stats.get('rcv_pruned', 0)
        if pruned > 0:
            stack_drops.append(('Rcv queue pruned', pruned, 'Socket buffer overflow, increase tcp_rmem'))

        collapsed = self.system_stats.get('rcv_collapsed', 0)
        if collapsed > 0:
            stack_drops.append(('Rcv queue collapsed', collapsed, 'Memory pressure'))

        backlog = self.system_stats.get('tcp_backlog_drop', 0)
        if backlog > 0:
            stack_drops.append(('Backlog drop', backlog, 'App processing slow, increase tcp_max_syn_backlog'))

        listen_drop = self.system_stats.get('listen_drops', 0)
        if listen_drop > 0:
            stack_drops.append(('SYN dropped', listen_drop, 'Listen queue full, increase somaxconn'))

        if stack_drops:
            print(f"\nWARNING: Stack packet drops detected:")
            for name, count, suggestion in stack_drops:
                print(f"  {name:22s}: {count:12,}  - {suggestion}")

        # 3. Timeout analysis
        timeout_after_sack = self.system_stats.get('timeout_after_sack', 0)
        timeout_in_loss = self.system_stats.get('timeout_in_loss', 0)
        other_timeouts = self.system_stats.get('other_tcp_timeouts', 0)
        timeout_total = timeout_after_sack + timeout_in_loss + other_timeouts

        if timeout_total > 0:
            print(f"\nTimeout Events:")
            if timeout_after_sack > 0:
                print(f"  After SACK recovery     : {timeout_after_sack:12,}  - Packets still lost")
            if timeout_in_loss > 0:
                print(f"  In loss state           : {timeout_in_loss:12,}  - Persistent congestion")
            if other_timeouts > 0:
                print(f"  Other timeouts          : {other_timeouts:12,}")

        # 4. Reordering detection
        sack_reorder = self.system_stats.get('sack_reordering', 0)
        ts_reorder = self.system_stats.get('reordering_ts', 0)
        if sack_reorder > 0 or ts_reorder > 0:
            print(f"\nPacket Reordering:")
            if sack_reorder > 0:
                print(f"  SACK detected reordering    : {sack_reorder:12,}")
            if ts_reorder > 0:
                print(f"  Timestamp detected reordering: {ts_reorder:12,}")

        # 5. Critical warnings
        print(f"\n{'='*80}")
        warnings = []

        # High retransmission ratio
        if 'segments_retransmitted' in self.system_stats and 'segments_sent' in self.system_stats:
            retrans_ratio = (self.system_stats['segments_retransmitted'] / self.system_stats['segments_sent']) * 100
            if retrans_ratio > 1.0:
                warnings.append(f"CRITICAL: High retransmission ratio: {retrans_ratio:.2f}% (normal <1%)")

        # TLP ratio too high
        if total_retrans > 0:
            tlp = self.system_stats.get('tcp_loss_probes', 0)
            if tlp > 0 and (tlp / total_retrans) > 0.3:
                warnings.append(f"CRITICAL: TLP ratio too high: {(tlp/total_retrans)*100:.1f}% - Check receive window (rwnd)")

        # Retransmitted packets lost
        if self.system_stats.get('tcp_lost_retransmit', 0) > 1000:
            warnings.append(f"CRITICAL: Many retrans packets lost: {self.system_stats['tcp_lost_retransmit']:,} - Poor path quality")

        # Socket buffer overflow
        if pruned > 1000:
            warnings.append(f"WARNING: Socket buffer overflow: {pruned:,} - Increase tcp_rmem")

        # Listen queue overflow
        if listen_drop > 1000:
            warnings.append(f"WARNING: Listen queue overflow: {listen_drop:,} - Increase net.core.somaxconn")

        if warnings:
            print("Critical Warnings:")
            for warning in warnings:
                print(f"  {warning}")
        else:
            print("OK: No serious issues found")

        print(f"{'='*80}\n")

    def run(self):
        """Main execution"""

        # Print system configuration (once, doesn't change)
        if self.args.show_config:
            self.print_system_config()

        if self.args.interval > 0:
            # Continuous monitoring
            print(f"Starting continuous monitoring (interval: {self.args.interval}s)")
            print("Press Ctrl+C to stop...")

            try:
                while True:
                    # Reload system stats each interval (cumulative counters)
                    # Always load stats for retrans analysis context, even if not displaying
                    self._load_system_stats()

                    # Display system stats if requested
                    if self.args.show_stats:
                        self.print_system_stats()

                    # Collect and analyze connections
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
            # Always load system stats for retrans analysis context
            self._load_system_stats()

            # Display system stats if requested
            if self.args.show_stats:
                self.print_system_stats()

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

  # Analyze server-side connections on port 5201
  %(prog)s --local-port 5201 --role server

  # Filter by specific local IP (useful for multi-homed hosts)
  %(prog)s --local-ip 70.0.0.31 --local-port 2181 --role server

  # Filter both local and remote
  %(prog)s --local-ip 70.0.0.31 --remote-ip 70.0.0.32 --local-port 2181 --role server

  # Continuous monitoring every 2 seconds
  %(prog)s --remote-ip 1.1.1.5 --remote-port 5201 --role client --interval 2

  # Monitor all connections to a remote IP (any port)
  %(prog)s --remote-ip 1.1.1.5 --role client --all

  # Show system TCP configuration (sysctl values)
  %(prog)s --show-config --role server --local-port 5201

  # Show system TCP statistics (netstat -s analysis)
  %(prog)s --show-stats --role server --local-port 5201

  # Show both config and stats
  %(prog)s --show-config --show-stats --role server --local-port 5201

  # Continuous monitoring with stats refresh
  %(prog)s --show-stats --role server --local-port 5201 --interval 5
        """
    )

    parser.add_argument('--role', type=str, choices=['client', 'server'],
                        required=True,
                        help='Role: client (initiator) or server (listener)')
    parser.add_argument('--local-ip', type=str,
                        help='Local IP address filter')
    parser.add_argument('--local-port', type=int,
                        help='Local port number (for server role, or additional filter)')
    parser.add_argument('--remote-ip', type=str,
                        help='Remote IP address (for client role, or additional filter)')
    parser.add_argument('--remote-port', type=int,
                        help='Remote port number (for client role, or additional filter)')
    parser.add_argument('--interval', type=int, default=0,
                        help='Monitoring interval in seconds (0 = single shot)')
    parser.add_argument('--all', action='store_true',
                        help='Monitor all connections (not just ESTABLISHED)')
    parser.add_argument('--target-bandwidth', type=float, default=25,
                        help='Target bandwidth in Gbps (default: 25)')
    parser.add_argument('--show-config', action='store_true',
                        help='Show system TCP configuration')
    parser.add_argument('--show-stats', action='store_true',
                        help='Show system TCP statistics (netstat -s)')
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
