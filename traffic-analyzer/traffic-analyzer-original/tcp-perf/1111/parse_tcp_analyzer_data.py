#!/usr/bin/env python3
"""
Parse TCP Connection Analyzer output files and extract key metrics
"""

import re
import sys
from collections import defaultdict
from statistics import mean, median

def parse_connection_file(filepath):
    """Parse a single TCP analyzer output file"""
    connections = []
    current_conn = None

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()

            # Detect new connection analysis block
            if line.startswith('TCP Connection Analysis'):
                if current_conn:
                    connections.append(current_conn)
                current_conn = {'timestamp': '', 'metrics': {}}
                # Extract timestamp
                match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)', line)
                if match:
                    current_conn['timestamp'] = match.group(1)

            elif line.startswith('Connection:'):
                match = re.search(r'Connection: (.+)', line)
                if match and current_conn is not None:
                    current_conn['connection'] = match.group(1)

            elif line.startswith('State:'):
                match = re.search(r'State: (\w+)', line)
                if match and current_conn is not None:
                    current_conn['state'] = match.group(1)

            # Parse metrics (format: "  key : value")
            elif line and ':' in line and current_conn is not None:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    current_conn['metrics'][key] = value

        # Add last connection
        if current_conn:
            connections.append(current_conn)

    return connections

def extract_numeric_value(value_str):
    """Extract numeric value from string like '10.5 Gbps' or '123 bytes'"""
    if not value_str:
        return None

    # Remove commas
    value_str = value_str.replace(',', '')

    # Try to extract number
    match = re.search(r'([\d.]+)', value_str)
    if match:
        return float(match.group(1))
    return None

def extract_ratio_value(value_str):
    """Extract ratio from format like '10/1000' or '5.5%'"""
    if not value_str:
        return None

    # Handle percentage
    if '%' in value_str:
        match = re.search(r'([\d.]+)%', value_str)
        if match:
            return float(match.group(1))

    # Handle fraction like '10/1000'
    match = re.search(r'(\d+)/(\d+)', value_str)
    if match:
        numerator = int(match.group(1))
        denominator = int(match.group(2))
        if denominator > 0:
            return (numerator / denominator) * 100

    return None

def analyze_connections(connections):
    """Analyze connection metrics"""
    if not connections:
        return None

    # Extract key metrics over time
    metrics_over_time = defaultdict(list)

    for conn in connections:
        metrics = conn.get('metrics', {})

        # Parse important metrics
        if 'send_rate' in metrics:
            val = extract_numeric_value(metrics['send_rate'])
            if val is not None:
                metrics_over_time['send_rate_gbps'].append(val)

        if 'delivery_rate' in metrics:
            val = extract_numeric_value(metrics['delivery_rate'])
            if val is not None:
                metrics_over_time['delivery_rate_gbps'].append(val)

        if 'pacing_rate' in metrics:
            val = extract_numeric_value(metrics['pacing_rate'])
            if val is not None:
                metrics_over_time['pacing_rate_gbps'].append(val)

        if 'retrans' in metrics:
            # Format: "0/9614"
            match = re.search(r'(\d+)/(\d+)', metrics['retrans'])
            if match:
                current = int(match.group(1))
                total = int(match.group(2))
                metrics_over_time['retrans_current'].append(current)
                metrics_over_time['retrans_total'].append(total)

        if 'retrans_ratio' in metrics:
            val = extract_ratio_value(metrics['retrans_ratio'])
            if val is not None:
                metrics_over_time['retrans_ratio_pct'].append(val)

        if 'spurious_retrans_rate' in metrics:
            val = extract_ratio_value(metrics['spurious_retrans_rate'])
            if val is not None:
                metrics_over_time['spurious_retrans_rate_pct'].append(val)

        if 'lost' in metrics:
            val = extract_numeric_value(metrics['lost'])
            if val is not None:
                metrics_over_time['lost'].append(val)

        if 'unacked' in metrics:
            val = extract_numeric_value(metrics['unacked'])
            if val is not None:
                metrics_over_time['unacked'].append(val)

        if 'cwnd' in metrics:
            val = extract_numeric_value(metrics['cwnd'])
            if val is not None:
                metrics_over_time['cwnd'].append(val)

        if 'rcv_ooopack' in metrics:
            # Format: "715,154 packets"
            val = extract_numeric_value(metrics['rcv_ooopack'])
            if val is not None:
                metrics_over_time['rcv_ooopack'].append(val)

        if 'ooo_ratio' in metrics:
            val = extract_ratio_value(metrics['ooo_ratio'])
            if val is not None:
                metrics_over_time['ooo_ratio_pct'].append(val)

        if 'rwnd_limited_ratio' in metrics:
            val = extract_ratio_value(metrics['rwnd_limited_ratio'])
            if val is not None:
                metrics_over_time['rwnd_limited_ratio_pct'].append(val)

        if 'cwnd_limited_ratio' in metrics:
            val = extract_ratio_value(metrics['cwnd_limited_ratio'])
            if val is not None:
                metrics_over_time['cwnd_limited_ratio_pct'].append(val)

        if 'sndbuf_limited_ratio' in metrics:
            val = extract_ratio_value(metrics['sndbuf_limited_ratio'])
            if val is not None:
                metrics_over_time['sndbuf_limited_ratio_pct'].append(val)

    # Calculate statistics
    stats = {}
    for metric, values in metrics_over_time.items():
        if values:
            stats[metric] = {
                'min': min(values),
                'max': max(values),
                'avg': mean(values),
                'median': median(values),
                'samples': len(values),
                'latest': values[-1],
                'first': values[0]
            }

    return {
        'connection': connections[0].get('connection', 'Unknown'),
        'state': connections[0].get('state', 'Unknown'),
        'samples': len(connections),
        'first_timestamp': connections[0].get('timestamp', ''),
        'last_timestamp': connections[-1].get('timestamp', ''),
        'stats': stats,
        'raw_connections': connections
    }

def print_analysis(analysis, role):
    """Print connection analysis"""
    print(f"\n{'='*100}")
    print(f"{role.upper()} SIDE ANALYSIS")
    print(f"{'='*100}")
    print(f"Connection: {analysis['connection']}")
    print(f"State: {analysis['state']}")
    print(f"Samples: {analysis['samples']}")
    print(f"Time Range: {analysis['first_timestamp']} -> {analysis['last_timestamp']}")
    print(f"\n{'Metric':<35} {'Min':>12} {'Max':>12} {'Avg':>12} {'Median':>12} {'Latest':>12}")
    print('-' * 100)

    stats = analysis['stats']

    # Rate metrics
    if 'send_rate_gbps' in stats:
        s = stats['send_rate_gbps']
        print(f"{'Send Rate (Gbps)':<35} {s['min']:>12.2f} {s['max']:>12.2f} {s['avg']:>12.2f} {s['median']:>12.2f} {s['latest']:>12.2f}")

    if 'delivery_rate_gbps' in stats:
        s = stats['delivery_rate_gbps']
        print(f"{'Delivery Rate (Gbps)':<35} {s['min']:>12.2f} {s['max']:>12.2f} {s['avg']:>12.2f} {s['median']:>12.2f} {s['latest']:>12.2f}")

    if 'pacing_rate_gbps' in stats:
        s = stats['pacing_rate_gbps']
        print(f"{'Pacing Rate (Gbps)':<35} {s['min']:>12.2f} {s['max']:>12.2f} {s['avg']:>12.2f} {s['median']:>12.2f} {s['latest']:>12.2f}")

    print()

    # Congestion window and unacked
    if 'cwnd' in stats:
        s = stats['cwnd']
        print(f"{'Congestion Window (cwnd)':<35} {s['min']:>12.0f} {s['max']:>12.0f} {s['avg']:>12.1f} {s['median']:>12.0f} {s['latest']:>12.0f}")

    if 'unacked' in stats:
        s = stats['unacked']
        print(f"{'Unacked Segments':<35} {s['min']:>12.0f} {s['max']:>12.0f} {s['avg']:>12.1f} {s['median']:>12.0f} {s['latest']:>12.0f}")

    print()

    # Retransmission metrics
    if 'retrans_total' in stats:
        s = stats['retrans_total']
        print(f"{'Retrans Total Count':<35} {s['min']:>12.0f} {s['max']:>12.0f} {s['avg']:>12.1f} {s['median']:>12.0f} {s['latest']:>12.0f}")
        # Calculate increase
        increase = s['latest'] - s['first']
        print(f"{'  -> Increase during monitoring':<35} {increase:>12.0f} {'':>12} {'':>12} {'':>12} {'':>12}")

    if 'retrans_ratio_pct' in stats:
        s = stats['retrans_ratio_pct']
        print(f"{'Retrans Ratio (%)':<35} {s['min']:>12.3f} {s['max']:>12.3f} {s['avg']:>12.3f} {s['median']:>12.3f} {s['latest']:>12.3f}")

    if 'spurious_retrans_rate_pct' in stats:
        s = stats['spurious_retrans_rate_pct']
        print(f"{'Spurious Retrans Rate (%)':<35} {s['min']:>12.1f} {s['max']:>12.1f} {s['avg']:>12.1f} {s['median']:>12.1f} {s['latest']:>12.1f}")

    if 'lost' in stats:
        s = stats['lost']
        print(f"{'Lost Packets':<35} {s['min']:>12.0f} {s['max']:>12.0f} {s['avg']:>12.1f} {s['median']:>12.0f} {s['latest']:>12.0f}")

    print()

    # Out-of-order packets
    if 'rcv_ooopack' in stats:
        s = stats['rcv_ooopack']
        print(f"{'Out-of-Order Packets':<35} {s['min']:>12.0f} {s['max']:>12.0f} {s['avg']:>12.1f} {s['median']:>12.0f} {s['latest']:>12.0f}")

    if 'ooo_ratio_pct' in stats:
        s = stats['ooo_ratio_pct']
        print(f"{'OOO Ratio (%)':<35} {s['min']:>12.3f} {s['max']:>12.3f} {s['avg']:>12.3f} {s['median']:>12.3f} {s['latest']:>12.3f}")

    print()

    # Limiting factors
    if 'rwnd_limited_ratio_pct' in stats:
        s = stats['rwnd_limited_ratio_pct']
        print(f"{'rwnd_limited Ratio (%)':<35} {s['min']:>12.1f} {s['max']:>12.1f} {s['avg']:>12.1f} {s['median']:>12.1f} {s['latest']:>12.1f}")

    if 'cwnd_limited_ratio_pct' in stats:
        s = stats['cwnd_limited_ratio_pct']
        print(f"{'cwnd_limited Ratio (%)':<35} {s['min']:>12.1f} {s['max']:>12.1f} {s['avg']:>12.1f} {s['median']:>12.1f} {s['latest']:>12.1f}")

    if 'sndbuf_limited_ratio_pct' in stats:
        s = stats['sndbuf_limited_ratio_pct']
        print(f"{'sndbuf_limited Ratio (%)':<35} {s['min']:>12.1f} {s['max']:>12.1f} {s['avg']:>12.1f} {s['median']:>12.1f} {s['latest']:>12.1f}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 parse_tcp_analyzer_data.py <file1> [file2] [file3] ...")
        sys.exit(1)

    for filepath in sys.argv[1:]:
        print(f"\n{'='*100}")
        print(f"Parsing: {filepath}")
        print(f"{'='*100}")

        connections = parse_connection_file(filepath)

        if not connections:
            print(f"No connections found in {filepath}")
            continue

        # Determine role from filename
        role = 'client' if 'client' in filepath.lower() else 'server'

        analysis = analyze_connections(connections)
        print_analysis(analysis, role)

if __name__ == '__main__':
    main()
