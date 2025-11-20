#!/usr/bin/env python3
"""
Convert Socket Log to CSV Format

Converts human-readable TCP socket analyzer log output to CSV format
compatible with SocketDataParser.

Usage:
    python3 convert_socket_log_to_csv.py <input_log> <output_csv>
"""

import re
import sys
import csv
from datetime import datetime
from typing import Dict, List, Optional


def parse_timestamp(line: str) -> Optional[float]:
    """Extract timestamp from header line"""
    match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)', line)
    if match:
        dt = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S.%f')
        return dt.timestamp()
    return None


def parse_connection(line: str) -> Optional[str]:
    """Extract connection string from Connection line"""
    match = re.search(r'Connection: (.+)', line)
    if match:
        # Convert "IP1:PORT1 -> IP2:PORT2" to "IP1:PORT1->IP2:PORT2"
        conn_str = match.group(1).strip()
        conn_str = conn_str.replace(' -> ', '->')
        conn_str = conn_str.replace(' ', '')
        # Remove IPv4-mapped IPv6 prefix ::ffff:
        conn_str = conn_str.replace('::ffff:', '')
        return conn_str
    return None


def parse_state(line: str) -> Optional[str]:
    """Extract state from State line"""
    match = re.search(r'State: (\w+)', line)
    if match:
        return match.group(1)
    return None


def extract_numeric_value(value_str: str) -> Optional[float]:
    """Extract numeric value from string like '10.5 Gbps' or '123 bytes'"""
    if not value_str:
        return None

    # Remove commas
    value_str = value_str.replace(',', '')

    # Handle bandwidth units (Gbps, Mbps, Kbps)
    if 'Gbps' in value_str:
        match = re.search(r'([\d.]+)', value_str)
        if match:
            return float(match.group(1)) * 1e9  # Convert to bps
    elif 'Mbps' in value_str:
        match = re.search(r'([\d.]+)', value_str)
        if match:
            return float(match.group(1)) * 1e6
    elif 'Kbps' in value_str:
        match = re.search(r'([\d.]+)', value_str)
        if match:
            return float(match.group(1)) * 1e3

    # Handle size units (KB, MB, GB, bytes)
    elif 'bytes' in value_str or 'KB' in value_str or 'MB' in value_str or 'GB' in value_str:
        match = re.search(r'([\d.]+)', value_str)
        if match:
            value = float(match.group(1))
            if 'KB' in value_str:
                value *= 1024
            elif 'MB' in value_str:
                value *= 1024 * 1024
            elif 'GB' in value_str:
                value *= 1024 * 1024 * 1024
            return value

    # Handle time units (ms, s)
    elif 'ms' in value_str:
        match = re.search(r'([\d.]+)', value_str)
        if match:
            return float(match.group(1))

    # Handle percentages
    elif '%' in value_str:
        match = re.search(r'([\d.]+)%', value_str)
        if match:
            return float(match.group(1)) / 100.0  # Convert to ratio

    # Handle fractions like "0/590"
    elif '/' in value_str:
        match = re.search(r'(\d+)/(\d+)', value_str)
        if match:
            current = int(match.group(1))
            total = int(match.group(2))
            # Return both as separate values (we'll handle this specially)
            return (current, total)

    # Try to extract plain number
    match = re.search(r'([\d.]+)', value_str)
    if match:
        return float(match.group(1))

    return None


def parse_metric_line(line: str) -> tuple:
    """Parse metric line: '  key  : value'"""
    if ':' not in line:
        return None, None

    parts = line.split(':', 1)
    if len(parts) == 2:
        key = parts[0].strip()
        value = parts[1].strip()
        return key, value
    return None, None


def parse_socket_log_to_records(input_file: str) -> List[Dict]:
    """
    Parse socket log file and return list of records

    Args:
        input_file: Path to socket log file

    Returns:
        List of dictionaries, each representing one record
    """
    records = []
    current_record = {}
    in_metrics_section = False

    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()

            # Detect new record
            if line.startswith('TCP Connection Analysis'):
                # Save previous record
                if current_record and 'timestamp' in current_record:
                    records.append(current_record)

                # Start new record
                current_record = {}
                timestamp = parse_timestamp(line)
                if timestamp:
                    current_record['timestamp'] = timestamp
                in_metrics_section = False
                continue

            # Parse connection
            if line.startswith('Connection:'):
                conn = parse_connection(line)
                if conn:
                    current_record['connection'] = conn
                continue

            # Parse state
            if line.startswith('State:'):
                state = parse_state(line)
                if state:
                    current_record['state'] = state
                continue

            # Enter metrics section
            if line.startswith('Metrics:'):
                in_metrics_section = True
                continue

            # Parse metrics
            if in_metrics_section and line:
                key, value = parse_metric_line(line)
                if key:
                    # Map to expected column names
                    key_mapping = {
                        'rtt': 'rtt', 'rttvar': 'rttvar', 'minrtt': 'minrtt', 'rto': 'rto',
                        'cwnd': 'cwnd', 'ssthresh': 'ssthresh',
                        'rcv_space': 'rwnd', 'rcv_ssthresh': 'rcv_ssthresh', 'snd_wnd': 'snd_wnd',
                        'mss': 'mss', 'pmtu': 'pmtu', 'advmss': 'advmss', 'rcvmss': 'rcvmss',
                        'send_rate': 'send_rate', 'pacing_rate': 'pacing_rate', 'delivery_rate': 'delivery_rate',
                        'send_q': 'send_q', 'recv_q': 'recv_q',
                        'socket_tx_queue': 'socket_tx_queue', 'socket_tx_buffer': 'socket_tx_buffer',
                        'socket_rx_queue': 'socket_rx_queue', 'socket_rx_buffer': 'socket_rx_buffer',
                        'socket_forward_alloc': 'socket_forward_alloc', 'socket_write_queue': 'socket_write_queue',
                        'socket_opt_mem': 'socket_opt_mem', 'socket_backlog': 'socket_backlog', 'socket_dropped': 'socket_dropped',
                        'unacked': 'packets_out', 'inflight_data': 'inflight_data',
                        'retrans': 'retrans', 'retrans_ratio': 'retrans_rate',
                        'lost': 'lost', 'sacked': 'sacked',
                        'dsack_dups': 'dsack_dups', 'spurious_retrans_rate': 'spurious_retrans_rate',
                        'segs_out': 'segs_out', 'segs_in': 'segs_in',
                        'data_segs_out': 'data_segs_out', 'data_segs_in': 'data_segs_in',
                        'bytes_sent': 'bytes_sent', 'bytes_acked': 'bytes_acked', 'bytes_received': 'bytes_received',
                        'lastsnd': 'lastsnd', 'lastrcv': 'lastrcv', 'lastack': 'lastack',
                        'app_limited': 'app_limited', 'rcv_rtt': 'rcv_rtt', 'ato': 'ato',
                        'congestion_algorithm': 'congestion_algorithm', 'ca_state': 'ca_state',
                        'reordering': 'reordering', 'rcv_ooopack': 'rcv_ooopack',
                        'busy_time': 'busy_time',
                        'rwnd_limited_time': 'rwnd_limited_time', 'rwnd_limited_ratio': 'rwnd_limited_ratio',
                        'sndbuf_limited_time': 'sndbuf_limited_time', 'sndbuf_limited_ratio': 'sndbuf_limited_ratio',
                        'cwnd_limited_time': 'cwnd_limited_time', 'cwnd_limited_ratio': 'cwnd_limited_ratio',
                        'tcp_features': 'tcp_features', 'bdp': 'bdp', 'recommended_window': 'recommended_window'
                    }

                    mapped_key = key_mapping.get(key)
                    if mapped_key:
                        # Handle string values specially
                        if key in ['congestion_algorithm', 'ca_state', 'app_limited', 'tcp_features']:
                            current_record[mapped_key] = value.strip()
                        else:
                            numeric_value = extract_numeric_value(value)
                            if isinstance(numeric_value, tuple):
                                # Handle retrans format "current/total"
                                current_record['retrans'] = numeric_value[0]
                                current_record['retrans_total'] = numeric_value[1]
                            elif numeric_value is not None:
                                current_record[mapped_key] = numeric_value

    # Save last record
    if current_record and 'timestamp' in current_record:
        records.append(current_record)

    return records


def convert_log_to_csv(input_file: str, output_file: str):
    """Convert socket log to CSV format"""

    records = parse_socket_log_to_records(input_file)

    if not records:
        print(f"No records found in {input_file}")
        return

    # Define CSV columns - comprehensive list of all TCP socket metrics
    columns = [
        'timestamp', 'connection', 'state',
        'rtt', 'rttvar', 'minrtt', 'rto',
        'cwnd', 'ssthresh', 'rwnd', 'rcv_ssthresh', 'snd_wnd',
        'mss', 'pmtu', 'advmss', 'rcvmss',
        'send_rate', 'pacing_rate', 'delivery_rate',
        'send_q', 'recv_q',
        'socket_tx_queue', 'socket_tx_buffer',
        'socket_rx_queue', 'socket_rx_buffer',
        'socket_forward_alloc', 'socket_write_queue',
        'socket_opt_mem', 'socket_backlog', 'socket_dropped',
        'packets_out', 'inflight_data',
        'retrans', 'retrans_rate', 'retrans_total',
        'lost', 'sacked', 'dsack_dups', 'spurious_retrans_rate',
        'segs_out', 'segs_in',
        'data_segs_out', 'data_segs_in',
        'bytes_sent', 'bytes_acked', 'bytes_received',
        'lastsnd', 'lastrcv', 'lastack',
        'app_limited', 'rcv_rtt', 'ato',
        'congestion_algorithm', 'ca_state',
        'reordering', 'rcv_ooopack',
        'busy_time',
        'rwnd_limited_time', 'rwnd_limited_ratio',
        'sndbuf_limited_time', 'sndbuf_limited_ratio',
        'cwnd_limited_time', 'cwnd_limited_ratio',
        'tcp_features', 'bdp', 'recommended_window'
    ]

    # Write CSV
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()

        for record in records:
            # Fill missing columns with defaults
            row = {}
            string_cols = ['connection', 'state', 'congestion_algorithm', 'ca_state', 'app_limited', 'tcp_features']
            for col in columns:
                if col in record:
                    row[col] = record[col]
                elif col in string_cols:
                    row[col] = record.get(col, '')
                else:
                    row[col] = 0.0
            writer.writerow(row)

    print(f"Converted {len(records)} records from {input_file} to {output_file}")


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 convert_socket_log_to_csv.py <input_log> <output_csv>")
        print("\nExample:")
        print("  python3 convert_socket_log_to_csv.py client-socket.log client-socket.csv")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    try:
        convert_log_to_csv(input_file, output_file)
        print("\nConversion successful!")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
