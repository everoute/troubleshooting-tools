#!/usr/bin/env python
"""
Socket Data Parser

Parses dual-side TCP socket data, validates connection matching, and performs time alignment.
Supports raw socket log format only.
Implements FR-SOCKET-SUM-001, FR-SOCKET-SUM-014.
"""

import os
import re
from typing import Tuple, Optional, Dict, List
from datetime import datetime
import pandas as pd

from ..models import FiveTuple


class ConnectionMismatchError(Exception):
    """Exception raised when client and server connections don't match"""
    pass


class SocketDataParser:
    """TCP Socket data parser with dual-side support (log format only)"""

    def parse_dual_directories(
        self,
        client_dir: str,
        server_dir: str
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Parse client and server directories and align data by timestamp

        Algorithm:
        1. Parse client-side data from all files in directory
        2. Parse server-side data from all files in directory
        3. Validate connection match (five-tuple reversal)
        4. Perform time alignment using merge_asof

        Args:
            client_dir: Directory containing client-side socket data files
            server_dir: Directory containing server-side socket data files

        Returns:
            Tuple of (client_df, server_df, aligned_df)

        Raises:
            ConnectionMismatchError: If client and server connections don't match

        Implements: FR-SOCKET-SUM-001, FR-SOCKET-SUM-014
        """
        # Parse both sides
        client_df = self.parse_directory(client_dir, side='client')
        server_df = self.parse_directory(server_dir, side='server')

        # Validate connection match
        self._validate_connection_match(client_df, server_df)

        # Time alignment
        aligned_df = self._align_dual_side_data(client_df, server_df)

        return client_df, server_df, aligned_df

    def parse_directory(self, path: str, side: str) -> pd.DataFrame:
        """
        Parse socket log data from a directory or single file

        Args:
            path: Path to directory containing socket log files, or path to single log file
            side: 'client' or 'server'

        Returns:
            DataFrame with all parsed data

        Raises:
            FileNotFoundError: If path doesn't exist
            ValueError: If no valid log files found
        """
        if not os.path.exists(path):
            raise FileNotFoundError(f"Path not found: {path}")

        # Handle single file
        if os.path.isfile(path):
            df = self.parse_file(path, side)
            if df is None or df.empty:
                raise ValueError(f"No valid data could be parsed from {path}")
            return df

        # Handle directory
        if not os.path.isdir(path):
            raise FileNotFoundError(f"Path is neither file nor directory: {path}")

        # Find all data files (skip hidden files)
        data_files = [
            os.path.join(path, f)
            for f in os.listdir(path)
            if not f.startswith('.') and os.path.isfile(os.path.join(path, f))
        ]

        if not data_files:
            raise ValueError(f"No data files found in {path}")

        # Parse each file and concatenate
        dfs = []
        for file_path in data_files:
            try:
                df = self.parse_file(file_path, side)
                if df is not None and not df.empty:
                    dfs.append(df)
            except Exception as e:
                print(f"Warning: Failed to parse {file_path}: {e}")
                continue

        if not dfs:
            raise ValueError(f"No valid data could be parsed from {path}")

        # Concatenate all DataFrames
        combined_df = pd.concat(dfs, ignore_index=True)

        # Sort by timestamp
        combined_df.sort_values('timestamp', inplace=True)
        combined_df.reset_index(drop=True, inplace=True)

        return combined_df

    def parse_file(self, file_path: str, side: str) -> Optional[pd.DataFrame]:
        """
        Parse a socket log file

        Supported format:
        - Raw log format: Human-readable TCP socket analyzer output

        Args:
            file_path: Path to socket log file
            side: 'client' or 'server'

        Returns:
            DataFrame with parsed data, or None if parsing fails
        """
        try:
            df = self._parse_raw_log_file(file_path)
            if df is None or df.empty:
                return None

            # Add side column
            df['side'] = side

            return df

        except Exception as e:
            print(f"Error parsing file {file_path}: {e}")
            return None

    def _parse_raw_log_file(self, file_path: str) -> Optional[pd.DataFrame]:
        """
        Parse raw socket log file into DataFrame

        Implements the same logic as convert_socket_log_to_csv.py
        but returns DataFrame directly instead of writing to file.

        Args:
            file_path: Path to raw socket log file

        Returns:
            DataFrame with parsed data, or None if parsing fails
        """
        records = []
        current_record = {}
        in_metrics_section = False

        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()

                    # Detect new record
                    if line.startswith('TCP Connection Analysis'):
                        # Save previous record
                        if current_record and 'timestamp' in current_record:
                            records.append(current_record)

                        # Start new record
                        current_record = {}
                        timestamp = self._parse_timestamp_from_line(line)
                        if timestamp:
                            current_record['timestamp'] = timestamp
                        in_metrics_section = False
                        continue

                    # Parse connection
                    if line.startswith('Connection:'):
                        conn = self._parse_connection_from_line(line)
                        if conn:
                            current_record['connection'] = conn
                        continue

                    # Parse state
                    if line.startswith('State:'):
                        state = self._parse_state_from_line(line)
                        if state:
                            current_record['state'] = state
                        continue

                    # Enter metrics section
                    if line.startswith('Metrics:'):
                        in_metrics_section = True
                        continue

                    # Parse metrics
                    if in_metrics_section and line:
                        self._parse_metric_line(line, current_record)

            # Save last record
            if current_record and 'timestamp' in current_record:
                records.append(current_record)

            if not records:
                return None

            # Convert to DataFrame
            df = pd.DataFrame(records)

            # Convert timestamp to datetime
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')

            # Fill missing values with appropriate defaults
            numeric_columns = [
                'rtt', 'rttvar', 'minrtt', 'rto', 'cwnd', 'ssthresh', 'rwnd',
                'pacing_rate', 'delivery_rate', 'send_rate',
                'socket_tx_queue', 'socket_tx_buffer',
                'socket_rx_queue', 'socket_rx_buffer',
                'packets_out', 'retrans', 'retrans_rate'
            ]

            for col in numeric_columns:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)

            return df

        except Exception as e:
            print(f"Error parsing raw log file {file_path}: {e}")
            return None

    def _parse_timestamp_from_line(self, line: str) -> Optional[float]:
        """Extract timestamp from header line"""
        match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)', line)
        if match:
            dt = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S.%f')
            return dt.timestamp()
        return None

    def _parse_connection_from_line(self, line: str) -> Optional[str]:
        """Extract connection string from Connection line"""
        match = re.search(r'Connection: (.+)', line)
        if match:
            conn_str = match.group(1).strip()
            conn_str = conn_str.replace(' -> ', '->')
            conn_str = conn_str.replace(' ', '')
            conn_str = conn_str.replace('::ffff:', '')
            return conn_str
        return None

    def _parse_state_from_line(self, line: str) -> Optional[str]:
        """Extract state from State line"""
        match = re.search(r'State: (\w+)', line)
        if match:
            return match.group(1)
        return None

    def _parse_metric_line(self, line: str, record: Dict) -> None:
        """Parse metric line and add to record"""
        if ':' not in line:
            return

        parts = line.split(':', 1)
        if len(parts) != 2:
            return

        key = parts[0].strip()
        value = parts[1].strip()

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
            'unacked': 'packets_out', 'inflight_data': 'inflight_data',
            'retrans': 'retrans', 'retrans_ratio': 'retrans_rate',
            'lost': 'lost', 'sacked': 'sacked',
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
            'cwnd_limited_time': 'cwnd_limited_time', 'cwnd_limited_ratio': 'cwnd_limited_ratio'
        }

        mapped_key = key_mapping.get(key)
        if mapped_key:
            # Handle string values specially
            if key in ['congestion_algorithm', 'ca_state', 'app_limited']:
                record[mapped_key] = value.strip()
            else:
                numeric_value = self._extract_numeric_value(value)
                if isinstance(numeric_value, tuple):
                    # Handle retrans format "current/total"
                    record['retrans'] = numeric_value[0]
                    record['retrans_total'] = numeric_value[1]
                elif numeric_value is not None:
                    record[mapped_key] = numeric_value

    def _extract_numeric_value(self, value_str: str) -> Optional[float]:
        """Extract numeric value from string like '10.5 Gbps' or '123 bytes'"""
        if not value_str:
            return None

        value_str = value_str.replace(',', '')

        # Handle bandwidth units
        if 'Gbps' in value_str:
            match = re.search(r'([\d.]+)', value_str)
            if match:
                return float(match.group(1)) * 1e9
        elif 'Mbps' in value_str:
            match = re.search(r'([\d.]+)', value_str)
            if match:
                return float(match.group(1)) * 1e6
        elif 'Kbps' in value_str:
            match = re.search(r'([\d.]+)', value_str)
            if match:
                return float(match.group(1)) * 1e3

        # Handle size units
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

        # Handle time units
        elif 'ms' in value_str:
            match = re.search(r'([\d.]+)', value_str)
            if match:
                return float(match.group(1))

        # Handle percentages
        elif '%' in value_str:
            match = re.search(r'([\d.]+)%', value_str)
            if match:
                return float(match.group(1)) / 100.0

        # Handle fractions like "0/590"
        elif '/' in value_str:
            match = re.search(r'(\d+)/(\d+)', value_str)
            if match:
                current = int(match.group(1))
                total = int(match.group(2))
                return (current, total)

        # Try to extract plain number
        match = re.search(r'([\d.]+)', value_str)
        if match:
            return float(match.group(1))

        return None

    def _validate_connection_match(
        self,
        client_df: pd.DataFrame,
        server_df: pd.DataFrame
    ) -> None:
        """
        Validate that client and server connections match

        Validation logic:
        Client's src->dst should equal Server's dst<-src

        Args:
            client_df: Client-side DataFrame
            server_df: Server-side DataFrame

        Raises:
            ConnectionMismatchError: If connections don't match
        """
        if client_df.empty or server_df.empty:
            raise ConnectionMismatchError("Empty DataFrame provided")

        # Get first connection from each side
        client_conn_str = client_df['connection'].iloc[0]
        server_conn_str = server_df['connection'].iloc[0]

        # Parse five-tuples
        client_ft = self._parse_connection_str(client_conn_str)
        server_ft = self._parse_connection_str(server_conn_str)

        # Check if they're reverse connections
        if not self._is_reverse_connection(client_ft, server_ft):
            raise ConnectionMismatchError(
                f"Connection mismatch:\n"
                f"  Client: {client_conn_str}\n"
                f"  Server: {server_conn_str}\n"
                f"  Expected server connection to be reverse of client"
            )

    def _align_dual_side_data(
        self,
        client_df: pd.DataFrame,
        server_df: pd.DataFrame,
        max_offset: float = 1.0
    ) -> pd.DataFrame:
        """
        Align client and server time-series data

        Algorithm:
        Use pandas merge_asof for nearest-neighbor timestamp matching
        Tolerance is max_offset seconds (default 1 second)

        Args:
            client_df: Client-side DataFrame
            server_df: Server-side DataFrame
            max_offset: Maximum time offset for matching (seconds)

        Returns:
            Aligned DataFrame with both client and server metrics
        """
        # Reset index to ensure timestamp is a column
        client_reset = client_df.reset_index(drop=True)
        server_reset = server_df.reset_index(drop=True)

        # Perform merge_asof (requires sorted data)
        aligned = pd.merge_asof(
            client_reset,
            server_reset,
            on='timestamp',
            direction='nearest',
            tolerance=pd.Timedelta(seconds=max_offset),
            suffixes=('_client', '_server')
        )

        # Drop rows with missing data (no match within tolerance)
        aligned = aligned.dropna()

        # Set timestamp as index
        aligned.set_index('timestamp', inplace=True)

        return aligned

    def _parse_connection_str(self, conn_str: str) -> FiveTuple:
        """
        Parse connection string to FiveTuple

        Supported formats:
        - IPv4: "192.168.1.1:12345->192.168.1.2:80"
        - IPv4-mapped IPv6: "::ffff:192.168.1.1:12345->::ffff:192.168.1.2:80"

        Args:
            conn_str: Connection string

        Returns:
            FiveTuple object

        Raises:
            ValueError: If connection string format is invalid
        """
        # Normalize IPv4-mapped IPv6 to IPv4
        # Remove ::ffff: prefix if present
        normalized = conn_str.replace('::ffff:', '')

        # Match pattern: IP:PORT->IP:PORT
        pattern = r'(\d+\.\d+\.\d+\.\d+):(\d+)->(\d+\.\d+\.\d+\.\d+):(\d+)'
        match = re.match(pattern, normalized)

        if not match:
            raise ValueError(f"Invalid connection string format: {conn_str}")

        src_ip, src_port, dst_ip, dst_port = match.groups()

        return FiveTuple(
            src_ip=src_ip,
            src_port=int(src_port),
            dst_ip=dst_ip,
            dst_port=int(dst_port),
            protocol='TCP'
        )

    def _is_reverse_connection(self, ft1: FiveTuple, ft2: FiveTuple) -> bool:
        """
        Check if two five-tuples are reverse connections

        Args:
            ft1: First FiveTuple
            ft2: Second FiveTuple

        Returns:
            True if ft2 is reverse of ft1, False otherwise
        """
        return (
            ft1.src_ip == ft2.dst_ip and
            ft1.src_port == ft2.dst_port and
            ft1.dst_ip == ft2.src_ip and
            ft1.dst_port == ft2.src_port
        )
