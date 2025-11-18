#!/usr/bin/env python
"""
Socket Data Parser

Parses dual-side TCP socket data, validates connection matching, and performs time alignment.
Implements FR-SOCKET-SUM-001, FR-SOCKET-SUM-014.
"""

import os
import re
from typing import Tuple, Optional
from datetime import datetime
import pandas as pd

from ..models import FiveTuple


class ConnectionMismatchError(Exception):
    """Exception raised when client and server connections don't match"""
    pass


class SocketDataParser:
    """TCP Socket data parser with dual-side support"""

    # Expected column names in socket data files
    EXPECTED_COLUMNS = [
        'timestamp', 'connection', 'state',
        'rtt', 'cwnd', 'ssthresh', 'rwnd',
        'pacing_rate', 'delivery_rate',
        'socket_tx_queue', 'socket_tx_buffer',
        'socket_rx_queue', 'socket_rx_buffer',
        'packets_out', 'retrans', 'retrans_rate'
    ]

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

    def parse_directory(self, dir_path: str, side: str) -> pd.DataFrame:
        """
        Parse all socket data files in a directory

        Args:
            dir_path: Path to directory containing socket data files
            side: 'client' or 'server'

        Returns:
            DataFrame with all parsed data

        Raises:
            FileNotFoundError: If directory doesn't exist
            ValueError: If no valid data files found
        """
        if not os.path.isdir(dir_path):
            raise FileNotFoundError(f"Directory not found: {dir_path}")

        # Find all data files (skip hidden files)
        data_files = [
            os.path.join(dir_path, f)
            for f in os.listdir(dir_path)
            if not f.startswith('.') and os.path.isfile(os.path.join(dir_path, f))
        ]

        if not data_files:
            raise ValueError(f"No data files found in {dir_path}")

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
            raise ValueError(f"No valid data could be parsed from {dir_path}")

        # Concatenate all DataFrames
        combined_df = pd.concat(dfs, ignore_index=True)

        # Sort by timestamp
        combined_df.sort_values('timestamp', inplace=True)
        combined_df.reset_index(drop=True, inplace=True)

        return combined_df

    def parse_file(self, file_path: str, side: str) -> Optional[pd.DataFrame]:
        """
        Parse a single socket data file

        Expected format: Space-separated values with header line
        Example line:
        1699999999.123 192.168.1.1:12345->192.168.1.2:80 ESTABLISHED 45.2 1000 ...

        Args:
            file_path: Path to socket data file
            side: 'client' or 'server'

        Returns:
            DataFrame with parsed data, or None if parsing fails
        """
        try:
            # Read file with space separator
            df = pd.read_csv(file_path, sep=r'\s+', comment='#')

            # Convert timestamp to datetime
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')

            # Add side column
            df['side'] = side

            return df

        except Exception as e:
            print(f"Error parsing file {file_path}: {e}")
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

        Expected format: "192.168.1.1:12345->192.168.1.2:80"

        Args:
            conn_str: Connection string

        Returns:
            FiveTuple object

        Raises:
            ValueError: If connection string format is invalid
        """
        # Match pattern: IP:PORT->IP:PORT
        pattern = r'(\d+\.\d+\.\d+\.\d+):(\d+)->(\d+\.\d+\.\d+\.\d+):(\d+)'
        match = re.match(pattern, conn_str)

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
