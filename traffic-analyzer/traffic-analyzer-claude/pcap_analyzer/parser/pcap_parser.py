#!/usr/bin/env python
"""
PCAP Parser

Uses tshark as backend to parse PCAP files with streaming processing.
Implements FR-PCAP-SUM-001.
"""

import json
import subprocess
import os
from typing import Iterator, List, Optional, Dict, Any
from datetime import datetime
from ..models import Packet, FileInfo


class PcapParser:
    """PCAP file parser using tshark as backend"""

    def __init__(self, tshark_path: str = 'tshark'):
        """
        Initialize PCAP parser

        Args:
            tshark_path: Path to tshark executable
        """
        self.tshark_path = tshark_path
        self._validate_tshark()

    def _validate_tshark(self) -> None:
        """Validate that tshark is available"""
        try:
            subprocess.run(
                [self.tshark_path, '--version'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            raise RuntimeError(
                f"tshark not found or not executable: {self.tshark_path}. "
                f"Please install Wireshark/tshark. Error: {e}"
            )

    def parse_file(self,
                   pcap_path: str,
                   fields: Optional[List[str]] = None,
                   filters: Optional[str] = None) -> Iterator[Dict[str, Any]]:
        """
        Parse PCAP file and return packet iterator (streaming mode)

        Design notes:
        - Uses tshark JSON output mode (-T json)
        - Streaming processing to avoid memory overflow
        - Supports display filters (-Y parameter)

        Args:
            pcap_path: Path to PCAP file
            fields: List of fields to extract (e.g., ['ip.src', 'ip.dst'])
            filters: tshark display filter string

        Yields:
            Packet dictionaries
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        cmd = [
            self.tshark_path,
            '-r', pcap_path,
            '-T', 'json',
        ]

        # Add fields if specified
        if fields:
            for field in fields:
                cmd.extend(['-e', field])

        # Add display filter if specified
        if filters:
            cmd.extend(['-Y', filters])

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Stream parse JSON
            buffer = ""
            in_array = False

            for line in proc.stdout:
                buffer += line

                # Detect start of JSON array
                if '[' in line and not in_array:
                    in_array = True
                    buffer = buffer[buffer.index('[') + 1:]

                # Try to parse individual packet JSON
                if in_array and (line.strip().endswith('},') or line.strip().endswith('}')):
                    try:
                        # Remove trailing comma if present
                        packet_json = buffer.strip().rstrip(',')
                        if packet_json:
                            packet = json.loads(packet_json)
                            normalized = self._normalize_packet(packet)
                            if normalized:
                                yield normalized
                        buffer = ""
                    except json.JSONDecodeError:
                        # Continue buffering if not a complete JSON object
                        continue

            proc.wait()
            if proc.returncode != 0:
                stderr = proc.stderr.read()
                raise RuntimeError(f"tshark failed: {stderr}")

        except Exception as e:
            raise RuntimeError(f"Error parsing PCAP file: {e}")

    def _normalize_packet(self, packet_json: Dict) -> Optional[Dict[str, Any]]:
        """
        Normalize tshark JSON packet to our internal format

        Args:
            packet_json: Raw packet from tshark JSON output

        Returns:
            Normalized packet dictionary or None if invalid
        """
        try:
            layers = packet_json.get('_source', {}).get('layers', {})

            # Extract frame info
            frame = layers.get('frame', {})
            frame_len = int(frame.get('frame.len', [0])[0]) if isinstance(frame.get('frame.len'), list) else int(frame.get('frame.len', 0))

            # Extract timestamp
            frame_time = frame.get('frame.time_epoch', ['0'])[0] if isinstance(frame.get('frame.time_epoch'), list) else frame.get('frame.time_epoch', '0')
            timestamp = datetime.fromtimestamp(float(frame_time))

            # Extract IP layer
            ip = layers.get('ip', {})
            src_ip = ip.get('ip.src', [None])[0] if isinstance(ip.get('ip.src'), list) else ip.get('ip.src')
            dst_ip = ip.get('ip.dst', [None])[0] if isinstance(ip.get('ip.dst'), list) else ip.get('ip.dst')

            # Extract protocol
            protocol = frame.get('frame.protocols', [''])[0] if isinstance(frame.get('frame.protocols'), list) else frame.get('frame.protocols', '')
            if ':' in protocol:
                protocol = protocol.split(':')[-1].upper()

            # Extract TCP/UDP ports
            tcp = layers.get('tcp', {})
            udp = layers.get('udp', {})

            src_port = None
            dst_port = None
            tcp_flags = None

            if tcp:
                src_port = int(tcp.get('tcp.srcport', [0])[0]) if isinstance(tcp.get('tcp.srcport'), list) else int(tcp.get('tcp.srcport', 0))
                dst_port = int(tcp.get('tcp.dstport', [0])[0]) if isinstance(tcp.get('tcp.dstport'), list) else int(tcp.get('tcp.dstport', 0))

                # Extract TCP flags
                tcp_flags = {
                    'syn': bool(tcp.get('tcp.flags.syn')),
                    'ack': bool(tcp.get('tcp.flags.ack')),
                    'fin': bool(tcp.get('tcp.flags.fin')),
                    'rst': bool(tcp.get('tcp.flags.rst')),
                    'psh': bool(tcp.get('tcp.flags.push')),
                }

            if udp:
                src_port = int(udp.get('udp.srcport', [0])[0]) if isinstance(udp.get('udp.srcport'), list) else int(udp.get('udp.srcport', 0))
                dst_port = int(udp.get('udp.dstport', [0])[0]) if isinstance(udp.get('udp.dstport'), list) else int(udp.get('udp.dstport', 0))

            return {
                'timestamp': timestamp,
                'frame_len': frame_len,
                'protocol': protocol,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'tcp_flags': tcp_flags,
                'raw_data': layers  # Store raw layers for detailed analysis
            }

        except Exception as e:
            # Skip malformed packets
            return None

    def get_file_info(self, pcap_path: str) -> FileInfo:
        """
        Get PCAP file information using capinfos

        Args:
            pcap_path: Path to PCAP file

        Returns:
            FileInfo object with file statistics
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        try:
            # Use capinfos for file statistics
            cmd = ['capinfos', '-M', '-T', pcap_path]
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )

            # Parse capinfos output (tab-separated)
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 2:
                values = lines[1].split('\t')

                file_size = os.path.getsize(pcap_path)
                packet_count = int(values[5]) if len(values) > 5 else 0

                # Parse timestamps
                first_packet_time = None
                last_packet_time = None
                duration = 0.0

                if len(values) > 7:
                    try:
                        first_packet_time = datetime.fromtimestamp(float(values[6]))
                        last_packet_time = datetime.fromtimestamp(float(values[7]))
                        duration = float(values[8]) if len(values) > 8 else 0.0
                    except (ValueError, IndexError):
                        pass

                return FileInfo(
                    file_path=pcap_path,
                    file_size=file_size,
                    packet_count=packet_count,
                    first_packet_time=first_packet_time,
                    last_packet_time=last_packet_time,
                    duration=duration
                )
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback: get basic info from file system
            return FileInfo(
                file_path=pcap_path,
                file_size=os.path.getsize(pcap_path),
                packet_count=0
            )
