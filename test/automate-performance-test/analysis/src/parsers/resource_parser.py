"""Resource Monitor Parser - Parse eBPF resource monitoring logs (pidstat output)"""

import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ResourceParser:
    """Parser for eBPF resource monitoring data (pidstat output)"""

    @staticmethod
    def parse(log_path: str, time_ranges: Optional[Dict[str, Tuple[int, int]]] = None) -> Optional[Dict]:
        """Parse resource monitor log file

        Log format (pidstat output):
            # eBPF Resource Monitoring - CPU and Memory statistics using pidstat
            # DEBUG: Starting resource monitoring for PID 47899 with interval 2s
            # START_DATETIME: 2025-10-21 22:12:39.672278096  START_EPOCH: 1761055959  INTERVAL: 2s  PID: 47899
            Linux 4.19.90-2307.3.0.el7.v97.x86_64 (node31)     10/21/2025      _x86_64_        (80 CPU)

            #      Time   UID       PID    %usr %system  %guest    %CPU   CPU  minflt/s  majflt/s     VSZ    RSS   %MEM  Command
             1761055961     0     47899   84.00    7.00    0.00   91.00     5   8292.00      0.00  356276 146004   0.03  python2

        Args:
            log_path: Path to resource monitor log file
            time_ranges: Optional dict of time ranges for filtering
                        Format: {"name": (start_epoch, end_epoch)}

        Returns:
            Dictionary with full cycle stats and time range stats
        """
        # Parse all records
        records = ResourceParser._parse_records(log_path)
        if not records:
            logger.warning(f"No records found in {log_path}")
            return None

        # Calculate full cycle statistics
        full_cycle = ResourceParser._calculate_full_cycle_stats(records)

        # Calculate time range statistics
        time_range_stats = {}
        if time_ranges:
            for name, (start_epoch, end_epoch) in time_ranges.items():
                filtered = [r for r in records
                           if start_epoch <= r["timestamp"] <= end_epoch]
                if filtered:
                    time_range_stats[name] = ResourceParser._calculate_stats(filtered)
                else:
                    logger.warning(f"No records in time range {name}: {start_epoch}-{end_epoch}")

        return {
            "full_cycle": full_cycle,
            "time_range_stats": time_range_stats
        }

    @staticmethod
    def _parse_records(log_path: str) -> List[Dict]:
        """Parse all pidstat records from log file

        Args:
            log_path: Path to log file

        Returns:
            List of record dictionaries
        """
        records = []

        try:
            with open(log_path, 'r') as f:
                for line in f:
                    # Skip comments and empty lines
                    if line.startswith('#') or not line.strip():
                        continue

                    # Skip header lines (contains "Time" keyword)
                    if "Time" in line and "UID" in line:
                        continue

                    # Parse data line
                    record = ResourceParser._parse_pidstat_line(line)
                    if record:
                        records.append(record)

        except FileNotFoundError:
            logger.warning(f"Resource monitor file not found: {log_path}")
            return []
        except Exception as e:
            logger.error(f"Error parsing resource monitor file {log_path}: {e}")
            return []

        logger.info(f"Parsed {len(records)} records from {log_path}")
        return records

    @staticmethod
    def _parse_pidstat_line(line: str) -> Optional[Dict]:
        """Parse a single pidstat output line

        Format:
         1761055961     0     47899   84.00    7.00    0.00   91.00     5   8292.00      0.00  356276 146004   0.03  python2

        Fields:
         0: Time (Unix timestamp)
         1: UID
         2: PID
         3: %usr
         4: %system
         5: %guest
         6: %CPU
         7: CPU
         8: minflt/s
         9: majflt/s
        10: VSZ (KB)
        11: RSS (KB)
        12: %MEM
        13: Command

        Args:
            line: Line from pidstat output

        Returns:
            Dictionary with parsed fields, or None if parsing fails
        """
        try:
            parts = line.split()
            if len(parts) < 13:
                return None

            return {
                "timestamp": int(parts[0]),
                "cpu_percent": float(parts[6]),
                "cpu_usr": float(parts[3]),
                "cpu_system": float(parts[4]),
                "rss_kb": int(parts[11]),
                "vsz_kb": int(parts[10]),
                "minflt_per_sec": float(parts[8]),
                "majflt_per_sec": float(parts[9]),
                "mem_percent": float(parts[12])
            }
        except (ValueError, IndexError) as e:
            logger.debug(f"Failed to parse pidstat line: {line.strip()} - {e}")
            return None

    @staticmethod
    def _calculate_stats(records: List[Dict]) -> Dict:
        """Calculate statistics from a list of records

        Args:
            records: List of parsed pidstat records

        Returns:
            Dictionary with calculated statistics
        """
        if not records:
            return None

        cpu_values = [r["cpu_percent"] for r in records]
        rss_values = [r["rss_kb"] for r in records]
        vsz_values = [r["vsz_kb"] for r in records]
        minflt_values = [r["minflt_per_sec"] for r in records]

        return {
            "cpu": {
                "avg_percent": round(sum(cpu_values) / len(cpu_values), 2),
                "max_percent": round(max(cpu_values), 2),
                "min_percent": round(min(cpu_values), 2)
            },
            "memory": {
                "avg_rss_kb": int(sum(rss_values) / len(rss_values)),
                "max_rss_kb": max(rss_values),
                "avg_vsz_kb": int(sum(vsz_values) / len(vsz_values)),
                "max_vsz_kb": max(vsz_values)
            },
            "page_faults": {
                "avg_minflt_per_sec": round(sum(minflt_values) / len(minflt_values), 2),
                "max_minflt_per_sec": round(max(minflt_values), 2)
            },
            "sample_count": len(records)
        }

    @staticmethod
    def _calculate_full_cycle_stats(records: List[Dict]) -> Dict:
        """Calculate full cycle statistics (max memory, etc.)

        Args:
            records: List of all pidstat records

        Returns:
            Dictionary with full cycle statistics
        """
        if not records:
            return None

        max_rss_record = max(records, key=lambda r: r["rss_kb"])
        max_vsz_record = max(records, key=lambda r: r["vsz_kb"])

        return {
            "max_rss_kb": max_rss_record["rss_kb"],
            "max_rss_timestamp": max_rss_record["timestamp"],
            "max_vsz_kb": max_vsz_record["vsz_kb"],
            "max_vsz_timestamp": max_vsz_record["timestamp"],
            "total_samples": len(records)
        }
