"""Utility functions for performance test analysis"""

import os
import re
import glob
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List

logger = logging.getLogger(__name__)


def parse_datetime(datetime_str: str) -> datetime:
    """Parse datetime string to datetime object

    Supports formats:
    - 2025-10-21 14:12:43.774
    - Tue, 21 Oct 2025 14:13:41 GMT
    - 2025-10-21 22:12:39.672278096

    Args:
        datetime_str: Datetime string

    Returns:
        datetime object

    Raises:
        ValueError: If format is not recognized
    """
    datetime_str = datetime_str.strip()

    # Format 1: 2025-10-21 14:12:43.774
    # Format 3: 2025-10-21 22:12:39.672278096
    if re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', datetime_str):
        # Split on space to handle optional microseconds
        parts = datetime_str.split()
        if len(parts) == 2:
            date_part, time_part = parts
            # Truncate microseconds if too long
            if '.' in time_part:
                time_base, microsec = time_part.split('.')
                microsec = microsec[:6].ljust(6, '0')  # Keep only 6 digits
                time_part = f"{time_base}.{microsec}"
            datetime_str = f"{date_part} {time_part}"

        try:
            return datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            return datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S")

    # Format 2: Tue, 21 Oct 2025 14:13:41 GMT
    if "GMT" in datetime_str:
        return datetime.strptime(datetime_str, "%a, %d %b %Y %H:%M:%S %Z")

    raise ValueError(f"Unrecognized datetime format: {datetime_str}")


def datetime_to_epoch(datetime_str: str) -> int:
    """Convert datetime string to Unix timestamp

    IMPORTANT: Assumes the input datetime string is in UTC timezone.
    The timing files from performance tests are recorded in UTC.

    Args:
        datetime_str: Datetime string in UTC timezone

    Returns:
        Unix timestamp (seconds since epoch)
    """
    # Parse the datetime string (returns naive datetime object)
    dt = parse_datetime(datetime_str)

    # The timing files are recorded in UTC
    # We need to treat the naive datetime as if it's in UTC
    dt_with_tz = dt.replace(tzinfo=timezone.utc)

    return int(dt_with_tz.timestamp())


def epoch_to_datetime(epoch: int) -> str:
    """Convert Unix timestamp to readable datetime string

    Args:
        epoch: Unix timestamp

    Returns:
        Formatted datetime string (YYYY-MM-DD HH:MM:SS)
    """
    dt = datetime.fromtimestamp(epoch)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def humanize_bytes(num_bytes: int) -> str:
    """Convert bytes to human-readable format

    Args:
        num_bytes: Number of bytes

    Returns:
        Human-readable string (e.g., "1.5MB")

    Examples:
        >>> humanize_bytes(0)
        '0B'
        >>> humanize_bytes(1024)
        '1.0KB'
        >>> humanize_bytes(1048576)
        '1.0MB'
    """
    if num_bytes == 0:
        return "0B"

    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0

    size = float(num_bytes)
    while size >= 1024.0 and unit_index < len(units) - 1:
        size /= 1024.0
        unit_index += 1

    return f"{size:.1f}{units[unit_index]}"


def bps_to_gbps(bps: float) -> float:
    """Convert bits per second to gigabits per second

    Args:
        bps: Bits per second

    Returns:
        Gigabits per second (rounded to 2 decimal places)
    """
    return round(bps / 1e9, 2)


def find_latest_file(pattern: str) -> Optional[str]:
    """Find the latest file matching glob pattern

    Args:
        pattern: Glob pattern

    Returns:
        Path to latest file, or None if no files found
    """
    files = glob.glob(pattern)
    if not files:
        return None
    return sorted(files)[-1]


def safe_read_json(file_path: str) -> Optional[Dict]:
    """Safely read JSON file with error handling

    Args:
        file_path: Path to JSON file

    Returns:
        Parsed JSON data, or None on error
    """
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"JSON file not found: {file_path}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in {file_path}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error reading JSON {file_path}: {e}")
        return None


def parse_tool_case_name(tool_case_name: str) -> Optional[Dict[str, any]]:
    """Parse tool case name into components

    Args:
        tool_case_name: Tool case name
                       Format: {topic}_case_{number}_{protocol}_{direction}_{hash}

    Returns:
        Dictionary with parsed components, or None if format doesn't match

    Examples:
        >>> parse_tool_case_name("system_network_performance_case_6_tcp_tx_0388a9")
        {
            'topic': 'system_network_performance',
            'case_number': 6,
            'protocol': 'tcp',
            'direction': 'tx',
            'hash': '0388a9'
        }
    """
    # Pattern: {topic}_case_{number}_{protocol}_{direction}_{hash}
    pattern = r"(.+)_case_(\d+)_(\w+)_(\w+)_(\w+)"
    match = re.match(pattern, tool_case_name)

    if not match:
        logger.warning(f"Tool case name doesn't match expected pattern: {tool_case_name}")
        return None

    return {
        "topic": match.group(1),
        "case_number": int(match.group(2)),
        "protocol": match.group(3),
        "direction": match.group(4),
        "hash": match.group(5)
    }


def safe_join_path(base: str, *parts: str) -> str:
    """Safely join path components and verify result is within base

    Args:
        base: Base directory path
        *parts: Path components to join

    Returns:
        Joined absolute path

    Raises:
        ValueError: If resulting path is outside base directory
    """
    path = os.path.join(base, *parts)
    abs_base = os.path.abspath(base)
    abs_path = os.path.abspath(path)

    if not abs_path.startswith(abs_base):
        raise ValueError(f"Invalid path: {path} is outside base {base}")

    return abs_path


def safe_parse(parser_func, *args, default=None, **kwargs):
    """Safely execute parser function with error handling

    Args:
        parser_func: Parser function to execute
        *args: Positional arguments for parser
        default: Default value to return on error
        **kwargs: Keyword arguments for parser

    Returns:
        Parser result or default value on error
    """
    try:
        return parser_func(*args, **kwargs)
    except FileNotFoundError as e:
        logger.warning(f"File not found in {parser_func.__name__}: {e}")
        return default
    except Exception as e:
        logger.error(f"Error in {parser_func.__name__}: {e}")
        return default


def get_file_size(file_path: str) -> int:
    """Get file size in bytes

    Args:
        file_path: Path to file

    Returns:
        File size in bytes, or 0 if file doesn't exist
    """
    try:
        return os.path.getsize(file_path)
    except OSError:
        return 0
