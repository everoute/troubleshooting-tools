"""SS输出解析器 - 解析ss -tinopm命令输出"""

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Union
import logging

from common.utils.file_utils import read_file_lines


@dataclass
class SSSample:
    """SS采样本 - 对应一个ss输出快照"""
    timestamp: datetime
    state: str
    recv_q: int
    send_q: int
    local_ip: str
    local_port: int
    peer_ip: str
    peer_port: int
    # TCP指标
    rtt: Optional[float] = None
    rtt_var: Optional[float] = None
    rto: Optional[int] = None
    mss: Optional[int] = None
    cwnd: Optional[int] = None
    snd_wnd: Optional[int] = None
    rcv_space: Optional[int] = None
    rcv_ssthresh: Optional[int] = None
    # 速率（bps）
    send_rate: Optional[float] = None
    pacing_rate: Optional[float] = None
    delivery_rate: Optional[float] = None
    # 重传
    retrans: Optional[int] = None
    retrans_total: Optional[int] = None
    unacked: Optional[int] = None
    lost: Optional[int] = None
    sacked: Optional[int] = None
    dsack_dups: Optional[int] = None
    # Buffer
    r: Optional[int] = None
    rb: Optional[int] = None
    t: Optional[int] = None
    tb: Optional[int] = None
    f: Optional[int] = None
    w: Optional[int] = None
    o: Optional[int] = None
    bl: Optional[int] = None
    d: Optional[int] = None
    # 限制比例
    rwnd_limited_ms: Optional[int] = None
    sndbuf_limited_ms: Optional[int] = None
    cwnd_limited_ms: Optional[int] = None
    # 原始行（调试用）
    raw_line: Optional[str] = None


class SSOutputParser:
    """SS输出解析器"""

    # 正则表达式模板
    TIMESTAMP_PATTERN = re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)')
    CONNECTION_PATTERN = re.compile(
        r'([A-Z]+)\s+(\d+)\s+(\d+)\s+([^:]+):(\d+)\s+([^:]+):(\d+)'
    )
    TCP_OPTS_PATTERN = re.compile(
        r'rtt:([\d\.]+)/([\d\.]+)\s+rto:(\d+)\s+mss:(\d+)'
    )
    CWND_PATTERN = re.compile(r'cwnd:(\d+)')
    RCV_SPACE_PATTERN = re.compile(r'rcv_space:(\d+)')
    SND_WND_PATTERN = re.compile(r'snd_wnd:(\d+)')
    RATE_PATTERN = re.compile(
        r'send\s+(\d+)bps\s+pacing_rate\s+(\d+)bps\s+delivery_rate\s+(\d+)bps'
    )
    RETRANS_PATTERN = re.compile(
        r'retrans:(\d+)/(\d+)\s+lost:(\d+)\s+unacked:(\d+)'
    )
    SACKED_PATTERN = re.compile(r'sacked:(\d+)')
    DSACK_PATTERN = re.compile(r'dsack_dups:(\d+)')
    SKMEM_PATTERN = re.compile(
        r'skmem:\(r(\d+),rb(\d+),t(\d+),tb(\d+),f(\d+),w(\d+),o(\d+),bl(\d+),d(\d+)\)'
    )
    LIMITED_PATTERN = re.compile(
        r'rwnd_limited:(\d+)ms\(([^)]+)\)\s+sndbuf_limited:(\d+)ms\(([^)]+)\)\s+cwnd_limited:(\d+)ms\(([^)]+)\)'
    )

    def __init__(self):
        self.samples: List[SSSample] = []
        self.logger = logging.getLogger(__name__)

    def parse_file(self, filepath: Union[str, Path]) -> List[SSSample]:
        """解析单个采集文件"""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        content = path.read_text(encoding='utf-8')
        samples = []

        # 按时间戳分段
        segments = self.TIMESTAMP_PATTERN.split(content)

        # segments格式: ['', timestamp1, body1, timestamp2, body2, ...]
        for i in range(1, len(segments), 2):
            if i + 1 >= len(segments):
                break

            timestamp_str = segments[i].strip()
            body = segments[i + 1]

            # 解析时间戳
            try:
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                self.logger.warning(f"Invalid timestamp format: {timestamp_str}")
                continue

            # 解析主体
            sample = self._parse_body(timestamp, body)
            if sample:
                samples.append(sample)

        self.logger.debug(f"Parsed {len(samples)} samples from {filepath}")
        return samples

    def parse_directory(self, dir_path: Union[str, Path]) -> List[List[SSSample]]:
        """解析目录中的所有采集文件"""
        dir_path = Path(dir_path)
        if not dir_path.is_dir():
            raise NotADirectoryError(f"Not a directory: {dir_path}")

        results = []
        for file_path in sorted(dir_path.glob("*")):
            if file_path.is_file():
                try:
                    samples = self.parse_file(file_path)
                    if samples:
                        results.append(samples)
                except Exception as e:
                    self.logger.warning(f"Failed to parse {file_path}: {e}")

        return results

    def _parse_body(self, timestamp: datetime, body: str) -> Optional[SSSample]:
        """解析主体内容"""
        lines = [line.strip() for line in body.strip().split('\n') if line.strip()]
        if not lines:
            return None

        # 第一行是连接信息
        conn_match = self.CONNECTION_PATTERN.search(lines[0])
        if not conn_match:
            self.logger.debug(f"No connection info in line: {lines[0][:100]}...")
            return None

        sample = SSSample(
            timestamp=timestamp,
            state=conn_match.group(1),
            recv_q=int(conn_match.group(2)),
            send_q=int(conn_match.group(3)),
            local_ip=conn_match.group(4),
            local_port=int(conn_match.group(5)),
            peer_ip=conn_match.group(6),
            peer_port=int(conn_match.group(7)),
            raw_line=lines[0]
        )

        # 剩余行是指标
        metrics_line = ' '.join(lines[1:]) if len(lines) > 1 else ''

        # 解析各个字段
        self._parse_tcp_options(sample, metrics_line)
        self._parse_rates(sample, metrics_line)
        self._parse_retrans(sample, metrics_line)
        self._parse_skmem(sample, metrics_line)
        self._parse_limited_times(sample, metrics_line)

        return sample

    def _parse_tcp_options(self, sample: SSSample, line: str):
        """解析TCP选项"""
        # rtt/rto/mss
        match = self.TCP_OPTS_PATTERN.search(line)
        if match:
            sample.rtt = float(match.group(1))
            sample.rtt_var = float(match.group(2))
            sample.rto = int(match.group(3))
            sample.mss = int(match.group(4))

        # cwnd
        match = self.CWND_PATTERN.search(line)
        if match:
            sample.cwnd = int(match.group(1))

        # rcv_space
        match = self.RCV_SPACE_PATTERN.search(line)
        if match:
            sample.rcv_space = int(match.group(1))

        # snd_wnd
        match = self.SND_WND_PATTERN.search(line)
        if match:
            sample.snd_wnd = int(match.group(1))

    def _parse_rates(self, sample: SSSample, line: str):
        """解析速率"""
        match = self.RATE_PATTERN.search(line)
        if match:
            sample.send_rate = float(match.group(1))  # 注意：这是内存使用量，不是速率
            sample.pacing_rate = float(match.group(2))
            sample.delivery_rate = float(match.group(3))

    def _parse_retrans(self, sample: SSSample, line: str):
        """解析重传信息"""
        # retrans/lost/unacked
        match = self.RETRANS_PATTERN.search(line)
        if match:
            sample.retrans = int(match.group(1))
            sample.retrans_total = int(match.group(2))
            sample.lost = int(match.group(3))
            sample.unacked = int(match.group(4))

        # sacked
        match = self.SACKED_PATTERN.search(line)
        if match:
            sample.sacked = int(match.group(1))

        # dsack_dups
        match = self.DSACK_PATTERN.search(line)
        if match:
            sample.dsack_dups = int(match.group(1))

    def _parse_skmem(self, sample: SSSample, line: str):
        """解析skmem"""
        match = self.SKMEM_PATTERN.search(line)
        if match:
            sample.r = int(match.group(1))
            sample.rb = int(match.group(2))
            sample.t = int(match.group(3))
            sample.tb = int(match.group(4))
            sample.f = int(match.group(5))
            sample.w = int(match.group(6))
            sample.o = int(match.group(7))
            sample.bl = int(match.group(8))
            sample.d = int(match.group(9))

    def _parse_limited_times(self, sample: SSSample, line: str):
        """解析受限时间"""
        match = self.LIMITED_PATTERN.search(line)
        if match:
            sample.rwnd_limited_ms = int(match.group(1))
            sample.sndbuf_limited_ms = int(match.group(3))
            sample.cwnd_limited_ms = int(match.group(5))


class ConnectionTracker:
    """连接跟踪器"""

    def __init__(self):
        self.connections: Dict[str, Dict] = {}

    def add_samples(self, samples: List[SSSample]):
        """添加样本"""
        for sample in samples:
            conn_id = self._make_conn_id(sample)

            if conn_id not in self.connections:
                self.connections[conn_id] = {
                    "local_ip": sample.local_ip,
                    "local_port": sample.local_port,
                    "peer_ip": sample.peer_ip,
                    "peer_port": sample.peer_port,
                    "state": sample.state,
                    "start_time": sample.timestamp,
                    "end_time": sample.timestamp,
                    "sample_count": 0,
                    "samples": []
                }

            conn = self.connections[conn_id]
            conn["end_time"] = sample.timestamp
            conn["sample_count"] += 1
            conn["samples"].append(sample)

    def _make_conn_id(self, sample: SSSample) -> str:
        """生成连接ID"""
        return f"{sample.local_ip}:{sample.local_port}-{sample.peer_ip}:{sample.peer_port}-{sample.state}"

    def get_connections(self) -> List[Dict]:
        """获取所有连接"""
        return list(self.connections.values())

    def get_connection_stats(self) -> Dict[str, int]:
        """获取连接统计"""
        return {
            "total_connections": len(self.connections),
        }
