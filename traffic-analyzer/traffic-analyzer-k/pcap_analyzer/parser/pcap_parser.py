"""PCAP解析器 - 封装tshark命令行工具"""

import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, List, Iterator, Optional

from common.utils.logger import get_logger
from common.utils.file_utils import check_file_exists


class PCAPParserError(Exception):
    """PCAP解析器异常"""
    pass


class TSharkNotFoundError(PCAPParserError):
    """tshark未找到异常"""
    pass


class ParseError(PCAPParserError):
    """解析异常"""
    pass


class PCAPParser:
    """PCAP文件解析器"""

    def __init__(self, pcap_path: str, tshark_path: str = "tshark"):
        """
        初始化解析器

        Args:
            pcap_path: PCAP文件或目录路径
            tshark_path: tshark命令路径
        """
        self.pcap_path = Path(pcap_path)
        self.tshark_path = tshark_path
        self.logger = get_logger(__name__)

        # 检查路径
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP path not found: {pcap_path}")

        # 检查tshark
        if not self._check_tshark():
            raise TSharkNotFoundError(
                f"tshark not found at: {tshark_path}. "
                "Please install Wireshark/tshark first."
            )

        self.total_packets = 0
        self.total_bytes = 0

    def _check_tshark(self) -> bool:
        """检查tshark是否可用"""
        try:
            result = subprocess.run(
                [self.tshark_path, "-v"],
                capture_output=True,
                check=True
            )
            return result.returncode == 0
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def parse_summary(self) -> Dict[str, Any]:
        """
        Summary模式解析 - 快速概览统计

        Returns:
            概览统计信息
        """
        self.logger.info("Parsing PCAP in summary mode: %s", self.pcap_path)

        if self.pcap_path.is_file():
            return self._parse_file_summary(self.pcap_path)
        else:
            # 目录：合并所有文件
            return self._parse_directory_summary()

    def _parse_file_summary(self, filepath: Path) -> Dict[str, Any]:
        """解析单个文件摘要"""
        self.logger.debug("Parsing file: %s", filepath)

        cmd = [
            self.tshark_path,
            "-r", str(filepath),
            "-q",  # 安静模式
            "-z", "io,stat,0"  # 统计信息
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return self._parse_tshark_summary_output(result.stdout)

        except subprocess.CalledProcessError as e:
            raise ParseError(f"tshark failed: {e.stderr}")

    def _parse_directory_summary(self) -> Dict[str, Any]:
        """解析目录（合并所有文件）"""
        self.logger.info("Parsing directory: %s", self.pcap_path)

        all_stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "protocol_distribution": {},
            "file_count": 0
        }

        for pcap_file in sorted(self.pcap_path.glob("*.pcap*")):
            if not pcap_file.is_file():
                continue

            self.logger.debug("Processing file: %s", pcap_file.name)

            try:
                file_stats = self._parse_file_summary(pcap_file)

                # 合并统计
                all_stats["total_packets"] += file_stats.get("total_packets", 0)
                all_stats["total_bytes"] += file_stats.get("total_bytes", 0)
                all_stats["file_count"] += 1

                # 合并协议分布
                for proto, count in file_stats.get("protocol_distribution", {}).items():
                    all_stats["protocol_distribution"][proto] = (
                        all_stats["protocol_distribution"].get(proto, 0) + count
                    )

            except ParseError as e:
                self.logger.warning("Failed to parse %s: %s", pcap_file, e)
                continue

        return all_stats

    def _parse_tshark_summary_output(self, output: str) -> Dict[str, Any]:
        """解析tshark摘要输出"""
        stats = {}

        lines = output.strip().split('\n')

        # 查找关键信息
        for line in lines:
            line = line.strip()

            # Duration
            if line.startswith("Duration"):
                stats["duration"] = line.split(":", 1)[1].strip()

            # 数据包和字节数
            elif line.startswith("Avg.") or line.startswith("Interval"):
                continue  # 跳过表头

            elif '|' in line:
                # 解析表格行
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 3 and parts[0] and not parts[0].startswith("-"):
                    # 这是数据行
                    try:
                        interval = parts[0]
                        bytes_val = int(parts[1].replace(",", ""))
                        packets_val = int(parts[2].replace(",", ""))

                        stats["total_bytes"] = bytes_val
                        stats["total_packets"] = packets_val
                    except (ValueError, IndexError):
                        continue

        return stats

    def parse_packets_stream(self, filter_expr: Optional[str] = None) -> Iterator[Dict[str, Any]]:
        """
        流式解析PCAP文件（逐包返回）

        Args:
            filter_expr: 过滤表达式（BPF语法）

        Yields:
            每个包的解析结果（JSON格式）
        """
        if self.pcap_path.is_dir():
            # 目录：逐个文件
            for pcap_file in sorted(self.pcap_path.glob("*.pcap*")):
                if not pcap_file.is_file():
                    continue

                yield from self._parse_file_stream(pcap_file, filter_expr)
        else:
            # 单个文件
            yield from self._parse_file_stream(self.pcap_path, filter_expr)

    def _parse_file_stream(self, filepath: Path, filter_expr: Optional[str] = None) -> Iterator[Dict[str, Any]]:
        """流式解析单个文件"""
        self.logger.debug("Streaming parse file: %s", filepath.name)

        cmd = [
            self.tshark_path,
            "-r", str(filepath),
            "-T", "json",  # JSON输出
            "-x"  # 包含原始数据
        ]

        if filter_expr:
            cmd.extend(["-f", filter_expr])

        try:
            # 使用管道流式读取
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True) as proc:
                # tshark JSON输出是多行格式，每行是一个JSON对象
                buffer = ""
                for line in proc.stdout:
                    line = line.strip()

                    if not line:
                        continue

                    # 收集完整的JSON对象
                    buffer += line

                    try:
                        packet = json.loads(buffer)
                        yield self._process_packet(packet)
                        buffer = ""
                    except json.JSONDecodeError:
                        # JSON不完整，继续读取
                        continue

        except subprocess.CalledProcessError as e:
            raise ParseError(f"tshark failed: {e}")

    def _process_packet(self, packet: Dict) -> Dict[str, Any]:
        """处理单个数据包"""
        # 提取基本字段
        result = {
            "timestamp": float(packet["_source"]["layers"]["frame"]["frame.time_epoch"]),
            "frame": packet["_source"]["layers"]["frame"],
            "layers": packet["_source"]["layers"]
        }

        return result

    def get_flows(self, filter_expr: Optional[str] = None) -> Dict[str, List[Dict]]:
        """
        提取所有数据流（按5元组分组）

        Args:
            filter_expr: 过滤表达式

        Returns:
            流字典，key为流ID（5元组哈希）
        """
        flows = {}

        for packet in self.parse_packets_stream(filter_expr):
            flow_key = self._extract_flow_key(packet)

            if not flow_key:
                continue

            if flow_key not in flows:
                flows[flow_key] = []

            flows[flow_key].append(packet)

        return flows

    def _extract_flow_key(self, packet: Dict) -> Optional[str]:
        """提取流标识（5元组）"""
        layers = packet.get("layers", {})

        # IP层
        if "ip" not in layers:
            return None

        ip_layer = layers["ip"]
        src_ip = ip_layer.get("ip.src")
        dst_ip = ip_layer.get("ip.dst")

        # 传输层
        protocol = None
        src_port = None
        dst_port = None

        if "tcp" in layers:
            tcp_layer = layers["tcp"]
            protocol = "tcp"
            src_port = tcp_layer.get("tcp.srcport")
            dst_port = tcp_layer.get("tcp.dstport")
        elif "udp" in layers:
            udp_layer = layers["udp"]
            protocol = "udp"
            src_port = udp_layer.get("udp.srcport")
            dst_port = udp_layer.get("udp.dstport")
        elif "icmp" in layers:
            protocol = "icmp"
            # ICMP没有端口，使用类型和代码
            icmp_layer = layers["icmp"]
            src_port = icmp_layer.get("icmp.type", "0")
            dst_port = icmp_layer.get("icmp.code", "0")

        if not all([src_ip, dst_ip, protocol]):
            return None

        # 创建流ID（双向统一）
        forward_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        reverse_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

        # 使用排序确保双向流使用相同ID
        return "-".join(sorted([forward_key, reverse_key]))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
