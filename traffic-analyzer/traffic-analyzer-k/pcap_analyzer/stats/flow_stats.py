"""流统计模块"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
import statistics


@dataclass(frozen=True)
class FlowKey:
    """流标识（5元组）"""
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str  # 'tcp', 'udp', 'icmp', etc.

    def __str__(self) -> str:
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"


@dataclass
class FlowStats:
    """流统计信息"""
    flow_key: FlowKey
    start_time: float
    end_time: float
    packet_count: int = 0
    byte_count: int = 0
    src_byte_count: int = 0
    dst_byte_count: int = 0
    # TCP特有
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    retrans_count: int = 0
    # 窗口相关
    min_window: Optional[int] = None
    max_window: Optional[int] = None
    window_values: List[int] = field(default_factory=list)
    # RTT
    rtt_values: List[float] = field(default_factory=list)

    def add_packet(self, packet: Dict[str, Any], direction: str = "forward"):
        """添加数据包到统计"""
        self.packet_count += 1

        # 字节数
        frame_len = int(packet.get("frame", {}).get("frame.len", 0))
        self.byte_count += frame_len

        if direction == "forward":
            self.src_byte_count += frame_len
        else:
            self.dst_byte_count += frame_len

        # TCP特殊处理
        if self.flow_key.protocol == "tcp" and "tcp" in packet:
            self._process_tcp_packet(packet["tcp"], direction)

    def _process_tcp_packet(self, tcp_layer: Dict, direction: str):
        """处理TCP数据包特有的字段"""
        # 标志位
        flags = int(tcp_layer.get("tcp.flags", 0))
        if flags & 0x02:
            self.syn_count += 1
        if flags & 0x01:
            self.fin_count += 1
        if flags & 0x04:
            self.rst_count += 1

        # 窗口大小
        window = int(tcp_layer.get("tcp.window_size", 0))
        if window > 0:
            self.window_values.append(window)
            if self.min_window is None or window < self.min_window:
                self.min_window = window
            if self.max_window is None or window > self.max_window:
                self.max_window = window

        # 重传检测（简单实现：检查重复序列号）
        # TODO: 更复杂的重传检测

    @property
    def duration(self) -> float:
        """流持续时间"""
        return self.end_time - self.start_time

    @property
    def avg_rate(self) -> float:
        """平均速率（bytes/sec）"""
        if self.duration > 0:
            return self.byte_count / self.duration
        return 0.0

    @property
    def avg_packet_size(self) -> float:
        """平均包大小"""
        if self.packet_count > 0:
            return self.byte_count / self.packet_count
        return 0.0

    def get_summary(self) -> Dict[str, Any]:
        """获取摘要信息"""
        return {
            "flow_key": str(self.flow_key),
            "duration": self.duration,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "avg_rate": self.avg_rate,
            "avg_packet_size": self.avg_packet_size,
            "protocol": self.flow_key.protocol,
            # TCP特有
            "syn_count": self.syn_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "retrans_count": self.retrans_count,
            "window_stats": {
                "min": self.min_window,
                "max": self.max_window,
                "avg": statistics.mean(self.window_values) if self.window_values else None
            } if self.window_values else None
        }


class FlowAggregator:
    """流聚合器"""

    def __init__(self):
        self.flows: Dict[FlowKey, FlowStats] = {}
        self.logger = logging.getLogger(__name__)

    def add_packet(self, packet: Dict[str, Any]):
        """添加数据包到聚合器"""
        flow_key = self._extract_flow_key(packet)
        if not flow_key:
            return

        # 获取或创建流统计
        if flow_key not in self.flows:
            timestamp = float(packet.get("frame", {}).get("frame.time_epoch", 0))
            self.flows[flow_key] = FlowStats(
                flow_key=flow_key,
                start_time=timestamp,
                end_time=timestamp
            )

        flow_stats = self.flows[flow_key]

        # 确定方向（client to server 或相反）
        direction = "forward"  # 简单实现，TODO: 更精确的方向判断

        # 更新统计
        timestamp = float(packet.get("frame", {}).get("frame.time_epoch", 0))
        flow_stats.end_time = max(flow_stats.end_time, timestamp)
        flow_stats.add_packet(packet, direction)

    def _extract_flow_key(self, packet: Dict[str, Any]) -> Optional[FlowKey]:
        """提取流标识（5元组）"""
        layers = packet.get("layers", {})

        # IP层
        if "ip" not in layers:
            return None

        ip_layer = layers["ip"]
        src_ip = ip_layer.get("ip.src")
        dst_ip = ip_layer.get("ip.dst")

        if not src_ip or not dst_ip:
            return None

        # 传输层
        protocol = None
        src_port = None
        dst_port = None

        if "tcp" in layers:
            tcp_layer = layers["tcp"]
            protocol = "tcp"
            src_port = int(tcp_layer.get("tcp.srcport", 0)) if tcp_layer.get("tcp.srcport") else None
            dst_port = int(tcp_layer.get("tcp.dstport", 0)) if tcp_layer.get("tcp.dstport") else None
        elif "udp" in layers:
            udp_layer = layers["udp"]
            protocol = "udp"
            src_port = int(udp_layer.get("udp.srcport", 0)) if udp_layer.get("udp.srcport") else None
            dst_port = int(udp_layer.get("udp.dstport", 0)) if udp_layer.get("udp.dstport") else None
        elif "icmp" in layers:
            protocol = "icmp"
            # ICMP没有端口，使用类型和代码
            icmp_layer = layers["icmp"]
            src_port = int(icmp_layer.get("icmp.type", 0))
            dst_port = int(icmp_layer.get("icmp.code", 0))
        else:
            # 不支持的协议
            return None

        return FlowKey(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol
        )

    def get_flow_stats(self) -> List[FlowStats]:
        """获取所有流统计"""
        return list(self.flows.values())

    def get_top_flows(self, by: str = "byte_count", top_n: int = 10) -> List[FlowStats]:
        """
        获取Top N流

        Args:
            by: 排序字段（byte_count, packet_count, duration）
            top_n: 返回数量

        Returns:
            Top N流列表
        """
        flows = self.get_flow_stats()

        if not flows:
            return []

        # 排序
        if by == "byte_count":
            flows.sort(key=lambda f: f.byte_count, reverse=True)
        elif by == "packet_count":
            flows.sort(key=lambda f: f.packet_count, reverse=True)
        elif by == "duration":
            flows.sort(key=lambda f: f.duration, reverse=True)
        elif by == "avg_rate":
            flows.sort(key=lambda f: f.avg_rate, reverse=True)
        else:
            raise ValueError(f"Unsupported sort field: {by}")

        return flows[:top_n]

    def clear(self):
        """清空所有流统计"""
        self.flows.clear()
