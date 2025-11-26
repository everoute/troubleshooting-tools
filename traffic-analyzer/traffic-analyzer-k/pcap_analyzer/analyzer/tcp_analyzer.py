"""TCP分析器 - 重传、窗口、RTT等深度分析"""

from collections import defaultdict
from typing import Dict, List, Optional, Any, Set
import statistics
import numpy as np


class RetransmissionDetector:
    """重传检测器"""

    def __init__(self):
        self.seen_seqs: Dict[str, Set[int]] = defaultdict(set)  # 流ID -> 已见序列号集合

    def detect_retransmission(self, flow_id: str, seq: int, packet: Dict) -> bool:
        """检测重传 - 如果序列号已确认过，则是重传"""
        if seq in self.seen_seqs[flow_id]:
            return True
        self.seen_seqs[flow_id].add(seq)
        return False


class RTTEstimator:
    """RTT估算器 - 基于TCP Timestamps"""

    def __init__(self):
        self.rtt_samples: List[float] = []

    def estimate_rtt(self, packet: Dict) -> Optional[float]:
        """
        从数据包估算RTT

        方法1: 使用TCP Timestamps选项（如果有）
        方法2: 通过SYN-ACK对估算（更简单）

        Returns:
            RTT值（ms）或None
        """
        layers = packet.get("layers", {})

        if "tcp" not in layers:
            return None

        tcp_layer = layers["tcp"]

        # 尝试使用TCP Timestamps
        # 注意：tshark的JSON输出可能包含这些字段
        if "tcp_options_timestamp_tsval" in tcp_layer and \
           "tcp_options_timestamp_tsecr" in tcp_layer:
            ts_val = float(tcp_layer["tcp_options_timestamp_tsval"])
            ts_echo = float(tcp_layer["tcp_options_timestamp_tsecr"])
            if ts_echo > 0:
                # RTT = 当前时间戳 - Echo的时间戳
                rtt = (ts_val - ts_echo) / 1000  # 转换为ms
                self.rtt_samples.append(rtt)
                return rtt

        return None

    def get_rtt_stats(self) -> Dict[str, float]:
        """获取RTT统计"""
        if not self.rtt_samples:
            return {}

        return {
            "min_rtt": min(self.rtt_samples),
            "max_rtt": max(self.rtt_samples),
            "avg_rtt": statistics.mean(self.rtt_samples),
            "rtt_std": statistics.stdev(self.rtt_samples) if len(self.rtt_samples) > 1 else 0,
            "p50_rtt": float(np.percentile(self.rtt_samples, 50)),
            "p95_rtt": float(np.percentile(self.rtt_samples, 95)),
            "p99_rtt": float(np.percentile(self.rtt_samples, 99))
        }


class WindowAnalyzer:
    """TCP窗口分析器"""

    def __init__(self):
        self.window_values: List[int] = []
        self.zero_window_events: int = 0
        self.window_full_events: int = 0

    def analyze_window(self, tcp_layer: Dict):
        """分析窗口字段"""
        window = int(tcp_layer.get("tcp.window_size", 0))

        if window > 0:
            self.window_values.append(window)

        # Zero Window事件
        if window == 0:
            self.zero_window_events += 1

    def get_window_stats(self) -> Optional[Dict[str, Any]]:
        """获取窗口统计"""
        if not self.window_values:
            return None

        return {
            "min_window": min(self.window_values),
            "max_window": max(self.window_values),
            "avg_window": statistics.mean(self.window_values),
            "zero_window_events": self.zero_window_events,
            "window_full_events": self.window_full_events
        }


class SmartAnalyzer:
    """智能问题识别分析器"""

    def __init__(self):
        self.issues: List[Dict] = []

    def add_issue(self, category: str, severity: str, title: str,
                  description: str, evidence: str, recommendation: str):
        """添加问题"""
        self.issues.append({
            "category": category,
            "severity": severity,  # high/medium/low
            "title": title,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation
        })

    def analyze_tcp(self, tcp_stats: Dict) -> Dict[str, Any]:
        """
        分析TCP问题

        Args:
            tcp_stats: TCP统计信息

        Returns:
            问题列表
        """
        self.issues.clear()

        # 1. 高重传率
        retrans_rate = tcp_stats.get("retrans_rate", 0)
        if retrans_rate > 0.05:  # > 5% 严重
            self.add_issue(
                category="retransmission",
                severity="high",
                title="高重传率",
                description="检测到重传率过高，表明网络质量较差或存在拥塞",
                evidence=f"重传率: {retrans_rate:.2%}",
                recommendation="检查物理链路质量、减少网络拥塞、调整TCP拥塞控制算法"
            )
        elif retrans_rate > 0.01:  # > 1% 中等
            self.add_issue(
                category="retransmission",
                severity="medium",
                title="重传率偏高",
                description="重传率超过正常范围",
                evidence=f"重传率: {retrans_rate:.2%}",
                recommendation="监控网络质量，检查是否有周期性丢包"
            )

        # 2. RTT异常
        avg_rtt = tcp_stats.get("avg_rtt", 0)
        if avg_rtt > 1000:  # > 1秒 严重
            self.add_issue(
                category="performance",
                severity="high",
                title="RTT异常高",
                description="平均RTT超过1秒，网络延迟严重",
                evidence=f"平均RTT: {avg_rtt:.1f}ms",
                recommendation="检查网络路径、路由、物理链路"
            )
        elif avg_rtt > 200:  # > 200ms 中等
            self.add_issue(
                category="performance",
                severity="medium",
                title="RTT偏高",
                description="网络延迟较高",
                evidence=f"平均RTT: {avg_rtt:.1f}ms",
                recommendation="检查网络拓扑、减少跳数"
            )

        # 3. Zero Window频繁
        zero_win = tcp_stats.get("zero_window_events", 0)
        if zero_win > 5:
            self.add_issue(
                category="window",
                severity="high",
                title="频繁Zero Window事件",
                description="多次出现接收窗口为0，表明接收方处理缓慢",
                evidence=f"Zero Window事件: {zero_win}次",
                recommendation="检查接收方应用性能，增大tcp_rmem缓冲区"
            )

        # 4. 小包过多
        avg_pkt_size = tcp_stats.get("avg_packet_size", 0)
        if avg_pkt_size < 200:
            self.add_issue(
                category="performance",
                severity="medium",
                title="小包过多",
                description="平均包大小过小，协议效率低",
                evidence=f"平均包大小: {avg_pkt_size:.1f} bytes",
                recommendation="考虑应用层合并小包或使用批量接口"
            )

        return {
            "issues": self.issues,
            "summary": {
                "total_issues": len(self.issues),
                "high_priority": sum(1 for i in self.issues if i["severity"] == "high"),
                "medium_priority": sum(1 for i in self.issues if i["severity"] == "medium"),
                "low_priority": sum(1 for i in self.issues if i["severity"] == "low")
            }
        }


class TCPAnalyzer:
    """TCP协议深度分析器 - 整合所有子分析器"""

    def __init__(self):
        self.retrans_detector = RetransmissionDetector()
        self.rtt_estimator = RTTEstimator()
        self.window_analyzer = WindowAnalyzer()
        self.smart_analyzer = SmartAnalyzer()

        self.flow_stats = {}
        self.total_packets = 0
        self.total_bytes = 0

    def analyze_flow(self, flow_key: str, packets: List[Dict]) -> Dict[str, Any]:
        """
        分析TCP流

        Args:
            flow_key: 流标识
            packets: 该流的所有数据包（按时间排序）

        Returns:
            分析结果
        """
        result = {
            "flow_key": flow_key,
            "packet_count": len(packets),
            "byte_count": sum(int(p.get("frame", {}).get("frame.len", 0)) for p in packets),
            "retrans_stats": {},
            "window_stats": {},
            "rtt_stats": {},
            "smart_analysis": {}
        }

        # 分析每个数据包
        for packet in packets:
            self._analyze_packet(flow_key, packet)

        # 收集统计
        result["retrans_stats"] = {
            "total_retrans": len([p for p in packets if self.retrans_detector.detect_retransmission(
                flow_key,
                int(p.get("tcp", {}).get("tcp.seq", 0)),
                p
            )])
        }

        result["window_stats"] = self.window_analyzer.get_window_stats()
        result["rtt_stats"] = self.rtt_estimator.get_rtt_stats()
        result["smart_analysis"] = self.smart_analyzer.analyze_tcp(result)

        return result

    def analyze_summary(self, packets: List[Dict]) -> Dict[str, Any]:
        """分析摘要统计"""
        total_packets = len(packets)
        total_bytes = sum(int(p.get("frame", {}).get("frame.len", 0)) for p in packets)
        tcp_packets = [p for p in packets if "tcp" in p.get("layers", {})]
        udp_packets = [p for p in packets if "udp" in p.get("layers", {})]
        icmp_packets = [p for p in packets if "icmp" in p.get("layers", {})]

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "protocol_distribution": {
                "tcp": len(tcp_packets),
                "udp": len(udp_packets),
                "icmp": len(icmp_packets),
                "other": total_packets - len(tcp_packets) - len(udp_packets) - len(icmp_packets)
            }
        }

    def _analyze_packet(self, flow_key: str, packet: Dict):
        """分析单个数据包"""
        # RTT估算
        self.rtt_estimator.estimate_rtt(packet)

        # 窗口分析
        tcp_layer = packet.get("layers", {}).get("tcp")
        if tcp_layer:
            self.window_analyzer.analyze_window(tcp_layer)

        # 重传检测（序列号）
        if tcp_layer and "tcp.seq" in tcp_layer:
            seq = int(tcp_layer["tcp.seq"])
            self.retrans_detector.detect_retransmission(flow_key, seq, packet)
