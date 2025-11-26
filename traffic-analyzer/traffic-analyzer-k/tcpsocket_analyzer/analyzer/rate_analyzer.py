"""Rate分析器 - 分析pacing_rate、delivery_rate、send_rate"""

from typing import Dict, List, Optional, Any
import pandas as pd
import numpy as np


class RateAnalyzer:
    """
    速率分析器

    根据内核调研结果：
    - send_rate: 发送缓冲区内存使用量（capacity used），不是速率！
    - pacing_rate: 由SO_MAX_PACING_RATE设置或通过fq/pacing算法计算
    - delivery_rate: 通过tcp_rate_gen()采样计算，受tcp_min_rtt约束
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化

        Args:
            config: 配置
                - delivery_rate_threshold: 速率差异阈值（默认0.2，即20%）
                - throughput_bottleneck_threshold: 吞吐瓶颈阈值（默认0.5，即50%）
        """
        self.config = config or {}
        self.delivery_rate_threshold = self.config.get('delivery_rate_threshold', 0.2)
        self.throughput_bottleneck_threshold = self.config.get('throughput_bottleneck_threshold', 0.5)

    def analyze(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析TCP速率

        Args:
            df: 时序数据

        Returns:
            速率分析结果
        """
        if df.empty:
            return {"error": "No data available"}

        # pacing_rate分析
        pacing_results = self._analyze_pacing_rate(df)

        # delivery_rate分析
        delivery_results = self._analyze_delivery_rate(df)

        # send_rate分析（注意：这是内存使用量！）
        buffer_results = self._analyze_send_buffer_usage(df)  # 重命名以澄清用途

        # 速率匹配度分析
        rate_alignment = self._analyze_rate_alignment(df, pacing_results, delivery_results)

        # 瓶颈检测
        bottleneck_detection = self._detect_bottleneck(df, pacing_results, delivery_results)

        # 吞吐量计算
        throughput = self._calculate_throughput(df, delivery_results)

        return {
            'pacing_rate': pacing_results,
            'delivery_rate': delivery_results,
            'buffer_usage': buffer_results,  # send_rate作为buffer usage
            'rate_alignment': rate_alignment,
            'bottleneck': bottleneck_detection,
            'throughput': throughput,
            'efficiency': self._calculate_rate_efficiency(pacing_results, delivery_results, throughput)
        }

    def _analyze_pacing_rate(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析pacing_rate

        pacing_rate: 发送速率限制，由fq/pacing层控制

        Returns:
            {
                "pacing_rate_avg_mbps": float,    # 平均速率（Mbps）
                "pacing_rate_min_mbps": float,    # 最小速率
                "pacing_rate_max_mbps": float,    # 最大速率
                "pacing_active_time": float,      # pacing激活时间比例
                "is_user_configured": bool        # 是否由用户配置SO_MAX_PACING_RATE
            }
        """
        if 'pacing_rate' not in df.columns or df['pacing_rate'].isna().all():
            return {"error": "No pacing_rate data"}

        pacing_series = df['pacing_rate'].dropna()

        # 计算Mbps（注意：ss输出是该值的中间值，需要还原）
        # ss -i中显示的是 >> 3后的值
        pacing_rate_mbps = (pacing_series * 8 * 1000 / 1024 / 1024)  # 转换为Mbps

        pacing_rate_avg = pacing_rate_mbps.mean()
        pacing_rate_min = pacing_rate_mbps.min()
        pacing_rate_max = pacing_rate_mbps.max()

        # 检查是否稳定（如果变化很小，可能是用户配置的）
        rate_std = pacing_rate_mbps.std()
        is_user_configured = rate_std < pacing_rate_avg * 0.1

        # 计算pacing活跃时间（pacing_rate > 0）
        pacing_active = (pacing_series > 0).sum()
        pacing_active_time = pacing_active / len(df)

        return {
            'pacing_rate_avg_mbps': float(pacing_rate_avg),
            'pacing_rate_min_mbps': float(pacing_rate_min),
            'pacing_rate_max_mbps': float(pacing_rate_max),
            'pacing_active_time': float(pacing_active_time),
            'is_user_configured': bool(is_user_configured),
            'pacing_rate_volatility': float(rate_std / pacing_rate_avg) if pacing_rate_avg > 0 else 0
        }

    def _analyze_delivery_rate(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析delivery_rate

        delivery_rate: 基于tcp_rate.c的采样机制计算，受tcp_min_rtt约束
        - 采样间隔：至少一个往返采样一次，最多128个包
        - 受tcp_min_rtt限制，会过滤异常样本以应对ack compression

        Returns:
            {
                "delivery_rate_avg_mbps": float,     # 平均速率（Mbps）
                "delivery_rate_min_mbps": float,     # 最小速率
                "delivery_rate_max_mbps": float,     # 最大速率
                "delivery_rate_samples": int,        # 有效样本数
                "is_throttled": bool                 # 是否被tcp_min_rtt限制
            }
        """
        if 'delivery_rate' not in df.columns or df['delivery_rate'].isna().all():
            return {"error": "No delivery_rate data"}

        delivery_series = df['delivery_rate'].dropna()

        # delivery_rate是已经计算好的速率（bps），需要转换为Mbps
        delivery_rate_mbps = delivery_series * 8  # 已经是bps，直接转Mbps

        delivery_rate_avg = delivery_rate_mbps.mean()
        delivery_rate_min = delivery_rate_mbps.min()
        delivery_rate_max = delivery_rate_mbps.max()

        # 有效样本统计
        delivery_rate_samples = len(delivery_series)

        # 速率变化分析（变异系数）
        rate_mean = delivery_rate_mbps.mean()
        rate_std = delivery_rate_mbps.std()
        rate_cv = rate_std / rate_mean if rate_mean > 0 else 0

        # 判断是否存在tcp_min_rtt限制（如果速率长时间不变）
        # 如果标准差相对于均值很小，可能被限制
        is_throttled = rate_cv < 0.1 and delivery_rate_samples > 10

        return {
            'delivery_rate_avg_mbps': float(delivery_rate_avg),
            'delivery_rate_min_mbps': float(delivery_rate_min),
            'delivery_rate_max_mbps': float(delivery_rate_max),
            'delivery_rate_samples': int(delivery_rate_samples),
            'is_throttled': bool(is_throttled),
            'rate_stability': float(rate_cv),
            'delivery_rate_std_mbps': float(rate_std)
        }

    def _analyze_send_buffer_usage(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析send_rate（实际上是发送缓冲区内存使用量）

        重要说明：根据内核调研，send_rate不是发送速率！
        - 它是发送缓冲区使用的内存量（sk_wmem_alloc）
        - 单位是字节

        Returns:
            {
                "buffer_usage_avg_mb": float,      # 平均内存使用（MB）
                "buffer_usage_max_mb": float,      # 峰值内存使用（MB）
                "buffer_usage_variance": float,    # 内存使用波动
                "is_misleading_name": bool         # 标记ss输出的误导性
            }
        """
        if 'send_rate' not in df.columns or df['send_rate'].isna().all():
            return {"error": "No send_rate data"}

        send_series = df['send_rate'].dropna()

        # send_rate是内存使用量（字节），转换为MB
        buffer_mb = send_series / 1024 / 1024

        buffer_avg = buffer_mb.mean()
        buffer_max = buffer_mb.max()
        buffer_min = buffer_mb.min()
        buffer_variance = buffer_mb.var()

        # 波动程度
        buffer_cv = buffer_mb.std() / buffer_avg if buffer_avg > 0 else 0

        return {
            'buffer_usage_avg_mb': float(buffer_avg),
            'buffer_usage_min_mb': float(buffer_min),
            'buffer_usage_max_mb': float(buffer_max),
            'buffer_usage_variance': float(buffer_variance),
            'buffer_usage_volatility': float(buffer_cv),
            'is_misleading_name': True,  # 重要：标记这个字段名的误导性
            'note': 'send_rate is buffer memory usage, NOT transmission rate!'
        }

    def _analyze_rate_alignment(self, df: pd.DataFrame,
                                pacing_results: Dict,
                                delivery_results: Dict) -> Dict[str, Any]:
        """
        分析pacing_rate和delivery_rate的匹配度

        pacing_rate是发送限制，delivery_rate是实际传输速率
        理想情况下：delivery_rate ≤ pacing_rate

        Returns:
            {
                "rate_match_ratio": float,          # rate匹配度（0-1）
                "exceed_count": int,                # delivery_rate > pacing_rate的次数
                "under_utilization_time": float,    # 带宽利用不足时间比例
                "bottleneck_type": str              # 瓶颈类型
            }
        """
        if ('pacing_rate' not in df.columns or df['pacing_rate'].isna().all() or
            'delivery_rate' not in df.columns or df['delivery_rate'].isna().all()):
            return {"error": "No pacing_rate or delivery_rate data"}

        # 去除NaN的行
        valid_df = df.dropna(subset=['pacing_rate', 'delivery_rate'])

        if len(valid_df) == 0:
            return {"error": "No valid pacing_rate and delivery_rate pairs"}

        # delivery_rate / pacing_rate比例
        # 注意：pacing_rate已经是Mbps，delivery_rate需要转换
        pacing_series = valid_df['pacing_rate'] * 8 * 1000 / 1024 / 1024  # Mbps
        delivery_series = valid_df['delivery_rate'] * 8  # Mbps

        rate_ratios = delivery_series / pacing_series.replace(0, np.inf)  # 避免除以0

        # 平均匹配度（越接近1越好）
        rate_match_ratio = rate_ratios.mean()

        # 统计delivery_rate超过pacing_rate的次数（不应该超过）
        exceed_count = (delivery_series > pacing_series).sum()

        # 统计带宽利用不足（delivery_rate < pacing_rate * 0.5）
        under_util_threshold = 0.5
        under_util_count = (delivery_series < pacing_series * under_util_threshold).sum()
        under_utilization_time = under_util_count / len(valid_df)

        # 判断瓶颈类型
        if rate_match_ratio > 0.9:
            bottleneck_type = "none"  # 无瓶颈，运行良好
        elif under_utilization_time > 0.3:
            bottleneck_type = "application"  # 应用层限制
            # 检查App Limited
            if 'cwnd_limited_ms' in valid_df.columns:
                if (valid_df['cwnd_limited_ms'] == 0).mean() > 0.3:
                    bottleneck_type = "application"
        elif rate_match_ratio < 0.7:
            bottleneck_type = "congestion"  # 网络拥塞
        else:
            bottleneck_type = "unknown"

        return {
            'rate_match_ratio': float(rate_match_ratio),
            'exceed_count': int(exceed_count),
            'exceed_ratio': float(exceed_count / len(valid_df)),
            'under_utilization_time': float(under_utilization_time),
            'bottleneck_type': bottleneck_type,
            'avg_rate_ratio': float(rate_match_ratio)
        }

    def _detect_bottleneck(self, df: pd.DataFrame,
                          pacing_results: Dict,
                          delivery_results: Dict) -> Dict[str, Any]:
        """
        检测性能瓶颈

        Returns:
            {
                "bottleneck_location": "none" | "sender" | "network" | "receiver",
                "confidence": float,          # 置信度（0-1）
                "bottleneck_metrics": Dict    # 相关指标
            }
        """
        bottleneck_score = {
            'sender': 0,
            'network': 0,
            'receiver': 0
        }

        # 1. 发送端瓶颈
        # - pacing_rate受限（用户配置）
        if pacing_results.get('is_user_configured'):
            bottleneck_score['sender'] += 2

        # - App Limited时间过长
        if 'cwnd_limited_ms' in df.columns:
            app_limited_ratio = (df['cwnd_limited_ms'] == 0).mean()
            if app_limited_ratio > 0.3:
                bottleneck_score['sender'] += 3
                # App Limited表示发送被应用层限制

        # 2. 网络瓶颈
        # - delivery_rate低且pacing_rate高
        if ('delivery_rate' in df.columns and not df['delivery_rate'].isna().all() and
            'pacing_rate' in df.columns and not df['pacing_rate'].isna().all()):

            valid_df = df.dropna(subset=['delivery_rate', 'pacing_rate'])

            if len(valid_df) > 0:
                pacing_series = valid_df['pacing_rate'] * 8 * 1000 / 1024 / 1024
                delivery_series = valid_df['delivery_rate'] * 8

                high_pacing_low_delivery = (
                    (pacing_series > pacing_series.quantile(0.7)) &
                    (delivery_series < delivery_series.quantile(0.3))
                ).mean()

                if high_pacing_low_delivery > 0.3:
                    bottleneck_score['network'] += 3

        # - 重传率高
        if 'retrans' in df.columns and not df['retrans'].isna().all():
            if df['retrans'].max() > 10:
                bottleneck_score['network'] += 2

        # - 丢包（d>0）
        if 'd' in df.columns and not df['d'].isna().all():
            if df['d'].max() > 0:
                bottleneck_score['network'] += 3

        # 3. 接收端瓶颈
        # - RWND受限时间长
        if 'rwnd_limited_ms' in df.columns and not df['rwnd_limited_ms'].isna().all():
            rwnd_limited_ratio = (df['rwnd_limited_ms'] > 0).mean()
            if rwnd_limited_ratio > 0.3:
                bottleneck_score['receiver'] += 3

        # - Zero Window事件
        if 'rcv_space' in df.columns:
            zero_window_count = (df['rcv_space'] == 0).sum()
            if zero_window_count > 0:
                bottleneck_score['receiver'] += 2

        # 确定瓶颈位置
        max_score = max(bottleneck_score.values())
        if max_score == 0:
            bottleneck_location = "none"
            confidence = 0.0
        else:
            # 找到得分最高的位置
            bottleneck_location = max(bottleneck_score, key=bottleneck_score.get)
            total_score = sum(bottleneck_score.values())
            confidence = max_score / total_score if total_score > 0 else 0

        return {
            'bottleneck_location': bottleneck_location,
            'confidence': float(confidence),
            'bottleneck_score': bottleneck_score,
            'bottleneck_metrics': {
                'sender_limitation': bottleneck_score['sender'],
                'network_limitation': bottleneck_score['network'],
                'receiver_limitation': bottleneck_score['receiver']
            }
        }

    def _calculate_throughput(self, df: pd.DataFrame, delivery_results: Dict) -> Dict[str, float]:
        """
        计算吞吐量

        Returns:
            {
                "avg_throughput_mbps": float,     # 平均吞吐量
                "max_throughput_mbps": float,     # 峰值吞吐量
                "throughput_efficiency": float    # 吞吐量效率
            }
        """
        if 'error' in delivery_results:
            return {"error": "Cannot calculate throughput without delivery_rate"}

        delivery_rate_avg = delivery_results.get('delivery_rate_avg_mbps', 0)
        delivery_rate_max = delivery_results.get('delivery_rate_max_mbps', 0)

        # 吞吐量效率 = delivery_rate / pacing_rate
        avg_throughput = delivery_rate_avg
        max_throughput = delivery_rate_max

        # 如果pacing_rate可用，计算效率
        throughput_efficiency = None
        if 'pacing_rate' in df.columns and not df['pacing_rate'].isna().all():
            pacing_avg = df['pacing_rate'].mean() * 8 * 1000 / 1024 / 1024
            if pacing_avg > 0:
                throughput_efficiency = delivery_rate_avg / pacing_avg

        return {
            'avg_throughput_mbps': float(avg_throughput),
            'max_throughput_mbps': float(max_throughput),
            'throughput_efficiency': float(throughput_efficiency) if throughput_efficiency else None
        }

    def _calculate_rate_efficiency(self, pacing_results: Dict,
                                  delivery_results: Dict,
                                  throughput_results: Dict) -> Dict[str, float]:
        """
        计算速率效率评分

        Returns:
            {
                "pacing_efficiency": float,      # pacing效率（0-1）
                "delivery_efficiency": float,    # delivery效率（0-1）
                "overall_efficiency": float      # 综合效率
            }
        """
        # pacing效率：变化适中且不太受限
        if 'error' not in pacing_results:
            volatility = pacing_results.get('pacing_rate_volatility', 0)
            # 波动适中（不太小也不太大）
            if 0.05 <= volatility <= 0.3:
                pacing_efficiency = 1.0
            else:
                pacing_efficiency = 1.0 - min(abs(volatility - 0.175) / 0.5, 1.0)
        else:
            pacing_efficiency = 0.0

        # delivery效率：稳定性和实际速率
        if 'error' not in delivery_results:
            stability = delivery_results.get('rate_stability', 0)
            delivery_efficiency = 1.0 - min(stability, 1.0)  # 越稳定越好
        else:
            delivery_efficiency = 0.0

        # overall效率：pacing_rate和delivery_rate的匹配度
        if ('error' not in throughput_results and
            throughput_results.get('throughput_efficiency') is not None):
            match_efficiency = throughput_results['throughput_efficiency']
        else:
            match_efficiency = 0.0

        overall_efficiency = (pacing_efficiency + delivery_efficiency + match_efficiency) / 3

        return {
            'pacing_efficiency': float(pacing_efficiency),
            'delivery_efficiency': float(delivery_efficiency),
            'match_efficiency': float(match_efficiency) if match_efficiency else 0.0,
            'overall_efficiency': float(overall_efficiency)
        }

    def generate_summary_text(self, analysis_results: Dict[str, Any]) -> str:
        """生成速率分析摘要文本"""
        if 'error' in analysis_results:
            return "速率分析: 无数据"

        pacing = analysis_results.get('pacing_rate', {})
        delivery = analysis_results.get('delivery_rate', {})
        bottleneck = analysis_results.get('bottleneck', {})
        throughput = analysis_results.get('throughput', {})

        text = "速率分析:"

        # Delivery Rate（实际传输速率）
        if 'error' not in delivery:
            text += f"\n  - 吞吐量: {delivery.get('delivery_rate_avg_mbps', 0):.1f} Mbps"

        # Pacing Rate
        if 'error' not in pacing:
            text += f"\n  - Pacing Rate: {pacing.get('pacing_rate_avg_mbps', 0):.1f} Mbps"

        # Buffer Usage
        buffer_usage = analysis_results.get('buffer_usage', {})
        if 'error' not in buffer_usage:
            text += f"\n  - 发送Buffer使用: {buffer_usage.get('buffer_usage_avg_mb', 0):.1f} MB"

        # 瓶颈
        if 'error' not in bottleneck:
            bottleneck_location = bottleneck.get('bottleneck_location', 'unknown')
            text += f"\n  - 瓶颈位置: {bottleneck_location}"

        # Zero Window检测
        zero_win_events = analysis_results.get('zero_window_events', [])
        if zero_win_events:
            text += f"\n  - Zero Window: {len(zero_win_events)}次"

        return text
