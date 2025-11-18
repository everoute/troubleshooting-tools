"""Window分析器 - 分析CWND/RWND/TCP窗口机制"""

from typing import Dict, List, Optional, Any
import pandas as pd
import numpy as np


class WindowAnalyzer:
    """TCP窗口分析器（拥塞窗口与接收窗口）"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化

        Args:
            config: 配置
                - rwnd_threshold: RWND下限阈值（BDP百分比，默认0.7）
                - cwnd_growth_threshold: CWND增长阈值（包/秒，默认10）
        """
        self.config = config or {}
        self.rwnd_threshold = self.config.get('rwnd_threshold', 0.7)
        self.cwnd_growth_threshold = self.config.get('cwnd_growth_threshold', 10)

    def analyze(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析TCP窗口

        Args:
            df: 时序数据

        Returns:
            窗口分析结果
        """
        if df.empty:
            return {"error": "No data available"}

        # BDP计算（带宽延迟积）
        bdp_results = self._calculate_bdp(df)

        # CWND分析
        cwnd_results = self._analyze_cwnd(df, bdp_results)

        # RWND分析
        rwnd_results = self._analyze_rwnd(df, bdp_results)

        # 拥塞避免检测
        congestion_state = self._detect_congestion_state(df)

        # Zero Window检测
        zero_window_events = self._detect_zero_window(df)

        return {
            'bdp': bdp_results,
            'cwnd': cwnd_results,
            'rwnd': rwnd_results,
            'congestion_state': congestion_state,
            'zero_window_events': zero_window_events,
            'window_efficiency': self._calculate_window_efficiency(cwnd_results, rwnd_results)
        }

    def _calculate_bdp(self, df: pd.DataFrame) -> Dict[str, float]:
        """
        计算带宽延迟积（BDP）

        Formula:
            BDP = bandwidth (bytes/sec) * rtt (sec)

        Returns:
            {
                "bdp_bytes": float,      # BDP（字节）
                "bdp_packets": float,    # BDP（包数，基于MSS）
                "mss": int               # 最大段大小
            }
        """
        if df.empty:
            return {"error": "No data"}

        # 估算带宽（使用delivery_rate或pacing_rate）
        if 'delivery_rate' in df.columns and not df['delivery_rate'].isna().all():
            bandwidth_bps = df['delivery_rate'].max() * 8  # 转换为bps
        elif 'pacing_rate' in df.columns and not df['pacing_rate'].isna().all():
            bandwidth_bps = df['pacing_rate'].max() * 8
        else:
            bandwidth_bps = 100 * 10**6  # 默认值：100Mbps

        # 估算RTT
        if 'rtt' in df.columns and not df['rtt'].isna().all():
            rtt_sec = df['rtt'].mean() / 1000  # ms转秒
        else:
            rtt_sec = 0.001  # 默认值：1ms

        # 计算BDP（字节）
        bdp_bytes = (bandwidth_bps * rtt_sec) / 8

        # 获取MSS
        mss = 1460  # 默认MSS
        if 'mss' in df.columns and not df['mss'].isna().all():
            mss = int(df['mss'].iloc[0])

        # BDP（包数）
        bdp_packets = bdp_bytes / mss

        return {
            'bdp_bytes': float(bdp_bytes),
            'bdp_packets': float(bdp_packets),
            'mss': int(mss),
            'bandwidth_bps': float(bandwidth_bps),
            'rtt_sec': float(rtt_sec)
        }

    def _analyze_cwnd(self, df: pd.DataFrame, bdp_results: Dict) -> Dict[str, Any]:
        """
        分析拥塞窗口（CWND）

        Returns:
            {
                "cwnd_avg": int,           # 平均CWND
                "cwnd_max": int,           # 最大CWND
                "cwnd_min": int,           # 最小CWND
                "cwnd_relative_bdp": float, # CWND/BDP比例
                "cwnd_growth_rate": float, # CWND增长率（包/秒）
                "app_limited_time": float,  # App Limited时间比例
                "congestion_recovery_count": int  # 拥塞恢复次数
            }
        """
        if 'cwnd' not in df.columns or df['cwnd'].isna().all():
            return {"error": "No CWND data"}

        cwnd_series = df['cwnd'].dropna()

        # 基本统计
        cwnd_avg = cwnd_series.mean()
        cwnd_max = cwnd_series.max()
        cwnd_min = cwnd_series.min()

        # CWND/BDP比例（理想情况是CWND ≈ BDP）
        bdp_packets = bdp_results.get('bdp_packets', cwnd_max)
        cwnd_relative_bdp = cwnd_avg / bdp_packets if bdp_packets > 0 else 0

        # CWND增长率（通过线性回归）
        if len(cwnd_series) > 1:
            x = np.arange(len(cwnd_series))
            slope, _, _, _, _ = np.polyfit(x, cwnd_series.values, 1)
            cwnd_growth_rate = float(slope)
        else:
            cwnd_growth_rate = 0

        # App Limited时间比例
        if 'cwnd_limited_ms' in df.columns and not df['cwnd_limited_ms'].isna().all():
            total_time = len(df)
            app_limited_time = (df['cwnd_limited_ms'] == 0).sum() / total_time
        else:
            app_limited_time = None

        # 拥塞恢复检测（CWND突然下降）
        congestion_recovery_count = 0
        if len(cwnd_series) > 1:
            for i in range(1, len(cwnd_series)):
                if cwnd_series.iloc[i] < cwnd_series.iloc[i-1] * 0.8:
                    congestion_recovery_count += 1

        return {
            'cwnd_avg': int(cwnd_avg),
            'cwnd_max': int(cwnd_max),
            'cwnd_min': int(cwnd_min),
            'cwnd_relative_bdp': float(cwnd_relative_bdp),
            'cwnd_growth_rate': float(cwnd_growth_rate),
            'app_limited_time': float(app_limited_time) if app_limited_time is not None else None,
            'congestion_recovery_count': int(congestion_recovery_count)
        }

    def _analyze_rwnd(self, df: pd.DataFrame, bdp_results: Dict) -> Dict[str, Any]:
        """
        分析接收窗口（RWND）

        Returns:
            {
                "rwnd_avg": int,              # 接收窗口（rcv_space）平均值
                "rwnd_min": int,              # 接收窗口最小值
                "rwnd_relative_bdp": float,   # RWND/BDP比例
                "rwnd_limited_time": float,   # RWND受限时间比例
                "rwnd_ssthresh_avg": int,     # 接收阈值平均值
                "under_utilized": bool        # 是否窗口利用不足
            }
        """
        if 'rcv_space' not in df.columns or df['rcv_space'].isna().all():
            return {"error": "No RWND data"}

        rwnd_series = df['rcv_space'].dropna()

        # 基本统计
        rwnd_avg = rwnd_series.mean()
        rwnd_min = rwnd_series.min()

        # RWND/BDP比例
        bdp_bytes = bdp_results.get('bdp_bytes', rwnd_avg)
        rwnd_relative_bdp = rwnd_avg / bdp_bytes if bdp_bytes > 0 else 0

        # RWND受限时间比例
        if 'rwnd_limited_ms' in df.columns and not df['rwnd_limited_ms'].isna().all():
            total_time = len(df)
            rwnd_limited_time = (df['rwnd_limited_ms'] > 0).sum() / total_time
        else:
            rwnd_limited_time = None

        # 接收阈值
        if 'rcv_ssthresh' in df.columns and not df['rcv_ssthresh'].isna().all():
            rwnd_ssthresh_avg = df['rcv_ssthresh'].mean()
        else:
            rwnd_ssthresh_avg = None

        # 窗口利用不足（RWND >> BDP）
        under_utilized = rwnd_relative_bdp > 2.0

        return {
            'rwnd_avg': int(rwnd_avg),
            'rwnd_min': int(rwnd_min),
            'rwnd_relative_bdp': float(rwnd_relative_bdp),
            'rwnd_limited_time': float(rwnd_limited_time) if rwnd_limited_time is not None else None,
            'rwnd_ssthresh_avg': int(rwnd_ssthresh_avg) if rwnd_ssthresh_avg else None,
            'under_utilized': bool(under_utilized)
        }

    def _detect_congestion_state(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        检测拥塞状态

        Returns:
            {
                "state": "normal" | "congested" | "recovery",
                "evidence": str,
                "duration": float
            }
        """
        if 'cwnd' not in df.columns or df['cwnd'].isna().all():
            return {"state": "unknown", "evidence": "No CWND data"}

        cwnd_series = df['cwnd'].dropna()

        if len(cwnd_series) < 3:
            return {"state": "unknown", "evidence": "Insufficient data"}

        # 检测连续下降（拥塞恢复）
        recent_cwnd = cwnd_series.tail(5)  # 最近5个样本
        decreasing_count = 0
        for i in range(1, len(recent_cwnd)):
            if recent_cwnd.iloc[i] < recent_cwnd.iloc[i-1]:
                decreasing_count += 1

        if decreasing_count >= 3:
            return {
                'state': 'recovery',
                'evidence': f'CWND连续下降{decreasing_count}次',
                'duration': len(recent_cwnd)
            }

        # 检测CWND < 10（严重拥塞）
        if cwnd_series.tail(3).mean() < 10:
            return {
                'state': 'congested',
                'evidence': 'CWND严重偏小（<10）',
                'duration': len(cwnd_series)
            }

        # 正常状态（CWND平稳或增长）
        return {
            'state': 'normal',
            'evidence': 'CWND正常波动',
            'duration': len(cwnd_series)
        }

    def _detect_zero_window(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        检测Zero Window事件

        Returns:
            [
                {
                    "timestamp": str,
                    "type": "rcv_zero" | "snd_zero",
                    "window": int,
                    "duration_ms": int
                }
            ]
        """
        events = []

        # 接收窗口为0的事件
        if 'rcv_space' in df.columns:
            zero_rcv_df = df[df['rcv_space'] == 0]
            for timestamp, _ in zero_rcv_df.iterrows():
                events.append({
                    'timestamp': timestamp.isoformat(),
                    'type': 'rcv_zero',
                    'window': 0,
                    'description': '接收窗口为0（接收方无法接收数据）'
                })

        # 发送窗口为0的事件
        if 'snd_wnd' in df.columns:
            zero_snd_df = df[df['snd_wnd'] == 0]
            for timestamp, _ in zero_snd_df.iterrows():
                events.append({
                    'timestamp': timestamp.isoformat(),
                    'type': 'snd_zero',
                    'window': 0,
                    'description': '发送窗口为0（发送方被阻塞）'
                })

        return events

    def _calculate_window_efficiency(self, cwnd_results: Dict, rwnd_results: Dict) -> Dict[str, float]:
        """
        计算窗口效率

        Returns:
            {
                "cwnd_efficiency": float,      # CWND效率（0-1）
                "rwnd_efficiency": float,      # RWND效率（0-1）
                "overall_efficiency": float    # 综合效率
            }
        """
        # CWND效率：接近BDP为最佳（1.0）
        if 'cwnd_relative_bdp' in cwnd_results:
            cwnd_ratio = cwnd_results['cwnd_relative_bdp']
            # 理想范围：0.8-1.2
            if 0.8 <= cwnd_ratio <= 1.2:
                cwnd_efficiency = 1.0
            else:
                cwnd_efficiency = 1.0 - min(abs(cwnd_ratio - 1.0), 1.0)
        else:
            cwnd_efficiency = 0.0

        # RWND效率：远大于BDP为低效
        if 'rwnd_relative_bdp' in rwnd_results:
            rwnd_ratio = rwnd_results['rwnd_relative_bdp']
            # RWND应该 >= BDP，但不应过大
            if rwnd_ratio >= 1.0:
                rwnd_efficiency = min(1.0, 2.0 / rwnd_ratio)  # >2.0时效率下降
            else:
                rwnd_efficiency = rwnd_ratio  # 小于BDP时效率降低
        else:
            rwnd_efficiency = 0.0

        # 综合效率
        overall_efficiency = (cwnd_efficiency + rwnd_efficiency) / 2

        return {
            'cwnd_efficiency': float(cwnd_efficiency),
            'rwnd_efficiency': float(rwnd_efficiency),
            'overall_efficiency': float(overall_efficiency)
        }

    def generate_summary_text(self, analysis_results: Dict[str, Any]) -> str:
        """生成窗口分析摘要文本"""
        if 'error' in analysis_results:
            return "窗口分析: 无数据"

        cwnd = analysis_results.get('cwnd', {})
        rwnd = analysis_results.get('rwnd', {})

        if 'error' in cwnd and 'error' in rwnd:
            return "窗口分析: 无CWND/RWND数据"

        text = "窗口分析:"

        # CWND信息
        if 'error' not in cwnd:
            text += f"\n  - CWND范围: {cwnd.get('cwnd_min', 0)}-{cwnd.get('cwnd_max', 0)}"
            if 'cwnd_relative_bdp' in cwnd:
                text += f"\n  - CWND/BDP: {cwnd['cwnd_relative_bdp']:.2f}"

        # RWND信息
        if 'error' not in rwnd:
            text += f"\n  - RWND范围: {rwnd.get('rwnd_min', 0)}-"
            if 'rwnd_avg' in rwnd:
                text += f"{rwnd['rwnd_avg']:.0f}"

        # 拥塞状态
        congestion_state = analysis_results.get('congestion_state', {})
        if 'state' in congestion_state:
            text += f"\n  - 拥塞状态: {congestion_state['state']}"

        # Zero Window事件
        zero_win_events = analysis_results.get('zero_window_events', [])
        if zero_win_events:
            text += f"\n  - Zero Window: {len(zero_win_events)}次"

        return text
