"""RTT分析器 - 时序分析、异常检测、趋势分析"""

from typing import Dict, List, Optional, Any
import pandas as pd
import numpy as np
from scipy import stats


class RTTAnalyzer:
    """RTT分析器"""

    def analyze(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析RTT

        Args:
            df: 时序数据DataFrame

        Returns:
            分析结果
        """
        if 'rtt' not in df.columns or df['rtt'].isna().all():
            return {"error": "No RTT data available"}

        rtt_series = df['rtt'].dropna()

        if rtt_series.empty:
            return {"error": "No valid RTT samples"}

        return {
            'basic_stats': self._calculate_basic_stats(rtt_series),
            'percentiles': self._calculate_percentiles(rtt_series),
            'trend': self._analyze_trend(rtt_series),
            'stability': self._analyze_stability(rtt_series),
            'outliers': self._detect_outliers(rtt_series, df)
        }

    def _calculate_basic_stats(self, series: pd.Series) -> Dict[str, float]:
        """计算基本统计"""
        return {
            'min': float(series.min()),
            'max': float(series.max()),
            'mean': float(series.mean()),
            'std': float(series.std()),
            'variance': float(series.var())
        }

    def _calculate_percentiles(self, series: pd.Series) -> Dict[str, float]:
        """计算分位数"""
        return {
            'p50': float(np.percentile(series, 50)),
            'p75': float(np.percentile(series, 75)),
            'p90': float(np.percentile(series, 90)),
            'p95': float(np.percentile(series, 95)),
            'p99': float(np.percentile(series, 99))
        }

    def _analyze_trend(self, series: pd.Series) -> Dict[str, Any]:
        """
        趋势分析（线性回归）

        Returns:
            {
                "direction": "increasing" | "decreasing" | "stable",
                "slope": float,
                "p_value": float,
                "r_squared": float
            }
        """
        # 创建时间索引（0到N-1）
        x = np.arange(len(series))
        y = series.values

        # 线性回归
        slope, intercept, r_value, p_value, std_err = stats.linregress(x, y)

        # 判断趋势方向
        if abs(slope) < 0.1:  # 斜率很小，视为稳定
            direction = 'stable'
        elif slope > 0:
            direction = 'increasing'  # RTT逐渐增大
        else:
            direction = 'decreasing'  # RTT逐渐减小

        return {
            'direction': direction,
            'slope': float(slope),
            'p_value': float(p_value),
            'r_squared': float(r_value ** 2),
            'std_err': float(std_err)
        }

    def _analyze_stability(self, series: pd.Series) -> Dict[str, float]:
        """
        稳定性分析

        Returns:
            {
                "jitter": float,     # 抖动（ms）
                "cv": float         # 变异系数
            }
        """
        # 抖动 = 相邻RTT差的绝对值的平均
        jitter = series.diff().abs().mean()

        # 变异系数 = std / mean
        mean = series.mean()
        cv = series.std() / mean if mean > 0 else 0

        return {
            'jitter': float(jitter),
            'cv': float(cv)
        }

    def _detect_outliers(self, series: pd.Series, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        异常点检测（使用IQR方法）

        Returns:
            异常点列表
        """
        Q1 = np.percentile(series, 25)
        Q3 = np.percentile(series, 75)
        IQR = Q3 - Q1

        lower_bound = Q1 - 1.5 * IQR
        upper_bound = Q3 + 1.5 * IQR

        outliers = []

        for timestamp, value in series.items():
            if value < lower_bound or value > upper_bound:
                # 找出原因
                cause = self._analyze_outlier_cause(df, timestamp)

                outliers.append({
                    'timestamp': timestamp.isoformat(),
                    'value': float(value),
                    'bound': 'upper' if value > upper_bound else 'lower',
                    'cause': cause
                })

        return outliers

    def _analyze_outlier_cause(self, df: pd.DataFrame, timestamp: pd.Timestamp) -> str:
        """分析异常点原因"""
        if timestamp not in df.index:
            return '未知'

        row = df.loc[timestamp]
        causes = []

        # 检查是否重传
        if 'retrans' in row and pd.notna(row['retrans']) and row['retrans'] > 0:
            causes.append('重传')

        # 检查是否丢包
        if 'd' in row and pd.notna(row['d']) and row['d'] > 0:
            causes.append('丢包')

        # 检查是否窗口受限
        if 'cwnd_limited_ms' in row and pd.notna(row['cwnd_limited_ms']) and row['cwnd_limited_ms'] > 0:
            causes.append('CWND受限')

        # 检查Buffer满
        if all(col in row for col in ['t', 'tb']) and pd.notna(row['t']) and pd.notna(row['tb']):
            if row['t'] > row['tb'] * 0.9:
                causes.append('发送缓冲区满')

        return ' + '.join(causes) if causes else '未知'

    def generate_summary_text(self, analysis_results: Dict[str, Any]) -> str:
        """生成RTT摘要文本"""
        if 'error' in analysis_results:
            return "RTT分析: 无数据"

        basic_stats = analysis_results.get('basic_stats', {})
        trend = analysis_results.get('trend', {})

        text = f"RTT分析:"
        text += f"\n  - 平均值: {basic_stats.get('mean', 0):.2f}ms"
        text += f"\n  - 范围: {basic_stats.get('min', 0):.2f}ms - {basic_stats.get('max', 0):.2f}ms"
        text += f"\n  - 标准差: {basic_stats.get('std', 0):.2f}ms"
        text += f"\n  - P95: {analysis_results.get('percentiles', {}).get('p95', 0):.2f}ms"
        text += f"\n  - 趋势: {trend.get('direction', 'unknown')}"

        outliers = analysis_results.get('outliers', [])
        if outliers:
            text += f"\n  - 异常点: {len(outliers)}个"

        return text
