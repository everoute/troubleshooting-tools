"""Buffer分析器 - 分析Buffer状态，识别压力点，计算健康度"""

from typing import Dict, List, Optional, Any
import pandas as pd
import numpy as np


class BufferAnalyzer:
    """Buffer分析器（基于Kernel调研结果）"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化

        Args:
            config: 配置
                - r_threshold: 接收Buffer阈值（0.8）
                - t_threshold: 发送Buffer阈值（0.8）
                - w_threshold: 写队列阈值（0.6）
        """
        self.config = config or {}
        self.r_threshold = self.config.get('r_threshold', 0.8)
        self.t_threshold = self.config.get('t_threshold', 0.8)
        self.w_threshold = self.config.get('w_threshold', 0.6)

    def analyze(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析Buffer

        Args:
            df: 时序数据

        Returns:
            分析结果
        """
        if df.empty:
            return {"error": "No data available"}

        # 接收Buffer分析
        rx_results = self._analyze_rx_buffer(df)

        # 发送Buffer分析
        tx_results = self._analyze_tx_buffer(df)

        # Write Queue分析
        w_results = self._analyze_write_queue(df)

        # 健康度评分
        health_score = self._calculate_health_score(rx_results, tx_results, w_results)

        # 压力事件检测
        pressure_events = self._detect_pressure_events(df)

        return {
            'rx_buffer': rx_results,
            'tx_buffer': tx_results,
            'write_queue': w_results,
            'health_score': health_score,
            'pressure_events': pressure_events,
            'recommendations': self._generate_recommendations(rx_results, tx_results, health_score)
        }

    def _analyze_rx_buffer(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析接收Buffer

        Returns:
            {
                "r_avg": float,              # r平均值
                "r_max": float,              # r最大值
                "rb_avg": float,             # rb平均值
                "utilization_avg": float,    # 平均使用率
                "utilization_max": float,    # 最大使用率
                "drops": int,                # 丢包计数（d>0）
                "high_pressure_time": float  # 高压时间（秒）
            }
        """
        if 'r' not in df.columns or df['r'].isna().all():
            return {"error": "No receive buffer data"}

        # 基本统计
        r_avg = df['r'].mean()
        r_max = df['r'].max()
        rb_avg = df['rb'].mean() if 'rb' in df and not df['rb'].isna().all() else 0

        # 计算使用率
        if 'rb' in df:
            rb_series = df['rb'].replace(0, 1)  # 避免除以0
            utilization = df['r'] / rb_series
            utilization_avg = utilization.mean()
            utilization_max = utilization.max()
        else:
            utilization_avg = 0
            utilization_max = 0

        # 丢包（d>0）
        drops = 0
        if 'd' in df:
            drops = (df['d'] > 0).sum()

        # 高压时间（r/rb > threshold）
        high_pressure_time = 0
        if 'rb' in df:
            high_pressure = utilization > self.r_threshold
            high_pressure_time = high_pressure.sum()

        return {
            'r_avg': float(r_avg),
            'r_max': float(r_max),
            'rb_avg': float(rb_avg),
            'utilization_avg': float(utilization_avg),
            'utilization_max': float(utilization_max),
            'drops': int(drops),
            'high_pressure_time': float(high_pressure_time)
        }

    def _analyze_tx_buffer(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析发送Buffer

        Returns:
            {
                "t_avg": float,              # t平均值
                "t_max": float,              # t最大值
                "tb_avg": float,             # tb平均值
                "utilization_avg": float,    # 平均使用率
                "utilization_max": float     # 最大使用率
            }
        """
        if 't' not in df.columns or df['t'].isna().all():
            return {"error": "No transmit buffer data"}

        t_avg = df['t'].mean()
        t_max = df['t'].max()
        tb_avg = df['tb'].mean() if 'tb' in df and not df['tb'].isna().all() else 0

        utilization = 0
        if 'tb' in df:
            tb_series = df['tb'].replace(0, 1)
            utilization = df['t'] / tb_series
            utilization_avg = utilization.mean()
            utilization_max = utilization.max()
        else:
            utilization_avg = 0
            utilization_max = 0

        return {
            't_avg': float(t_avg),
            't_max': float(t_max),
            'tb_avg': float(tb_avg),
            'utilization_avg': float(utilization_avg),
            'utilization_max': float(utilization_max)
        }

    def _analyze_write_queue(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析写队列w（基于调研：w = t - unacked）

        Returns:
            {
                "w_avg": float,               # w平均值
                "w_max": float,               # w最大值
                "w_rel_t_avg": float,         # w/t平均比例
                "w_rel_unacked_avg": float    # w/unacked平均比例
            }
        """
        if 'w' not in df.columns or df['w'].isna().all():
            return {"error": "No write queue data"}

        w_avg = df['w'].mean()
        w_max = df['w'].max()

        # w/t比例
        if 't' in df:
            t_series = df['t'].replace(0, 1)
            w_rel_t = df['w'] / t_series
            w_rel_t_avg = w_rel_t.mean()
        else:
            w_rel_t_avg = 0

        # w/unacked比例（验证w = t - unacked）
        if 'unacked' in df and 't' in df:
            w_vs_unacked = df['w'] / (df['unacked'] + 1)  # +1避免除以0
            w_rel_unacked_avg = w_vs_unacked.mean()
        else:
            w_rel_unacked_avg = None

        return {
            'w_avg': float(w_avg),
            'w_max': float(w_max),
            'w_rel_t_avg': float(w_rel_t_avg) if w_rel_t_avg else 0,
            'w_rel_unacked_avg': float(w_rel_unacked_avg) if w_rel_unacked_avg else None
        }

    def _calculate_health_score(self, rx_results: Dict, tx_results: Dict, w_results: Dict) -> Dict[str, Any]:
        """
        计算Buffer健康度评分（0-100）

        评分标准（基于调研报告）：
        - sk_drops > 0: -50分（直接扣50）
        - r/rb > 0.9: -20分
        - r/rb > 0.8: -10分
        - r/rb > 0.7: -5分
        - t/tb > 0.9: -15分
        - t/tb > 0.8: -7分
        - w/tb > 0.8: -10分

        返回:
            {
                "score": int,              # 0-100
                "grade": str,              # 等级：优秀/良好/一般/较差/严重
                "reasons": List[str]      # 扣分原因
            }
        """
        score = 100
        reasons = []

        # 丢包（最严重）
        if 'drops' in rx_results and rx_results['drops'] > 0:
            score -= 50
            reasons.append(f"检测到丢包: {rx_results['drops']}次（最高优先级）")

        # 接收Buffer压力
        if 'utilization_avg' in rx_results:
            util = rx_results['utilization_avg']
            if util > 0.9:
                score -= 20
                reasons.append(f"接收Buffer压力严重: {util:.1%}")
            elif util > 0.8:
                score -= 10
                reasons.append(f"接收Buffer压力较高: {util:.1%}")
            elif util > 0.7:
                score -= 5
                reasons.append(f"接收Buffer压力: {util:.1%}")

        # 发送Buffer压力
        if 'utilization_avg' in tx_results:
            util = tx_results['utilization_avg']
            if util > 0.9:
                score -= 15
                reasons.append(f"发送Buffer压力高: {util:.1%}")
            elif util > 0.8:
                score -= 7
                reasons.append(f"发送Buffer压力: {util:.1%}")

        # 写队列堆积
        if 'w_rel_t_avg' in w_results and w_results['w_rel_t_avg']:
            w_ratio = w_results['w_rel_t_avg']
            if w_ratio > 0.8:
                score -= 10
                reasons.append(f"写队列堆积严重: {w_ratio:.1%}")
            elif w_ratio > 0.6:
                score -= 5
                reasons.append(f"写队列堆积: {w_ratio:.1%}")

        # 确保分数在0-100范围内
        score = max(0, score)

        # 分级
        if score >= 90:
            grade = "优秀"
        elif score >= 70:
            grade = "良好"
        elif score >= 50:
            grade = "一般"
        elif score >= 30:
            grade = "较差"
        else:
            grade = "严重"

        return {
            'score': score,
            'grade': grade,
            'reasons': reasons
        }

    def _detect_pressure_events(self, df: pd.DataFrame) -> List[Dict]:
        """
        检测压力事件

        返回:
            [
                {
                    "timestamp": str,
                    "type": "sk_drops" | "rx_pressure" | "tx_pressure",
                    "severity": "high" | "medium",
                    "value": float
                }
            ]
        """
        events = []

        # 检测丢包事件（d>0） - 最高优先级
        if 'd' in df.columns:
            drops_df = df[df['d'] > 0]
            for timestamp, row in drops_df.iterrows():
                events.append({
                    'timestamp': timestamp.isoformat(),
                    'type': 'sk_drops',
                    'severity': 'high',
                    'value': int(row['d']),
                    'description': f"Socket层丢包（sk_drops={int(row['d'])})"
                })

        # 检测接收Buffer高压
        if all(col in df.columns for col in ['r', 'rb']):
            rb_safe = df['rb'].replace(0, 1)
            rx_pressure_df = df[df['r'] / rb_safe > self.r_threshold]
            for timestamp, row in rx_pressure_df.iterrows():
                util = row['r'] / rb_safe.loc[timestamp]
                events.append({
                    'timestamp': timestamp.isoformat(),
                    'type': 'rx_pressure',
                    'severity': 'medium',
                    'value': float(util),
                    'description': f"接收Buffer压力高（{util:.1%}）"
                })

        # 检测发送Buffer高压
        if all(col in df.columns for col in ['t', 'tb']):
            tb_safe = df['tb'].replace(0, 1)
            tx_pressure_df = df[df['t'] / tb_safe > self.t_threshold]
            for timestamp, row in tx_pressure_df.iterrows():
                util = row['t'] / tb_safe.loc[timestamp]
                events.append({
                    'timestamp': timestamp.isoformat(),
                    'type': 'tx_pressure',
                    'severity': 'medium',
                    'value': float(util),
                    'description': f"发送Buffer压力高（{util:.1%}）"
                })

        return events

    def _generate_recommendations(self, rx_results: Dict, tx_results: Dict, health: Dict) -> List[Dict]:
        """
        生成调优建议（基于调研报告的算法）

        Args:
            rx_results: 接收Buffer分析结果
            tx_results: 发送Buffer分析结果
            health: 健康度评分结果

        Returns:
            建议列表
        """
        recommendations = []

        # 检查丢包
        if rx_results.get('drops', 0) > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'receive_buffer',
                'issue': 'Socket层丢包',
                'evidence': f"sk_drops={rx_results['drops']}",
                'recommendation': '立即增大接收缓冲区',
                'commands': [
                    'sudo sysctl -w net.core.rmem_max=134217728',
                    'sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"'
                ]
            })

        # 接收Buffer压力
        if rx_results.get('utilization_avg', 0) > 0.9:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'receive_buffer',
                'issue': '接收Buffer压力严重',
                'evidence': f"利用率={rx_results['utilization_avg']:.1%}",
                'recommendation': '增大tcp_rmem上限，并检查应用读取性能',
                'metrics_to_check': ['Recv-Q', '应用CPU使用率', '系统调用延迟']
            })
        elif rx_results.get('utilization_avg', 0) > 0.8:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'receive_buffer',
                'issue': '接收Buffer压力较高',
                'recommendation': '建议增大tcp_rmem或优化应用读取'
            })

        # 发送Buffer压力
        if tx_results.get('utilization_avg', 0) > 0.9:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'send_buffer',
                'issue': '发送Buffer压力高',
                'recommendation': '增大tcp_wmem上限',
                'commands': [
                    'sudo sysctl -w net.ipv4.tcp_wmem="4096 16384 4194304"',
                    'sudo sysctl -w net.core.wmem_max=212992'
                ]
            })

        return recommendations
