"""TCPSocket分析报告生成器 - 生成综合分析报告"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import pandas as pd

from ..analyzer.buffer_analyzer import BufferAnalyzer
from ..analyzer.rtt_analyzer import RTTAnalyzer
from ..analyzer.window_analyzer import WindowAnalyzer
from ..analyzer.rate_analyzer import RateAnalyzer


class ConnectionReport:
    """单个连接的详细分析报告"""

    def __init__(self, connection_data: Dict[str, Any], samples_df: pd.DataFrame):
        self.conn_id = connection_data.get('conn_id', 'unknown')
        self.local_addr = f"{connection_data.get('local_ip', 'unknown')}:{connection_data.get('local_port', 0)}"
        self.peer_addr = f"{connection_data.get('peer_ip', 'unknown')}:{connection_data.get('peer_port', 0)}"
        self.state = connection_data.get('state', 'unknown')
        self.start_time = connection_data.get('start_time')
        self.end_time = connection_data.get('end_time')
        self.sample_count = connection_data.get('sample_count', 0)
        self.samples_df = samples_df

        # 所有分析器
        self.buffer_analyzer = BufferAnalyzer()
        self.rtt_analyzer = RTTAnalyzer()
        self.window_analyzer = WindowAnalyzer()
        self.rate_analyzer = RateAnalyzer()

        # 分析结果
        self.analysis_results = {}

    def generate(self) -> Dict[str, Any]:
        """生成完整的连接分析报告"""
        # 执行各项分析
        self.analysis_results['buffer'] = self.buffer_analyzer.analyze(self.samples_df)
        self.analysis_results['rtt'] = self.rtt_analyzer.analyze(self.samples_df)
        self.analysis_results['window'] = self.window_analyzer.analyze(self.samples_df)
        self.analysis_results['rate'] = self.rate_analyzer.analyze(self.samples_df)

        # 综合分析
        comprehensive_analysis = self._generate_comprehensive_analysis()

        return {
            'metadata': self._generate_metadata(),
            'summary': self._generate_summary(),
            'analysis': self.analysis_results,
            'comprehensive_analysis': comprehensive_analysis,
            'recommendations': self._generate_recommendations(),
            'format': 'detailed'
        }

    def _generate_metadata(self) -> Dict[str, Any]:
        """生成元数据"""
        return {
            'connection_id': self.conn_id,
            'local_address': self.local_addr,
            'peer_address': self.peer_addr,
            'state': self.state,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': (
                (self.end_time - self.start_time).total_seconds()
                if self.start_time and self.end_time else 0
            ),
            'sample_count': self.sample_count,
            'report_generated_at': datetime.now().isoformat()
        }

    def _generate_summary(self) -> Dict[str, Any]:
        """生成摘要信息"""
        # 从Buffer分析获取健康度
        buffer_health = self.analysis_results.get('buffer', {}).get('health_score', {})

        # 从RTT分析获取RTT摘要
        rtt_summary = self.analysis_results.get('rtt', {})

        # 从Window分析获取拥塞状态
        window_summary = self.analysis_results.get('window', {})
        congestion_state = window_summary.get('congestion_state', {})

        # 从Rate分析获取吞吐量和瓶颈
        rate_summary = self.analysis_results.get('rate', {})
        bottleneck = rate_summary.get('bottleneck', {})
        throughput = rate_summary.get('throughput', {})

        return {
            'health_score': buffer_health.get('score', 0),
            'health_grade': buffer_health.get('grade', 'unknown'),
            'congestion_state': congestion_state.get('state', 'unknown'),
            'bottleneck_location': bottleneck.get('bottleneck_location', 'unknown'),
            'avg_throughput_mbps': throughput.get('avg_throughput_mbps', 0),
            'rtt_summary': {
                'rtt_avg': rtt_summary.get('basic_stats', {}).get('mean', 0),
                'rtt_trend': rtt_summary.get('trend', {}).get('direction', 'unknown'),
                'outlier_count': len(rtt_summary.get('outliers', []))
            },
            'text_summary': self._generate_text_summary()
        }

    def _generate_text_summary(self) -> str:
        """生成文本摘要"""
        buffer_text = self.buffer_analyzer.generate_summary_text(
            self.analysis_results.get('buffer', {})
        )
        rtt_text = self.rtt_analyzer.generate_summary_text(
            self.analysis_results.get('rtt', {})
        )
        window_text = self.window_analyzer.generate_summary_text(
            self.analysis_results.get('window', {})
        )
        rate_text = self.rate_analyzer.generate_summary_text(
            self.analysis_results.get('rate', {})
        )

        return f"{buffer_text}\n{rtt_text}\n{window_text}\n{rate_text}"

    def _generate_comprehensive_analysis(self) -> Dict[str, Any]:
        """生成综合分析结果"""
        buffer_analysis = self.analysis_results.get('buffer', {})
        rtt_analysis = self.analysis_results.get('rtt', {})
        window_analysis = self.analysis_results.get('window', {})
        rate_analysis = self.analysis_results.get('rate', {})

        return {
            'problem_detection': self._detect_problems(),
            'performance_metrics': self._calculate_performance_metrics(),
            'bottleneck_analysis': self._analyze_bottlenecks(),
            'stability_assessment': self._assess_stability()
        }

    def _detect_problems(self) -> Dict[str, Any]:
        """检测问题"""
        problems = []
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}

        # Buffer相关问题
        health_score = self.analysis_results.get('buffer', {}).get('health_score', {})
        if health_score.get('score', 100) < 50:
            problems.append({
                'category': 'buffer',
                'severity': 'high',
                'title': 'Buffer健康度较差',
                'description': f"健康度评分: {health_score.get('score')}/100",
                'suggestion': '检查Buffer压力并考虑增大tcp_rmem/tcp_wmem'
            })
            severity_counts['high'] += 1

        # RTT相关问题
        rtt_outliers = self.analysis_results.get('rtt', {}).get('outliers', [])
        if rtt_outliers:
            problems.append({
                'category': 'rtt',
                'severity': 'medium',
                'title': f'RTT异常点 ({len(rtt_outliers)}个)',
                'description': '检测到RTT异常波动',
                'suggestion': '检查网络稳定性，排查丢包和重传'
            })
            severity_counts['medium'] += 1

        # 拥塞问题
        congestion_state = self.analysis_results.get('window', {}).get('congestion_state', {})
        if congestion_state.get('state') == 'recovery':
            problems.append({
                'category': 'congestion',
                'severity': 'high',
                'title': 'TCP拥塞恢复',
                'description': congestion_state.get('evidence', 'CWND下降'),
                'suggestion': '网络可能经历拥塞，建议检查链路质量'
            })
            severity_counts['high'] += 1

        return {
            'problem_count': len(problems),
            'severity_breakdown': severity_counts,
            'problems': problems
        }

    def _calculate_performance_metrics(self) -> Dict[str, Any]:
        """计算性能指标"""
        rate_analysis = self.analysis_results.get('rate', {})
        rtt_analysis = self.analysis_results.get('rtt', {})
        throughput = rate_analysis.get('throughput', {})
        window_analysis = self.analysis_results.get('window', {})

        # 平均吞吐量
        avg_throughput = throughput.get('avg_throughput_mbps', 0)

        # 平均RTT
        avg_rtt = rtt_analysis.get('basic_stats', {}).get('mean', 0)

        # 窗口效率
        window_efficiency = window_analysis.get('window_efficiency', {})

        return {
            'throughput': {
                'avg_mbps': avg_throughput,
                'max_mbps': throughput.get('max_throughput_mbps', 0)
            },
            'latency': {
                'rtt_avg': avg_rtt,
                'rtt_p95': rtt_analysis.get('percentiles', {}).get('p95', 0)
            },
            'efficiency': window_efficiency.get('overall_efficiency', 0),
            'text_summary': f"Throughput: {avg_throughput:.1f} Mbps | "
                          f"RTT Avg: {avg_rtt:.1f} ms | "
                          f"Efficiency: {window_efficiency.get('overall_efficiency', 0):.1%}"
        }

    def _analyze_bottlenecks(self) -> Dict[str, Any]:
        """分析瓶颈"""
        rate_analysis = self.analysis_results.get('rate', {})
        buffer_analysis = self.analysis_results.get('buffer', {})
        window_analysis = self.analysis_results.get('window', {})

        # 速率瓶颈
        rate_bottleneck = rate_analysis.get('bottleneck', {})

        # Buffer瓶颈
        buffer_health = buffer_analysis.get('health_score', {})

        # Window瓶颈
        zero_window_events = window_analysis.get('zero_window_events', [])

        return {
            'primary_bottleneck': rate_bottleneck.get('bottleneck_location', 'unknown'),
            'bottleneck_confidence': rate_bottleneck.get('confidence', 0),
            'bottleneck_details': {
                'rate': rate_bottleneck,
                'buffer': {
                    'health_score': buffer_health.get('score'),
                    'health_grade': buffer_health.get('grade')
                },
                'window': {
                    'zero_window_count': len(zero_window_events),
                    'congestion_state': window_analysis.get('congestion_state', {})
                }
            }
        }

    def _assess_stability(self) -> Dict[str, Any]:
        """评估稳定性"""
        rtt_analysis = self.analysis_results.get('rtt', {})
        rate_analysis = self.analysis_results.get('rate', {})

        # RTT稳定性
        rtt_stability = rtt_analysis.get('stability', {})
        rtt_cv = rtt_stability.get('cv', 0)

        # Rate稳定性
        delivery_analysis = rate_analysis.get('delivery_rate', {})
        rate_stability = delivery_analysis.get('rate_stability', 1)

        # 综合稳定性（越低越稳定）
        overall_stability = (rtt_cv + rate_stability) / 2

        # 稳定性评级
        if overall_stability < 0.1:
            stability_grade = 'excellent'
        elif overall_stability < 0.2:
            stability_grade = 'good'
        elif overall_stability < 0.4:
            stability_grade = 'fair'
        else:
            stability_grade = 'poor'

        return {
            'stability_score': 1 - min(overall_stability, 1),  # 转换为0-1的稳定性分数
            'stability_grade': stability_grade,
            'rtt_stability': 1 - min(rtt_cv, 1),
            'rate_stability': 1 - min(rate_stability, 1)
        }

    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """生成调优建议"""
        recommendations = []

        # Buffer相关建议
        buffer_analysis = self.analysis_results.get('buffer', {})
        buffer_health = buffer_analysis.get('health_score', {})
        if buffer_health.get('score', 100) < 70:
            reasons = buffer_health.get('reasons', [])
            recommendations.extend(self._generate_buffer_recommendations(reasons))

        # RTT相关建议
        rtt_analysis = self.analysis_results.get('rtt', {})
        rtt_outliers = rtt_analysis.get('outliers', [])
        if rtt_outliers:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'network',
                'title': 'RTT异常',
                'issue': f'检测到{len(rtt_outliers)}个RTT异常点',
                'recommendation': '检查网络路径、路由稳定性，考虑更换网络链路'
            })

        return recommendations

    def _generate_buffer_recommendations(self, reasons: List[str]) -> List[Dict[str, Any]]:
        """生成Buffer调优建议"""
        recommendations = []

        for reason in reasons:
            if '丢包' in reason or 'sk_drops' in reason:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'buffer',
                    'title': 'Socket层丢包',
                    'issue': reason,
                    'recommendation': '立即增大接收缓冲区',
                    'commands': [
                        'sudo sysctl -w net.core.rmem_max=134217728',
                        'sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"'
                    ]
                })
            elif '接收Buffer压力' in reason:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'buffer',
                    'title': '接收Buffer压力',
                    'issue': reason,
                    'recommendation': '增大tcp_rmem上限并检查应用读取性能',
                    'metrics_to_check': ['Recv-Q', '应用CPU使用率', '系统调用延迟']
                })
            elif '发送Buffer压力' in reason:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'buffer',
                    'title': '发送Buffer压力',
                    'issue': reason,
                    'recommendation': '增大tcp_wmem上限'
                })

        return recommendations


class MasterReportGenerator:
    """主报告生成器"""

    def __init__(self, connections_data: List[Dict[str, Any]], output_dir: Optional[str] = None):
        self.connections_data = connections_data
        self.output_dir = Path(output_dir) if output_dir else None
        self.reports = []

    def generate_all_reports(self, format_type: str = 'json') -> Dict[str, Any]:
        """生成所有连接的报告"""
        all_reports = []

        for conn_data in self.connections_data:
            # 构建DataFrame
            samples_df = self._build_samples_df(conn_data.get('samples', []))

            # 生成单连接报告
            conn_report = ConnectionReport(conn_data, samples_df)
            report = conn_report.generate()

            all_reports.append(report)

        self.reports = all_reports

        # 生成汇总统计
        summary_stats = self._generate_summary_stats()

        master_report = {
            'metadata': {
                'total_connections': len(all_reports),
                'report_generated_at': datetime.now().isoformat(),
                'tool_version': '1.0.0'
            },
            'summary_statistics': summary_stats,
            'connections': all_reports
        }

        # 保存报告
        if self.output_dir:
            self._save_report(master_report, format_type)

        return master_report

    def _build_samples_df(self, samples: List[Dict[str, Any]]) -> pd.DataFrame:
        """构建样本DataFrame"""
        if not samples:
            return pd.DataFrame()

        df = pd.DataFrame(samples)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df.set_index('timestamp', inplace=True)

        return df

    def _generate_summary_stats(self) -> Dict[str, Any]:
        """生成汇总统计"""
        if not self.reports:
            return {}

        health_scores = [
            r.get('summary', {}).get('health_score', 0)
            for r in self.reports
        ]

        avg_throughputs = [
            r.get('summary', {}).get('avg_throughput_mbps', 0)
            for r in self.reports
        ]

        rtt_avgs = [
            r.get('summary', {}).get('rtt_summary', {}).get('rtt_avg', 0)
            for r in self.reports
        ]

        return {
            'connections_by_health': {
                'excellent': sum(1 for s in health_scores if s >= 90),
                'good': sum(1 for s in health_scores if 70 <= s < 90),
                'fair': sum(1 for s in health_scores if 50 <= s < 70),
                'poor': sum(1 for s in health_scores if s < 50)
            },
            'total_throughput_mbps': sum(avg_throughputs),
            'avg_rtt_ms': sum(rtt_avgs) / len(rtt_avgs) if rtt_avgs else 0,
            'avg_health_score': sum(health_scores) / len(health_scores) if health_scores else 0,
            'problem_connections': sum(
                1 for r in self.reports
                if r.get('comprehensive_analysis', {})
                       .get('problem_detection', {})
                       .get('problem_count', 0) > 0
            )
        }

    def _save_report(self, report: Dict[str, Any], format_type: str = 'json'):
        """保存报告"""
        if not self.output_dir:
            return

        self.output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        if format_type == 'json':
            output_file = self.output_dir / f'connection_report_{timestamp}.json'
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        elif format_type == 'text':
            output_file = self.output_dir / f'connection_report_{timestamp}.txt'
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(self._format_as_text(report))

    def _format_as_text(self, report: Dict[str, Any]) -> str:
        """格式化为文本报告"""
        lines = []
        lines.append("=" * 80)
        lines.append("TCP连接分析报告")
        lines.append("=" * 80)
        lines.append("")

        # 汇总统计
        lines.append("【汇总统计】")
        summary = report.get('summary_statistics', {})
        lines.append(f"总连接数: {summary.get('connections_by_health', {}).get('excellent', 0) + summary.get('connections_by_health', {}).get('good', 0) + summary.get('connections_by_health', {}).get('fair', 0) + summary.get('connections_by_health', {}).get('poor', 0)}")
        lines.append(f"平均健康度: {summary.get('avg_health_score', 0):.1f}/100")
        lines.append(f"总吞吐量: {summary.get('total_throughput_mbps', 0):.1f} Mbps")
        lines.append(f"平均RTT: {summary.get('avg_rtt_ms', 0):.1f} ms")
        lines.append(f"问题连接数: {summary.get('problem_connections', 0)}")
        lines.append("")

        # 连接详情
        for conn in report.get('connections', []):
            metadata = conn.get('metadata', {})
            summary = conn.get('summary', {})
            lines.append("-" * 80)
            lines.append(f"连接: {metadata.get('local_address', '')} → {metadata.get('peer_address', '')}")
            lines.append(f"健康度: {summary.get('health_score')}/100 ({summary.get('health_grade')})")
            lines.append(summary.get('text_summary', ''))
            lines.append("")

        return "\n".join(lines)
