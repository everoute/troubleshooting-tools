#!/usr/bin/env python3
"""
TCPSocket网络分析工具 - 主CLI入口

对ss命令输出进行深度分析，识别性能问题、网络瓶颈和调优机会。
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tcpsocket_analyzer.parser.ss_parser import SSOutputParser, ConnectionTracker
from tcpsocket_analyzer.report.report_generator import MasterReportGenerator


def main():
    parser = argparse.ArgumentParser(
        description='TCPSocket网络分析工具 - 深度分析TCP连接性能',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 分析单个ss输出文件
  python3 tcp_analyzer_cli.py -f ss_output.txt -o ./reports

  # 分析目录中的所有采集文件
  python3 tcp_analyzer_cli.py -d ./ss_samples/ -o ./reports

  # 分析指定连接
  python3 tcp_analyzer_cli.py -f ss_output.txt --conn-port 8080 -o ./reports

  # 生成JSON格式报告
  python3 tcp_analyzer_cli.py -f ss_output.txt -o ./reports -j
        """
    )

    # 输入选项（互斥）
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '-f', '--file',
        type=str,
        help='SS输出文件路径'
    )
    input_group.add_argument(
        '-d', '--directory',
        type=str,
        help='包含SS输出文件的目录路径'
    )

    # 输出选项
    parser.add_argument(
        '-o', '--output',
        type=str,
        default='./tcpsocket_reports',
        help='输出报告目录（默认: ./tcpsocket_reports）'
    )

    # 过滤选项
    parser.add_argument(
        '--local-ip',
        type=str,
        help='过滤本地IP地址'
    )
    parser.add_argument(
        '--peer-ip',
        type=str,
        help='过滤对端IP地址'
    )
    parser.add_argument(
        '--local-port',
        type=int,
        help='过滤本地端口'
    )
    parser.add_argument(
        '--peer-port',
        type=int,
        help='过滤对端端口'
    )
    parser.add_argument(
        '--conn-port',
        type=int,
        help='特定端口（自动匹配本地或对端）'
    )

    # 格式选项
    parser.add_argument(
        '-j', '--json',
        action='store_true',
        help='输出JSON格式报告（默认为文本格式）'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='静默模式，只输出关键信息'
    )

    args = parser.parse_args()

    try:
        # 解析SS输出
        parser = SSOutputParser()

        if not args.quiet:
            print("=" * 80, file=sys.stderr)
            print("TCPSocket网络分析工具", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(file=sys.stderr)
            print(f"正在解析采集数据...", file=sys.stderr)

        if args.file:
            samples = parser.parse_file(args.file)
        else:
            results = parser.parse_directory(args.directory)
            samples = [s for sublist in results for s in sublist]  # 展平列表

        if not samples:
            print("错误: 未找到有效的SS样本数据", file=sys.stderr)
            sys.exit(1)

        if not args.quiet:
            print(f"  ✓ 解析了 {len(samples)} 个样本", file=sys.stderr)
            print(f"正在跟踪连接...", file=sys.stderr)

        # 跟踪连接
        tracker = ConnectionTracker()
        tracker.add_samples(samples)
        connections = tracker.get_connections()

        if not args.quiet:
            print(f"  ✓ 发现 {len(connections)} 个连接", file=sys.stderr)
            print(f"正在应用过滤器...", file=sys.stderr)

        # 应用过滤器
        filtered_connections = apply_filters(
            connections,
            local_ip=args.local_ip,
            peer_ip=args.peer_ip,
            local_port=args.local_port,
            peer_port=args.peer_port,
            conn_port=args.conn_port
        )

        if not args.quiet:
            print(f"  ✓ 过滤后: {len(filtered_connections)} 个连接", file=sys.stderr)
            print(f"正在分析连接...", file=sys.stderr)

        # 生成报告
        generator = MasterReportGenerator(
            connections_data=filtered_connections,
            output_dir=args.output
        )

        report = generator.generate_all_reports(
            format_type='json' if args.json else 'text'
        )

        if not args.quiet:
            print(f"  ✓ 分析完成！", file=sys.stderr)
            print(file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print("报告已保存至:", file=sys.stderr)
            print(f"  目录: {args.output}", file=sys.stderr)
            print(f"  连接数: {len(filtered_connections)}", file=sys.stderr)
            print(f"  问题连接: {report['summary_statistics']['problem_connections']}", file=sys.stderr)
            print(f"  平均健康度: {report['summary_statistics']['avg_health_score']:.1f}/100", file=sys.stderr)
            print("=" * 80, file=sys.stderr)

        # 控制台输出
        if not args.quiet:
            if not args.json:
                # 输出文本摘要到stdout
                print(report['_formatted_text'] if '_formatted_text' in report
                      else print_text_summary(report))
        else:
            # 安静模式：只输出简要统计
            print(f"Connections: {len(filtered_connections)}, "
                  f"Health: {report['summary_statistics']['avg_health_score']:.1f}, "
                  f"Problems: {report['summary_statistics']['problem_connections']}")

        return 0

    except KeyboardInterrupt:
        print("\n\n中断: 用户取消操作", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return 1


def apply_filters(connections: List[Dict[str, Any]],
                  local_ip: Optional[str] = None,
                  peer_ip: Optional[str] = None,
                  local_port: Optional[int] = None,
                  peer_port: Optional[int] = None,
                  conn_port: Optional[int] = None) -> List[Dict[str, Any]]:
    """应用过滤器到连接列表"""
    filtered = connections

    if local_ip:
        filtered = [c for c in filtered if c.get('local_ip') == local_ip]

    if peer_ip:
        filtered = [c for c in filtered if c.get('peer_ip') == peer_ip]

    if local_port:
        filtered = [c for c in filtered if c.get('local_port') == local_port]

    if peer_port:
        filtered = [c for c in filtered if c.get('peer_port') == peer_port]

    if conn_port:
        filtered = [
            c for c in filtered
            if c.get('local_port') == conn_port or c.get('peer_port') == conn_port
        ]

    return filtered


def print_text_summary(report: Dict[str, Any]) -> str:
    """打印文本摘要"""
    lines = []
    lines.append("=" * 80)
    lines.append("TCP连接分析报告")
    lines.append("=" * 80)
    lines.append("")

    # 汇总统计
    summary = report.get('summary_statistics', {})
    lines.append("【汇总统计】")
    lines.append(f"总连接数     : {summary.get('connections_by_health', {}).get('excellent', 0) + summary.get('connections_by_health', {}).get('good', 0) + summary.get('connections_by_health', {}).get('fair', 0) + summary.get('connections_by_health', {}).get('poor', 0)}")
    lines.append(f"优秀连接     : {summary.get('connections_by_health', {}).get('excellent', 0)}")
    lines.append(f"良好连接     : {summary.get('connections_by_health', {}).get('good', 0)}")
    lines.append(f"一般连接     : {summary.get('connections_by_health', {}).get('fair', 0)}")
    lines.append(f"问题连接     : {summary.get('connections_by_health', {}).get('poor', 0)}")
    lines.append(f"平均健康度   : {summary.get('avg_health_score', 0):.1f}/100")
    lines.append(f"总吞吐量     : {summary.get('total_throughput_mbps', 0):.1f} Mbps")
    lines.append(f"平均RTT      : {summary.get('avg_rtt_ms', 0):.1f} ms")
    lines.append(f"需关注连接   : {summary.get('problem_connections', 0)}")
    lines.append("")

    # 连接详情
    for conn in report.get('connections', []):
        metadata = conn.get('metadata', {})
        summary = conn.get('summary', {})
        analysis = conn.get('analysis', {})

        health_score = summary.get('health_score', 0)
        health_grade = summary.get('health_grade', 'unknown')

        # 健康度颜色编码
        if health_score >= 70:
            grade_indicator = "✓"  # Good
        elif health_score >= 50:
            grade_indicator = "⚠"  # Fair
        else:
            grade_indicator = "✗"  # Poor

        lines.append("-" * 80)
        lines.append(f"连接: {metadata.get('local_address', 'unknown')} → {metadata.get('peer_address', 'unknown')}")
        lines.append(f"健康度: {grade_indicator} {health_score}/100 ({health_grade})")
        lines.append(f"状态: {metadata.get('state', 'unknown')}")
        lines.append(f"样本数: {metadata.get('sample_count', 0)}")

        # RTT摘要
        rtt_summary = summary.get('rtt_summary', {})
        lines.append(f"RTT平均: {rtt_summary.get('rtt_avg', 0):.2f} ms "
                    f"(趋势: {rtt_summary.get('rtt_trend', 'unknown')})")
        if rtt_summary.get('outlier_count', 0) > 0:
            lines.append(f"RTT异常点: {rtt_summary['outlier_count']}个")

        # 瓶颈
        bottleneck_location = summary.get('bottleneck_location', 'unknown')
        lines.append(f"瓶颈位置: {bottleneck_location}")

        # Buffer健康度详细信息
        buffer_analysis = analysis.get('buffer', {})
        health_score_detail = buffer_analysis.get('health_score', {})
        if health_score_detail.get('reasons', []):
            lines.append("问题:")
            for reason in health_score_detail.get('reasons', [])[:2]:
                lines.append(f"  • {reason}")

        # 性能指标
        perf_metrics = conn.get('comprehensive_analysis', {}).get('performance_metrics', {})
        lines.append(f"性能: {perf_metrics.get('text_summary', '')}")

        lines.append("")

    # 问题连接列表
    problem_conns = [
        (conn, conn.get('comprehensive_analysis', {}).get('problem_detection', {}))
        for conn in report.get('connections', [])
        if conn.get('comprehensive_analysis', {}).get('problem_detection', {}).get('problem_count', 0) > 0
    ]

    if problem_conns:
        lines.append("=" * 80)
        lines.append("需关注的连接")
        lines.append("=" * 80)
        lines.append("")

        for conn, problem_detect in problem_conns:
            metadata = conn.get('metadata', {})
            problems = problem_detect.get('problems', [])

            lines.append(f"连接: {metadata.get('local_address')} → {metadata.get('peer_address')}")
            for problem in problems:
                severity = problem.get('severity', '').upper()
                lines.append(f"  [{severity}] {problem.get('title')}")
                lines.append(f"    问题: {problem.get('description')}")
                lines.append(f"    建议: {problem.get('suggestion')}")
                lines.append("")

    lines.append("=" * 80)
    lines.append(f"报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 80)

    return "\n".join(lines)


if __name__ == '__main__':
    sys.exit(main())
