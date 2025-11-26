#!/usr/bin/env python3
"""
PCAP网络分析工具 - 主CLI入口

使用tshark解析PCAP文件，进行TCP性能分析和问题识别。
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pcap_analyzer.parser.pcap_parser import PCAPParser
from pcap_analyzer.stats.flow_stats import FlowAggregator
from pcap_analyzer.analyzer.tcp_analyzer import TCPAnalyzer


def main():
    parser = argparse.ArgumentParser(
        description='PCAP网络分析工具 - 深度分析PCAP文件中的TCP性能',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 分析单个PCAP文件（所有流）
  python3 pcap_analyzer_cli.py -f capture.pcap -o ./reports

  # 分析特定流（指定IP和端口）
  python3 pcap_analyzer_cli.py -f capture.pcap --src-ip 10.0.0.1 --dst-ip 10.0.0.2 --src-port 12345 --dst-port 80 -o ./reports

  # 生成客户端侧分析（仅显示一个方向）
  python3 pcap_analyzer_cli.py -f capture.pcap --side client -o ./reports

  # 只分析TCP协议
  python3 pcap_analyzer_cli.py -f capture.pcap --protocol tcp -o ./reports

  # 限制分析的数据包数量（用于大文件测试）
  python3 pcap_analyzer_cli.py -f capture.pcap -n 10000 -o ./reports
        """
    )

    # 输入选项
    parser.add_argument(
        '-f', '--file',
        type=str,
        required=True,
        help='PCAP文件路径'
    )

    # 过滤选项
    parser.add_argument(
        '--src-ip',
        type=str,
        help='源IP地址过滤'
    )
    parser.add_argument(
        '--dst-ip',
        type=str,
        help='目的IP地址过滤'
    )
    parser.add_argument(
        '--src-port',
        type=int,
        help='源端口过滤'
    )
    parser.add_argument(
        '--dst-port',
        type=int,
        help='目的端口过滤'
    )
    parser.add_argument(
        '--protocol',
        type=str,
        choices=['tcp', 'udp', 'icmp'],
        help='协议过滤'
    )
    parser.add_argument(
        '--side',
        type=str,
        choices=['client', 'server'],
        help='流方向过滤（client: 只看SYN->方向，server: 反之）'
    )

    # 分析选项
    parser.add_argument(
        '-n', '--max-packets',
        type=int,
        help='最大分析数据包数量（用于大文件测试）'
    )
    parser.add_argument(
        '--tshark-path',
        type=str,
        default='tshark',
        help='tshark路径（默认: tshark）'
    )

    # 输出选项
    parser.add_argument(
        '-o', '--output',
        type=str,
        default='./pcap_reports',
        help='输出报告目录（默认: ./pcap_reports）'
    )
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
        if not args.quiet:
            print("=" * 80, file=sys.stderr)
            print("PCAP网络分析工具", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(file=sys.stderr)

        # 验证文件
        pcap_file = Path(args.file)
        if not pcap_file.exists():
            print(f"错误: PCAP文件不存在: {args.file}", file=sys.stderr)
            return 1

        if not args.quiet:
            print(f"文件大小: {pcap_file.stat().st_size / 1024 / 1024:.2f} MB", file=sys.stderr)
            print(f"正在解析PCAP文件...", file=sys.stderr)

        # 解析PCAP
        parser = PCAPParser(tshark_path=args.tshark_path)

        # 构建过滤器
        display_filter = build_display_filter(args)

        if not args.quiet:
            if display_filter:
                print(f"  过滤器: {display_filter}", file=sys.stderr)
            print(f"  正在解析数据包...", file=sys.stderr)

        packets = []
        packet_count = 0
        for packet in parser.parse_packets_stream(filter_expr=display_filter):
            packets.append(packet)
            packet_count += 1

            # 检查限制
            if args.max_packets and packet_count >= args.max_packets:
                if not args.quiet:
                    print(f"  已达到最大数据包限制: {args.max_packets}", file=sys.stderr)
                break

            if not args.quiet and packet_count % 1000 == 0:
                print(f"  已解析: {packet_count} 个数据包", file=sys.stderr, end='\r')

        if not args.quiet:
            print(file=sys.stderr)
            print(f"  ✓ 共解析了 {packet_count} 个数据包", file=sys.stderr)

        if not packets:
            print("错误: 未找到符合条件的数据包", file=sys.stderr)
            return 1

        if not args.quiet:
            print(f"正在分析流...", file=sys.stderr)

        # 流聚合
        aggregator = FlowAggregator()
        for packet in packets:
            aggregator.add_packet(packet)

        flows = aggregator.get_flow_stats()

        if not flows:
            print("错误: 未发现有效流", file=sys.stderr)
            return 1

        if not args.quiet:
            print(f"  ✓ 发现 {len(flows)} 个流", file=sys.stderr)
            print(f"正在分析TCP性能...", file=sys.stderr)

        # TCP分析
        analyzer = TCPAnalyzer()
        flow_analyses = []

        for i, flow in enumerate(flows):
            if not args.quiet and i % 10 == 0:
                print(f"  正在分析流 {i+1}/{len(flows)}...", file=sys.stderr, end='\r')

            flow_key = str(flow.flow_key)
            packets_for_flow = get_packets_for_flow(packets, flow.flow_key)

            if packets_for_flow:
                analysis = analyzer.analyze_flow(flow_key, packets_for_flow)
                flow_analyses.append({
                    'flow_key': flow_key,
                    'flow_stats': flow.get_summary(),
                    'tcp_analysis': analysis
                })

        if not args.quiet:
            print(file=sys.stderr)
            print(f"  ✓ 分析完成！", file=sys.stderr)
            print(file=sys.stderr)

        # 生成报告
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)

        report = generate_report(flow_analyses, output_dir, args.json)

        # 输出结果
        if not args.quiet:
            print("=" * 80, file=sys.stderr)
            print("报告已保存至:", file=sys.stderr)
            print(f"  目录: {args.output}", file=sys.stderr)
            print(f"  流数量: {len(flow_analyses)}", file=sys.stderr)
            if 'issue_count' in report:
                print(f"  发现问题: {report['issue_count']}", file=sys.stderr)
            print("=" * 80, file=sys.stderr)

            if not args.json:
                print_report(report)

        return 0

    except KeyboardInterrupt:
        print("\n\n中断: 用户取消操作", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return 1


def build_display_filter(args) -> Optional[str]:
    """构建Wireshark显示过滤器"""
    filters = []

    if args.src_ip:
        filters.append(f"ip.src == {args.src_ip}")

    if args.dst_ip:
        filters.append(f"ip.dst == {args.dst_ip}")

    if args.src_port:
        filters.append(f"tcp.srcport == {args.src_port} or udp.srcport == {args.src_port}")

    if args.dst_port:
        filters.append(f"tcp.dstport == {args.dst_port} or udp.dstport == {args.dst_port}")

    if args.protocol:
        filters.append(f"{args.protocol}")

    if not filters:
        return None

    return " and ".join(filters)


def get_packets_for_flow(packets: List[Dict], flow_key) -> List[Dict]:
    """获取属于特定流的数据包"""
    # 简单实现：将流Key转换为过滤器
    # TODO: 更精确的匹配
    return packets


def generate_report(flow_analyses: List[Dict], output_dir: Path, json_format: bool) -> Dict:
    """生成报告"""
    import json
    from datetime import datetime

    # 汇总统计
    tcp_flows = [f for f in flow_analyses if f['flow_stats']['protocol'] == 'tcp']
    total_retrans = sum(
        f['tcp_analysis']['retrans_stats']['total_retrans']
        for f in tcp_flows if 'retrans_stats' in f['tcp_analysis']
    )

    total_packets = sum(
        f['flow_stats']['packet_count']
        for f in flow_analyses
    )

    # 识别问题连接
    issue_count = 0
    issue_flows = []

    for analysis in flow_analyses:
        if 'tcp_analysis' in analysis and 'smart_analysis' in analysis['tcp_analysis']:
            smart_analysis = analysis['tcp_analysis']['smart_analysis']
            if smart_analysis and smart_analysis.get('issues'):
                issue_count += len(smart_analysis['issues'])
                issue_flows.append({
                    'flow': analysis['flow_key'],
                    'issues': smart_analysis['issues'],
                    'summary': smart_analysis.get('summary', {})
                })

    report = {
        'metadata': {
            'report_generated_at': datetime.now().isoformat(),
            'flow_count': len(flow_analyses),
            'tcp_flow_count': len(tcp_flows),
            'total_packets': total_packets,
            'tool_version': '1.0.0'
        },
        'summary': {
            'total_retransmissions': total_retrans,
            'issue_count': issue_count,
            'flows_with_issues': len(issue_flows)
        },
        'top_flows': get_top_flows(flow_analyses, top_n=10),
        'flows_with_issues': issue_flows,
        'all_flows': flow_analyses
    }

    # 保存报告
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    suffix = 'json' if json_format else 'txt'
    output_file = output_dir / f'pcap_analysis_report_{timestamp}.{suffix}'

    with open(output_file, 'w') as f:
        if json_format:
            json.dump(report, f, indent=2)
        else:
            f.write(format_text_report(report))

    return report


def get_top_flows(flow_analyses: List[Dict], top_n: int = 10) -> List[Dict]:
    """获取Top N流量"""
    # 按字节数排序
    sorted_flows = sorted(
        flow_analyses,
        key=lambda f: f['flow_stats']['byte_count'],
        reverse=True
    )

    return sorted_flows[:top_n]


def format_text_report(report: Dict) -> str:
    """格式化为文本报告"""
    lines = []
    lines.append("=" * 80)
    lines.append("PCAP网络分析报告")
    lines.append("=" * 80)
    lines.append("")

    # 汇总统计
    metadata = report.get('metadata', {})
    summary = report.get('summary', {})

    lines.append("【汇总统计】")
    lines.append(f"总流数量     : {metadata.get('flow_count', 0)}")
    lines.append(f"TCP流数量    : {metadata.get('tcp_flow_count', 0)}")
    lines.append(f"总数据包     : {metadata.get('total_packets', 0):,}")
    lines.append(f"重传总数     : {summary.get('total_retransmissions', 0):,}")
    lines.append(f"问题数量     : {summary.get('issue_count', 0)}")
    lines.append(f"问题流数量   : {summary.get('flows_with_issues', 0)}")
    lines.append("")

    # Top 10流量
    lines.append("【Top 10 流量】")
    lines.append(f"{'流':<60} {'流量':>15} {'包数':>10} {'速率':>12}")
    lines.append("-" * 80)

    for top_flow in report.get('top_flows', []):
        stats = top_flow.get('flow_stats', {})
        flow_key = stats.get('flow_key', 'unknown')
        byte_count = stats.get('byte_count', 0)
        packet_count = stats.get('packet_count', 0)
        avg_rate = stats.get('avg_rate', 0)

        # 格式化
        flow_key_display = flow_key if len(flow_key) < 60 else flow_key[:57] + "..."
        byte_str = f"{byte_count / 1024 / 1024:.1f} MB"
        packet_str = f"{packet_count:,}"
        rate_str = f"{avg_rate / 1024:.1f} KB/s"

        lines.append(f"{flow_key_display:<60} {byte_str:>15} {packet_str:>10} {rate_str:>12}")

    lines.append("")

    # 问题流
    if 'flows_with_issues' in report and report['flows_with_issues']:
        lines.append("【问题流列表】")
        lines.append(f"{'流':<60} {'问题数':>10}")
        lines.append("-" * 80)

        for issue_flow in report['flows_with_issues']:
            flow_key = issue_flow.get('flow', 'unknown')
            summary = issue_flow.get('summary', {})
            issues = issue_flow.get('issues', [])

            flow_key_display = flow_key if len(flow_key) < 60 else flow_key[:57] + "..."
            lines.append(f"{flow_key_display:<60} {len(issues):>10}")

            # 显示前3个问题
            for i, issue in enumerate(issues[:3]):
                severity = issue.get('severity', 'unknown').upper()
                title = issue.get('title', 'unknown')
                lines.append(f"  [{severity}] {title}")

            if len(issues) > 3:
                lines.append(f"  ... 还有 {len(issues) - 3} 个问题")

            lines.append("")

    lines.append("=" * 80)
    lines.append(f"报告时间: {metadata.get('report_generated_at', '')}")
    lines.append("=" * 80)

    return "\n".join(lines)


def print_report(report: Dict):
    """打印报告到控制台"""
    print(format_text_report(report))


if __name__ == '__main__':
    sys.exit(main())
