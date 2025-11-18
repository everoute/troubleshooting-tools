#!/usr/bin/env python
"""
PCAP Analyzer CLI

Command-line interface for PCAP traffic analysis tool.
Supports three modes: summary, details, and analysis.
"""

import argparse
import sys
from datetime import datetime
from typing import Optional

from pcap_analyzer.parser import PcapParser
from pcap_analyzer.statistics import (
    StatisticsEngine,
    FlowAggregator,
    TimeSeriesAnalyzer,
    TopTalkersAnalyzer
)
from pcap_analyzer.analyzers import (
    TCPAnalyzer,
    ProblemDetector,
    DiagnosisEngine,
    ProblemClassifier
)
from pcap_analyzer.filters import FilterEngine
from pcap_analyzer.formatters import JSONFormatter, ProgressTracker
from common.utils import print_error, print_info, validate_file_path, format_bytes, format_rate


def run_summary_mode(args):
    """
    Execute summary mode analysis

    Provides L2/L3/L4 statistics, flow aggregation, and time-series analysis.

    Args:
        args: Command-line arguments
    """
    print_info(f"Running summary mode on {args.pcap}")

    # Initialize components
    parser = PcapParser()
    stats_engine = StatisticsEngine()
    flow_aggregator = FlowAggregator()
    timeseries_analyzer = TimeSeriesAnalyzer()
    top_talkers_analyzer = TopTalkersAnalyzer()
    filter_engine = FilterEngine()
    progress = ProgressTracker()

    try:
        # Get file info
        file_info = parser.get_file_info(args.pcap)
        print_info(f"Total packets: {file_info['packet_count']}")

        # Parse packets (with optional filtering)
        packets = parser.parse_file(args.pcap)

        # Apply filters if specified
        if args.src_ip or args.dst_ip:
            packets = filter_engine.apply_ip_filter(packets, args.src_ip, args.dst_ip)

        if args.src_port or args.dst_port:
            packets = filter_engine.apply_port_filter(packets, args.src_port, args.dst_port)

        if args.protocol:
            packets = filter_engine.apply_protocol_filter(packets, args.protocol)

        # Convert iterator to list for multiple passes
        packets_list = list(packets)
        print_info(f"Packets after filtering: {len(packets_list)}")

        # Compute statistics
        print_info("Computing L2 statistics...")
        l2_stats = stats_engine.compute_l2_stats(iter(packets_list))

        print_info("Computing L3 statistics...")
        l3_stats = stats_engine.compute_l3_stats(iter(packets_list))

        print_info("Computing L4 statistics...")
        l4_stats = stats_engine.compute_l4_stats(iter(packets_list))

        # Aggregate flows
        print_info("Aggregating flows...")
        flows = flow_aggregator.aggregate_flows(iter(packets_list))
        print_info(f"Total flows: {len(flows)}")

        # Time-series analysis
        print_info("Computing time-series statistics...")
        timeseries_stats = timeseries_analyzer.compute_rates(
            iter(packets_list),
            interval=args.interval
        )

        # Top talkers
        print_info("Identifying top talkers...")
        top_talkers = top_talkers_analyzer.identify_top_talkers(flows, n=args.top_n)

        # Build result
        result = {
            'file_info': file_info,
            'l2_stats': l2_stats,
            'l3_stats': l3_stats,
            'l4_stats': l4_stats,
            'flow_count': len(flows),
            'timeseries': timeseries_stats,
            'top_talkers': top_talkers
        }

        # Output
        if args.output:
            formatter = JSONFormatter()
            formatter.write_to_file(result, args.output)
            print_info(f"Results written to {args.output}")
        else:
            print_summary_results(result)

    except Exception as e:
        print_error(f"Analysis failed: {str(e)}")
        if args.debug:
            raise
        sys.exit(1)


def run_details_mode(args):
    """
    Execute details mode analysis

    Provides detailed TCP flow analysis including retransmissions, DupACK, etc.

    Args:
        args: Command-line arguments
    """
    print_info(f"Running details mode on {args.pcap}")

    # Initialize components
    parser = PcapParser()
    flow_aggregator = FlowAggregator()
    tcp_analyzer = TCPAnalyzer()
    filter_engine = FilterEngine()

    try:
        # Parse and filter packets
        packets = parser.parse_file(args.pcap)

        if args.src_ip or args.dst_ip or args.src_port or args.dst_port or args.protocol:
            packets = filter_engine.apply_combined_filter(
                packets,
                src_ip=args.src_ip,
                dst_ip=args.dst_ip,
                src_port=args.src_port,
                dst_port=args.dst_port,
                protocol=args.protocol
            )

        packets_list = list(packets)
        print_info(f"Analyzing {len(packets_list)} packets")

        # Aggregate flows
        flows = flow_aggregator.aggregate_flows(iter(packets_list))

        # Analyze each TCP flow
        detailed_results = []
        for five_tuple, flow in flows.items():
            if flow.five_tuple.protocol.upper() != 'TCP':
                continue

            # TCP deep analysis
            retrans_stats = tcp_analyzer.analyze_retransmissions(flow)
            dupack_stats = tcp_analyzer.analyze_dupack(flow)
            zero_window_stats = tcp_analyzer.analyze_zero_window(flow)
            sack_stats = tcp_analyzer.analyze_sack(flow)
            tcp_features = tcp_analyzer.analyze_features(flow)

            detailed_results.append({
                'five_tuple': five_tuple,
                'flow_stats': flow_aggregator.get_flow_statistics(flow),
                'retrans_stats': retrans_stats,
                'dupack_stats': dupack_stats,
                'zero_window_stats': zero_window_stats,
                'sack_stats': sack_stats,
                'tcp_features': tcp_features
            })

        result = {
            'total_flows': len(flows),
            'tcp_flows': len(detailed_results),
            'detailed_analysis': detailed_results
        }

        # Output
        if args.output:
            formatter = JSONFormatter()
            formatter.write_to_file(result, args.output)
            print_info(f"Results written to {args.output}")
        else:
            print_detailed_results(result)

    except Exception as e:
        print_error(f"Analysis failed: {str(e)}")
        if args.debug:
            raise
        sys.exit(1)


def run_analysis_mode(args):
    """
    Execute analysis mode with problem detection

    Identifies network problems and provides diagnosis/recommendations.

    Args:
        args: Command-line arguments
    """
    print_info(f"Running analysis mode on {args.pcap}")

    # Initialize components
    parser = PcapParser()
    flow_aggregator = FlowAggregator()
    tcp_analyzer = TCPAnalyzer()
    problem_detector = ProblemDetector()
    diagnosis_engine = DiagnosisEngine()
    problem_classifier = ProblemClassifier()
    filter_engine = FilterEngine()

    try:
        # Parse and filter packets
        packets = parser.parse_file(args.pcap)

        if args.src_ip or args.dst_ip or args.src_port or args.dst_port or args.protocol:
            packets = filter_engine.apply_combined_filter(
                packets,
                src_ip=args.src_ip,
                dst_ip=args.dst_ip,
                src_port=args.src_port,
                dst_port=args.dst_port,
                protocol=args.protocol
            )

        packets_list = list(packets)

        # Aggregate flows
        flows = flow_aggregator.aggregate_flows(iter(packets_list))

        # Analyze each TCP flow for problems
        all_problems = []
        flow_analyses = []

        for five_tuple, flow in flows.items():
            if flow.five_tuple.protocol.upper() != 'TCP':
                continue

            # Detect problems in this flow
            problems = problem_detector.detect_all(flow)

            for problem in problems:
                # Analyze causes
                causes = diagnosis_engine.analyze_causes(problem, flow)

                # Generate recommendations
                recommendations = diagnosis_engine.generate_recommendations(problem, causes)

                flow_analyses.append({
                    'five_tuple': five_tuple,
                    'problem': problem,
                    'causes': causes,
                    'recommendations': recommendations
                })

                all_problems.append(problem)

        # Classify and rank problems
        ranked_problems = problem_classifier.rank_by_severity(all_problems)
        categorized_problems = problem_classifier.classify(all_problems)
        summary = problem_classifier.summarize(all_problems)

        result = {
            'total_flows': len(flows),
            'problems_found': len(all_problems),
            'summary': summary,
            'ranked_problems': ranked_problems,
            'categorized_problems': categorized_problems,
            'detailed_analysis': flow_analyses
        }

        # Output
        if args.output:
            formatter = JSONFormatter()
            formatter.write_to_file(result, args.output)
            print_info(f"Results written to {args.output}")
        else:
            print_analysis_results(result)

    except Exception as e:
        print_error(f"Analysis failed: {str(e)}")
        if args.debug:
            raise
        sys.exit(1)


def print_summary_results(result):
    """Print summary mode results to console"""
    print("\n" + "="*60)
    print("PCAP SUMMARY ANALYSIS")
    print("="*60)

    # File info
    print(f"\nFile: {result['file_info']['filename']}")
    print(f"Total Packets: {result['file_info']['packet_count']}")

    # L3 stats
    l3 = result['l3_stats']
    print(f"\nTotal Traffic: {format_bytes(l3.total_bytes)}")
    print(f"IP Versions: {l3.ip_versions}")
    print(f"Protocols: {l3.protocols}")

    # L4 stats
    l4 = result['l4_stats']
    print(f"\nTCP: {l4.tcp_packets} packets ({format_bytes(l4.tcp_bytes)})")
    print(f"UDP: {l4.udp_packets} packets ({format_bytes(l4.udp_bytes)})")

    # Timeseries
    ts = result['timeseries']
    print(f"\nAverage pps: {ts.avg_pps:.2f}")
    print(f"Peak pps: {ts.peak_pps:.2f}")
    print(f"Average bps: {format_rate(ts.avg_bps)}")
    print(f"Peak bps: {format_rate(ts.peak_bps)}")

    # Top talkers
    tt = result['top_talkers']
    print(f"\nTop Senders:")
    for ip, bytes_count in tt.top_senders[:5]:
        print(f"  {ip}: {format_bytes(bytes_count)}")


def print_detailed_results(result):
    """Print details mode results to console"""
    print("\n" + "="*60)
    print("PCAP DETAILED ANALYSIS")
    print("="*60)

    print(f"\nTotal Flows: {result['total_flows']}")
    print(f"TCP Flows: {result['tcp_flows']}")

    for i, analysis in enumerate(result['detailed_analysis'][:10], 1):
        print(f"\n--- Flow {i} ---")
        ft = analysis['five_tuple']
        print(f"{ft.src_ip}:{ft.src_port} -> {ft.dst_ip}:{ft.dst_port}")

        retrans = analysis['retrans_stats']
        print(f"Retransmissions: {retrans.retrans_packets}/{retrans.total_packets} ({retrans.retrans_rate*100:.2f}%)")

        if analysis['tcp_features'].sack_permitted:
            print("SACK: Enabled")


def print_analysis_results(result):
    """Print analysis mode results to console"""
    print("\n" + "="*60)
    print("PCAP PROBLEM ANALYSIS")
    print("="*60)

    summary = result['summary']
    print(f"\nTotal Flows Analyzed: {result['total_flows']}")
    print(f"Problems Found: {result['problems_found']}")

    if result['problems_found'] == 0:
        print("\nNo significant problems detected!")
        return

    print(f"\nProblems by Severity:")
    for severity, count in summary['by_severity'].items():
        print(f"  {severity}: {count}")

    print(f"\nProblems by Category:")
    for category, count in summary['by_category'].items():
        print(f"  {category}: {count}")

    print(f"\nTop Problems (by severity):")
    for i, problem in enumerate(result['ranked_problems'][:5], 1):
        print(f"\n{i}. [{problem.severity}] {problem.type}")
        print(f"   {problem.description}")


def main():
    """Main entry point for PCAP Analyzer CLI"""
    parser = argparse.ArgumentParser(
        description='PCAP Traffic Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Required arguments
    parser.add_argument(
        '--mode',
        choices=['summary', 'details', 'analysis'],
        required=True,
        help='Analysis mode'
    )
    parser.add_argument(
        '--pcap',
        required=True,
        help='Path to PCAP file'
    )

    # Filter options
    parser.add_argument('--src-ip', help='Filter by source IP address')
    parser.add_argument('--dst-ip', help='Filter by destination IP address')
    parser.add_argument('--src-port', type=int, help='Filter by source port')
    parser.add_argument('--dst-port', type=int, help='Filter by destination port')
    parser.add_argument('--protocol', help='Filter by protocol (tcp, udp, icmp)')

    # Output options
    parser.add_argument('--output', '-o', help='Output file (JSON format)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')

    # Mode-specific options
    parser.add_argument('--interval', type=float, default=1.0, help='Time interval for timeseries (seconds)')
    parser.add_argument('--top-n', type=int, default=10, help='Number of top talkers to show')

    args = parser.parse_args()

    # Validate PCAP file
    if not validate_file_path(args.pcap):
        print_error(f"PCAP file not found or not readable: {args.pcap}")
        sys.exit(1)

    # Dispatch to appropriate mode
    if args.mode == 'summary':
        run_summary_mode(args)
    elif args.mode == 'details':
        run_details_mode(args)
    elif args.mode == 'analysis':
        run_analysis_mode(args)


if __name__ == '__main__':
    main()
