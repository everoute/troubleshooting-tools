#!/usr/bin/env python
"""
TCP Socket Analyzer CLI

Command-line interface for TCP socket performance analysis.
Supports three modes: summary, detailed, and pipeline.
"""

import argparse
import sys
from typing import Optional

from tcpsocket_analyzer.parser import SocketDataParser, ConnectionMismatchError
from tcpsocket_analyzer.analyzers import SummaryAnalyzer, BandwidthParser
from tcpsocket_analyzer.reporters import RecommendationEngine
from common.utils import print_error, print_info, validate_directory, format_rate


def run_summary_mode(args):
    """
    Execute summary mode analysis

    Provides window, rate, RTT, buffer, and bottleneck analysis.

    Args:
        args: Command-line arguments
    """
    print_info(f"Running summary mode")
    print_info(f"Client data: {args.client_dir}")
    print_info(f"Server data: {args.server_dir}")

    try:
        # Parse bandwidth
        bw_parser = BandwidthParser()
        bandwidth = bw_parser.parse(args.bandwidth)
        print_info(f"Bandwidth: {bw_parser.format(bandwidth)}")

        # Parse socket data
        parser = SocketDataParser()
        print_info("Parsing client and server data...")
        client_df, server_df, aligned_df = parser.parse_dual_directories(
            args.client_dir,
            args.server_dir
        )

        print_info(f"Client samples: {len(client_df)}")
        print_info(f"Server samples: {len(server_df)}")
        print_info(f"Aligned samples: {len(aligned_df)}")

        # Get connection info
        conn_str = client_df['connection'].iloc[0]
        connection = parser._parse_connection_str(conn_str)

        # Perform summary analysis
        analyzer = SummaryAnalyzer()
        print_info("Performing summary analysis...")
        result = analyzer.analyze(
            client_df,
            server_df,
            aligned_df,
            bandwidth,
            connection
        )

        # Generate recommendations
        rec_engine = RecommendationEngine()
        recommendations = rec_engine.generate(
            result.window_analysis,
            result.rate_analysis,
            result.buffer_analysis,
            result.bottleneck
        )
        result.recommendations = recommendations

        # Print results
        print_summary_results(result, bandwidth)

    except ConnectionMismatchError as e:
        print_error(f"Connection mismatch: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Analysis failed: {str(e)}")
        if args.debug:
            raise
        sys.exit(1)


def run_detailed_mode(args):
    """
    Execute detailed mode analysis

    Provides detailed window, rate, retransmission, and buffer analysis.

    Args:
        args: Command-line arguments
    """
    print_info(f"Running detailed mode")
    print_info(f"Client data: {args.client_dir}")
    print_info(f"Server data: {args.server_dir}")

    try:
        # Parse bandwidth
        from tcpsocket_analyzer.analyzers import BandwidthParser, DetailedAnalyzer, AnalyzerConfig
        from tcpsocket_analyzer.parser import SocketDataParser

        bw_parser = BandwidthParser()
        bandwidth = bw_parser.parse(args.bandwidth)
        print_info(f"Bandwidth: {bw_parser.format(bandwidth)}")

        # Parse socket data
        parser = SocketDataParser()
        print_info("Parsing client and server data...")
        client_df, server_df, aligned_df = parser.parse_dual_directories(
            args.client_dir,
            args.server_dir
        )

        print_info(f"Client samples: {len(client_df)}")
        print_info(f"Server samples: {len(server_df)}")
        print_info(f"Aligned samples: {len(aligned_df)}")

        # Get connection info
        conn_str = client_df['connection'].iloc[0]
        connection = parser._parse_connection_str(conn_str)

        # Configure analyzer
        config = AnalyzerConfig(
            export_timeseries=args.export_timeseries,
            timeseries_output_path=args.output
        )

        # Perform detailed analysis
        analyzer = DetailedAnalyzer(config)
        print_info("Performing detailed analysis...")
        result = analyzer.analyze(
            client_df,
            server_df,
            aligned_df,
            bandwidth,
            connection
        )

        # Print results
        print_detailed_results(result, bandwidth)

        # Export to file if requested
        if args.output and not args.export_timeseries:
            # TODO: Implement JSON export
            print_info(f"JSON export to {args.output} not yet implemented")

    except Exception as e:
        print_error(f"Analysis failed: {str(e)}")
        if args.debug:
            raise
        sys.exit(1)


def run_pipeline_mode(args):
    """
    Execute pipeline mode analysis

    Identifies bottlenecks in send and receive paths.

    Args:
        args: Command-line arguments
    """
    print_info(f"Running pipeline mode")
    print_info(f"Client data: {args.client_dir}")
    print_info(f"Server data: {args.server_dir}")

    try:
        # Parse bandwidth
        from tcpsocket_analyzer.analyzers import (
            BandwidthParser, BottleneckFinder, DiagnosisEngine
        )
        from tcpsocket_analyzer.parser import SocketDataParser
        from tcpsocket_analyzer.reporters import PipelineReporter
        from tcpsocket_analyzer.models import PipelineResult

        bw_parser = BandwidthParser()
        bandwidth = bw_parser.parse(args.bandwidth)
        print_info(f"Bandwidth: {bw_parser.format(bandwidth)}")

        # Parse socket data
        parser = SocketDataParser()
        print_info("Parsing client and server data...")
        client_df, server_df, aligned_df = parser.parse_dual_directories(
            args.client_dir,
            args.server_dir
        )

        print_info(f"Client samples: {len(client_df)}")
        print_info(f"Server samples: {len(server_df)}")

        # Get connection info
        conn_str = client_df['connection'].iloc[0]
        connection = parser._parse_connection_str(conn_str)

        # Perform pipeline analysis
        print_info("Identifying pipeline bottlenecks...")
        finder = BottleneckFinder()

        # Find bottlenecks in both paths
        send_bottlenecks = finder.find_send_path_bottlenecks(client_df)
        recv_bottlenecks = finder.find_recv_path_bottlenecks(server_df)

        print_info(f"Send path bottlenecks: {len(send_bottlenecks)}")
        print_info(f"Recv path bottlenecks: {len(recv_bottlenecks)}")

        # Identify primary bottleneck
        all_bottlenecks = send_bottlenecks + recv_bottlenecks
        primary = finder.identify_primary(all_bottlenecks)

        # Rank by priority
        optimization_priority = finder.rank_priority(all_bottlenecks)

        # Calculate health score
        reporter = PipelineReporter()
        health = reporter.generate_health_overview(all_bottlenecks, primary)

        # Create result
        result = PipelineResult(
            connection=connection,
            send_path_bottlenecks=send_bottlenecks,
            recv_path_bottlenecks=recv_bottlenecks,
            primary_bottleneck=primary,
            health_score=health.health_score,
            optimization_priority=optimization_priority
        )

        # Print results
        print_pipeline_results(result, reporter)

        # Export to file if requested
        if args.output:
            import json
            # TODO: Implement JSON export
            print_info(f"JSON export to {args.output} not yet implemented")

    except Exception as e:
        print_error(f"Analysis failed: {str(e)}")
        if args.debug:
            raise
        sys.exit(1)


def _print_basic_stats(stats, unit="", decimals=2):
    """Helper function to print BasicStats in consistent format"""
    fmt = f".{decimals}f"
    print(f"  Min: {stats.min:{fmt}}{unit}, Max: {stats.max:{fmt}}{unit}, Mean: {stats.mean:{fmt}}{unit}")
    print(f"  Std: {stats.std:{fmt}}{unit}, CV: {stats.cv:.3f}")
    print(f"  P50: {stats.p50:{fmt}}{unit}, P95: {stats.p95:{fmt}}{unit}, P99: {stats.p99:{fmt}}{unit}")


def print_summary_results(result, bandwidth):
    """Print summary mode results to console"""
    print("\n" + "="*70)
    print("TCP SOCKET SUMMARY ANALYSIS")
    print("="*70)

    # Connection info
    print(f"\nConnection: {result.connection}")

    # Window analysis
    wa = result.window_analysis
    print(f"\n--- Window Analysis ---")
    print(f"BDP: {wa.bdp:.0f} bytes ({wa.bdp/1024/1024:.2f} MB)")
    print(f"Optimal CWND: {wa.optimal_cwnd:.2f} packets")
    print(f"Actual CWND: {wa.actual_cwnd:.2f} packets")
    print(f"CWND Utilization: {wa.cwnd_utilization*100:.1f}%")
    print(f"\nClient CWND Statistics:")
    _print_basic_stats(wa.client_cwnd_stats, " pkts", 0)
    print(f"\nServer CWND Statistics:")
    _print_basic_stats(wa.server_cwnd_stats, " pkts", 0)
    print(f"\nRWND Analysis:")
    print(f"  Min: {wa.rwnd_min:.0f} bytes, Avg: {wa.rwnd_avg:.0f} bytes")
    print(f"  RWND Limited: {wa.rwnd_limited_ratio*100:.1f}% of time")
    print(f"SSThresh: avg={wa.ssthresh_avg:.0f} pkts, cwnd/ssthresh={wa.cwnd_ssthresh_ratio:.2f}")

    # Rate analysis
    ra = result.rate_analysis
    print(f"\n--- Rate Analysis ---")
    print(f"Bandwidth: {format_rate(bandwidth)}")
    print(f"Bandwidth Utilization: avg={ra.avg_bandwidth_utilization*100:.1f}%, peak={ra.peak_bandwidth_utilization*100:.1f}%")
    print(f"Pacing/Delivery Ratio: {ra.pacing_delivery_ratio:.2f}")
    print(f"Rate Stability: {ra.rate_stability:.2f}")
    print(f"\nPacing Rate Statistics:")
    print(f"  Min: {format_rate(ra.pacing_rate_stats.min)}, Max: {format_rate(ra.pacing_rate_stats.max)}, Mean: {format_rate(ra.pacing_rate_stats.mean)}")
    print(f"  Std: {ra.pacing_rate_stats.std/1e9:.2f} Gbps, CV: {ra.pacing_rate_stats.cv:.3f}")
    print(f"  P50: {format_rate(ra.pacing_rate_stats.p50)}, P95: {format_rate(ra.pacing_rate_stats.p95)}, P99: {format_rate(ra.pacing_rate_stats.p99)}")
    print(f"\nDelivery Rate Statistics:")
    print(f"  Min: {format_rate(ra.delivery_rate_stats.min)}, Max: {format_rate(ra.delivery_rate_stats.max)}, Mean: {format_rate(ra.delivery_rate_stats.mean)}")
    print(f"  Std: {ra.delivery_rate_stats.std/1e9:.2f} Gbps, CV: {ra.delivery_rate_stats.cv:.3f}")
    print(f"  P50: {format_rate(ra.delivery_rate_stats.p50)}, P95: {format_rate(ra.delivery_rate_stats.p95)}, P99: {format_rate(ra.delivery_rate_stats.p99)}")

    # RTT analysis
    rtt = result.rtt_analysis
    print(f"\n--- RTT Analysis ---")
    print(f"RTT Statistics:")
    _print_basic_stats(rtt.rtt_stats, " ms", 2)
    print(f"RTT Stability: {rtt.rtt_stability}")
    print(f"RTT Trend: {rtt.rtt_trend}")

    # Buffer analysis
    ba = result.buffer_analysis
    print(f"\n--- Buffer Analysis ---")
    print(f"Send Buffer Size: {ba.send_buffer_size:.0f} bytes ({ba.send_buffer_size/1024/1024:.2f} MB)")
    print(f"Send Buffer Pressure: {ba.send_buffer_pressure*100:.1f}%")
    print(f"Send Buffer Limited: {ba.send_buffer_limited_ratio*100:.1f}% of time")
    print(f"Send Queue Statistics:")
    _print_basic_stats(ba.send_queue_stats, " bytes", 0)
    print(f"\nRecv Buffer Size: {ba.recv_buffer_size:.0f} bytes ({ba.recv_buffer_size/1024/1024:.2f} MB)")
    print(f"Recv Buffer Pressure: {ba.recv_buffer_pressure*100:.1f}%")
    print(f"Recv Buffer Limited: {ba.recv_buffer_limited_ratio*100:.1f}% of time")
    print(f"Recv Queue Statistics:")
    _print_basic_stats(ba.recv_queue_stats, " bytes", 0)

    # Retransmission analysis
    retrans = result.retrans_analysis
    print(f"\n--- Retransmission Analysis ---")
    print(f"Total Retransmissions: {retrans.total_retrans}")
    print(f"Retransmission Rate Statistics:")
    _print_basic_stats(retrans.retrans_rate_stats, "%", 4)
    print(f"Retransmission Type Breakdown:")
    print(f"  Fast Retrans: {retrans.fast_retrans_ratio*100:.1f}%")
    print(f"  Timeout Retrans: {retrans.timeout_retrans_ratio*100:.1f}%")
    print(f"  Spurious Retrans: {retrans.spurious_retrans_ratio*100:.1f}%")

    # Bottleneck identification
    bn = result.bottleneck
    print(f"\n--- Bottleneck Analysis ---")
    print(f"Primary Bottleneck: {bn.primary_bottleneck} (confidence={bn.bottleneck_confidence*100:.1f}%)")
    if bn.limiting_factors:
        print(f"Limiting Factors: {', '.join(bn.limiting_factors)}")

    # Recommendations
    if result.recommendations:
        print(f"\n--- Recommendations ({len(result.recommendations)}) ---")
        for i, rec in enumerate(result.recommendations[:5], 1):
            print(f"\n{i}. [{rec.priority}] {rec.action}")
            print(f"   {rec.description}")
            if rec.configuration_example:
                print(f"   Example: {rec.configuration_example}")


def print_detailed_results(result, bandwidth):
    """Print detailed mode results to console"""
    print("\n" + "="*70)
    print("TCP SOCKET DETAILED ANALYSIS")
    print("="*70)

    # Connection info
    print(f"\nConnection: {result.connection}")

    # Summary section (brief)
    print(f"\n--- Summary ---")
    print(f"Bandwidth: {format_rate(bandwidth)}")
    print(f"Primary Bottleneck: {result.summary.bottleneck.primary_bottleneck}")

    # Window detailed
    wd = result.window_detailed
    print(f"\n--- Window Detailed Analysis ---")
    print(f"CWND Limited: {wd.cwnd_limited_ratio*100:.1f}% of time")
    print(f"RWND Limited: {wd.rwnd_limited_ratio*100:.1f}% of time")
    print(f"SNDBUF Limited: {wd.sndbuf_limited_ratio*100:.1f}% of time")
    print(f"Recovery Events: {len(wd.recovery_events)}")
    if wd.recovery_events:
        print(f"Average Recovery Time: {wd.avg_recovery_time:.2f}s")
    print(f"Congestion Avoidance Ratio: {wd.congestion_avoidance_ratio*100:.1f}%")

    # Rate detailed
    rd = result.rate_detailed
    print(f"\n--- Rate Detailed Analysis ---")
    print(f"Pacing Trend: {rd.pacing_rate_trend.trend_type}")
    print(f"Delivery Trend: {rd.delivery_rate_trend.trend_type}")
    print(f"Pacing Limited: {rd.pacing_limited_ratio*100:.1f}% of time")
    print(f"Network Limited: {rd.network_limited_ratio*100:.1f}% of time")
    print(f"App Limited: {rd.app_limited_ratio*100:.1f}% of time")
    print(f"\nCorrelations:")
    for metric, value in rd.correlations.items():
        print(f"  {metric}: {value:.3f}")

    # Retransmission detailed
    retrans_d = result.retrans_detailed
    print(f"\n--- Retransmission Detailed Analysis ---")
    print(f"Burst Events: {len(retrans_d.burst_events)}")
    if retrans_d.burst_events:
        for i, burst in enumerate(retrans_d.burst_events[:3], 1):
            print(f"  {i}. {burst.severity} burst: {burst.retrans_count} retrans")

    # Buffer detailed
    bd = result.buffer_detailed
    print(f"\n--- Buffer Detailed Analysis ---")
    print(f"High Pressure Ratio: {bd.high_pressure_ratio*100:.1f}%")
    print(f"Buffer Exhaustion Events: {bd.buffer_exhaustion_events}")


def print_pipeline_results(result, reporter):
    """Print pipeline mode results to console"""
    # Use reporter to generate full report
    report_text = reporter.generate_full_report(result)
    print(report_text)


def main():
    """Main entry point for TCP Socket Analyzer CLI"""
    parser = argparse.ArgumentParser(
        description='TCP Socket Performance Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Summary mode with log files
  %(prog)s --mode summary --client-dir client-socket.log --server-dir server-socket.log --bandwidth 1gbps

  # Detailed mode with timeseries export
  %(prog)s --mode detailed --client-dir client-socket.log --server-dir server-socket.log --export-timeseries

  # Pipeline mode for bottleneck analysis
  %(prog)s --mode pipeline --client-dir client-socket.log --server-dir server-socket.log --bandwidth 10gbps

  # Using directory containing multiple log files
  %(prog)s --mode summary --client-dir ./client-logs/ --server-dir ./server-logs/ --bandwidth 25gbps
        """
    )

    # Required arguments
    parser.add_argument(
        '--mode',
        choices=['summary', 'detailed', 'pipeline'],
        required=True,
        help='Analysis mode'
    )
    parser.add_argument(
        '--client-dir',
        required=True,
        help='Path to client-side socket log file or directory containing log files'
    )
    parser.add_argument(
        '--server-dir',
        required=True,
        help='Path to server-side socket log file or directory containing log files'
    )

    # Optional arguments
    parser.add_argument(
        '--bandwidth',
        default='1gbps',
        help='Network bandwidth (e.g., 1gbps, 100mbps) [default: 1gbps]'
    )
    parser.add_argument(
        '--output',
        '-o',
        help='Output file (JSON format)'
    )
    parser.add_argument(
        '--export-timeseries',
        action='store_true',
        help='Export time-series data (detailed mode only)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output'
    )

    args = parser.parse_args()

    # Validate paths (file or directory)
    import os
    if not os.path.exists(args.client_dir):
        print_error(f"Client path not found: {args.client_dir}")
        sys.exit(1)
    if not os.access(args.client_dir, os.R_OK):
        print_error(f"Client path not readable: {args.client_dir}")
        sys.exit(1)

    if not os.path.exists(args.server_dir):
        print_error(f"Server path not found: {args.server_dir}")
        sys.exit(1)
    if not os.access(args.server_dir, os.R_OK):
        print_error(f"Server path not readable: {args.server_dir}")
        sys.exit(1)

    # Dispatch to appropriate mode
    if args.mode == 'summary':
        run_summary_mode(args)
    elif args.mode == 'detailed':
        run_detailed_mode(args)
    elif args.mode == 'pipeline':
        run_pipeline_mode(args)


if __name__ == '__main__':
    main()
