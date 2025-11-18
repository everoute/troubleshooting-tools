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
    print_info("Detailed mode analysis not yet fully implemented")
    print_info("Running summary mode instead...")
    run_summary_mode(args)


def run_pipeline_mode(args):
    """
    Execute pipeline mode analysis

    Identifies bottlenecks in send and receive paths.

    Args:
        args: Command-line arguments
    """
    print_info("Pipeline mode analysis not yet fully implemented")
    print_info("Running summary mode instead...")
    run_summary_mode(args)


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
    print(f"BDP: {wa.bdp:.0f} bytes")
    print(f"Optimal CWND: {wa.optimal_cwnd:.2f} packets")
    print(f"Actual CWND: {wa.actual_cwnd:.2f} packets")
    print(f"CWND Utilization: {wa.cwnd_utilization*100:.1f}%")
    print(f"Client CWND: min={wa.client_cwnd_stats.min:.0f}, "
          f"avg={wa.client_cwnd_stats.mean:.0f}, "
          f"max={wa.client_cwnd_stats.max:.0f}")

    # Rate analysis
    ra = result.rate_analysis
    print(f"\n--- Rate Analysis ---")
    print(f"Bandwidth Utilization: avg={ra.avg_bandwidth_utilization*100:.1f}%, "
          f"peak={ra.peak_bandwidth_utilization*100:.1f}%")
    print(f"Delivery Rate: min={format_rate(ra.delivery_rate_stats.min)}, "
          f"avg={format_rate(ra.delivery_rate_stats.mean)}, "
          f"max={format_rate(ra.delivery_rate_stats.max)}")
    print(f"Pacing/Delivery Ratio: {ra.pacing_delivery_ratio:.2f}")
    print(f"Rate Stability: {ra.rate_stability:.2f}")

    # RTT analysis
    rtt = result.rtt_analysis
    print(f"\n--- RTT Analysis ---")
    print(f"RTT: min={rtt.rtt_stats.min:.2f}ms, "
          f"avg={rtt.rtt_stats.mean:.2f}ms, "
          f"max={rtt.rtt_stats.max:.2f}ms")
    print(f"RTT Stability: {rtt.rtt_stability} (CV={rtt.rtt_stats.cv:.3f})")
    print(f"RTT Trend: {rtt.rtt_trend}")

    # Buffer analysis
    ba = result.buffer_analysis
    print(f"\n--- Buffer Analysis ---")
    print(f"Send Buffer: size={ba.send_buffer_size:.0f}, pressure={ba.send_buffer_pressure*100:.1f}%")
    print(f"Recv Buffer: size={ba.recv_buffer_size:.0f}, pressure={ba.recv_buffer_pressure*100:.1f}%")
    print(f"Send Buffer Limited: {ba.send_buffer_limited_ratio*100:.1f}% of time")
    print(f"Recv Buffer Limited: {ba.recv_buffer_limited_ratio*100:.1f}% of time")

    # Retransmission analysis
    retrans = result.retrans_analysis
    print(f"\n--- Retransmission Analysis ---")
    print(f"Total Retransmissions: {retrans.total_retrans}")
    print(f"Retrans Rate: avg={retrans.retrans_rate_stats.mean:.4f}%, "
          f"max={retrans.retrans_rate_stats.max:.4f}%")

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


def main():
    """Main entry point for TCP Socket Analyzer CLI"""
    parser = argparse.ArgumentParser(
        description='TCP Socket Performance Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Summary mode
  %(prog)s --mode summary --client-dir ./client --server-dir ./server --bandwidth 1gbps

  # Detailed mode with timeseries export
  %(prog)s --mode detailed --client-dir ./client --server-dir ./server --export-timeseries

  # Pipeline mode for bottleneck analysis
  %(prog)s --mode pipeline --client-dir ./client --server-dir ./server --bandwidth 10gbps
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
        help='Directory containing client-side socket data'
    )
    parser.add_argument(
        '--server-dir',
        required=True,
        help='Directory containing server-side socket data'
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

    # Validate directories
    if not validate_directory(args.client_dir):
        print_error(f"Client directory not found or not readable: {args.client_dir}")
        sys.exit(1)

    if not validate_directory(args.server_dir):
        print_error(f"Server directory not found or not readable: {args.server_dir}")
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
