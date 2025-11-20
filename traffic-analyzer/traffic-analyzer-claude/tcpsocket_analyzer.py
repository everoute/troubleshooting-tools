#!/usr/bin/env python
"""
TCP Socket Analyzer CLI

Command-line interface for TCP socket performance analysis.
Supports three modes: summary, detailed, and pipeline.
"""

import argparse
import sys
from typing import Optional

import os
import sys
from tcpsocket_analyzer.parser import SocketDataParser, ConnectionMismatchError
from tcpsocket_analyzer.analyzers import SummaryAnalyzer, BandwidthParser
from tcpsocket_analyzer.reporters import RecommendationEngine
from common.utils import print_error, print_info, validate_directory, format_rate

# Import unified conversion tool
tools_path = os.path.join(os.path.dirname(__file__), 'tools')
sys.path.insert(0, tools_path)
from convert_socket_log_to_csv import convert_log_to_csv


def export_csv_files(args):
    """
    Export parsed socket log files to CSV using unified conversion tool
    Generates client, server, and aligned CSV files with statistics appended

    Args:
        args: Command-line arguments containing export settings

    Returns:
        Dictionary with statistics DataFrames for client, server, and aligned data
    """
    if not args.export_csv:
        return None

    # Determine output directory
    if args.csv_output_dir:
        output_dir = args.csv_output_dir
    else:
        # Use client log file directory as default
        output_dir = os.path.dirname(args.client_log)
        if not output_dir:
            output_dir = '.'

    # Create output directory if needed
    os.makedirs(output_dir, exist_ok=True)

    # Generate output filenames
    client_csv = os.path.join(output_dir, 'client-socket-parsed.csv')
    server_csv = os.path.join(output_dir, 'server-socket-parsed.csv')
    aligned_csv = os.path.join(output_dir, 'aligned-socket-parsed.csv')

    # Convert log files to CSV using unified conversion logic (with statistics)
    try:
        print_info("Converting socket logs to CSV format with statistics...")

        # Convert client and server logs (statistics will be auto-appended)
        stats_client = convert_log_to_csv(args.client_log, client_csv, add_statistics=True)
        stats_server = convert_log_to_csv(args.server_log, server_csv, add_statistics=True)

        print_info(f"Exported client CSV to: {client_csv}")
        print_info(f"Exported server CSV to: {server_csv}")

        # Generate aligned data
        from tcpsocket_analyzer.parser.socket_parser import SocketDataParser
        parser = SocketDataParser()
        client_df, server_df, aligned_df = parser.parse_dual_directories(
            args.client_log,
            args.server_log
        )

        # Export aligned DataFrame to CSV
        aligned_df.reset_index().to_csv(aligned_csv, index=False)

        # Append statistics to aligned CSV
        from tcpsocket_analyzer.analyzer.csv_statistics import append_statistics_to_csv
        stats_aligned = append_statistics_to_csv(aligned_csv)

        print_info(f"Exported aligned CSV to: {aligned_csv}")
        print_info("All CSV files exported with statistics appended")

        # Return statistics for use by analysis modes
        return {
            'client': stats_client,
            'server': stats_server,
            'aligned': stats_aligned
        }

    except Exception as e:
        print_error(f"Failed to export CSV files: {e}")
        import traceback
        traceback.print_exc()
        return None


def run_summary_mode(args):
    """
    Execute summary mode analysis

    Provides window, rate, RTT, buffer, and bottleneck analysis.

    Args:
        args: Command-line arguments
    """
    print_info(f"Running summary mode - dual-side analysis")
    print_info(f"Client log: {args.client_log}")
    print_info(f"Server log: {args.server_log}")

    try:
        # Parse bandwidth
        bw_parser = BandwidthParser()
        bandwidth = bw_parser.parse(args.bandwidth)
        print_info(f"Bandwidth: {bw_parser.format(bandwidth)}")

        # Parse socket data
        parser = SocketDataParser()
        print_info("Parsing client and server data...")
        client_df, server_df, aligned_df = parser.parse_dual_directories(
            args.client_log,
            args.server_log
        )

        print_info(f"Client samples: {len(client_df)}")
        print_info(f"Server samples: {len(server_df)}")
        print_info(f"Aligned samples: {len(aligned_df)}")

        # Export CSV if requested (using original log files)
        export_csv_files(args)

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
    print_info(f"Running detailed mode - dual-side analysis")
    print_info(f"Client log: {args.client_log}")
    print_info(f"Server log: {args.server_log}")

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
            args.client_log,
            args.server_log
        )

        print_info(f"Client samples: {len(client_df)}")
        print_info(f"Server samples: {len(server_df)}")
        print_info(f"Aligned samples: {len(aligned_df)}")

        # Export CSV if requested (using original log files)
        export_csv_files(args)

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
    print_info(f"Running pipeline mode - dual-side analysis")
    print_info(f"Client log: {args.client_log}")
    print_info(f"Server log: {args.server_log}")

    try:
        # Parse bandwidth
        from tcpsocket_analyzer.analyzers import (
            BandwidthParser, BottleneckFinder, DiagnosisEngine
        )
        from tcpsocket_analyzer.parser import SocketDataParser
        from tcpsocket_analyzer.reporters import PipelineReporter
        from tcpsocket_analyzer.models import PipelineResult
        from tcpsocket_analyzer.analyzers.diagnosis_engine import AnalysisContext

        bw_parser = BandwidthParser()
        bandwidth = bw_parser.parse(args.bandwidth)
        print_info(f"Bandwidth: {bw_parser.format(bandwidth)}")

        # Parse socket data
        parser = SocketDataParser()
        print_info("Parsing client and server data...")
        client_df, server_df, aligned_df = parser.parse_dual_directories(
            args.client_log,
            args.server_log
        )

        print_info(f"Client samples: {len(client_df)}")
        print_info(f"Server samples: {len(server_df)}")

        # Export CSV if requested (using original log files)
        export_csv_files(args)

        # Get connection info
        conn_str = client_df['connection'].iloc[0]
        connection = parser._parse_connection_str(conn_str)

        # Perform pipeline analysis
        print_info("Identifying pipeline bottlenecks...")
        finder = BottleneckFinder()

        # Find bottlenecks in both paths
        send_bottlenecks = finder.find_send_path_bottlenecks(client_df, bandwidth)
        recv_bottlenecks = finder.find_recv_path_bottlenecks(server_df, bandwidth)

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

        # Build context for diagnosis
        avg_rtt_ms = aligned_df['rtt_client'].mean() if 'rtt_client' in aligned_df.columns else client_df['rtt'].mean()
        avg_rtt = avg_rtt_ms / 1000.0
        avg_cwnd = client_df['cwnd'].mean() if 'cwnd' in client_df.columns else 0
        avg_delivery_rate = client_df['delivery_rate'].mean() if 'delivery_rate' in client_df.columns else 0
        bdp = bandwidth * avg_rtt / 8 if bandwidth else 0
        context = AnalysisContext(
            bdp=bdp,
            bandwidth=bandwidth,
            avg_rtt=avg_rtt_ms,
            avg_cwnd=avg_cwnd,
            avg_delivery_rate=avg_delivery_rate
        )

        diag_engine = DiagnosisEngine()
        action_plans = diag_engine.generate_next_steps(optimization_priority, context)

        # Create result
        result = PipelineResult(
            connection=connection,
            send_path_bottlenecks=send_bottlenecks,
            recv_path_bottlenecks=recv_bottlenecks,
            primary_bottleneck=primary,
            health_score=health.health_score,
            optimization_priority=optimization_priority,
            action_plans=action_plans
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
    if stats is None:
        print("  (no data)")
        return
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
    ra = result.rate_analysis
    bn = result.bottleneck
    print(f"Summary: Bandwidth {format_rate(bandwidth)}, Utilization avg={ra.avg_bandwidth_utilization*100:.1f}% "
          f"Primary Bottleneck: {bn.primary_bottleneck}")

    # Window analysis
    wa = result.window_analysis
    print(f"\n--- Window Analysis ---")
    print(f"BDP: {wa.bdp:.0f} bytes ({wa.bdp/1024/1024:.2f} MB)")
    print(f"Optimal CWND: {wa.optimal_cwnd:.2f} packets")
    print(f"Actual CWND: {wa.actual_cwnd:.2f} packets")
    print(f"CWND Utilization: {wa.cwnd_utilization*100:.1f}%")
    print(f"cwnd/ssthresh ratio: <1 {wa.cwnd_ssthresh_distribution.get('<1',0)*100:.1f}% , "
          f">=1 {wa.cwnd_ssthresh_distribution.get('>=1',0)*100:.1f}%")
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
    if ra.send_rate_stats:
        print(f"\nSend Rate Statistics:")
        print(f"  Min: {format_rate(ra.send_rate_stats.min)}, Max: {format_rate(ra.send_rate_stats.max)}, Mean: {format_rate(ra.send_rate_stats.mean)}")
        print(f"  Std: {ra.send_rate_stats.std/1e9:.2f} Gbps, CV: {ra.send_rate_stats.cv:.3f}")
        print(f"  P50: {format_rate(ra.send_rate_stats.p50)}, P95: {format_rate(ra.send_rate_stats.p95)}, P99: {format_rate(ra.send_rate_stats.p99)}")

    # RTT analysis
    rtt = result.rtt_analysis
    print(f"\n--- RTT Analysis ---")
    print(f"Client RTT Statistics:")
    _print_basic_stats(rtt.client_rtt_stats, " ms", 2)
    print(f"Server RTT Statistics:")
    _print_basic_stats(rtt.server_rtt_stats, " ms", 2)
    print(f"RTT Stability: {rtt.rtt_stability}, Jitter: {rtt.jitter:.2f} ms")
    print(f"RTT Trend: {rtt.rtt_trend}")
    print(f"RTT Diff (client-server): {rtt.rtt_diff:.2f} ms ({rtt.asymmetry})")

    # Buffer analysis
    ba = result.buffer_analysis
    print(f"\n--- Buffer Analysis ---")
    print(f"Send Buffer Size: {ba.send_buffer_size:.0f} bytes ({ba.send_buffer_size/1024/1024:.2f} MB)")
    print(f"Send Buffer Pressure: {ba.send_buffer_pressure*100:.1f}%")
    print(f"Send Buffer Limited: {ba.send_buffer_limited_ratio*100:.1f}% of time")
    print(f"Send Queue Statistics:")
    _print_basic_stats(ba.send_queue_stats, " bytes", 0)
    print(f"Raw send_q stats:")
    _print_basic_stats(ba.send_q_stats, " bytes", 0)
    print(f"Write Queue Statistics:")
    _print_basic_stats(ba.write_queue_stats, " bytes", 0)
    print(f"Backlog Statistics:")
    _print_basic_stats(ba.backlog_stats, " bytes", 0)
    print(f"Dropped Statistics:")
    _print_basic_stats(ba.dropped_stats, " packets", 0)
    print(f"\nRecv Buffer Size: {ba.recv_buffer_size:.0f} bytes ({ba.recv_buffer_size/1024/1024:.2f} MB)")
    print(f"Recv Buffer Pressure: {ba.recv_buffer_pressure*100:.1f}%")
    print(f"Recv Buffer Limited: {ba.recv_buffer_limited_ratio*100:.1f}% of time")
    print(f"Recv Queue Statistics:")
    _print_basic_stats(ba.recv_queue_stats, " bytes", 0)
    print(f"Raw recv_q stats:")
    _print_basic_stats(ba.recv_q_stats, " bytes", 0)

    # Retransmission analysis
    retrans = result.retrans_analysis
    print(f"\n--- Retransmission Analysis ---")
    print(f"Client Total Retransmissions: {retrans.total_retrans_client}")
    print(f"Client Retrans Rate (packets): {retrans.retrans_rate_client:.3f}%")
    print(f"Client Retrans Bytes Rate: {retrans.retrans_bytes_rate_client:.3f}%")
    print(f"Client Retransmission Rate Statistics:")
    _print_basic_stats(retrans.client_retrans_rate_stats, "%", 4)
    print(f"Client Breakdown: Fast {retrans.fast_retrans_ratio_client*100:.1f}%, Timeout {retrans.timeout_retrans_ratio_client*100:.1f}%, "
          f"Spurious {retrans.spurious_retrans_ratio_client*100:.1f}% (count={retrans.spurious_retrans_count_client})")
    print(f"\nServer Total Retransmissions: {retrans.total_retrans_server}")
    print(f"Server Retrans Rate (packets): {retrans.retrans_rate_server:.3f}%")
    print(f"Server Retrans Bytes Rate: {retrans.retrans_bytes_rate_server:.3f}%")
    print(f"Server Retransmission Rate Statistics:")
    _print_basic_stats(retrans.server_retrans_rate_stats, "%", 4)
    print(f"Server Breakdown: Fast {retrans.fast_retrans_ratio_server*100:.1f}% (heuristic), "
          f"Timeout {retrans.timeout_retrans_ratio_server*100:.1f}% (heuristic), "
          f"Spurious {retrans.spurious_retrans_ratio_server*100:.1f}% (count={retrans.spurious_retrans_count_server})")

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
        description='TCP Socket Performance Analyzer - Dual-Side Analysis Tool\n\n'
                    'This tool requires BOTH client-side and server-side TCP socket measurements\n'
                    'of the SAME connection during the SAME time period for accurate analysis.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Summary mode - dual-side analysis
  %(prog)s --mode summary --client-log client-socket.log --server-log server-socket.log --bandwidth 25gbps

  # Detailed mode with timeseries export
  %(prog)s --mode detailed --client-log client-socket.log --server-log server-socket.log --export-timeseries

  # Pipeline mode for bottleneck analysis
  %(prog)s --mode pipeline --client-log client-socket.log --server-log server-socket.log --bandwidth 10gbps

  # Export parsed socket data to CSV files
  %(prog)s --mode summary --client-log client-socket.log --server-log server-socket.log --export-csv --csv-output-dir ./output

IMPORTANT:
  This tool performs DUAL-SIDE analysis and requires:
  - Client-side socket log: measurements from the data sender (e.g., iperf3 client)
  - Server-side socket log: measurements from the data receiver (e.g., iperf3 server)
  - Both logs must measure the SAME TCP connection (matching src/dst IPs and ports)
  - Both logs must cover the SAME time period for accurate time-alignment
  - Single-side analysis mode is NOT supported
        """
    )

    # Required arguments
    parser.add_argument(
        '--mode',
        choices=['summary', 'detailed', 'pipeline'],
        required=True,
        help='Analysis mode (summary/detailed/pipeline)'
    )
    parser.add_argument(
        '--client-log',
        required=True,
        metavar='FILE',
        help='Path to client-side socket log file (required for dual-side analysis)'
    )
    parser.add_argument(
        '--server-log',
        required=True,
        metavar='FILE',
        help='Path to server-side socket log file (required for dual-side analysis)'
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
        '--export-csv',
        action='store_true',
        help='Export parsed socket data to CSV files in the output directory'
    )
    parser.add_argument(
        '--csv-output-dir',
        help='Directory to save CSV files (default: same as log directory)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output'
    )

    args = parser.parse_args()

    # Validate log file paths
    import os
    if not os.path.exists(args.client_log):
        print_error(f"Client log file not found: {args.client_log}")
        sys.exit(1)
    if not os.path.isfile(args.client_log):
        print_error(f"Client log path is not a file: {args.client_log}")
        sys.exit(1)
    if not os.access(args.client_log, os.R_OK):
        print_error(f"Client log file not readable: {args.client_log}")
        sys.exit(1)

    if not os.path.exists(args.server_log):
        print_error(f"Server log file not found: {args.server_log}")
        sys.exit(1)
    if not os.path.isfile(args.server_log):
        print_error(f"Server log path is not a file: {args.server_log}")
        sys.exit(1)
    if not os.access(args.server_log, os.R_OK):
        print_error(f"Server log file not readable: {args.server_log}")
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
