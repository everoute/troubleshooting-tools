#!/usr/bin/env python
"""
Summary Analyzer

Main analyzer for Summary mode providing window, rate, RTT, buffer, and bottleneck analysis.
Implements FR-SOCKET-SUM-003~010.
"""

from typing import List, Optional
import pandas as pd

from ..models import (
    BasicStats,
    WindowAnalysisResult,
    RateAnalysisResult,
    RTTAnalysisResult,
    BufferAnalysisResult,
    LimitAnalysisResult,
    RetransAnalysisResult,
    BottleneckIdentification,
    SummaryResult,
    FiveTuple
)
from ..statistics.timeseries_stats import TimeSeriesStats


class SummaryAnalyzer:
    """Summary mode main analyzer"""

    def __init__(self):
        """Initialize summary analyzer"""
        self.stats_engine = TimeSeriesStats()

    def analyze(
        self,
        client_df: pd.DataFrame,
        server_df: pd.DataFrame,
        aligned_df: pd.DataFrame,
        bandwidth: float,
        connection: FiveTuple
    ) -> SummaryResult:
        """
        Perform complete summary analysis

        Args:
            client_df: Client-side DataFrame
            server_df: Server-side DataFrame
            aligned_df: Time-aligned DataFrame
            bandwidth: Network bandwidth in bps
            connection: Connection five-tuple

        Returns:
            SummaryResult with all analyses
        """
        # Perform individual analyses
        window_analysis = self.analyze_window(client_df, server_df, bandwidth)
        rate_analysis = self.analyze_rate(client_df, server_df, bandwidth)
        rtt_analysis = self.analyze_rtt(client_df, server_df)
        buffer_analysis = self.analyze_buffer(client_df, server_df)
        limit_analysis = self.analyze_limits(client_df, server_df)
        retrans_analysis = self.analyze_retrans(client_df, server_df)

        # Identify bottlenecks
        bottleneck = self.identify_bottlenecks(
            window_analysis,
            rate_analysis,
            buffer_analysis
        )

        return SummaryResult(
            connection=connection,
            window_analysis=window_analysis,
            rate_analysis=rate_analysis,
            rtt_analysis=rtt_analysis,
            buffer_analysis=buffer_analysis,
            limit_analysis=limit_analysis,
            retrans_analysis=retrans_analysis,
            bottleneck=bottleneck,
            recommendations=[]  # Will be filled by RecommendationEngine
        )

    def analyze_window(
        self,
        client_df: pd.DataFrame,
        server_df: pd.DataFrame,
        bandwidth: float
    ) -> WindowAnalysisResult:
        """
        Window analysis

        Analyzes:
        1. BDP calculation: BDP = Bandwidth × RTT
        2. Optimal CWND: Optimal_CWND = BDP / MSS
        3. CWND utilization: actual_cwnd / optimal_cwnd

        Args:
            client_df: Client-side DataFrame
            server_df: Server-side DataFrame
            bandwidth: Network bandwidth in bps

        Returns:
            WindowAnalysisResult with window metrics

        Implements: FR-SOCKET-SUM-003, FR-SOCKET-SUM-006
        """
        # CWND statistics
        client_cwnd_stats = self.stats_engine.compute_basic_stats(client_df['cwnd'])
        server_cwnd_stats = self.stats_engine.compute_basic_stats(server_df['cwnd'])

        # Calculate BDP using dual-side RTT average
        avg_rtt_ms = (
            client_df['rtt'].mean() + server_df['rtt'].mean()
        ) / 2.0
        avg_rtt = avg_rtt_ms / 1000.0  # Convert ms to seconds
        bdp = bandwidth * avg_rtt / 8  # bits → bytes

        # Optimal CWND
        mss = 1460  # Standard MSS
        optimal_cwnd = bdp / mss

        # Actual CWND
        actual_cwnd = client_cwnd_stats.mean

        # CWND utilization
        cwnd_utilization = actual_cwnd / optimal_cwnd if optimal_cwnd > 0 else 0.0

        # cwnd/ssthresh 比值分布（慢启动 vs 拥塞避免/快速恢复）
        if 'ssthresh' in client_df.columns and len(client_df['ssthresh']) > 0:
            ratio_series = client_df['cwnd'] / client_df['ssthresh']
            slow_start_ratio = (ratio_series < 1).mean()
            ca_fastrecovery_ratio = (ratio_series >= 1).mean()
        else:
            slow_start_ratio = 0.0
            ca_fastrecovery_ratio = 0.0

        # RWND analysis
        rwnd_min = client_df['rwnd'].min() if 'rwnd' in client_df.columns else 0.0
        rwnd_avg = client_df['rwnd'].mean() if 'rwnd' in client_df.columns else 0.0

        # RWND limited ratio (when CWND >= RWND)
        if 'rwnd' in client_df.columns:
            rwnd_limited = (client_df['cwnd'] >= client_df['rwnd']).mean()
        else:
            rwnd_limited = 0.0

        # SSTHRESH analysis
        ssthresh_avg = client_df['ssthresh'].mean() if 'ssthresh' in client_df.columns else 0.0
        cwnd_ssthresh_ratio = actual_cwnd / ssthresh_avg if ssthresh_avg > 0 else 0.0

        return WindowAnalysisResult(
            client_cwnd_stats=client_cwnd_stats,
            server_cwnd_stats=server_cwnd_stats,
            bdp=bdp,
            optimal_cwnd=optimal_cwnd,
            actual_cwnd=actual_cwnd,
            cwnd_utilization=cwnd_utilization,
            cwnd_ssthresh_distribution={
                '<1': slow_start_ratio,
                '>=1': ca_fastrecovery_ratio
            },
            rwnd_min=rwnd_min,
            rwnd_avg=rwnd_avg,
            rwnd_limited_ratio=rwnd_limited,
            ssthresh_avg=ssthresh_avg,
            cwnd_ssthresh_ratio=cwnd_ssthresh_ratio
        )

    def analyze_rate(
        self,
        client_df: pd.DataFrame,
        server_df: pd.DataFrame,
        bandwidth: float
    ) -> RateAnalysisResult:
        """
        Rate analysis

        Analyzes:
        1. Pacing Rate and Delivery Rate statistics
        2. Bandwidth utilization
        3. Rate ratios

        Args:
            client_df: Client-side DataFrame
            server_df: Server-side DataFrame
            bandwidth: Network bandwidth in bps

        Returns:
            RateAnalysisResult with rate metrics

        Implements: FR-SOCKET-SUM-004, FR-SOCKET-SUM-007
        """
        # Pacing Rate statistics
        pacing_rate_stats = self.stats_engine.compute_basic_stats(
            client_df['pacing_rate'] if 'pacing_rate' in client_df.columns
            else pd.Series([0])
        )

        # Delivery Rate statistics
        delivery_rate_stats = self.stats_engine.compute_basic_stats(
            client_df['delivery_rate'] if 'delivery_rate' in client_df.columns
            else pd.Series([0])
        )

        # Send Rate statistics if available
        send_rate_stats = self.stats_engine.compute_basic_stats(
            client_df['send_rate']
        ) if 'send_rate' in client_df.columns else None

        # Bandwidth utilization
        avg_bw_util = delivery_rate_stats.mean / bandwidth if bandwidth > 0 else 0.0
        peak_bw_util = delivery_rate_stats.max / bandwidth if bandwidth > 0 else 0.0

        # Pacing/Delivery ratio
        pacing_delivery_ratio = (
            pacing_rate_stats.mean / delivery_rate_stats.mean
            if delivery_rate_stats.mean > 0 else 0.0
        )

        # Rate stability (inverse of CV)
        rate_stability = 1.0 - delivery_rate_stats.cv if delivery_rate_stats.cv < 1.0 else 0.0

        return RateAnalysisResult(
            pacing_rate_stats=pacing_rate_stats,
            delivery_rate_stats=delivery_rate_stats,
            send_rate_stats=send_rate_stats,
            avg_bandwidth_utilization=avg_bw_util,
            peak_bandwidth_utilization=peak_bw_util,
            pacing_delivery_ratio=pacing_delivery_ratio,
            rate_stability=rate_stability
        )

    def analyze_rtt(
        self,
        client_df: pd.DataFrame,
        server_df: pd.DataFrame
    ) -> RTTAnalysisResult:
        """
        RTT stability analysis (dual-side)

        Stability criteria:
        - CV < 0.3: STABLE
        - 0.3 <= CV < 0.6: UNSTABLE
        - >= 0.6: HIGHLY_VARIABLE

        Implements: FR-SOCKET-SUM-005
        """
        client_rtt_stats = self.stats_engine.compute_basic_stats(client_df['rtt'])
        server_rtt_stats = self.stats_engine.compute_basic_stats(server_df['rtt'])

        # Use client RTT for stability (sender-side is usually critical)
        rtt_cv = client_rtt_stats.cv
        if rtt_cv < 0.3:
            rtt_stability = 'STABLE'
        elif rtt_cv < 0.6:
            rtt_stability = 'UNSTABLE'
        else:
            rtt_stability = 'HIGHLY_VARIABLE'

        # Jitter = std dev (ms)
        jitter = client_rtt_stats.std

        # Trend detection (client)
        rtt_trend = self.stats_engine.detect_trend(client_df['rtt'])

        # Client/Server差异
        rtt_diff = client_rtt_stats.mean - server_rtt_stats.mean
        asymmetry = 'ASYMMETRIC' if abs(rtt_diff) > max(client_rtt_stats.std, 1) else 'SYMMETRIC'

        return RTTAnalysisResult(
            client_rtt_stats=client_rtt_stats,
            server_rtt_stats=server_rtt_stats,
            rtt_stability=rtt_stability,
            jitter=jitter,
            rtt_trend=rtt_trend,
            rtt_diff=rtt_diff,
            asymmetry=asymmetry
        )

    def analyze_buffer(
        self,
        client_df: pd.DataFrame,
        server_df: pd.DataFrame
    ) -> BufferAnalysisResult:
        """Buffer pressure analysis (send & receive). Implements FR-SOCKET-SUM-009"""

        # Raw q stats (from SS send_q/recv_q)
        send_q_stats = self.stats_engine.compute_basic_stats(
            client_df['send_q'] if 'send_q' in client_df.columns else pd.Series([0])
        )
        recv_q_stats = self.stats_engine.compute_basic_stats(
            server_df['recv_q'] if 'recv_q' in server_df.columns else pd.Series([0])
        )

        # Send buffer analysis
        if 'socket_tx_queue' in client_df.columns:
            send_queue_stats = self.stats_engine.compute_basic_stats(client_df['socket_tx_queue'])
            send_buffer_size = client_df['socket_tx_buffer'].mean() if 'socket_tx_buffer' in client_df.columns else 0.0
            if send_buffer_size > 0:
                send_pressure = (client_df['socket_tx_queue'] / client_df['socket_tx_buffer']).mean()
                send_limited_ratio = (
                    client_df['socket_tx_queue'] >= client_df['socket_tx_buffer'] * 0.95
                ).mean()
            else:
                send_pressure = 0.0
                send_limited_ratio = 0.0
        else:
            send_queue_stats = self.stats_engine.compute_basic_stats(pd.Series([0]))
            send_buffer_size = 0.0
            send_pressure = 0.0
            send_limited_ratio = 0.0

        # Receive buffer analysis (server side)
        if 'socket_rx_queue' in server_df.columns:
            recv_queue_stats = self.stats_engine.compute_basic_stats(server_df['socket_rx_queue'])
            recv_buffer_size = server_df['socket_rx_buffer'].mean() if 'socket_rx_buffer' in server_df.columns else 0.0
            if recv_buffer_size > 0:
                recv_pressure = (server_df['socket_rx_queue'] / server_df['socket_rx_buffer']).mean()
                recv_limited_ratio = (
                    server_df['socket_rx_queue'] >= server_df['socket_rx_buffer'] * 0.95
                ).mean()
            else:
                recv_pressure = 0.0
                recv_limited_ratio = 0.0
        else:
            recv_queue_stats = self.stats_engine.compute_basic_stats(pd.Series([0]))
            recv_buffer_size = 0.0
            recv_pressure = 0.0
            recv_limited_ratio = 0.0

        # Additional send-side queue/backlog/drop stats
        write_queue_stats = self.stats_engine.compute_basic_stats(
            client_df['socket_write_queue']
        ) if 'socket_write_queue' in client_df.columns else self.stats_engine.compute_basic_stats(pd.Series([0]))
        backlog_stats = self.stats_engine.compute_basic_stats(
            client_df['socket_backlog']
        ) if 'socket_backlog' in client_df.columns else self.stats_engine.compute_basic_stats(pd.Series([0]))
        dropped_stats = self.stats_engine.compute_basic_stats(
            client_df['socket_dropped']
        ) if 'socket_dropped' in client_df.columns else self.stats_engine.compute_basic_stats(pd.Series([0]))

        # Server side additional queue/backlog/drop stats
        server_write_queue_stats = self.stats_engine.compute_basic_stats(
            server_df['socket_write_queue']
        ) if 'socket_write_queue' in server_df.columns else self.stats_engine.compute_basic_stats(pd.Series([0]))
        server_backlog_stats = self.stats_engine.compute_basic_stats(
            server_df['socket_backlog']
        ) if 'socket_backlog' in server_df.columns else self.stats_engine.compute_basic_stats(pd.Series([0]))
        server_dropped_stats = self.stats_engine.compute_basic_stats(
            server_df['socket_dropped']
        ) if 'socket_dropped' in server_df.columns else self.stats_engine.compute_basic_stats(pd.Series([0]))

        return BufferAnalysisResult(
            send_buffer_size=send_buffer_size,
            send_queue_stats=send_queue_stats,
            send_buffer_pressure=send_pressure,
            recv_buffer_size=recv_buffer_size,
            recv_queue_stats=recv_queue_stats,
            recv_buffer_pressure=recv_pressure,
            send_q_stats=send_q_stats,
            recv_q_stats=recv_q_stats,
            write_queue_stats=write_queue_stats,
            backlog_stats=backlog_stats,
            dropped_stats=dropped_stats,
            write_queue_stats_server=server_write_queue_stats,
            backlog_stats_server=server_backlog_stats,
            dropped_stats_server=server_dropped_stats,
            send_buffer_limited_ratio=send_limited_ratio,
            recv_buffer_limited_ratio=recv_limited_ratio
        )

    def analyze_limits(
        self,
        client_df: pd.DataFrame,
        server_df: pd.DataFrame
    ) -> LimitAnalysisResult:
        """Analyze busy time and limited ratios directly from raw fields."""

        def _stats(df: pd.DataFrame, column: str) -> BasicStats:
            if column in df.columns:
                return self.stats_engine.compute_basic_stats(df[column])
            return self.stats_engine.compute_basic_stats(pd.Series([0]))

        def _ratio(df: pd.DataFrame, column: str) -> float:
            return float(df[column].mean()) if column in df.columns else 0.0

        return LimitAnalysisResult(
            busy_time_stats_client=_stats(client_df, 'busy_time'),
            busy_time_stats_server=_stats(server_df, 'busy_time'),
            cwnd_limited_ratio_client=_ratio(client_df, 'cwnd_limited_ratio'),
            cwnd_limited_ratio_server=_ratio(server_df, 'cwnd_limited_ratio'),
            rwnd_limited_ratio_client=_ratio(client_df, 'rwnd_limited_ratio'),
            rwnd_limited_ratio_server=_ratio(server_df, 'rwnd_limited_ratio'),
            sndbuf_limited_ratio_client=_ratio(client_df, 'sndbuf_limited_ratio'),
            sndbuf_limited_ratio_server=_ratio(server_df, 'sndbuf_limited_ratio'),
            cwnd_limited_time_stats_client=_stats(client_df, 'cwnd_limited_time'),
            cwnd_limited_time_stats_server=_stats(server_df, 'cwnd_limited_time'),
            rwnd_limited_time_stats_client=_stats(client_df, 'rwnd_limited_time'),
            rwnd_limited_time_stats_server=_stats(server_df, 'rwnd_limited_time'),
            sndbuf_limited_time_stats_client=_stats(client_df, 'sndbuf_limited_time'),
            sndbuf_limited_time_stats_server=_stats(server_df, 'sndbuf_limited_time')
        )

    def analyze_retrans(
        self,
        client_df: pd.DataFrame,
        server_df: pd.DataFrame
    ) -> RetransAnalysisResult:
        """Retransmission analysis. Implements FR-SOCKET-SUM-008"""
        def _compute_side(df: pd.DataFrame):
            # Prefer cumulative retrans_total if present, otherwise use retrans column
            if 'retrans_total' in df.columns and df['retrans_total'].notna().any():
                base = df['retrans_total'].dropna()
                total = int(base.max() - base.min()) if len(base) else 0
                incr_series = base.diff().fillna(0).clip(lower=0)
            else:
                series = df['retrans'] if 'retrans' in df.columns else pd.Series([0])
                total = int(series.max()) if len(series) else 0
                incr_series = series.diff().fillna(series).clip(lower=0)

            # Rate stats based on per-sample increments (percentage values if already provided)
            rate_series = df['retrans_rate'] if 'retrans_rate' in df.columns else incr_series
            rate_stats = self.stats_engine.compute_basic_stats(rate_series)

            # Total packets sent for % calculation
            if 'data_segs_out' in df.columns and df['data_segs_out'].notna().any():
                packets_total = df['data_segs_out'].max() - df['data_segs_out'].min()
            elif 'segs_out' in df.columns and df['segs_out'].notna().any():
                packets_total = df['segs_out'].max() - df['segs_out'].min()
            else:
                packets_total = 0

            rate_pct = (total / packets_total * 100) if packets_total > 0 else rate_stats.mean

            # Bytes retrans if available
            if 'bytes_retrans' in df.columns and 'bytes_sent' in df.columns and df['bytes_sent'].max() > 0:
                bytes_rate = (df['bytes_retrans'].max() - df['bytes_retrans'].min()) / df['bytes_sent'].max() * 100
            else:
                bytes_rate = 0.0

            spurious_count = int(df['spurious_retrans_rate'].sum()) if 'spurious_retrans_rate' in df.columns else 0
            spurious_rate_stats = self.stats_engine.compute_basic_stats(
                df['spurious_retrans_rate']
            ) if 'spurious_retrans_rate' in df.columns else self.stats_engine.compute_basic_stats(pd.Series([0]))

            spurious_ratio = min(1.0, spurious_count / total) if total > 0 else 0.0

            # SACK/DSACK counts (compute deltas to avoid cumulative start)
            if 'sacked' in df.columns and df['sacked'].notna().any():
                sacked_packets = int(df['sacked'].max() - df['sacked'].min())
            else:
                sacked_packets = 0

            if 'dsack_dups' in df.columns and df['dsack_dups'].notna().any():
                dsack_dups = int(df['dsack_dups'].max() - df['dsack_dups'].min())
            else:
                dsack_dups = 0

            return (
                rate_stats,
                total,
                rate_pct,
                bytes_rate,
                spurious_count,
                spurious_ratio,
                sacked_packets,
                dsack_dups,
                spurious_rate_stats
            )

        (
            c_stats,
            c_total,
            c_rate_pct,
            c_bytes_rate,
            c_spurious,
            c_spurious_ratio,
            c_sacked,
            c_dsack,
            c_spurious_rate_stats
        ) = _compute_side(client_df)

        (
            s_stats,
            s_total,
            s_rate_pct,
            s_bytes_rate,
            s_spurious,
            s_spurious_ratio,
            s_sacked,
            s_dsack,
            s_spurious_rate_stats
        ) = _compute_side(server_df)

        return RetransAnalysisResult(
            client_retrans_rate_stats=c_stats,
            server_retrans_rate_stats=s_stats,
            total_retrans_client=c_total,
            total_retrans_server=s_total,
            retrans_rate_client=c_rate_pct,
            retrans_rate_server=s_rate_pct,
            retrans_bytes_rate_client=c_bytes_rate,
            retrans_bytes_rate_server=s_bytes_rate,
            spurious_retrans_count_client=c_spurious,
            spurious_retrans_count_server=s_spurious,
            spurious_retrans_ratio_client=c_spurious_ratio,
            spurious_retrans_ratio_server=s_spurious_ratio,
            sacked_packets_client=c_sacked,
            sacked_packets_server=s_sacked,
            dsack_dups_client=c_dsack,
            dsack_dups_server=s_dsack,
            spurious_retrans_rate_stats_client=c_spurious_rate_stats,
            spurious_retrans_rate_stats_server=s_spurious_rate_stats
        )

    def identify_bottlenecks(
        self,
        window_result: WindowAnalysisResult,
        rate_result: RateAnalysisResult,
        buffer_result: BufferAnalysisResult
    ) -> BottleneckIdentification:
        """
        Identify primary performance bottleneck

        Bottleneck types:
        1. CWND_LIMITED: cwnd_utilization > 0.9
        2. BUFFER_LIMITED: buffer_pressure > 0.8
        3. NETWORK_LIMITED: bandwidth_utilization > 0.9
        4. APP_LIMITED: other cases

        Args:
            window_result: Window analysis result
            rate_result: Rate analysis result
            buffer_result: Buffer analysis result

        Returns:
            BottleneckIdentification with primary bottleneck

        Implements: FR-SOCKET-SUM-010
        """
        limiting_factors = []
        scores = {}

        # Check CWND limitation
        if window_result.cwnd_utilization > 0.9:
            limiting_factors.append('CWND_LIMITED')
            scores['CWND_LIMITED'] = window_result.cwnd_utilization

        # Check buffer limitation
        if buffer_result.send_buffer_pressure > 0.8 or buffer_result.recv_buffer_pressure > 0.8:
            limiting_factors.append('BUFFER_LIMITED')
            scores['BUFFER_LIMITED'] = max(
                buffer_result.send_buffer_pressure,
                buffer_result.recv_buffer_pressure
            )

        # Check network bandwidth limitation
        if rate_result.avg_bandwidth_utilization > 0.9:
            limiting_factors.append('NETWORK_LIMITED')
            scores['NETWORK_LIMITED'] = rate_result.avg_bandwidth_utilization

        # Determine primary bottleneck
        if scores:
            primary_bottleneck = max(scores, key=scores.get)
            confidence = min(1.0, scores[primary_bottleneck])
        else:
            primary_bottleneck = 'APP_LIMITED'
            confidence = 0.5

        return BottleneckIdentification(
            primary_bottleneck=primary_bottleneck,
            bottleneck_confidence=confidence,
            limiting_factors=limiting_factors
        )
