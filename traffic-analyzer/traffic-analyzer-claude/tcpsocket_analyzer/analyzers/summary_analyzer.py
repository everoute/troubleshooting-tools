#!/usr/bin/env python
"""
Summary Analyzer

Main analyzer for Summary mode providing window, rate, RTT, buffer, and bottleneck analysis.
Implements FR-SOCKET-SUM-003~010.
"""

from typing import List
import pandas as pd

from ..models import (
    WindowAnalysisResult,
    RateAnalysisResult,
    RTTAnalysisResult,
    BufferAnalysisResult,
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

        # Calculate BDP
        avg_rtt = client_df['rtt'].mean() / 1000.0  # Convert ms to seconds
        bdp = bandwidth * avg_rtt / 8  # Convert bits to bytes

        # Optimal CWND
        mss = 1460  # Standard MSS
        optimal_cwnd = bdp / mss

        # Actual CWND
        actual_cwnd = client_cwnd_stats.mean

        # CWND utilization
        cwnd_utilization = actual_cwnd / optimal_cwnd if optimal_cwnd > 0 else 0.0

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
        RTT stability analysis

        Stability criteria:
        - CV < 0.3: STABLE
        - CV >= 0.3: UNSTABLE

        Args:
            client_df: Client-side DataFrame
            server_df: Server-side DataFrame

        Returns:
            RTTAnalysisResult with RTT metrics

        Implements: FR-SOCKET-SUM-005
        """
        # RTT statistics
        rtt_stats = self.stats_engine.compute_basic_stats(client_df['rtt'])

        # Stability classification
        if rtt_stats.cv < 0.3:
            rtt_stability = 'STABLE'
        elif rtt_stats.cv < 0.6:
            rtt_stability = 'UNSTABLE'
        else:
            rtt_stability = 'HIGHLY_VARIABLE'

        # Trend detection
        rtt_trend = self.stats_engine.detect_trend(client_df['rtt'])

        return RTTAnalysisResult(
            rtt_stats=rtt_stats,
            rtt_stability=rtt_stability,
            rtt_trend=rtt_trend
        )

    def analyze_buffer(
        self,
        client_df: pd.DataFrame,
        server_df: pd.DataFrame
    ) -> BufferAnalysisResult:
        """
        Buffer pressure analysis

        Pressure calculation:
        Pressure = socket_queue / socket_buffer

        Args:
            client_df: Client-side DataFrame
            server_df: Server-side DataFrame

        Returns:
            BufferAnalysisResult with buffer metrics

        Implements: FR-SOCKET-SUM-009
        """
        # Send buffer analysis
        if 'socket_tx_queue' in client_df.columns:
            send_queue_stats = self.stats_engine.compute_basic_stats(
                client_df['socket_tx_queue']
            )
            send_buffer_size = client_df['socket_tx_buffer'].mean() if 'socket_tx_buffer' in client_df.columns else 0.0

            # Calculate pressure
            if 'socket_tx_buffer' in client_df.columns:
                send_pressure = (
                    client_df['socket_tx_queue'] / client_df['socket_tx_buffer']
                ).mean()
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

        # Receive buffer analysis
        if 'socket_rx_queue' in server_df.columns:
            recv_queue_stats = self.stats_engine.compute_basic_stats(
                server_df['socket_rx_queue']
            )
            recv_buffer_size = server_df['socket_rx_buffer'].mean() if 'socket_rx_buffer' in server_df.columns else 0.0

            # Calculate pressure
            if 'socket_rx_buffer' in server_df.columns:
                recv_pressure = (
                    server_df['socket_rx_queue'] / server_df['socket_rx_buffer']
                ).mean()
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

        return BufferAnalysisResult(
            send_buffer_size=send_buffer_size,
            send_queue_stats=send_queue_stats,
            send_buffer_pressure=send_pressure,
            recv_buffer_size=recv_buffer_size,
            recv_queue_stats=recv_queue_stats,
            recv_buffer_pressure=recv_pressure,
            send_buffer_limited_ratio=send_limited_ratio,
            recv_buffer_limited_ratio=recv_limited_ratio
        )

    def analyze_retrans(
        self,
        client_df: pd.DataFrame,
        server_df: pd.DataFrame
    ) -> RetransAnalysisResult:
        """
        Retransmission analysis

        Args:
            client_df: Client-side DataFrame
            server_df: Server-side DataFrame

        Returns:
            RetransAnalysisResult with retransmission metrics

        Implements: FR-SOCKET-SUM-008
        """
        # Retransmission rate statistics
        if 'retrans_rate' in client_df.columns:
            retrans_rate_stats = self.stats_engine.compute_basic_stats(
                client_df['retrans_rate']
            )
        else:
            retrans_rate_stats = self.stats_engine.compute_basic_stats(pd.Series([0]))

        # Total retransmissions
        total_retrans = int(client_df['retrans'].max()) if 'retrans' in client_df.columns else 0

        # Placeholder ratios (would need more detailed data)
        fast_retrans_ratio = 0.7  # Typical ratio
        timeout_retrans_ratio = 0.2
        spurious_retrans_ratio = 0.1

        return RetransAnalysisResult(
            retrans_rate_stats=retrans_rate_stats,
            total_retrans=total_retrans,
            fast_retrans_ratio=fast_retrans_ratio,
            timeout_retrans_ratio=timeout_retrans_ratio,
            spurious_retrans_ratio=spurious_retrans_ratio
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
            confidence = scores[primary_bottleneck]
        else:
            primary_bottleneck = 'APP_LIMITED'
            confidence = 0.5

        return BottleneckIdentification(
            primary_bottleneck=primary_bottleneck,
            bottleneck_confidence=confidence,
            limiting_factors=limiting_factors
        )
