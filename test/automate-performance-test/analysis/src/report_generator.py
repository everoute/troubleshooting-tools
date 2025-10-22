"""Report Generator - Generate analysis reports in various formats"""

import os
import csv
import logging
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generator for analysis reports"""

    def __init__(self, output_dir: str):
        """Initialize ReportGenerator

        Args:
            output_dir: Output directory for reports
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, topic: str, results: List[Dict], iteration: str, formats: List[str] = None):
        """Generate reports in specified formats

        Args:
            topic: Topic name
            results: List of analysis results for all tool cases
            iteration: Iteration name
            formats: List of output formats (default: ["csv", "markdown"])
        """
        if formats is None:
            formats = ["csv", "markdown"]

        if "csv" in formats:
            self.generate_csv(topic, results, iteration)

        if "markdown" in formats:
            self.generate_markdown(topic, results, iteration)

        logger.info(f"Generated {len(formats)} report(s) for topic {topic}")

    def generate_csv(self, topic: str, results: List[Dict], iteration: str):
        """Generate CSV report

        Args:
            topic: Topic name
            results: List of analysis results
            iteration: Iteration name
        """
        output_path = os.path.join(self.output_dir, f"{topic}_summary_{iteration}.csv")

        # Define headers
        headers = self._get_csv_headers()

        # Extract rows
        rows = []
        for result in results:
            row = self._extract_row_data(result)
            if row:
                rows.append(row)

        # Write CSV
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(rows)

            logger.info(f"Generated CSV report: {output_path}")
        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")

    def generate_markdown(self, topic: str, results: List[Dict], iteration: str):
        """Generate Markdown report

        Args:
            topic: Topic name
            results: List of analysis results
            iteration: Iteration name
        """
        output_path = os.path.join(self.output_dir, f"{topic}_summary_{iteration}.md")

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                # Write header
                f.write(f"# {topic.replace('_', ' ').title()} - Summary Report\n\n")
                f.write(f"**Iteration:** {iteration}\n")
                f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Total Cases:** {len(results)}\n\n")

                # Write table
                f.write(self._generate_markdown_table(results))

                # Write notes
                f.write("\n\n## Notes\n\n")
                f.write("- Positive diff% for latency indicates performance degradation (higher latency)\n")
                f.write("- Negative diff% for throughput/PPS indicates performance degradation (lower throughput/PPS)\n")
                f.write("- N/A indicates missing data\n")

            logger.info(f"Generated Markdown report: {output_path}")
        except Exception as e:
            logger.error(f"Failed to generate Markdown report: {e}")

    def _get_csv_headers(self) -> List[str]:
        """Get CSV column headers

        Returns:
            List of header strings
        """
        return [
            "Tool Case",
            "Protocol",
            "Direction",
            # Latency
            "Latency TCP Mean (us)",
            "Latency TCP Diff (%)",
            "Latency UDP Mean (us)",
            "Latency UDP Diff (%)",
            # Throughput - Client
            "Throughput Single Client (Gbps)",
            "Throughput Single Client Diff (%)",
            "Throughput Multi Client (Gbps)",
            "Throughput Multi Client Diff (%)",
            # Throughput - Server
            "Throughput Single Server (Gbps)",
            "Throughput Single Server Diff (%)",
            "Throughput Multi Server (Gbps)",
            "Throughput Multi Server Diff (%)",
            # PPS - Client
            "PPS Single Client",
            "PPS Single Client Diff (%)",
            "PPS Multi Client",
            "PPS Multi Client Diff (%)",
            # PPS - Server
            "PPS Single Server",
            "PPS Single Server Diff (%)",
            "PPS Multi Server",
            "PPS Multi Server Diff (%)",
            # eBPF Resources - PPS workload
            "CPU Avg (%) - PPS Single",
            "CPU Max (%) - PPS Single",
            "Memory Max (KB) - PPS Single",
            "CPU Avg (%) - PPS Multi",
            "CPU Max (%) - PPS Multi",
            "Memory Max (KB) - PPS Multi",
            # eBPF Resources - Throughput workload
            "CPU Avg (%) - TP Single",
            "CPU Max (%) - TP Single",
            "Memory Max (KB) - TP Single",
            "CPU Avg (%) - TP Multi",
            "CPU Max (%) - TP Multi",
            "Memory Max (KB) - TP Multi",
            # Full cycle
            "Max RSS (KB)",
            "Max VSZ (KB)",
            "Log Size (Bytes)"
        ]

    def _extract_row_data(self, result: Dict) -> List:
        """Extract row data from analysis result

        Args:
            result: Analysis result dictionary

        Returns:
            List of values for CSV row
        """
        def safe_get(d, *keys, default="N/A"):
            """Safely get nested dictionary value"""
            for key in keys:
                if isinstance(d, dict) and key in d:
                    d = d[key]
                else:
                    return default
            return d if d is not None else default

        metadata = result.get("metadata", {})
        perf = result.get("performance", {})
        comparison = result.get("comparison", {})
        resources = result.get("resources", {})
        logs = result.get("logs", {})

        row = [
            result.get("tool_case", "N/A"),
            metadata.get("protocol", "N/A"),
            metadata.get("direction", "N/A"),
        ]

        # Latency
        row.extend([
            safe_get(comparison, "latency", "tcp_rr_mean_us", "ebpf"),
            safe_get(comparison, "latency", "tcp_rr_mean_us", "diff_percent"),
            safe_get(comparison, "latency", "udp_rr_mean_us", "ebpf"),
            safe_get(comparison, "latency", "udp_rr_mean_us", "diff_percent"),
        ])

        # Throughput - Client
        row.extend([
            safe_get(comparison, "throughput_client", "single_gbps", "ebpf"),
            safe_get(comparison, "throughput_client", "single_gbps", "diff_percent"),
            safe_get(comparison, "throughput_client", "multi_gbps", "ebpf"),
            safe_get(comparison, "throughput_client", "multi_gbps", "diff_percent"),
        ])

        # Throughput - Server
        row.extend([
            safe_get(comparison, "throughput_server", "single_gbps", "ebpf"),
            safe_get(comparison, "throughput_server", "single_gbps", "diff_percent"),
            safe_get(comparison, "throughput_server", "multi_gbps", "ebpf"),
            safe_get(comparison, "throughput_server", "multi_gbps", "diff_percent"),
        ])

        # PPS - Client
        row.extend([
            safe_get(comparison, "pps_client", "single_pps", "ebpf"),
            safe_get(comparison, "pps_client", "single_pps", "diff_percent"),
            safe_get(comparison, "pps_client", "multi_pps", "ebpf"),
            safe_get(comparison, "pps_client", "multi_pps", "diff_percent"),
        ])

        # PPS - Server
        row.extend([
            safe_get(comparison, "pps_server", "single_pps", "ebpf"),
            safe_get(comparison, "pps_server", "single_pps", "diff_percent"),
            safe_get(comparison, "pps_server", "multi_pps", "ebpf"),
            safe_get(comparison, "pps_server", "multi_pps", "diff_percent"),
        ])

        # eBPF Resources - PPS workload
        row.extend([
            safe_get(resources, "time_range_stats", "pps_single", "cpu", "avg_percent"),
            safe_get(resources, "time_range_stats", "pps_single", "cpu", "max_percent"),
            safe_get(resources, "time_range_stats", "pps_single", "memory", "max_rss_kb"),
            safe_get(resources, "time_range_stats", "pps_multi", "cpu", "avg_percent"),
            safe_get(resources, "time_range_stats", "pps_multi", "cpu", "max_percent"),
            safe_get(resources, "time_range_stats", "pps_multi", "memory", "max_rss_kb"),
        ])

        # eBPF Resources - Throughput workload
        row.extend([
            safe_get(resources, "time_range_stats", "throughput_single", "cpu", "avg_percent"),
            safe_get(resources, "time_range_stats", "throughput_single", "cpu", "max_percent"),
            safe_get(resources, "time_range_stats", "throughput_single", "memory", "max_rss_kb"),
            safe_get(resources, "time_range_stats", "throughput_multi", "cpu", "avg_percent"),
            safe_get(resources, "time_range_stats", "throughput_multi", "cpu", "max_percent"),
            safe_get(resources, "time_range_stats", "throughput_multi", "memory", "max_rss_kb"),
        ])

        # Full cycle
        row.extend([
            safe_get(resources, "full_cycle", "max_rss_kb"),
            safe_get(resources, "full_cycle", "max_vsz_kb"),
            safe_get(logs, "log_size", "final_size_bytes"),
        ])

        return row

    def _generate_markdown_table(self, results: List[Dict]) -> str:
        """Generate Markdown table

        Args:
            results: List of analysis results

        Returns:
            Markdown table string
        """
        if not results:
            return "No results to display.\n"

        # Simplified table for readability
        headers = [
            "Tool Case", "Protocol", "Dir",
            "Latency Mean (us)", "Lat Diff (%)",
            "TP Single (Gbps)", "TP Diff (%)",
            "PPS Single", "PPS Diff (%)",
            "CPU Avg (%)", "Mem Max (KB)",
            "Max RSS (KB)", "Log Size (B)"
        ]

        # Create header row
        table = "| " + " | ".join(headers) + " |\n"
        table += "|" + "|".join(["---" for _ in headers]) + "|\n"

        # Add data rows
        for result in results:
            row_data = self._extract_simplified_row(result)
            table += "| " + " | ".join(str(v) for v in row_data) + " |\n"

        return table

    def _extract_simplified_row(self, result: Dict) -> List:
        """Extract simplified row for Markdown table

        Args:
            result: Analysis result dictionary

        Returns:
            List of values for table row
        """
        def safe_get(d, *keys, default="N/A"):
            """Safely get nested dictionary value"""
            for key in keys:
                if isinstance(d, dict) and key in d:
                    d = d[key]
                else:
                    return default
            return d if d is not None else default

        metadata = result.get("metadata", {})
        comparison = result.get("comparison", {})
        resources = result.get("resources", {})
        logs = result.get("logs", {})

        # Extract tool case name (shorten if too long)
        tool_case = result.get("tool_case", "N/A")
        if len(tool_case) > 30:
            tool_case = tool_case[:27] + "..."

        return [
            tool_case,
            metadata.get("protocol", "N/A"),
            metadata.get("direction", "N/A"),
            safe_get(comparison, "latency", "tcp_rr_mean_us", "ebpf"),
            safe_get(comparison, "latency", "tcp_rr_mean_us", "diff_percent"),
            safe_get(comparison, "throughput_client", "single_gbps", "ebpf"),
            safe_get(comparison, "throughput_client", "single_gbps", "diff_percent"),
            safe_get(comparison, "pps_client", "single_pps", "ebpf"),
            safe_get(comparison, "pps_client", "single_pps", "diff_percent"),
            safe_get(resources, "time_range_stats", "pps_single", "cpu", "avg_percent"),
            safe_get(resources, "time_range_stats", "pps_single", "memory", "max_rss_kb"),
            safe_get(resources, "full_cycle", "max_rss_kb"),
            safe_get(logs, "log_size", "final_size_bytes"),
        ]
