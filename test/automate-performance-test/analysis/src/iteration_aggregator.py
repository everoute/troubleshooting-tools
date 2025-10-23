"""Iteration Aggregator - Aggregate results from multiple iterations"""

import os
import csv
import logging
from typing import List, Dict
from collections import defaultdict

logger = logging.getLogger(__name__)


class IterationAggregator:
    """Aggregates analysis results from multiple iterations"""

    def __init__(self, output_base_dir: str, output_subdir: str):
        """Initialize IterationAggregator

        Args:
            output_base_dir: Base output directory
            output_subdir: Subdirectory name (e.g., "1022")
        """
        self.output_base_dir = output_base_dir
        self.output_subdir = output_subdir
        self.iteration_base = os.path.join(output_base_dir, output_subdir)
        self.summary_dir = os.path.join(output_base_dir, output_subdir, "summary")

    def aggregate_all(self, iterations: List[str], topics: List[str]):
        """Aggregate all reports from multiple iterations

        Args:
            iterations: List of iteration names to aggregate
            topics: List of topics to process
        """
        if len(iterations) < 2:
            logger.info("Skipping aggregation: need at least 2 iterations")
            return

        logger.info("")
        logger.info("=" * 60)
        logger.info(f"Aggregating results from {len(iterations)} iterations")
        logger.info("=" * 60)

        os.makedirs(self.summary_dir, exist_ok=True)

        # Define report types to aggregate
        report_types = [
            "latency",
            "throughput",
            "pps",
            "resources",
            "summary"
        ]

        # Aggregate each topic
        for topic in topics:
            logger.info(f"Aggregating topic: {topic}")

            for report_type in report_types:
                self._aggregate_report(iterations, topic, report_type)

        logger.info(f"Aggregated reports saved to: {self.summary_dir}")

    def _aggregate_report(self, iterations: List[str], topic: str, report_type: str):
        """Aggregate a specific report type across iterations

        Args:
            iterations: List of iteration names
            topic: Topic name
            report_type: Report type (latency, throughput, pps, resources, summary)
        """
        # Collect report files from all iterations
        report_files = []
        for iteration in iterations:
            report_file = os.path.join(
                self.iteration_base,
                iteration,
                f"{topic}_{report_type}_{iteration}.csv"
            )
            if os.path.exists(report_file):
                report_files.append(report_file)
            else:
                logger.warning(f"Report not found: {report_file}")

        if not report_files:
            logger.warning(f"No reports found for {topic}_{report_type}")
            return

        if len(report_files) != len(iterations):
            logger.warning(f"Only found {len(report_files)}/{len(iterations)} reports for {topic}_{report_type}")

        # Read all reports
        reports_data = []
        for report_file in report_files:
            data = self._read_csv_report(report_file)
            if data:
                reports_data.append(data)

        if not reports_data:
            logger.warning(f"Failed to read any reports for {topic}_{report_type}")
            return

        # Aggregate data
        aggregated = self._compute_average(reports_data, report_type)

        # Write aggregated report
        output_file = os.path.join(self.summary_dir, f"{topic}_{report_type}_avg.csv")
        self._write_csv_report(output_file, aggregated)
        logger.info(f"  Generated: {os.path.basename(output_file)}")

    def _read_csv_report(self, file_path: str) -> Dict:
        """Read CSV report file

        Args:
            file_path: Path to CSV file

        Returns:
            Dictionary with headers and rows
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                rows = list(reader)

                if not rows:
                    return None

                # Handle resources report with multiple header rows
                if len(rows) > 1 and rows[1] and rows[1][0] == '':
                    # Resources report has 2 header rows
                    return {
                        "headers": rows[:2],
                        "data": rows[2:]
                    }
                else:
                    # Other reports have 1 header row
                    return {
                        "headers": [rows[0]],
                        "data": rows[1:]
                    }
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            return None

    def _compute_average(self, reports_data: List[Dict], report_type: str) -> Dict:
        """Compute average across multiple reports

        Args:
            reports_data: List of report data dictionaries
            report_type: Report type

        Returns:
            Aggregated report data
        """
        if not reports_data:
            return None

        # Use first report's headers
        headers = reports_data[0]["headers"]

        # Group rows by tool case (first column)
        grouped_data = defaultdict(list)
        for report in reports_data:
            for row in report["data"]:
                if row:  # Skip empty rows
                    tool_case = row[0]
                    grouped_data[tool_case].append(row)

        # Compute average for each tool case
        averaged_rows = []
        for tool_case in sorted(grouped_data.keys()):
            rows = grouped_data[tool_case]
            averaged_row = self._average_rows(rows)
            if averaged_row:
                averaged_rows.append(averaged_row)

        return {
            "headers": headers,
            "data": averaged_rows
        }

    def _average_rows(self, rows: List[List[str]]) -> List[str]:
        """Average multiple rows (one from each iteration)

        Args:
            rows: List of rows to average

        Returns:
            Averaged row
        """
        if not rows:
            return None

        # Use first row as template
        num_cols = len(rows[0])
        averaged = []

        for col_idx in range(num_cols):
            # Column 0: Tool Case (keep as-is from first row)
            # Column 1: Command (keep as-is from first row)
            if col_idx <= 1:
                averaged.append(rows[0][col_idx])
                continue

            # For other columns, try to compute average
            values = []
            for row in rows:
                if col_idx < len(row):
                    val = row[col_idx]
                    # Try to parse as number
                    try:
                        # Handle various formats
                        if val and val != "N/A" and val != "":
                            # Remove any non-numeric characters except . and -
                            cleaned = val.strip()
                            num_val = float(cleaned)
                            values.append(num_val)
                    except (ValueError, AttributeError):
                        # Not a number, skip
                        pass

            # Compute average if we have numeric values
            if values:
                avg = sum(values) / len(values)
                # Format based on magnitude
                if abs(avg) < 0.01:
                    averaged.append(f"{avg:.4f}")
                elif abs(avg) < 1:
                    averaged.append(f"{avg:.3f}")
                elif abs(avg) < 100:
                    averaged.append(f"{avg:.2f}")
                else:
                    averaged.append(f"{int(round(avg))}")
            else:
                # No numeric values, use first row's value
                if col_idx < len(rows[0]):
                    averaged.append(rows[0][col_idx])
                else:
                    averaged.append("N/A")

        return averaged

    def _write_csv_report(self, file_path: str, data: Dict):
        """Write aggregated report to CSV

        Args:
            file_path: Output file path
            data: Report data with headers and rows
        """
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)

                # Write headers
                for header_row in data["headers"]:
                    writer.writerow(header_row)

                # Write data rows
                writer.writerows(data["data"])

            logger.debug(f"Wrote aggregated report: {file_path}")
        except Exception as e:
            logger.error(f"Failed to write {file_path}: {e}")
