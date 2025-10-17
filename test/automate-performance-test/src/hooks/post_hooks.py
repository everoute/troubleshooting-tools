#!/usr/bin/env python3
"""Post-processing hooks - remote execution"""

import logging
from typing import Dict, List, Optional
from datetime import datetime


logger = logging.getLogger(__name__)


class PostHooks:
    """Layered post-processing hooks for remote execution"""

    def __init__(self, ssh_manager, path_manager, init_hooks=None):
        """Initialize hooks

        Args:
            ssh_manager: SSH connection manager
            path_manager: Remote path manager
            init_hooks: Reference to init_hooks for getting case context
        """
        self.ssh_manager = ssh_manager
        self.path_manager = path_manager
        self.init_hooks = init_hooks

    def execute_hook(self, stage: str, action: str, context: Dict) -> Dict:
        """Execute hook based on stage and action

        Args:
            stage: Hook stage (global/tool/case/test)
            action: Hook action (init/post)
            context: Execution context

        Returns:
            Execution results
        """
        if action != "post":
            return {"error": "Invalid action for post hooks"}

        if stage == "global":
            return self._execute_global_post(context)
        elif stage == "tool":
            return self._execute_tool_post(context)
        elif stage == "case":
            return self._execute_case_post(context)
        elif stage == "test":
            return self._execute_test_post(context)
        else:
            return {"error": f"Unknown stage: {stage}"}

    def _execute_test_post(self, context: Dict) -> Dict:
        """Execute test-level cleanup"""
        results = {"stage": "test", "action": "post", "tasks": []}
        timestamp = self.path_manager.get_timestamp()

        test_type = context.get('test_type')
        server_ip = context.get('server_ip')
        server_host_ref = context.get('server_host_ref')
        result_path = context.get('result_path')

        # Stop performance servers
        if test_type in ["throughput", "pps"]:
            stop_cmd = f'pkill -f "iperf3.*-s.*{server_ip}" || true'
            self.ssh_manager.execute_command(server_host_ref, stop_cmd)
            results['tasks'].append({
                'name': 'stop_iperf3_server',
                'status': True
            })

        elif test_type == "latency":
            stop_cmd = f'pkill -f "netserver.*{server_ip}" || true'
            self.ssh_manager.execute_command(server_host_ref, stop_cmd)
            results['tasks'].append({
                'name': 'stop_netserver',
                'status': True
            })

        # Collect test results
        collect_cmd = f"""
            echo "Test {test_type} completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_path}/test_complete_{test_type}_{timestamp}.log
            sync
        """
        self.ssh_manager.execute_command(server_host_ref, collect_cmd)
        results['tasks'].append({
            'name': 'collect_test_results',
            'status': True
        })

        return results

    def _execute_case_post(self, context: Dict) -> Dict:
        """Execute case-level cleanup"""
        results = {"stage": "case", "action": "post", "tasks": []}
        timestamp = self.path_manager.get_timestamp()

        tool_id = context.get('tool_id')
        case_id = context.get('case_id')
        environment = context.get('environment')

        # Performance test host (VM or physical host)
        host_ref = context.get('host_ref')
        result_path = context.get('result_path')

        # eBPF monitoring host (physical host, may be different from host_ref)
        ebpf_host_ref = context.get('ebpf_host_ref', host_ref)
        ebpf_result_path = context.get('ebpf_result_path', result_path)
        ebpf_command = context.get('ebpf_command')

        # Get case context with consistent timestamp from init_hooks
        case_context = {}
        if self.init_hooks and hasattr(self.init_hooks, 'get_case_context'):
            case_context = self.init_hooks.get_case_context(tool_id, case_id)
            if case_context:
                # Use the timestamp from case init, not current timestamp
                case_timestamp = case_context.get('case_timestamp', timestamp)
                logger.info(f"DEBUG: Using case timestamp {case_timestamp} instead of current {timestamp}")
                timestamp = case_timestamp

                # Override eBPF paths from case_context if available
                if 'ebpf_result_path' in case_context:
                    ebpf_result_path = case_context['ebpf_result_path']
                    logger.info(f"DEBUG: Using ebpf_result_path from case_context: {ebpf_result_path}")
                if 'ebpf_host_ref' in case_context:
                    ebpf_host_ref = case_context['ebpf_host_ref']
                    logger.info(f"DEBUG: Using ebpf_host_ref from case_context: {ebpf_host_ref}")

        # Stop case monitoring if eBPF program was running (on eBPF monitoring host - physical host)
        if ebpf_command:
            # Record monitoring stop time
            monitor_stop_timestamp = f"""
                echo "Monitor stop time: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log
            """
            self.ssh_manager.execute_command(ebpf_host_ref, monitor_stop_timestamp)

            # Stop monitoring processes (updated for new pidstat monitoring)
            monitoring_cmd = f"""
                echo "DEBUG: Stopping monitoring processes for case {case_id}" >> {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log
                pkill -f "ebpf_resource_monitor.*{case_id}" || true
                pkill -f "ebpf_logsize_monitor.*{case_id}" || true
                # Also try to kill by pattern matching the result path
                pkill -f "{ebpf_result_path}/ebpf_monitoring" || true
                echo "Case monitoring stopped at: $(date '+%Y-%m-%d %H:%M:%S.%N')" >> {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log
                echo "DEBUG: Monitoring stop commands completed" >> {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log
            """
            logger.info(f"DEBUG: monitoring_cmd = {monitoring_cmd}")
            self.ssh_manager.execute_command(ebpf_host_ref, monitoring_cmd)
            results['tasks'].append({
                'name': 'stop_case_monitoring',
                'status': True
            })

            # Enhanced eBPF program cleanup with process tree termination (on eBPF monitoring host)
            stop_ebpf_cmd = f"""
                # Function to kill process and its children
                kill_process_tree() {{
                    local PID=$1
                    local NAME=$2
                    if [ -n "$PID" ]; then
                        if ps -p $PID -o pid= >/dev/null 2>&1; then
                            echo "Terminating $NAME process $PID and its children"
                            # Kill all children first
                            pkill -P $PID 2>/dev/null || true
                            sleep 1
                            # Try graceful termination
                            kill -TERM $PID 2>/dev/null || true
                            sleep 2
                            # Force kill if still alive
                            if ps -p $PID -o pid= >/dev/null 2>&1; then
                                kill -KILL $PID 2>/dev/null || true
                            fi
                            echo "$NAME process $PID terminated at: $(date '+%Y-%m-%d %H:%M:%S.%N')"
                        else
                            echo "$NAME process $PID already stopped"
                        fi
                    fi
                }}

                echo "eBPF case stop time: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {ebpf_result_path}/ebpf_stop_{timestamp}.log

                # DEBUG: List available PID files
                echo "DEBUG: Available PID files in {ebpf_result_path}:" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                ls -la {ebpf_result_path}/*pid*.txt >> {ebpf_result_path}/ebpf_stop_{timestamp}.log 2>&1 || echo "No PID files found" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log

                # Stop actual eBPF process
                EBPF_PID_FILE="{ebpf_result_path}/ebpf_pid_{timestamp}.txt"
                if [ -f "$EBPF_PID_FILE" ]; then
                    EBPF_PID=$(cat "$EBPF_PID_FILE")
                    echo "DEBUG: Found eBPF PID file with PID: $EBPF_PID" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                    kill_process_tree "$EBPF_PID" "eBPF"
                else
                    echo "DEBUG: eBPF PID file not found: $EBPF_PID_FILE" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                    # Try to find PID files with any timestamp in same directory
                    FOUND_EBPF_PID_FILE=$(find {ebpf_result_path} -name "ebpf_pid_*.txt" -type f | head -1)
                    if [ -n "$FOUND_EBPF_PID_FILE" ]; then
                        EBPF_PID=$(cat "$FOUND_EBPF_PID_FILE")
                        echo "DEBUG: Using fallback eBPF PID file: $FOUND_EBPF_PID_FILE with PID: $EBPF_PID" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                        kill_process_tree "$EBPF_PID" "eBPF"
                    fi
                fi

                # Stop wrapper process if different
                WRAPPER_PID_FILE="{ebpf_result_path}/wrapper_pid_{timestamp}.txt"
                if [ -f "$WRAPPER_PID_FILE" ]; then
                    WRAPPER_PID=$(cat "$WRAPPER_PID_FILE")
                    echo "DEBUG: Found wrapper PID file with PID: $WRAPPER_PID" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                    if [ -f "$EBPF_PID_FILE" ]; then
                        EBPF_PID=$(cat "$EBPF_PID_FILE")
                        if [ "$WRAPPER_PID" != "$EBPF_PID" ]; then
                            kill_process_tree "$WRAPPER_PID" "Wrapper"
                        fi
                    else
                        kill_process_tree "$WRAPPER_PID" "Wrapper"
                    fi
                else
                    echo "DEBUG: Wrapper PID file not found: $WRAPPER_PID_FILE" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                    # Try to find wrapper PID files with any timestamp in same directory
                    FOUND_WRAPPER_PID_FILE=$(find {ebpf_result_path} -name "wrapper_pid_*.txt" -type f | head -1)
                    if [ -n "$FOUND_WRAPPER_PID_FILE" ]; then
                        WRAPPER_PID=$(cat "$FOUND_WRAPPER_PID_FILE")
                        echo "DEBUG: Using fallback wrapper PID file: $FOUND_WRAPPER_PID_FILE with PID: $WRAPPER_PID" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                        kill_process_tree "$WRAPPER_PID" "Wrapper"
                    fi
                fi

                echo "eBPF case cleanup completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
            """
            self.ssh_manager.execute_command(ebpf_host_ref, stop_ebpf_cmd)
            results['tasks'].append({
                'name': 'stop_ebpf_program',
                'status': True
            })

        # Generate time range statistics (on eBPF monitoring host)
        if ebpf_command:
            self._generate_time_statistics(ebpf_host_ref, ebpf_result_path, timestamp)
            results['tasks'].append({
                'name': 'generate_time_statistics',
                'status': True
            })

        # Collect eBPF case data (on eBPF monitoring host)
        if ebpf_command:
            ebpf_collect_cmd = f"""
                echo "eBPF case {case_id} data collection completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {ebpf_result_path}/ebpf_case_complete_{timestamp}.log
                du -sh {ebpf_result_path}/* > {ebpf_result_path}/ebpf_case_data_size_{timestamp}.log 2>/dev/null || true
                sync
            """
            self.ssh_manager.execute_command(ebpf_host_ref, ebpf_collect_cmd)
            results['tasks'].append({
                'name': 'collect_ebpf_case_data',
                'status': True
            })

        # Collect performance test data (on performance test host)
        perf_collect_cmd = f"""
            echo "Performance test {case_id} data collection completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_path}/perf_case_complete_{timestamp}.log
            du -sh {result_path}/* > {result_path}/perf_case_data_size_{timestamp}.log 2>/dev/null || true
            sync
        """
        self.ssh_manager.execute_command(host_ref, perf_collect_cmd)
        results['tasks'].append({
            'name': 'collect_performance_case_data',
            'status': True
        })

        return results

    def _execute_tool_post(self, context: Dict) -> Dict:
        """Execute tool-level cleanup"""
        results = {"stage": "tool", "action": "post", "tasks": []}
        timestamp = self.path_manager.get_timestamp()

        tool_id = context.get('tool_id')
        environment = context.get('environment')
        host_ref = context.get('host_ref')
        workdir = context.get('workdir', '/home/smartx/lcc')

        result_base = f"{workdir}/performance-test-results"

        # Collect tool summary
        summary_cmd = f"""
            echo "Tool {tool_id} testing completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_base}/ebpf/{tool_id}/tool_complete_{timestamp}.log
            find {result_base}/ebpf/{tool_id}* -name "*.log" 2>/dev/null | wc -l > {result_base}/ebpf/{tool_id}/total_files_{timestamp}.txt || true
        """
        self.ssh_manager.execute_command(host_ref, summary_cmd)
        results['tasks'].append({
            'name': 'collect_tool_summary',
            'status': True
        })

        # Tool specific cleanup
        cleanup_cmd = f"""
            echo "Tool {tool_id} cleanup completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_base}/ebpf/{tool_id}/tool_cleanup_{timestamp}.log
        """
        self.ssh_manager.execute_command(host_ref, cleanup_cmd)
        results['tasks'].append({
            'name': 'tool_specific_cleanup',
            'status': True
        })

        return results

    def _generate_time_statistics(self, host_ref: str, result_path: str, timestamp: str):
        """Generate time range statistics for eBPF monitoring and performance tests"""
        stats_cmd = f"""
            # Generate time range statistics
            STATS_FILE="{result_path}/ebpf_monitoring/time_range_statistics_{timestamp}.log"

            echo "# eBPF Tool Time Range Statistics" > $STATS_FILE
            echo "# Generated at: $(date '+%Y-%m-%d %H:%M:%S.%N')" >> $STATS_FILE
            echo "" >> $STATS_FILE

            # eBPF Monitoring Time Range
            echo "## eBPF Monitoring Time Range" >> $STATS_FILE
            if [ -f "{result_path}/ebpf_monitoring/ebpf_cpu_monitor_{timestamp}.log" ]; then
                FIRST_CPU=$(grep -v '^#' "{result_path}/ebpf_monitoring/ebpf_cpu_monitor_{timestamp}.log" | head -1 | awk '{{print $1" "$2}}')
                LAST_CPU=$(grep -v '^#' "{result_path}/ebpf_monitoring/ebpf_cpu_monitor_{timestamp}.log" | tail -1 | awk '{{print $1" "$2}}')
                echo "CPU Monitoring Start: $FIRST_CPU" >> $STATS_FILE
                echo "CPU Monitoring End: $LAST_CPU" >> $STATS_FILE
            fi

            if [ -f "{result_path}/ebpf_monitoring/ebpf_memory_monitor_{timestamp}.log" ]; then
                FIRST_MEM=$(grep -v '^#' "{result_path}/ebpf_monitoring/ebpf_memory_monitor_{timestamp}.log" | head -1 | awk '{{print $1" "$2}}')
                LAST_MEM=$(grep -v '^#' "{result_path}/ebpf_monitoring/ebpf_memory_monitor_{timestamp}.log" | tail -1 | awk '{{print $1" "$2}}')
                echo "Memory Monitoring Start: $FIRST_MEM" >> $STATS_FILE
                echo "Memory Monitoring End: $LAST_MEM" >> $STATS_FILE
            fi

            if [ -f "{result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log" ]; then
                FIRST_LOG=$(grep -v '^#' "{result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log" | head -1 | awk '{{print $1" "$2}}')
                LAST_LOG=$(grep -v '^#' "{result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log" | tail -1 | awk '{{print $1" "$2}}')
                echo "LogSize Monitoring Start: $FIRST_LOG" >> $STATS_FILE
                echo "LogSize Monitoring End: $LAST_LOG" >> $STATS_FILE
            fi

            echo "" >> $STATS_FILE
            echo "## Performance Test Time Ranges (from client timing files)" >> $STATS_FILE

            # Find and process all timing files
            find {result_path}/../../ -name '*_timing.log' -type f 2>/dev/null | while read timing_file; do
                if [ -f "$timing_file" ]; then
                    echo "" >> $STATS_FILE
                    echo "### Test: $(basename "$timing_file" _timing.log)" >> $STATS_FILE
                    cat "$timing_file" >> $STATS_FILE
                fi
            done
        """
        self.ssh_manager.execute_command(host_ref, stats_cmd)

    def _execute_global_post(self, context: Dict) -> Dict:
        """Execute global cleanup"""
        results = {"stage": "global", "action": "post", "tasks": []}
        timestamp = self.path_manager.get_timestamp()
        targets = context.get('targets', ['server', 'client'])

        for target in targets:
            host_ref = context.get(f'{target}_host_ref')
            if not host_ref:
                continue

            workdir = context.get('workdir', '/home/smartx/lcc')
            result_base = f"{workdir}/performance-test-results"

            # Final cleanup
            final_cleanup_cmd = """
                pkill -f "iperf3.*-s" || true
                pkill -f "netserver" || true
                pkill -f "python.*ebpf" || true
            """
            self.ssh_manager.execute_command(host_ref, final_cleanup_cmd)

            # Log cleanup completion
            log_cmd = f'echo "All test processes cleaned at: $(date \'+%Y-%m-%d %H:%M:%S.%N\')" > {result_base}/final_cleanup_{timestamp}.log'
            self.ssh_manager.execute_command(host_ref, log_cmd)

            results['tasks'].append({
                'name': 'final_cleanup',
                'target': target,
                'status': True
            })

            # Generate session summary
            summary_cmd = f"""
                echo "Test session completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_base}/session_summary_{timestamp}.json
                echo "Total result files: $(find {result_base} -name "*.log" -o -name "*.json" 2>/dev/null | wc -l)" >> {result_base}/session_summary_{timestamp}.json
                echo "Total disk usage: $(du -sh {result_base} 2>/dev/null | cut -f1)" >> {result_base}/session_summary_{timestamp}.json
                sync
            """
            self.ssh_manager.execute_command(host_ref, summary_cmd)

            results['tasks'].append({
                'name': 'generate_session_summary',
                'target': target,
                'status': True
            })

        return results
