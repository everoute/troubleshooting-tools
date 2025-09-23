#!/usr/bin/env python3
"""Post-processing hooks - remote execution"""

import logging
from typing import Dict, List, Optional
from datetime import datetime


logger = logging.getLogger(__name__)


class PostHooks:
    """Layered post-processing hooks for remote execution"""

    def __init__(self, ssh_manager, path_manager):
        """Initialize hooks

        Args:
            ssh_manager: SSH connection manager
            path_manager: Remote path manager
        """
        self.ssh_manager = ssh_manager
        self.path_manager = path_manager

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
        host_ref = context.get('host_ref')
        result_path = context.get('result_path')
        ebpf_command = context.get('ebpf_command')

        # Stop case monitoring if eBPF program was running
        if ebpf_command:
            # Stop monitoring processes
            monitoring_cmd = f"""
                pkill -f "ebpf_cpu_monitor.*{case_id}" || true
                pkill -f "ebpf_memory_monitor.*{case_id}" || true
                pkill -f "ebpf_logsize_monitor.*{case_id}" || true
                echo "Case monitoring stopped at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_path}/monitoring_stop_{timestamp}.log
            """
            self.ssh_manager.execute_command(host_ref, monitoring_cmd)
            results['tasks'].append({
                'name': 'stop_case_monitoring',
                'status': True
            })

            # Stop eBPF program
            stop_ebpf_cmd = f"""
                if [ -f {result_path}/ebpf_pid_{timestamp}.txt ]; then
                    EBPF_PID=$(cat {result_path}/ebpf_pid_{timestamp}.txt)
                    if kill -0 $EBPF_PID 2>/dev/null; then
                        kill $EBPF_PID
                        echo "eBPF program (PID: $EBPF_PID) stopped at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_path}/ebpf_stop_{timestamp}.log
                    else
                        echo "eBPF program already stopped at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_path}/ebpf_stop_{timestamp}.log
                    fi
                fi
            """
            self.ssh_manager.execute_command(host_ref, stop_ebpf_cmd)
            results['tasks'].append({
                'name': 'stop_ebpf_program',
                'status': True
            })

        # Collect case data
        collect_cmd = f"""
            echo "Case {case_id} data collection completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_path}/case_complete_{timestamp}.log
            du -sh {result_path}/* > {result_path}/case_data_size_{timestamp}.log 2>/dev/null || true
            sync
        """
        self.ssh_manager.execute_command(host_ref, collect_cmd)
        results['tasks'].append({
            'name': 'collect_case_data',
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