#!/usr/bin/env python3
"""Initialization hooks - remote execution"""

import logging
from typing import Dict, List, Optional
from datetime import datetime


logger = logging.getLogger(__name__)


class InitHooks:
    """Layered initialization hooks for remote execution"""

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
        if action != "init":
            return {"error": "Invalid action for init hooks"}

        if stage == "global":
            return self._execute_global_init(context)
        elif stage == "tool":
            return self._execute_tool_init(context)
        elif stage == "case":
            return self._execute_case_init(context)
        elif stage == "test":
            return self._execute_test_init(context)
        else:
            return {"error": f"Unknown stage: {stage}"}

    def _execute_global_init(self, context: Dict) -> Dict:
        """Execute global initialization"""
        results = {"stage": "global", "action": "init", "tasks": []}
        timestamp = self.path_manager.get_timestamp()
        targets = context.get('targets', ['server', 'client'])

        for target in targets:
            host_ref = context.get(f'{target}_host_ref')
            if not host_ref:
                continue

            workdir = context.get('workdir', '/home/smartx/lcc')
            result_base = f"{workdir}/performance-test-results"

            # Create base directories
            cmd = f"mkdir -p {result_base}/{{baseline,ebpf}}"
            stdout, stderr, status = self.ssh_manager.execute_command(host_ref, cmd)
            results['tasks'].append({
                'name': 'create_base_directories',
                'target': target,
                'status': status == 0
            })

            # Check system requirements
            check_cmd = f"""
                echo "Checking system requirements at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_base}/system_check_{timestamp}.log
                which iperf3 netperf python3 >> {result_base}/system_check_{timestamp}.log 2>&1
            """
            stdout, stderr, status = self.ssh_manager.execute_command(host_ref, check_cmd)
            results['tasks'].append({
                'name': 'check_system_requirements',
                'target': target,
                'status': status == 0
            })

            # Cleanup previous processes
            cleanup_cmd = """
                pkill -f "iperf3.*-s" || true
                pkill -f "netserver" || true
            """
            self.ssh_manager.execute_command(host_ref, cleanup_cmd)
            results['tasks'].append({
                'name': 'cleanup_previous_processes',
                'target': target,
                'status': True
            })

        return results

    def _execute_tool_init(self, context: Dict) -> Dict:
        """Execute tool-level initialization"""
        results = {"stage": "tool", "action": "init", "tasks": []}
        timestamp = self.path_manager.get_timestamp()

        tool_id = context.get('tool_id')
        environment = context.get('environment')
        host_ref = context.get('host_ref')
        workdir = context.get('workdir', '/home/smartx/lcc')

        if not all([tool_id, environment, host_ref]):
            results['error'] = "Missing required context"
            return results

        result_base = f"{workdir}/performance-test-results"

        # Create tool directories
        cmd = f"mkdir -p {result_base}/ebpf/{tool_id}"
        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, cmd)
        results['tasks'].append({
            'name': 'create_tool_directories',
            'status': status == 0
        })

        # Tool specific setup
        setup_cmd = f"""
            echo "Starting tool {tool_id} in environment {environment} at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_base}/ebpf/{tool_id}/tool_start_{timestamp}.log
        """
        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, setup_cmd)
        results['tasks'].append({
            'name': 'tool_specific_setup',
            'status': status == 0
        })

        return results

    def _execute_case_init(self, context: Dict) -> Dict:
        """Execute case-level initialization"""
        results = {"stage": "case", "action": "init", "tasks": []}
        timestamp = self.path_manager.get_timestamp()

        tool_id = context.get('tool_id')
        case_id = context.get('case_id')
        ebpf_command = context.get('ebpf_command')
        environment = context.get('environment')
        host_ref = context.get('host_ref')
        workdir = context.get('workdir', '/home/smartx/lcc')
        result_path = context.get('result_path')

        if not result_path:
            result_path = f"{workdir}/performance-test-results/ebpf/{tool_id}_case_{case_id}/{environment}"

        # Create case directories
        cmd = f"mkdir -p {result_path}/{{client_results,server_results,monitoring,ebpf_monitoring}}"
        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, cmd)
        results['tasks'].append({
            'name': 'create_case_directories',
            'status': status == 0
        })

        # Start eBPF program if provided
        if ebpf_command:
            start_cmd = f"""
                cd {workdir}
                echo "Starting eBPF case {case_id}: {ebpf_command}" > {result_path}/ebpf_start_{timestamp}.log
                nohup {ebpf_command} > {result_path}/ebpf_output_{timestamp}.log 2>&1 &
                EBPF_PID=$!
                echo $EBPF_PID > {result_path}/ebpf_pid_{timestamp}.txt
                echo "eBPF program started with PID: $EBPF_PID at $(date '+%Y-%m-%d %H:%M:%S.%N')" >> {result_path}/ebpf_start_{timestamp}.log
                echo $EBPF_PID
            """
            stdout, stderr, status = self.ssh_manager.execute_command(host_ref, start_cmd)
            if status == 0 and stdout:
                ebpf_pid = stdout.strip()
                results['ebpf_pid'] = ebpf_pid
                results['tasks'].append({
                    'name': 'start_ebpf_program',
                    'status': True,
                    'pid': ebpf_pid
                })

                # Start case monitoring
                self._start_case_monitoring(host_ref, ebpf_pid, result_path, timestamp)
                results['tasks'].append({
                    'name': 'start_case_monitoring',
                    'status': True
                })

        return results

    def _execute_test_init(self, context: Dict) -> Dict:
        """Execute test-level initialization"""
        results = {"stage": "test", "action": "init", "tasks": []}
        timestamp = self.path_manager.get_timestamp()

        test_type = context.get('test_type')
        test_config = context.get('test_config')
        server_ip = context.get('server_ip')
        server_host_ref = context.get('server_host_ref')
        result_path = context.get('result_path')

        if not all([test_type, server_ip, server_host_ref]):
            results['error'] = "Missing required context"
            return results

        # Start performance servers based on test type
        if test_type in ["throughput", "pps"]:
            server_cmd = f"nohup iperf3 -s -p 5001 -B {server_ip} > {result_path}/iperf3_server_{test_type}_{timestamp}.log 2>&1 &"
            self.ssh_manager.execute_command(server_host_ref, server_cmd)
            results['tasks'].append({
                'name': 'start_iperf3_server',
                'status': True
            })

        elif test_type == "latency":
            server_cmd = f"nohup netserver -L {server_ip} -p 12865 -D > {result_path}/netserver_{test_type}_{timestamp}.log 2>&1 &"
            self.ssh_manager.execute_command(server_host_ref, server_cmd)
            results['tasks'].append({
                'name': 'start_netserver',
                'status': True
            })

        # Wait for servers to start
        self.ssh_manager.execute_command(server_host_ref, "sleep 2")

        return results

    def _start_case_monitoring(self, host_ref: str, ebpf_pid: str,
                              result_path: str, timestamp: str):
        """Start case-level monitoring"""
        # CPU monitoring
        cpu_cmd = f"""
            nohup bash -c '
                while kill -0 {ebpf_pid} 2>/dev/null; do
                    echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "$(top -b -n 1 -p {ebpf_pid} | tail -1 | awk "{{print \\$9}}")"
                    sleep 1
                done
            ' > {result_path}/ebpf_monitoring/ebpf_cpu_monitor_{timestamp}.log 2>&1 &
        """
        self.ssh_manager.execute_command(host_ref, cpu_cmd)

        # Memory monitoring
        mem_cmd = f"""
            nohup bash -c '
                while kill -0 {ebpf_pid} 2>/dev/null; do
                    echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "$(ps -p {ebpf_pid} -o vsz,rss,pmem --no-headers)"
                    sleep 1
                done
            ' > {result_path}/ebpf_monitoring/ebpf_memory_monitor_{timestamp}.log 2>&1 &
        """
        self.ssh_manager.execute_command(host_ref, mem_cmd)

        # Log size monitoring
        log_file = f"{result_path}/ebpf_output_{timestamp}.log"
        logsize_cmd = f"""
            nohup bash -c '
                while kill -0 {ebpf_pid} 2>/dev/null; do
                    SIZE=$(stat -c %s "{log_file}" 2>/dev/null || echo 0)
                    echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "$SIZE"
                    sleep 1
                done
            ' > {result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log 2>&1 &
        """
        self.ssh_manager.execute_command(host_ref, logsize_cmd)