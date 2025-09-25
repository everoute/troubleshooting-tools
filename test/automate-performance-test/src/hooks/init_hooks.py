#!/usr/bin/env python3
"""Initialization hooks - remote execution"""

import logging
from typing import Dict, List, Optional
from datetime import datetime


logger = logging.getLogger(__name__)


class InitHooks:
    """Layered initialization hooks for remote execution"""

    def __init__(self, ssh_manager, path_manager, config=None):
        """Initialize hooks

        Args:
            ssh_manager: SSH connection manager
            path_manager: Remote path manager
            config: Full configuration dict (optional)
        """
        self.ssh_manager = ssh_manager
        self.path_manager = path_manager
        self.config = config or {}

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

        # Store tool context for monitoring cleanup
        self.tool_context = {
            'tool_id': tool_id,
            'environment': environment,
            'host_ref': host_ref,
            'workdir': workdir,
            'timestamp': timestamp
        }

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

        # Create case directories (only server_results and ebpf_monitoring on server)
        cmd = f"mkdir -p {result_path}/{{server_results,ebpf_monitoring}}"
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
                echo "eBPF case start time: $(date '+%Y-%m-%d %H:%M:%S.%N')" >> {result_path}/ebpf_start_{timestamp}.log

                nohup {ebpf_command} > {result_path}/ebpf_output_{timestamp}.log 2>&1 &
                WRAPPER_PID=$!
                echo "Wrapper PID: $WRAPPER_PID" >> {result_path}/ebpf_start_{timestamp}.log

                # Wait a moment for the process to start
                sleep 2

                # If command starts with sudo, find the actual child process
                if echo "{ebpf_command}" | grep -q '^sudo'; then
                    ACTUAL_PID=$(pgrep -P $WRAPPER_PID | head -1)
                    if [ -z "$ACTUAL_PID" ]; then
                        # Fallback: look for python process in the process group
                        ACTUAL_PID=$(ps -eo pid,ppid,cmd | grep -v grep | grep "$WRAPPER_PID" | grep -E "python|python2|python3" | awk '{{print $1}}' | head -1)
                    fi
                    if [ -z "$ACTUAL_PID" ]; then
                        ACTUAL_PID=$WRAPPER_PID
                    fi
                else
                    ACTUAL_PID=$WRAPPER_PID
                fi

                echo $WRAPPER_PID > {result_path}/wrapper_pid_{timestamp}.txt
                echo $ACTUAL_PID > {result_path}/ebpf_pid_{timestamp}.txt
                echo "Wrapper PID: $WRAPPER_PID, Actual eBPF PID: $ACTUAL_PID" >> {result_path}/ebpf_start_{timestamp}.log
                echo "eBPF program started at $(date '+%Y-%m-%d %H:%M:%S.%N')" >> {result_path}/ebpf_start_{timestamp}.log
                echo $ACTUAL_PID
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

                # Start tool-level monitoring (covers entire tool lifecycle)
                monitor_start_cmd = f'echo "eBPF monitoring start time: $(date "+%Y-%m-%d %H:%M:%S.%N"), PID: {ebpf_pid}" > {result_path}/ebpf_monitoring/monitor_start_{timestamp}.log'
                logger.info(f"DEBUG: monitor_start_cmd = {monitor_start_cmd}")
                self.ssh_manager.execute_command(host_ref, monitor_start_cmd)

                self._start_tool_monitoring(host_ref, ebpf_pid, result_path, timestamp)
                results['tasks'].append({
                    'name': 'start_tool_monitoring',
                    'status': True
                })

                # Store case context with consistent timestamp for cleanup
                if not hasattr(self, 'case_context'):
                    self.case_context = {}
                self.case_context[f"{tool_id}_{case_id}"] = {
                    'case_timestamp': timestamp,
                    'result_path': result_path,
                    'ebpf_pid': ebpf_pid,
                    'tool_id': tool_id,
                    'case_id': case_id
                }
                logger.info(f"DEBUG: Stored case context for {tool_id}_{case_id}: timestamp={timestamp}, result_path={result_path}, ebpf_pid={ebpf_pid}")

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
            # Get test config to determine if multi-stream
            test_config = context.get('test_config', 'single_stream')
            streams = 1
            if 'multi_stream' in test_config:
                # Extract stream count from config name or use default
                if '_' in test_config:
                    try:
                        streams = int(test_config.split('_')[-1])
                    except:
                        streams = 2  # Default
                else:
                    streams = 2

            # Kill any existing iperf3 servers
            self.ssh_manager.execute_command(server_host_ref, "pkill -f 'iperf3.*-s' || true")

            # Ensure log directory exists (result_path now already points to server_results)
            self.ssh_manager.execute_command(server_host_ref, f"mkdir -p {result_path}")

            # Start multiple servers for multi-stream tests
            base_port = 5001
            started_ports = []

            for i in range(streams):
                port = base_port + i
                server_cmd = f"nohup iperf3 -s -p {port} -B {server_ip} > {result_path}/iperf3_server_{test_type}_port_{port}_{timestamp}.log 2>&1 &"
                self.ssh_manager.execute_command(server_host_ref, server_cmd)
                started_ports.append(port)

            # Wait and verify server startup
            self.ssh_manager.execute_command(server_host_ref, "sleep 3")

            # Check all ports
            all_listening = True
            for port in started_ports:
                stdout, stderr, exit_code = self.ssh_manager.execute_command(server_host_ref, f"ss -tln | grep ':{port} ' || echo 'NOT_LISTENING'")
                if 'NOT_LISTENING' in stdout:
                    all_listening = False
                    break

            results['tasks'].append({
                'name': 'start_iperf3_server',
                'status': all_listening,
                'details': f"Ports {started_ports} listening: {all_listening}",
                'ports': started_ports
            })

        elif test_type == "latency":
            # Kill any existing netserver processes on the port
            self.ssh_manager.execute_command(server_host_ref, "pkill -f 'netserver.*-p 12865' || true")

            # Ensure log directory exists (result_path now already points to server_results)
            self.ssh_manager.execute_command(server_host_ref, f"mkdir -p {result_path}")
            server_cmd = f"nohup netserver -L {server_ip} -p 12865 -D > {result_path}/netserver_{test_type}_{timestamp}.log 2>&1 &"
            self.ssh_manager.execute_command(server_host_ref, server_cmd)

            # Wait and verify server startup
            self.ssh_manager.execute_command(server_host_ref, "sleep 3")
            stdout, stderr, exit_code = self.ssh_manager.execute_command(server_host_ref, "ss -tln | grep ':12865 ' || echo 'NOT_LISTENING'")

            server_status = 'NOT_LISTENING' not in stdout
            results['tasks'].append({
                'name': 'start_netserver',
                'status': server_status,
                'details': f"Port 12865 listening: {server_status}"
            })

        return results

    def get_case_context(self, tool_id, case_id):
        """Get stored case context for cleanup"""
        if hasattr(self, 'case_context'):
            key = f"{tool_id}_{case_id}"
            context = self.case_context.get(key, {})
            logger.info(f"DEBUG: Retrieved case context for {key}: {context}")
            return context
        return {}

    def _start_tool_monitoring(self, host_ref: str, ebpf_pid: str,
                              result_path: str, timestamp: str):
        """Start tool-level monitoring with headers and configurable interval (covers entire tool lifecycle)"""
        # Get monitoring interval from config (default 2 seconds)
        interval = self.config.get('perf', {}).get('performance_tests', {}).get('monitoring', {}).get('interval', 2)

        # Combined CPU and Memory monitoring using ps (single command, single file)
        resource_cmd = f"""
            nohup bash -c '
                echo "# eBPF Resource Monitoring - CPU and Memory statistics using ps" > {result_path}/ebpf_monitoring/ebpf_resource_monitor_{timestamp}.log
                echo "# Timestamp                     PID         CPU_Percent  VSZ_KB    RSS_KB    MEM_Percent" >> {result_path}/ebpf_monitoring/ebpf_resource_monitor_{timestamp}.log
                echo "# DEBUG: Starting resource monitoring for PID {ebpf_pid}" >> {result_path}/ebpf_monitoring/ebpf_resource_monitor_{timestamp}.log
                while ps -p {ebpf_pid} >/dev/null 2>&1; do
                    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S.%N")
                    CPU=$(ps -p {ebpf_pid} -o %cpu=)
                    MEMLINE=$(ps -p {ebpf_pid} -o vsz= -o rss= -o pmem=)
                    [ -z "$CPU" ] && CPU="0.00"
                    [ -z "$MEMLINE" ] && MEMLINE="0 0 0.00"
                    echo "$TIMESTAMP {ebpf_pid} $CPU $MEMLINE" >> {result_path}/ebpf_monitoring/ebpf_resource_monitor_{timestamp}.log
                    sleep {interval}
                done
                echo "# DEBUG: resource monitoring ended for PID {ebpf_pid}" >> {result_path}/ebpf_monitoring/ebpf_resource_monitor_{timestamp}.log
            ' >> {result_path}/ebpf_monitoring/ebpf_resource_monitor_{timestamp}.log 2>&1 &
        """
        logger.info(f"DEBUG: resource_cmd = {resource_cmd}")
        self.ssh_manager.execute_command(host_ref, resource_cmd)

        # Log size monitoring with header and human-readable conversion
        log_file = f"{result_path}/ebpf_output_{timestamp}.log"
        logsize_cmd = f"""
            nohup bash -c '
                echo "# eBPF Log Size Monitoring - Log file size (instantaneous)" > {result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log
                echo "# Timestamp                     Size_Bytes  Size_Human" >> {result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log
                echo "# DEBUG: Starting logsize monitoring for {log_file}" >> {result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log
                while ps -p {ebpf_pid} >/dev/null 2>&1; do
                    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S.%N")
                    SIZE=$(stat -c %s "{log_file}" 2>/dev/null || echo 0)
                    if [ $SIZE -lt 1024 ]; then
                        HUMAN="${{SIZE}}B"
                    elif [ $SIZE -lt 1048576 ]; then
                        HUMAN="$((SIZE/1024))K"
                    elif [ $SIZE -lt 1073741824 ]; then
                        HUMAN="$((SIZE/1048576))M"
                    else
                        HUMAN="$((SIZE/1073741824))G"
                    fi
                    echo "$TIMESTAMP $SIZE $HUMAN" >> {result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log
                    sleep {interval}
                done
                echo "# DEBUG: logsize monitoring ended for {log_file}" >> {result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log
            ' >> {result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log 2>&1 &
        """
        logger.info(f"DEBUG: logsize_cmd = {logsize_cmd}")
        self.ssh_manager.execute_command(host_ref, logsize_cmd)
