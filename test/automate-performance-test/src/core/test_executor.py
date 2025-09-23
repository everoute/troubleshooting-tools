#!/usr/bin/env python3
"""Test execution engine - remote execution"""

import json
import logging
import time
from typing import Dict, List, Optional, Any
from datetime import datetime

from .ssh_manager import SSHManager
from .remote_path_manager import RemotePathManager


logger = logging.getLogger(__name__)


class TestExecutor:
    """Test execution engine for remote test runs"""

    def __init__(self, ssh_manager: SSHManager, path_manager: RemotePathManager):
        """Initialize test executor

        Args:
            ssh_manager: SSH connection manager
            path_manager: Remote path manager
        """
        self.ssh_manager = ssh_manager
        self.path_manager = path_manager
        self.current_test_context = {}
        self.ebpf_processes = {}

    def execute_workflow(self, workflow_spec: Dict) -> Dict:
        """Execute complete workflow

        Args:
            workflow_spec: Workflow specification

        Returns:
            Execution results
        """
        results = {
            "start_time": datetime.now().isoformat(),
            "test_cycles": [],
            "status": "running"
        }

        try:
            # Execute global init
            self._execute_global_init(workflow_spec)

            # Execute each test cycle
            for cycle in workflow_spec['test_sequence']:
                logger.info(f"Executing test cycle: {cycle['cycle_id']}")
                cycle_result = self._execute_test_cycle(cycle, workflow_spec)
                results['test_cycles'].append(cycle_result)

            # Execute global post
            self._execute_global_post(workflow_spec)

            results['status'] = "completed"
        except Exception as e:
            logger.error(f"Workflow execution failed: {str(e)}")
            results['status'] = "failed"
            results['error'] = str(e)
        finally:
            results['end_time'] = datetime.now().isoformat()

        return results

    def _execute_test_cycle(self, cycle: Dict, workflow_spec: Dict) -> Dict:
        """Execute single test cycle

        Args:
            cycle: Test cycle configuration
            workflow_spec: Complete workflow spec

        Returns:
            Cycle execution results
        """
        cycle_result = {
            "cycle_id": cycle['cycle_id'],
            "start_time": datetime.now().isoformat(),
            "status": "running"
        }

        try:
            # Set current test context
            self._set_test_context(cycle, workflow_spec)

            # Execute init hook
            if cycle['cycle_type'] == 'baseline':
                self._execute_baseline_init(cycle)
            else:
                self._execute_ebpf_init(cycle)

            # Execute performance tests
            perf_results = self._execute_performance_tests(
                cycle['test_cycle']['performance_tests']
            )
            cycle_result['performance_results'] = perf_results

            # Execute post hook
            if cycle['cycle_type'] == 'baseline':
                self._execute_baseline_post(cycle)
            else:
                self._execute_ebpf_post(cycle)

            cycle_result['status'] = "completed"
        except Exception as e:
            logger.error(f"Test cycle failed: {str(e)}")
            cycle_result['status'] = "failed"
            cycle_result['error'] = str(e)
        finally:
            cycle_result['end_time'] = datetime.now().isoformat()

        return cycle_result

    def _execute_global_init(self, workflow_spec: Dict):
        """Execute global initialization"""
        env_config = workflow_spec.get('global_config', {})

        for host_ref in env_config.get('ssh_hosts', {}).keys():
            # Create base directories
            workdir = env_config['ssh_hosts'][host_ref]['workdir']
            commands = [
                f"mkdir -p {workdir}/performance-test-results/{{baseline,ebpf}}",
                f"pkill -f 'iperf3.*-s' || true",
                f"pkill -f 'netserver' || true"
            ]

            for cmd in commands:
                self.ssh_manager.execute_command(host_ref, cmd)

            logger.info(f"Global init completed for {host_ref}")

    def _execute_global_post(self, workflow_spec: Dict):
        """Execute global cleanup"""
        env_config = workflow_spec.get('global_config', {})

        for host_ref in env_config.get('ssh_hosts', {}).keys():
            # Final cleanup
            commands = [
                "pkill -f 'iperf3.*-s' || true",
                "pkill -f 'netserver' || true",
                "pkill -f 'python.*ebpf' || true"
            ]

            for cmd in commands:
                self.ssh_manager.execute_command(host_ref, cmd)

            logger.info(f"Global post completed for {host_ref}")

    def _execute_baseline_init(self, cycle: Dict):
        """Execute baseline test initialization"""
        timestamp = self.path_manager.get_timestamp()
        env_name = cycle['environment']

        # Prepare test environment
        logger.info(f"Initializing baseline test for {env_name}")

        # No eBPF program to start for baseline
        self.current_test_context['ebpf_pid'] = None
        self.current_test_context['timestamp'] = timestamp

    def _execute_ebpf_init(self, cycle: Dict):
        """Execute eBPF test initialization"""
        timestamp = self.path_manager.get_timestamp()
        env_name = cycle['environment']
        ebpf_case = cycle['ebpf_case']

        logger.info(f"Initializing eBPF test: {ebpf_case['case_id']}")

        # Get host reference from environment
        host_ref = self._get_host_ref_for_env(env_name, 'server')

        # Create result directories
        result_path = self._get_result_path(cycle)
        self.ssh_manager.execute_command(
            host_ref,
            f"mkdir -p {result_path}/{{client_results,server_results,monitoring,ebpf_monitoring}}"
        )

        # Start eBPF program
        if ebpf_case['command']:
            ebpf_log = f"{result_path}/ebpf_output_{timestamp}.log"
            pid = self.ssh_manager.execute_command(
                host_ref,
                f"cd {self._get_workdir(host_ref)} && {ebpf_case['command']} > {ebpf_log} 2>&1",
                background=True
            )[0]

            self.ebpf_processes[ebpf_case['case_id']] = {
                'pid': pid,
                'host': host_ref,
                'log_file': ebpf_log
            }

            self.current_test_context['ebpf_pid'] = pid
            logger.info(f"Started eBPF program with PID: {pid}")

            # Start custom monitoring
            if cycle['test_cycle']['init_hook'].get('custom_monitoring'):
                self._start_custom_monitoring(host_ref, pid, result_path, timestamp)

        self.current_test_context['timestamp'] = timestamp

    def _execute_baseline_post(self, cycle: Dict):
        """Execute baseline test cleanup"""
        logger.info(f"Cleaning up baseline test for {cycle['environment']}")

        # Collect results
        result_path = self._get_result_path(cycle)
        timestamp = self.current_test_context.get('timestamp')

        # Write metadata
        self._write_test_metadata(cycle, result_path, timestamp)

    def _execute_ebpf_post(self, cycle: Dict):
        """Execute eBPF test cleanup"""
        ebpf_case = cycle['ebpf_case']
        case_id = ebpf_case['case_id']

        logger.info(f"Cleaning up eBPF test: {case_id}")

        if case_id in self.ebpf_processes:
            proc_info = self.ebpf_processes[case_id]

            # Stop monitoring
            self._stop_custom_monitoring(proc_info['host'])

            # Stop eBPF program
            if self.ssh_manager.check_process(proc_info['host'], proc_info['pid']):
                self.ssh_manager.kill_process(proc_info['host'], proc_info['pid'])
                logger.info(f"Stopped eBPF program PID: {proc_info['pid']}")

            del self.ebpf_processes[case_id]

        # Collect results
        result_path = self._get_result_path(cycle)
        timestamp = self.current_test_context.get('timestamp')

        # Write metadata
        self._write_test_metadata(cycle, result_path, timestamp)

    def _execute_performance_tests(self, perf_tests: List[Dict]) -> List[Dict]:
        """Execute performance tests

        Args:
            perf_tests: Performance test configurations

        Returns:
            Test results
        """
        results = []

        for test in perf_tests:
            test_type = test['type']
            configs = test.get('configs', [])

            logger.info(f"Executing {test_type} tests")

            for config in configs:
                result = self._run_single_performance_test(test_type, config)
                results.append(result)

        return results

    def _run_single_performance_test(self, test_type: str, config: str) -> Dict:
        """Run single performance test

        Args:
            test_type: Test type (throughput/latency/pps)
            config: Test configuration

        Returns:
            Test result
        """
        result = {
            "test_type": test_type,
            "config": config,
            "start_time": datetime.now().isoformat()
        }

        try:
            if test_type == "throughput":
                self._run_throughput_test(config)
            elif test_type == "latency":
                self._run_latency_test(config)
            elif test_type == "pps":
                self._run_pps_test(config)

            result['status'] = "completed"
        except Exception as e:
            logger.error(f"Performance test failed: {str(e)}")
            result['status'] = "failed"
            result['error'] = str(e)
        finally:
            result['end_time'] = datetime.now().isoformat()

        return result

    def _run_throughput_test(self, config: str):
        """Run throughput performance test"""
        # Implementation placeholder
        logger.info(f"Running throughput test: {config}")
        time.sleep(2)  # Simulate test execution

    def _run_latency_test(self, config: str):
        """Run latency performance test"""
        # Implementation placeholder
        logger.info(f"Running latency test: {config}")
        time.sleep(2)  # Simulate test execution

    def _run_pps_test(self, config: str):
        """Run PPS performance test"""
        # Implementation placeholder
        logger.info(f"Running PPS test: {config}")
        time.sleep(2)  # Simulate test execution

    def _start_custom_monitoring(self, host_ref: str, ebpf_pid: str,
                                result_path: str, timestamp: str):
        """Start custom monitoring for eBPF program"""
        monitoring_path = f"{result_path}/ebpf_monitoring"

        # CPU monitoring
        cpu_cmd = f"""nohup bash -c 'while kill -0 {ebpf_pid} 2>/dev/null; do \
            echo "$(date +\\"%Y-%m-%d %H:%M:%S.%N\\")" $(top -b -n 1 -p {ebpf_pid} | tail -1 | awk "{{print \\$9}}"); \
            sleep 1; done' > {monitoring_path}/tool_cpu_usage_{timestamp}.log 2>&1 &"""
        self.ssh_manager.execute_command(host_ref, cpu_cmd)

        # Memory monitoring
        mem_cmd = f"""nohup bash -c 'while kill -0 {ebpf_pid} 2>/dev/null; do \
            echo "$(date +\\"%Y-%m-%d %H:%M:%S.%N\\")" $(ps -p {ebpf_pid} -o vsz,rss --no-headers); \
            sleep 1; done' > {monitoring_path}/tool_memory_{timestamp}.log 2>&1 &"""
        self.ssh_manager.execute_command(host_ref, mem_cmd)

        logger.info(f"Started custom monitoring for PID: {ebpf_pid}")

    def _stop_custom_monitoring(self, host_ref: str):
        """Stop custom monitoring processes"""
        # Kill monitoring processes
        commands = [
            "pkill -f 'tool_cpu_usage' || true",
            "pkill -f 'tool_memory' || true"
        ]

        for cmd in commands:
            self.ssh_manager.execute_command(host_ref, cmd)

        logger.info("Stopped custom monitoring")

    def _set_test_context(self, cycle: Dict, workflow_spec: Dict):
        """Set current test context"""
        self.current_test_context = {
            'cycle': cycle,
            'workflow': workflow_spec,
            'environment': cycle['environment']
        }

    def _get_result_path(self, cycle: Dict) -> str:
        """Get result path for test cycle"""
        base_workdir = "/home/smartx/lcc"  # Default, should be from config
        results_dir = f"{base_workdir}/performance-test-results"

        if cycle['cycle_type'] == 'baseline':
            return f"{results_dir}/{cycle['result_path']}"
        else:
            return f"{results_dir}/{cycle['result_path']}"

    def _get_workdir(self, host_ref: str) -> str:
        """Get working directory for host"""
        # Should get from config
        if 'vm' in host_ref:
            return "/root/lcc"
        else:
            return "/home/smartx/lcc"

    def _get_host_ref_for_env(self, env_name: str, role: str) -> str:
        """Get host reference for environment and role"""
        # Map environment and role to host reference
        return f"{env_name}-{role}"

    def _write_test_metadata(self, cycle: Dict, result_path: str, timestamp: str):
        """Write test metadata to remote"""
        metadata = {
            "cycle_id": cycle['cycle_id'],
            "cycle_type": cycle['cycle_type'],
            "environment": cycle['environment'],
            "timestamp": timestamp,
            "execution_time": datetime.now().isoformat()
        }

        metadata_file = f"{result_path}/metadata_{timestamp}.json"
        metadata_json = json.dumps(metadata, indent=2)

        host_ref = self._get_host_ref_for_env(cycle['environment'], 'server')
        self.ssh_manager.execute_command(
            host_ref,
            f"echo '{metadata_json}' > {metadata_file}"
        )

        logger.info(f"Wrote metadata to {metadata_file}")