#!/usr/bin/env python3
"""
Unified Test Runner with Configuration File Support
Supports both full test execution and single case execution
"""

import os
import sys
import subprocess
import time
import argparse
import yaml
import json
from pathlib import Path

# Add the test/tools directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

from bpf_remote_executor import BPFRemoteExecutor

class TestConfig:
    """Configuration manager for test execution"""
    def __init__(self, config_file, topic=None):
        self.config_file = config_file
        self.topic = topic
        self.config = self._load_config()

        # Validate topic if specified
        if self.topic and self.topic not in self.config.get('topics', {}):
            available_topics = list(self.config.get('topics', {}).keys())
            raise ValueError(f"Topic '{self.topic}' not found in config. Available topics: {available_topics}")

    def _validate_config_file(self):
        """Validate that the config file exists"""
        if not os.path.exists(self.config_file):
            raise FileNotFoundError(f"Config file not found: {self.config_file}")

    def _load_config(self):
        """Load configuration from YAML file"""
        self._validate_config_file()
        try:
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
            return config
        except Exception as e:
            raise RuntimeError(f"Failed to load config file {self.config_file}: {e}")

    @property
    def remote_host(self):
        return self.config['remote']['host']

    @property
    def remote_user(self):
        return self.config['remote']['user']

    @property
    def remote_workdir(self):
        return self.config['remote']['workdir']

    def get_topic_config(self, topic=None):
        """Get configuration for the specified topic or current topic"""
        target_topic = topic or self.topic
        if not target_topic:
            raise ValueError("No topic specified")
        if 'topics' not in self.config or target_topic not in self.config['topics']:
            raise ValueError(f"Topic '{target_topic}' not found in configuration")
        return self.config['topics'][target_topic]

    def get_available_topics(self):
        """Get list of available topics"""
        return list(self.config.get('topics', {}).keys())

    def get_local_dirs(self, topic=None):
        """Get local code directories for current topic"""
        topic_config = self.get_topic_config(topic)
        return topic_config.get('dirs', [])

    def get_case_file(self, topic=None):
        """Get test cases file path"""
        target_topic = topic or self.topic
        topic_config = self.get_topic_config(topic)
        return topic_config.get('case_file', f"test/workflow/case/{target_topic}-test-cases.json")

    def get_results_dir(self, topic=None):
        """Get results directory path"""
        target_topic = topic or self.topic
        topic_config = self.get_topic_config(topic)
        return topic_config.get('result_dir', f"test/workflow/result/{target_topic}")

def sync_code_to_remote(config, topic, force_copy=True):
    """Sync local code directories to remote workdir"""
    print(f"\n=== Syncing code to remote host {config.remote_host} ===")

    local_dirs = config.get_local_dirs(topic)
    if not local_dirs:
        print(f"No local directories configured for topic: {topic}")
        return False

    ssh_target = f"{config.remote_user}@{config.remote_host}"

    # Create remote workdir if it doesn't exist
    print(f"Creating remote workdir: {config.remote_workdir}")
    mkdir_result = subprocess.run([
        'ssh', ssh_target, f"mkdir -p {config.remote_workdir}"
    ], capture_output=True, text=True)

    if mkdir_result.returncode != 0:
        print(f"Error creating remote workdir: {mkdir_result.stderr}")
        return False

    # Sync each local directory
    for local_dir in local_dirs:
        if not os.path.exists(local_dir):
            print(f"Warning: Local directory not found: {local_dir}")
            continue

        print(f"Syncing {local_dir} to remote...")

        # Use rsync for better directory synchronization
        # Create the parent directory structure on remote
        remote_parent = f"{config.remote_workdir}/{os.path.dirname(local_dir)}"
        subprocess.run([
            'ssh', ssh_target, f"mkdir -p {remote_parent}"
        ], capture_output=True, text=True)

        # Sync the directory
        rsync_cmd = [
            'rsync', '-avz', '--delete' if force_copy else '--update',
            f"{local_dir}/",  # Trailing slash to sync contents
            f"{ssh_target}:{config.remote_workdir}/{local_dir}/"
        ]

        print(f"Running: {' '.join(rsync_cmd)}")
        rsync_result = subprocess.run(rsync_cmd, capture_output=True, text=True)

        if rsync_result.returncode != 0:
            print(f"Error syncing {local_dir}: {rsync_result.stderr}")
            return False
        else:
            print(f"Successfully synced {local_dir}")

    print("=== Code synchronization completed ===\n")
    return True

def sync_single_file_to_remote(script_name, config, topic, force_copy=True):
    """Sync a single script file to remote workdir"""
    print(f"\n=== Syncing single file to remote host {config.remote_host} ===")

    # Find the script file
    local_script_path, local_dir = find_script_file(script_name, config, topic)

    if not local_script_path:
        print(f"Error: Script file not found: {script_name}")
        return False

    print(f"Found script: {local_script_path}")
    print(f"In directory: {local_dir}")

    ssh_target = f"{config.remote_user}@{config.remote_host}"

    # Create remote directory structure
    remote_dir = f"{config.remote_workdir}/{local_dir}"
    print(f"Creating remote directory: {remote_dir}")

    mkdir_result = subprocess.run([
        'ssh', ssh_target, f"mkdir -p {remote_dir}"
    ], capture_output=True, text=True)

    if mkdir_result.returncode != 0:
        print(f"Error creating remote directory: {mkdir_result.stderr}")
        return False

    # Copy the single file
    remote_script_path = f"{remote_dir}/{script_name}"
    print(f"Copying {local_script_path} to {remote_script_path}")

    scp_result = subprocess.run([
        'scp', local_script_path, f"{ssh_target}:{remote_script_path}"
    ], capture_output=True, text=True)

    if scp_result.returncode != 0:
        print(f"Error copying file: {scp_result.stderr}")
        return False

    # Make it executable
    chmod_result = subprocess.run([
        'ssh', ssh_target, f"chmod +x {remote_script_path}"
    ], capture_output=True, text=True)

    if chmod_result.returncode != 0:
        print(f"Warning: Failed to make script executable: {chmod_result.stderr}")

    print(f"Successfully synced {script_name}")
    print("=== File synchronization completed ===\n")
    return True

def find_script_file(script_name, config, topic):
    """Find the local path of a script file"""
    local_dirs = config.get_local_dirs(topic)

    for local_dir in local_dirs:
        script_path = os.path.join(local_dir, script_name)
        if os.path.exists(script_path):
            return script_path, local_dir

    return None, None

def create_results_dir(config, topic):
    """Create results directory according to config"""
    results_dir = config.get_results_dir(topic)
    os.makedirs(results_dir, exist_ok=True)
    return results_dir

def parse_test_cases(config, topic):
    """Parse test cases from the JSON test cases file"""
    case_file = config.get_case_file(topic)

    if not os.path.exists(case_file):
        raise FileNotFoundError(f"Test cases file not found: {case_file}")

    try:
        with open(case_file, 'r') as f:
            if case_file.endswith('.json'):
                data = json.load(f)
                test_cases = data.get('test_cases', [])
            else:
                # Fallback to text format for backwards compatibility
                test_cases = []
                f.seek(0)
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Convert old format to new format
                        test_cases.append({
                            'id': len(test_cases) + 1,
                            'name': generate_case_name(line),
                            'command': line,
                            'duration': 10  # Default duration for old format
                        })
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Failed to parse JSON test cases file {case_file}: {e}")
    except Exception as e:
        raise RuntimeError(f"Failed to load test cases file {case_file}: {e}")

    return test_cases

def generate_case_name(command):
    """Generate a descriptive name for the test case"""
    parts = command.split()

    # Extract the script name
    script_name = None
    for part in parts:
        if part.endswith('.py'):
            script_name = os.path.basename(part).replace('.py', '')
            break

    if not script_name:
        return "unknown_test"

    # Extract direction and protocol
    direction = None
    protocol = None

    for i, part in enumerate(parts):
        if part == '--direction' and i + 1 < len(parts):
            direction = parts[i + 1]
        elif part == '--protocol' and i + 1 < len(parts):
            protocol = parts[i + 1]

    # Build case name
    case_parts = [script_name]
    if direction:
        case_parts.append(direction)
    if protocol:
        case_parts.append(protocol)

    return '_'.join(case_parts)

def extract_script_name_from_command(command):
    """Extract the script name from a test command"""
    parts = command.split()
    for part in parts:
        if part.endswith('.py'):
            return os.path.basename(part)
    return None

def run_single_test(test_command, case_name, results_dir, config, topic, duration=10):
    """Run a single test case and save results"""
    print(f"\n=== Running test case: {case_name} ===")
    print(f"Command: {test_command}")

    # Initialize executor
    executor = BPFRemoteExecutor(config.remote_host, config.remote_user)

    # Extract workspace from the command - check script names
    if 'system_network_' in test_command:
        workspace = f"{config.remote_workdir}/ebpf-tools/performance/system-network"
    elif 'vm_network_' in test_command:
        workspace = f"{config.remote_workdir}/ebpf-tools/performance/vm-network"
    else:
        workspace = config.remote_workdir

    # Clean up the command to remove the full path and sudo
    command_parts = test_command.split()
    clean_command_parts = []

    for part in command_parts:
        if part == 'sudo':
            continue
        elif part == 'python3':
            clean_command_parts.append(part)
        elif part.endswith('.py'):
            # Extract just the script name from any path (absolute or relative)
            script_name = os.path.basename(part)
            clean_command_parts.append(script_name)
        else:
            clean_command_parts.append(part)

    clean_command = ' '.join(clean_command_parts)

    print(f"Workspace: {workspace}")
    print(f"Clean command: {clean_command}")

    # Execute the test
    return_code, output, error = executor.execute_bpf(
        workspace=workspace,
        command=clean_command,
        duration=duration,
        use_sudo=True
    )

    # Save complete results to single file as per updated spec
    result_file = os.path.join(results_dir, f"{case_name}_result.txt")

    with open(result_file, 'w') as f:
        f.write(f"=== Test Case: {case_name} ===\n")
        f.write(f"Command: {test_command}\n")
        f.write(f"Return Code: {return_code}\n")
        f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 50 + "\n")
        f.write(output)  # Include complete output including debug info
        if error:
            f.write(f"\n=== Error Output ===\n")
            f.write(error)

    print(f"Results saved to {result_file}")

    return return_code == 0

def create_summary_report(results_dir, test_results, config):
    """Create a summary report of all test results"""
    summary_file = os.path.join(results_dir, "test_summary.txt")

    with open(summary_file, 'w') as f:
        topic_config = config.get_topic_config()
        f.write(f"=== {topic_config.get('name', config.topic.title())} Test Summary Report ===\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Topic: {config.topic}\n")
        f.write(f"Description: {topic_config.get('description', 'No description')}\n")
        f.write(f"Total Tests: {len(test_results)}\n")

        passed = sum(1 for result in test_results if result['success'])
        failed = len(test_results) - passed

        f.write(f"Passed: {passed}\n")
        f.write(f"Failed: {failed}\n")
        f.write("=" * 50 + "\n\n")

        f.write("=== Individual Test Results ===\n")
        for i, result in enumerate(test_results, 1):
            status = "PASS" if result['success'] else "FAIL"
            f.write(f"{i:2d}. [{status}] {result['case_name']}\n")

        f.write("\n=== Failed Tests Details ===\n")
        for i, result in enumerate(test_results, 1):
            if not result['success']:
                f.write(f"{i}. {result['case_name']}: {result['command']}\n")

    print(f"Summary report saved to: {summary_file}")

def run_tests(config, topic=None, case_numbers=None, no_copy=False, force_copy=True):
    """Run tests based on configuration"""
    target_topic = topic or config.topic
    if not target_topic:
        print("Available topics:")
        for t in config.get_available_topics():
            topic_config = config.get_topic_config(t)
            print(f"  {t}: {topic_config.get('description', 'No description')}")
        return

    print(f"=== Running tests for topic: {target_topic} ===")
    print(f"Remote host: {config.remote_host}")
    print(f"Remote workdir: {config.remote_workdir}")
    print(f"Config file: {config.config_file}")

    # Parse test cases
    test_cases = parse_test_cases(config, target_topic)
    print(f"Found {len(test_cases)} test cases available")

    # Filter test cases if specific case numbers are provided
    if case_numbers:
        filtered_cases = []
        for case_num in case_numbers:
            # Find test case by ID
            found_case = None
            for case in test_cases:
                if isinstance(case, dict) and case.get('id') == case_num:
                    found_case = case
                    break
                elif isinstance(case, str) and case_num <= len(test_cases):
                    # Backwards compatibility for old format
                    found_case = case
                    break

            if found_case:
                filtered_cases.append((case_num, found_case))
            else:
                available_ids = [case.get('id', i+1) if isinstance(case, dict) else i+1 for i, case in enumerate(test_cases)]
                print(f"Warning: Case ID {case_num} not found. Available IDs: {available_ids}")

        if not filtered_cases:
            print("Error: No valid case IDs provided")
            sys.exit(1)

        print(f"Running {len(filtered_cases)} selected test cases: {[c[0] for c in filtered_cases]}")
    else:
        # Run all cases
        filtered_cases = []
        for i, case in enumerate(test_cases):
            case_id = case.get('id', i+1) if isinstance(case, dict) else i+1
            filtered_cases.append((case_id, case))
        print(f"Running all {len(filtered_cases)} test cases")

    # Sync code to remote unless --no-copy is specified
    if not no_copy:
        if len(filtered_cases) == 1 and case_numbers:
            # Single case: sync only the specific script file
            _, test_case = filtered_cases[0]
            test_command = test_case.get('command', test_case) if isinstance(test_case, dict) else test_case
            script_name = extract_script_name_from_command(test_command)
            if script_name:
                if not sync_single_file_to_remote(script_name, config, target_topic, force_copy):
                    print("File synchronization failed. Exiting.")
                    sys.exit(1)
            else:
                print("Warning: Could not extract script name from command. Skipping file sync.")
        else:
            # Multiple cases or full run: sync all directories
            if not sync_code_to_remote(config, target_topic, force_copy):
                print("Code synchronization failed. Exiting.")
                sys.exit(1)
    else:
        print("Skipping code synchronization (--no-copy specified)")

    # Create results directory
    results_dir = create_results_dir(config, target_topic)
    print(f"Results will be saved to: {results_dir}")

    # Run selected tests
    test_results = []

    for i, (case_id, test_case) in enumerate(filtered_cases, 1):
        # Extract case information based on format
        if isinstance(test_case, dict):
            case_name = test_case.get('name', f'test_case_{case_id}')
            test_command = test_case.get('command', '')
            duration = test_case.get('duration', 10)
        else:
            # Backwards compatibility for old text format
            test_command = test_case
            case_name = generate_case_name(test_command)
            duration = 10

        print(f"\n{'='*60}")
        print(f"Progress: {i}/{len(filtered_cases)} (Case ID: {case_id})")

        try:
            success = run_single_test(test_command, case_name, results_dir, config, target_topic, duration)
            test_results.append({
                'case_name': case_name,
                'command': test_command,
                'case_id': case_id,
                'success': success
            })

            if success:
                print(f"PASS Test ID {case_id}: {case_name}")
            else:
                print(f"FAIL Test ID {case_id}: {case_name}")

        except Exception as e:
            print(f"ERROR Test ID {case_id}: {case_name} - {str(e)}")
            test_results.append({
                'case_name': case_name,
                'command': test_command,
                'case_id': case_id,
                'success': False
            })

        # Small delay between tests
        if i < len(filtered_cases):
            time.sleep(2)

    # Create summary report
    create_summary_report(results_dir, test_results, config)

    # Final summary
    passed = sum(1 for result in test_results if result['success'])
    failed = len(test_results) - passed

    print(f"\n{'='*60}")
    print(f"=== FINAL SUMMARY ===")
    print(f"Topic: {config.topic}")
    print(f"Cases run: {len(test_results)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success rate: {passed/len(test_results)*100:.1f}%")
    print(f"Results directory: {results_dir}")

    if failed > 0:
        print(f"\nFAIL {failed} tests failed")
        sys.exit(1)
    else:
        print(f"\nPASS All tests passed!")

def main():
    parser = argparse.ArgumentParser(
        description='Unified test runner with configuration file support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all available topics in config
  python3 test_runner.py --config test/workflow/config/performance-test-config.yaml

  # Run all tests for a specific topic
  python3 test_runner.py --config test/workflow/config/performance-test-config.yaml --topic performance

  # Run specific test cases for a topic
  python3 test_runner.py --config test/workflow/config/performance-test-config.yaml --topic performance --cases 1 3 5

  # Run without code synchronization
  python3 test_runner.py --config test/workflow/config/performance-test-config.yaml --topic performance --no-copy
        """)

    parser.add_argument('--config', required=True, help='Configuration file path')
    parser.add_argument('--topic', help='Test topic to run (optional, if not specified, lists available topics)')
    parser.add_argument('--cases', type=int, nargs='+', help='Specific case numbers to run (1-based, requires --topic)')
    parser.add_argument('--no-copy', action='store_true', help='Skip code synchronization')
    parser.add_argument('--force-copy', action='store_true', help='Force overwrite remote code (default: true)')

    args = parser.parse_args()

    # Validate arguments
    if args.cases and not args.topic:
        print("Error: --cases requires --topic to be specified")
        sys.exit(1)

    try:
        # Initialize configuration
        config = TestConfig(args.config, args.topic)

        # Run tests
        run_tests(
            config=config,
            topic=args.topic,
            case_numbers=args.cases,
            no_copy=args.no_copy,
            force_copy=not args.force_copy if args.force_copy else True
        )

    except FileNotFoundError as e:
        print(f"Config Error: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"Configuration Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()