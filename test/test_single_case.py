#!/usr/bin/env python3
"""
Single test case execution script for performance testing
"""

import os
import sys
import subprocess
import time
from pathlib import Path

# Add the test/tools directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'tools'))

from bpf_remote_executor import BPFRemoteExecutor

def create_results_dir():
    """Create results directory according to spec: performance-test-results"""
    results_dir = "test/performance-test-results"
    os.makedirs(results_dir, exist_ok=True)
    return results_dir

def parse_test_cases():
    """Parse test cases from the test cases file"""
    test_cases = []
    with open('test/performance-test-cases.txt', 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                test_cases.append(line)
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

# Remove debug extraction function as per updated spec - all output goes to result file

def run_single_test(test_command, case_name, results_dir):
    """Run a single test case and save results"""
    print(f"\n=== Running test case: {case_name} ===")
    print(f"Command: {test_command}")

    # Initialize executor
    executor = BPFRemoteExecutor("172.21.152.82", "smartx")

    # Extract workspace from the command (it should be absolute path)
    if 'system-network' in test_command:
        workspace = "/home/smartx/lcc/ebpf-tools/performance/system-network"
    elif 'vm-network' in test_command:
        workspace = "/home/smartx/lcc/ebpf-tools/performance/vm-network"
    else:
        workspace = "/home/smartx/lcc"

    # Clean up the command to remove the full path and sudo
    command_parts = test_command.split()
    clean_command_parts = []

    for part in command_parts:
        if part == 'sudo':
            continue
        elif part == 'python3':
            clean_command_parts.append(part)
        elif part.startswith('/home/smartx/'):
            # Extract just the script name
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
        duration=10,
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

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 test_single_case.py <case_number>")
        print("Case numbers start from 1")
        sys.exit(1)

    try:
        case_number = int(sys.argv[1])
    except ValueError:
        print("Error: Case number must be an integer")
        sys.exit(1)

    # Parse test cases
    test_cases = parse_test_cases()

    if case_number < 1 or case_number > len(test_cases):
        print(f"Error: Case number must be between 1 and {len(test_cases)}")
        sys.exit(1)

    # Create results directory
    results_dir = create_results_dir()
    print(f"Results will be saved to: {results_dir}")

    # Get the specific test case
    test_command = test_cases[case_number - 1]
    case_name = generate_case_name(test_command)

    # Run the test
    success = run_single_test(test_command, case_name, results_dir)

    if success:
        print(f"\n✅ Test case {case_number} completed successfully")
    else:
        print(f"\n❌ Test case {case_number} failed")
        sys.exit(1)

if __name__ == "__main__":
    main()