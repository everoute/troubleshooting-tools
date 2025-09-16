#!/usr/bin/env python
"""
BPF-specific remote execution tool - Final Version

Specialized for BPF/BCC programs that need graceful shutdown handling
with proper debug statistics output capture and cleanup.
"""

import subprocess
import time
import sys
import argparse
import signal
import os
import random


class BPFRemoteExecutor:
    
    def __init__(self, host, user=None):
        self.host = host
        self.user = user
        self.ssh_target = f"{user}@{host}" if user else host
    
    def execute_bpf(self, workspace, command, duration=10, process_pattern=None, 
                   use_sudo=False, local_script=None):
        """
        Execute BPF program with proper KeyboardInterrupt handling
        """
        
        print(f"=== BPF Remote Execution on {self.ssh_target} ===")
        print(f"Workspace: {workspace}")
        print(f"Command: {command}")
        print(f"Duration: {duration}s")
        print(f"Process pattern: {process_pattern}")
        if local_script:
            print(f"Local script: {local_script}")
        
        # Generate unique output file
        output_file = f"/tmp/bpf_output_{int(time.time())}_{random.randint(1000, 9999)}.txt"
        expect_file = None
        
        try:
            # Copy local script if provided
            if local_script:
                if not os.path.exists(local_script):
                    raise FileNotFoundError(f"Local script not found: {local_script}")
                
                # Ensure remote workspace directory exists
                mkdir_result = subprocess.run([
                    'ssh', self.ssh_target, f"mkdir -p {workspace}"
                ], capture_output=True, text=True)
                
                if mkdir_result.returncode != 0:
                    print(f"Warning: Failed to create workspace directory: {mkdir_result.stderr}")
                
                script_name = os.path.basename(local_script)
                remote_path = f"{workspace}/{script_name}"
                
                print(f"Copying {local_script} to {self.ssh_target}:{remote_path}")
                scp_result = subprocess.run([
                    'scp', local_script, f"{self.ssh_target}:{remote_path}"
                ], capture_output=True, text=True)
                
                if scp_result.returncode != 0:
                    raise RuntimeError(f"SCP failed: {scp_result.stderr}")
                
                # Make it executable
                chmod_result = subprocess.run([
                    'ssh', self.ssh_target, f"chmod +x {remote_path}"
                ], capture_output=True, text=True)
                
                if chmod_result.returncode != 0:
                    print(f"Warning: Failed to make script executable: {chmod_result.stderr}")
                
                print(f"Script copied and made executable")
            
            # Initial cleanup if pattern provided
            if process_pattern:
                self._cleanup_processes(process_pattern)
            
            # Build the complete command
            if use_sudo:
                full_command = f"cd {workspace} && sudo {command}"
            else:
                full_command = f"cd {workspace} && {command}"

            # Escape quotes for expect script
            escaped_command = full_command.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$')

            # Use expect script for proper Ctrl+C handling
            expect_script = f'''#!/usr/bin/expect -f
set timeout {duration + 5}
log_file {output_file}
spawn bash -c "{escaped_command}"

# Start timer immediately, regardless of output
after [expr {duration} * 1000] {{
    send "\\003"
    expect {{
        eof {{ exit 0 }}
        timeout {{ 
            send "\\003"
            expect eof {{ exit 0 }}
        }}
    }}
}}

# Handle program output and termination
expect {{
    eof {{
        exit 0
    }}
    timeout {{
        send "\\003"
        expect {{
            eof {{ exit 0 }}
            timeout {{
                send "\\003"
                send "\\003"
                exit 1
            }}
        }}
    }}
}}
'''
            
            expect_file = f"/tmp/bpf_expect_{int(time.time())}.exp"
            
            # Write expect script to remote
            print(f"Creating expect script for proper Ctrl+C handling...")
            write_expect_result = subprocess.run([
                'ssh', self.ssh_target, f"cat > {expect_file}"
            ], input=expect_script, text=True, capture_output=True)
            
            if write_expect_result.returncode != 0:
                raise RuntimeError(f"Failed to write expect script: {write_expect_result.stderr}")
            
            # Make it executable
            subprocess.run(['ssh', self.ssh_target, f"chmod +x {expect_file}"], 
                          capture_output=True)
            
            print(f"\nStarting BPF program using expect for proper signal handling...")
            start_result = subprocess.run([
                'ssh', self.ssh_target, expect_file
            ], capture_output=True, text=True)
            
            print(f"Expect script completed with return code: {start_result.returncode}")
            
            # Retrieve complete log file
            print(f"Retrieving complete output from {output_file}...")
            log_result = subprocess.run([
                'ssh', self.ssh_target, f"cat {output_file}"
            ], capture_output=True, text=True)
            
            if log_result.returncode != 0:
                print(f"Warning: Failed to retrieve log file: {log_result.stderr}")
                output_content = ""
            else:
                output_content = log_result.stdout
            
            # Display complete output
            if output_content.strip():
                print(f"\n=== Complete BPF Program Output ===")
                for line in output_content.splitlines():
                    print(f">> {line}")
                print(f"=== End of Output ===")
            else:
                print("No output captured from BPF program")
            
            # Cleanup temporary files
            self._cleanup_temp_files(output_file, expect_file)
            
            print(f"\n=== Execution completed successfully ===")
            return 0, output_content, ""
            
        except Exception as e:
            print(f"Error during execution: {e}")
            if process_pattern:
                self._cleanup_processes(process_pattern, force=True)
            # Cleanup files on error
            if expect_file:
                self._cleanup_temp_files(output_file, expect_file)
            else:
                self._cleanup_temp_files(output_file, None)
            return -1, "", str(e)
    
    def _cleanup_temp_files(self, output_file, expect_file):
        """Clean up temporary files on remote host"""
        files_to_cleanup = []
        if output_file:
            files_to_cleanup.append(output_file)
        if expect_file:
            files_to_cleanup.append(expect_file)
            
        if files_to_cleanup:
            cleanup_cmd = f"rm -f {' '.join(files_to_cleanup)}"
            cleanup_result = subprocess.run([
                'ssh', self.ssh_target, cleanup_cmd
            ], capture_output=True, text=True)
            
            if cleanup_result.returncode != 0:
                print(f"Warning: Failed to cleanup temporary files: {cleanup_result.stderr}")
            else:
                print(f"Cleaned up temporary files: {', '.join(files_to_cleanup)}")
    
    def _cleanup_processes(self, pattern, force=False):
        signal_type = "KILL" if force else "TERM"
        print(f"Cleaning up processes matching '{pattern}' with {signal_type}...")
        
        cleanup_cmd = f"sudo pkill -{signal_type} -f \"{pattern}\""
        result = subprocess.call(['ssh', self.ssh_target, cleanup_cmd], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if result == 0:
            print(f"Processes cleaned up successfully")


def main():
    parser = argparse.ArgumentParser(description='BPF Remote execution tool - Final Version')
    parser.add_argument('host', help='Remote host address')
    parser.add_argument('workspace', help='Remote workspace directory')
    parser.add_argument('command', help='BPF command to execute')
    parser.add_argument('--user', help='Username')
    parser.add_argument('--duration', type=int, default=10, help='Execution duration (seconds)')
    parser.add_argument('--pattern', help='Process pattern for cleanup')
    parser.add_argument('--sudo', action='store_true', help='Use sudo')
    parser.add_argument('--local-script', help='Local script path to copy to remote workspace')
    
    args = parser.parse_args()
    
    executor = BPFRemoteExecutor(args.host, args.user)
    
    code, stdout, stderr = executor.execute_bpf(
        workspace=args.workspace,
        command=args.command,
        duration=args.duration,
        process_pattern=args.pattern,
        use_sudo=args.sudo,
        local_script=args.local_script
    )
    
    print(f"\nReturn code: {code}")
    return code


if __name__ == "__main__":
    sys.exit(main())