# Remote Execution Tools

This directory contains tools for remote execution of BPF/BCC programs on target systems.

## bpf_remote_executor.py

A specialized remote execution tool for BPF/BCC programs that require proper signal handling for graceful shutdown and debug statistics output.

### Features

- SSH-based remote BPF program execution
- Proper SIGINT (Ctrl+C) handling using expect for KeyboardInterrupt
- Captures complete debug statistics output
- Automatic cleanup of temporary files
- Local BPF script deployment to remote system
- sudo support for privileged BPF operations
- Process pattern-based cleanup

### How It Works

1. **Script Deployment**: If `--local-script` is provided, copies the script to the remote workspace
2. **Process Cleanup**: Kills any existing processes matching the pattern
3. **Expect Script Creation**: Creates an expect script on the remote host that:
   - Spawns the BPF program in a proper terminal environment
   - Waits for "Hit Ctrl-C to end" output
   - Sends actual Ctrl+C signal (`\003`) after the specified duration
   - Allows Python to properly handle KeyboardInterrupt exception
   - Captures all output including debug statistics from the finally block
4. **Output Retrieval**: Fetches the complete output from the remote log file
5. **Cleanup**: Removes all temporary files (log files and expect scripts)

### Usage

```bash
# Basic usage
./bpf_remote_executor.py user@host /remote/workspace "command to run" --duration 10

# With sudo and local script deployment
./bpf_remote_executor.py user@host /remote/workspace "python2 bpf_script.py" --sudo --local-script ./bpf_script.py --duration 30

# With process pattern for cleanup
./bpf_remote_executor.py user@host /remote/workspace "python trace.py" --pattern "trace.py" --duration 60
```

### Arguments

- `host`: Remote host address (can include user@host)
- `workspace`: Remote directory to run BPF programs in
- `command`: BPF command to execute on remote system
- `--user`: Username (if not included in host)
- `--duration`: Execution duration in seconds before sending SIGINT (default: 10)
- `--pattern`: Process pattern for cleanup
- `--sudo`: Use sudo for BPF program execution
- `--local-script`: Local BPF script path to copy to remote workspace

### Examples

```bash
# Run VM network latency measurement
./bpf_remote_executor.py smartx@192.168.70.33 /home/smartx/lcc/vm-latency \
    "python2 vm_network_latency.py --vm-interface vnet57 --phy-interface enp94s0f0np0 \
     --dst-ip 192.168.76.198 --src-ip 192.168.64.1 --dst-port 22 --protocol tcp --direction rx" \
    --duration 30 --sudo --local-script ./vm_network_latency.py --pattern "vm_network_latency"

# Run BPF trace with debug output
./bpf_remote_executor.py root@target-server /tmp \
    "python bpf_trace.py" \
    --local-script ./bpf_trace.py --duration 60

# Simple BCC tool execution
./bpf_remote_executor.py user@host /usr/share/bcc/tools \
    "sudo python tcpconnect -t" \
    --duration 20
```

### Return Values

- 0: Successful execution with debug output captured
- -1: Execution error

### Output

The tool provides:
- Execution status updates
- Complete BPF program output including:
  - Program initialization messages
  - Real-time trace output
  - Debug statistics on graceful shutdown
- Cleanup confirmation for temporary files
- Return code from the execution

### Requirements

Remote host must have:
- SSH access
- `expect` package installed (for proper signal handling)
- Python with BCC/BPF support (if running BPF programs)
- sudo privileges (if using --sudo)

### Troubleshooting

1. **No debug statistics output**: Ensure the BPF program handles KeyboardInterrupt properly in a try/except/finally block
2. **expect not found**: Install expect on remote host: `sudo apt-get install expect` or `sudo yum install expect`
3. **Permission denied**: Use --sudo flag for BPF programs that require root privileges
4. **Temporary files not cleaned**: Check SSH connectivity and permissions on /tmp directory

### Implementation Details

The key innovation is using `expect` to send a real Ctrl+C character to the Python process, which properly triggers the KeyboardInterrupt exception. This allows BPF programs to execute their cleanup code in the finally block, outputting debug statistics that would otherwise be lost with simple signal-based termination.