# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

<<<<<<< HEAD
## Memory File Structure
This is the main Claude configuration file. Additional context-specific memory files:
- `claude_local_project_overview.md` - project overview
- `claude_local_coding.md` - BPF/BCC coding guidelines and conventions
- `claude_local_test.md` - Testing procedures and environment setup

## Quick Reference

### Common Commands
```bash
# Execute BCC tools (requires root/sudo)
sudo python2 ebpf-tools/linux-network-stack/packet-drop/eth_drop.py
sudo python2 ebpf-tools/performance/system-network/icmp_rtt_latency.py --src-ip IP1 --dst-ip IP2

# Execute bpftrace scripts
sudo bpftrace ebpf-tools/other/trace-abnormal-arp.bt
sudo bpftrace ebpf-tools/kvm-virt-network/tun/tun-abnormal-gso-type.bt
```

### Architecture Overview
**eBPF-based network troubleshooting toolset** for virtualized environments:
- **ebpf-tools/**: Main directory containing all eBPF tools
  - **linux-network-stack/**: Packet drop monitoring, connection tracking
  - **performance/**: System and VM network latency measurement
  - **ovs/**: Open vSwitch monitoring (megaflow, upcall, drops)
  - **kvm-virt-network/**: Virtio/TUN/TAP/vhost monitoring
  - **cpu/**: CPU and scheduler analysis tools
- **Target Stack**: Physical → OVS → TUN/TAP → VM network layers
- **Target Kernel**: openEuler 4.19.90

### Critical Safety Notes
- **All tools require root access** - can impact system performance
- **Test in dev environment first** - never run untested BPF on production
- **BPF stack limit**: 512 bytes - use maps for large data structures
- **Python compatibility**: Tools use `#!/usr/bin/env python` for Python 2/3 compatibility

## BCC Tool Development Guidelines
See `claude_local_coding.md` for detailed BPF/BCC coding guidelines including:
- Import patterns and Python compatibility
- Code style rules
- eBPF implementation details

## Important Instructions
Do what has been asked; nothing more, nothing less.
NEVER create files unless they're absolutely necessary for achieving your goal.
ALWAYS prefer editing an existing file to creating a new one.
NEVER proactively create documentation files (*.md) or README files unless explicitly requested.
=======
## Overview

This is a comprehensive eBPF-based toolset for monitoring, tracing, and analyzing network performance issues in virtualized environments. The tools help identify packet drops, measure latency, trace data paths, and analyze system performance bottlenecks.

## Key Commands

### Testing and Running Tools

**Run the test suite:**
```bash
# Generate test cases
python3 test/workflow/tools/test_case_generator.py --spec test/workflow/spec/performance-test-spec.yaml --output test/workflow/case/performance-test-cases.json

# Run all tests for a topic
python3 test/workflow/tools/test_runner.py --config test/workflow/config/performance-test-config.yaml --topic performance

# Run specific test case
python3 test/workflow/tools/test_runner.py --config test/workflow/config/performance-test-config.yaml --topic performance --cases 1
```

**Common eBPF tool commands (require sudo):**
```bash
# System network performance metrics
sudo python3 ebpf-tools/performance/system-network/system_network_perfomance_metrics.py --internal-interface port-storage --phy-interface ens11 --src-ip 10.132.114.11 --dst-ip 10.132.114.12 --direction rx --protocol tcp

# VM network latency summary
sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_summary.py --vm-interface vnet0 --phy-interface ens4 --direction tx --src-ip 172.21.153.114 --dst-ip 172.21.153.113 --protocol tcp

# Packet drop monitoring
sudo python3 ebpf-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats_summary.py

# OVS monitoring
sudo python3 ebpf-tools/ovs/ovs_userspace_megaflow.py --debug
```

## Architecture

### Directory Structure

- **`ebpf-tools/`**: Main directory containing all eBPF monitoring tools
  - `performance/`: Network performance measurement tools
    - `system-network/`: Host-level network performance tools
    - `vm-network/`: VM network performance analysis tools
  - `linux-network-stack/`: Linux kernel network stack tracing
    - `packet-drop/`: Packet drop analysis tools
  - `ovs/`: Open vSwitch monitoring tools
  - `kvm-virt-network/`: KVM/virtio network monitoring
  - `cpu/`: CPU performance analysis tools

- **`test/workflow/`**: Testing framework
  - `spec/`: Test specifications (YAML files defining test parameters)
  - `config/`: Test configurations (remote host, paths, etc.)
  - `case/`: Generated test cases (JSON)
  - `tools/`: Test runner and generator scripts

- **`docs/`**: Design documents and detailed analysis guides

### Key Design Patterns

1. **Tool Arguments**: Most tools follow a consistent argparse pattern with common flags:
   - `--src-ip`, `--dst-ip`: Source and destination IP addresses
   - `--protocol`: Protocol type (tcp, udp, icmp)
   - `--direction`: Traffic direction (rx, tx)
   - `--phy-interface`: Physical interface name
   - `--vm-interface`: Virtual machine interface name
   - `--debug`: Enable debug output

2. **Test Framework**: Uses a specification-driven approach:
   - Test specs define parameter matrices and tool configurations
   - Test runner executes tools remotely via SSH (configured for `smartx@172.21.152.82`)
   - Results are collected and stored in `test/workflow/result/`

3. **eBPF Patterns**: Tools use BCC (BPF Compiler Collection) Python bindings:
   - Attach to kernel tracepoints, kprobes, or uprobes
   - Collect metrics in BPF maps
   - Process and display results in Python userspace

## Important Notes

- All eBPF tools require root privileges (sudo)
- Tools are designed for Linux with eBPF support (kernel 4.1+ recommended)
- Remote test execution assumes SSH access to configured test hosts
- Performance tools may introduce overhead in production environments
- Use filtering options to reduce noise and performance impact
>>>>>>> f4bf5d6 (feat: update git ignore)
