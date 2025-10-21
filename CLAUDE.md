# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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