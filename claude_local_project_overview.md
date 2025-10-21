## Project Overview

This is a troubleshooting and performance analysis toolset for virtualized network systems. It contains eBPF-based tools for monitoring, tracing, and analyzing network packet drops, latency, and data path issues in virtualization environments. The primary focus is on providing comprehensive network performance analysis capabilities for virtualized infrastructures.

## Architecture

The codebase follows a modular architecture with tools organized by functionality and technology:

### Core Directories
- **bcc-tools/**: Python-based BPF tools using the BCC framework (main functionality)
  - **packet-drop/**: Packet drop analysis (`eth_drop.py`)
  - **performance/**: Performance analysis tools with subdirectories:
    - **system-network/**: System-level network latency tools
    - **vm-network/**: VM network performance analysis with vm_pair_latency subdirectory
  - **ovs/**: Open vSwitch specific monitoring tools
  - **linux-network-stack/**: Linux kernel network stack tracing
  - **cpu/**: CPU-specific monitoring and latency analysis
  - **virtio-network/**: Virtio network device monitoring (TUN/TAP devices, vhost, KVM IRQ)

- **bpftrace-tools/**: High-level tracing scripts using bpftrace syntax
  - **Network event tracers**: ARP anomalies (`trace-abnormal-arp.bt`), OVS conntrack (`trace-ovs-ct-invalid.bt`)
  - **Queue and transmission**: qdisc dequeue (`trace-qdisc-dequeue.bt`), dev queue xmit (`trace_dev_queue_xmit.bt`)
  - **Virtio tracing**: virtio interrupt (`trace_virtio_interrupt_simple.bt`), virtnet polling (`trace_virtnet_poll.bt`)
  - **TUN/VHOST**: TUN ring (`tun-ring.bt`), TUN GSO type (`tun-abnormal-gso-type.bt`), vhost eventfd (`vhost_eventfd_count.bt`)
  - **VPC/VM datapath**: UDP workload (`trace_vlanvm_udp_workload.bt`), VM UDP datapath (`vpc-vm-udp-datapath.bt`)

- **kernel-source/**: Linux kernel source code (openEuler 4.19.90) for reference
- **docs/**: Documentation and design documents for analysis methodologies

## Development Commands

### Running BPF Tools

All BPF tools require root privileges. Python tools use env python (marked with `#!/usr/bin/env python`):

```bash
# Packet drop monitoring
sudo python bcc-tools/packet-drop/eth_drop.py

# System network latency measurement
sudo python bcc-tools/performance/system-network/icmp_rtt_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 --phy-iface1 eth0 --phy-iface2 eth1

# TCP/UDP latency measurement 
sudo python bcc-tools/performance/system-network/system_tcp_udp_latency.py

# VM network latency measurement
sudo python bcc-tools/performance/vm-network/vm_network_latency.py

# VM pair latency analysis
sudo python bcc-tools/performance/vm-network/vm_pair_latency/vm_pair_latency.py

# TUN device ring buffer monitoring
sudo python bcc-tools/virtio-network/tun_ring_monitor.py --device vnet12

# KVM IRQ statistics
sudo python bcc-tools/virtio-network/kvm_irqfd_stats.py

# Run with log output
sudo python [tool-name] [options] > output.log 2>&1
```

### Running bpftrace Scripts

```bash
# Run bpftrace scripts
sudo bpftrace bpftrace-tools/trace-abnormal-arp.bt
sudo bpftrace bpftrace-tools/trace-ovs-ct-invalid.bt
sudo bpftrace bpftrace-tools/vpc-vm-udp-datapath.bt
```

### Testing and Deployment

BCC tools that require testing should be deployed to the test environment:

```bash
# Deploy to test environment
scp [tool-name] smartx@192.168.70.33:/home/smartx/lcc/[test-directory]/
# or use: ssh mcpserver

# Run tests remotely
ssh smartx@192.168.70.33
# or use: ssh mcpserver
```

Create test subdirectories under `/home/smartx/lcc/` named after the tool's purpose for each testing session.

## Key Components and Data Flow Architecture

### Packet Drop Analysis Pipeline
- **Ethernet Drop Monitor**: `bcc-tools/packet-drop/eth_drop.py`
  - Traces `kfree_skb` kernel function to detect packet drops
  - Supports filtering by protocol type (ARP, IPv4, IPv6, etc.)
  - Provides kernel stack traces for drop location analysis
  - Filters out normal expected drops with pattern matching

### Performance Analysis Layers
- **System Network**: Physical host network interfaces and kernel stack
  - ICMP latency measurement: `icmp_rtt_latency.py`
  - TCP/UDP latency measurement: `system_tcp_udp_latency.py`
  - TCP latency measurement: `tcp_latency.py`
  - Interface network statistics: `iface_netstat.py`
- **VM Network**: Virtual machine network interfaces (TUN/TAP devices, vnet interfaces)
  - VM network latency: `vm_network_latency.py`
  - VM pair latency analysis: `vm_pair_latency.py`, `multi_vm_pair_latency.py`
  - VM pair latency gap analysis: `vm_pair_gap.py`, `multi_port_gap.py`
- **Virtio Network**: Virtio network device performance
  - TUN ring buffer monitoring: `tun_ring_monitor.py`
  - KVM IRQ statistics: `kvm_irqfd_stats.py`, `kvm_irqfd_stats_histogram.py`
  - VHOST buffer and queue monitoring: `vhost_buf_peek_stats.py`, `vhost_queue_*_monitor.py`
  - Virtnet IRQ and polling: `virtnet_irq_monitor.py`, `virtnet_poll_monitor.py`
  - TUN TX to KVM IRQ correlation: `tun_tx_to_kvm_irq.py`

### OVS (Open vSwitch) Integration
- **Kernel Module Analysis**: `ovs-kernel-module-drop-monitor.py`
- **Userspace Flow Analysis**: `ovs_userspace_megaflow.py`
- **Megaflow Kernel Parse**: `ovs_megaflow_kernel_parse.py`
- **Connection Tracking**: `trace-ovs-ct-invalid.bt` (in bpftrace-tools)

### CPU Performance and Analysis
- **CPU Monitoring**: `cpu_monitor.sh`, `offcputime-ts.py`
- **Scheduler Analysis**: `sched_latency_monitor.sh`
- **Thread Locking**: `futex.bt`, `pthread_rwlock_wrlock.bt`, `pthread_rwlock_wrlock-stack.bt`

## Virtualized Network Architecture

The toolset is designed for complex virtualized network environments with multiple layers:

### Network Stack Hierarchy
1. **Physical Network Layer**: Host physical interfaces (eth0, eth1, etc.)
2. **Virtualization Layer**: TUN/TAP devices, vnet interfaces, OVS bridges
3. **Guest Network Layer**: VM internal network interfaces
4. **Application Layer**: Network applications and services

### Data Path Analysis Methodology
- **Root Cause Analysis**: Tools trace execution paths to identify where data structures/metadata values change unexpectedly, affecting control logic
- **Drop Analysis**: Beyond simple drop detection, tools analyze data structure changes at multiple points along the data path
- **Performance Bottleneck Identification**: Multi-layer latency measurement from physical to virtual interfaces

## Common Analysis Scenarios

### Execution Path Anomalies
When packet processing in virtualized data paths doesn't behave as expected, tools help identify:
- Control logic execution path changes
- Data structure/metadata value changes at critical points
- Correlation between multiple processing stages

### Packet Drop Root Cause Analysis
Tools provide detailed drop analysis by:
- Identifying drop locations through call stack analysis
- Analyzing data structure changes before/after drop points
- Correlating drops with system state changes

### Performance Optimization
Tools support systematic performance analysis:
- VM network latency measurement and optimization
- CPU binding and affinity optimization
- System-level network performance analysis

## Dependencies

- **bcc** (BPF Compiler Collection) - Required for Python BPF tools
- **bpftrace** - Required for .bt scripts
- **Python** - Tools use env python (shebang: `#!/usr/bin/env python`), compatible with Python 2/3
- **Kernel Debug Symbols** - Required for proper stack trace resolution
- **Root/sudo access** - Required for all BPF operations

## Important Implementation Notes

1. **Output Handling**: All tools output to stdout by default. Use redirection for logging: `tool > output.log 2>&1`
2. **Interface Configuration**: Tools are designed for virtualization environments. Many have hardcoded interface names (vnet, tap, tun) - modify as needed
3. **Performance Impact**: Consider performance overhead when running in production environments
4. **Symbol Resolution**: Stack traces require proper kernel debug symbols for meaningful analysis
5. **Kernel Version Compatibility**: Tools are tested with openEuler 4.19.90 kernel (available in kernel-source/ directory)

## Target Users

### Development Team
- Configure specific tracing parameters based on problem analysis
- Provide complete command lines for field support or self-execution
- Analyze complex execution path and data structure changes

### Field Support Team
- Follow documented procedures to collect logs
- Deploy tools according to provided instructions
- Forward collected data to development team for analysis

## Safety Guidelines and Important Reminders

### System Safety
- **CRITICAL**: All BPF tools require root/sudo access and can impact system performance
- **ALWAYS** test tools in development environment before production deployment
- **NEVER** run untested BPF programs on critical production systems
- **MONITOR** system resources when running continuous tracing tools

### Development Guidelines
- Do what has been asked; nothing more, nothing less
- NEVER create files unless absolutely necessary
- ALWAYS prefer editing existing files over creating new ones
- NEVER proactively create documentation files unless explicitly requested

### Common Pitfalls to Avoid
1. **Stack Overflow**: BPF stack is limited to 512 bytes - use maps for large data structures
2. **Verifier Errors**: Complex loops may fail BPF verification - keep logic simple
3. **Performance Impact**: High-frequency kprobes can significantly impact system performance
4. **Symbol Resolution**: Ensure kernel debug symbols are available for stack traces