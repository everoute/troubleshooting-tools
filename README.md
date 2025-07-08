# Troubleshooting Tools

A comprehensive toolset for performance analysis and troubleshooting of virtualized network systems using eBPF technologies.

## Overview

This repository provides a collection of eBPF-based tools for monitoring, tracing, and analyzing network performance issues in virtualized environments. The tools are designed to help identify packet drops, measure latency, trace data paths, and analyze system performance bottlenecks.

## Repository Structure

### `bcc-tools/`
Python-based BPF tools using the BCC (BPF Compiler Collection) framework. This directory contains the majority of the functionality:

#### `cpu-measurement/`
CPU-specific monitoring and measurement tools:
- `cpu_monitor.sh` - CPU usage monitoring script
- `offcputime-ts.py` - Off-CPU time analysis with timestamps
- `sched_latency_monitor.sh` - Scheduler latency monitoring
- `futex.bt` - Futex contention tracing
- `pthread_rwlock_wrlock*.bt` - Pthread rwlock monitoring

#### `linux-network-stack/`
Linux kernel network stack tracing tools:
- `trace_ct.py` - Connection tracking analysis
- `trace_ct_multi_conn.py` - Multi-connection tracking
- `trace_ip_defrag.py` - IP fragmentation/defragmentation tracing

#### `ovs-measurement/`
Open vSwitch (OVS) specific monitoring tools:
- `ovs_userspace_megaflow.py` - OVS userspace megaflow analysis
- `ovs_userspace_megaflow_kernel_parse.py` - Kernel-level megaflow parsing
- `ovs-clone-execute-summary.py` - OVS clone and execute operation summary
- `ovs-kernel-module-drop-monitor.py` - OVS kernel module drop monitoring
- `ovs-upcall-execute.py` - OVS upcall execution tracing

#### `packet-drop/`
Packet drop analysis tools:
- `multi-protocol-drop-monitor.py` - Multi-protocol packet drop monitoring
- `drop.py` - Generic packet drop analysis
- `eth_drop.py` - Ethernet-specific drop monitoring

#### `performance/`
Performance analysis and optimization tools:

##### `system-network/`
System-level network performance tools:
- `icmp_rtt_latency.py` - ICMP round-trip time latency measurement
- `icmp_rx_latency.py` - ICMP receive path latency
- `icmp_tx_latency.py` - ICMP transmit path latency
- `tcp_latency.py` - TCP latency measurement

##### `vm-network/`
VM network performance analysis:
- `vm_latency.py` - VM network end-to-end latency measurement
- `vm_pair_latency/` - VM pair latency analysis tools
- `vm_pair_latency_gap/` - VM pair latency gap analysis tools

##### `vm-binding-tools/`
VM CPU binding and affinity tools:
- `binding.py` - VM CPU binding management
- `set-vm-pair-cpu-affinity.sh` - VM pair CPU affinity configuration
- `set-process-cpu-mem-affinitity.sh` - Process CPU/memory affinity

##### `iface_netstat.py` - Network interface statistics

#### `virtio-network/`
Virtio network device monitoring:
- `tun_ring_monitor.py` - TUN device ring buffer monitoring

### `bpftrace-tools/`
High-level tracing scripts using bpftrace syntax:
- `trace-abnormal-arp.bt` - Abnormal ARP event tracing
- `trace-ovs-ct-invalid.bt` - OVS connection tracking invalid state tracing
- `trace_offloading_segment.bt` - Network offloading segmentation tracing
- `tun-abnormal-gso-type` - TUN device GSO type anomaly detection
- `vpc-vm-udp-datapath.bt` - VPC VM UDP datapath tracing
- Various queue and transmission monitoring scripts

### `md/`
Documentation and design documents:
- `system-network-latency.md` - System network latency analysis guide
- `vm-network-latency-design.md` - VM network latency measurement degign 
- `ovs_userspace_megaflow_generate.md` - OVS userspace megaflow generation design

## Prerequisites

### System Requirements
- Linux kernel with eBPF support (4.1+ recommended)
- Root privileges for BPF operations

### Software Dependencies
- **BCC (BPF Compiler Collection)** - Required for Python BPF tools
- **bpftrace** - Required for .bt scripts
- **Python 2/3** - Most tools support both versions
  - Python 2 for el7 systems with bcc package
  - Python 3 for oe1 systems with bpfcc package

## Installation

1. Install BCC:
```bash
# For RHEL/CentOS 7
sudo yum install bcc-tools python2-bcc

# For newer distributions
sudo apt-get install bpfcc-tools python3-bpfcc
```

2. Install bpftrace:
```bash
# For RHEL/CentOS
sudo yum install bpftrace

# For Ubuntu/Debian
sudo apt-get install bpftrace
```

3. Clone the repository:
```bash
git clone <repository-url>
cd troubleshooting-tools
```

## Usage Examples

### Packet Drop Analysis
Monitor packet drops for specific connections:
```bash
# Monitor TCP drops for specific connection
sudo ./bcc-tools/packet-drop/multi-protocol-drop-monitor.py \
    --src 192.168.1.10 --dst 192.168.1.20 --protocol tcp --dst-port 443

# Monitor all protocol drops
sudo ./bcc-tools/packet-drop/drop.py
```

### Network Latency Measurement
Measure network latency at various layers:
```bash
# System network ICMP latency
sudo ./bcc-tools/performance/system-network/icmp_rtt_latency.py \
    --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
    --phy-iface1 eth0 --phy-iface2 eth1

# VM network latency
sudo ./bcc-tools/performance/vm-network/vm_latency.py \
    --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
    --vm-interface vnet0 --phy-interface eth0 --direction tx
```

### OVS Analysis
Monitor OVS operations:
```bash
# OVS upcall monitoring
sudo ./bcc-tools/ovs-measurement/ovs-upcall-execute.py

# OVS megaflow analysis
sudo ./bcc-tools/ovs-measurement/ovs_userspace_megaflow.py --debug
```

### CPU Performance Analysis
Monitor CPU-related performance issues:
```bash
# Off-CPU time analysis
sudo ./bcc-tools/cpu-measurement/offcputime-ts.py

# Scheduler latency monitoring
sudo ./bcc-tools/cpu-measurement/sched_latency_monitor.sh
```

### Bpftrace Scripts
Use bpftrace for quick analysis:
```bash
# Trace abnormal ARP events
sudo bpftrace bpftrace-tools/trace-abnormal-arp.bt

# Monitor OVS connection tracking issues
sudo bpftrace bpftrace-tools/trace-ovs-ct-invalid.bt
```

## Network Architecture

This toolset is designed for virtualized network environments with the following architecture:

- **System Network**: Physical host network interfaces and kernel network stack
- **VM Network**: Virtual machine network interfaces (TUN/TAP devices, vnet interfaces)
- **OVS Integration**: Open vSwitch datapath monitoring and analysis
- **Virtio Network**: Virtio network device performance monitoring

For detailed architecture information, see the documentation in the `md/` directory.

## Output and Logging

Most tools output to stdout by default. To capture logs:
```bash
# Redirect output to log file
sudo ./tool-name --options > output.log 2>&1

# Real-time monitoring with logging
sudo ./tool-name --options | tee output.log
```

## Performance Considerations

- Tools may introduce overhead in production environments
- Use filtering options to reduce noise and performance impact
- Monitor system resources when running intensive tracing
- Consider using sampling or time-limited tracing for high-traffic systems

## Troubleshooting

### Common Issues
1. **Permission Denied**: Ensure running with root privileges
2. **BPF Program Load Failed**: Check kernel BPF support and function availability
3. **Symbol Resolution**: Ensure kernel debug symbols are installed
4. **Interface Not Found**: Verify interface names and indices

### Debug Mode
Many tools support debug mode for detailed output:
```bash
sudo ./tool-name --debug
```

## Contributing

When adding new tools:
1. Follow the existing directory structure
2. Include comprehensive help text and examples
3. Add appropriate error handling
4. Document tool functionality in comments
5. Test on target kernel versions

## Q&A (中文)

### 常见场景
#### 执行路径不符合预期
例如数据包在虚拟化数据路径中的处理不符合预期，需要定位 root cause。这类问题往往是非常复杂的，其根本原因在于执行路径上特定位置的处理逻辑不符合预期，再进一步其根本原因在于某些数据结构/元数据的值发生非预期的变化。因此最根本的问题是找到这些影响控制逻辑的非预期的数据结构/元数据值的变化。此工具正是为了便于做这类追踪，基本原理是在数据路径各个关键点上嵌入追踪各类最常见网络处理相关数据结构中的核心数据的能力，方便直观对比各个点的数据变化，进一步分析在对应代码中控制逻辑执行路径变化的原因，定位问题。

#### 丢包详细原因分析
类似的，丢包追踪工具仅能初步筛查：虚拟化数据路径的 host 段是否发生特定类型的丢包，丢包位于何处（调用栈）。更进一步分析，需要结合丢包位置前后其他数据路径点上的数据结构/元数据具体内容变化来进一步定位，就需要借助该工具。

#### 虚拟机网络/系统网络性能分析/优化
使用 performance 目录下的工具进行系统级和虚拟机网络性能分析，包括延迟测量、CPU 绑定优化等。

### 本工具集合针对的对象
1. **非研发**：按照说明采集日志，交研发人员进一步分析
2. **研发**：根据特定问题确定追踪参数，提供完整命令给售后或自行执行

### 使用建议
- 所有工具都需要 root 权限
- 输出默认到 stdout，使用重定向进行日志记录
- 工具针对虚拟化环境设计，监控 tun 接口, ovs internal port, 物理接口等
- 在生产环境中使用时考虑性能影响
- 内核/userspace 程序调用栈追踪需要正确的符号解析: 需要安装相应 debuginfo