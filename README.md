# Troubleshooting Tools

A comprehensive toolset for performance analysis and troubleshooting of virtualized network systems using eBPF technologies.

## Overview

This repository provides a collection of eBPF-based tools for monitoring, tracing, and analyzing network performance issues in virtualized environments. The tools are designed to help identify packet drops, measure latency, trace data paths, and analyze system performance bottlenecks.

## Repository Structure

### `ebpf-tools/`
Main directory containing all eBPF-based monitoring and troubleshooting tools organized by system component:

#### `cpu/`
CPU and scheduler monitoring tools:
- Off-CPU time analysis
- Scheduler latency monitoring
- Futex and pthread lock tracing

#### `kvm-virt-network/`
KVM virtualization network stack monitoring:
- `kvm/` - KVM IRQ injection and interrupt statistics
- `tun/` - TUN/TAP device monitoring (ring buffer, GSO, TX stats)
- `vhost-net/` - vhost eventfd, queue correlation, buffer peek stats
- `virtio-net/` - virtio-net polling, IRQ monitoring, RX path tracing

#### `linux-network-stack/`
Linux kernel network stack tools:
- Connection tracking (conntrack) monitoring
- IP fragmentation/defragmentation tracing
- `packet-drop/` - Comprehensive packet drop detection and analysis

#### `ovs/`
Open vSwitch specific monitoring:
- Userspace megaflow analysis
- Kernel module drop monitoring
- Upcall latency measurement

#### `performance/`
Network performance measurement tools:
- `system-network/` - System-level network latency and metrics (ICMP RTT, TCP latency)
- `vm-network/` - VM-specific network performance analysis
  - VM network latency decomposition
  - `vm_pair_latency/` - Inter-VM latency monitoring
  - `vm_pair_latency_gap/` - Latency gap and jitter analysis

#### `other/`
Additional tracing tools:
- Abnormal ARP detection
- OVS connection tracking invalid states
- Network offloading and segmentation tracing
- Qdisc and TX queue monitoring

### `docs/`
Documentation and guides:
- `publish/` - User manuals and deployment guides
- Design documents for various monitoring approaches

### `test/`
Test configurations and specifications for all tool categories

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

# For openEuler distributions
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
- Consider using sampling or time-limited tracing for high-traffic systems: summary version

## Troubleshooting

### Common Issues
1. **Permission Denied**: Ensure running with root privileges
2. **BPF Program Load Failed**: Check kernel BPF support and function availability
3. **Symbol Resolution**: Ensure kernel debug symbols are installed
4. **Interface Not Found**: Verify interface names and indices


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

## 文档
用户手册见： docs/user-manual.md