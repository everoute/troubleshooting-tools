

# troubleshooting-tools 
虚拟化网络系统进行数据路径性能问题分析与调优的工具集 (Troubleshooting and performance analysis/tune toolset).

## Project Overview

This is a troubleshooting and performance analysis toolset (troubleshooting-tools) for virtualized network systems. It contains eBPF-based tools for monitoring, tracing, and analyzing network packet drops, latency, and data path issues in virtualization environments.

## Architecture

The codebase is organized into several key directories:

- **bpftools/**: Python-based BPF tools using the bcc framework
  - Packet drop monitors (multi-protocol, OVS-specific, TUN devices)
  - Latency monitoring tools (ICMP, VM pairs, system network)
  - Connection tracking and flow analysis
  - Performance monitoring utilities

- **bpftrace/**: High-level tracing scripts using bpftrace syntax
  - Network event tracers (ARP, OVS conntrack, GSO)
  - Queue and transmission monitors
  - Protocol-specific datapath tracers

- **data/**: Performance metrics, analysis reports, and deployment tools
  - Performance benchmarks (latency summaries)
  - VM internal drop analysis and deployment scripts

- **poc/**: Proof-of-concept scripts for CPU affinity and resource optimization

## Development Commands

### Running BPF Tools

All BPF tools require root privileges. Python tools in bpftools/ use Python 2:

```bash
# Basic packet drop monitoring
sudo python2 bpftools/multi-protocol-drop-monitor.py

# Monitor specific protocol with filters
sudo python2 bpftools/multi-protocol-drop-monitor.py --src 192.168.1.10 --dst 192.168.1.20 --protocol tcp --dst-port 80

# Run with log output
sudo python2 bpftools/multi-protocol-drop-monitor.py [options] > drop-monitor.log 2>&1
```

### Running bpftrace Scripts

```bash
# Run bpftrace scripts
sudo bpftrace bpftrace/trace-abnormal-arp.bt
sudo bpftrace bpftrace/trace-ovs-ct-invalid.bt
```

### Testing

Currently, there are no automated tests. Testing is done manually by running the tools with various filters and verifying output.

## Key Components

### Multi-Protocol Drop Monitor
- Main tool: `bpftools/multi-protocol-drop-monitor.py`
- Traces `kfree_skb` to detect packet drops
- Supports filtering by IP, port, protocol (TCP/UDP/ICMP)
- Provides kernel and user stack traces
- C code separated in `multi-protocol-drop-monitor.c`

### OVS (Open vSwitch) Tools
- Kernel module drop monitor: `ovs-kernel-module-drop-monitor.py`
- Clone/execute summary: `ovs-clone-execute-summary.py`
- Upcall tracer: `ovs-upcall-execute.py`
- Conntrack tracer: `trace-ovs-ct-invalid.bt`

### performance measurement 
- ICMP latency: `icmp_latency_monitor.sh`, `icmp_rx_latency.py`, `icmp_tx_latency.py`
- VM pair latency: `vm_pair_latency/` directory tools
- System network latency: `system_network_latency.py`

### 1. 多协议丢包追踪工具
用于对满足特定条件的数据包，其在虚拟化数据路径中发生丢包的位置初步筛查。
代码见 bpftools/multi_protocol_drop_monitor.py

#### 具体使用
下载代码至需要进行丢包追踪的 host，运行 ./multi_protocol_drop_monitor.py ，具体选项可通过脚本的 --help 查看。
支持指定 L4 协议，端口号等过滤数据包，同时支持仅 L3 过滤。

日志采集: 则通过指定标准输出到日志文件的方式，收集运行追踪脚本期间的日志，具体如下：
./multi_protocol_drop_monitor.py --options xxx > drop-monitor.log 2>&1

### 2. 多协议数据包数据路径追踪工具
用于对特定的数据包，追踪其在虚拟化环境中的完整数据路径中各个位置上主要元数据信息，进一步定位具体问题。
代码见 bpftools/packet_datapath_tracing.py

#### 具体使用
下载代码至需要进行丢包追踪的 host，运行 ./packet_datapath_tracing.py ，具体选项可通过脚本的 --help 查看。
支持指定 L4 协议，端口号等过滤数据包，同时支持仅 L3 过滤。类似的，收集日志同样通过指定标准输出文件的方式。


### 性能问题测量与分析(WIP)
性能分析中也常需要执行路径分析章节提出的方法，例如需要分析某类数据包在数据路径多个点(例如 vnet && internal 
port 以及其他中间点)上的 queuing 信息，也可以通过类似的方式，采集多点的队列信息（sk 或 dev queue 等）直接对比，
进一步分析问题。
### 延迟测量
bpftools/icmp_rtt_latency.py
bpftools/tcp_latency.py


## Dependencies

- **bcc** (BPF Compiler Collection) - Required for Python BPF tools
- **bpftrace** - Required for .bt scripts
- **Python 2** - Most tools use Python 2 (shebang: `#!/usr/bin/python2`)
- Root/sudo access required for all BPF operations

## Important Notes

1. All tools output to stdout by default. Use redirection for logging.
2. Tools are designed for virtualization environments (monitoring vnet, tap, tun interfaces).
3. Many tools have hardcoded interface names or IP addresses - check and modify as needed.
4. Stack traces may require kernel symbols to be properly resolved.
5. Performance impact should be considered when running in production environments.
================================================================================================



# 测量数据分析
https://github.com/echkenluo/network-measurement-analyzer/tree/main
主要涵盖：
1. 集群 network-monitor 等主要网络相关测量数据/日志自动分析；
2. troubleshooting-tools 相关工具测量数据分析；



# Q&A

## 常见场景
### 执行路径不符合预期
例如数据包在虚拟化数据路径中的处理不符合预期，需要定位 root cause。这类问题往往是非常复杂的，其根本原因在于
执行路径上特定位置的处理逻辑不符合预期，再进一步其根本原因在于某些数据结构/元数据的值发生非预期的变化。因此
最根本的问题是找到这些影响控制逻辑的非预期的数据结构/元数据值的变化。此工具正是为了便于做这类追踪，基本原理
是在数据路径各个关键点上嵌入追踪各类最常见网络处理相关数据结构中的核心数据(例如 skbuff->shared_info)的能力，
方便直观对比各个点的数据变化，进一步分析在对应代码中控制逻辑执行路径变化的原因，定位问题。

### 丢包详细原因分析
类似的，上述丢包追踪工具仅能初步筛查: 虚拟化数据路径的 host 段是否发生特定类型的丢包，有的话大体位于何处
（调用栈）。 更进一步分析，需要结合丢包位置前后其他数据路径点上的数据结构/元数据具体内容变化来进一步定位，就
需要借助该工具。
当前支持 skb 基本信息在各个网卡 tx/rx 处的信息采集，仅支持 skb 核心信息.

### 虚拟机网络/系统网络性能分析/优化


## 本工具集合针对的对象
1. 售后人员
需要进行丢包分析以及其他各类数据路径详细分析的问题, 具体问题已经比较深入，一般需要研发介入，售后人员仅需要按照
上述说明采集日志，交研发人员进一步分析。
如果售后人员可以明确初步的需要采集的具体数据包信息，可直接通过命令行指定参数，采集信息。如不能则需要研发初步定位
问题，为售后提供完整命令行参数。

2. 研发
研发需要根据特定问题，确定期望一线进行追踪的具体类型以及程序参数，提供具体命令给售后，或自行通过远程方式执行指令
，采集日志。
例如，初步定为得到有以下 tcp 连接(src_ip: 192.168.32.10, dst_ip: 192.168.32.20, dst_port: 443)受影响，产生不明原
因丢包，则可以通过运行多协议丢包追踪工具收集日志进行初步筛查，具体命令如下收集日志：
./multi_protocol_drop_monitor.py --src 192.168.32.10 --dst 192.168.32.20 --protocol tcp --dst-port 443 > tcp-drop.log 2>&1
运行一段时间后可通过查看 tcp-drop.log 分析调用栈信息完成初步筛查。
