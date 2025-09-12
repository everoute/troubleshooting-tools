# eBPF Network Troubleshooting Tools - Project Documentation

## 1. Project Structure

The project is organized into modular directories based on system components and problem domains. The primary structure consists of eBPF-based tools written in Python (using BCC) and bpftrace scripts.

### Directory Classification

```
ebpf-tools/
├── cpu/                              # CPU and scheduler monitoring tools
├── kvm-virtualization-network/      # KVM/QEMU virtualization network stack tools
│   ├── kvm/                         # KVM interrupt and IRQ monitoring
│   ├── tun/                         # TUN/TAP device monitoring
│   ├── vhost-net/                   # vhost-net backend monitoring
│   └── virtio-net/                  # virtio-net guest driver monitoring
├── linux-network-stack/             # Linux kernel network stack tools
│   └── packet-drop/                 # Packet drop detection and analysis
├── other/                           # Miscellaneous tracing tools
├── ovs/                             # Open vSwitch monitoring tools
└── performance/                     # Network performance monitoring
    ├── system-network/              # System-level network performance
    └── vm-network/                  # VM-specific network performance
        └── vm_pair_latency/         # VM-to-VM latency monitoring
```

## 2. Module-Specific Tool Details

### 2.1 CPU Module (`cpu/`)

**Purpose**: Monitor CPU scheduling, lock contention, and off-CPU time analysis

#### Tools:
- **offcputime-ts.py**: Tracks time threads spend blocked (off-CPU)
  - **Use Case**: Identifying performance bottlenecks caused by blocking operations
  - **Data Collected**: Stack traces, blocking duration, timestamps
  
- **futex.bt**: Traces futex system calls
  - **Use Case**: Debugging mutex/semaphore contention issues
  - **Data Collected**: Futex operations, wait times
  
- **pthread_rwlock_wrlock.bt**: Monitors pthread read-write lock write operations
  - **Use Case**: Analyzing read-write lock contention
  - **Data Collected**: Lock acquisition attempts, wait times, stack traces

- **cpu_monitor.sh**: Comprehensive CPU monitoring script
  - **Use Case**: System-wide CPU performance analysis
  - **Data Collected**: CPU utilization, scheduling metrics

- **sched_latency_monitor.sh**: Scheduler latency monitoring
  - **Use Case**: Detecting scheduling delays
  - **Data Collected**: Scheduling latency histograms

### 2.2 KVM Virtualization Network Module (`kvm-virtualization-network/`)

#### 2.2.1 KVM Subsystem (`kvm/`)
- **kvm_irqfd_stats_summary.py**: KVM interrupt injection statistics
  - **Use Case**: Monitoring virtual interrupt delivery performance
  - **Data Collected**: IRQ injection counts, latencies, per-VM statistics
  
- **kvm_irqfd_stats_summary_arm.py**: ARM-specific KVM interrupt monitoring
  - **Use Case**: ARM virtualization interrupt analysis
  - **Data Collected**: ARM-specific IRQ statistics

#### 2.2.2 TUN/TAP Subsystem (`tun/`)
- **tun_ring_monitor.py**: TUN device ring buffer monitoring
  - **Use Case**: Detecting TUN device buffer issues
  - **Data Collected**: Ring buffer utilization, overflow events
  
- **tun-abnormal-gso-type.bt**: Abnormal GSO type detection
  - **Use Case**: Identifying GSO offload issues
  - **Data Collected**: Invalid GSO types, packet details
  
- **tun-tx-ring-stas.bt**: TUN transmit ring statistics
  - **Use Case**: TX ring performance analysis
  - **Data Collected**: TX ring occupancy, throughput

#### 2.2.3 vhost-net Backend (`vhost-net/`)
- **vhost_eventfd_count.py/bt**: vhost eventfd signaling monitoring
  - **Use Case**: Analyzing guest-host notification efficiency
  - **Data Collected**: Eventfd signal counts, frequencies
  
- **vhost_queue_correlation_simple.py**: Simple queue correlation analysis
  - **Use Case**: Understanding queue utilization patterns
  - **Data Collected**: Queue pair mapping, utilization metrics
  
- **vhost_queue_correlation_details.py**: Detailed queue correlation
  - **Use Case**: Deep queue performance analysis
  - **Data Collected**: Per-queue statistics, correlation metrics
  
- **vhost_buf_peek_stats.py**: vhost buffer peek operations
  - **Use Case**: Buffer management efficiency
  - **Data Collected**: Buffer peek counts, latencies

#### 2.2.4 virtio-net Guest Driver (`virtio-net/`)
- **virtnet_poll_monitor.py**: virtio-net NAPI polling monitoring
  - **Use Case**: NAPI polling efficiency analysis
  - **Data Collected**: Poll counts, packet batch sizes
  
- **virtnet_irq_monitor.py**: virtio-net interrupt monitoring
  - **Use Case**: Interrupt coalescing effectiveness
  - **Data Collected**: IRQ rates, CPU affinity
  
- **virtionet-rx-path-monitor.bt**: RX path detailed monitoring
  - **Use Case**: RX processing bottleneck identification
  - **Data Collected**: Function latencies, packet flow
  
- **virtionet-rx-path-summary.bt**: RX path summary statistics
  - **Use Case**: Overall RX performance assessment
  - **Data Collected**: Aggregated RX metrics
  
- **trace_virtio_net_rcvbuf.bt**: Receive buffer tracing
  - **Use Case**: Buffer allocation issues
  - **Data Collected**: Buffer sizes, allocation failures

#### 2.2.5 Cross-Layer Tools
- **tun_to_vhost_queue_status_simple.py**: TUN to vhost queue mapping
  - **Use Case**: Understanding data flow between layers
  - **Data Collected**: Queue mappings, flow statistics
  
- **tun_to_vhost_queue_stats_details.py**: Detailed queue statistics
  - **Use Case**: Performance correlation analysis
  - **Data Collected**: Detailed per-queue metrics
  
- **tun_tx_to_kvm_irq.py**: TX to IRQ injection correlation
  - **Use Case**: End-to-end latency analysis
  - **Data Collected**: TX to IRQ latency, injection rates

### 2.3 Linux Network Stack Module (`linux-network-stack/`)

#### Core Network Stack Tools
- **trace_conntrack.py**: Connection tracking monitoring
  - **Use Case**: NAT/firewall connection issues
  - **Data Collected**: Connection states, timeouts
  
- **trace_ip_defrag.py**: IP fragmentation/defragmentation
  - **Use Case**: Fragmentation-related packet loss
  - **Data Collected**: Fragment counts, reassembly failures

#### Packet Drop Subsystem (`packet-drop/`)
- **drop_monitor_controller.py**: Centralized drop monitoring
  - **Use Case**: System-wide packet drop detection
  - **Data Collected**: Drop locations, reasons, counts
  
- **eth_drop.py**: Ethernet-level drop monitoring
  - **Use Case**: NIC driver drop detection
  - **Data Collected**: Driver drop statistics
  
- **kernel_drop_stack_stats_summary.py**: Kernel drop stack analysis
  - **Use Case**: Identifying drop locations in kernel
  - **Data Collected**: Stack traces, drop frequencies
  
- **kernel_drop_stack_stats.bt**: Real-time drop stack tracing
  - **Use Case**: Live drop debugging
  - **Data Collected**: Real-time stack traces
  
- **qdisc_drop_trace.py**: Queue discipline drop monitoring
  - **Use Case**: Traffic control drop analysis
  - **Data Collected**: Qdisc drop reasons, queue depths

### 2.4 Open vSwitch Module (`ovs/`)

- **ovs-kernel-module-drop-monitor.py**: OVS datapath drop monitoring
  - **Use Case**: OVS kernel module packet drops
  - **Data Collected**: Drop reasons, flow information
  
- **ovs_userspace_megaflow.py**: Megaflow cache monitoring
  - **Use Case**: Flow cache efficiency analysis
  - **Data Collected**: Cache hit/miss rates, flow counts

### 2.5 Performance Module (`performance/`)

#### System Network Performance (`system-network/`)
- **system_network_icmp_rtt.py**: ICMP RTT measurement
  - **Use Case**: Network latency baseline testing
  - **Data Collected**: RTT statistics, packet loss
  
- **system_network_latency_details.py**: Detailed latency breakdown
  - **Use Case**: Component-level latency analysis
  - **Data Collected**: Per-layer latency measurements
  
- **system_network_perfomance_metrics.py**: Comprehensive metrics
  - **Use Case**: Overall network performance assessment
  - **Data Collected**: Throughput, latency, CPU usage

#### VM Network Performance (`vm-network/`)
- **vm_network_latency_details.py**: VM network latency breakdown
  - **Use Case**: VM-specific latency analysis
  - **Data Collected**: Host-VM-Host latency components
  
- **vm_network_latency_summary.py**: VM latency summary
  - **Use Case**: Quick VM network assessment
  - **Data Collected**: Aggregated latency statistics
  
- **vm_network_performance_metrics.py**: VM performance metrics
  - **Use Case**: VM network performance monitoring
  - **Data Collected**: VM-specific throughput, PPS

##### VM Pair Latency Analysis (`vm_pair_latency/`)
- **vm_pair_latency.py**: Basic VM-to-VM latency
  - **Use Case**: Inter-VM communication latency
  - **Data Collected**: Point-to-point latency
  
- **multi_vm_pair_latency.py**: Multiple VM pair monitoring
  - **Use Case**: Multi-tenant latency analysis
  - **Data Collected**: Per-pair latency matrices
  
- **multi_vm_pair_latency_pairid.py**: Pair-identified latency
  - **Use Case**: Specific VM pair tracking
  - **Data Collected**: Identified pair metrics

##### Latency Gap Analysis (`vm_pair_latency_gap/`)
- **vm_pair_gap.py**: VM pair latency gaps
  - **Use Case**: Latency variation analysis
  - **Data Collected**: Gap statistics, jitter
  
- **multi_port_gap.py**: Multi-port latency gaps
  - **Use Case**: Port-specific latency analysis
  - **Data Collected**: Per-port gap metrics
  
- **multi_vm_pair_multi_port_gap.py**: Comprehensive gap analysis
  - **Use Case**: Complex topology latency analysis
  - **Data Collected**: Multi-dimensional gap data

#### General Performance Tools
- **iface_netstat.py**: Interface statistics monitoring
  - **Use Case**: Network interface performance
  - **Data Collected**: RX/TX counters, errors
  
- **ovs_upcall_latency_summary.py**: OVS upcall latency
  - **Use Case**: OVS slow path performance
  - **Data Collected**: Upcall latencies, frequencies
  
- **qdisc_lateny_details.py**: Qdisc latency analysis
  - **Use Case**: Traffic control performance
  - **Data Collected**: Qdisc processing times

### 2.6 Other Tools Module (`other/`)

- **trace-abnormal-arp.bt**: Abnormal ARP detection
  - **Use Case**: ARP poisoning/issues detection
  - **Data Collected**: Suspicious ARP packets
  
- **trace-ovs-ct-invalid.bt**: OVS conntrack invalid states
  - **Use Case**: Connection tracking issues
  - **Data Collected**: Invalid CT entries
  
- **trace_offloading_segment.bt**: Segmentation offload tracing
  - **Use Case**: TSO/GSO issue debugging
  - **Data Collected**: Offload parameters
  
- **trace_vlanvm_udp_workload.bt**: VLAN VM UDP tracing
  - **Use Case**: VLAN-specific UDP issues
  - **Data Collected**: VLAN tags, UDP flows
  
- **vpc-vm-udp-datapath.bt**: VPC VM UDP datapath
  - **Use Case**: Cloud network UDP analysis
  - **Data Collected**: VPC flow paths
  
- **trace-qdisc-dequeue.bt**: Qdisc dequeue operations
  - **Use Case**: Queue scheduling analysis
  - **Data Collected**: Dequeue patterns
  
- **trace_dev_queue_xmit.bt**: Device queue transmit
  - **Use Case**: TX queue behavior
  - **Data Collected**: Queue depths, drops
  
- **trace_tc_qdisc.bt**: Traffic control qdisc tracing
  - **Use Case**: TC configuration debugging
  - **Data Collected**: TC actions, classifications

## 3. Tool Usage Guide

### 3.1 Python BCC Tools

**General Usage Pattern:**
```bash
sudo python2 <tool_path> [options]
```

**Common Parameters:**
- `-i, --interval`: Sampling interval in seconds
- `-d, --duration`: Total monitoring duration
- `-c, --count`: Number of samples to collect
- `--src-ip`: Source IP address filter
- `--dst-ip`: Destination IP address filter
- `-p, --pid`: Process ID filter
- `-v, --verbose`: Verbose output mode

**Example Usage:**

```bash
# Monitor VM network latency for 60 seconds
sudo python2 ebpf-tools/performance/vm-network/vm_network_latency_summary.py -d 60

# Track specific VM pair latency
sudo python2 ebpf-tools/performance/vm-network/vm_pair_latency/vm_pair_latency.py \
    --src-ip 192.168.1.10 --dst-ip 192.168.1.20 -i 1

# Monitor OVS packet drops
sudo python2 ebpf-tools/ovs/ovs-kernel-module-drop-monitor.py -v

# Analyze vhost queue correlation
sudo python2 ebpf-tools/kvm-virtualization-network/vhost-net/vhost_queue_correlation_details.py \
    --vm-name test-vm -i 5
```

### 3.2 Bpftrace Scripts

**General Usage Pattern:**
```bash
sudo bpftrace <script_path> [arguments]
```

**Common Usage:**

```bash
# Trace abnormal ARP packets
sudo bpftrace ebpf-tools/other/trace-abnormal-arp.bt

# Monitor virtio-net RX path
sudo bpftrace ebpf-tools/kvm-virtualization-network/virtio-net/virtionet-rx-path-monitor.bt

# Track kernel packet drops with stack traces
sudo bpftrace ebpf-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats.bt
```

### 3.3 Shell Scripts

**CPU Monitoring:**
```bash
# Comprehensive CPU monitoring
sudo ./ebpf-tools/cpu/cpu_monitor.sh

# Scheduler latency analysis
sudo ./ebpf-tools/cpu/sched_latency_monitor.sh --interval 1 --duration 60
```

## 4. Output Data Format

### 4.1 Python BCC Tools Output

Most Python tools provide structured output in the following formats:

**Latency Tools:**
```
Timestamp: 1234567890.123
Source: 192.168.1.10:5000 -> Destination: 192.168.1.20:8080
Latency Breakdown:
  - Kernel TX: 12.5 us
  - OVS Processing: 8.3 us
  - vhost-net: 15.2 us
  - Guest RX: 10.1 us
  Total: 46.1 us
```

**Drop Monitor Tools:**
```
Drop Location: netif_receive_skb_core+0x123
Reason: NETDEV_DROP_REASON_NO_BUFFER
Count: 150
Stack Trace:
  netif_receive_skb_core+0x123
  __netif_receive_skb+0x45
  process_backlog+0x89
  ...
```

**Performance Metrics:**
```
Interface: eth0
RX Packets: 1234567 (1.2M pps)
TX Packets: 987654 (987K pps)
RX Bytes: 1.5 GB
TX Bytes: 1.2 GB
Errors: 0
Drops: 5
```

### 4.2 Bpftrace Output

Bpftrace scripts typically output:

**Event Traces:**
```
TIME     PID    COMM           EVENT           DETAILS
10:15:23 1234   qemu-kvm       virtio_rx       len=1500 queue=0
10:15:23 1234   qemu-kvm       virtio_notify   vq=0 
```

**Histograms:**
```
@latency_us:
[0, 1)          1234 |@@@@@@@@@@                    |
[1, 2)          5678 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@  |
[2, 4)          2345 |@@@@@@@@@@@                   |
[4, 8)          890  |@@@@                          |
```

**Stack Counts:**
```
@stack_count[
    kfree_skb+0x0
    tcp_v4_rcv+0x123
    ip_local_deliver+0x45
]: 250
```

### 4.3 Summary Reports

Many tools generate summary reports:

```
========== VM Network Performance Summary ==========
Monitoring Duration: 60 seconds
Total Packets: 1,234,567
Average Latency: 45.2 us
P50 Latency: 42.1 us
P95 Latency: 78.3 us
P99 Latency: 125.6 us
Max Latency: 1,234.5 us

Top Latency Contributors:
1. vhost-net processing: 35%
2. OVS forwarding: 25%
3. Guest driver: 20%
4. Other: 20%
====================================================
```

## 5. Deployment and Requirements

### System Requirements
- Linux kernel 4.19+ with BPF support enabled
- BCC (BPF Compiler Collection) installed
- bpftrace installed
- Python 2.7 or Python 3.6+
- Root privileges for BPF program loading

### Target Environment
- Virtualization: KVM/QEMU with virtio-net
- Network: Open vSwitch 2.10+
- OS: openEuler, CentOS 7+, Ubuntu 18.04+

### Safety Considerations
- All tools require root access
- May impact system performance when running
- Recommended to test in development environment first
- Use sampling intervals to reduce overhead
- Monitor system load while tools are running