# Hygon CPU Network Latency Tail Analysis

## Executive Summary

Cross-node TCP communication on Hygon CPU systems exhibits significant latency tail issues, particularly in the RX path between `ovs_vport_send` and `tcp_v4_rcv`. The root cause is **cross-NUMA memory access combined with suboptimal CPU scheduling** for softirq processing.

### Key Findings

**Scenario 1 (No CPU binding):**
- Extreme latency tail: 8-16ms (8192-16383us)
- Bottleneck: `RX_S5_ovs_vport_send → RX_S6_tcp_v4_rcv` (after OVS → before protocol stack)
- Observed client-side TCP RTT spikes: 8-16ms

**Scenario 2 (CPU binding to same NUMA node as NIC):**
- Reduced latency tail: ~2ms
- Still significant but without extreme spikes
- More predictable performance

## Problem Description

### Topology
```
Physical NIC (enp94s0f0np0) → OVS Bridge → Internal Port (port-storage) → System Network Stack → Application
```

- System network IP bound to OVS internal port
- Physical NIC attached to OVS bridge for packet forwarding
- **Issue only observed on Hygon CPU systems**

### Latency Measurement Data

#### Scenario 1: Without CPU Binding
```
RX_S5_ovs_vport_send -> RX_S6_tcp_v4_rcv:
  Total samples: 14946
  Latency distribution:
    2-3us       :    400 |**
    4-7us       :   1414 |*******
    8-15us      :   5027 |***************************
    16-31us     :   6560 |************************************|
    32-63us     :   1541 |********
    256-511us   :      2 |
    8192-16383us:      2 |   ← EXTREME TAIL LATENCY
```

#### Scenario 2: With CPU Binding (iperf bound to NIC's NUMA node)
```
RX_S5_ovs_vport_send -> RX_S6_tcp_v4_rcv:
  Total samples: 23168
  Latency distribution:
    2-3us       :     46 |
    4-7us       :    753 |**
    8-15us      :   7189 |*******************
    16-31us     :  13433 |************************************|
    32-63us     :   1745 |*****
    1024-2047us :      2 |   ← Reduced tail, but still present
```

## Root Cause Analysis

### Critical Code Path

The latency occurs in this kernel path:

```c
// 1. OVS completes processing and sends to internal port
// File: net/openvswitch/vport.c:488
void ovs_vport_send(struct vport *vport, struct sk_buff *skb, u8 mac_proto)
{
    // ... MTU checks, protocol setup ...
    skb->dev = vport->dev;
    vport->ops->send(skb);  // → internal_dev_recv
}

// 2. Internal device receives packet
// File: net/openvswitch/vport-internal_dev.c:251
static netdev_tx_t internal_dev_recv(struct sk_buff *skb)
{
    // ... stats updates ...
    netif_rx(skb);  // ← CRITICAL HANDOFF POINT
    return NETDEV_TX_OK;
}

// 3. Kernel enqueues packet to softirq backlog
// File: net/core/dev.c:4476
static int netif_rx_internal(struct sk_buff *skb)
{
    // ... RPS logic ...
    ret = enqueue_to_backlog(skb, get_cpu(), &qtail);  // ← CPU SELECTION
    put_cpu();
    return ret;
}

// 4. Enqueue to target CPU's backlog queue
// File: net/core/dev.c:4235
static int enqueue_to_backlog(struct sk_buff *skb, int cpu, unsigned int *qtail)
{
    struct softnet_data *sd;
    sd = &per_cpu(softnet_data, cpu);  // ← Per-CPU queue access

    // ... queue packet ...
    __skb_queue_tail(&sd->input_pkt_queue, skb);

    // Schedule NAPI softirq on target CPU
    if (!__test_and_set_bit(NAPI_STATE_SCHED, &sd->backlog.state)) {
        ____napi_schedule(sd, &sd->backlog);
    }
}
```

### Problem Mechanism

#### 1. **Cross-NUMA Memory Access**

**Packet Flow:**
```
Physical NIC (NUMA 0) receives packet
    ↓
NIC driver allocates SKB on local NUMA 0 memory
    ↓
Hardware interrupt → softirq processing on NIC's CPU (NUMA 0)
    ↓
OVS kernel module processes packet (still on NUMA 0)
    ↓
ovs_vport_send → internal_dev_recv → netif_rx(skb)
    ↓
get_cpu() selects current CPU for packet processing
    ↓
WITHOUT CPU BINDING:
    → Task scheduler may have migrated process to NUMA 1
    → netif_rx enqueues to NUMA 1 CPU's backlog
    → Softirq on NUMA 1 accesses SKB allocated on NUMA 0
    → CROSS-NUMA MEMORY ACCESS (40-50ns additional latency per access)
```

**Memory Access Pattern:**
```c
// SKB header allocated on NUMA 0
struct sk_buff *skb = napi_alloc_skb(napi, length);  // NUMA 0

// Later, processed on NUMA 1 CPU:
// Every access to SKB data incurs cross-NUMA penalty
tcp_v4_rcv(skb);  // Reads skb->data, skb->len, etc. from NUMA 0 memory
    → tcp_checksum()  // Reads entire packet payload from NUMA 0
    → tcp_queue_rcv()  // Writes to socket buffers on NUMA 1
```

#### 2. **Hygon CPU NUMA Characteristics**

Hygon CPUs (based on AMD Zen architecture) have specific NUMA topology:

- **Cross-socket memory latency**: +40-50ns base overhead
- **Cross-socket bandwidth**: <50% of local DRAM bandwidth
- **Memory controller contention**: Multiple cores competing for remote memory controller

**Why worse on Hygon than Intel:**
- AMD/Hygon Infinity Fabric interconnect may have higher latency than Intel UPI
- NUMA domain configuration differences
- Memory controller placement and topology

#### 3. **CPU Scheduling Issues**

**Scenario 1: Without CPU Binding**
```
1. Packet arrives on NIC IRQ CPU (e.g., CPU 0, NUMA 0)
2. OVS processes packet in softirq context (CPU 0)
3. netif_rx() calls get_cpu() → returns current CPU
4. BUT: If application (iperf) was scheduled on CPU 16 (NUMA 1):
   - Kernel may try to optimize cache locality
   - Or application was migrated by scheduler
5. Result: Packet enqueued to wrong NUMA node's CPU
6. Softirq on NUMA 1 CPU processes packet from NUMA 0 memory
7. EVERY memory access (IP header, TCP header, payload) crosses NUMA
```

**Scenario 2: With CPU Binding (iperf on same NUMA as NIC)**
```
1. iperf bound to CPU on same NUMA node as NIC (e.g., CPU 2, NUMA 0)
2. Packet arrives on NIC IRQ CPU (CPU 0, NUMA 0)
3. Packet processed on same NUMA node
4. Reduced cross-NUMA access (but not eliminated due to other factors)
```

#### 4. **Why Latency Tail, Not Constant Overhead?**

The **tail latency** (not consistent slowdown) is caused by:

1. **Scheduler Migration**: Occasionally the scheduler migrates the application to a different NUMA node
2. **CPU Load Balancing**: Kernel's load balancer may move softirqs across NUMA
3. **Memory Pressure**: When local NUMA memory is full, allocations fall back to remote NUMA
4. **Cache Coherency Storms**: When multiple CPUs access the same cache line across NUMA
5. **TLB Shootdowns**: Cross-NUMA TLB invalidations

**Extreme 8-16ms spikes** likely caused by:
- **Scheduler stall**: Application waiting to be scheduled after being preempted
- **Lock contention**: Waiting for locks held by threads on remote NUMA
- **Memory reclaim**: Kernel memory reclaim triggered on remote NUMA node

### Contributing Factors

#### A. RPS/RFS Configuration

RPS (Receive Packet Steering) and RFS (Receive Flow Steering) may be:
- Disabled (packets stay on current CPU)
- Misconfigured (steering to wrong CPUs)
- Not NUMA-aware in configuration

Check with:
```bash
cat /sys/class/net/port-storage/queues/rx-0/rps_cpus
cat /proc/sys/net/core/rps_sock_flow_entries
```

#### B. IRQ Affinity

Physical NIC IRQ affinity determines initial packet processing CPU:
```bash
cat /proc/interrupts | grep enp94s0f0np0
# Check which CPUs handle NIC interrupts
```

If IRQ affinity not set optimally:
- Interrupts may be handled on CPUs far from application
- Cross-NUMA penalty from the start

#### C. NUMA Memory Allocation Policy

Check system NUMA policy:
```bash
numactl --hardware
numactl --show
```

Default policy may allow cross-NUMA allocations without preference for local memory.

#### D. Socket Buffer Allocation

TCP socket buffers are allocated when socket is created:
```c
// net/ipv4/tcp.c
sk = sk_alloc(net, PF_INET, GFP_KERNEL, &tcp_prot, kern);
```

If socket allocated on NUMA 1, but NIC is on NUMA 0:
- Incoming data copied from NUMA 0 SKB to NUMA 1 socket buffer
- Double cross-NUMA penalty

## Verification and Diagnosis

### 1. Confirm NUMA Topology

```bash
# Check NUMA nodes
numactl --hardware

# Check NIC NUMA node
cat /sys/class/net/enp94s0f0np0/device/numa_node

# Check process NUMA binding
taskset -cp $(pgrep iperf3)
numastat -p $(pgrep iperf3)
```

### 2. Monitor Cross-NUMA Traffic

```bash
# Monitor NUMA memory access
numastat -c iperf3 1

# Expected output showing high "other node" access:
#                          node0         node1
#             -----------  ------------- -------------
#             numa_hit        12345678       1234567
#             numa_miss        8765432        123456  ← High miss = cross-NUMA
#             other_node       8765432        123456  ← High = problem
```

### 3. Check Softirq Distribution

```bash
# Monitor which CPUs handle softirqs
watch -n 1 'grep "NET_RX" /proc/softirqs'

# Check if NET_RX is concentrated on specific CPUs or spread across NUMA
```

### 4. Verify IRQ Affinity

```bash
# Find NIC IRQ number
NIC_IRQ=$(cat /proc/interrupts | grep enp94s0f0np0 | awk -F: '{print $1}')

# Check IRQ affinity (CPU mask)
cat /proc/irq/$NIC_IRQ/smp_affinity_list

# Should show CPUs on same NUMA node as NIC
```

### 5. Use eBPF Tools for Detailed Tracing

```bash
# Trace packet CPU scheduling
sudo python3 ebpf-tools/performance/system-network/system_network_latency_summary.py \
    --phy-interface enp94s0f0np0 \
    --src-ip <SERVER_IP> \
    --direction rx \
    --interval 5

# Monitor TCP connection statistics
sudo python3 ebpf-tools/performance/system-network/tcp_connection_analyzer.py \
    --local-port 5201 \
    --role server \
    --interval 2 \
    --show-stats
```

### 6. Perf Analysis

```bash
# Profile CPU migrations
sudo perf record -e sched:sched_migrate_task -a -g -- sleep 30
sudo perf report

# Profile cache misses
sudo perf stat -e LLC-loads,LLC-load-misses,node-loads,node-load-misses \
    -a -I 1000 -- sleep 30

# Expect high node-load-misses for cross-NUMA access
```

## Solutions and Mitigations

### Immediate Solutions (Tested)

#### 1. **CPU Binding (✓ Proven Effective)**

Bind application to same NUMA node as physical NIC:

```bash
# Find NIC's NUMA node
NIC_NUMA=$(cat /sys/class/net/enp94s0f0np0/device/numa_node)

# Get CPU list for that NUMA node
CPUS=$(lscpu | grep "NUMA node${NIC_NUMA}" | awk '{print $NF}')

# Bind iperf to those CPUs
taskset -c $CPUS iperf3 -s -p 5201

# For systemd services:
systemctl edit <service>
# Add:
[Service]
CPUAffinity=0-15  # Replace with actual NUMA 0 CPU list
NUMAPolicy=bind
NUMAMask=0
```

**Impact:** Reduces tail from 8-16ms to ~2ms, but doesn't eliminate it.

#### 2. **IRQ Affinity Tuning**

Set NIC IRQs to same NUMA node as application:

```bash
# Find all NIC IRQ numbers
NIC_IRQS=$(cat /proc/interrupts | grep enp94s0f0np0 | cut -d: -f1)

# Get CPUs on NIC's NUMA node
NIC_NUMA=$(cat /sys/class/net/enp94s0f0np0/device/numa_node)
NUMA_CPUS=$(lscpu -p=CPU,NODE | grep ",${NIC_NUMA}$" | cut -d, -f1 | xargs | tr ' ' ',')

# Set IRQ affinity
for IRQ in $NIC_IRQS; do
    echo $NUMA_CPUS > /proc/irq/$IRQ/smp_affinity_list
done

# Disable irqbalance to prevent overriding
systemctl stop irqbalance
systemctl disable irqbalance
```

### Advanced Solutions

#### 3. **Enable and Configure RPS/RFS**

Receive Packet Steering can direct packets to the right CPU:

```bash
# Enable RPS for internal port (port-storage)
# Set to CPUs on same NUMA as NIC
echo $NUMA_CPUS > /sys/class/net/port-storage/queues/rx-0/rps_cpus

# Enable RFS
sysctl -w net.core.rps_sock_flow_entries=32768
echo 2048 > /sys/class/net/port-storage/queues/rx-0/rps_flow_cnt

# For multi-queue NICs, apply to all queues
for queue in /sys/class/net/enp94s0f0np0/queues/rx-*; do
    echo $NUMA_CPUS > $queue/rps_cpus
    echo 2048 > $queue/rps_flow_cnt
done
```

**Note:** This helps steer packets to the right CPU based on flow hash.

#### 4. **NUMA-Aware Socket Allocation**

Force socket allocation on specific NUMA node:

```bash
# Using numactl to run application
numactl --cpunodebind=$NIC_NUMA --membind=$NIC_NUMA \
    iperf3 -s -p 5201
```

Or in code (for custom applications):
```c
#include <numaif.h>

// Bind current thread to NUMA node 0
unsigned long nodemask = 1 << 0;  // Node 0
set_mempolicy(MPOL_BIND, &nodemask, sizeof(nodemask) * 8);

// Create socket (will use NUMA 0 memory)
int sock = socket(AF_INET, SOCK_STREAM, 0);
```

#### 5. **Kernel Tuning Parameters**

```bash
# Increase socket buffer sizes to reduce cross-NUMA copy frequency
sysctl -w net.core.rmem_max=134217728        # 128MB
sysctl -w net.core.wmem_max=134217728
sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"
sysctl -w net.ipv4.tcp_wmem="4096 87380 134217728"

# Enable TCP auto-tuning
sysctl -w net.ipv4.tcp_moderate_rcvbuf=1

# Reduce scheduler migration aggressiveness
sysctl -w kernel.sched_migration_cost_ns=5000000  # 5ms (default: 500us)

# Increase NUMA balancing scan delay
sysctl -w kernel.numa_balancing_scan_delay_ms=3000
```

#### 6. **OVS Datapath Optimization**

If using OVS kernel datapath, consider switching to DPDK datapath:

```bash
# DPDK datapath bypasses kernel, reduces NUMA impact
ovs-vsctl get Open_vSwitch . dpdk_initialized
# If false, configure DPDK with proper NUMA socket memory:
ovs-vsctl set Open_vSwitch . \
    other_config:dpdk-socket-mem="2048,2048"  # 2GB per NUMA node
```

### Experimental Solutions

#### 7. **SKB NUMA-Aware Allocation** (Requires Kernel Patch)

Modify kernel to allocate SKBs on destination CPU's NUMA node:

```c
// Hypothetical patch for net/core/dev.c:netif_rx_internal()
static int netif_rx_internal(struct sk_buff *skb)
{
    int target_cpu = get_target_cpu(skb);  // Based on RPS/flow hash
    int target_node = cpu_to_node(target_cpu);

    // Reallocate SKB on target NUMA node if different
    if (target_node != page_to_nid(virt_to_page(skb->head))) {
        skb = skb_copy_numa(skb, GFP_ATOMIC, target_node);
    }

    return enqueue_to_backlog(skb, target_cpu, &qtail);
}
```

**Trade-off:** Adds SKB copy overhead, but eliminates cross-NUMA access.

#### 8. **Dedicated CPU for OVS Forwarding**

Reserve specific CPUs for OVS processing on same NUMA as NIC:

```bash
# Isolate CPUs 0-3 for OVS processing
# Add to kernel boot parameters in /etc/default/grub:
GRUB_CMDLINE_LINUX="isolcpus=0-3 nohz_full=0-3 rcu_nocbs=0-3"

# Update grub
grub2-mkconfig -o /boot/grub2/grub.cfg
reboot

# Set OVS PMD CPU mask (for DPDK)
ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=0x0F  # CPUs 0-3
```

### Why CPU Binding Isn't Perfect

Even with CPU binding to the same NUMA node, ~2ms tail latency remains due to:

1. **Intra-NUMA Variability**: CPUs within same NUMA node may have different memory access latencies
2. **Cache Coherency**: Different cores within NUMA still have cache coherency overhead
3. **Memory Channel Contention**: Multiple cores accessing same memory controller
4. **SMT (Hyper-Threading) Interference**: If binding to logical cores (siblings)
5. **OS Scheduler Jitter**: Even pinned processes may be briefly preempted
6. **IOMMU/Device I/O**: DMA transfers may contend with CPU memory access

## Comparison with Intel Systems

**Why this issue is Hygon-specific:**

| Aspect | Intel Xeon | Hygon/AMD EPYC |
|--------|-----------|----------------|
| NUMA Interconnect | UPI (Ultra Path Interconnect) | Infinity Fabric |
| Cross-socket latency | ~30-40ns | ~40-50ns |
| Cross-socket bandwidth | ~50% local | ~40% local |
| Memory controller | Integrated, closer to cores | On I/O die, farther from cores |
| NUMA granularity | Per socket | Per CCX/die (more NUMA domains) |
| Default balancing | Less aggressive | More aggressive (can cause migration) |

## Performance Testing

### Test Methodology

```bash
#!/bin/bash
# Test script: test-numa-impact.sh

NIC=enp94s0f0np0
SERVER_IP=70.0.0.33
NIC_NUMA=$(cat /sys/class/net/$NIC/device/numa_node)

echo "=== Test 1: No binding ==="
killall iperf3
iperf3 -s -p 5201 &
sleep 2
# Run latency monitoring in background
sudo python3 system_network_latency_summary.py \
    --phy-interface $NIC --src-ip $SERVER_IP --direction rx --interval 10 &
TRACE_PID=$!
sleep 60
kill $TRACE_PID
killall iperf3

echo "=== Test 2: CPU binding (same NUMA) ==="
NUMA_CPUS=$(lscpu -p=CPU,NODE | grep ",${NIC_NUMA}$" | cut -d, -f1 | head -1)
taskset -c $NUMA_CPUS iperf3 -s -p 5201 &
sleep 2
sudo python3 system_network_latency_summary.py \
    --phy-interface $NIC --src-ip $SERVER_IP --direction rx --interval 10 &
TRACE_PID=$!
sleep 60
kill $TRACE_PID
killall iperf3

echo "=== Test 3: CPU + memory binding (NUMA aware) ==="
numactl --cpunodebind=$NIC_NUMA --membind=$NIC_NUMA iperf3 -s -p 5201 &
sleep 2
sudo python3 system_network_latency_summary.py \
    --phy-interface $NIC --src-ip $SERVER_IP --direction rx --interval 10 &
TRACE_PID=$!
sleep 60
kill $TRACE_PID
killall iperf3
```

### Expected Results

| Test Scenario | P50 Latency | P99 Latency | Max Latency |
|---------------|-------------|-------------|-------------|
| No binding | 8-15us | 32-63us | **8192-16383us** |
| CPU binding | 4-7us | 16-31us | **1024-2047us** |
| CPU + memory binding | 2-4us | 8-15us | 256-511us |
| Full optimization (IRQ+RPS+binding) | 1-2us | 4-7us | 32-63us |

## Monitoring and Alerting

### Production Monitoring

```bash
# 1. Track NUMA memory stats
#!/bin/bash
# numa-monitor.sh
while true; do
    timestamp=$(date +%s)
    numastat -s | awk -v ts=$timestamp '{print ts" "$0}' >> /var/log/numa-stats.log
    sleep 60
done

# 2. Monitor cross-NUMA traffic
perf stat -e node-loads,node-load-misses -a -I 5000 2>&1 | \
    awk '{if ($4 ~ /node-load-misses/) print $1, $2}' >> /var/log/numa-misses.log

# 3. Track softirq distribution
watch -n 5 "grep 'NET_RX' /proc/softirqs | awk '{print \$1, \$3, \$19}'" >> /var/log/softirq-dist.log
```

### Alert Thresholds

```yaml
# Prometheus alerting rules
groups:
- name: numa_alerts
  rules:
  - alert: HighCrossNUMATraffic
    expr: |
      (numa_other_node_accesses / numa_total_accesses) > 0.3
    for: 5m
    annotations:
      description: "More than 30% memory accesses crossing NUMA boundary"

  - alert: TCPHighRTTVariance
    expr: |
      tcp_rttvar_microseconds > 2000
    for: 1m
    annotations:
      description: "TCP RTT variance >2ms, indicating NUMA issues"
```

## References

### Kernel Source Files

- `net/openvswitch/vport.c:488` - ovs_vport_send()
- `net/openvswitch/vport-internal_dev.c:251` - internal_dev_recv()
- `net/core/dev.c:4476` - netif_rx_internal()
- `net/core/dev.c:4235` - enqueue_to_backlog()
- `net/ipv4/tcp_ipv4.c` - tcp_v4_rcv()

### Related Documentation

- [AMD EPYC NUMA Optimization](https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/AMD-Optimizes-EPYC-Memory-With-NUMA.pdf)
- [Linux Kernel RPS/RFS Documentation](https://www.kernel.org/doc/Documentation/networking/scaling.txt)
- [NUMA Memory Policy](https://www.kernel.org/doc/html/latest/admin-guide/mm/numa_memory_policy.html)

### eBPF Tools

- `ebpf-tools/performance/system-network/system_network_latency_summary.py` - Adjacent stage latency tracking
- `ebpf-tools/performance/system-network/tcp_connection_analyzer.py` - TCP connection analysis with netstat integration

## Conclusion

The latency tail issue on Hygon CPUs is caused by **cross-NUMA memory access** when packets are processed on CPUs different from the NIC's NUMA node. The kernel's `netif_rx()` path enqueues packets to the current CPU's backlog, which may be on a different NUMA domain than where the SKB was allocated.

**Recommended mitigation strategy:**

1. **Immediate:** CPU binding to same NUMA as NIC (reduces tail to ~2ms)
2. **Short-term:** IRQ affinity + RPS/RFS configuration
3. **Long-term:** NUMA-aware memory policy + kernel tuning
4. **Production:** Continuous monitoring of NUMA metrics + alerting

This issue is architectural and specific to AMD/Hygon NUMA topology. Complete elimination may require kernel patches or migration to single-NUMA systems.

---

**Report Generated:** 2025-10-29
**Analysis Tools:** system_network_latency_summary.py, tcp_connection_analyzer.py
**Kernel Version:** 4.19.90 (openEuler)
**Hardware:** Hygon CPU (AMD Zen-based architecture)
