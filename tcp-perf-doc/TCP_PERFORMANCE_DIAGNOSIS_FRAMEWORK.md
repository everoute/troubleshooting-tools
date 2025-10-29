# TCP Performance End-to-End Diagnosis Framework

## Problem Statement

**Observed Symptoms**:
- Server-side RTT (5.422 ms) significantly higher than client-side RTT (0.167 ms)
- Server-side RTTvar very high (10.612 ms, ~195% of RTT)
- Server-side recv_q backlog (122 KB)
- **Issue is intermittent and unstable** - hard to attribute to single factor

**Challenge**: Non-deterministic performance degradation requires systematic analysis across all layers.

## Diagnosis Methodology

### Phase 1: Establish Baseline and Monitoring

#### 1.1 Continuous Metrics Collection

**Collect metrics from both endpoints simultaneously**:

```bash
# On server side (1.1.1.2)
while true; do
    echo "=== $(date +%s.%N) ==="
    ss -tinopm dst 1.1.1.3 and dport = :53730 | grep -A 20 "ESTAB"
    sleep 0.1
done > /tmp/server_metrics.log

# On client side (1.1.1.3)
while true; do
    echo "=== $(date +%s.%N) ==="
    ss -tinopm dst 1.1.1.2 and dport = :5201 | grep -A 20 "ESTAB"
    sleep 0.1
done > /tmp/client_metrics.log
```

**Metrics to track**:
- RTT and RTTvar over time
- recv_q and send_q variations
- cwnd and ssthresh changes
- Retransmission events
- Delivery rate fluctuations

#### 1.2 Packet-Level Capture

**Simultaneous tcpdump on both sides**:

```bash
# On server (1.1.1.2)
sudo tcpdump -i any -nn -ttt -s 128 \
    'host 1.1.1.3 and port 5201' \
    -w /tmp/server_packets_$(date +%s).pcap

# On client (1.1.1.3)
sudo tcpdump -i any -nn -ttt -s 128 \
    'host 1.1.1.2 and port 5201' \
    -w /tmp/client_packets_$(date +%s).pcap
```

**Analysis focus**:
- ACK timing patterns
- Retransmission patterns
- TCP window advertisements
- Out-of-order delivery
- Timestamp differences

#### 1.3 System-Wide Statistics

```bash
# TCP statistics delta monitoring (both sides)
while true; do
    echo "=== $(date +%s) ==="
    netstat -s | grep -A 50 "Tcp:"
    sleep 1
done > /tmp/tcp_stats.log

# Compare deltas to identify bursts
```

### Phase 2: Layer-by-Layer Analysis

## 2.1 Application Layer

### Questions to Answer:
1. **Is the application reading data fast enough?**
2. **Are there CPU scheduling delays?**
3. **Is there memory pressure causing delays?**

### Diagnostic Commands:

```bash
# Monitor application CPU and memory
pidstat -p $(pgrep iperf3) -u -r -d 1

# Check application syscalls
strace -p $(pgrep iperf3) -e trace=read,write,sendto,recvfrom -T -tt

# Check application I/O wait
iotop -p $(pgrep iperf3) -o -b -d 1

# Check if application is blocked
cat /proc/$(pgrep iperf3)/stack

# Monitor context switches
perf stat -p $(pgrep iperf3) -e context-switches,cpu-migrations sleep 10
```

### Key Metrics:
- **User CPU %**: Should be high if app is compute-bound
- **System CPU %**: High if syscall overhead
- **IO wait %**: High if disk I/O blocking
- **Context switches**: High if scheduling issues
- **Read latency**: Time spent in read() syscalls

### Expected Values:
```
Normal iperf3:
- User CPU: 5-20%
- System CPU: 10-30%
- Context switches: < 1000/sec
- Read syscall time: < 1ms

Problematic:
- User CPU: > 50% (processing bottleneck)
- System CPU: > 50% (kernel overhead)
- Context switches: > 10000/sec (scheduling thrashing)
- Read syscall time: > 10ms (blocking on I/O)
```

## 2.2 TCP/Socket Layer

### Questions to Answer:
1. **Why does recv_q accumulate?**
2. **Why is RTTvar so high?**
3. **Are there TCP layer drops?**

### Diagnostic Commands:

```bash
# Socket buffer monitoring
ss -tmi dst 1.1.1.3 | grep -E "skmem|rcv|snd"

# Detailed socket statistics
cat /proc/net/sockstat
cat /proc/net/tcp | grep "1.1.1.3:5201"

# TCP memory pressure
sysctl net.ipv4.tcp_mem
cat /proc/net/protocols | grep TCP

# Socket receive queue size over time
watch -n 0.1 'ss -tm dst 1.1.1.3 | grep Recv-Q'
```

### Key Metrics from ss skmem:
```
skmem:(r0,rb2227323,t0,tb14971392,f0,w0,o0,bl0,d0)
       │  │         │  │          │  │  │  │   │
       │  │         │  │          │  │  │  │   └─ d: Dropped packets
       │  │         │  │          │  │  │  └───── bl: Backlog
       │  │         │  │          │  │  └──────── o: Option memory
       │  │         │  │          │  └─────────── w: Write buffer
       │  │         │  │          └────────────── f: Forward alloc
       │  │         │  └───────────────────────── tb: TX buffer size
       │  │         └──────────────────────────── t: TX queue length
       │  └────────────────────────────────────── rb: RX buffer size
       └───────────────────────────────────────── r: RX queue length (recv_q)
```

### Problematic Patterns:
```
1. r > 0 sustained: Application not reading
2. bl > 0: Backlog processing
3. d > 0: Socket drops (critical!)
4. rb == r: Buffer full (flow control)
```

## 2.3 Linux Network Stack

### Questions to Answer:
1. **Are there packet drops in the stack?**
2. **Is softirq processing delayed?**
3. **Are there queueing delays?**

### Diagnostic Commands:

```bash
# NIC ring buffer drops
ethtool -S eth0 | grep -i drop

# Softirq CPU usage
mpstat -P ALL 1 | grep -E "CPU|soft"

# Softirq breakdown
watch -n 1 'cat /proc/softirqs | grep -E "NET_RX|NET_TX"'

# Backlog drops
netstat -s | grep -i "listened\|backlog\|drop\|overflow"

# RPS/RFS configuration
cat /sys/class/net/eth0/queues/rx-*/rps_cpus
cat /proc/sys/net/core/rps_sock_flow_entries

# Network stack latency tracing
sudo perf record -e net:netif_receive_skb -a -g -- sleep 10
sudo perf report
```

### Key Metrics:
- **softirq %si**: Should be < 20%
- **NIC drops**: Should be 0
- **Listen queue overflow**: Should be 0
- **Backlog drops**: Should be 0

### Expected Values:
```
Normal:
- softirq CPU: 5-15%
- NIC rx_dropped: 0
- NIC rx_errors: 0
- TCP listen drops: 0

Problematic:
- softirq CPU: > 30% (interrupt storm)
- NIC drops > 0: Ring buffer too small
- Listen drops > 0: Backlog queue full
```

## 2.4 Network Path

### Questions to Answer:
1. **Is there actual packet loss in the network?**
2. **Are there path changes causing jitter?**
3. **Is there queuing delay in switches?**

### Diagnostic Commands:

```bash
# Continuous ping with timestamps
ping -D -i 0.01 1.1.1.3 > /tmp/ping_timestamps.log

# Traceroute with MTR
mtr -r -c 1000 -i 0.1 1.1.1.3 > /tmp/mtr_report.txt

# Check for path asymmetry
traceroute -n 1.1.1.3
# Compare with reverse traceroute from 1.1.1.3 to 1.1.1.2

# ICMP RTT statistics
ping -c 1000 -i 0.01 -q 1.1.1.3 | tail -5

# Check ARP table stability
watch -n 1 'arp -n | grep 1.1.1.3'

# Interface statistics
ip -s link show
```

### Key Metrics:
- **ICMP min RTT**: Baseline network latency
- **ICMP RTT stddev**: Network jitter
- **Packet loss %**: Network reliability
- **Path stability**: Route flapping

### Expected Values:
```
Normal (datacenter):
- ICMP RTT: 0.05-0.2 ms
- Jitter (mdev): < 0.05 ms
- Loss: 0%

Problematic:
- ICMP RTT: > 1 ms
- Jitter: > 0.5 ms (indicates queuing or congestion)
- Loss: > 0.01%
```

## 2.5 Hardware Layer

### Questions to Answer:
1. **Are there NIC issues?**
2. **Is there CPU throttling?**
3. **Is NUMA causing issues?**

### Diagnostic Commands:

```bash
# NIC statistics
ethtool -S eth0
ethtool -k eth0  # Offload features
ethtool -c eth0  # Coalescing settings

# CPU frequency scaling
watch -n 1 'grep MHz /proc/cpuinfo'
cpupower frequency-info

# Check for CPU throttling
turbostat --interval 1

# NUMA topology
numactl --hardware
numastat -p $(pgrep iperf3)

# IRQ affinity
cat /proc/interrupts | grep eth0
cat /proc/irq/*/smp_affinity_list

# Check for CPU steal (in VMs)
vmstat 1 10 | awk '{print $15}'  # %st column
```

### Key Metrics:
- **NIC errors/drops**: Should be 0
- **CPU frequency**: Should be max
- **NUMA remote access**: Should be < 10%
- **CPU steal time**: Should be < 5%

### Expected Values:
```
Normal:
- NIC errors: 0
- CPU freq: Max turbo frequency
- NUMA local: > 95%
- CPU steal: < 1%

Problematic:
- NIC CRC errors: > 0 (cable/hardware issue)
- CPU freq throttled: < 80% of max
- NUMA remote: > 20% (cross-NUMA penalty)
- CPU steal: > 10% (VM overcommit)
```

## Phase 3: Correlation Analysis

### 3.1 Time-Series Correlation

**Goal**: Find which metrics correlate with high RTT events

```bash
# Parse metrics logs to extract time-series
# Example: Extract RTT over time
grep "rtt:" /tmp/server_metrics.log | \
    awk '{print $1, $NF}' > /tmp/rtt_timeseries.txt

# Correlate with other metrics
# Example: recv_q vs RTT
paste /tmp/rtt_timeseries.txt /tmp/recvq_timeseries.txt | \
    awk '{if ($2 > 1) print "High RTT:", $2, "recv_q:", $4}'
```

### Correlation Hypotheses to Test:

1. **recv_q → RTT**: Does high recv_q always cause high RTT?
2. **CPU usage → recv_q**: Does high CPU cause recv_q backlog?
3. **Retrans → RTT**: Do retransmissions correlate with RTT spikes?
4. **cwnd → throughput**: Is cwnd limiting throughput?
5. **Time of day → performance**: Is there periodic pattern?

### 3.2 Event-Based Analysis

**Identify high RTT events**:

```bash
# Find periods where RTT > 2ms
awk '/rtt:/ {
    if ($NF > 2.0) {
        print "High RTT event at", $1, "RTT=", $NF
    }
}' /tmp/server_metrics.log > /tmp/high_rtt_events.txt

# Cross-reference with other logs at same timestamps
```

**For each high RTT event, check**:
- What was recv_q at that time?
- What was CPU usage?
- Were there retransmissions?
- Were there NIC errors?
- What was softirq CPU?

### 3.3 Statistical Analysis

```python
# Example analysis script
import pandas as pd
import numpy as np

# Load metrics
df = pd.read_csv('metrics.csv', parse_dates=['timestamp'])

# Calculate correlation matrix
correlation = df[['rtt', 'rttvar', 'recv_q', 'cwnd', 'retrans', 'cpu']].corr()
print(correlation)

# Identify outliers
rtt_mean = df['rtt'].mean()
rtt_std = df['rtt'].std()
outliers = df[df['rtt'] > rtt_mean + 2*rtt_std]

print(f"Normal RTT: {rtt_mean:.3f} ± {rtt_std:.3f} ms")
print(f"Outlier events: {len(outliers)}")

# Analyze outlier characteristics
print(outliers[['rtt', 'recv_q', 'cpu', 'retrans']].describe())
```

## Phase 4: Root Cause Categories

### Category 1: Application-Level Issues

**Symptoms**:
- recv_q consistently high
- Application CPU low
- No network issues

**Possible Causes**:
1. Application blocked on I/O (disk, database)
2. Application doing expensive computation per read
3. Application buffer management inefficient
4. Lock contention in multithreaded app

**Diagnostic**:
```bash
# Check what app is doing
strace -p $(pgrep iperf3) -c -f -T

# Check app stack traces
perf record -p $(pgrep iperf3) -g -- sleep 10
perf report

# Check for locks
cat /proc/$(pgrep iperf3)/status | grep voluntary
```

### Category 2: TCP Stack Issues

**Symptoms**:
- High RTTvar
- Frequent cwnd changes
- Retransmissions present

**Possible Causes**:
1. Small receive buffers causing flow control
2. Delayed ACK mechanism
3. TCP buffer memory exhausted
4. Socket backlog drops

**Diagnostic**:
```bash
# Check TCP memory
cat /proc/net/sockstat
sysctl net.ipv4.tcp_mem

# Check buffer sizes
ss -tmi dst 1.1.1.3 | grep rcv

# Check for socket drops
netstat -s | grep "pruned\|collapsed\|backlog"
```

### Category 3: Scheduling/CPU Issues

**Symptoms**:
- High softirq CPU
- High context switches
- Variable application CPU

**Possible Causes**:
1. IRQ affinity not optimized
2. CPU frequency scaling
3. Scheduler delays
4. NUMA placement issues

**Diagnostic**:
```bash
# Check IRQ distribution
cat /proc/interrupts | grep eth

# Check CPU isolation
cat /sys/devices/system/cpu/isolated

# Check scheduler stats
perf sched record -- sleep 10
perf sched latency
```

### Category 4: Network Path Issues

**Symptoms**:
- ICMP RTT also variable
- Packet loss
- MTR shows issues

**Possible Causes**:
1. Switch buffer overflow
2. Link congestion
3. Path changes (ECMP flapping)
4. MTU mismatches

**Diagnostic**:
```bash
# Check link utilization
ethtool -S eth0 | grep bytes
# Calculate: (bytes_delta * 8) / time_delta

# Check for pause frames
ethtool -S eth0 | grep pause

# Path MTU discovery
tracepath 1.1.1.3

# Check switch if accessible
# (vendor-specific commands)
```

### Category 5: Hardware Issues

**Symptoms**:
- NIC errors increasing
- CPU throttling
- VM steal time high

**Possible Causes**:
1. NIC hardware faults
2. Cable issues
3. CPU thermal throttling
4. VM resource contention

**Diagnostic**:
```bash
# NIC diagnostics
ethtool -t eth0  # Self-test

# Check hardware errors
dmesg | grep -i error

# Check temperatures
sensors

# VM-specific
virt-top  # If host access available
```

## Phase 5: Targeted eBPF Tracing

### 5.1 TCP RTT Breakdown Tracing

Create eBPF tool to measure RTT components:

```python
#!/usr/bin/env python3
# tcp_rtt_breakdown.py

from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct event_t {
    u64 ts;
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 srtt_us;
    u32 mdev_us;
    u32 rto;
    u64 data_sent_ts;
    u64 ack_recv_ts;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(packet_ts, u64, u64);  // Track packet send time

// Hook tcp_transmit_skb - when packet is sent
int trace_tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk) {
    if (sk == NULL)
        return 0;

    u16 dport = sk->__sk_common.skc_dport;
    u16 sport = sk->__sk_common.skc_num;

    // Filter by port (e.g., 5201)
    if (ntohs(dport) != 5201 && sport != 5201)
        return 0;

    u64 ts = bpf_ktime_get_ns();
    u64 sk_ptr = (u64)sk;
    packet_ts.update(&sk_ptr, &ts);

    return 0;
}

// Hook tcp_ack - when ACK is received
int trace_tcp_ack(struct pt_regs *ctx, struct sock *sk) {
    if (sk == NULL)
        return 0;

    u64 sk_ptr = (u64)sk;
    u64 *send_ts = packet_ts.lookup(&sk_ptr);
    if (send_ts == NULL)
        return 0;

    struct tcp_sock *tp = tcp_sk(sk);
    struct event_t event = {};

    event.ts = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.saddr = sk->__sk_common.skc_rcv_saddr;
    event.daddr = sk->__sk_common.skc_daddr;
    event.sport = sk->__sk_common.skc_num;
    event.dport = ntohs(sk->__sk_common.skc_dport);
    event.srtt_us = tp->srtt_us >> 3;
    event.mdev_us = tp->mdev_us >> 2;
    event.rto = tp->icsk_rto;
    event.data_sent_ts = *send_ts;
    event.ack_recv_ts = event.ts;

    events.perf_submit(ctx, &event, sizeof(event));
    packet_ts.delete(&sk_ptr);

    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_transmit_skb", fn_name="trace_tcp_transmit_skb")
b.attach_kprobe(event="tcp_ack", fn_name="trace_tcp_ack")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    rtt_actual = (event.ack_recv_ts - event.data_sent_ts) / 1000000.0  # ms
    print(f"{event.ts/1e9:.3f} PID:{event.pid} "
          f"{event.saddr}:{event.sport} -> {event.daddr}:{event.dport} "
          f"Actual_RTT:{rtt_actual:.3f}ms SRTT:{event.srtt_us/1000:.3f}ms "
          f"RTTVAR:{event.mdev_us/1000:.3f}ms RTO:{event.rto}ms")

b["events"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()
```

### 5.2 Application Read Latency Tracing

```python
#!/usr/bin/env python3
# app_read_latency.py

from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>

struct event_t {
    u64 ts;
    u32 pid;
    u64 duration_ns;
    u64 bytes;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(start, u32, u64);

int trace_read_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

int trace_read_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *start_ts = start.lookup(&pid);
    if (start_ts == NULL)
        return 0;

    struct event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.pid = pid;
    event.duration_ns = event.ts - *start_ts;
    event.bytes = PT_REGS_RC(ctx);

    events.perf_submit(ctx, &event, sizeof(event));
    start.delete(&pid);
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_uprobe(name="c", sym="read", fn_name="trace_read_entry")
b.attach_uretprobe(name="c", sym="read", fn_name="trace_read_return")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    latency_ms = event.duration_ns / 1000000.0
    if latency_ms > 1.0:  # Only print if > 1ms
        print(f"{event.ts/1e9:.3f} PID:{event.pid} "
              f"read() latency:{latency_ms:.3f}ms bytes:{event.bytes}")

b["events"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()
```

### 5.3 ACK Delay Tracing

```python
#!/usr/bin/env python3
# ack_delay_tracer.py

from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/tcp.h>

struct event_t {
    u64 ts;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u64 data_recv_ts;
    u64 ack_send_ts;
    u32 ack_delay_us;
    u8 delayed_ack;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(recv_ts, u64, u64);

// Hook tcp_rcv_established - when data is received
int trace_tcp_rcv_established(struct pt_regs *ctx, struct sock *sk) {
    if (sk == NULL)
        return 0;

    u64 ts = bpf_ktime_get_ns();
    u64 sk_ptr = (u64)sk;
    recv_ts.update(&sk_ptr, &ts);

    return 0;
}

// Hook __tcp_send_ack - when ACK is sent
int trace_tcp_send_ack(struct pt_regs *ctx, struct sock *sk) {
    if (sk == NULL)
        return 0;

    u64 sk_ptr = (u64)sk;
    u64 *recv_time = recv_ts.lookup(&sk_ptr);
    if (recv_time == NULL)
        return 0;

    struct tcp_sock *tp = tcp_sk(sk);
    struct event_t event = {};

    event.ts = bpf_ktime_get_ns();
    event.saddr = sk->__sk_common.skc_rcv_saddr;
    event.daddr = sk->__sk_common.skc_daddr;
    event.sport = sk->__sk_common.skc_num;
    event.dport = ntohs(sk->__sk_common.skc_dport);
    event.data_recv_ts = *recv_time;
    event.ack_send_ts = event.ts;
    event.ack_delay_us = (event.ts - *recv_time) / 1000;

    // Check if this is delayed ACK
    struct inet_connection_sock *icsk = inet_csk(sk);
    event.delayed_ack = (icsk->icsk_ack.pending & ICSK_ACK_TIMER) ? 1 : 0;

    events.perf_submit(ctx, &event, sizeof(event));
    recv_ts.delete(&sk_ptr);

    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_rcv_established", fn_name="trace_tcp_rcv_established")
b.attach_kprobe(event="__tcp_send_ack", fn_name="trace_tcp_send_ack")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    delay_ms = event.ack_delay_us / 1000.0
    ack_type = "DELAYED" if event.delayed_ack else "IMMEDIATE"

    if delay_ms > 0.5:  # Only print if delay > 0.5ms
        print(f"{event.ts/1e9:.3f} {event.saddr}:{event.sport} -> {event.daddr}:{event.dport} "
              f"ACK_delay:{delay_ms:.3f}ms type:{ack_type}")

b["events"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()
```

## Phase 6: Decision Tree for Root Cause

```
Start: High server-side RTT observed (> 1ms)
│
├─ recv_q > 0?
│  ├─ YES → Check application
│  │  ├─ App CPU high? → Application compute-bound
│  │  ├─ App in D state? → Application I/O blocked
│  │  └─ App normal? → Socket buffer too small
│  │
│  └─ NO → Check network/stack
│     ├─ ICMP RTT also high?
│     │  ├─ YES → Network path issue
│     │  └─ NO → TCP-specific issue
│     │
│     ├─ RTTvar very high (> 50% of RTT)?
│     │  ├─ YES → Delayed ACK or variable processing
│     │  └─ NO → Stable delay, check for queuing
│     │
│     ├─ Retransmissions > 0?
│     │  ├─ YES → Packet loss, check network
│     │  └─ NO → No loss, ACK timing issue
│     │
│     └─ softirq CPU high (> 30%)?
│        ├─ YES → Interrupt processing bottleneck
│        └─ NO → Check hardware offloads
│
└─ Is issue intermittent?
   ├─ YES → Correlation analysis needed
   │  ├─ Pattern recognition
   │  ├─ Event-based triggers
   │  └─ Time-series analysis
   │
   └─ NO → Systematic issue, direct debugging
```

## Phase 7: Recommended Tools Suite

### Essential Tools:

1. **ss + custom script**: Real-time metric collection
2. **tcpdump**: Packet-level verification
3. **netstat -s**: System-wide TCP statistics
4. **perf**: CPU profiling and scheduling analysis
5. **eBPF tools**: Custom kernel tracing
6. **mtr/ping**: Network path validation

### Advanced Tools:

1. **tcp_connection_analyzer.py**: Automated analysis (your current tool)
2. **iperf3 + json output**: Controlled testing with detailed metrics
3. **Grafana + Prometheus**: Long-term metric visualization
4. **Wireshark**: Deep packet analysis
5. **SystemTap**: Advanced kernel tracing
6. **Brendan Gregg's perf-tools**: Ready-made profiling scripts

## Phase 8: Test Matrix for Systematic Debugging

### Controlled Experiments:

1. **Buffer size sweep**:
   ```bash
   for bufsize in 16K 64K 256K 1M 4M 16M; do
       iperf3 -c 1.1.1.2 -w $bufsize -t 30 -J > result_$bufsize.json
   done
   ```

2. **Parallelism test**:
   ```bash
   for parallel in 1 2 4 8 16; do
       iperf3 -c 1.1.1.2 -P $parallel -t 30 -J > result_P$parallel.json
   done
   ```

3. **Delayed ACK tuning**:
   ```bash
   for delack in 0 10 20 40 80; do
       sysctl -w net.ipv4.tcp_delack_min=$delack
       iperf3 -c 1.1.1.2 -t 30 -J > result_delack$delack.json
   done
   ```

4. **CPU affinity test**:
   ```bash
   for cpu in 0 1 2 3; do
       taskset -c $cpu iperf3 -c 1.1.1.2 -t 30 -J > result_cpu$cpu.json
   done
   ```

5. **Congestion control comparison**:
   ```bash
   for cc in cubic reno bbr; do
       sysctl -w net.ipv4.tcp_congestion_control=$cc
       iperf3 -c 1.1.1.2 -t 30 -J > result_cc_$cc.json
   done
   ```

## Summary Checklist

### For Each High RTT Event:

- [ ] Timestamp recorded
- [ ] recv_q value
- [ ] send_q value
- [ ] Application CPU usage
- [ ] System CPU (softirq)
- [ ] Retransmission count
- [ ] ICMP RTT at same time
- [ ] NIC statistics snapshot
- [ ] Packet capture available
- [ ] System logs checked
- [ ] Application logs checked

### Root Cause Hypothesis Template:

```
Event ID:
Timestamp:
Observed RTT:
Expected RTT:
Delta:

Primary suspect: [Application/TCP Stack/Network/Hardware]
Supporting evidence:
1.
2.
3.

Contradicting evidence:
1.
2.

Test to confirm:
1.
2.

Expected outcome if hypothesis correct:
```

## Conclusion

Since the issue is **intermittent and non-deterministic**, the key is:

1. **Continuous monitoring** across all layers simultaneously
2. **Correlation analysis** to find patterns
3. **Event-driven debugging** when high RTT occurs
4. **Systematic elimination** of potential causes through controlled tests
5. **eBPF tracing** for microsecond-level visibility

The problem is likely a combination of factors that occasionally align to cause high RTT, rather than a single root cause.
