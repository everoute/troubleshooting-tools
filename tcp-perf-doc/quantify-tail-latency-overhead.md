# Quantifying Tail Latency Overhead Sources: 8-16ms Deep Dive

## Problem Statement

**Observed**: 8-16ms latency tail in `ovs_vport_send → tcp_v4_rcv` path

**Expected cross-NUMA overhead**: ~5us (based on memory access latency)

**Discrepancy**: **1600x - 3200x** worse than pure NUMA overhead

**Question**: What accounts for the remaining 7.995 - 15.995ms delay?

---

## Hypothesis: Delay Composition

The 8-16ms delay is likely composed of:

```
Total delay = NUMA_overhead + Scheduler_delay + Lock_contention +
              CPU_throttling + Memory_pressure + IRQ_processing + Other

Expected breakdown:
- Pure NUMA overhead: 5-10us (0.06-0.12%)
- Scheduler delay: 1-5ms (12-31%)
- Lock contention: 0.5-2ms (6-12%)
- CPU throttling/frequency scaling: 0.1-1ms (1-6%)
- Memory pressure (page faults, reclaim): 0.5-3ms (6-19%)
- IRQ processing delay: 0.5-2ms (6-12%)
- Unexpected factors: 2-8ms (25-50%)
```

---

## Quantification Strategy

### Phase 1: Hardware Performance Counters
### Phase 2: Kernel Tracepoints
### Phase 3: eBPF Fine-Grained Tracing
### Phase 4: Statistical Analysis

---

## Phase 1: Hardware Performance Counters (PMU)

### 1.1 NUMA-Specific Counters

**Measure actual NUMA traffic**:

```bash
#!/bin/bash
# numa-pmu-trace.sh

# Start iperf server
iperf3 -s -p 5201 &
IPERF_PID=$!

# Run perf with NUMA-specific events
perf stat -e \
    'cpu/event=0x2e,umask=0x41,name=longest_lat_cache.miss/' \
    'cpu/event=0xb7,umask=0x01,offcore_response=0x10003c0001,name=offcore_local_dram/' \
    'cpu/event=0xb7,umask=0x01,offcore_response=0x10003c0002,name=offcore_remote_dram/' \
    'node-loads,node-load-misses,node-stores,node-store-misses' \
    -a -I 1000 -p $IPERF_PID -- sleep 60

# Analyze: offcore_remote_dram should be <30% of total if NUMA optimized
```

**Expected output**:
```
Time   offcore_local_dram  offcore_remote_dram  node-load-misses  % Remote
-----  ------------------  -------------------  ----------------  ---------
1.000  1,234,567,890       456,789,012          123,456,789       27%  ← BAD
2.000  1,245,678,901       12,345,678           8,765,432         1%   ← GOOD
```

**Analysis**:
```python
# If remote_dram > 30% of total: NUMA is the problem
# If remote_dram < 10%: NUMA is NOT the main cause
remote_ratio = offcore_remote_dram / (offcore_local_dram + offcore_remote_dram)

if remote_ratio > 0.30:
    print("NUMA memory access is significant contributor")
    numa_overhead_us = (node_load_misses * 40ns) / 1000  # 40ns per remote access
else:
    print("NUMA is NOT the main cause - look elsewhere")
```

### 1.2 Cache Miss Quantification

**Measure cache hierarchy performance**:

```bash
perf stat -e \
    L1-dcache-loads,L1-dcache-load-misses \
    LLC-loads,LLC-load-misses \
    -a -I 1000 -p $IPERF_PID -- sleep 60
```

**Calculate cache miss latency contribution**:
```python
# L1 miss → L2: 10 cycles @ 3GHz = 3.3ns
# L2 miss → L3: 40 cycles = 13.3ns
# L3 miss → DRAM (local): 200 cycles = 66ns
# L3 miss → DRAM (remote): 300 cycles = 100ns

cache_latency_us = (
    L1_misses * 0.003 +      # 3.3ns
    L2_misses * 0.013 +      # 13.3ns
    LLC_local_misses * 0.066 + # 66ns
    LLC_remote_misses * 0.1    # 100ns
) / 1000

print(f"Cache miss contribution: {cache_latency_us:.2f} us")
```

### 1.3 CPU Stall Cycles

**Identify what CPUs are waiting for**:

```bash
perf stat -e \
    cycles \
    instructions \
    'cycle_activity.stalls_ldm_pending' \
    'cycle_activity.stalls_mem_any' \
    -a -I 1000 -p $IPERF_PID -- sleep 60
```

**Analysis**:
```python
ipc = instructions / cycles  # Instructions per cycle

if ipc < 1.0:
    print("CPU is stalled frequently")
    stall_ratio = stalls_mem_any / cycles
    stall_time_ms = (stalls_mem_any / cpu_frequency_hz) * 1000
    print(f"Memory stalls: {stall_ratio*100:.1f}% of time, {stall_time_ms:.2f}ms total")
```

---

## Phase 2: Kernel Tracepoints Analysis

### 2.1 Scheduler Delay Tracing

**Track when packets are delayed by scheduler**:

```bash
#!/bin/bash
# trace-scheduler-delays.sh

# Enable tracepoints
echo 1 > /sys/kernel/debug/tracing/events/sched/sched_switch/enable
echo 1 > /sys/kernel/debug/tracing/events/sched/sched_wakeup/enable
echo 1 > /sys/kernel/debug/tracing/events/irq/softirq_raise/enable
echo 1 > /sys/kernel/debug/tracing/events/irq/softirq_entry/enable
echo 1 > /sys/kernel/debug/tracing/events/irq/softirq_exit/enable

# Start iperf
iperf3 -s -p 5201 &
IPERF_PID=$!

# Trace for 10 seconds
timeout 10 cat /sys/kernel/debug/tracing/trace_pipe > scheduler_trace.log

# Disable tracepoints
echo 0 > /sys/kernel/debug/tracing/events/sched/sched_switch/enable
echo 0 > /sys/kernel/debug/tracing/events/sched/sched_wakeup/enable
echo 0 > /sys/kernel/debug/tracing/events/irq/softirq_raise/enable
echo 0 > /sys/kernel/debug/tracing/events/irq/softirq_entry/enable
echo 0 > /sys/kernel/debug/tracing/events/irq/softirq_exit/enable

kill $IPERF_PID
```

**Parse scheduler delays**:

```python
#!/usr/bin/env python3
# parse_scheduler_delays.py

import re
from collections import defaultdict

softirq_raise = {}  # {cpu: timestamp}
softirq_entry = {}
delays = []

with open('scheduler_trace.log') as f:
    for line in f:
        # softirq_raise: vec=3 [action=NET_RX]
        match = re.search(r'(\d+\.\d+).*cpu=(\d+).*softirq_raise:.*vec=3', line)
        if match:
            ts, cpu = float(match.group(1)), int(match.group(2))
            softirq_raise[cpu] = ts

        # softirq_entry: vec=3 [action=NET_RX]
        match = re.search(r'(\d+\.\d+).*cpu=(\d+).*softirq_entry:.*vec=3', line)
        if match:
            ts, cpu = float(match.group(1)), int(match.group(2))
            if cpu in softirq_raise:
                delay_ms = (ts - softirq_raise[cpu]) * 1000
                delays.append(delay_ms)
                del softirq_raise[cpu]

# Analyze delays
delays.sort()
print(f"Total softirq delays: {len(delays)}")
print(f"P50: {delays[len(delays)//2]:.3f}ms")
print(f"P99: {delays[int(len(delays)*0.99)]:.3f}ms")
print(f"P99.9: {delays[int(len(delays)*0.999)]:.3f}ms")
print(f"Max: {max(delays):.3f}ms")

# Find culprits
long_delays = [d for d in delays if d > 5.0]
print(f"\nDelays >5ms: {len(long_delays)} ({len(long_delays)/len(delays)*100:.2f}%)")
```

**Expected findings**:
```
Total softirq delays: 15432
P50: 0.015ms
P99: 0.234ms
P99.9: 8.567ms  ← MATCHES OBSERVED TAIL!
Max: 15.234ms

Delays >5ms: 23 (0.15%)
```

**Interpretation**: If P99.9 scheduler delay matches observed tail → scheduler is the primary cause!

### 2.2 Lock Contention Tracing

**Trace kernel lock contention**:

```bash
# Use lockdep or lock_stat
echo 1 > /proc/sys/kernel/lock_stat

# Run workload
iperf3 -s -p 5201 &
sleep 60
killall iperf3

# Dump lock statistics
cat /proc/lock_stat > lock_contention.log

# Parse for high-contention locks
grep -A 5 "contentions" lock_contention.log | \
    awk '$2 > 1000 {print $0}' | \
    sort -k2 -rn | head -20
```

**Look for**:
```
Lock class         Contentions  Wait-time-avg  Hold-time-avg
-----------------------------------------------------------------
&sd->input_pkt_queue.lock  15234   2.3ms          0.05ms  ← SUSPECT!
&sk->sk_lock              8765    1.8ms          0.02ms
```

**Quantification**:
```python
# If input_pkt_queue lock has 15234 contentions over 60s
# And average wait time is 2.3ms
total_lock_wait = 15234 * 0.0023  # 35 seconds of total wait time

# If packet rate is 2M packets/sec
packet_rate = 2_000_000
lock_overhead_per_packet = 35 / (60 * packet_rate)  # seconds
lock_overhead_us = lock_overhead_per_packet * 1e6

print(f"Lock contention adds {lock_overhead_us:.2f}us per packet on average")
print(f"But P99.9 lock wait: {max_lock_wait_ms:.2f}ms")  # Could explain tail!
```

---

## Phase 3: eBPF Fine-Grained Tracing

### 3.1 Timestamp Each Stage with CPU Tracking

**Enhanced eBPF tool to track CPU migrations**:

```python
#!/usr/bin/env python3
# system_network_latency_cpu_tracking.py

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>

struct event_t {
    u64 ts;
    u32 cpu;
    u32 numa_node;
    u8 stage_id;
    u32 src_ip;
    u32 dst_ip;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(stage_cpu, u64, u32);  // Track which CPU processed each stage

static __always_inline void track_stage(struct pt_regs *ctx, struct sk_buff *skb, u8 stage_id) {
    struct event_t evt = {};
    evt.ts = bpf_ktime_get_ns();
    evt.cpu = bpf_get_smp_processor_id();
    evt.numa_node = cpu_to_node(evt.cpu);
    evt.stage_id = stage_id;

    // Extract packet key (src_ip, dst_ip)
    // ... parse_packet_key() ...

    events.perf_submit(ctx, &evt, sizeof(evt));

    // Track CPU for this packet+stage
    u64 key = ((u64)evt.src_ip << 32) | evt.dst_ip;
    stage_cpu.update(&key, &evt.cpu);
}

int kprobe__ovs_vport_send(struct pt_regs *ctx, void *vport, struct sk_buff *skb) {
    track_stage(ctx, skb, 5);
    return 0;
}

int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    track_stage(ctx, skb, 6);
    return 0;
}
"""

# Python handler
def process_event(cpu, data, size):
    event = b["events"].event(data)

    # Check for CPU migration
    key = (event.src_ip << 32) | event.dst_ip
    prev_cpu = stage_cpu.get(key, None)

    if prev_cpu and prev_cpu != event.cpu:
        print(f"CPU MIGRATION: {prev_cpu} -> {event.cpu} (NUMA {cpu_to_numa[prev_cpu]} -> {cpu_to_numa[event.cpu]})")
        migration_count[event.stage_id] += 1
```

**Run and analyze**:

```bash
sudo python3 system_network_latency_cpu_tracking.py --duration 60

# Output:
CPU MIGRATION detected: 1234 times (8.2% of packets)
  Stage 5→6 migrations: 987 (80% of migrations)
  Cross-NUMA migrations: 456 (37% of migrations)
  Same-NUMA migrations: 531 (43% of migrations)

Average latency:
  No migration: 15us
  Same-NUMA migration: 25us (+10us)
  Cross-NUMA migration: 8500us (+8485us)  ← SMOKING GUN!
```

**Conclusion**: If cross-NUMA migrations correlate with 8ms delays → CPU migration is the root cause!

### 3.2 Track Packet Lifecycle with Timestamps

**Create detailed timeline for delayed packets**:

```python
#!/usr/bin/env python3
# track_packet_lifecycle.py

bpf_text = """
struct packet_timeline_t {
    u64 ts_ovs_vport_send;
    u64 ts_internal_dev_recv;
    u64 ts_netif_rx;
    u64 ts_enqueue_to_backlog;
    u64 ts_softirq_entry;
    u64 ts_process_backlog;
    u64 ts_netif_receive_skb;
    u64 ts_tcp_v4_rcv;

    u32 cpu_ovs;
    u32 cpu_softirq;
    u32 numa_ovs;
    u32 numa_softirq;
};

BPF_HASH(packet_timelines, struct packet_key_t, struct packet_timeline_t);

// Trace each function
int kprobe__ovs_vport_send(...) {
    struct packet_timeline_t *tl = packet_timelines.lookup_or_init(&key, &zero);
    tl->ts_ovs_vport_send = bpf_ktime_get_ns();
    tl->cpu_ovs = bpf_get_smp_processor_id();
    tl->numa_ovs = cpu_to_node(tl->cpu_ovs);
}

int kprobe__netif_rx(...) {
    struct packet_timeline_t *tl = packet_timelines.lookup(&key);
    if (tl) tl->ts_netif_rx = bpf_ktime_get_ns();
}

int kprobe__enqueue_to_backlog(...) {
    struct packet_timeline_t *tl = packet_timelines.lookup(&key);
    if (tl) tl->ts_enqueue_to_backlog = bpf_ktime_get_ns();
}

TRACEPOINT_PROBE(irq, softirq_entry) {
    // Track when softirq starts processing
}

int kprobe__tcp_v4_rcv(...) {
    struct packet_timeline_t *tl = packet_timelines.lookup(&key);
    if (tl) {
        tl->ts_tcp_v4_rcv = bpf_ktime_get_ns();
        tl->cpu_softirq = bpf_get_smp_processor_id();
        tl->numa_softirq = cpu_to_node(tl->cpu_softirq);

        // Analyze delays
        u64 total_delay = tl->ts_tcp_v4_rcv - tl->ts_ovs_vport_send;
        if (total_delay > 5000000) {  // >5ms
            // Report detailed timeline
            events.perf_submit(ctx, tl, sizeof(*tl));
        }

        packet_timelines.delete(&key);
    }
}
"""

# Python analysis
def analyze_delayed_packet(timeline):
    """
    Breakdown of where time was spent
    """
    delays = {
        'ovs_to_netif_rx': timeline.ts_netif_rx - timeline.ts_ovs_vport_send,
        'netif_rx_to_enqueue': timeline.ts_enqueue_to_backlog - timeline.ts_netif_rx,
        'enqueue_to_softirq': timeline.ts_softirq_entry - timeline.ts_enqueue_to_backlog,
        'softirq_to_tcp': timeline.ts_tcp_v4_rcv - timeline.ts_softirq_entry,
    }

    total = timeline.ts_tcp_v4_rcv - timeline.ts_ovs_vport_send

    print(f"\nPacket Timeline (total: {total/1e6:.2f}ms):")
    for stage, delay_ns in delays.items():
        delay_ms = delay_ns / 1e6
        pct = (delay_ns / total) * 100
        print(f"  {stage:25s}: {delay_ms:8.3f}ms ({pct:5.1f}%)")

    print(f"\nCPU/NUMA info:")
    print(f"  OVS processing: CPU {timeline.cpu_ovs} (NUMA {timeline.numa_ovs})")
    print(f"  Softirq processing: CPU {timeline.cpu_softirq} (NUMA {timeline.numa_softirq})")

    if timeline.numa_ovs != timeline.numa_softirq:
        print(f"  *** CROSS-NUMA DETECTED ***")
```

**Expected output for 8ms delay**:

```
Packet Timeline (total: 8.567ms):
  ovs_to_netif_rx          :    0.015ms (  0.2%)  ← Normal
  netif_rx_to_enqueue      :    0.008ms (  0.1%)  ← Normal
  enqueue_to_softirq       :    8.234ms ( 96.1%)  ← CULPRIT!
  softirq_to_tcp           :    0.310ms (  3.6%)  ← Elevated (cross-NUMA read)

CPU/NUMA info:
  OVS processing: CPU 2 (NUMA 0)
  Softirq processing: CPU 18 (NUMA 1)
  *** CROSS-NUMA DETECTED ***
```

**Key finding**: 96% of delay is in `enqueue_to_softirq` → **scheduler delay, not memory access**!

---

## Phase 4: Targeted Micro-Benchmarks

### 4.1 Measure Raw Scheduler Latency

```c
// scheduler_latency_test.c
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <sched.h>

void* worker(void* arg) {
    struct timespec ts_send, ts_recv;

    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &ts_send);

        // Simulate enqueue_to_backlog: raise softirq
        pthread_kill(pthread_self(), SIGUSR1);

        // Wait for softirq handler (simulated)
        usleep(100);

        clock_gettime(CLOCK_MONOTONIC, &ts_recv);

        long delay_us = (ts_recv.tv_sec - ts_send.tv_sec) * 1000000 +
                       (ts_recv.tv_nsec - ts_send.tv_nsec) / 1000;

        if (delay_us > 5000) {
            printf("Scheduler delay: %ld us\n", delay_us);
        }
    }
}

int main() {
    // Pin to different NUMA nodes
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(2, &cpuset);  // NUMA 0
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

    pthread_t thread;
    pthread_create(&thread, NULL, worker, NULL);
    pthread_join(thread, NULL);
}
```

**Compile and run**:
```bash
gcc -o scheduler_test scheduler_latency_test.c -lpthread
./scheduler_test

# Observe P99.9 latency
# Compare with eBPF observed latency
```

### 4.2 Measure Cross-NUMA Memory Access Only

```c
// numa_memory_latency.c
#include <numa.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

int main() {
    if (numa_available() < 0) {
        fprintf(stderr, "NUMA not available\n");
        return 1;
    }

    // Allocate memory on NUMA 0
    void *mem_numa0 = numa_alloc_onnode(1024*1024, 0);

    // Bind current thread to NUMA 1
    numa_run_on_node(1);

    // Measure memory access latency
    struct timespec ts_start, ts_end;
    volatile char *ptr = mem_numa0;

    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    // Read 1500 bytes (simulate packet)
    for (int i = 0; i < 1500; i++) {
        char dummy = ptr[i];
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_end);

    long latency_ns = (ts_end.tv_sec - ts_start.tv_sec) * 1000000000 +
                      (ts_end.tv_nsec - ts_start.tv_nsec);

    printf("Cross-NUMA memory access (1500 bytes): %ld ns (%.2f us)\n",
           latency_ns, latency_ns / 1000.0);

    numa_free(mem_numa0, 1024*1024);
}
```

**Expected**: 2-10us for 1500 bytes cross-NUMA

**Conclusion**: If micro-benchmark shows 5us but real system shows 8ms → **memory access is NOT the cause**!

---

## Phase 5: Kernel ftrace Full Call Stack

**Capture exact call stack during delay**:

```bash
#!/bin/bash
# ftrace_delay_capture.sh

cd /sys/kernel/debug/tracing

# Set up function graph tracer
echo function_graph > current_tracer
echo 1 > options/funcgraph-abstime
echo 1 > options/funcgraph-cpu
echo 1 > options/funcgraph-duration
echo 1 > options/funcgraph-proc

# Filter for relevant functions
echo 'ovs_vport_send' > set_ftrace_filter
echo 'internal_dev_recv' >> set_ftrace_filter
echo 'netif_rx' >> set_ftrace_filter
echo 'enqueue_to_backlog' >> set_ftrace_filter
echo '__napi_schedule' >> set_ftrace_filter
echo 'net_rx_action' >> set_ftrace_filter
echo 'tcp_v4_rcv' >> set_ftrace_filter

# Start tracing
echo 1 > tracing_on

# Run workload
iperf3 -s -p 5201 &
sleep 10
killall iperf3

# Stop tracing
echo 0 > tracing_on

# Extract traces
cat trace > ftrace_output.log

# Find long delays
grep -B 5 -A 10 "duration: [0-9]\{4,\}" ftrace_output.log > long_delays.log
```

**Example output**:
```
 CPU)    DURATION    |  FUNCTION CALLS
 2)   0.234 us    |  ovs_vport_send();
 2)   0.156 us    |  internal_dev_recv();
 2)   0.089 us    |  netif_rx();
 2)   0.067 us    |  enqueue_to_backlog();
 2)   0.045 us    |  __napi_schedule();
 2)               |  /* schedule() called - switching to CPU 18 */
 ...
 18) + 8234.567 us |  /* Woke up after 8.2ms */  ← CULPRIT IDENTIFIED!
 18)  125.345 us  |  net_rx_action();
 18)   89.234 us  |    process_backlog();
 18)   45.123 us  |      __netif_receive_skb();
 18)   12.456 us  |        tcp_v4_rcv();
```

**Analysis**: The delay happened **between `__napi_schedule` and `net_rx_action`** → scheduler issue!

---

## Phase 6: Correlate with System Events

### 6.1 Check for Competing Workloads

```bash
# During tail latency events, what else is running?

# Start monitoring
sar -u ALL 1 60 > cpu_usage.log &
sar -r 1 60 > memory_usage.log &
vmstat 1 60 > vmstat.log &

# Run workload
iperf3 -s -p 5201 &
IPERF_PID=$!

# Trace high-latency events
python3 track_packet_lifecycle.py &
TRACE_PID=$!

sleep 60
kill $IPERF_PID $TRACE_PID
```

**Correlate timestamps**:
```python
import pandas as pd

# Load latency events
latency_events = pd.read_csv('latency_events.csv')  # From eBPF tool
cpu_usage = pd.read_csv('cpu_usage.log', sep='\s+')

# Merge by timestamp
merged = pd.merge_asof(
    latency_events,
    cpu_usage,
    left_on='timestamp',
    right_on='timestamp',
    tolerance=pd.Timedelta('1s')
)

# Check if high latency correlates with:
# - High system CPU: merged[merged['%sys'] > 30]
# - High IRQ: merged[merged['%irq'] > 5]
# - High soft IRQ: merged[merged['%softirq'] > 10]
# - High steal time: merged[merged['%steal'] > 1]
# - Memory pressure: merged[merged['kbmemfree'] < 1000000]

print("High latency events correlated with:")
for col in ['%sys', '%irq', '%softirq', '%steal']:
    corr = merged['latency_ms'].corr(merged[col])
    print(f"  {col}: {corr:.3f}")
```

**Example findings**:
```
High latency events correlated with:
  %sys: 0.023 (no correlation)
  %irq: 0.087 (weak correlation)
  %softirq: 0.892 (strong correlation!)  ← CULPRIT
  %steal: -0.012 (no correlation)
```

### 6.2 Check for Kernel Tasks

```bash
# During high latency, what kernel tasks are running?

# Enable process tracking in ftrace
echo 1 > /sys/kernel/debug/tracing/options/record-cmd

# Capture sched_switch events
echo 1 > /sys/kernel/debug/tracing/events/sched/sched_switch/enable

# Run workload
iperf3 -s -p 5201 &
sleep 60
killall iperf3

# Analyze what was running during delays
cat /sys/kernel/debug/tracing/trace | \
    grep -A 1 -B 1 "CPU 18" | \
    grep "prev_comm" | \
    sort | uniq -c | sort -rn | head -20
```

**Example output**:
```
  1234 prev_comm=swapper/18        ← CPU was IDLE!
   456 prev_comm=kworker/18:1
   123 prev_comm=ksoftirqd/18
    89 prev_comm=migration/18      ← Kernel doing CPU migration
    45 prev_comm=rcu_sched
```

**Interpretation**: If CPU was idle (`swapper`), delay is due to **scheduler not waking up softirq fast enough**!

---

## Expected Findings & Interpretation

### Scenario A: Pure NUMA Overhead (Unlikely)

```
PMU counters: 90% remote NUMA access
Scheduler delays: <1ms P99
Lock contention: minimal
eBPF timeline: 90% time in actual memory reads

→ Pure NUMA problem
→ Solution: Memory locality optimizations
```

### Scenario B: Scheduler Delay (Most Likely)

```
PMU counters: 10-20% remote NUMA access
Scheduler delays: 8-16ms P99.9  ← MATCHES!
Lock contention: minimal
eBPF timeline: 95% time in enqueue_to_softirq→softirq_entry

→ Scheduler not waking up softirq fast enough
→ Possible causes:
  1. CPU overloaded with other work
  2. Scheduler tunables too conservative
  3. CPU frequency scaling delays
  4. Softirq budget exhausted
  5. Kernel preemption issues

→ Solution: Scheduler tuning, CPU isolation, real-time priorities
```

### Scenario C: Lock Contention (Possible)

```
PMU counters: Normal
Scheduler delays: <1ms P99
Lock contention: 8-16ms on input_pkt_queue.lock
eBPF timeline: Time spent in spin_lock() calls

→ Lock contention between CPUs
→ Solution: Lock-free queues, per-CPU data structures
```

### Scenario D: CPU Frequency Scaling (Possible)

```
PMU counters: Normal
Scheduler delays: Normal
CPU frequency logs: CPU 18 was at 1.2GHz (not 3.0GHz) during delays

→ CPU in low power state, slow to ramp up
→ Solution: Set governor to 'performance'
```

### Scenario E: Memory Pressure (Possible)

```
Memory stats: High page fault rate during delays
eBPF timeline: Time spent in page fault handlers

→ Memory reclaim or allocation delays
→ Solution: Increase memory, reduce memory pressure
```

---

## Automated Analysis Script

```python
#!/usr/bin/env python3
# diagnose_tail_latency.py

import subprocess
import time
import json

class TailLatencyDiagnoser:
    def __init__(self):
        self.results = {}

    def run_pmu_analysis(self):
        """Phase 1: PMU counters"""
        print("[1/6] Running PMU analysis...")
        # ... (see Phase 1 code)

        remote_ratio = self.parse_pmu_output()
        self.results['numa_overhead_us'] = remote_ratio * 5.0  # Estimate

        if remote_ratio > 0.5:
            return "NUMA_HEAVY"
        return "NUMA_OK"

    def run_scheduler_trace(self):
        """Phase 2: Scheduler tracing"""
        print("[2/6] Tracing scheduler delays...")
        # ... (see Phase 2 code)

        delays = self.parse_scheduler_trace()
        p99_9 = delays[int(len(delays) * 0.999)]
        self.results['scheduler_delay_p99_9_ms'] = p99_9

        if p99_9 > 5.0:
            return "SCHEDULER_ISSUE"
        return "SCHEDULER_OK"

    def run_lock_analysis(self):
        """Phase 2: Lock contention"""
        print("[3/6] Analyzing lock contention...")
        # ... (see Phase 2 code)

        max_lock_wait = self.parse_lock_stat()
        self.results['max_lock_wait_ms'] = max_lock_wait

        if max_lock_wait > 5.0:
            return "LOCK_CONTENTION"
        return "LOCK_OK"

    def run_ebpf_timeline(self):
        """Phase 3: eBPF detailed timeline"""
        print("[4/6] Running eBPF packet lifecycle tracing...")
        # ... (see Phase 3 code)

        timeline = self.parse_ebpf_timeline()
        self.results['timeline_breakdown'] = timeline

        # Find dominant delay source
        max_stage = max(timeline.items(), key=lambda x: x[1])
        return max_stage[0]  # e.g., "enqueue_to_softirq"

    def run_ftrace(self):
        """Phase 5: Kernel function graph"""
        print("[5/6] Running ftrace analysis...")
        # ... (see Phase 5 code)

        call_stacks = self.parse_ftrace()
        self.results['long_delays_callstack'] = call_stacks

    def run_correlation(self):
        """Phase 6: System event correlation"""
        print("[6/6] Correlating with system events...")
        # ... (see Phase 6 code)

        correlations = self.correlate_system_events()
        self.results['correlations'] = correlations

    def diagnose(self):
        """Run all phases and produce diagnosis"""

        numa_status = self.run_pmu_analysis()
        sched_status = self.run_scheduler_trace()
        lock_status = self.run_lock_analysis()
        timeline_bottleneck = self.run_ebpf_timeline()
        self.run_ftrace()
        self.run_correlation()

        # Produce diagnosis
        print("\n" + "="*80)
        print("DIAGNOSIS REPORT")
        print("="*80)

        print(f"\nOverall latency breakdown:")
        print(f"  NUMA overhead:      {self.results['numa_overhead_us']:.2f} us ({self.results['numa_overhead_us']/8000*100:.1f}%)")
        print(f"  Scheduler delay:    {self.results['scheduler_delay_p99_9_ms']:.2f} ms ({self.results['scheduler_delay_p99_9_ms']/8*100:.1f}%)")
        print(f"  Lock contention:    {self.results['max_lock_wait_ms']:.2f} ms ({self.results['max_lock_wait_ms']/8*100:.1f}%)")
        print(f"  Other/unaccounted:  {8.0 - self.results['numa_overhead_us']/1000 - self.results['scheduler_delay_p99_9_ms'] - self.results['max_lock_wait_ms']:.2f} ms")

        print(f"\nPrimary bottleneck: {timeline_bottleneck}")

        if sched_status == "SCHEDULER_ISSUE":
            print("\n🔴 PRIMARY CAUSE: Scheduler delay")
            print("   Softirq not being scheduled promptly")
            print("\n   RECOMMENDED ACTIONS:")
            print("   1. Check CPU utilization and competing workloads")
            print("   2. Tune scheduler parameters:")
            print("      sysctl -w kernel.sched_min_granularity_ns=1000000  # 1ms")
            print("      sysctl -w kernel.sched_wakeup_granularity_ns=2000000  # 2ms")
            print("   3. Increase softirq priority:")
            print("      echo -20 > /proc/$(pgrep ksoftirqd)/oom_score_adj")
            print("   4. Enable threaded IRQs:")
            print("      echo 1 > /proc/sys/kernel/softirq_thread_enable")

        elif numa_status == "NUMA_HEAVY":
            print("\n🟡 PRIMARY CAUSE: Cross-NUMA memory access")
            print("   However, this only accounts for <1ms")
            print("   Combined with scheduler delay = observed tail")

        elif lock_status == "LOCK_CONTENTION":
            print("\n🟠 PRIMARY CAUSE: Lock contention")
            print(f"   input_pkt_queue lock wait: {self.results['max_lock_wait_ms']:.2f}ms")

        # Save full report
        with open('diagnosis_report.json', 'w') as f:
            json.dump(self.results, f, indent=2)

        print(f"\nFull report saved to: diagnosis_report.json")

if __name__ == "__main__":
    diagnoser = TailLatencyDiagnoser()
    diagnoser.diagnose()
```

**Run**:
```bash
sudo python3 diagnose_tail_latency.py

# Expected output:
================================================================================
DIAGNOSIS REPORT
================================================================================

Overall latency breakdown:
  NUMA overhead:      8.50 us (0.1%)
  Scheduler delay:    7.89 ms (98.6%)
  Lock contention:    0.08 ms (1.0%)
  Other/unaccounted:  0.02 ms

Primary bottleneck: enqueue_to_softirq

🔴 PRIMARY CAUSE: Scheduler delay
   Softirq not being scheduled promptly

   RECOMMENDED ACTIONS:
   1. Check CPU utilization and competing workloads
   2. Tune scheduler parameters (see above)
   3. Increase softirq priority
   4. Enable threaded IRQs
```

---

## Summary

**Quantification Strategy:**

| Phase | Method | Measures | Expected Time | Accuracy |
|-------|--------|----------|---------------|----------|
| 1 | PMU counters | NUMA traffic % | <1 min | ±10% |
| 2 | Kernel tracepoints | Scheduler delay | 5-10 min | ±5% |
| 3 | eBPF timeline | Per-stage breakdown | 10-20 min | ±1% |
| 4 | Micro-benchmarks | Isolated component cost | 10 min | High |
| 5 | ftrace | Call stack analysis | 10 min | Qualitative |
| 6 | Correlation | System-wide events | 5 min | Qualitative |

**Most Likely Finding:**
- NUMA overhead: 5-10us (0.06-0.12% of delay)
- **Scheduler delay: 7-15ms (87-94% of delay)** ← PRIMARY CAUSE
- Lock contention: 0.5-1ms (6-12% of delay)
- Other factors: <1ms

The key is **scheduler not promptly scheduling softirq processing after `__napi_schedule()`** is called, likely due to:
1. CPU running other high-priority tasks
2. Softirq budget exhausted
3. CPU in low-power state
4. Kernel preemption disabled for too long
