# Enqueue to Receive Latency Measurement Tools Guide

## Overview

This guide explains how to use the `enqueue_to_iprec_latency.py` and `enqueue_to_iprec_latency_threshold.py` tools to measure packet processing latency in the critical async boundary: `enqueue_to_backlog` → `__netif_receive_skb`.

## Tools

### 1. `enqueue_to_iprec_latency.py`

**Purpose**: Continuous latency distribution monitoring with histogram output

**Measures**:
- Stage 1→2: `enqueue_to_backlog` → `__netif_receive_skb` (CRITICAL ASYNC BOUNDARY)
- Stage 2→3: `__netif_receive_skb` → `ip_rcv`

### 2. `enqueue_to_iprec_latency_threshold.py`

**Purpose**: Threshold-based alerting with stack trace capture

**Captures on threshold breach**:
- Complete kernel stack trace
- CPU information (enqueue CPU, receive CPU, migration detection)
- Flow information (IP, port, protocol)
- Timestamp and queue depth

---

## Understanding the Measurement Points

### Kernel RX Path Architecture

```
Physical NIC Path (without RPS):
┌──────────────┐
│ Driver NAPI  │
└──────┬───────┘
       │
       v
┌─────────────────────────┐
│ netif_receive_skb()     │
└──────┬──────────────────┘
       │
       v
┌─────────────────────────┐     RPS enabled?
│ netif_receive_skb_      │────────Yes────┐
│ internal()              │                │
└──────┬──────────────────┘                │
       │ No                                 │
       v                                    v
┌─────────────────────────┐    ┌─────────────────────────┐
│ __netif_receive_skb()   │    │ enqueue_to_backlog()    │ ← Stage 1
│ (synchronous)           │    └──────┬──────────────────┘
└──────┬──────────────────┘           │ (async boundary)
       │                               │
       v                               v
┌─────────────────────────┐    ┌─────────────────────────┐
│ ip_rcv()                │    │ process_backlog()       │
└─────────────────────────┘    └──────┬──────────────────┘
                                      │
                                      v
                               ┌─────────────────────────┐
                               │ __netif_receive_skb()   │ ← Stage 2
                               └──────┬──────────────────┘
                                      │
                                      v
                               ┌─────────────────────────┐
                               │ ip_rcv()                │ ← Stage 3
                               └─────────────────────────┘

OVS Internal Port Path (ALWAYS uses enqueue):
┌──────────────────────┐
│ OVS datapath         │
└──────┬───────────────┘
       │
       v
┌──────────────────────┐
│ internal_dev_recv()  │
└──────┬───────────────┘
       │
       v
┌──────────────────────┐
│ netif_rx()           │ (ALWAYS calls enqueue_to_backlog)
└──────┬───────────────┘
       │
       v
┌──────────────────────┐
│ enqueue_to_backlog() │ ← Stage 1
└──────┬───────────────┘
       │ (async boundary)
       v
┌──────────────────────┐
│ process_backlog()    │
└──────┬───────────────┘
       │
       v
┌──────────────────────┐
│ __netif_receive_skb()│ ← Stage 2
└──────┬───────────────┘
       │
       v
┌──────────────────────┐
│ ip_rcv()             │ ← Stage 3
└──────────────────────┘
```

### Key Insights

1. **Physical NIC (without RPS)**: May bypass `enqueue_to_backlog` and directly call `__netif_receive_skb` synchronously
2. **OVS Internal Port**: ALWAYS goes through `enqueue_to_backlog` (via `netif_rx()`)
3. **With RPS enabled**: Both paths go through `enqueue_to_backlog`

**Important**: These tools monitor a **SINGLE interface** at a time. In OVS environments, packets traverse multiple interfaces, so you need separate measurements for each.

---

## Usage Patterns

### Pattern 1: Monitor Physical NIC

**Use case**: Measure hardware interrupt → softirq latency on physical interface

```bash
sudo ./enqueue_to_iprec_latency.py \
    --interface enp24s0f0np0 \
    --src-ip 70.0.0.32 \
    --dst-ip 70.0.0.31 \
    --dst-port 2181 \
    --protocol tcp \
    --interval 1
```

**What you're measuring**:
- If RPS disabled: Only packets that are enqueued (e.g., from other CPUs)
- If RPS enabled: All packets going through RPS steering

### Pattern 2: Monitor OVS Internal Port

**Use case**: Measure OVS → protocol stack latency

```bash
sudo ./enqueue_to_iprec_latency.py \
    --interface br-int \
    --dst-ip 70.0.0.31 \
    --protocol tcp \
    --interval 1
```

**What you're measuring**:
- Time from OVS calling `netif_rx()` to protocol stack processing
- This captures ksoftirqd scheduling delays

### Pattern 3: Threshold-based Alerting

**Use case**: Capture stack traces when latency exceeds threshold

```bash
# Alert on latency > 5ms on physical NIC
sudo ./enqueue_to_iprec_latency_threshold.py \
    --interface enp24s0f0np0 \
    --threshold-us 5000 \
    --protocol tcp

# Alert on latency > 1ms on OVS internal port
sudo ./enqueue_to_iprec_latency_threshold.py \
    --interface br-int \
    --threshold-us 1000 \
    --dst-port 2181 \
    --protocol tcp
```

### Pattern 4: End-to-End OVS Measurement

**Use case**: Understand total packet path in OVS environment

**Step 1**: Measure physical NIC latency
```bash
sudo ./enqueue_to_iprec_latency.py \
    --interface enp24s0f0np0 \
    --dst-port 2181 \
    --protocol tcp \
    --interval 5 > /tmp/phy_nic_latency.txt &
PHY_PID=$!
```

**Step 2**: Simultaneously measure internal port latency
```bash
sudo ./enqueue_to_iprec_latency.py \
    --interface br-int \
    --dst-port 2181 \
    --protocol tcp \
    --interval 5 > /tmp/internal_port_latency.txt &
INT_PID=$!
```

**Step 3**: Generate traffic and wait
```bash
# Run your workload...
sleep 60
```

**Step 4**: Stop and analyze
```bash
kill $PHY_PID $INT_PID
cat /tmp/phy_nic_latency.txt
cat /tmp/internal_port_latency.txt
```

---

## Interpreting Results

### Example Output (enqueue_to_iprec_latency.py)

```
================================================================================
[2024-01-15 10:30:45] Enqueue → IP_RCV Latency Report (Interval: 5.0s)
================================================================================

Latency Measurements:
--------------------------------------------------------------------------------

  STAGE1_enqueue_to_backlog -> STAGE2___netif_receive_skb:
    Total samples: 15234
    Latency distribution:
      0-1us           :   8520 ( 55.9%) |************************                |
      2-3us           :   4210 ( 27.6%) |************                            |
      4-7us           :   1890 ( 12.4%) |*****                                   |
      8-15us          :    456 (  3.0%) |*                                       |
      16-31us         :    123 (  0.8%) |                                        |
      32-63us         :     28 (  0.2%) |                                        |
      64-127us        :      7 (  0.0%) |                                        |
    ^^^ CRITICAL ASYNC BOUNDARY (enqueue → receive) ^^^

  STAGE2___netif_receive_skb -> STAGE3_ip_rcv:
    Total samples: 15234
    Latency distribution:
      0-1us           :  15180 ( 99.6%) |****************************************|
      2-3us           :     48 (  0.3%) |                                        |
      4-7us           :      6 (  0.0%) |                                        |

================================================================================
Packet Counters:
  Enqueued packets:        15234
  Received packets:        15234
  IP layer packets:        15234
  Cross-CPU migrations:    2345
  Parse failures:          0
  Flow lookup failures:    0

Backlog Queue Statistics:
  Average queue depth: 2.34 packets
  Total enqueue operations: 15234
================================================================================
```

### Key Metrics to Watch

1. **Enqueue → Receive Latency (Stage 1→2)**:
   - **< 10us**: Normal, healthy system
   - **10-100us**: Moderate load, possible CPU contention
   - **> 100us**: High scheduling delays, investigate ksoftirqd

2. **Cross-CPU Migrations**:
   - Should be low if RPS configured correctly
   - High values indicate poor RPS hash distribution

3. **Flow Lookup Failures**:
   - Should be 0 or very low
   - High values indicate packet loss or incorrect filtering

### Example Output (enqueue_to_iprec_latency_threshold.py)

```
================================================================================
HIGH LATENCY EVENT #1
================================================================================
Timestamp: 2024-01-15 10:32:17.123456

Latency: 8.456 ms (threshold: 5.000 ms)

Flow Information:
  Protocol: TCP
  Source: 70.0.0.32:45678
  Destination: 70.0.0.31:2181

CPU Information:
  Enqueue CPU: 2
  Receive CPU: 4
  ^^^ CROSS-CPU MIGRATION DETECTED ^^^

Timing Information:
  Enqueue timestamp: 1234567890123456 ns
  Receive timestamp: 1234567898579456 ns
  Queue depth: 128 packets

Kernel Stack Trace:
  __netif_receive_skb+0x1
  process_backlog+0xa5
  net_rx_action+0x123
  __do_softirq+0x89
  run_ksoftirqd+0x2a
  smpboot_thread_fn+0x14c
  kthread+0x112
  ret_from_fork+0x22
================================================================================
```

### Diagnosing High Latency

**Symptom**: High enqueue → receive latency (> 1ms)

**Possible causes**:

1. **ksoftirqd scheduling delay**
   - Stack trace shows `run_ksoftirqd`
   - Check CPU scheduler latency with `perf sched latency`
   - Solution: Adjust CPU affinity, increase ksoftirqd priority

2. **Cross-CPU migration overhead**
   - High "Cross-CPU migrations" counter
   - RPS hash may be suboptimal
   - Solution: Tune RPS configuration or disable RPS

3. **Queue depth buildup**
   - High queue depth values in events
   - Softirq processing slower than packet arrival
   - Solution: Increase `net.core.netdev_budget`, check for CPU saturation

4. **CPU contention**
   - High scheduling delays across all CPUs
   - Solution: Reduce overall system load, isolate CPUs for network processing

---

## Debug Mode

Enable debug mode to diagnose why packets aren't being captured:

```bash
sudo ./enqueue_to_iprec_latency.py \
    --interface enp24s0f0np0 \
    --protocol tcp \
    --interval 5 \
    --debug
```

**Debug output shows**:
```
================================================================================
DEBUG STATISTICS (Stage Execution Flow)
================================================================================

STAGE1_enqueue_to_backlog:
  PROBE_ENTRY              : 25678
  HANDLE_ENTRY             : 25678
  PARSE_ENTRY              : 25678
  PARSE_SUCCESS            : 15234
  IP_FILTER                : 8234    ← Packets filtered by IP
  PORT_FILTER              : 2210    ← Packets filtered by port
  FLOW_CREATE              : 15234

STAGE2___netif_receive_skb:
  PROBE_ENTRY              : 45678
  HANDLE_ENTRY             : 25678   ← 20000 packets wrong interface
  PARSE_ENTRY              : 25678
  PARSE_SUCCESS            : 15234
  FLOW_LOOKUP              : 15234
  FLOW_FOUND               : 15234
  LATENCY_SUBMIT           : 15234
```

**Interpretation**:
- If `PROBE_ENTRY` is 0: kprobe not attached correctly
- If `HANDLE_ENTRY` < `PROBE_ENTRY`: Interface filter working
- If `PARSE_SUCCESS` < `PARSE_ENTRY`: IP/port filters working
- If `FLOW_FOUND` < `FLOW_LOOKUP`: Packets missing flow state (indicates tool issue)

---

## Common Issues

### Issue 1: No packets captured

**Symptoms**: All counters are 0

**Possible causes**:
1. Wrong interface name: Check with `ip link show`
2. No matching traffic: Verify with `tcpdump -i <interface> -c 10`
3. RPS disabled on physical NIC: No packets going through `enqueue_to_backlog`

**Solution**:
```bash
# Verify interface exists
ip link show enp24s0f0np0

# Check for traffic
sudo tcpdump -i enp24s0f0np0 -c 10 port 2181

# For physical NIC without RPS, monitor internal port instead
sudo ./enqueue_to_iprec_latency.py --interface br-int --protocol tcp
```

### Issue 2: High flow lookup failures

**Symptoms**: `Flow lookup failures` counter is high

**Possible causes**:
1. RPS disabled: Physical NIC packets bypass `enqueue_to_backlog`
2. Interface changes mid-path (shouldn't happen with single interface mode)

**Solution**: Use `--debug` to see where packets are being lost

### Issue 3: Only seeing one stage

**Symptoms**: Packets counted in Stage 1 but not Stage 2

**Possible causes**:
1. Packets dropped between stages
2. Wrong interface specified (e.g., monitoring physical NIC but packets go to internal port)

**Solution**:
```bash
# Check for packet drops
cat /proc/net/softnet_stat

# Try monitoring internal port instead
sudo ./enqueue_to_iprec_latency.py --interface br-int
```

---

## Performance Considerations

### Overhead

- **Histogram mode**: Low overhead, ~1-2% CPU per 1000 pps
- **Threshold mode**: Higher overhead when stack traces captured, ~5-10% CPU per event

### Recommendations

1. **Production monitoring**: Use histogram mode with 5-60s intervals
2. **Troubleshooting**: Use threshold mode with high threshold (> 1ms) to avoid spam
3. **Heavy traffic**: Apply IP/port filters to reduce BPF map pressure

### Map Sizes

Default settings:
- Flow sessions: 10,240 entries (LRU hash)
- Stack traces: 1,024 entries (threshold mode only)

High-throughput environments may need larger maps. Edit the BPF code:
```c
BPF_TABLE("lru_hash", struct packet_key_t, struct flow_data_t, flow_sessions, 102400);
```

---

## Related Tools

- `ksoftirqd_sched_latency.py`: Measures ksoftirqd scheduling delays
- `system_network_perfomance_metrics.py`: End-to-end RX path measurement
- `kernel_drop_stack_stats_summary.py`: Packet drop analysis

---

## Summary

These tools provide precise measurement of the critical async boundary in Linux network stack. Use them to:

1. **Identify bottlenecks**: Quantify softirq scheduling delays
2. **Validate tuning**: Measure impact of RPS, CPU affinity, priority changes
3. **Root cause analysis**: Capture stack traces during high-latency events
4. **Capacity planning**: Understand packet processing behavior under load

**Remember**: Monitor each interface independently. In OVS environments, packets traverse multiple interfaces, each with its own enqueue→receive cycle.
