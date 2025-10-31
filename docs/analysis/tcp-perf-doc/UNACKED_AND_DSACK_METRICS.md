# unacked, retrans, and dsack_dups Metrics Explained

## Overview

These three metrics appear together in ss output and provide detailed information about TCP transmission state and duplicate acknowledgments:

```
unacked:675 retrans:0/27758 dsack_dups:9
```

---

## 1. unacked - Unacknowledged Segments

### What is unacked?

`unacked` represents the **number of data segments that have been sent but not yet acknowledged** by the receiver.

### Source in Linux Kernel

**Location**: `include/linux/tcp.h` and `net/ipv4/tcp_output.c`

```c
// From include/linux/tcp.h
struct tcp_sock {
    u32 packets_out;  // Segments in flight (unacked + retransmitted)
    u32 sacked_out;   // SACKed segments
    u32 lost_out;     // Lost segments
    u32 retrans_out;  // Retransmitted segments currently in flight
    // ...
};

// Calculation of unacked:
// unacked = packets_out - sacked_out - lost_out - retrans_out
```

### What Does unacked Mean?

**Value**: Number of segments waiting for ACK

```
unacked:675
→ 675 data segments have been sent but not yet acknowledged
→ These are "in flight" on the network
```

### Normal vs Problematic Values

```
Small unacked (< 10):
- Low throughput
- Network has capacity but sender not utilizing it
- May indicate:
  • Application not sending fast enough
  • Small congestion window (cwnd)
  • Receive window (rwnd) limiting

Moderate unacked (10-100):
- Normal for active connections
- Good pipeline utilization
- Healthy data flow

Large unacked (> cwnd):
- Should NOT exceed cwnd!
- If unacked > cwnd: KERNEL BUG or measurement timing issue

Large unacked (close to cwnd):
- Sender is cwnd-limited
- Network capacity fully utilized
- Normal for bulk transfers
```

### Relationship with cwnd

**Important constraint**: `unacked ≤ cwnd` (always!)

```
Example 1: Sender Not Fully Utilizing
cwnd: 100
unacked: 20
→ Can send 80 more segments
→ Application-limited or not enough data

Example 2: Sender Fully Utilizing (cwnd-limited)
cwnd: 100
unacked: 98
→ Can only send 2 more segments
→ Cwnd is the bottleneck

Example 3: Your Case
cwnd: (unknown, but likely large)
unacked: 675
→ 675 segments in flight
→ Waiting for ACKs to come back
```

### Calculating In-Flight Bytes

```
unacked: 675 segments
mss: 1448 bytes

In-flight data = 675 × 1448 = 977,400 bytes ≈ 955 KB

If RTT = 1 ms:
  Max throughput = 955 KB / 0.001 s = 955 MB/s = 7.6 Gbps

This is the BDP being utilized!
```

---

## 2. retrans:0/27758 - Retransmission Statistics

### Format: retrans:X/Y

- **X** (first number): **Current unacked retransmissions**
  - Retransmitted segments that are still in flight (not yet re-ACKed)

- **Y** (second number): **Total retransmissions since connection start**
  - Cumulative count of all retransmissions on this connection

### Your Example: retrans:0/27758

```
retrans:0/27758

Current state:
- retrans: 0
  → No retransmitted segments currently in flight
  → All retransmissions have been successfully ACKed
  → Good sign!

Historical total:
- retrans_total: 27758
  → 27,758 segments have been retransmitted since connection started
  → This is cumulative over the connection lifetime
```

### Interpreting the Total Retransmissions

**Need context: Compare with segments sent**

If you have `segs_out` available:
```
segs_out: 1,000,000
retrans_total: 27,758

Retransmission ratio = 27,758 / 1,000,000 = 2.78%

Interpretation:
- 2.78% retransmission rate
- Acceptable: < 2% is good
- Borderline: 2-5% is marginal
- Poor: > 5% indicates network issues
```

**Your case appears to have ~2.8% retrans rate**, which is borderline acceptable but worth investigating.

### Why Retransmissions Happen

```
Common causes:
1. Packet loss (network congestion, buffer overflow)
2. Packet reordering (seen as loss by TCP)
3. Delayed ACKs causing timeout
4. Path MTU issues
5. Network equipment drops
```

### Current vs Total Retransmissions

```
Scenario 1: Active Retransmission
retrans:10/5000
→ 10 retransmitted segments currently unacked
→ Active packet loss or recovery in progress

Scenario 2: Recovered (Your Case)
retrans:0/27758
→ No current retransmissions
→ Past losses have been recovered
→ Connection is healthy now

Scenario 3: Chronic Issues
retrans:50/50000 (constantly > 0)
→ Persistent retransmissions
→ Ongoing packet loss
→ Network path has problems
```

---

## 3. dsack_dups:9 - Duplicate SACK (D-SACK)

### What is dsack_dups?

`dsack_dups` counts the number of **Duplicate SACK (D-SACK)** events detected on this connection.

### What is D-SACK?

**D-SACK** is a TCP extension (RFC 2883) that allows the receiver to report **duplicate data** it has received.

### Why Does Duplicate Data Occur?

**Scenario 1: Spurious Retransmission**
```
Sender                          Receiver
  |                                |
  |---- Packet 1 (seq=1000) ------>| ✓ Received
  |                                |
  |                (RTT delay)     |
  |                                |
  | (Timeout! Assumes lost)        |
  |---- Packet 1 RETRANS --------->| ✓ Received AGAIN (duplicate!)
  |                                |
  |<---- ACK with D-SACK ----------| Reports: "seq=1000 was duplicate"
  |                                |

Kernel counts: dsack_dups++
```

**Scenario 2: Network Duplication**
```
Sender                          Receiver
  |                                |
  |---- Packet 1 (seq=1000) ------>|
  |          |                     |
  |          |---> (Network duplicates packet)
  |          |                     |
  |          +-------------------->| ✓ Received DUPLICATE
  |                                |
  |<---- ACK with D-SACK ----------| Reports: "seq=1000 was duplicate"

Kernel counts: dsack_dups++
```

### Your Example: dsack_dups:9

```
dsack_dups:9

Interpretation:
- 9 times the receiver reported receiving duplicate data
- 9 instances of either:
  • Spurious retransmissions (false loss detection)
  • Network packet duplication
  • Reordering misinterpreted as loss
```

### Why D-SACK Matters

**1. Identifies Spurious Retransmissions**
```
Sender thinks packet was lost and retransmits
But receiver already had the original
D-SACK tells sender: "That was unnecessary!"

Causes of spurious retransmits:
- RTO too aggressive
- High RTT variance
- Delayed ACKs
- Network jitter
```

**2. Helps Kernel Learn**
```
When D-SACK is received:
- Kernel knows the retransmission was unnecessary
- Can adjust RTO (increase timeout)
- Can undo cwnd reduction (tcp_dsack_undo)
- Improves future behavior
```

**3. Detects Network Duplication**
```
If network equipment is duplicating packets:
- D-SACK will detect it
- May indicate:
  • Faulty switch/router
  • Layer 2 loops
  • Misconfigured bonding/teaming
```

### Analyzing dsack_dups Value

```
dsack_dups:0
→ No duplicate data detected
→ Clean transmission
→ Good sign

dsack_dups:9 (over 27,758 retransmissions)
→ 9 / 27,758 = 0.032%
→ Very low rate of spurious retransmissions
→ Acceptable
→ Most retransmissions were legitimate (real packet loss)

dsack_dups:1000 (over 2000 retransmissions)
→ 1000 / 2000 = 50%
→ Half of retransmissions were spurious!
→ CRITICAL: RTO too aggressive or high jitter
→ Need to tune RTO settings
```

---

## Combined Analysis: Your Metrics

```
unacked:675 retrans:0/27758 dsack_dups:9
```

### Complete Picture

**1. Current State: Healthy**
```
unacked:675
→ 675 segments in flight, waiting for ACKs
→ Active transmission with good pipeline utilization

retrans:0
→ No current retransmissions
→ All past losses have been recovered
→ Connection is clean right now
```

**2. Historical Issues: Moderate Packet Loss**
```
retrans_total:27758
→ 27,758 retransmissions since connection started

If segs_out ≈ 1,000,000 (estimated):
  Retrans ratio ≈ 2.8%

Interpretation:
- Moderate packet loss on this connection
- Acceptable but not ideal
- Worth investigating causes
```

**3. Spurious Retransmission: Very Low**
```
dsack_dups:9
→ Only 9 out of 27,758 retransmissions were spurious
→ 9 / 27,758 = 0.032%
→ Excellent! Almost all retransmissions were legitimate
→ RTO is well-tuned
```

### What This Tells Us

**Good News**:
1. ✅ Connection is actively transmitting (unacked:675)
2. ✅ No current retransmissions (retrans:0)
3. ✅ Very few spurious retransmits (dsack_dups:9)
4. ✅ RTO is well-calibrated

**Concerns**:
1. ⚠️ Historical retransmission rate ~2.8% (if estimated segs_out is correct)
2. ⚠️ Suggests moderate packet loss on network path
3. ⚠️ Should investigate:
   - Network path quality
   - Switch/router drops
   - Buffer overflows
   - Congestion

---

## Comparison Table

| Metric | Your Value | Meaning | Status |
|--------|-----------|---------|--------|
| **unacked** | 675 | Segments in flight | ✅ Normal (good pipeline) |
| **retrans (current)** | 0 | Current retransmits | ✅ Excellent (no ongoing loss) |
| **retrans_total** | 27758 | Historical retransmits | ⚠️ Moderate (~2.8% estimated) |
| **dsack_dups** | 9 | Spurious retransmits | ✅ Excellent (0.032%) |

---

## How These Metrics Relate to Each Other

### Relationship Diagram

```
Total Segments Sent (segs_out)
    ↓
  ┌─────────────────────────────┐
  │ Successfully delivered      │ Most segments
  │ on first try               │
  └─────────────────────────────┘
  ┌─────────────────────────────┐
  │ Retransmitted (retrans)     │ 27,758 segments
  │   ↓                         │
  │   ├─ Legitimate loss        │ 27,749 (99.97%)
  │   │   (packet really lost)  │
  │   │                         │
  │   └─ Spurious (dsack_dups)  │ 9 (0.03%)
  │       (false loss detection)│
  └─────────────────────────────┘

Currently in flight (unacked): 675
  ├─ Original transmissions: 675
  └─ Retransmissions: 0
```

### State Machine View

```
Segment Lifecycle:

1. [SENT] → segment transmitted
     ↓
     ├─→ [ACKED] → successful (most common)
     │
     └─→ [LOST or TIMEOUT] → retransmit needed
           ↓
           [RETRANSMITTED] (retrans_total++)
           ↓
           ├─→ [ACKED] → recovered
           │
           └─→ [D-SACK RECEIVED] (dsack_dups++)
                 → Was spurious! Original was already ACKed
```

---

## Kernel Data Structures

### Where These Values Come From

```c
// From include/linux/tcp.h
struct tcp_sock {
    // Segments in flight
    u32 packets_out;     // Total segments in flight
    u32 sacked_out;      // SACKed but not fully ACKed
    u32 lost_out;        // Considered lost
    u32 retrans_out;     // Retransmitted and still in flight

    // Retransmission counters
    u32 total_retrans;   // Total retransmissions (retrans_total)

    // D-SACK counters
    u32 dsack_dups;      // D-SACK duplicate reports

    // Derived:
    // unacked = packets_out - sacked_out - lost_out - retrans_out
};
```

### How ss Gets These Values

```c
// From iproute2: misc/ss.c
void tcp_stats_print(struct tcpstat *s)
{
    // Get from kernel via TCP_INFO sockopt
    struct tcp_info info;
    getsockopt(fd, SOL_TCP, TCP_INFO, &info, &len);

    // Calculate unacked
    unsigned int unacked = info.tcpi_unacked;
    printf("unacked:%u ", unacked);

    // Retransmissions
    printf("retrans:%u/%u ",
           info.tcpi_retrans,      // Current
           info.tcpi_total_retrans); // Total

    // D-SACK duplicates
    if (info.tcpi_dsack_dups)
        printf("dsack_dups:%u ", info.tcpi_dsack_dups);
}
```

---

## Recommendations for Your Connection

Based on `unacked:675 retrans:0/27758 dsack_dups:9`:

### 1. Monitor Retransmission Ratio

**Need to know**: What is `segs_out`?

```bash
# Get complete metrics including segs_out
ss -tinopm | grep "your connection"

# Calculate:
retrans_ratio = retrans_total / segs_out

If > 2%: Investigate packet loss
If > 5%: Serious network issues
```

### 2. Investigate Packet Loss Causes

Since you have ~2.8% retrans rate (estimated):

```bash
# Check NIC drops
ethtool -S <interface> | grep -E 'drop|error|miss'

# Check system-wide retrans breakdown
netstat -s | grep -iE 'retrans|loss|timeout'

# Check specific connection with your tool
python3 tcp_connection_analyzer.py --show-stats ...
```

### 3. Analyze Retransmission Types

From your system stats (already implemented):
```
fast_retransmits: X     → Network packet loss
tcp_loss_probes: Y      → Small window (rwnd/cwnd)
timeout_retrans: Z      → Severe loss or high RTT
```

### 4. Verify D-SACK is Working

Your `dsack_dups:9` is very low, which is good:
```
9 / 27758 = 0.032% spurious retransmission rate

This means:
✅ RTO is well-tuned
✅ Very few false positives
✅ D-SACK is working correctly
```

---

## Summary

| Metric | Value | Interpretation |
|--------|-------|----------------|
| **unacked:675** | 675 segments in flight | Normal, healthy transmission |
| **retrans:0** | No current retransmissions | Good, no ongoing loss |
| **retrans_total:27758** | Historical retransmissions | Moderate loss (~2.8%), investigate |
| **dsack_dups:9** | Spurious retransmits | Excellent (0.032%), RTO well-tuned |

**Overall Assessment**: Connection is currently healthy but has experienced moderate packet loss historically. Investigate network path quality to reduce the ~2.8% retransmission rate.
