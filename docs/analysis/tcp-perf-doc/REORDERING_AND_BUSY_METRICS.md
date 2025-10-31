# reordering and busy Metrics Explained

## 1. reordering - Packet Reordering Metric

### What is reordering?

`reordering` is a kernel metric that tracks the **maximum detected out-of-order distance** for packets on this TCP connection. It indicates how much packet reordering the network path has exhibited.

### Source in Linux Kernel

**Location**: `include/linux/tcp.h` and `net/ipv4/tcp_input.c`

```c
// From include/linux/tcp.h
struct tcp_sock {
    u8 reordering;  // Maximum reordering distance (in segments)
    // ...
};
```

**Initial Value**:
```c
// From net/ipv4/tcp_ipv4.c - tcp_v4_init_sock()
tp->reordering = sock_net(sk)->ipv4.sysctl_tcp_reordering;
// Default: 3 (from sysctl net.ipv4.tcp_reordering)
```

### How Reordering is Detected

**Scenario: Packets Arrive Out of Order**

```
Sender sends:
  Packet 1 (seq=1000)
  Packet 2 (seq=2000)
  Packet 3 (seq=3000)
  Packet 4 (seq=4000)

Receiver receives (out of order):
  Packet 1 (seq=1000)  ✓
  Packet 3 (seq=3000)  ← Gap! (Packet 2 missing)
  Packet 4 (seq=4000)  ← Another packet before Packet 2
  Packet 2 (seq=2000)  ← Arrives late

Kernel detects:
  - Packet 2 arrived AFTER Packets 3 and 4
  - Reordering distance: 2 packets
  - tp->reordering = max(tp->reordering, 2)
```

### Kernel Code for Reordering Detection

```c
// From net/ipv4/tcp_input.c - tcp_check_sack_reordering()
static void tcp_check_sack_reordering(struct sock *sk, const u32 low_seq,
                                       const u32 high_seq)
{
    struct tcp_sock *tp = tcp_sk(sk);
    const u32 mss = tcp_skb_mss(skb);
    u32 fack_count = 0;

    // Calculate how many packets were skipped
    fack_count = (high_seq - low_seq) / mss;

    // Update reordering metric if this is larger
    if (fack_count > tp->reordering) {
        tp->reordering = min(fack_count, 127);  // Max: 127

        // Also update system-wide reordering metric
        NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPRENORECOVERY);
    }
}
```

### What Does reordering Value Mean?

**Value**: Maximum number of packets that arrived out of order

```
reordering:3    (Default)
→ No significant reordering detected yet
→ Or max 3 packets arrived out of order

reordering:10
→ At some point, 10 packets arrived before an earlier packet
→ Moderate reordering on this path

reordering:50
→ Up to 50 packets arrived out of order
→ Severe reordering, likely due to:
  • Multi-path routing (ECMP)
  • Load balancing
  • Packet-level parallelism in network

reordering:127
→ Maximum value (kernel limit)
→ Extremely high reordering
```

### Real-World Example from ZooKeeper

From your environment (70.0.0.31 → 70.0.0.32):

```bash
$ sudo ss -tinopm '( src 70.0.0.31 and sport = :2181 )'
ESTAB  0  0  [::ffff:70.0.0.31]:2181  [::ffff:70.0.0.32]:41572
       ...
       reordering:9
       ...
```

**Interpretation**:
```
reordering:9
→ At some point in this connection's history:
  - 9 packets arrived before an earlier packet
  - This is MODERATE reordering

Possible causes:
  1. Multi-path between 70.0.0.31 and 70.0.0.32
  2. Switch/router load balancing per-packet
  3. Different RTTs on different paths
  4. Network equipment packet buffering
```

### Impact on TCP Performance

**Low Reordering (reordering:3-5)**:
```
Impact: Minimal
- TCP treats 3 duplicate ACKs as packet loss
- With reordering=3, false loss detection is rare
→ Normal performance
```

**Moderate Reordering (reordering:10-20)**:
```
Impact: May cause unnecessary retransmissions
- Packet arrives after 10 others
- Receiver sends duplicate ACKs
- Sender may think packet is lost
- Fast retransmit triggered unnecessarily
→ Wasted bandwidth, reduced throughput
```

**High Reordering (reordering:50+)**:
```
Impact: Severe performance degradation
- Frequent false loss detection
- Spurious retransmissions
- cwnd reduction (unnecessary)
- SACK overhead increases
→ Throughput can drop by 30-50%
```

### How Kernel Adapts to Reordering

**Dynamic Adjustment**:
```c
// Kernel uses reordering metric to adjust:

// 1. Duplicate ACK threshold for fast retransmit
if (dupacks >= tp->reordering) {
    // Trigger fast retransmit
}

// 2. Loss detection timeout
rto = srtt + 4 * rttvar + (tp->reordering * mss / rate);
```

**Example**:
```
Without reordering adaptation:
  dupacks_threshold = 3
  Packet reordered by 5 → False fast retransmit!

With reordering adaptation:
  dupacks_threshold = max(3, tp->reordering) = 9
  Packet reordered by 5 → No false retransmit
  Only retransmit after 9 dupacks
```

### Checking System-Wide Reordering

```bash
# Default reordering threshold
$ sysctl net.ipv4.tcp_reordering
net.ipv4.tcp_reordering = 3

# System-wide reordering events (from netstat -s)
$ netstat -s | grep -i reorder
    5905118 detected reordering 127 times using SACK
    731823 detected reordering 127 times using time stamp

# Your tcp_connection_analyzer.py already captures these:
# - sack_reordering: 5,905,118
# - reordering_ts: 731,823
```

---

## 2. busy - Active Sending Time

### What is busy?

`busy` is a metric that tracks the **total time this connection has been actively sending data** (not idle). It's measured in milliseconds.

### Source in Linux Kernel

**Location**: `net/ipv4/tcp.c` and timing infrastructure

```c
// Kernel tracks cumulative time spent in different states
struct tcp_sock {
    u64 tcp_mstamp;       // Current timestamp
    u32 chrono_start;     // Start time of current chronograph
    u32 chrono_stat[3];   // Time spent in each state
};

// States:
enum tcp_chrono {
    TCP_CHRONO_UNSPEC = 0,
    TCP_CHRONO_BUSY,      // Actively sending
    TCP_CHRONO_RWND_LIMITED,  // Limited by receive window
    TCP_CHRONO_SNDBUF_LIMITED, // Limited by send buffer
};
```

### How busy is Calculated

**Kernel Chronograph System**:

```c
// From net/ipv4/tcp_output.c - tcp_chrono_start()
static void tcp_chrono_start(struct sock *sk, enum tcp_chrono type)
{
    struct tcp_sock *tp = tcp_sk(sk);
    u32 now = tcp_jiffies32;

    // Stop previous chronograph
    if (tp->chrono_type > TCP_CHRONO_UNSPEC)
        tcp_chrono_stop(sk, tp->chrono_type);

    // Start new chronograph
    tp->chrono_type = type;
    tp->chrono_start = now;
}

// From net/ipv4/tcp_output.c - tcp_chrono_stop()
static void tcp_chrono_stop(struct sock *sk, enum tcp_chrono type)
{
    struct tcp_sock *tp = tcp_sk(sk);
    u32 now = tcp_jiffies32;
    u32 delta = now - tp->chrono_start;

    // Accumulate time for this state
    tp->chrono_stat[type] += delta;
}
```

**When is Connection "BUSY"?**

```c
// Connection enters BUSY state when:
// 1. Has data to send
// 2. cwnd allows sending
// 3. rwnd allows sending
// 4. Actually transmitting packets

// Kernel starts BUSY chronograph:
if (tcp_send_head(sk) != NULL &&     // Has data to send
    cwnd_allows_sending &&           // cwnd not limiting
    rwnd_allows_sending) {           // rwnd not limiting
    tcp_chrono_start(sk, TCP_CHRONO_BUSY);
}
```

### What Does busy Value Mean?

**Value**: Total milliseconds spent actively sending data

```
busy:10ms
→ Connection has actively sent data for 10ms total
→ Rest of the time: idle or limited by windows

busy:5000ms (5 seconds)
→ Connection actively sent data for 5 seconds
→ High utilization (if connection age is ~5 seconds)

busy:100ms out of 60000ms connection age
→ Only 0.17% utilization
→ Mostly idle or limited
```

### Real-World Examples

#### Example 1: Bulk Data Transfer (iperf3)

```bash
$ ss -tinopm dst 1.1.1.3
ESTAB  0  0  1.1.1.2:5201  1.1.1.3:53730
       ...
       busy:10000ms rwnd_limited:500ms(5%) sndbuf_limited:200ms(2%)
       ...
```

**Interpretation**:
```
busy:10000ms (10 seconds)
rwnd_limited:500ms (5%)
sndbuf_limited:200ms (2%)

Total time breakdown:
- Actively sending: 10,000ms (93%)
- Rwnd limited: 500ms (5%)
- Sndbuf limited: 200ms (2%)
- Total: 10,700ms

Conclusion: High utilization, mostly busy sending
```

#### Example 2: Request-Response Pattern (ZooKeeper)

```bash
$ ss -tinopm '( src 70.0.0.31 and sport = :2181 )'
ESTAB  0  0  [::ffff:70.0.0.31]:2181  [::ffff:70.0.0.32]:41572
       ...
       busy:111073ms
       ...
```

**Interpretation**:
```
busy:111073ms (111 seconds)

If connection age is ~1 hour (3600 seconds):
  Utilization: 111 / 3600 = 3.1%

Conclusion: Low utilization, bursty traffic
- ZooKeeper sends responses in bursts
- Most of the time idle waiting for requests
- 3% busy time is NORMAL for request-response
```

#### Example 3: Idle Connection

```bash
$ ss -tinopm dst 192.168.1.100
ESTAB  0  0  192.168.1.50:22  192.168.1.100:54321
       ...
       busy:50ms
       ...
```

**Interpretation**:
```
busy:50ms

If connection age is 1 hour:
  Utilization: 50ms / 3600000ms = 0.0014%

Conclusion: Almost completely idle
- SSH connection with no activity
- Only brief bursts (50ms total)
```

### Relationship with Other Time Metrics

**busy + rwnd_limited + sndbuf_limited ≈ Total Active Time**

```
Connection Age: 10 seconds (10000ms)

Time Breakdown:
  busy:              9000ms (90%)
  rwnd_limited:       500ms (5%)
  sndbuf_limited:     300ms (3%)
  cwnd_limited:       200ms (2%)
  ────────────────────────────────
  Total active:     10000ms (100%)
  Idle time:            0ms (0%)

Interpretation:
- Connection fully utilized
- Mostly busy sending (90%)
- Occasionally limited by windows (10%)
```

**Example with Idle Time**:
```
Connection Age: 60 seconds (60000ms)

Time Breakdown:
  busy:               5000ms (8.3%)
  rwnd_limited:        500ms (0.8%)
  sndbuf_limited:      200ms (0.3%)
  ────────────────────────────────
  Total active:       5700ms (9.5%)
  Idle time:        54300ms (90.5%)

Interpretation:
- Connection mostly idle (90%)
- When active, mostly busy (8%)
- Low utilization, bursty traffic
```

### How to Use busy for Performance Analysis

#### Scenario 1: Distinguishing Network vs Application Bottleneck

**Case A: Network Bottleneck**
```
Connection age: 10 seconds
busy:           9500ms (95%)
send_rate:      100 Mbps
app_limited:    NO

Conclusion: Network-limited
- Connection is busy 95% of the time
- Network bandwidth is the bottleneck
- Application is keeping up
```

**Case B: Application Bottleneck**
```
Connection age: 10 seconds
busy:           500ms (5%)
send_rate:      100 Mbps
app_limited:    YES
lastsnd:        5000ms

Conclusion: Application-limited
- Connection only busy 5% of the time
- Application not providing data (lastsnd=5s)
- Network has capacity, but app can't use it
```

#### Scenario 2: Understanding Throughput

```
Connection age: 60 seconds
busy:           30000ms (50%)
bytes_sent:     1.5 GB
send_rate:      200 Mbps

Calculation:
  Average throughput = 1.5 GB / 60s = 200 Mbps
  Active throughput = 1.5 GB / 30s = 400 Mbps

Interpretation:
- When busy, achieves 400 Mbps
- But only busy 50% of the time
- Average throughput: 200 Mbps
→ Bursty traffic pattern, not a bottleneck
```

#### Scenario 3: Detecting Window Limitations

```
Connection age: 10 seconds
busy:           2000ms (20%)
rwnd_limited:   7000ms (70%)
sndbuf_limited: 500ms (5%)
cwnd_limited:   500ms (5%)

Interpretation:
- Only busy 20% of the time
- Mostly rwnd-limited (70%)
→ Receiver window is the bottleneck
→ Action: Increase receive buffer on receiver
```

### Comparison with lastsnd

**Difference**:

| Metric | Meaning | Use Case |
|--------|---------|----------|
| **busy** | Cumulative time actively sending | Long-term utilization analysis |
| **lastsnd** | Time since last send | Immediate state detection |

**Example**:
```
Connection age: 60 seconds
busy:           30000ms (50% utilization over 60s)
lastsnd:        5000ms (last sent 5 seconds ago)

Interpretation:
- Historically: 50% busy (good utilization)
- Currently: Idle for 5 seconds (current idle)
→ Bursty pattern: active periods + idle periods
```

### Viewing in ss Output

```bash
$ ss -tinopm state established
ESTAB  0  0  10.0.0.1:5201  10.0.0.2:53730
       ...
       busy:10000ms rwnd_limited:500ms(4.8%) sndbuf_limited:200ms(1.9%)
       ...
```

**Reading**:
```
busy:10000ms
  → Spent 10 seconds actively sending

rwnd_limited:500ms(4.8%)
  → Spent 500ms limited by receive window
  → 4.8% of total busy time

sndbuf_limited:200ms(1.9%)
  → Spent 200ms limited by send buffer
  → 1.9% of total busy time
```

### Summary Table

| Metric | Type | Meaning | Units | Use Case |
|--------|------|---------|-------|----------|
| **reordering** | Per-connection state | Max out-of-order distance detected | Packets | Diagnose packet reordering issues |
| **busy** | Cumulative time | Total time actively sending data | Milliseconds | Calculate utilization, distinguish busy vs idle |

### Practical Example: Your ZooKeeper Connection

```
Connection: 70.0.0.31:2181 → 70.0.0.32:41572
reordering: 9
busy: 111073ms

Interpretation:
1. reordering:9
   - Moderate packet reordering on this path
   - Network may use multi-path routing
   - Not severe (< 20), acceptable

2. busy:111073ms (111 seconds)
   - If connection age ≈ 1 hour:
     Utilization = 111 / 3600 = 3%
   - ZooKeeper typical pattern: request-response
   - 3% busy is NORMAL for this workload
   - Most time spent waiting for requests

Conclusion: Both metrics are NORMAL for this use case
```

### Current Code Coverage

**From tcp_connection_analyzer.py**:

```python
# Line 513-516: Already parsing busy!
match = re.search(r'busy:(\d+)ms', line)
if match:
    conn.busy_time = int(match.group(1))
```

✅ **busy**: Already parsed
❌ **reordering**: NOT parsed (but should be added)

### Recommended Addition

**Add reordering to TCPConnectionInfo** (line 67-68):

```python
# Congestion control
self.cwnd = 0
self.ssthresh = 0
self.ca_state = ""
self.reordering = 0  # NEW: Add this line
```

**Add reordering parsing** (after line 550):

```python
# Reordering: reordering:56
match = re.search(r'reordering:(\d+)', line)
if match:
    conn.reordering = int(match.group(1))
```

This would give complete visibility into packet reordering issues.
