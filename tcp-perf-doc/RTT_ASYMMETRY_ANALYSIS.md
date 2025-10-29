# RTT Asymmetry Analysis: Why Server-Side RTT is Much Higher Than Client-Side

## Observation

From the test results between 1.1.1.2 (iperf3 client) and 1.1.1.3 (iperf3 server):

### Server-Side View (1.1.1.2:5201 -> 1.1.1.3:53730)
```
Connection: ::ffff:1.1.1.2:5201 -> ::ffff:1.1.1.3:53730
State: ESTAB

Metrics:
  recv_q                   : 122064        # 122 KB backlog!
  send_q                   : 0
  rtt                      : 5.422 ms      # HIGH RTT
  rttvar                   : 10.612 ms     # VERY HIGH variance (195% of RTT!)
  cwnd                     : 10            # Small congestion window
  ssthresh                 : 46
  rcv_space                : 14600 bytes (14.3 KB)
  send_rate                : 0.02 Gbps    # Very low send rate
  pacing_rate              : 0.04 Gbps
  delivery_rate            : 0.34 Gbps
  retrans                  : 0/0
  bdp                      : 16943750 bytes (16546.6 KB)   # 16 MB BDP!
  recommended_window       : 67775000 bytes (66186.5 KB)   # 66 MB recommended!
```

### Client-Side View (1.1.1.3:53728 -> 1.1.1.2:5201)
```
Connection: 1.1.1.3:53728 -> 1.1.1.2:5201
State: ESTAB

Metrics:
  recv_q                   : 0             # No backlog
  send_q                   : 0
  rtt                      : 0.167 ms      # LOW RTT (32x lower!)
  rttvar                   : 0.021 ms      # Low variance (12.6% of RTT)
  cwnd                     : 4067          # Large congestion window
  ssthresh                 : 3449
  rcv_space                : 14480 bytes (14.1 KB)
  send_rate                : 282.11 Gbps  # Very high send rate
  pacing_rate              : 3.25 Gbps
  delivery_rate            : 19.07 Gbps
  retrans                  : 0/26         # 26 total retransmissions
  bdp                      : 521875 bytes (509.6 KB)     # 509 KB BDP
  recommended_window       : 2087500 bytes (2038.6 KB)   # 2 MB recommended
```

## Key Differences Summary

| Metric | Server Side (1.1.1.2) | Client Side (1.1.1.3) | Ratio |
|--------|----------------------|----------------------|-------|
| **RTT** | 5.422 ms | 0.167 ms | **32.5x** |
| **RTTvar** | 10.612 ms | 0.021 ms | **505x** |
| **recv_q** | 122064 bytes | 0 bytes | **∞** |
| **cwnd** | 10 | 4067 | **1/407** |
| **send_rate** | 0.02 Gbps | 282.11 Gbps | **1/14,105** |
| **BDP** | 16.9 MB | 509 KB | **32x** |

## Root Cause Analysis

### 1. **Application-Level Processing Delay (Primary Cause)**

**The Critical Clue**: `recv_q: 122064` on server side

```
Server Side (iperf3 server):
  recv_q = 122 KB  <-- Data waiting in kernel buffer, app not reading fast enough!

Client Side (iperf3 client):
  recv_q = 0       <-- App consuming data immediately
```

**What This Means**:

The RTT measurement on the **server side** includes:
```
RTT_server = Network_Delay + Client_Processing_Time + Client_ACK_Delay

But Client_ACK_Delay is affected by:
- When client application reads data from receive buffer
- How quickly client sends ACK after receiving data
```

**Why recv_q Backlog Increases RTT**:

```
Server                                  Client
  |                                       |
  |---- Send Data (100 KB) ------------->| [Data arrives at kernel]
  |                                       | [App hasn't read yet, recv_q += 100KB]
  |                                       | [TCP stack delays ACK waiting for app]
  |                                       | [Eventually timeout, send delayed ACK]
  |<---- Delayed ACK (after 40-200ms) ---|
  |                                       |
  └─ RTT = Network + Delayed_ACK_Timer ──┘
         = 0.2ms + 5ms = 5.2ms
```

**Kernel Behavior**:
- Linux uses **delayed ACK** mechanism (TCP_QUICKACK disabled by default)
- ACK timer: typically 40ms default, can be up to 200ms
- If receiver buffer has space but **app isn't reading**, ACK is delayed
- This increases measured RTT on sender side

### 2. **Asymmetric Traffic Pattern (iperf3 Characteristic)**

**iperf3 Client → Server**:
- Client sends **continuous data stream** at high rate (282 Gbps send_rate)
- Server receives data but application may process slowly
- Server sends small ACKs back

**iperf3 Server → Client**:
- Server sends data at low rate (0.02 Gbps send_rate)
- Client receives and processes immediately
- Client sends ACKs quickly

**Traffic Direction**:
```
Client (1.1.1.3)  ----[High Volume Data]---->  Server (1.1.1.2)
                                                   ↓
                                            [recv_q backlog]
                                                   ↓
                  <----[Delayed ACKs]----------

RTT_measured_by_server = High (includes ACK delay)


Server (1.1.1.2)  ----[Low Volume Data]---->  Client (1.1.1.3)
                                                   ↓
                                            [No backlog, immediate ACK]
                  <----[Immediate ACKs]--------

RTT_measured_by_client = Low (no ACK delay)
```

### 3. **TCP Delayed ACK Algorithm**

**RFC 1122 Standard**:
- TCP receiver should not ACK every packet immediately
- Should wait for 2 packets or 40-200ms timeout
- Goal: Reduce ACK traffic overhead

**In Your Case**:

**Server receiving (from client 1.1.1.3)**:
```c
// Server-side TCP stack behavior
if (recv_q_backlog > 0 && app_not_reading) {
    // Delay ACK until:
    // 1. Received 2 full packets, OR
    // 2. Delayed ACK timer expires (40ms default)
    delay_ack_timer = 40ms;  // or up to 200ms
}
```

**Client receiving (from server 1.1.1.2)**:
```c
// Client-side TCP stack behavior
if (recv_q_empty && app_reading_fast) {
    // Send ACK immediately or after short delay
    delay_ack_timer = 1-10ms;  // Much shorter
}
```

### 4. **Congestion Window Impact**

**Server Side**: `cwnd: 10`
- Very small congestion window (likely 10 packets = 14.5 KB)
- Indicates TCP is in slow start or recovery
- Small cwnd → Send fewer packets → Wait longer for ACK

**Client Side**: `cwnd: 4067`
- Large congestion window (4067 packets ≈ 5.7 MB)
- Can send large bursts without waiting for ACK
- Large cwnd → Lower perceived RTT for measurement

**Why cwnd is Small on Server**:
```
Possible causes:
1. Packet loss in the past (retrans: 0/0 shows no current retrans, but ssthresh=46 suggests past loss)
2. Receiver window limitation (client's rcv_space = 14.1 KB is small)
3. Application-limited (server not pushing data fast)
```

### 5. **Receive Window Limitation**

Both sides have **very small** receive buffers:
```
Server: rcv_space = 14600 bytes (14.3 KB)
Client: rcv_space = 14480 bytes (14.1 KB)
```

**Impact on Client → Server Direction**:

When client sends to server at high rate:
```
Client sends burst → Server rcv_space fills quickly → Server advertises rwnd=0
→ Client must wait → Server delays ACK → High RTT measured by server
```

**Why This Affects Server-Side RTT More**:

Server is **receiving** high-rate traffic with small buffer:
- Buffer fills fast
- ACKs are delayed to manage flow control
- RTT measurement includes this delay

Client is **receiving** low-rate traffic:
- Buffer never fills
- ACKs sent promptly
- RTT remains low

### 6. **High RTT Variance on Server (10.612 ms)**

**Extremely High**: RTTvar = 10.612 ms, which is **195% of RTT (5.422 ms)**!

**This Indicates**:
- ACK timing is **highly variable**
- Sometimes ACKs come back quickly (< 1 ms)
- Sometimes ACKs are very delayed (> 15 ms)
- Suggests delayed ACK timer is inconsistently triggered

**Calculation Example**:
```
Sample 1: RTT = 0.5 ms   (fast ACK, no delay)
Sample 2: RTT = 12 ms    (delayed ACK timer fired)
Sample 3: RTT = 2 ms     (moderate delay)
Sample 4: RTT = 18 ms    (max delayed ACK)

SRTT (smoothed) = 5.4 ms
RTTVAR = 10.6 ms  (high variance due to mix of fast and delayed ACKs)
```

## Detailed Scenario Walkthrough

### Server-Side RTT Measurement (High RTT)

```
Timeline: Server (1.1.1.2) sending to Client (1.1.1.3)

T=0ms:    Server sends data packet (seq=1000, len=1448)
          [Packet has timestamp for RTT measurement]

T=0.2ms:  Packet arrives at client's NIC
          Client kernel receives packet
          Data copied to receive buffer (recv_q still = 0)

T=0.3ms:  Client TCP stack checks:
          - recv_q has space? Yes
          - App reading data? No (iperf3 client is busy sending data)
          - Should ACK now? No, wait for delayed ACK timer

T=40ms:   Delayed ACK timer fires on client
          Client sends ACK (ack=1001+1448)

T=40.2ms: Server receives ACK
          Server calculates: RTT = 40.2ms - 0ms = 40.2ms (for this sample)

T=40.2ms: Server updates SRTT and RTTVAR:
          SRTT = 7/8 × 5.422 + 1/8 × 40.2 = 9.2 ms
          RTTVAR increases due to variance
```

### Client-Side RTT Measurement (Low RTT)

```
Timeline: Client (1.1.1.3) sending to Server (1.1.1.2)

T=0ms:    Client sends data packet (seq=5000, len=1448)
          [Packet has timestamp for RTT measurement]

T=0.1ms:  Packet arrives at server's NIC
          Server kernel receives packet
          Data copied to receive buffer
          recv_q += 1448 (now 122064 + 1448)

T=0.12ms: Server TCP stack checks:
          - recv_q has data? Yes (122 KB waiting)
          - Need to ACK? Must ACK to manage flow control
          - Send ACK immediately to update window

T=0.15ms: Server sends ACK (ack=5001+1448)
          [ACK sent quickly because recv_q is non-empty, need to update rwnd]

T=0.25ms: Client receives ACK
          Client calculates: RTT = 0.25ms - 0ms = 0.25ms (for this sample)

T=0.25ms: Client updates SRTT:
          SRTT = 7/8 × 0.167 + 1/8 × 0.25 = 0.177 ms
```

**Key Difference**:
- Server-side: Client **delays** ACK by 40ms (delayed ACK timer)
- Client-side: Server sends ACK **immediately** (0.15ms) due to flow control needs

## Why Server recv_q Has Backlog

The 122 KB `recv_q` backlog on server indicates:

### Possible Causes:

1. **Application Not Reading Fast Enough**
   ```
   iperf3 server process:
   - Busy with other operations
   - Slow read() syscalls
   - Processing previous data
   ```

2. **CPU Contention**
   ```
   iperf3 server thread:
   - Waiting for CPU time
   - Preempted by other processes
   - Context switch delays
   ```

3. **Intentional by iperf3 Design**
   ```
   iperf3 may intentionally:
   - Read data in chunks
   - Batch processing
   - Not optimize for low latency
   ```

### Impact on RTT:

```
recv_q backlog → Application delay → ACK delay → High measured RTT

Server measures RTT including:
  Network_Delay (0.2ms) + Client_App_Delay (5ms) = 5.2ms total
```

## Verification Methods

### 1. Check Delayed ACK Settings

```bash
# On client side (1.1.1.3)
sysctl net.ipv4.tcp_delack_min
# Default: 40 (40ms)

# Check if quickack is enabled
ss -ti dst 1.1.1.2 and dport = :5201
# Look for 'quickack' flag
```

### 2. Monitor recv_q Over Time

```bash
# On server side (1.1.1.2)
watch -n 0.1 'ss -tm dst 1.1.1.3 and dport = :53730 | grep -E "recv_q|Recv-Q"'
```

### 3. Use tcpdump to Measure Actual Network RTT

```bash
# On server side, capture outgoing data and incoming ACK
sudo tcpdump -i any -nn -ttt 'host 1.1.1.3 and port 5201' > /tmp/server_tcpdump.txt

# Analyze timestamp differences between data packet and corresponding ACK
```

### 4. Enable TCP Timestamps and Analyze

```bash
# Ensure timestamps are enabled
sysctl net.ipv4.tcp_timestamps
# Should be: net.ipv4.tcp_timestamps = 1

# Use ss to see detailed timing
ss -tinopm dst 1.1.1.3 and dport = :53730
```

## Solutions to Reduce Server-Side RTT

### 1. Reduce Delayed ACK on Client Side

```bash
# On client (1.1.1.3), reduce delayed ACK timer
sudo sysctl -w net.ipv4.tcp_delack_min=10  # Reduce from 40ms to 10ms

# Or enable TCP_QUICKACK for specific connection (programmatic)
# In iperf3 or application code:
setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, (int[]){1}, sizeof(int));
```

**Expected Impact**: Client will ACK faster → Server-side RTT reduces

### 2. Increase Receive Buffer on Both Sides

```bash
# On both server and client
sudo sysctl -w net.core.rmem_max=134217728        # 128 MB
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"

# Restart iperf3 test
```

**Expected Impact**:
- Larger rcv_space (currently 14 KB → 128 MB)
- Reduced flow control delays
- Better handling of bursts

### 3. Optimize Application Reading Behavior

```bash
# On server side, ensure iperf3 is reading data frequently
# Check if iperf3 has options for:
# - Buffer size: -w, --window
# - Interval: -i
# - Parallel streams: -P

# Example: Use larger buffer and parallel streams
iperf3 -s -p 5201 -w 128M -i 0.1 -P 4
```

**Expected Impact**:
- Reduce recv_q backlog
- Faster application reads → Faster ACKs → Lower RTT

### 4. Disable Delayed ACK (Not Recommended for Production)

```bash
# On client (1.1.1.3), disable delayed ACK entirely
# Note: This increases ACK traffic significantly!

sudo sysctl -w net.ipv4.tcp_delack_min=0
```

**Trade-off**:
- ✅ Lower RTT
- ❌ Higher ACK traffic (2x overhead)
- ❌ Increased CPU usage

### 5. Tune Congestion Control

```bash
# Use BBR or other modern congestion control
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr

# BBR adapts better to delay and loss
```

## Real Network Delay vs Application Delay

To isolate **actual network delay** from **application delay**:

### Method 1: ICMP Ping

```bash
# From server to client
ping -c 100 1.1.1.3 -i 0.01

# Typical output:
# rtt min/avg/max/mdev = 0.150/0.180/0.250/0.020 ms
```

**Expected**: ICMP RTT should be close to client-side TCP RTT (0.167 ms)

### Method 2: TCP SYN-ACK RTT

During connection establishment, measure SYN → SYN-ACK time:

```bash
# Use hping3 to measure TCP handshake RTT
sudo hping3 -S -p 5201 1.1.1.3 -c 10

# This measures pure network delay without application layer
```

### Method 3: Compare with Kernel Metrics

```bash
# Check minimum RTT (minrtt) from ss output
ss -tinopm dst 1.1.1.3 and dport = :53730 | grep minrtt

# minrtt shows the lowest RTT ever observed
# This is closer to actual network delay
```

**Expected**: `minrtt` should be ~0.2 ms (actual network delay)

## Summary Table

| Factor | Impact on Server RTT | Impact on Client RTT | Explanation |
|--------|---------------------|---------------------|-------------|
| **Delayed ACK** | ✅ **HIGH** (40ms+) | ❌ Low (< 1ms) | Client delays ACK, server sends ACK quickly |
| **recv_q Backlog** | ✅ **HIGH** (causes delayed ACK) | ❌ None (recv_q=0) | Server has 122KB backlog, client has none |
| **Traffic Pattern** | ✅ **HIGH** (receiving bulk) | ❌ Low (receiving small) | Server receives high rate, client receives low rate |
| **Application Speed** | ✅ **HIGH** (iperf3 slow read) | ❌ Low (iperf3 fast read) | Server app not reading fast enough |
| **cwnd Size** | ❌ Low (cwnd=10, few pkts) | ✅ Moderate (cwnd=4067) | Small cwnd doesn't directly cause high RTT |
| **rcv_space** | ✅ Moderate (14KB too small) | ✅ Moderate (14KB too small) | Both sides have small buffers |
| **Network Delay** | ✅ Small (~0.2ms) | ✅ Small (~0.2ms) | Actual network delay is similar for both |

## Conclusion

**Primary Cause**: Server-side RTT (5.422 ms) is high because the **client is delaying ACKs** due to:

1. **Application not reading fast enough** (recv_q backlog on server means data is piling up)
2. **Delayed ACK mechanism** on client side (40ms timer)
3. **Asymmetric traffic pattern** (client sends bulk → server, server sends small → client)

**Client-side RTT (0.167 ms) is low** because:

1. **Server sends ACKs quickly** (no delayed ACK due to flow control needs)
2. **No recv_q backlog on client** (client application is reading fast)
3. **Server must ACK promptly** to update advertised receive window

**The RTT asymmetry is NOT due to**:
- Network path asymmetry (network delay is similar ~0.2ms)
- Different physical paths (same network segment)
- Packet loss (retrans are low on both sides)

**This is NORMAL behavior** for high-throughput unidirectional traffic patterns like iperf3.

## Recommendation

If you want to measure **pure network RTT**, use:
1. ICMP ping
2. TCP SYN-ACK timing during handshake
3. `minrtt` value from `ss` output (minimum RTT ever observed)
4. Monitor both directions and take the minimum

If you want to **reduce server-side measured RTT**:
1. Increase receive buffers on both sides
2. Reduce delayed ACK timer on client
3. Optimize application reading speed
4. Use TCP_QUICKACK socket option if latency-sensitive
