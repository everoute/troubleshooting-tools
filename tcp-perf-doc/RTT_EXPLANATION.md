# RTT and RTTvar Explanation in TCP Connection Analyzer

## Overview

The TCP Connection Analyzer displays `rtt` and `rttvar` metrics for both client-side and server-side connections. This document explains what these metrics represent, how they are measured, and what they mean in different contexts.

## Data Source

### Source Chain
```
Linux Kernel TCP Stack
    ↓
Per-connection TCP control block (struct tcp_sock)
    ↓
ss command (iproute2 tool)
    ↓
tcp_connection_analyzer.py parsing
    ↓
Display output
```

### Parsing Code
```python
# From tcp_connection_analyzer.py line 436-440
# RTT: rtt:0.078/0.036
match = re.search(r'rtt:([\d.]+)/([\d.]+)', line)
if match:
    conn.rtt = float(match.group(1))      # Smoothed RTT
    conn.rttvar = float(match.group(2))   # RTT variance
```

### ss Command Output Format
```bash
$ ss -tinopm state established '( src 70.0.0.31 and sport = :2181 )'
ESTAB  0  0  ::ffff:70.0.0.31:2181  ::ffff:70.0.0.31:43960
         cubic rto:201 rtt:0.098/0.009 ato:40 mss:1448 pmtu:65535 rcvmss:1448
         advmss:65483 cwnd:10 ssthresh:768 bytes_sent:189 bytes_acked:190
```

In the format `rtt:0.098/0.009`:
- `0.098` = Smoothed RTT (SRTT) in milliseconds
- `0.009` = RTT variance (RTTVAR) in milliseconds

## RTT Metrics Definitions

### 1. RTT (Round-Trip Time)
**Full name**: Smoothed Round-Trip Time (SRTT)

**Definition**: The exponentially weighted moving average (EWMA) of measured round-trip times for this TCP connection.

**Formula** (from RFC 6298):
```
SRTT = (1 - α) × SRTT + α × RTT_sample
where α = 1/8 = 0.125
```

**Kernel Implementation** (net/ipv4/tcp_input.c):
```c
// Simplified from tcp_rtt_estimator()
tp->srtt_us = srtt + (rtt_sample - (srtt >> 3));  // EWMA with α = 1/8
```

**Meaning**:
- Represents the **expected** round-trip time for this connection
- Updated each time an ACK is received
- Smoothed to reduce impact of individual outliers
- Used to calculate RTO (Retransmission Timeout)

### 2. RTTvar (RTT Variance)
**Full name**: Round-Trip Time Variation

**Definition**: The mean deviation of RTT samples, measuring how much RTT fluctuates.

**Formula** (from RFC 6298):
```
RTTVAR = (1 - β) × RTTVAR + β × |SRTT - RTT_sample|
where β = 1/4 = 0.25
```

**Kernel Implementation** (net/ipv4/tcp_input.c):
```c
// Simplified from tcp_rtt_estimator()
tp->mdev_us = mdev + (abs(rtt_sample - srtt) - (mdev >> 2));  // EWMA with β = 1/4
```

**Meaning**:
- Measures the **variability** or **jitter** in round-trip times
- Higher RTTvar indicates unstable network path
- Used to calculate RTO with safety margin: `RTO = SRTT + 4 × RTTVAR`

## Client vs Server Side

### Important: RTT is Bidirectional but Context-Dependent

**Key Insight**: RTT measures the time from **sending data** to **receiving its ACK**. The "direction" depends on which side is actively sending data.

### Client-Side RTT (Data Sender)

When the **client sends data to server**:

```
Client                                    Server
  |                                          |
  |------- Data packet (seq=X) ------------>|
  |                                          | [Process]
  |<------- ACK (ack=X+1) -------------------|
  |                                          |
  └─── RTT measurement ──────────────────────┘
```

**RTT Components** (for client-side data transmission):
```
RTT = T_client_tx + T_network_to_server + T_server_process + T_network_to_client + T_client_rx
    = Network delay (both directions) + Server processing time
```

**Example Output** (Client sending to remote server):
```
Connection: 70.0.0.31:45678 -> 70.0.0.32:5201
rtt: 15.234 ms    # Time from sending data to receiving ACK
rttvar: 2.156 ms  # Variation in these measurements
```

**Interpretation**:
- **rtt = 15.234 ms**: Average time for data to reach server and ACK to return
- **rttvar = 2.156 ms**: ACK timing varies by ~2.1 ms (network jitter)
- **High RTT**: Indicates either network latency or server processing delay
- **High RTTvar**: Indicates network congestion, variable queuing, or inconsistent server response

### Server-Side RTT (ACK Sender)

When the **server sends data to client** (or ACKs client data):

```
Server                                    Client
  |                                          |
  |------- Data/ACK packet (seq=Y) -------->|
  |                                          | [Process]
  |<------- ACK (ack=Y+1) -------------------|
  |                                          |
  └─── RTT measurement ──────────────────────┘
```

**Example Output** (Server receiving from local client):
```
Connection: ::ffff:70.0.0.31:2181 -> ::ffff:70.0.0.31:43960
rtt: 0.098 ms     # Time from sending ACK to receiving next data
rttvar: 0.009 ms  # Variation in these measurements
```

**Interpretation**:
- **rtt = 0.098 ms**: Very low RTT (local connection, ~98 microseconds)
- **rttvar = 0.009 ms**: Very stable (9 microseconds variation)
- **Low values**: Indicate local communication (same host or same datacenter)
- **Server RTT**: Typically measures time for client to process and send next request

### Special Case: Passive Server (Request-Response Pattern)

In typical request-response protocols (HTTP, ZooKeeper, database queries):

**Server perspective**:
- Server mostly **receives** requests and **sends** responses
- Server's RTT measurement is based on ACKs from client acknowledging server's response
- **BUT**: In many cases, the client doesn't send immediate data after ACK
- So server RTT often reflects: "How long for client to ACK my response?"

**Your Test Case** (ZooKeeper on port 2181):
```
Server: ::ffff:70.0.0.31:2181 -> ::ffff:70.0.0.31:43960
rtt: 0.098 ms
```

**What this measures**:
1. Server sends response to client
2. Client sends ACK back
3. RTT = time between (1) and (2)
4. Very fast (0.098 ms) because it's local loopback connection

**Why RTTvar is so small** (0.009 ms):
- Loopback has very stable latency
- No physical network variability
- No queuing delays

## How Kernel Measures RTT

### Measurement Points

The Linux kernel measures RTT using **TCP timestamps** or **ACK sequence matching**:

#### Method 1: TCP Timestamps (RFC 7323)
```c
// When sending packet
tcp_header->tsval = current_time();

// When receiving ACK
RTT_sample = current_time() - tcp_header->tsecr;
```

#### Method 2: Sequence Number Matching
```c
// Track when each segment was sent
sent_time[seq_num] = current_time();

// When ACK received
RTT_sample = current_time() - sent_time[ack_seq];
```

### Kernel Code Path

**Location**: `net/ipv4/tcp_input.c`

**Key Functions**:
1. `tcp_ack()` - Called when ACK received
2. `tcp_clean_rtx_queue()` - Process ACKed data
3. `tcp_rtt_estimator()` - Update SRTT and RTTVAR

**Simplified Code**:
```c
// From tcp_rtt_estimator() in net/ipv4/tcp_input.c
static void tcp_rtt_estimator(struct sock *sk, long mrtt_us)
{
    struct tcp_sock *tp = tcp_sk(sk);
    long m = mrtt_us;  // Measured RTT sample

    if (tp->srtt_us != 0) {
        // Update SRTT using EWMA (α = 1/8)
        m -= (tp->srtt_us >> 3);
        tp->srtt_us += m;

        // Update RTTVAR using EWMA (β = 1/4)
        if (m < 0) {
            m = -m;
            m -= (tp->mdev_us >> 2);
            if (m > 0)
                m >>= 3;
        } else {
            m -= (tp->mdev_us >> 2);
        }
        tp->mdev_us += m;
    } else {
        // First measurement
        tp->srtt_us = m << 3;
        tp->mdev_us = m << 1;
    }
}
```

## Relationship with RTO (Retransmission Timeout)

**RTO Calculation** (from RFC 6298):
```
RTO = SRTT + max(G, 4 × RTTVAR)
where G = clock granularity (typically 1ms)
```

**Kernel Implementation**:
```c
// From tcp_set_rto() in net/ipv4/tcp_input.c
inet_csk(sk)->icsk_rto = tcp_rto_min(sk) +
    ((tp->srtt_us >> 3) + tp->mdev_us);  // SRTT + 4×RTTVAR
```

**Example**:
```
SRTT = 0.098 ms = 98 µs
RTTVAR = 0.009 ms = 9 µs
RTO = 0.098 + 4 × 0.009 = 0.098 + 0.036 = 0.134 ms (minimum: 200 ms)
```

**Note**: Linux enforces minimum RTO of 200ms (HZ-dependent).

## Practical Interpretation

### Example 1: Local Connection (Your Test Case)
```
Connection: ::ffff:70.0.0.31:2181 -> ::ffff:70.0.0.31:43960 (Server side)
rtt: 0.098 ms
rttvar: 0.009 ms
```

**Analysis**:
- **RTT 0.098 ms**: Loopback connection, very fast
- **RTTvar 0.009 ms**: Very stable, <10% variation
- **Conclusion**: Healthy local communication, no network issues

### Example 2: Cross-Datacenter Connection
```
Connection: 10.0.0.31:45678 -> 10.1.0.32:5201 (Client side)
rtt: 15.234 ms
rttvar: 2.156 ms
```

**Analysis**:
- **RTT 15.234 ms**: Typical cross-datacenter latency
- **RTTvar 2.156 ms**: ~14% variation, moderate jitter
- **Conclusion**: Normal for cross-datacenter, monitor if RTTvar increases

### Example 3: Congested Path
```
Connection: 192.168.1.10:45678 -> 8.8.8.8:443 (Client side)
rtt: 45.678 ms
rttvar: 12.456 ms
```

**Analysis**:
- **RTT 45.678 ms**: Higher than expected
- **RTTvar 12.456 ms**: High variation (~27%), indicates instability
- **Conclusion**: Network congestion or path instability

### Example 4: High Jitter
```
Connection: 172.16.0.10:5000 -> 172.16.0.20:8080 (Client side)
rtt: 2.345 ms
rttvar: 1.876 ms
```

**Analysis**:
- **RTT 2.345 ms**: Reasonable for LAN
- **RTTvar 1.876 ms**: Very high relative to RTT (80%!)
- **Conclusion**: Severe jitter, check for:
  - Network congestion
  - CPU throttling on endpoints
  - Virtual machine CPU steal time
  - Network equipment issues

## Common Questions

### Q1: Why is server-side RTT so low in your test?

**A**: Because it's a **loopback connection** (same host):
```
::ffff:70.0.0.31:2181 -> ::ffff:70.0.0.31:43960
              ^                     ^
         Same IP address (loopback)
```

Loopback RTT is typically < 0.1 ms because:
- No physical network traversal
- No network card processing
- Only kernel memory copy
- No queuing delays

### Q2: Do client and server measure the same RTT?

**A**: **Not exactly**, because:

1. **Different data directions**: Client measures data → ACK, server measures response → ACK
2. **Different traffic patterns**: Client sends requests, server sends responses
3. **Asymmetric paths**: Network path A→B may differ from B→A in latency
4. **Different measurement timing**: Depends on when each side sends data

**However**, in a stable bidirectional connection with similar traffic in both directions, RTT should be similar.

### Q3: What does high RTTvar indicate?

**A**: High RTTvar (relative to RTT) indicates:

1. **Network Congestion**: Variable queuing delays
2. **Path Changes**: Route flapping or load balancing across paths
3. **CPU Overload**: Inconsistent processing time on endpoints
4. **Virtualization Issues**: CPU steal time in VMs
5. **Interrupt Coalescing**: Batching causes timing variation

**Rule of thumb**:
- RTTvar < 10% of RTT: Excellent stability
- RTTvar 10-20% of RTT: Normal
- RTTvar 20-50% of RTT: Concerning, investigate
- RTTvar > 50% of RTT: Critical, severe instability

### Q4: Why does RTO in ss output (201ms) not match the formula?

**A**: Linux enforces minimum RTO:

```c
// From include/net/tcp.h
#define TCP_RTO_MIN ((unsigned)(HZ/5))  // 200ms on HZ=1000
#define TCP_RTO_MAX ((unsigned)(120*HZ))  // 120 seconds
```

Even if calculated RTO is lower (e.g., 0.134 ms), Linux uses minimum 200 ms to avoid spurious retransmissions.

## Viewing Raw ss Output

To see the raw data that tcp_connection_analyzer.py parses:

```bash
# Server side
sudo ss -tinopm state established '( src 70.0.0.31 and sport = :2181 )'

# Client side
sudo ss -tinopm state established '( dst 70.0.0.32 and dport = :5201 )'

# Continuous monitoring
watch -n 1 'sudo ss -tinopm state established "( src 70.0.0.31 and sport = :2181 )"'
```

## Summary Table

| Metric | Definition | Typical Values | High Value Indicates |
|--------|-----------|----------------|---------------------|
| **RTT** | Smoothed round-trip time | LAN: < 1ms<br>DC: 1-10ms<br>WAN: 10-100ms | Network latency or processing delay |
| **RTTvar** | RTT variation (jitter) | < 10% of RTT | Network instability, congestion, or CPU issues |
| **RTO** | Retransmission timeout | ≥ 200ms (Linux min) | SRTT + 4×RTTvar (with minimum) |

## References

- RFC 6298: Computing TCP's Retransmission Timer
- RFC 7323: TCP Extensions for High Performance (Timestamps)
- Linux Kernel Source: `net/ipv4/tcp_input.c` (tcp_rtt_estimator)
- iproute2 Source: `misc/ss.c` (ss command implementation)
