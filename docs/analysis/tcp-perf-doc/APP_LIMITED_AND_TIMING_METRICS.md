# app_limited and Timing Metrics Deep Dive

## 1. app_limited - Application Limited Flag

### What is app_limited?

`app_limited` is a **kernel flag** that indicates the TCP connection's throughput is limited by the **application** providing data too slowly, rather than by network capacity or congestion control.

### Source in Linux Kernel

**Location**: `include/linux/tcp.h` and `net/ipv4/tcp_output.c`

```c
// From include/linux/tcp.h
struct tcp_sock {
    // ... other fields ...

    u8 app_limited:1,  // Application is limiting the sending rate
       rate_app_limited:1;

    // ... other fields ...
};
```

**Set by kernel when**:
```c
// From net/ipv4/tcp_output.c - tcp_chrono_start()

// Kernel sets app_limited when:
if (tp->write_seq == tp->snd_nxt &&
    !tcp_send_head(sk) &&           // No data to send
    sk_under_memory_pressure(sk) == 0) {  // Not under memory pressure
    tp->app_limited = 1;
}
```

### When is app_limited Set?

**Condition 1: Send Buffer Empty**
```
Application → TCP Send Buffer → Network
              ↑
              Empty! (No data to send)

→ Kernel marks: app_limited = 1
```

**Condition 2: Socket Write Queue Empty**
```c
// Kernel checks:
if (tcp_send_head(sk) == NULL) {  // No pending data in send queue
    tp->app_limited = 1;
}
```

**Condition 3: Application Not Writing Fast Enough**
```
Time ─────────────────────────────────────>
         │                    │
    App writes 1KB       App writes 1KB again
         │                    │
         └──── 5 seconds ─────┘

Network could send 10 GB in 5 seconds
But app only provided 2 KB
→ app_limited = 1
```

### Real-World Example

**iperf3 Test**:
```bash
# Server side (receiving bulk data)
$ ss -tinopm dst 1.1.1.3 | grep app_limited
# No app_limited flag (server is receiving, not sending)

# Client side (sending bulk data)
$ ss -tinopm dst 1.1.1.2 | grep app_limited
app_limited busy:10ms
#     ↑
# Flag appears when iperf3 briefly pauses between bursts
```

### Why app_limited Appears

**Scenario 1: Application Doing Other Work**
```
iperf3 process:
1. Read data from memory buffer
2. Call write(sockfd, data, len)
3. Do some processing (stats calculation)  ← App busy here
4. Go back to step 1

During step 3: TCP send buffer empties → app_limited = 1
```

**Scenario 2: Application I/O Blocked**
```
Application:
1. Read data from disk
2. write() to socket
3. Read more data from disk  ← Waiting for disk I/O
4. write() to socket

During disk I/O wait: send buffer empties → app_limited = 1
```

**Scenario 3: Rate Limiting by Application**
```
Application deliberately limits rate:
while (true) {
    send_data(1MB);
    sleep(100ms);  ← Intentional pause
}

During sleep: app_limited = 1
```

### How ss Gets app_limited

**Path**: Kernel → `/proc/net/tcp` → `ss` tool

```c
// From net/ipv4/tcp_ipv4.c - tcp_get_info()
void tcp_get_info(struct sock *sk, struct tcp_info *info)
{
    const struct tcp_sock *tp = tcp_sk(sk);

    // ... other fields ...

    if (tp->app_limited)
        info->tcpi_delivery_rate_app_limited = 1;
}
```

**ss reads this from**:
- `/proc/net/tcp` (text format)
- `TCP_INFO` socket option (binary format)

```bash
# ss internally calls:
getsockopt(sock, SOL_TCP, TCP_INFO, &info, &len);

# Then displays:
if (info.tcpi_delivery_rate_app_limited)
    printf("app_limited ");
```

### Significance for Performance Analysis

**If app_limited is SET**:
```
→ Throughput is NOT limited by:
  ✗ Network bandwidth
  ✗ Congestion window (cwnd)
  ✗ Receive window (rwnd)
  ✗ Packet loss

→ Throughput IS limited by:
  ✓ Application not providing data fast enough
  ✓ Application CPU usage
  ✓ Application I/O wait
  ✓ Application intentional rate limiting
```

**If app_limited is NOT set**:
```
→ Throughput limited by network or TCP protocol:
  • Congestion window (cwnd)
  • Receive window (rwnd)
  • Packet loss / retransmissions
  • Network bandwidth
```

---

## 2. lastsnd / lastrcv / lastack - Timing Metrics

### What Are These Metrics?

These are **time-since-last-activity** metrics measured in **milliseconds**:

- **`lastsnd`**: Milliseconds since last **data packet** was sent
- **`lastrcv`**: Milliseconds since last **packet** (data or ACK) was received
- **`lastack`**: Milliseconds since last **ACK** was received

### Source in Linux Kernel

**Location**: `include/linux/tcp.h`

```c
// From include/linux/tcp.h
struct tcp_sock {
    u32 lsndtime;  // Last time data was sent (in jiffies)
    u32 lrcvtime;  // Last time packet received (in jiffies)

    // ... other fields ...
};
```

**Updated by kernel**:

```c
// From net/ipv4/tcp_output.c - tcp_transmit_skb()
// When sending data packet:
tcp_sk(sk)->lsndtime = tcp_jiffies32;

// From net/ipv4/tcp_input.c - tcp_rcv_established()
// When receiving packet:
tcp_sk(sk)->lrcvtime = tcp_jiffies32;
```

### How ss Calculates These Values

**ss reads current time and socket timestamps**:

```c
// Simplified ss logic
u32 current_time = get_jiffies_32();
u32 lsndtime = tp->lsndtime;  // From kernel
u32 lrcvtime = tp->lrcvtime;  // From kernel

// Calculate deltas (in jiffies)
u32 lastsnd_jiffies = current_time - lsndtime;
u32 lastrcv_jiffies = current_time - lrcvtime;

// Convert to milliseconds (HZ = ticks per second, usually 1000)
u32 lastsnd_ms = jiffies_to_msecs(lastsnd_jiffies);
u32 lastrcv_ms = jiffies_to_msecs(lastrcv_jiffies);

printf("lastsnd:%u lastrcv:%u", lastsnd_ms, lastrcv_ms);
```

### What Do These Values Mean?

#### lastsnd (Last Send Time)

**Measures**: Time since TCP stack last **sent a data packet** (not ACK)

```
Timeline:
T=0ms:    App calls write(sockfd, data, 1KB)
          → TCP sends packet
          → lsndtime = current_jiffies

T=100ms:  ss command runs
          → lastsnd = 100ms - 0ms = 100ms
          → Output: lastsnd:100
```

**Does NOT track**:
- Pure ACK packets (ACKs without data)
- Keepalive packets
- TCP retransmissions (some implementations may update, some may not)

**Interpretation**:
```
lastsnd:10     → Last sent data 10ms ago (active sending)
lastsnd:1000   → Last sent data 1 second ago (idle or slow)
lastsnd:30000  → Last sent data 30 seconds ago (connection idle)
```

#### lastrcv (Last Receive Time)

**Measures**: Time since TCP stack last **received any packet** (data or ACK)

```
Timeline:
T=0ms:    TCP receives ACK packet from peer
          → lrcvtime = current_jiffies

T=50ms:   ss command runs
          → lastrcv = 50ms - 0ms = 50ms
          → Output: lastrcv:50
```

**Tracks**:
- Data packets
- ACK packets
- Any TCP segment received

**Interpretation**:
```
lastrcv:10     → Received packet 10ms ago (active connection)
lastrcv:5000   → Received packet 5 seconds ago (possibly idle)
lastrcv:60000  → Received packet 60 seconds ago (likely keepalive or idle)
```

#### lastack (Last ACK Received Time)

**Measures**: Time since TCP stack last **received an ACK** that acknowledged new data

```
Timeline:
T=0ms:    Sent data (seq=1000, len=1448)
T=5ms:    Received ACK (ack=2448)  → Acknowledges new data
          → lastack_time = current_jiffies

T=105ms:  ss command runs
          → lastack = 105ms - 5ms = 100ms
          → Output: lastack:100
```

**Only counts**:
- ACKs that advance `snd_una` (acknowledge new data)
- Does NOT count duplicate ACKs

**Interpretation**:
```
lastack:10     → Last ACK 10ms ago (actively transmitting)
lastack:200    → Last ACK 200ms ago (slow ACK or idle)
lastack:5000   → Last ACK 5 seconds ago (likely idle or flow control)
```

### Relationship Between These Metrics

**Normal Active Connection**:
```
lastsnd:100   lastrcv:100   lastack:100

Interpretation:
- Sent data 100ms ago
- Received ACK 100ms ago
- Last ACK was 100ms ago
→ All in sync, normal bidirectional traffic
```

**One-Way Traffic (Client Sending to Server)**:
```
Client side:
lastsnd:10    lastrcv:15    lastack:15

Interpretation:
- Client sent data 10ms ago
- Received ACK 15ms ago
→ Small RTT (~5ms), normal

Server side:
lastsnd:500   lastrcv:10    lastack:600

Interpretation:
- Server last sent data 500ms ago (server mostly receives)
- Server received data 10ms ago (client actively sending)
- Server last got ACK 600ms ago (server sends little, so few ACKs)
→ Normal for unidirectional flow
```

**Idle Connection**:
```
lastsnd:30000   lastrcv:30000   lastack:30000

Interpretation:
- No activity for 30 seconds
- Connection may be kept alive by TCP keepalive
- Or application is idle
```

**Stalled Connection (Problem)**:
```
lastsnd:10   lastrcv:5000   lastack:5000

Interpretation:
- Just sent data 10ms ago
- But haven't received anything for 5 seconds!
- No ACK for 5 seconds!
→ PROBLEM: Network path broken, peer dead, or severe packet loss
```

### Example from Your Screenshot

From the screenshot, typical output looks like:
```
lastsnd:100 lastrcv:100 lastack:100
```

**What this means**:
```
Current time: T = now
Last sent data: T - 100ms
Last received packet: T - 100ms
Last received ACK: T - 100ms

Interpretation:
- Connection was active 100ms ago
- Then went quiet (no activity in last 100ms)
- This is NORMAL for bursty traffic or between iperf3 report intervals
```

### Why These Metrics Matter

#### Scenario 1: Detecting Stalled Transfers

```
Before:
lastsnd:10   lastrcv:10   lastack:10    → Normal

After 5 seconds:
lastsnd:10   lastrcv:5000  lastack:5000  → STUCK!

Diagnosis:
- Still trying to send (lastsnd recent)
- Not receiving ACKs (lastack old)
→ Network path broken or peer crashed
```

#### Scenario 2: Detecting Idle Connections

```
lastsnd:60000   lastrcv:60000   lastack:60000

Diagnosis:
- No activity for 60 seconds
- Connection may be:
  • Idle (waiting for user input)
  • Using TCP keepalive
  • Should be closed but isn't
```

#### Scenario 3: Understanding High RTT

```
Your case:
Server side: lastsnd:100   lastrcv:100   lastack:100
Client side: lastsnd:10    lastrcv:15    lastack:15

Diagnosis:
- Server sent 100ms ago (infrequent sending)
- Client sent 10ms ago, got ACK 15ms ago (active sending)
→ Asymmetric traffic pattern
→ Server lastsnd being old is NORMAL (server doesn't send much)
→ NOT related to high RTT directly
```

#### Scenario 4: Application-Limited Detection

```
lastsnd:5000   app_limited   cwnd:1000

Diagnosis:
- Haven't sent data for 5 seconds
- app_limited flag set
- cwnd has plenty of room (1000 segments available)
→ Application not providing data (confirmed by lastsnd)
```

### Relationship to TCP Protocol

**These are NOT seq/ack numbers!**

```
TCP Protocol:
seq = 1000              ← Sequence number (bytes)
ack = 2448              ← Acknowledgment number (bytes)
↑
These track DATA position

lastsnd/lastrcv/lastack:
lastsnd = 100ms         ← Time since last send
lastrcv = 100ms         ← Time since last receive
lastack = 100ms         ← Time since last ACK
↑
These track TIME since activity
```

**But they ARE related to seq/ack in that**:

```c
// Kernel updates lsndtime when:
tcp_transmit_skb() {
    send_packet_with_seq(seq);
    tp->lsndtime = current_jiffies;  // Update time
}

// Kernel updates lastack time when:
tcp_ack() {
    if (ack > tp->snd_una) {  // New ACK advances snd_una
        tp->snd_una = ack;
        tp->lastack_time = current_jiffies;  // Update time
    }
}
```

### How to Read ss Output with These Metrics

```bash
$ ss -tinopm dst 1.1.1.3
ESTAB  0  0  1.1.1.2:5201  1.1.1.3:53730
       ...
       send 1.18Gbps lastsnd:100 lastrcv:100 lastack:100
       pacing_rate 2.35Gbps delivery_rate 0.18Gbps
       app_limited busy:10ms
```

**Reading**:
1. `lastsnd:100` - Sent data 100ms ago
2. `lastrcv:100` - Received packet 100ms ago
3. `lastack:100` - Received ACK 100ms ago
4. `app_limited` - Currently limited by application
5. `busy:10ms` - Connection was actively sending for 10ms total

**Interpretation**:
- Connection is currently **idle** (100ms no activity)
- Was **app_limited** during last active period
- Only spent **10ms** actively sending data
- This is normal for **bursty traffic** or measurement intervals

### Summary Table

| Metric | Measures | Units | Source | Updates On | Use Case |
|--------|----------|-------|--------|------------|----------|
| **app_limited** | Application-limited flag | Boolean | `tcp_sock.app_limited` | Send buffer empty | Distinguish app vs network bottleneck |
| **lastsnd** | Time since last data sent | Milliseconds | `tcp_sock.lsndtime` | `tcp_transmit_skb()` | Detect sending stalls, idle connections |
| **lastrcv** | Time since last packet received | Milliseconds | `tcp_sock.lrcvtime` | `tcp_rcv_established()` | Detect receive stalls, path issues |
| **lastack** | Time since last ACK received | Milliseconds | Calculated from ACK events | ACK advances `snd_una` | Detect ACK delays, peer issues |

### Practical Example with Your Case

**Your Server-Side Observation**:
```
RTT: 5.422 ms
recv_q: 122064
lastsnd: 100 ms      (if we had this metric)
lastrcv: 5 ms        (if we had this metric)
app_limited: YES     (if we had this metric)
```

**What This Would Tell Us**:
```
1. lastsnd:100 + app_limited → Server not sending because app hasn't provided data
2. lastrcv:5 → Server actively receiving data (5ms ago)
3. recv_q:122064 → Data piling up, app not reading fast enough
4. RTT:5.422 → High because client is delaying ACKs (related to recv_q backlog)

Root Cause: Server application bottleneck (reading slowly)
```

**Your Client-Side Observation**:
```
RTT: 0.167 ms
recv_q: 0
lastsnd: 10 ms       (if we had this metric)
lastrcv: 15 ms       (if we had this metric)
app_limited: NO      (if we had this metric)
```

**What This Would Tell Us**:
```
1. lastsnd:10 + app_limited:NO → Client actively sending, not app-limited
2. lastrcv:15 → Receiving ACKs promptly
3. recv_q:0 → No backlog, reading immediately
4. RTT:0.167 → Low because server sends ACKs promptly (no backlog)

Conclusion: Client side healthy, no bottleneck
```

## Conclusion

- **`app_limited`**: Kernel flag showing app can't provide data fast enough
- **`lastsnd/lastrcv/lastack`**: Time-based metrics (milliseconds), NOT seq/ack numbers
- These metrics are essential for distinguishing **application bottlenecks** from **network bottlenecks**
- Without these, you might misdiagnose network issues when the real problem is application-side

For your intermittent performance issue, having these metrics would immediately show:
- When issue occurs: Is `app_limited` set?
- When issue occurs: Has `lastsnd` become very large (>1000ms)?
- This would confirm whether it's an application issue or network issue
