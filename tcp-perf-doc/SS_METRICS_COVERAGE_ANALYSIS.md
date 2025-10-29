# ss Metrics Coverage Analysis

## Current Implementation Analysis

### 1. ss Command Used in Code

**Command**: `ss -tinopm state established 'filter_expression'`

**Flags Breakdown**:
- `-t`: TCP sockets only
- `-i`: Show internal TCP information
- `-n`: Numeric addresses (no hostname resolution)
- `-o`: Show timer information
- `-p`: Show process information
- `-m`: Show socket memory information

### 2. Metrics Currently Parsed by Code

Based on `tcp_connection_analyzer.py` lines 433-549, the following metrics are parsed:

#### Connection Basics (lines 356-421)
- ✅ `state` - Connection state (ESTAB, etc.)
- ✅ `recv_q` - Receive queue size
- ✅ `send_q` - Send queue size
- ✅ `local_addr` - Local IP address
- ✅ `local_port` - Local port
- ✅ `remote_addr` - Remote IP address
- ✅ `remote_port` - Remote port

#### RTT Metrics (lines 436-445)
- ✅ `rtt` - Smoothed RTT (from `rtt:0.078/0.036`)
- ✅ `rttvar` - RTT variance (from `rtt:0.078/0.036`)
- ✅ `rto` - Retransmission timeout (from `rto:201`)
- ✅ `minrtt` - Minimum RTT (from `minrtt:0.042`)

#### Congestion Control (lines 447-455)
- ✅ `cwnd` - Congestion window (from `cwnd:10`)
- ✅ `ssthresh` - Slow start threshold (from `ssthresh:285`)
- ❌ `ca_state` - Congestion avoidance state (NOT PARSED)

#### Window Sizes (lines 467-506)
- ✅ `mss` - Maximum segment size (from `mss:1448`)
- ✅ `pmtu` - Path MTU (from `pmtu:1500`)
- ✅ `wscale` - Window scale (from `wscale:9,9`)
- ✅ `rcv_space` - Receive buffer space (from `rcv_space:14480`)
- ✅ `rcv_ssthresh` - Receive slow start threshold (from `rcv_ssthresh:65535`)
- ❌ `snd_wnd` - Send window (DEFINED but NOT PARSED)

#### Rate Metrics (lines 472-485)
- ✅ `send_rate` - Send rate (from `send 148512820bps`)
- ✅ `pacing_rate` - Pacing rate (from `pacing_rate 257809520bps`)
- ✅ `delivery_rate` - Delivery rate (from `delivery_rate 3200000000bps`)

#### Retransmission (lines 487-496)
- ✅ `retrans` - Current unacked retransmissions (from `retrans:0/1195`)
- ✅ `retrans_total` - Total retransmissions (from `retrans:0/1195`)
- ✅ `lost` - Lost packets (from `lost:5`)

#### Time-Limited Statistics (lines 513-534)
- ✅ `busy_time` - Time spent busy (from `busy:60000ms`)
- ✅ `rwnd_limited_time` - Time limited by receive window (from `rwnd_limited:157971ms(95.6%)`)
- ✅ `rwnd_limited_ratio` - Percentage of time rwnd-limited (from `rwnd_limited:157971ms(95.6%)`)
- ✅ `sndbuf_limited_time` - Time limited by send buffer (from `sndbuf_limited:1000ms(5.0%)`)
- ✅ `sndbuf_limited_ratio` - Percentage of time sndbuf-limited (from `sndbuf_limited:1000ms(5.0%)`)
- ✅ `cwnd_limited_time` - Time limited by congestion window (from `cwnd_limited:500ms(2.5%)`)
- ✅ `cwnd_limited_ratio` - Percentage of time cwnd-limited (from `cwnd_limited:500ms(2.5%)`)

#### Byte Statistics (lines 536-549)
- ✅ `bytes_sent` - Total bytes sent (from `bytes_sent:189`)
- ✅ `bytes_acked` - Total bytes acknowledged (from `bytes_acked:190`)
- ✅ `bytes_received` - Total bytes received (from `bytes_received:4`)

## 3. Screenshot Analysis

### Screenshot Content (ss -tinopm output)

From the provided screenshot, I can see the following ss output format:

```
State    Recv-Q  Send-Q  Local Address:Port    Peer Address:Port    Process
ESTAB    0       0       [::ffff:1.1.1.2]:5201  [::ffff:1.1.1.3]:58688  users:(("iperf3",pid=xxx,fd=x))
         skmem:(r0,rb87380,t0,tb87040,f0,w0,o0,bl0,d0)
         ts sack cubic wscale:9,9 rto:201 rtt:0.078/0.036 ato:40 mss:1448
         pmtu:1500 rcvmss:536 advmss:1448 cwnd:10 ssthresh:768
         bytes_acked:190 bytes_received:4 segs_out:10 segs_in:9
         data_segs_out:1 data_segs_in:1 send 1.18Gbps lastsnd:100
         lastrcv:100 lastack:100 pacing_rate 2.35Gbps delivery_rate 0.18Gbps
         app_limited busy:10ms rcv_rtt:1000 rcv_space:14480 rcv_ssthresh:65535
         minrtt:0.005
```

### 4. Missing Metrics in Current Code

Based on the screenshot, here are the metrics that appear in ss output but are **NOT parsed** by the current code:

#### Process Information
- ❌ **`users`** - Process info `users:(("iperf3",pid=xxx,fd=x))`
  - Process name: `iperf3`
  - PID: process ID
  - File descriptor: socket fd number

#### Socket Memory (skmem)
- ❌ **`skmem`** - Socket memory usage `skmem:(r0,rb87380,t0,tb87040,f0,w0,o0,bl0,d0)`
  - `r`: RX queue length (same as Recv-Q, but in skmem format)
  - `rb`: RX buffer size
  - `t`: TX queue length (same as Send-Q)
  - `tb`: TX buffer size
  - `f`: Forward alloc
  - `w`: Write buffer
  - `o`: Option memory
  - `bl`: Backlog
  - `d`: Dropped packets at socket level

#### TCP Options/Features
- ❌ **`ts`** - TCP timestamps enabled
- ❌ **`sack`** - SACK (Selective Acknowledgment) enabled
- ❌ **`cubic`** - Congestion control algorithm name (cubic/reno/bbr/etc.)

#### Timing Metrics
- ❌ **`ato`** - ACK timeout (from `ato:40`)
- ❌ **`lastsnd`** - Time since last send (from `lastsnd:100`)
- ❌ **`lastrcv`** - Time since last receive (from `lastrcv:100`)
- ❌ **`lastack`** - Time since last ACK (from `lastack:100`)

#### Segment Counters
- ❌ **`segs_out`** - Total segments sent out (from `segs_out:10`)
- ❌ **`segs_in`** - Total segments received (from `segs_in:9`)
- ❌ **`data_segs_out`** - Data segments sent (from `data_segs_out:1`)
- ❌ **`data_segs_in`** - Data segments received (from `data_segs_in:1`)

#### Receive-Side Metrics
- ❌ **`rcvmss`** - Received MSS advertisement (from `rcvmss:536`)
- ❌ **`advmss`** - Advertised MSS (from `advmss:1448`)
- ❌ **`rcv_rtt`** - Receiver-side RTT estimate (from `rcv_rtt:1000`)

#### Application State
- ❌ **`app_limited`** - Application-limited flag (indicates app not providing data fast enough)

#### Additional Metrics (may appear in some outputs)
- ❌ **`reordering`** - Reordering metric
- ❌ **`snd_cwnd`** - Send congestion window (different from cwnd in some contexts)
- ❌ **`snd_ssthresh`** - Send slow start threshold
- ❌ **`unacked`** - Number of unacknowledged packets
- ❌ **`sacked`** - Number of SACKed packets
- ❌ **`fackets`** - Forward acknowledgment packets
- ❌ **`retr`** - Retransmits counter (current)
- ❌ **`lost_out`** - Lost packets out
- ❌ **`snd_wnd`** - Peer's advertised receive window

## 5. Categorized Missing Metrics by Importance

### Critical for Performance Analysis

1. **`cubic/reno/bbr`** (Congestion control algorithm)
   - **Why important**: Different algorithms have different behaviors
   - **Use case**: Understanding why cwnd behaves a certain way
   - **Screenshot location**: Right after `sack`
   - **Example**: `sack cubic wscale:9,9`

2. **`segs_out` / `segs_in`** (Segment counters)
   - **Why important**: Calculate segment loss rate, retransmission rate
   - **Use case**: `retrans_total / segs_out = retransmission_ratio`
   - **Screenshot location**: After `bytes_received`
   - **Example**: `segs_out:10 segs_in:9`

3. **`data_segs_out` / `data_segs_in`** (Data segment counters)
   - **Why important**: Distinguish data segments from ACK-only segments
   - **Use case**: Calculate pure data throughput efficiency
   - **Screenshot location**: After `segs_in`
   - **Example**: `data_segs_out:1 data_segs_in:1`

4. **`app_limited`** (Application-limited flag)
   - **Why important**: Indicates if throughput is limited by application, not network
   - **Use case**: Distinguish application bottleneck from network bottleneck
   - **Screenshot location**: Before `busy:`
   - **Example**: `app_limited busy:10ms`

5. **`lastsnd` / `lastrcv` / `lastack`** (Timing since last activity)
   - **Why important**: Detect idle connections, stalled transfers
   - **Use case**: If `lastsnd` > 1000ms, connection may be idle or stuck
   - **Screenshot location**: After `send` rate
   - **Example**: `lastsnd:100 lastrcv:100 lastack:100`

6. **`rcv_rtt`** (Receiver-side RTT estimate)
   - **Why important**: Independent RTT measurement from receiver perspective
   - **Use case**: Compare sender RTT vs receiver RTT
   - **Screenshot location**: After `app_limited`
   - **Example**: `rcv_rtt:1000`

### Important for Diagnosis

7. **`skmem` breakdown** (Socket memory details)
   - **Why important**: Diagnose memory allocation issues
   - **Use case**: Check if TX/RX buffers are properly sized
   - **Screenshot location**: Second line of output
   - **Example**: `skmem:(r0,rb87380,t0,tb87040,f0,w0,o0,bl0,d0)`
     - `rb87380`: RX buffer = 85 KB
     - `tb87040`: TX buffer = 85 KB
     - `bl0`: Backlog = 0
     - `d0`: Dropped = 0 (CRITICAL if > 0!)

8. **`ato`** (ACK timeout)
   - **Why important**: Shows delayed ACK timer setting
   - **Use case**: Correlate with high RTT (delayed ACK adds latency)
   - **Screenshot location**: After `rtt`
   - **Example**: `ato:40` (40ms delayed ACK timer)

9. **`rcvmss` / `advmss`** (MSS negotiation)
   - **Why important**: Check MSS mismatch issues
   - **Use case**: If `rcvmss` != `advmss`, may indicate MTU issues
   - **Screenshot location**: After `pmtu`
   - **Example**: `rcvmss:536 advmss:1448` (mismatch!)

10. **`ts` / `sack` flags** (TCP options)
    - **Why important**: Check if performance features are enabled
    - **Use case**: SACK disabled → poor loss recovery
    - **Screenshot location**: Second line, before congestion control
    - **Example**: `ts sack cubic`

### Nice to Have

11. **`users` (Process information)**
    - **Why important**: Identify which process owns the connection
    - **Use case**: Multiple processes on same port
    - **Screenshot location**: End of first line
    - **Example**: `users:(("iperf3",pid=12345,fd=3))`

12. **`reordering`** (Reordering metric)
    - **Why important**: Network path reordering detection
    - **Use case**: High reordering → may trigger unnecessary retransmissions
    - **May appear**: `reordering:56`

## 6. Impact Analysis

### What You're Missing Without These Metrics

#### Scenario 1: Diagnosing Low Throughput

**Current Analysis (with existing metrics)**:
```
cwnd: 10
send_rate: 0.02 Gbps
RTT: 5.422 ms
→ Conclusion: cwnd is small, limiting throughput
```

**Enhanced Analysis (with missing metrics)**:
```
cwnd: 10
send_rate: 0.02 Gbps
RTT: 5.422 ms
app_limited: YES           ← NEW: Application not sending data!
lastsnd: 5000 ms           ← NEW: 5 seconds since last send!
→ Conclusion: Application bottleneck, NOT network bottleneck!
```

#### Scenario 2: High Retransmission Rate

**Current Analysis**:
```
retrans_total: 1195
→ Conclusion: High retransmissions (but how high is "high"?)
```

**Enhanced Analysis**:
```
retrans_total: 1195
segs_out: 100000           ← NEW
Retrans ratio: 1195/100000 = 1.195%  ← Calculated!
→ Conclusion: 1.2% retrans is acceptable (< 2%)
```

#### Scenario 3: Delayed ACK Impact

**Current Analysis**:
```
Server RTT: 5.422 ms
Client RTT: 0.167 ms
→ Conclusion: RTT asymmetry (but why?)
```

**Enhanced Analysis**:
```
Server RTT: 5.422 ms
Client RTT: 0.167 ms
ato (client): 40 ms        ← NEW: Delayed ACK timer!
lastsnd (server): 100 ms   ← NEW: Last sent 100ms ago
lastack (server): 5 ms     ← NEW: ACK came 5ms ago
→ Conclusion: Delayed ACK is causing high server-side RTT
```

#### Scenario 4: Buffer Size Issues

**Current Analysis**:
```
recv_q: 122064
rcv_space: 14600
→ Conclusion: Buffer too small
```

**Enhanced Analysis**:
```
recv_q: 122064
rcv_space: 14600
skmem rb: 87380            ← NEW: Kernel buffer = 85 KB
skmem d: 15                ← NEW: 15 PACKETS DROPPED!
→ Conclusion: CRITICAL - Socket dropping packets due to buffer overflow!
```

#### Scenario 5: Congestion Control Behavior

**Current Analysis**:
```
cwnd: 10
ssthresh: 768
→ Conclusion: In slow start (cwnd < ssthresh)
```

**Enhanced Analysis**:
```
cwnd: 10
ssthresh: 768
cubic: YES                 ← NEW: Using CUBIC algorithm
ca_state: Recovery         ← NEW: Currently in recovery mode!
sacked: 5                  ← NEW: 5 packets SACKed but not ACKed
→ Conclusion: Loss recovery in progress with CUBIC
```

## 7. Metric Parsing Complexity

### Easy to Parse (Simple Regex)

```python
# Pattern: key:value or key value
'ato:40'                    → r'ato:(\d+)'
'lastsnd:100'               → r'lastsnd:(\d+)'
'segs_out:10'               → r'segs_out:(\d+)'
'app_limited'               → r'app_limited'  (boolean flag)
'cubic'                     → r'(cubic|reno|bbr|vegas|westwood)'
```

### Medium Complexity

```python
# skmem requires structured parsing
'skmem:(r0,rb87380,t0,tb87040,f0,w0,o0,bl0,d0)'
→ Need to parse: r'skmem:\(r(\d+),rb(\d+),t(\d+),tb(\d+),f(\d+),w(\d+),o(\d+),bl(\d+),d(\d+)\)'

# users requires nested parsing
'users:(("iperf3",pid=12345,fd=3))'
→ Need to parse: r'users:\(\("([^"]+)",pid=(\d+),fd=(\d+)\)\)'

# Multiple flags on one line
'ts sack cubic wscale:9,9'
→ Need to check presence of 'ts', 'sack', and extract algorithm name
```

## 8. Recommended Parsing Priority

### Phase 1: Critical Metrics (Immediate Value)

1. ✅ **`cubic/reno/bbr`** - Congestion control algorithm
2. ✅ **`segs_out` / `segs_in`** - Segment counters
3. ✅ **`data_segs_out` / `data_segs_in`** - Data segment counters
4. ✅ **`app_limited`** - Application-limited flag
5. ✅ **`skmem:d`** - Socket dropped packets (CRITICAL!)

**Rationale**: These immediately improve root cause analysis accuracy.

### Phase 2: Diagnostic Metrics (High Value)

6. ✅ **`lastsnd` / `lastrcv` / `lastack`** - Activity timing
7. ✅ **`rcv_rtt`** - Receiver-side RTT
8. ✅ **`ato`** - ACK timeout
9. ✅ **`skmem:rb,tb,bl`** - Buffer sizes and backlog
10. ✅ **`rcvmss` / `advmss`** - MSS negotiation

**Rationale**: Essential for diagnosing specific performance issues.

### Phase 3: Supplemental Metrics (Nice to Have)

11. ✅ **`users`** - Process information
12. ✅ **`ts` / `sack`** - TCP options
13. ✅ **`reordering`** - Reordering metric
14. ✅ **`ca_state`** - Congestion avoidance state

**Rationale**: Useful for complete picture but not critical.

## 9. Example Enhanced Analysis Output

### Current Output:
```
Metrics:
  rtt                      : 5.422 ms
  cwnd                     : 10
  retrans                  : 0/1195
```

### Enhanced Output (with missing metrics):
```
Metrics:
  rtt                      : 5.422 ms
  cwnd                     : 10
  retrans                  : 0/1195 (1.2% of 100000 segments)  ← NEW CALC
  congestion_control       : cubic                            ← NEW
  app_limited              : YES                              ← NEW
  lastsnd                  : 5000 ms (5.0 seconds ago)        ← NEW
  lastrcv                  : 100 ms (0.1 seconds ago)         ← NEW
  lastack                  : 100 ms (0.1 seconds ago)         ← NEW
  ato                      : 40 ms (delayed ACK timer)        ← NEW
  rcv_rtt                  : 1000 ms (receiver-side RTT)      ← NEW
  segs_out                 : 100000                           ← NEW
  segs_in                  : 95000                            ← NEW
  data_segs_out            : 90000 (90% efficiency)           ← NEW
  socket_dropped           : 15 packets (CRITICAL!)           ← NEW
  tx_buffer_size           : 85 KB                            ← NEW
  rx_buffer_size           : 85 KB                            ← NEW
  backlog                  : 0 packets                        ← NEW
  process                  : iperf3 (pid=12345, fd=3)         ← NEW
```

### Enhanced Bottleneck Detection:
```
Bottlenecks Detected:
  ⚠️ [WARNING] Application Limited
     The application (iperf3) is not providing data fast enough
     Evidence:
       - app_limited flag set
       - lastsnd: 5000ms (no data sent for 5 seconds)
       - cwnd has room (10 segments available)
     Action: Check application performance, CPU usage, I/O blocking

  🔴 [CRITICAL] Socket Buffer Drops
     15 packets dropped at socket level due to buffer overflow
     Evidence:
       - skmem d=15 (dropped packets)
       - recv_q: 122064 bytes
       - rx_buffer_size: 87380 bytes (too small!)
     Action: Increase receive buffer size immediately
     Commands:
       sudo sysctl -w net.core.rmem_max=134217728
       sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"
```

## 10. Summary

### Current Coverage: ~60%

**Covered**:
- Basic connection info (state, queues, addresses)
- RTT metrics (rtt, rttvar, minrtt, rto)
- Congestion control basics (cwnd, ssthresh)
- Window sizes (mss, pmtu, wscale, rcv_space)
- Rates (send_rate, pacing_rate, delivery_rate)
- Retransmissions (retrans, lost)
- Limited statistics (rwnd_limited, cwnd_limited, sndbuf_limited)
- Byte counters (bytes_sent, bytes_acked, bytes_received)

**Missing** (Critical):
- Congestion control algorithm name (cubic/reno/bbr)
- Segment counters (segs_out, segs_in, data_segs_out, data_segs_in)
- Application-limited flag
- Activity timing (lastsnd, lastrcv, lastack)
- Socket memory details (skmem, especially dropped packets)
- Receiver-side RTT (rcv_rtt)
- ACK timeout (ato)
- MSS negotiation (rcvmss, advmss)

**Missing** (Nice to have):
- Process information (users)
- TCP options (ts, sack flags)
- Reordering metric
- CA state

### Impact of Missing Metrics

1. **Cannot distinguish application vs network bottlenecks** (missing `app_limited`)
2. **Cannot calculate retransmission ratio** (missing `segs_out`)
3. **Cannot detect socket-level drops** (missing `skmem:d`)
4. **Cannot identify delayed ACK impact** (missing `ato`)
5. **Cannot see congestion control algorithm** (missing `cubic/reno/bbr`)
6. **Cannot detect idle/stalled connections** (missing `lastsnd/lastrcv`)

### Recommendation

**Implement Phase 1 metrics immediately** to gain:
- Application bottleneck detection
- Accurate retransmission rate calculation
- Socket drop detection
- Congestion control visibility

This will significantly improve the tool's diagnostic accuracy for intermittent performance issues.
