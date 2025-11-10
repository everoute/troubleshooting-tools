# TCP Connection Analyzer

## Overview

TCP Connection Analyzer is a comprehensive tool for collecting and analyzing TCP connection performance metrics. It helps diagnose network throughput issues, identify performance bottlenecks, and provide actionable optimization recommendations.

The tool combines per-connection analysis with system-wide TCP statistics to provide deep insights into retransmission sources and protocol stack packet drops.

## Key Features

### 1. Connection Information Collection
- Uses `ss` command to collect detailed TCP connection metrics
- Supports both client and server roles
- Flexible filtering by IP address and port
- Can monitor single connection or multiple connections

### 2. Performance Metrics Analysis

**Per-Connection Metrics:**
- RTT (Round-Trip Time) and RTT variance
- Congestion window (cwnd) and slow start threshold (ssthresh)
- Receive window (rcv_space) and send window
- Send rate, pacing rate, and delivery rate
- Retransmission and packet loss statistics
- Queue status (Recv-Q, Send-Q)

**System-Wide Statistics (from netstat -s):**
- Retransmission type breakdown (TLP, fast retransmit, timeout, etc.)
- Protocol stack packet drops (socket buffer overflow, backlog drops, listen queue drops)
- SACK recovery and packet reordering detection
- Congestion window recovery statistics
- Timeout event classification

### 3. Bottleneck Detection

**Connection-Level Bottlenecks:**
- **rwnd_limited**: Receive window limitation
- **cwnd_limited**: Congestion window limitation
- **sndbuf_limited**: Send buffer limitation
- High retransmission rate detection
- Queue backlog detection
- Pacing rate limitation

**System-Level Issues:**
- Socket buffer overflow (receive queue pruned)
- Backlog queue drops (processing overload)
- Listen queue overflow (SYN drops)
- High TLP ratio (small receive window)
- Retransmitted packets lost again (severe congestion)

### 4. Intelligent Analysis & Recommendations

**BDP Calculation:**
- Calculates Bandwidth-Delay Product
- Recommends optimal receive/send buffer sizes
- Provides specific sysctl tuning commands

**Retransmission Source Analysis:**
- Identifies retransmission types and their percentages
- Pinpoints root causes (small window, network loss, congestion)
- Provides targeted remediation steps

**Critical Warnings:**
- High TLP ratio (>30%) - indicates small rwnd
- Many retrans packets lost (>1000) - indicates path quality issues
- Socket buffer overflow - requires tcp_rmem increase
- Listen queue overflow - requires somaxconn increase

### 5. Flexible Monitoring Modes
- Single snapshot analysis
- Continuous monitoring with specified interval
- System configuration display
- System statistics display

## Installation Requirements

- **OS**: Linux with kernel 4.9+ (for full metrics support)
- **Tools**: `ss` command (from iproute2 package), `netstat` command
- **Permissions**: sudo/root required
- **Python**: Python 3.6+

## Usage

### Basic Usage

#### 1. Client-Side Analysis (Analyzing connection to server)

```bash
# Analyze connection to iperf3 server
sudo python3 tcp_connection_analyzer.py \
    --remote-ip 1.1.1.5 \
    --remote-port 5201 \
    --role client

# Analyze all connections to specific remote IP
sudo python3 tcp_connection_analyzer.py \
    --remote-ip 1.1.1.5 \
    --role client

# Filter by both local and remote endpoints
sudo python3 tcp_connection_analyzer.py \
    --local-ip 10.0.0.31 \
    --remote-ip 10.0.0.32 \
    --remote-port 5201 \
    --role client
```

#### 2. Server-Side Analysis (Analyzing connections from clients)

```bash
# Analyze iperf3 server connections
sudo python3 tcp_connection_analyzer.py \
    --local-port 5201 \
    --role server

# Filter by specific local IP (for multi-homed hosts)
sudo python3 tcp_connection_analyzer.py \
    --local-ip 70.0.0.31 \
    --local-port 2181 \
    --role server

# Filter by both local and remote endpoints
sudo python3 tcp_connection_analyzer.py \
    --local-ip 70.0.0.31 \
    --remote-ip 70.0.0.32 \
    --local-port 2181 \
    --role server
```

#### 3. Continuous Monitoring

```bash
# Sample every 2 seconds
sudo python3 tcp_connection_analyzer.py \
    --remote-ip 1.1.1.5 \
    --remote-port 5201 \
    --role client \
    --interval 2
```

#### 4. View System TCP Configuration & Statistics

```bash
# Show system TCP configuration and statistics
sudo python3 tcp_connection_analyzer.py \
    --local-port 5201 \
    --role server \
    --show-config

# Show only system TCP statistics (netstat -s analysis)
sudo python3 tcp_connection_analyzer.py \
    --local-port 5201 \
    --role server \
    --show-stats
```

### Advanced Options

```bash
# Specify target bandwidth (for BDP calculation, default 25 Gbps)
--target-bandwidth 25

# Monitor all connection states (not just ESTABLISHED)
--all

# JSON format output (for script processing)
--json
```

## Output Explanation

### 1. System TCP Statistics (--show-stats or --show-config)

```
================================================================================
System TCP Statistics (netstat -s)
================================================================================

=== Retransmission Type Breakdown ===:
--------------------------------------------------------------------------------
  segments_retransmitted             :     59,545,149  # Total retransmitted segments (all causes)
  fast_retransmits                   :     33,063,030  # Fast retransmits (packet loss/reordering, 3 DupACKs)
  retrans_in_slowstart               :      5,247,139  # Retrans during slow start (initial cwnd small)
  tcp_loss_probes                    :     24,564,762  # TLP probe retrans (window too small for fast retransmit)
  tcp_loss_probe_recovery            :       224,453  # TLP probe successful recovery
  tcp_lost_retransmit                :      3,518,314  # Retransmitted packet lost again (severe congestion or path issue)
  tcp_spurious_rtos                  :         7,839  # Spurious RTO (false positive, high RTT variance)

=== Stack Packet Drops ===:
--------------------------------------------------------------------------------
  rcv_pruned                         :        29,892  # Rcv queue pruned (socket buffer overflow)
  rcv_collapsed                      :         1,772  # Rcv queue collapsed (memory pressure)
  tcp_backlog_drop                   :         3,641  # Backlog queue drop (processing overload)
  listen_overflows                   :     28,747,070  # Listen queue overflow count
  listen_drops                       :     28,747,070  # SYN dropped (listen queue full)

================================================================================
=== Intelligent Analysis ===
================================================================================

Retransmission Ratio: 0.0267% (59,545,149 / 223,417,376,312)

Retransmission Type Breakdown:
  TLP probe retrans   :   24,564,762  ( 41.3%)  - Window too small
  Fast retransmit     :   33,063,030  ( 55.5%)  - Packet loss/reordering
  Slow start retrans  :    5,247,139  (  8.8%)  - Small cwnd
  Retrans pkt lost    :    3,518,314  (  5.9%)  - Severe congestion WARNING

WARNING: Stack packet drops detected:
  Rcv queue pruned      :       29,892  - Socket buffer overflow, increase tcp_rmem
  Backlog drop          :        3,641  - App processing slow, increase tcp_max_syn_backlog
  SYN dropped           :   28,747,070  - Listen queue full, increase somaxconn

Critical Warnings:
  CRITICAL: TLP ratio too high: 41.3% - Check receive window (rwnd)
  CRITICAL: Many retrans packets lost: 3,518,314 - Poor path quality
  WARNING: Socket buffer overflow: 29,892 - Increase tcp_rmem
  WARNING: Listen queue overflow: 28,747,070 - Increase net.core.somaxconn
```

**Key Statistics Explained:**

**Retransmission Types:**
- **TLP probe retrans**: Tail Loss Probe used when window too small to trigger fast retransmit (needs 3 DupACKs)
- **Fast retransmit**: Triggered by 3 duplicate ACKs, indicates network packet loss or reordering
- **Slow start retrans**: During initial connection phase, expected behavior
- **Retrans pkt lost**: Retransmitted packets lost again, indicates severe congestion or poor path quality
- **Spurious RTO**: False timeout detection, often due to high RTT variance

**Stack Packet Drops:**
- **Rcv queue pruned**: Socket buffer overflow, packets discarded by kernel
- **Rcv queue collapsed**: Memory pressure, kernel compressing receive queue
- **Backlog drop**: Application processing too slow, backlog queue full
- **Listen overflow**: Too many SYN requests, listen queue full
- **SYN dropped**: SYN packets dropped due to full listen queue

### 2. Connection Basic Information

```
Connection: 1.1.1.2:53858 -> 1.1.1.5:5201
State: ESTAB
```

### 3. Performance Metrics

```
Metrics:
  recv_q                   : 0
  send_q                   : 0
  rtt                      : 0.078 ms
  rttvar                   : 0.036 ms
  cwnd                     : 10
  ssthresh                 : 285
  rcv_space                : 14480 bytes (14.1 KB)
  mss                      : 1448
  pmtu                     : 1500
  send_rate                : 0.15 Gbps
  pacing_rate              : 0.26 Gbps
  retrans                  : 0/1195
  bdp                      : 243750 bytes (238.0 KB)
  recommended_window       : 975000 bytes (952.1 KB)
```

**Key Metrics Explained:**

- **rtt**: Round-trip time, lower is better (LAN typically < 1ms)
- **cwnd**: Congestion window, too small (<100) indicates issues
- **rcv_space**: Receive window, should be much larger than BDP
- **pacing_rate**: Send rate limit, should be close to target bandwidth
- **retrans**: Retransmission count, format "unacked/total"
- **bdp**: Bandwidth-Delay Product, theoretical minimum window size
- **recommended_window**: Recommended window size (BDP × 4)

### 4. Bottleneck Detection

```
Bottlenecks Detected:
  🔴 [CRITICAL] rwnd_limited
     Value: 95.6%
     Receive window limited for 95.6% of the time

  ⚠️ [WARNING] small_cwnd
     Value: 10
     Congestion window very small (10), possibly in slow start or recovery

  ⚠️ [WARNING] high_retransmissions
     Value: 1195
     High retransmission count (1195)

Likely Causes:
  - TLP probe retrans: 24,562,987 (41.3%) - Window too small (rwnd/cwnd), cannot trigger fast retransmit
  - Fast retransmit: 33,062,483 (55.5%) - Packet loss or reordering
  - Retrans pkt lost: 3,518,221 - Severe congestion or path quality issue
```

**Bottleneck Types:**

- **rwnd_limited**: Receive window limitation (most common throughput bottleneck)
- **cwnd_limited**: Congestion window limitation (caused by packet loss)
- **sndbuf_limited**: Send buffer limitation
- **small_cwnd**: Congestion window too small (only for client role)
- **high_retransmissions**: High retransmission rate
- **recv_queue_backlog**: Receive queue backlog (slow application)
- **low_pacing_rate**: Send rate far below target

### 5. Optimization Recommendations

```
Recommendations:
  1. Issue: Receive window too small
     Current: rcv_space = 14480 bytes (14.1 KB)
     Recommended: 975000 bytes (952.1 KB, 0.9 MB)
     Action: Increase tcp_rmem on the receiver side
     Commands:
       sudo sysctl -w net.core.rmem_max=1950000
       sudo sysctl -w net.ipv4.tcp_rmem="4096 131072 1950000"

  2. Issue: High retransmissions detected
     Likely Causes:
       - TLP probe retrans: 24,562,987 (41.3%) - Window too small (rwnd/cwnd), cannot trigger fast retransmit
       - Fast retransmit: 33,062,483 (55.5%) - Packet loss or reordering
     Action: Investigate retransmission causes
     Commands:
       # Check system-wide retrans breakdown:
       netstat -s | grep -iE 'retrans|loss probe|spurious'

       # Check NIC drops:
       ethtool -S <interface> | grep -E 'drop|error|miss'

       # Use eBPF tools for detailed tracing:
       # sudo python3 ebpf-tools/linux-network-stack/packet-drop/*.py
```

## Typical Use Cases

### Case 1: iperf3 Throughput Lower Than Expected

**Problem:** 25G NIC, but iperf3 only achieves 6-7 Gbps

**Diagnostic Steps:**

1. **On iperf3 client:**
   ```bash
   # Start iperf3 test
   iperf3 -c 1.1.1.5 -t 60 -P 2 &

   # Analyze connection in another terminal
   sudo python3 tcp_connection_analyzer.py \
       --remote-ip 1.1.1.5 \
       --remote-port 5201 \
       --role client \
       --show-config
   ```

2. **On iperf3 server:**
   ```bash
   sudo python3 tcp_connection_analyzer.py \
       --local-port 5201 \
       --role server \
       --show-config
   ```

3. **Check output, focus on:**
   - `rwnd_limited` > 50% → Receive window bottleneck
   - `cwnd` < 100 → Congestion issue
   - `retrans` very high → Network packet loss
   - `rcv_space` << BDP × 4 → Window too small
   - `TLP ratio` > 30% → Receive window (rwnd) too small

4. **Tune system parameters based on recommendations**

5. **Re-test to verify improvement**

### Case 2: Continuous Monitoring for State Changes

```bash
# Start continuous monitoring
sudo python3 tcp_connection_analyzer.py \
    --remote-ip 1.1.1.5 \
    --remote-port 5201 \
    --role client \
    --interval 1 > tcp_analysis.log

# Monitor key metric trends:
# - Is rcv_space gradually increasing?
# - Is cwnd stable?
# - Is rwnd_limited decreasing?
# - Are retrans increasing?
```

### Case 3: Before/After Tuning Comparison

```bash
# Before tuning
echo "=== Before Tuning ===" > comparison.txt
sudo python3 tcp_connection_analyzer.py \
    --remote-ip 1.1.1.5 \
    --remote-port 5201 \
    --role client \
    --show-config >> comparison.txt

# Tune system parameters
sudo sysctl -w net.core.rmem_max=268435456
sudo sysctl -w net.ipv4.tcp_rmem="4096 131072 268435456"

# Restart iperf3 test

# After tuning
echo "=== After Tuning ===" >> comparison.txt
sudo python3 tcp_connection_analyzer.py \
    --remote-ip 1.1.1.5 \
    --remote-port 5201 \
    --role client \
    --show-config >> comparison.txt

# Compare results
less comparison.txt
```

### Case 4: Diagnosing High Retransmissions

```bash
# Check system-wide retransmission breakdown
sudo python3 tcp_connection_analyzer.py \
    --local-port 2181 \
    --role server \
    --show-stats

# Look for:
# - High TLP ratio (>30%) → Small rwnd issue
# - Many retrans packets lost → Path quality issue
# - High fast retransmit → Network packet loss
# - Stack packet drops → Socket buffer overflow
```

## How It Works

### Data Collection

The tool uses the `ss` command with the following options:

```bash
ss -tinopm <filter>
```

- `-t`: TCP only
- `-i`: Internal TCP information (cwnd, rtt, retrans, etc.)
- `-n`: Don't resolve service names
- `-o`: Timer information
- `-p`: Process information
- `-m`: Socket memory usage

### System Statistics Collection

Parses `netstat -s` output to extract TCP and TcpExt statistics:

- **Tcp section**: Basic counters (segments sent/received, retransmitted, etc.)
- **TcpExt section**: Advanced counters (TLP probes, fast retransmits, SACK recovery, etc.)

### Bottleneck Detection Logic

#### 1. rwnd_limited Detection

```python
if rwnd_limited_ratio > 50%:
    # Receive window is main bottleneck
    # Calculate required window = BDP × 4
    # Provide tcp_rmem tuning recommendations
```

#### 2. cwnd_limited Detection

```python
if cwnd_limited_ratio > 50%:
    # Congestion window limitation
    # Recommend checking for packet loss
    # Check ethtool statistics
```

#### 3. Small cwnd Detection (Client Role Only)

```python
if role == 'client' and cwnd < 100:
    # Congestion window too small
    # Possibly in slow start or recovery phase
    # Usually result of packet loss
```

#### 4. High Retransmission Detection

```python
if retrans_total > 100:
    # High retransmission rate
    # Analyze retransmission types from system stats
    # Provide targeted recommendations
```

### BDP Calculation

```python
BDP (bytes) = Bandwidth (bps) × RTT (seconds) / 8

Recommended Window = BDP × 4
```

**Example:**
```
Bandwidth = 25 Gbps = 25,000,000,000 bps
RTT = 0.1 ms = 0.0001 seconds

BDP = 25,000,000,000 × 0.0001 / 8
    = 312,500 bytes
    ≈ 305 KB

Recommended Window = 305 KB × 4 = 1.2 MB
```

## Common Questions

### Q1: Why is sudo required?

A: Some `ss` options (like `-p` for process information) require root permissions.

### Q2: How to determine client vs server role?

A:
- **Client**: Initiates connection, uses high port to connect to server's fixed port
- **Server**: Listens on fixed port

Example with iperf3:
- Server: `iperf3 -s` (listens on 5201)
- Client: `iperf3 -c <server>` (uses random high port)

### Q3: Is 95% rwnd_limited definitely a receive window issue?

A: Yes, this metric directly reflects the percentage of time the sender was limited by the receiver's window. If over 50%, receive window is definitely the main bottleneck.

### Q4: Why is rcv_space still small after adjusting tcp_rmem?

A: Possible reasons:
1. Connection established before adjustment → Need to re-establish connection
2. Window auto-tuning needs time → Wait a few RTT cycles
3. Caught in vicious cycle → Need to increase default value as well

### Q5: How to interpret retrans field "0/1195"?

A: Format is "unacked retrans / total retrans"
- First number: Currently unacknowledged retransmissions
- Second number: Cumulative retransmissions since connection establishment

### Q6: What bottlenecks can the tool detect?

A: Main detections:
1. TCP layer bottlenecks (rwnd_limited, cwnd_limited, sndbuf_limited)
2. Congestion issues (small cwnd, high retrans with type analysis)
3. Application layer issues (Recv-Q > 0)
4. Rate limiting (pacing_rate far below target)
5. Protocol stack drops (socket buffer overflow, backlog drops, listen queue overflow)

Cannot directly detect:
- NIC hardware issues (use ethtool)
- CPU bottlenecks (use mpstat)
- Memory pressure (check system logs)

### Q7: What does high TLP ratio mean?

A: TLP (Tail Loss Probe) ratio over 30% indicates:
- Receive window (rwnd) is too small
- Cannot trigger fast retransmit (needs 3 DupACKs)
- Need to increase `tcp_rmem` on receiver side

### Q8: What causes "retrans packets lost"?

A: When retransmitted packets are lost again, it indicates:
- Severe network congestion
- Poor path quality
- Need to investigate network infrastructure

## Integration with Other Tools

### 1. With ethtool for NIC Checks

```bash
# Run analyzer
sudo python3 tcp_connection_analyzer.py --remote-ip 1.1.1.5 --remote-port 5201 --role client

# If drops detected, check with ethtool
sudo ethtool -S <interface> | grep -E "drop|error|miss"
```

### 2. With eBPF Tools for Deep Analysis

```bash
# If high latency detected, use latency analysis tool
sudo python3 system_network_latency_details.py \
    --src-ip 1.1.1.2 --dst-ip 1.1.1.5 \
    --protocol tcp --direction tx \
    --phy-interface <interface> \
    --latency-us 100
```

### 3. With netstat for System Statistics

```bash
# View system-level retransmission statistics (now integrated in tool)
netstat -s | grep -i retrans

# Check TCP memory usage
cat /proc/net/sockstat
```

## Output Examples

Complete output example includes:

1. **System Configuration** (--show-config)
2. **System Statistics with Intelligent Analysis** (--show-config or --show-stats)
3. **Connection Information and Metrics**
4. **Bottleneck Detection Results**
5. **Optimization Recommendations and Commands**

## Limitations and Notes

1. **Requires ss tool**: System must have iproute2 package installed
2. **Kernel version**: Some metrics (like rwnd_limited) require newer kernel (4.9+)
3. **Connection state**: Can only analyze established connections
4. **Sampling moment**: Single snapshot is instantaneous value, continuous monitoring recommended
5. **Cannot replace eBPF**: Cannot trace detailed kernel internal paths
6. **netstat -s statistics**: System-wide counters, not per-connection
7. **Server role cwnd**: Server-side small cwnd is normal (only sends ACKs)

## Implementation Details

### New Features in Latest Version

**Comprehensive netstat -s Statistics Parsing:**
- Parses 40+ TCP statistics from Tcp and TcpExt sections
- Categorizes retransmissions by type (TLP, fast retransmit, slow start, lost retrans)
- Detects protocol stack packet drops (socket buffer overflow, backlog drops, listen queue overflow)
- Analyzes timeout events (after SACK recovery, in loss state, other)
- Tracks SACK recovery and packet reordering
- Monitors congestion window recovery statistics

**Intelligent Analysis:**
- Calculates retransmission ratio and type breakdown
- Identifies root causes with percentage analysis
- Generates critical warnings with severity levels
- Provides targeted remediation recommendations

**Enhanced Per-Connection Analysis:**
- Cross-references connection metrics with system-wide patterns
- Shows likely causes from system stats when high retrans detected
- Distinguishes client vs server role behavior

### Code Statistics

- **Total lines**: ~1100 lines
- **New code (latest version)**: ~430 lines
- **Regex patterns**: 40+ patterns for netstat -s parsing
- **Statistics categories**: 7 categories (Retrans, Timeout, Stack Drops, SACK, Recovery, Connection, Basic)

## Future Plans

- [ ] Add historical data recording and trend analysis
- [ ] Support multi-connection comparison
- [ ] Add graphical output
- [ ] Integrate eBPF tools for deeper analysis
- [ ] Add automated testing scripts
- [ ] Support nstat command (delta statistics)
- [ ] JSON output implementation (flag exists but not implemented)

## References

- ss(8) man page
- netstat(8) man page
- TCP RFC 793, 1323, 5681, 6937 (TLP)
- Linux kernel TCP implementation
- BCC/eBPF performance tools
- [TCP Performance Analysis Guide](https://www.kernel.org/doc/Documentation/networking/tcp.txt)
- [Linux TCP Statistics Documentation](https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt)

## Test Results Summary

**Test Environment:**
- Host: smartx@192.168.70.31
- Service: ZooKeeper (port 2181)
- Kernel: openEuler 4.19.90

**Key Findings:**
- Total retrans: 59.5M (0.027% ratio) - Acceptable
- **TLP ratio: 41.3% - TOO HIGH** (indicates small rwnd)
- Fast retransmit: 55.5% - Normal network loss
- Lost retrans: 3.5M - Path quality issue
- Listen queue overflow: 28.7M - CRITICAL issue

**Actions Taken:**
- Detected receive window bottleneck via TLP ratio
- Identified listen queue overflow issue
- Provided specific tuning recommendations
