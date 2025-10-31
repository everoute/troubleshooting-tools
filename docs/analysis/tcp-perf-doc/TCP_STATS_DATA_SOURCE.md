# TCP Statistics Data Source Explanation

## Overview

The `--show-stats` option displays system-wide TCP statistics parsed from `netstat -s` command output. This document explains the data source, characteristics, and limitations.

## Data Source Chain

```
Kernel TCP Stack
    ↓
/proc/net/snmp (Tcp section)
/proc/net/netstat (TcpExt section)
    ↓
netstat -s command
    ↓
tcp_connection_analyzer.py parsing
    ↓
Categorized display output
```

### 1. Kernel Level

TCP statistics are maintained by the Linux kernel as **global cumulative counters**:

```c
// Linux kernel: include/uapi/linux/snmp.h
enum {
    TCP_MIB_RTOALGORITHM,
    TCP_MIB_RTOMIN,
    TCP_MIB_RTOMAX,
    TCP_MIB_MAXCONN,
    TCP_MIB_ACTIVEOPENS,      // Active connection openings
    TCP_MIB_PASSIVEOPENS,     // Passive connection openings
    TCP_MIB_ATTEMPTFAILS,     // Failed connection attempts
    TCP_MIB_ESTABRESETS,      // Connection resets received
    TCP_MIB_CURRESTAB,        // Connections currently established
    TCP_MIB_INSEGS,           // Segments received
    TCP_MIB_OUTSEGS,          // Segments sent
    TCP_MIB_RETRANSSEGS,      // Segments retransmitted
    TCP_MIB_INERRS,           // Bad segments received
    TCP_MIB_OUTRSTS,          // Resets sent
    // ...
};

// When TCP event occurs:
NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPFASTRETRANS);  // Fast retransmit
NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPLOSSPROBES);   // TLP probe
NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPLOSTRETRANSMIT); // Lost retrans
```

### 2. Proc Filesystem

Kernel exports these counters through `/proc`:

**`/proc/net/snmp` - Basic TCP statistics:**
```bash
$ cat /proc/net/snmp
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
Tcp: 1 200 120000 -1 468679325 631176597 22744207 15329010 1091 125985579572 223442701751 59552995 2289 110496037 0
```

**`/proc/net/netstat` - Extended TCP statistics (TcpExt):**
```bash
$ cat /proc/net/netstat
TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed ... TCPLossProbes TCPLossProbeRecovery TCPFastRetrans ...
TcpExt: 0 980 0 ... 24570526 224491 33066266 ...
```

### 3. netstat -s Command

The `netstat -s` command reads from `/proc/net/snmp` and `/proc/net/netstat` and formats the output:

```bash
$ netstat -s
Tcp:
    468679325 active connections openings
    631176597 passive connection openings
    22744207 failed connection attempts
    15329010 connection resets received
    1091 connections established
    125985579572 segments received
    223442701751 segments send out
    59552995 segments retransmited
    2289 bad segments received.
    110496037 resets sent
TcpExt:
    980 invalid SYN cookies received
    3624 resets received for embryonic SYN_RECV sockets
    29892 packets pruned from receive queue because of socket buffer overrun
    TCPLossProbes: 24570526
    TCPLossProbeRecovery: 224491
    33066266 fast retransmits
    5247586 retransmits in slow start
    TCPLostRetransmit: 3518392
    ...
```

### 4. tcp_connection_analyzer.py Parsing

The analyzer parses `netstat -s` output using regex patterns:

```python
stats_patterns = {
    # Retransmission types
    'segments_retransmitted': r'(\d+) segments retransmit',
    'fast_retransmits': r'(\d+) fast retransmits',
    'tcp_loss_probes': r'TCPLossProbes:\s*(\d+)',
    'tcp_lost_retransmit': r'TCPLostRetransmit:\s*(\d+)',

    # Stack drops
    'rcv_pruned': r'(\d+) packets pruned from receive queue because of socket buffer overrun',
    'listen_drops': r'(\d+) SYNs to LISTEN sockets dropped',
    # ... 40+ patterns total
}
```

## Data Characteristics

### ✅ System-Wide Scope

- **Applies to**: ALL TCP connections on the system
- **Cannot distinguish**: Individual connections
- **Use case**: Understanding overall system TCP behavior

Example:
```
fast_retransmits: 33,066,266
```
This is the **total count** of fast retransmits across **all TCP connections** since system boot.

### ✅ Cumulative Counters

- **Type**: Monotonically increasing counters
- **Reset**: Only on system reboot
- **Not delta**: Values are cumulative, not per-interval

Example over 3 samples at 5-second intervals:
```
Sample 1: segments_retransmitted = 59,552,995
Sample 2: segments_retransmitted = 59,553,357  (+362 in 5 seconds)
Sample 3: segments_retransmitted = 59,553,598  (+241 in 5 seconds)
```

To calculate delta (change per interval):
```
Delta = Sample2 - Sample1 = 59,553,357 - 59,552,995 = 362 retransmissions in 5s
Rate = 362 / 5 = 72.4 retransmissions per second
```

### ❌ Not Per-Connection

These statistics are **NOT** associated with specific connections:

| What You Can Know | What You Cannot Know |
|-------------------|---------------------|
| ✅ Total TLP probes system-wide | ❌ Which connections triggered TLP |
| ✅ Total fast retransmits | ❌ Which connections had fast retransmits |
| ✅ Overall retrans ratio | ❌ Per-connection retrans ratio |
| ✅ Stack drop events (rcv_pruned) | ❌ Which connections caused drops |

### ❌ No Historical Data

- Current implementation does not store previous values
- Cannot show trends or deltas automatically
- User must manually calculate differences between samples

## Comparison with Per-Connection Metrics

| Metric Type | Scope | Source | Granularity | Reset |
|-------------|-------|--------|-------------|-------|
| **System Stats** (`--show-stats`) | System-wide | `netstat -s` | All connections | System boot |
| **Connection Metrics** (default) | Per-connection | `ss -tinopm` | Single connection | Connection establishment |

### Example: Retransmissions

**System-wide** (`--show-stats`):
```
segments_retransmitted: 59,553,357  # All connections, since boot
fast_retransmits: 33,066,266        # All connections, since boot
tcp_loss_probes: 24,570,590         # All connections, since boot
```

**Per-connection** (default output):
```
Connection: 70.0.0.31:2181 -> 70.0.0.32:41572
retrans: 0/38  # Only this connection: 0 unacked, 38 total since connection start
```

## Use Cases

### 1. Identifying System-Wide Issues

**Good for:**
- "Are there many TLP probes happening on this host?" → Check TLP ratio
- "Is the listen queue overflowing?" → Check listen_drops
- "Are there socket buffer overflows?" → Check rcv_pruned

**Example:**
```bash
$ sudo python3 tcp_connection_analyzer.py \
    --show-stats \
    --role server \
    --local-port 2181
```

Output shows:
```
TLP probe retrans: 24,570,590 (41.3%) - Window too small
Listen drops: 28,747,070 - CRITICAL issue
```

**Action**: These are system-wide problems affecting many connections.

### 2. Monitoring System Health Over Time

**Good for:**
- Tracking retransmission rates over time
- Detecting degradation trends
- Correlating with application performance

**Example:**
```bash
# Continuous monitoring
$ sudo python3 tcp_connection_analyzer.py \
    --show-stats \
    --role server \
    --local-port 2181 \
    --interval 60 > stats.log

# Analyze growth rate
$ grep "segments_retransmitted" stats.log
segments_retransmitted: 59,552,995  # T0
segments_retransmitted: 59,553,357  # T0 + 60s: +362 retrans
segments_retransmitted: 59,553,598  # T0 + 120s: +241 retrans
```

### 3. Root Cause Analysis for Connection Issues

**Good for:**
- Understanding if high retrans is due to TLP, fast retrans, or timeouts
- Checking if drops are due to socket buffers or listen queue
- Validating tuning effectiveness

**Example:**
Connection has high retransmissions (38), check system stats:
```
TLP ratio: 41.3% → Root cause: receive window too small
Fast retrans: 55.5% → Also: some network packet loss
```

### 4. Comparing Across Hosts

**Good for:**
- Identifying which hosts have worse TCP behavior
- Finding infrastructure issues (e.g., one host has high listen_drops)

**Not good for:**
- Comparing specific connections (use per-connection metrics instead)

## Limitations

### 1. Cannot Isolate Specific Connections

If you have 1000 TCP connections and see:
```
fast_retransmits: 33,066,266
```

You cannot determine:
- Which of the 1000 connections contributed to this
- Whether it's evenly distributed or concentrated in few connections
- Whether it's related to your application or other services

**Solution**: Use per-connection analysis (default mode) to identify specific problematic connections.

### 2. Cumulative Nature Makes Short-Term Analysis Difficult

The counters accumulate since boot, so:
- Small changes are hard to see in large numbers
- Recent problems may be diluted by historical data
- Need manual delta calculation for rate analysis

**Example:**
```
Boot time total: 59,552,995 retransmissions
Current: 59,553,357 retransmissions
Recent 5s: +362 retransmissions (0.0006% increase, hard to notice)
```

**Solution**: Use continuous monitoring and calculate deltas manually, or use `nstat -az` for automatic delta calculation (future enhancement).

### 3. No Breakdown by Service/Application

Cannot distinguish:
- Your application's traffic vs system traffic
- Different services on the same host
- Client vs server role retransmissions

**Solution**: Use port/IP filtering in per-connection mode to focus on specific services.

### 4. Missing Some Useful Metrics

`netstat -s` / `/proc/net/netstat` does not provide:
- Per-connection retransmission types
- Retransmission timestamps
- Correlation with specific events
- Buffer usage history

**Solution**: Use eBPF tools for deeper per-connection analysis.

## Best Practices

### 1. Use Both System-Wide and Per-Connection Analysis

```bash
# Step 1: Check system-wide health
$ sudo python3 tcp_connection_analyzer.py \
    --show-stats \
    --role server \
    --local-port 2181

# If issues found, drill down to specific connections
$ sudo python3 tcp_connection_analyzer.py \
    --local-ip 70.0.0.31 \
    --remote-ip 70.0.0.32 \
    --local-port 2181 \
    --role server
```

### 2. Calculate Deltas for Rate Analysis

```bash
# Continuous monitoring
$ sudo python3 tcp_connection_analyzer.py \
    --show-stats \
    --role server \
    --local-port 2181 \
    --interval 60 \
    | grep -E "segments_retransmitted|segments_sent" \
    | awk '{print $3}' > /tmp/stats.txt

# Calculate delta
$ paste -d' ' <(head -2 /tmp/stats.txt) <(tail -2 /tmp/stats.txt) \
    | awk '{print "Retrans delta:", $3-$1, "Sent delta:", $4-$2}'
```

### 3. Baseline Your System

```bash
# Establish baseline during normal operation
$ sudo python3 tcp_connection_analyzer.py \
    --show-stats \
    --role server \
    --local-port 2181 \
    > baseline_stats.txt

# Compare during issues
$ sudo python3 tcp_connection_analyzer.py \
    --show-stats \
    --role server \
    --local-port 2181 \
    > issue_stats.txt

# Diff to see what changed significantly
$ diff baseline_stats.txt issue_stats.txt
```

### 4. Focus on Ratios, Not Absolute Numbers

Instead of:
```
segments_retransmitted: 59,553,357  # Is this high? Hard to tell.
```

Look at:
```
Retransmission Ratio: 0.0267% (59,553,357 / 223,443,516,551)  # This is acceptable (<1%)
TLP ratio: 41.3% of total retrans  # This IS high (>30% is concerning)
```

## Future Enhancements

### 1. Support for nstat Command

`nstat` provides automatic delta calculation:

```bash
$ nstat -az
#kernel
TcpPassiveOpens                 0                  0.0
TcpAttemptFails                 0                  0.0
TcpEstabResets                  0                  0.0
TcpRetransSegs                  362                0.0  # Delta since last call
TcpExtTCPFastRetrans            200                0.0  # Delta since last call
TcpExtTCPLossProbes             150                0.0  # Delta since last call
```

**Benefit**: Automatic rate calculation, clearer short-term trends.

### 2. Historical Data Storage

Store previous samples to show trends:

```
Retransmission Rate Trend:
  Last minute:  72 retrans/s
  Last 5 min:   68 retrans/s  (-5.6%)
  Last 15 min:  71 retrans/s  (+1.4%)
```

### 3. Per-Service Breakdown

Combine with connection tracking to attribute system-wide stats to specific services:

```
Service-Level Stats:
  ZooKeeper (port 2181):  TLP: 15M (61%), Fast retrans: 8M (32%)
  MySQL (port 3306):      TLP: 9M (38%), Fast retrans: 25M (59%)
```

## Summary

| Aspect | Description |
|--------|-------------|
| **Source** | `netstat -s` reading from `/proc/net/snmp` and `/proc/net/netstat` |
| **Scope** | System-wide, all TCP connections |
| **Type** | Cumulative counters since boot |
| **Granularity** | Cannot isolate individual connections |
| **Update** | Refreshed each monitoring interval (if `--interval` specified) |
| **Use Case** | Understand system-level TCP behavior and identify infrastructure issues |
| **Limitation** | Cannot pinpoint specific connections, requires manual delta calculation |
| **Best Practice** | Use with per-connection analysis for complete diagnosis |
