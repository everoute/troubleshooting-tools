# BCC Tools Research: RTT and Unacked Distribution Collection

## Research Date: 2024-11-27

## 1. Requirements Recap

We need per-packet granularity data to accurately estimate bandwidth:
- **RTT distribution**: Time-series histogram of SRTT values per connection
- **Unacked distribution**: Time-series histogram of in-flight packets per connection

Current ss-based sampling has limitations:
- Sampling interval too coarse (1s typical)
- Uses point-in-time values, not per-packet measurements
- Missing correlation between RTT and unacked at packet level

## 2. Existing Tools Analysis

### 2.1 Standard BCC tcprtt (iovisor/bcc)

**Location**: https://github.com/iovisor/bcc/blob/master/tools/tcprtt.py

**Mechanism**:
- Attaches kprobe to `tcp_rcv_established()`
- Reads `tp->srtt_us >> 3` from tcp_sock structure
- Outputs log2 histogram of RTT values

**Limitations**:
- RTT only, no unacked/in-flight data
- Single histogram, not time-series
- No per-connection breakdown by default

**Key Code**:
```c
int trace_tcp_rcv(struct pt_regs *ctx, struct sock *sk) {
    struct tcp_sock *ts = (struct tcp_sock *)sk;
    u32 srtt = ts->srtt_us >> 3;
    // histogram update...
}
```

### 2.2 MicroBPF Project (alvenwong/MicroBPF)

**Purpose**: TCP metrics for microservice performance diagnosis

**tcpack.py captures**:
- Flight size (packets sent but not ACKed)
- CWND, RWND
- Retransmission counts

**Mechanism**: Triggered by ACK events, captures tcp_sock fields

**Limitations**:
- Research prototype, not production-ready
- Event-based output (not histogram)
- No time-series histogram aggregation

### 2.3 This Repository's tcp_perf_observer.py

**Location**: measurement-tools/performance/system-network/tcp_perf_observer.py

**Features**:
- RTT histogram (log2 buckets)
- Connection latency histogram
- cwnd/ssthresh in detail events
- Rate-limited detail events

**Limitations**:
- No unacked/packets_out histogram
- Detail events throttled, not systematic
- cwnd only in high-RTT events

## 3. Kernel Data Structures (tcp_sock)

From linux/tcp.h, relevant fields:

```c
struct tcp_sock {
    u32 srtt_us;        /* smoothed RTT << 3 in usecs (line 292) */
    u32 packets_out;    /* Packets which are "in flight" (line 299) */
    u32 snd_cwnd;       /* Sending congestion window (line 320) */
    u32 snd_una;        /* First byte we want an ack for (line 230) */
    u32 snd_nxt;        /* Next sequence we send (line 213) */
    u32 mss_cache;      /* Cached effective mss (line 245) */
};
```

**Key insight**:
- `packets_out` directly gives in-flight packet count (what ss reports as "unacked")
- `snd_nxt - snd_una` gives in-flight bytes

## 4. Gap Analysis

| Requirement          | tcprtt | MicroBPF   | tcp_perf_observer |
|---------------------|--------|------------|-------------------|
| RTT histogram       | Yes    | No         | Yes               |
| Unacked histogram   | No     | Event-only | No                |
| Time-series output  | No     | No         | No                |
| Per-packet granularity | Yes | Yes        | Yes (sampled)     |
| Production-ready    | Yes    | No         | Yes               |
| Connection filtering| Yes    | Yes        | Yes               |

**Conclusion**: No existing tool provides both RTT and unacked histograms in time-series format.

## 5. Proposed Solution: tcp_rtt_inflight_hist.py

### 5.1 Design Goals

1. Capture SRTT and packets_out on every ACK event
2. Store in dual log2 histograms
3. Print time-series output at configurable intervals
4. Support IP/port filtering
5. Minimal overhead (kernel-side aggregation)

### 5.2 Kernel Attachment Point

**Best option**: `tcp_rcv_established()`
- Called on every received packet in ESTABLISHED state
- Has access to tcp_sock with all required fields
- Same as tcprtt (proven approach)

**Alternative**: `tcp_ack()` in tcp_input.c
- More specific to ACK processing
- But may not be kprobe-able on all kernels

### 5.3 Data Collection

```c
struct tcp_sock *tp = (struct tcp_sock *)sk;

// RTT: stored scaled by 8
u32 srtt_us = tp->srtt_us >> 3;

// In-flight packets
u32 inflight = tp->packets_out;

// Optional: in-flight bytes
// u32 inflight_bytes = tp->snd_nxt - tp->snd_una;
```

### 5.4 Histogram Structure

Two BPF_HISTOGRAM maps:
- `rtt_hist`: log2 histogram of SRTT (microseconds)
- `inflight_hist`: log2 histogram of packets_out

### 5.5 Time-Series Output Format

Each interval prints:
```
==== Interval @ HH:MM:SS ====
[RTT (us)]
     usecs               : count     distribution
         0 -> 1          : 0        |                    |
         2 -> 3          : 0        |                    |
         4 -> 7          : 12       |**                  |
         ...

[In-flight (packets)]
     packets             : count     distribution
         0 -> 1          : 0        |                    |
         2 -> 3          : 45       |*****               |
         4 -> 7          : 234      |********************|
         ...
```

### 5.6 Bandwidth Estimation Integration

With histograms, we can compute:
- Mean RTT: weighted average from RTT histogram
- Mean in-flight: weighted average from inflight histogram
- Estimated BW = mean_inflight * MSS / mean_RTT

Better yet, compute percentile distributions for robust estimation.

## 6. Implementation Plan

1. Create new file: `measurement-tools/performance/system-network/tcp_rtt_inflight_hist.py`
2. Base structure on tcp_perf_observer.py and tcprtt.py
3. Dual histogram collection with interval printing
4. Add --raw-output option for machine-readable format
5. Test with iperf3 workload

## 7. References

- [tcprtt.py source](https://github.com/iovisor/bcc/blob/master/tools/tcprtt.py)
- [MicroBPF project](https://github.com/alvenwong/MicroBPF)
- [BCC tutorial](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md)
- Linux kernel: include/linux/tcp.h (tcp_sock structure)
