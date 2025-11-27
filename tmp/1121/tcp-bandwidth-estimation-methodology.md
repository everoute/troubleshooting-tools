# TCP Bandwidth Estimation Methodology

## 1. SRTT (Smoothed RTT) Calculation

### 1.1 Kernel Storage Format

From `include/linux/tcp.h:256`:
```c
u32 srtt_us;    /* smoothed round trip time << 3 in usecs */
u32 mdev_us;    /* medium deviation */
```

**Key point**: Kernel stores scaled values for integer arithmetic precision.

| Variable | Storage | Actual Value |
|----------|---------|--------------|
| `srtt_us` | actual_srtt × 8 | `srtt_us >> 3` |
| `mdev_us` | actual_mdev × 4 | `mdev_us >> 2` |

### 1.2 ss Output Conversion

From `net/ipv4/tcp.c:3247-3248`:
```c
info->tcpi_rtt = tp->srtt_us >> 3;      // ss displays this as "rtt"
info->tcpi_rttvar = tp->mdev_us >> 2;   // ss displays this as "rttvar"
```

**Conclusion**: `ss` shows the actual SRTT value in microseconds (after dividing by 8).

### 1.3 SRTT EWMA Update Algorithm

From `net/ipv4/tcp_input.c:725-787` (Jacobson 1988):

```c
static void tcp_rtt_estimator(struct sock *sk, long mrtt_us)
{
    struct tcp_sock *tp = tcp_sk(sk);
    long m = mrtt_us; /* RTT measurement */
    u32 srtt = tp->srtt_us;

    if (srtt != 0) {
        m -= (srtt >> 3);    /* m = error = new_rtt - srtt/8 */
        srtt += m;           /* srtt = srtt + error */
                             /* equivalent to: srtt = 7/8*srtt + 1/8*new_rtt */
        // ... mdev update ...
    } else {
        /* First measurement */
        srtt = m << 3;       /* srtt = new_rtt * 8 */
    }
    tp->srtt_us = max(1U, srtt);
}
```

### 1.4 EWMA Formula

```
SRTT_new = (1 - α) × SRTT_old + α × RTT_sample

Where α = 1/8 = 0.125

Expanded:
  SRTT = 7/8 × SRTT + 1/8 × new_measurement
```

**Characteristics**:
- Exponentially Weighted Moving Average (EWMA)
- New sample weight: 1/8 (12.5%)
- Historical weight: 7/8 (87.5%)
- Convergence: ~8 samples to reach new steady state
- Smoothing: Reduces impact of single RTT spikes

### 1.5 Why Scale by 8?

```
Problem: Integer division truncation loses precision

Without scaling:
  srtt = 7/8 * srtt + 1/8 * m
  Integer division of small numbers loses precision

With 8x scaling:
  srtt_us stores "actual_srtt × 8"
  Calculation: srtt += (m - srtt>>3)
  Equivalent to: srtt×8 = 7×srtt + m
  Display: srtt_us >> 3 restores actual value

Result: Better precision in integer arithmetic
```

---

## 2. Bandwidth Estimation Formula

### 2.1 Correct Formula

```
Est.BW = min(unacked × MSS / RTT, cwnd × MSS / RTT)
       = min(unacked, cwnd) × MSS / RTT
```

Where:
- `unacked`: Actual in-flight packets (from ss output)
- `cwnd`: Congestion window (maximum allowed in-flight)
- `MSS`: Maximum Segment Size (typically 1448 bytes)
- `RTT`: Round-trip time from ss (= SRTT)

### 2.2 Why Use min()?

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Bandwidth Constraints                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  cwnd × MSS / RTT:                                                  │
│    - Theoretical MAXIMUM allowed by congestion control              │
│    - Upper bound, may not be fully utilized                         │
│                                                                     │
│  unacked × MSS / RTT:                                               │
│    - ACTUAL sending rate based on in-flight data                    │
│    - Reflects real utilization                                      │
│                                                                     │
│  Taking min():                                                      │
│    - Ensures estimate doesn't exceed either constraint              │
│    - When unacked << cwnd: actual rate is low                       │
│    - When unacked ≈ cwnd: cwnd is the bottleneck                    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.3 Additional Constraint: NIC Rate Limit

For high-speed networks, also cap at physical NIC rate:

```
Est.BW = min(unacked × MSS / RTT, cwnd × MSS / RTT, NIC_rate)

Example with 25 Gbps NIC:
  cwnd_bw = min(cwnd × MSS × 8 / RTT, 25 Gbps)
```

### 2.4 Unit Conversion

```
BW (bps) = packets × MSS (bytes) × 8 (bits/byte) / RTT (seconds)

Example:
  unacked = 1000 packets
  MSS = 1448 bytes
  RTT = 1 ms = 0.001 s

  BW = 1000 × 1448 × 8 / 0.001
     = 11,584,000,000 bps
     = 11.584 Gbps
```

---

## 3. Practical Implementation

### 3.1 Data Extraction from ss Output

```bash
# Key fields from ss -ti output:
#   rtt:X.XXX        - SRTT in ms (tcpi_rtt / 1000)
#   cwnd:XXXX        - Congestion window in packets
#   unacked:XXXX     - In-flight packets (packets_out)
```

### 3.2 Calculation Steps

```python
MSS = 1448  # bytes
NIC_LIMIT = 25e9  # 25 Gbps in bps

for each sample:
    rtt_ms = float(rtt_field)
    cwnd = int(cwnd_field)
    unacked = int(unacked_field)

    # Calculate both bandwidths
    unacked_bw = unacked * MSS * 8 / (rtt_ms / 1000)  # bps
    cwnd_bw = cwnd * MSS * 8 / (rtt_ms / 1000)        # bps
    cwnd_bw = min(cwnd_bw, NIC_LIMIT)                 # cap at NIC rate

    # Estimated bandwidth is the minimum
    est_bw = min(unacked_bw, cwnd_bw)
    est_bw_gbps = est_bw / 1e9
```

### 3.3 Statistical Analysis

```python
# For a collection of samples:
avg_bw = sum(est_bw_list) / len(est_bw_list)
median_bw = sorted(est_bw_list)[len(est_bw_list) // 2]

# Median is often more robust against outliers
```

---

## 4. Validation Results

### 4.1 Test Environment Data (1121 Tests)

| Metric | Bind Test | Nobind Test |
|--------|-----------|-------------|
| Samples | 190 | 227 |
| **Avg Est. BW** | **16.61 Gbps** | **16.64 Gbps** |
| Median Est. BW | 19.22 Gbps | 19.78 Gbps |
| Actual iperf3 | ~13.5 Gbps | ~6.5 Gbps |
| Actual delivery_rate | ~15 Gbps | ~15 Gbps |

### 4.2 Analysis

**Bind Test**:
- Estimated (16.6 Gbps) close to measured iperf3 (~13.5 Gbps)
- Reasonable accuracy (~20% overestimate)

**Nobind Test**:
- Estimated (16.6 Gbps) significantly higher than iperf3 (~6.5 Gbps)
- Reason: Additional `rwnd_limited` factor (24.5%) not captured by this formula
- Need to account for receiver window constraints

### 4.3 Limitations

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Estimation Limitations                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Sampling timing:                                                │
│     - ss snapshots may not capture low points                       │
│     - unacked and RTT may not be perfectly synchronized             │
│                                                                     │
│  2. Not captured factors:                                           │
│     - rwnd_limited (receiver window constraints)                    │
│     - Retransmission overhead                                       │
│     - Application-level delays                                      │
│     - Virtualization overhead                                       │
│                                                                     │
│  3. RTT smoothing lag:                                              │
│     - SRTT uses EWMA with α=1/8                                     │
│     - Takes ~8 samples to converge to new RTT level                 │
│     - May underestimate impact of RTT spikes                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 5. RTT Variability Impact

### 5.1 Non-linear Effect

```
BW = constant / RTT

This 1/x relationship means:
- RTT doubling → BW halves
- RTT variability disproportionately impacts average throughput
- Jensen's inequality: E[1/RTT] ≤ 1/E[RTT]
```

### 5.2 Example from Test Data

```
Bind Test RTT distribution:
  Min RTT:    0.124 ms  → theoretical BW capped at NIC (25 Gbps)
  Avg RTT:    2.134 ms  → theoretical BW ~48 Gbps (capped at 25)
  Max RTT:   21.843 ms  → theoretical BW ~4.7 Gbps

High RTT samples (>5ms): 20.9% of total
  - These samples contribute disproportionately to low average
  - Even though 78.5% of samples hit 25 Gbps cap
```

### 5.3 Key Insight

```
High RTT variance (CV > 1.5) significantly degrades throughput:

1. Low RTT periods: BW capped at NIC rate (no extra benefit)
2. High RTT periods: BW drops dramatically (severe penalty)
3. Net effect: Average throughput << theoretical maximum

Solution approaches:
- Reduce RTT variance (network optimization)
- Reduce base RTT (shorter paths)
- Increase cwnd (if not already bottleneck)
```

---

## 6. Summary

### Key Formulas

```
# SRTT Update (Kernel)
SRTT_new = 7/8 × SRTT_old + 1/8 × RTT_sample

# ss Display
rtt_displayed = srtt_us >> 3  (microseconds)

# Bandwidth Estimation
Est.BW = min(unacked × MSS / RTT, cwnd × MSS / RTT, NIC_rate)
```

### Practical Guidelines

1. **Use min() of both constraints** for realistic estimate
2. **Median is more robust** than average for high-variance data
3. **Account for rwnd_limited** when receiver is slow
4. **RTT variability matters more than average RTT** for throughput
5. **SRTT lags behind actual RTT** by ~8 samples due to EWMA smoothing
