# TCP 性能分析报告

**日期**: 2025-11-26
**测试环境**: 1.1.1.3 (客户端) <-> 1.1.1.2 (服务端)
**带宽**: 25 Gbps
**测试工具**: iperf3 (端口 5201)

---

## 1. 分析命令

### 1.1 TCP Socket 分析

```bash
# Bind 测试 - 摘要模式
python3 traffic-analyzer/traffic-analyzer/tcpsocket_analyzer.py \
    --mode summary \
    --client-log .tmp/1121/1121-client/bind-client.log \
    --server-log .tmp/1121/1121-server/bind-server.log \
    --bandwidth 25gbps

# Bind 测试 - 详细模式
python3 traffic-analyzer/traffic-analyzer/tcpsocket_analyzer.py \
    --mode detailed \
    --client-log .tmp/1121/1121-client/bind-client.log \
    --server-log .tmp/1121/1121-server/bind-server.log \
    --bandwidth 25gbps

# Nobind 测试 - 摘要模式
python3 traffic-analyzer/traffic-analyzer/tcpsocket_analyzer.py \
    --mode summary \
    --client-log .tmp/1121/1121-client/nobind-client.log \
    --server-log .tmp/1121/1121-server/nobind-server.log \
    --bandwidth 25gbps

# Nobind 测试 - 详细模式
python3 traffic-analyzer/traffic-analyzer/tcpsocket_analyzer.py \
    --mode detailed \
    --client-log .tmp/1121/1121-client/nobind-client.log \
    --server-log .tmp/1121/1121-server/nobind-server.log \
    --bandwidth 25gbps
```

### 1.2 PCAP 分析

```bash
# 客户端 PCAP - 摘要模式
python3 traffic-analyzer/traffic-analyzer/pcap_analyzer.py \
    --mode summary \
    --pcap .tmp/1121/1121-client/client.pcap

# 客户端 PCAP - 详细模式
python3 traffic-analyzer/traffic-analyzer/pcap_analyzer.py \
    --mode details \
    --pcap .tmp/1121/1121-client/client.pcap

# 服务端 PCAP - 摘要模式
python3 traffic-analyzer/traffic-analyzer/pcap_analyzer.py \
    --mode summary \
    --pcap .tmp/1121/1121-server/server.pcap

# 服务端 PCAP - 详细模式
python3 traffic-analyzer/traffic-analyzer/pcap_analyzer.py \
    --mode details \
    --pcap .tmp/1121/1121-server/server.pcap
```

---

## 2. 原始分析结果

### 2.1 Bind 测试 - TCP Socket 摘要

```
======================================================================
TCP SOCKET SUMMARY ANALYSIS
======================================================================

Connection: 1.1.1.3:39428 -> 1.1.1.2:5201
Summary: Bandwidth 25.00 Gbps, Utilization avg=61.8% Primary Bottleneck: UNKNOWN

--- Window Analysis ---
BDP: 6668079 bytes (6.36 MB)
Optimal CWND: 4605.03 packets
Actual CWND: 8864.75 packets
CWND Utilization: 192.5%
CWND Adequacy Distribution (191 samples):
  UNDER (ratio < 0.8):   36 samples ( 18.8%) - Actual CWND < Optimal
  OVER  (ratio > 1.0):  150 samples ( 78.5%) - Actual CWND > Optimal
Unacked/CWND Utilization (191 samples):
  LOW     (ratio < 0.9):   153 samples ( 80.1%) - Underutilized
  OK      (0.9 <= r <= 1):  34 samples ( 17.8%) - Near optimal
  LIMITED (ratio > 1.0):     4 samples (  2.1%) - CWND limited
  Mean unacked/cwnd: 27.0%
cwnd/ssthresh ratio: <1 0.0% , >=1 100.0%

Client CWND Statistics:
  Min: 6016 pkts, Max: 11620 pkts, Mean: 8865 pkts
  Std: 1047 pkts, CV: 0.118
  P50: 9039 pkts, P95: 10632 pkts, P99: 11522 pkts

Server CWND Statistics:
  Min: 10 pkts, Max: 10 pkts, Mean: 10 pkts
  Std: 0 pkts, CV: 0.000
  P50: 10 pkts, P95: 10 pkts, P99: 10 pkts

RWND Analysis:
  Min: 14480 bytes, Avg: 14480 bytes
  RWND Limited: 0.0% of time
RWND Adequacy Distribution (191 samples):
  UNDER (ratio < 0.8):  191 samples (100.0%) - RWND < Optimal (BDP)
  OVER  (ratio > 1.0):    0 samples (  0.0%) - RWND > Optimal (BDP)
SSThresh: avg=7094 pkts, cwnd/ssthresh=1.25

--- Rate Analysis ---
Bandwidth: 25.00 Gbps
Bandwidth Utilization: avg=61.8%, peak=109.0%
Pacing/Delivery Ratio: 0.20
Rate Stability: 0.46

Pacing Rate Statistics:
  Min: 0.00 bps, Max: 33.26 Gbps, Mean: 3.04 Gbps
  Std: 7.47 Gbps, CV: 2.458
  P50: 0.00 bps, P95: 22.18 Gbps, P99: 26.81 Gbps

Delivery Rate Statistics:
  Min: 50.00 Mbps, Max: 27.26 Gbps, Mean: 15.45 Gbps
  Std: 8.40 Gbps, CV: 0.543
  P50: 18.47 Gbps, P95: 25.12 Gbps, P99: 26.63 Gbps

Send Rate Statistics:
  Min: 3.51 Gbps, Max: 865.15 Gbps, Mean: 359.41 Gbps
  Std: 249.39 Gbps, CV: 0.694
  P50: 436.84 Gbps, P95: 718.14 Gbps, P99: 789.48 Gbps

--- RTT Analysis ---
Client RTT Statistics:
  Min: 0.12 ms, Max: 21.84 ms, Mean: 2.13 ms
  Std: 3.95 ms, CV: 1.852
  P50: 0.23 ms, P95: 8.70 ms, P99: 17.95 ms
Server RTT Statistics:
  Min: 0.07 ms, Max: 0.07 ms, Mean: 0.07 ms
RTT Stability: HIGHLY_VARIABLE, Jitter: 3.95 ms
RTT Trend: STABLE
RTT Diff (client-server): 2.06 ms (SYMMETRIC)

--- Buffer Analysis ---
socket_tx_buffer (client): 134217728 bytes (128.00 MB)
socket_tx_queue pressure: 0.1%
socket_tx_buffer limited: 0.0% of time
socket_write_queue (client) Mean: 103974118 bytes
socket_dropped (client): Mean 0 packets

socket_rx_buffer (server): 134217728 bytes (128.00 MB)
socket_rx_queue pressure: 4.9%
socket_rx_buffer limited: 0.0% of time
socket_dropped (server): Min: 8, Max: 12, Mean: 10 packets

--- Limited & Busy Statistics ---
cwnd_limited_ratio: client 0.0%, server 0.0%
rwnd_limited_ratio: client 0.0%, server 0.0%
sndbuf_limited_ratio: client 0.0%, server 0.0%

--- Retransmission Analysis ---
Client Total Retransmissions: 12044
Client Retrans Rate (packets): 0.005%
Client Retrans Bytes Rate: 0.003%
Client Spurious Retrans: 0 (0.0% of retrans)
Client DSACK duplicates (total): 4

Server Total Retransmissions: 0

--- Bottleneck Analysis ---
Primary Bottleneck: UNKNOWN (confidence=0.0%)
```

### 2.2 Bind 测试 - TCP Socket 详细

```
======================================================================
TCP SOCKET DETAILED ANALYSIS
======================================================================

Connection: 1.1.1.3:39428 -> 1.1.1.2:5201

--- Summary ---
Bandwidth: 25.00 Gbps
Primary Bottleneck: UNKNOWN

--- Window Detailed Analysis ---
Inflight Near CWND (>=95%): 19.9% of time
RWND < CWND: 0.0% of time
TX Queue Near Buffer (>=95%): 0.0% of time
Recovery Events: 0
Congestion Avoidance Ratio: 100.0%

--- Limited & Busy Statistics ---
cwnd_limited_ratio: client 0.0%, server 0.0%
rwnd_limited_ratio: client 0.0%, server 0.0%
sndbuf_limited_ratio: client 0.0%, server 0.0%

--- Rate Detailed Analysis ---
Pacing Trend: STABLE
Delivery Trend: STABLE
Pacing Limited: 85.3% of time
Network Limited: 20.4% of time

Correlations:
  cwnd_delivery: 0.016
  rtt_delivery: -0.725
  pacing_delivery: -0.517

--- Retransmission Detailed Analysis ---
Total Retransmissions (client): 12044
Retrans Rate (packets): 0.005%
Retrans Bytes Rate: 0.003%
Spurious Retrans: 0 (0.0% of retrans)
DSACK duplicates: 4
Burst Events: 0

--- Buffer Detailed Analysis ---
Send path (client):
  socket_tx_queue/socket_tx_buffer pressure: Mean 0.1%
  socket_write_queue: Mean 103974118 bytes

Recv path (server):
  socket_rx_queue/socket_rx_buffer pressure: Mean 4.9%, Max 28.2%
  socket_dropped: Mean 10 packets

Combined indicators:
  High Pressure Ratio (send path >90% buffer): 0.0%
  Buffer Exhaustion Events (send path >99% buffer): 0
```

### 2.3 Nobind 测试 - TCP Socket 摘要

```
======================================================================
TCP SOCKET SUMMARY ANALYSIS
======================================================================

Connection: 1.1.1.3:48162 -> 1.1.1.2:5201
Summary: Bandwidth 25.00 Gbps, Utilization avg=62.4% Primary Bottleneck: RWND_LIMITED

--- Window Analysis ---
BDP: 4033433 bytes (3.85 MB)
Optimal CWND: 2785.52 packets
Actual CWND: 3346.28 packets
CWND Utilization: 120.1%
CWND Adequacy Distribution (239 samples):
  UNDER (ratio < 0.8):   31 samples ( 13.0%) - Actual CWND < Optimal
  OVER  (ratio > 1.0):  205 samples ( 85.8%) - Actual CWND > Optimal
Unacked/CWND Utilization (239 samples):
  LOW     (ratio < 0.9):   208 samples ( 87.0%) - Underutilized
  OK      (0.9 <= r <= 1):  21 samples (  8.8%) - Near optimal
  LIMITED (ratio > 1.0):    10 samples (  4.2%) - CWND limited
  Mean unacked/cwnd: 27.9%
cwnd/ssthresh ratio: <1 0.0% , >=1 100.0%

Client CWND Statistics:
  Min: 1636 pkts, Max: 9099 pkts, Mean: 3346 pkts
  Std: 1582 pkts, CV: 0.473
  P50: 2864 pkts, P95: 7072 pkts, P99: 8449 pkts

Server CWND Statistics:
  Min: 10 pkts, Max: 10 pkts, Mean: 10 pkts

RWND Analysis:
  Min: 14480 bytes, Avg: 14480 bytes
  RWND Limited: 0.0% of time
RWND Adequacy Distribution (239 samples):
  UNDER (ratio < 0.8):  239 samples (100.0%) - RWND < Optimal (BDP)
  OVER  (ratio > 1.0):    0 samples (  0.0%) - RWND > Optimal (BDP)
SSThresh: avg=2576 pkts, cwnd/ssthresh=1.30

--- Rate Analysis ---
Bandwidth: 25.00 Gbps
Bandwidth Utilization: avg=62.4%, peak=119.6%
Pacing/Delivery Ratio: 0.11
Rate Stability: 0.46

Pacing Rate Statistics:
  Min: 0.00 bps, Max: 33.38 Gbps, Mean: 1.68 Gbps
  Std: 5.48 Gbps, CV: 3.273
  P50: 0.00 bps, P95: 12.92 Gbps, P99: 28.30 Gbps

Delivery Rate Statistics:
  Min: 60.00 Mbps, Max: 29.91 Gbps, Mean: 15.60 Gbps
  Std: 8.35 Gbps, CV: 0.536
  P50: 17.91 Gbps, P95: 25.57 Gbps, P99: 27.06 Gbps

Send Rate Statistics:
  Min: 1.88 Gbps, Max: 552.20 Gbps, Mean: 136.72 Gbps
  Std: 105.89 Gbps, CV: 0.774
  P50: 115.00 Gbps, P95: 368.25 Gbps, P99: 473.01 Gbps

--- RTT Analysis ---
Client RTT Statistics:
  Min: 0.12 ms, Max: 29.37 ms, Mean: 1.29 ms
  Std: 3.10 ms, CV: 2.404
  P50: 0.26 ms, P95: 7.97 ms, P99: 14.42 ms
Server RTT Statistics:
  Min: 0.06 ms, Max: 0.06 ms, Mean: 0.06 ms
RTT Stability: HIGHLY_VARIABLE, Jitter: 3.10 ms
RTT Diff (client-server): 1.23 ms (SYMMETRIC)

--- Buffer Analysis ---
socket_tx_buffer (client): 84663808 bytes (80.74 MB)
socket_tx_queue pressure: 0.2%
socket_tx_buffer limited: 0.0% of time
socket_write_queue (client) Mean: 62530242 bytes
socket_dropped (client): Mean 0 packets

socket_rx_buffer (server): 131823742 bytes (125.72 MB)
socket_rx_queue pressure: 19.5%
socket_rx_buffer limited: 2.6% of time
socket_dropped (server): Min: 278, Max: 449, Mean: 374 packets

--- Limited & Busy Statistics ---
cwnd_limited_ratio: client 0.0%, server 0.0%
rwnd_limited_ratio: client 24.5%, server 0.0%
sndbuf_limited_ratio: client 0.0%, server 0.0%

--- Retransmission Analysis ---
Client Total Retransmissions: 1021
Client Retrans Rate (packets): 0.000%
Client Retrans Bytes Rate: 0.000%
Client Spurious Retrans: 18 (1.8% of retrans)
Client DSACK duplicates (total): 100

Server Total Retransmissions: 0

--- Bottleneck Analysis ---
Primary Bottleneck: RWND_LIMITED (confidence=24.5%)
Limiting Factors: RWND_LIMITED
```

### 2.4 Nobind 测试 - TCP Socket 详细

```
======================================================================
TCP SOCKET DETAILED ANALYSIS
======================================================================

Connection: 1.1.1.3:48162 -> 1.1.1.2:5201

--- Summary ---
Bandwidth: 25.00 Gbps
Primary Bottleneck: RWND_LIMITED

--- Window Detailed Analysis ---
Inflight Near CWND (>=95%): 12.6% of time
RWND < CWND: 0.0% of time
TX Queue Near Buffer (>=95%): 0.0% of time
Recovery Events: 3
Average Recovery Time: 84.19s
Congestion Avoidance Ratio: 100.0%

--- Limited & Busy Statistics ---
cwnd_limited_ratio: client 0.0%, server 0.0%
rwnd_limited_ratio: client 24.5%, server 0.0%
sndbuf_limited_ratio: client 0.0%, server 0.0%

--- Rate Detailed Analysis ---
Pacing Trend: INCREASING
Delivery Trend: STABLE
Pacing Limited: 90.0% of time
Network Limited: 23.4% of time

Correlations:
  cwnd_delivery: -0.114
  rtt_delivery: -0.467
  pacing_delivery: -0.189

--- Retransmission Detailed Analysis ---
Total Retransmissions (client): 1021
Retrans Rate (packets): 0.000%
Retrans Bytes Rate: 0.000%
Spurious Retrans: 18 (1.8% of retrans)
DSACK duplicates: 100
Burst Events: 0

--- Buffer Detailed Analysis ---
Send path (client):
  socket_tx_queue/socket_tx_buffer pressure: Mean 0.2%
  socket_write_queue: Mean 62530242 bytes

Recv path (server):
  socket_rx_queue/socket_rx_buffer pressure: Mean 19.5%, Max 95.6%, P99 95.2%
  socket_dropped: Mean 374 packets

Combined indicators:
  High Pressure Ratio (send path >90% buffer): 0.0%
  Buffer Exhaustion Events (send path >99% buffer): 0
```

### 2.5 客户端 PCAP - 摘要

```
============================================================
PCAP SUMMARY ANALYSIS
============================================================

File: client.pcap
Total Packets: 20000
Duration: 1.708s

------------------------------------------------------------
LAYER 2 STATISTICS (Data Link)
------------------------------------------------------------
Total Frames: 20000

Ethernet Types:
  IPv4: 20000 (100.00%)

Frame Size Distribution:
  64-127 bytes: 9976 (49.88%)
  >=1518 bytes: 9442 (47.21%)
  1024-1517 bytes: 305 (1.52%)
  512-1023 bytes: 274 (1.37%)
  128-255 bytes: 3 (0.01%)

------------------------------------------------------------
LAYER 3 STATISTICS (Network)
------------------------------------------------------------
Protocol Distribution:
  IPERF3: 10090 (50.45%)
  TCP: 9910 (49.55%)

------------------------------------------------------------
LAYER 4 STATISTICS (Transport)
------------------------------------------------------------
Total Traffic: 561.59 MB

TCP: 9910 packets, 638.73 KB
Other: 10090 packets, 560.97 MB

------------------------------------------------------------
TIME-SERIES STATISTICS
------------------------------------------------------------
Average Packet Rate: 6666.67 pps
Peak Packet Rate: 12340.00 pps
Average Throughput: 1.57 Gbps
Peak Throughput: 2.84 Gbps

------------------------------------------------------------
TOP TALKERS
------------------------------------------------------------
Top Senders:
  1.1.1.3: 560.97 MB
  1.1.1.2: 638.73 KB
```

### 2.6 客户端 PCAP - 详细

```
============================================================
PCAP DETAILED ANALYSIS
============================================================

Total Flows: 1
TCP Flows: 1

--- Flow 1 ---
1.1.1.3:44404 -> 1.1.1.2:5201
Packets: 20000, Bytes: 561.59 MB, Duration: 1.708s
Retransmissions: 0/20000 (0.00%)
  Fast Retrans: 0, Timeout Retrans: 0, Spurious: 0
DupACKs: 0 (rate: 0.00%), Max consecutive: 0
Zero Windows: 0 events
SACK: Not enabled
TCP Features: SACK=No, WScale=No, Timestamps=No, MSS=1460
```

### 2.7 服务端 PCAP - 摘要

```
============================================================
PCAP SUMMARY ANALYSIS
============================================================

File: server.pcap
Total Packets: 20000
Duration: 1.602s

------------------------------------------------------------
LAYER 2 STATISTICS (Data Link)
------------------------------------------------------------
Total Frames: 20000

Frame Size Distribution:
  >=1518 bytes: 10068 (50.34%)
  64-127 bytes: 9931 (49.66%)
  1024-1517 bytes: 1 (0.01%)

------------------------------------------------------------
LAYER 3 STATISTICS (Network)
------------------------------------------------------------
Protocol Distribution:
  IPERF3: 10069 (50.34%)
  TCP: 9931 (49.66%)

------------------------------------------------------------
LAYER 4 STATISTICS (Transport)
------------------------------------------------------------
Total Traffic: 623.34 MB

TCP: 9931 packets, 640.08 KB
Other: 10069 packets, 622.71 MB

------------------------------------------------------------
TIME-SERIES STATISTICS
------------------------------------------------------------
Average Packet Rate: 10000.00 pps
Peak Packet Rate: 10459.00 pps
Average Throughput: 2.61 Gbps
Peak Throughput: 2.72 Gbps

------------------------------------------------------------
TOP TALKERS
------------------------------------------------------------
Top Senders:
  1.1.1.3: 622.71 MB
  1.1.1.2: 640.08 KB
```

### 2.8 服务端 PCAP - 详细

```
============================================================
PCAP DETAILED ANALYSIS
============================================================

Total Flows: 1
TCP Flows: 1

--- Flow 1 ---
1.1.1.3:44404 -> 1.1.1.2:5201
Packets: 20000, Bytes: 623.34 MB, Duration: 1.602s
Retransmissions: 0/20000 (0.00%)
  Fast Retrans: 0, Timeout Retrans: 0, Spurious: 0
DupACKs: 0 (rate: 0.00%), Max consecutive: 0
Zero Windows: 0 events
SACK: Not enabled
TCP Features: SACK=No, WScale=No, Timestamps=No, MSS=1460
```

---

## 3. 对比分析

### 3.1 TCP Socket 分析: Bind vs Nobind

| 指标 | Bind 测试 | Nobind 测试 | 差异 |
|------|-----------|-------------|------|
| **连接** | 1.1.1.3:39428 -> 1.1.1.2:5201 | 1.1.1.3:48162 -> 1.1.1.2:5201 | 源端口不同 |
| **采样数** | 客户端: 191, 服务端: 190 | 客户端: 239, 服务端: 234 | - |
| **带宽利用率** | 平均 61.8%, 峰值 109.0% | 平均 62.4%, 峰值 119.6% | 相近 |
| **主要瓶颈** | **未知** | **接收窗口受限** | **不同** |

#### 窗口分析

| 指标 | Bind | Nobind | 备注 |
|------|------|--------|------|
| BDP (内核) | 6.36 MB | 3.85 MB | Bind 更高 |
| 最优 CWND | 4605 pkts | 2786 pkts | - |
| 实际 CWND (均值) | 8865 pkts | 3346 pkts | Bind 是 Nobind 的 2.6 倍 |
| CWND 利用率 | 192.5% | 120.1% | 均 > 100% (充足) |
| CWND 变异系数 | 0.118 (稳定) | 0.473 (不稳定) | Nobind 波动大 4 倍 |
| CWND 范围 | 6016-11620 | 1636-9099 | Nobind 范围更宽 |

#### CWND 充足性分布 (按采样点)

| 状态 | Bind (191 采样) | Nobind (239 采样) | 备注 |
|------|-----------------|-------------------|------|
| 不足 (ratio < 0.8) | 36 (18.8%) | 31 (13.0%) | CWND < 最优值 |
| 充足 (ratio > 1.0) | 150 (78.5%) | 205 (85.8%) | CWND > 最优值 |

#### Unacked/CWND 利用率分布 (按采样点)

| 状态 | Bind (191 采样) | Nobind (239 采样) | 备注 |
|------|-----------------|-------------------|------|
| 低 (ratio < 0.9) | 153 (80.1%) | 208 (87.0%) | 未充分利用 |
| 正常 (0.9 <= r <= 1.0) | 34 (17.8%) | 21 (8.8%) | 接近最优 |
| 受限 (ratio > 1.0) | 4 (2.1%) | 10 (4.2%) | **CWND 受限** |
| 均值 unacked/cwnd | 27.0% | 27.9% | 利用率相近 |

#### RWND 充足性分布 (按采样点)

| 状态 | Bind (191 采样) | Nobind (239 采样) | 备注 |
|------|-----------------|-------------------|------|
| 不足 (ratio < 0.8) | 191 (100.0%) | 239 (100.0%) | RWND < BDP (始终) |
| 充足 (ratio > 1.0) | 0 (0.0%) | 0 (0.0%) | RWND > BDP (从不) |

#### 速率分析

| 指标 | Bind | Nobind |
|------|------|--------|
| 投递速率均值 | 15.45 Gbps | 15.60 Gbps |
| 投递速率 P99 | 26.63 Gbps | 27.06 Gbps |
| Pacing 速率均值 | 3.04 Gbps | 1.68 Gbps |

#### RTT 分析

| 指标 | Bind | Nobind |
|------|------|--------|
| 客户端 RTT 均值 | 2.13 ms | 1.29 ms |
| 客户端 RTT P99 | 17.95 ms | 14.42 ms |
| 客户端 RTT 变异系数 | 1.852 | 2.404 |
| RTT 稳定性 | 高度波动 | 高度波动 |

#### 缓冲区分析

| 指标 | Bind | Nobind | 问题 |
|------|------|--------|------|
| TX 缓冲区大小 | 128 MB | 80.74 MB | Nobind 小 37% |
| TX 缓冲区压力 | 0.1% | 0.2% | 相近 |
| RX 缓冲区大小 | 128 MB | 125.72 MB | 相近 |
| **RX 缓冲区压力** | 4.9% | **19.5%** | **Nobind 高 4 倍** |
| **RX 缓冲区受限** | 0.0% | **2.6%** | **Nobind 受限** |

#### 受限统计 (内核指标)

| 指标 | Bind | Nobind | 问题 |
|------|------|--------|------|
| **CWND 受限** | **0.0%** | **0.0%** | 均未受 CWND 限制 |
| **RWND 受限** | 0.0% | **24.5%** | **Nobind 接收端受限** |
| Sndbuf 受限 | 0.0% | 0.0% | - |

#### 详细分析差异

| 指标 | Bind | Nobind |
|------|------|--------|
| 在途接近 CWND (>=95%) | 19.9% | 12.6% |
| 恢复事件 | 0 | 3 |
| Pacing 受限 | 85.3% | 90.0% |
| 网络受限 | 20.4% | 23.4% |
| RTT-投递率相关性 | -0.725 | -0.467 |

#### 丢包与重传

| 指标 | Bind | Nobind | 问题 |
|------|------|--------|------|
| 客户端重传 | 12044 (0.005%) | 1021 (0.000%) | Bind 重传更多 |
| **服务端丢包** | 8-12 pkts | **278-449 pkts** | **Nobind 高 30 倍以上** |
| 虚假重传 | 0 | 18 (1.8%) | - |
| DSACK 重复 | 4 | 100 | Nobind 更多 |

### 3.2 PCAP 分析汇总

| 指标 | 客户端 PCAP | 服务端 PCAP |
|------|-------------|-------------|
| 总包数 | 20000 | 20000 |
| 时长 | 1.708s | 1.602s |
| 总流量 | 561.59 MB | 623.34 MB |
| 平均吞吐量 | 1.57 Gbps | 2.61 Gbps |
| 峰值吞吐量 | 2.84 Gbps | 2.72 Gbps |
| 平均包速率 | 6666.67 pps | 10000.00 pps |
| 重传 | 0 | 0 |
| TCP 特性 | SACK=No, WScale=No, Timestamps=No | 相同 |

---

## 4. 关键发现

### 4.1 瓶颈分析

| 测试 | 主要瓶颈 | 置信度 | 证据 |
|------|----------|--------|------|
| **Bind** | **未知** | 0% | cwnd_limited=0%, rwnd_limited=0%, 内核未报告限制 |
| **Nobind** | **接收窗口受限** | 24.5% | rwnd_limited=24.5%, server_dropped=374 pkts |

### 4.2 CWND/RWND 充足性分析 (使用内核 BDP)

| 测试 | BDP (内核) | 最优 CWND | 实际 CWND | 利用率 |
|------|------------|-----------|-----------|--------|
| **Bind** | 6.36 MB | 4605 pkts | 8865 pkts | 192.5% |
| **Nobind** | 3.85 MB | 2786 pkts | 3346 pkts | 120.1% |

#### CWND 充足性分布

| 测试 | 采样数 | 不足 (<0.8) | 充足 (>1.0) | 分析 |
|------|--------|-------------|-------------|------|
| **Bind** | 191 | 36 (18.8%) | 150 (78.5%) | 大多数采样点 CWND 充足 |
| **Nobind** | 239 | 31 (13.0%) | 205 (85.8%) | 大多数采样点 CWND 充足 |

#### RWND 充足性分布

| 测试 | 采样数 | 不足 (<0.8) | 充足 (>1.0) | 分析 |
|------|--------|-------------|-------------|------|
| **Bind** | 191 | 191 (100.0%) | 0 (0.0%) | **RWND 始终小于 BDP** |
| **Nobind** | 239 | 239 (100.0%) | 0 (0.0%) | **RWND 始终小于 BDP** |

#### Unacked/CWND 利用率分布

| 测试 | 采样数 | 低 (<0.9) | 正常 (0.9-1.0) | 受限 (>1.0) | 均值 |
|------|--------|-----------|----------------|-------------|------|
| **Bind** | 191 | 153 (80.1%) | 34 (17.8%) | 4 (2.1%) | 27.0% |
| **Nobind** | 239 | 208 (87.0%) | 21 (8.8%) | 10 (4.2%) | 27.9% |

**关键发现:**
- **CWND 不是瓶颈**: 两个测试 78-86% 的采样点显示 CWND > 最优值
- **CWND 严重未充分利用**: 仅约 27% 的 CWND 被实际使用 (unacked/cwnd)，80-87% 的采样点利用率低 (<0.9)
- **很少 CWND 受限**: 仅 2-4% 的采样点显示 unacked/cwnd > 1.0 (内核的 cwnd_limited 条件)
- **RWND 严重不足**: 100% 的采样点中，RWND < 80% 的 BDP (内核 BDP)
- 这解释了为什么 nobind 测试显示 RWND_LIMITED 为主要瓶颈

### 4.3 共同问题 (两个测试)

1. **带宽利用率**: 仅约 62% 的 25 Gbps (实际投递速率约 15-16 Gbps)
2. **RTT 稳定性**: 两个测试都高度波动 (CV > 1.8)
3. **Pacing 受限**: 85-90% 的时间
4. **非 CWND 受限**: 内核确认 cwnd_limited = 0%, CWND 利用率 > 100%

### 4.4 Nobind 特有问题

| 问题 | 严重程度 | 影响 |
|------|----------|------|
| **RWND 受限 24.5%** | 高 | 接收端无法足够快地接收数据 |
| **服务端丢包 278-449 pkts** | 高 | 比 bind 测试高 30 倍以上 |
| **RX 缓冲区压力 19.5%** | 中 | 比 bind 测试高 4 倍 |
| **CWND 不稳定 (CV=0.473)** | 中 | 波动比 bind 大 4 倍 |
| **TX 缓冲区较小 (80 MB)** | 低 | 比 bind 小 37% |

---

## 5. 结论

### 5.1 Bind 测试

- **瓶颈**: 未知 (无明确的内核报告限制)
- **特征**:
  - CWND 稳定 (CV=0.118)
  - 大缓冲区 (TX: 128 MB, RX: 128 MB)
  - 缓冲区压力低 (TX: 0.1%, RX: 4.9%)
  - 丢包少 (8-12 包)
  - cwnd_limited=0%, rwnd_limited=0%, sndbuf_limited=0%
  - CWND 利用率 192.5% (实际 >> 最优)
- **分析**: 内核未报告任何特定限制。带宽利用率 (~62%) 可能受 TCP socket 指标之外的因素限制 (如应用层 pacing、网络路径特性或测量局限)。

### 5.2 Nobind 测试

- **瓶颈**: 接收窗口受限 (RWND_LIMITED, 24.5%)
- **特征**:
  - CWND 不稳定 (CV=0.473)
  - TX 缓冲区较小 (80.74 MB vs 128 MB)
  - RX 缓冲区压力高 (19.5%, 峰值 95.6%)
  - 丢包多 (278-449 包)
  - CWND 利用率 120.1% (实际 > 最优)
- **根因**: 服务端应用读取数据不够快，导致接收窗口收缩，限制了发送端吞吐量。

### 5.3 关键差异

Bind 和 Nobind 测试的主要差异是 nobind 的**接收端瓶颈**:
- RWND 受限 24.5% vs 0%
- 服务端丢包高 30 倍以上
- RX 缓冲区压力高 4 倍

---

## 6. 优化建议

### 6.1 针对 Nobind 测试 (RWND 受限)

```bash
# 增大服务端接收缓冲区
sysctl -w net.core.rmem_max=268435456
sysctl -w net.ipv4.tcp_rmem="4096 131072 268435456"

# 确保应用更快地读取数据
# 对应用进行性能分析以识别读取瓶颈
```

### 6.2 针对两个测试 (提升吞吐量)

```bash
# 检查当前拥塞控制算法
sysctl net.ipv4.tcp_congestion_control

# 增大缓冲区
sysctl -w net.core.wmem_max=268435456
sysctl -w net.ipv4.tcp_wmem="4096 131072 268435456"
```

---

## 7. 数据文件

| 文件 | 位置 | 描述 |
|------|------|------|
| bind-client.log | .tmp/1121/1121-client/ | 客户端 TCP socket 数据 (bind 测试) |
| bind-server.log | .tmp/1121/1121-server/ | 服务端 TCP socket 数据 (bind 测试) |
| nobind-client.log | .tmp/1121/1121-client/ | 客户端 TCP socket 数据 (nobind 测试) |
| nobind-server.log | .tmp/1121/1121-server/ | 服务端 TCP socket 数据 (nobind 测试) |
| client.pcap | .tmp/1121/1121-client/ | 客户端抓包文件 |
| server.pcap | .tmp/1121/1121-server/ | 服务端抓包文件 |
| cwnd-analysis.txt | .tmp/1121/ | 按采样点的 CWND vs 最优 CWND 分析 |
