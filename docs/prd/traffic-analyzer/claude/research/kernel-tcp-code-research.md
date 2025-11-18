# Linux Kernel TCP代码研究报告

**文档版本**: 1.0
**创建日期**: 2025-11-17
**作者**: Claude Code
**项目**: traffic-analyzer 通用分析工具
**Kernel版本**: Linux 4.18.0 (openEuler)

---

## 目录

1. [研究概述](#1-研究概述)
2. [Rate计算机制研究](#2-rate计算机制研究)
3. [Socket Memory和Buffer字段研究](#3-socket-memory和buffer字段研究)
4. [Window字段研究](#4-window字段研究)
5. [TCP数据包Pipeline](#5-tcp数据包pipeline)
6. [字段映射关系](#6-字段映射关系)
7. [分析工具设计建议](#7-分析工具设计建议)

---

## 1. 研究概述

### 1.1 研究目标

本研究旨在深入理解Linux Kernel中TCP相关的核心实现，为开发TCP Socket分析工具提供准确的理论基础。重点研究内容包括：

- Rate计算方式（send_rate、pacing_rate、delivery_rate）
- Socket Memory和Buffer字段的实际含义
- Window字段（CWND、RWND、SWND）的kernel实现
- TCP数据包收发的完整Pipeline

### 1.2 研究方法

- **静态代码分析**：阅读Linux Kernel源代码（版本4.18.0）
- **代码位置**：`/Users/admin/workspace/linux-4.18.0-553.47.1.el8_10/`
- **关键文件**：
  - `net/ipv4/tcp_rate.c` - delivery_rate计算
  - `net/ipv4/tcp_input.c` - pacing_rate更新、接收处理
  - `net/ipv4/tcp_output.c` - 发送处理
  - `net/ipv4/tcp.c` - 主要TCP实现
  - `include/linux/tcp.h` - tcp_sock结构体定义
  - `include/net/sock.h` - sock结构体定义

### 1.3 核心数据结构

**struct tcp_sock** (`include/linux/tcp.h:183`)：

```c
struct tcp_sock {
    struct inet_connection_sock inet_conn;  // 继承inet_connection_sock

    // 窗口相关
    u32 snd_cwnd;        // 发送拥塞窗口 (line 320)
    u32 snd_ssthresh;    // 慢启动阈值 (line 319)
    u32 rcv_wnd;         // 接收窗口 (line 338)
    u32 snd_wnd;         // 对端通告窗口 (line 243)

    // RTT相关
    u32 srtt_us;         // 平滑RTT (usec) (line 292)
    u32 rttvar_us;       // RTT方差 (usec) (line 295)
    u32 mdev_us;         // 中等偏差 (line 293)

    // 在途数据
    u32 packets_out;     // 在途包数 (line 299)
    u32 retrans_out;     // 重传包数 (line 300)
    u32 sacked_out;      // SACK'd包数 (line 343)
    u32 lost_out;        // 丢失包数 (line 342)

    // Delivery rate相关
    u32 delivered;       // 已交付的总包数 (line 329)
    u32 rate_delivered;  // rate采样：已交付包数 (line 335)
    u32 rate_interval_us; // rate采样：时间间隔 (line 336)
    u64 first_tx_mstamp; // 窗口发送阶段开始时间 (line 333)
    u64 delivered_mstamp; // 到达delivered时的时间 (line 334)

    // D-SACK
    u32 dsack_dups;      // DSACK块总数 (line 227)

    // 其他
    u32 mss_cache;       // 缓存的有效MSS (line 245)
    u32 total_retrans;   // 总重传数 (line 381)
};
```

**struct sock** (`include/net/sock.h`)：

```c
struct sock {
    // Buffer大小限制
    int sk_rcvbuf;           // 接收buffer大小 (line 401)
    int sk_sndbuf;           // 发送buffer大小 (line 414)

    // 实际占用
    atomic_t sk_rmem_alloc;  // 接收队列占用内存 (backlog.rmem_alloc, line 393)
    refcount_t sk_wmem_alloc; // 发送队列占用内存 (line 418)

    // 队列管理
    int sk_wmem_queued;      // 发送队列排队字节数 (line 417)
    int sk_forward_alloc;    // 预分配内存 (line 395)

    // 队列结构
    struct sk_buff_head sk_receive_queue;  // 接收队列 (line 378)
    struct sk_buff_head sk_write_queue;    // 写队列 (line 424)
    struct sk_backlog sk_backlog;          // Backlog队列 (line 389-392)

    // Pacing
    u64 sk_pacing_rate;      // Pacing速率 (set in tcp_update_pacing_rate)
    u64 sk_max_pacing_rate;  // 最大pacing速率
};
```

---

## 2. Rate计算机制研究

### 2.1 Delivery Rate（交付速率）

#### 2.1.1 核心原理

**文件位置**: `net/ipv4/tcp_rate.c`

Delivery rate估算网络当前能够交付数据包的速率。它通过为每个ACK生成一个delivery rate样本来工作。

**核心算法** (line 20-22):
```c
send_rate = #pkts_delivered / (last_snd_time - first_snd_time)
ack_rate  = #pkts_delivered / (last_ack_time - first_ack_time)
bw = min(send_rate, ack_rate)
```

#### 2.1.2 关键函数

**1. tcp_rate_skb_sent()** (`tcp_rate.c:39`)

在数据包发送时调用，记录时间戳和delivered信息到skb：

```c
void tcp_rate_skb_sent(struct sock *sk, struct sk_buff *skb)
{
    struct tcp_sock *tp = tcp_sk(sk);

    // 如果没有在途包，记录新的发送阶段开始时间
    if (!tp->packets_out) {
        u64 tstamp_us = tcp_skb_timestamp_us(skb);
        tp->first_tx_mstamp  = tstamp_us;      // 发送阶段开始
        tp->delivered_mstamp = tstamp_us;       // 交付时间
    }

    // 将当前状态信息打标到skb
    TCP_SKB_CB(skb)->tx.first_tx_mstamp  = tp->first_tx_mstamp;
    TCP_SKB_CB(skb)->tx.delivered_mstamp = tp->delivered_mstamp;
    TCP_SKB_CB(skb)->tx.delivered        = tp->delivered;
    TCP_SKB_CB(skb)->tx.is_app_limited   = tp->app_limited ? 1 : 0;
}
```

**2. tcp_rate_skb_delivered()** (`tcp_rate.c:78`)

在skb被SACK或ACK时调用，提取delivery信息：

```c
void tcp_rate_skb_delivered(struct sock *sk, struct sk_buff *skb,
                            struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct tcp_skb_cb *scb = TCP_SKB_CB(skb);

    // 选择最近发送的skb的信息
    if (!rs->prior_delivered ||
        tcp_skb_sent_after(tx_tstamp, tp->first_tx_mstamp,
                          scb->end_seq, rs->last_end_seq)) {
        rs->prior_delivered  = scb->tx.delivered;
        rs->prior_mstamp     = scb->tx.delivered_mstamp;
        rs->is_app_limited   = scb->tx.is_app_limited;
        rs->is_retrans       = scb->sacked & TCPCB_RETRANS;

        // 更新发送阶段时间
        tp->first_tx_mstamp  = tx_tstamp;

        // 计算发送阶段持续时间
        rs->interval_us = tcp_stamp_us_delta(tp->first_tx_mstamp,
                                            scb->tx.first_tx_mstamp);
    }
}
```

**3. tcp_rate_gen()** (`tcp_rate.c:114`)

生成最终的rate样本：

```c
void tcp_rate_gen(struct sock *sk, u32 delivered, u32 lost,
                  bool is_sack_reneg, struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    u32 snd_us, ack_us;

    // 计算delivered数量
    rs->delivered = tp->delivered - rs->prior_delivered;

    // 计算两个阶段的时间
    snd_us = rs->interval_us;                    // 发送阶段
    ack_us = tcp_stamp_us_delta(tp->tcp_mstamp,
                                rs->prior_mstamp); // ACK阶段

    // 使用较长的阶段（应对ACK压缩）
    rs->interval_us = max(snd_us, ack_us);

    // 验证interval >= min-rtt
    if (unlikely(rs->interval_us < tcp_min_rtt(tp))) {
        rs->interval_us = -1;  // 无效样本
        return;
    }

    // 记录最佳样本（非app-limited或最高的app-limited）
    if (!rs->is_app_limited ||
        ((u64)rs->delivered * tp->rate_interval_us >=
         (u64)tp->rate_delivered * rs->interval_us)) {
        tp->rate_delivered = rs->delivered;
        tp->rate_interval_us = rs->interval_us;
        tp->rate_app_limited = rs->is_app_limited;
    }
}
```

#### 2.1.3 计算公式总结

```
delivery_rate = rate_delivered / rate_interval_us
```

其中：
- `rate_delivered`: 在采样窗口内交付的包数
- `rate_interval_us`: 采样窗口的时间（微秒）
- 单位转换：`delivery_rate (bps) = rate_delivered * MSS * 8 * 1000000 / rate_interval_us`

#### 2.1.4 特性说明

1. **应对ACK压缩**: 使用 `max(send_time, ack_time)` 避免ACK压缩导致的高估
2. **App-limited检测**: 标记应用限制的样本（`tcp_rate_check_app_limited()`）
3. **重传处理**: 虚假重传可能导致interval被低估
4. **采样策略**: 保留非app-limited或最高的app-limited样本

---

### 2.2 Pacing Rate（调度速率）

#### 2.2.1 核心原理

**文件位置**: `net/ipv4/tcp_input.c:873`

Pacing rate控制数据包的发送速率，避免突发流量。Linux使用Fair Queue (FQ) qdisc配合socket的pacing_rate实现。

#### 2.2.2 关键函数

**tcp_update_pacing_rate()** (`tcp_input.c:873`)

```c
static void tcp_update_pacing_rate(struct sock *sk)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    u64 rate;

    /* 基础计算: mss * cwnd / srtt */
    rate = (u64)tp->mss_cache * ((USEC_PER_SEC / 100) << 3);

    /*
     * 慢启动阶段: 设置为当前速率的200%
     * 拥塞避免阶段: 设置为当前速率的120%
     *
     * 慢启动条件: tp->snd_cwnd < tp->snd_ssthresh / 2
     */
    if (tp->snd_cwnd < tp->snd_ssthresh / 2)
        rate *= sock_net(sk)->ipv4.sysctl_tcp_pacing_ss_ratio;  // 默认200
    else
        rate *= sock_net(sk)->ipv4.sysctl_tcp_pacing_ca_ratio;  // 默认120

    /* 乘以窗口大小 */
    rate *= max(tp->snd_cwnd, tp->packets_out);

    /* 除以RTT */
    if (likely(tp->srtt_us))
        do_div(rate, tp->srtt_us);

    /* 写入sk_pacing_rate (需要WRITE_ONCE避免编译器优化) */
    WRITE_ONCE(sk->sk_pacing_rate, min_t(u64, rate,
                                         sk->sk_max_pacing_rate));
}
```

#### 2.2.3 计算公式总结

**基础公式**:
```
current_rate = (CWND * MSS) / srtt_us

慢启动 (CWND < ssthresh/2):
    pacing_rate = current_rate * 200%

拥塞避免 (CWND >= ssthresh/2):
    pacing_rate = current_rate * 120%
```

**详细计算**:
```c
rate = MSS * ratio% * max(CWND, packets_out) * USEC_PER_SEC / srtt_us

其中:
- ratio = 200 (慢启动) 或 120 (拥塞避免)
- MSS: 最大段大小(字节)
- CWND: 拥塞窗口(包数)
- srtt_us: 平滑RTT(微秒)
- packets_out: 当前在途包数
```

#### 2.2.4 更新时机

`tcp_update_pacing_rate()` 在以下情况被调用：

1. **ACK处理后** (`tcp_input.c:3423`)
2. **拥塞窗口变化后** (`tcp_input.c:6398`)
3. **RTT更新后**

#### 2.2.5 Pacing机制

**工作原理**:
1. Kernel设置 `sk->sk_pacing_rate`
2. Fair Queue (FQ) qdisc读取这个值
3. FQ根据pacing_rate调度数据包发送
4. 使用高精度定时器(hrtimer)实现精确调度

**相关sysctl参数**:
- `net.ipv4.tcp_pacing_ss_ratio` - 慢启动比率（默认200）
- `net.ipv4.tcp_pacing_ca_ratio` - 拥塞避免比率（默认120）

---

### 2.3 Send Rate（发送速率）

#### 2.3.1 实际含义

在ss命令和tcp_diag中显示的"send"并**不是kernel直接计算的一个独立字段**，而是通过其他字段计算得出的。

#### 2.3.2 可能的计算方式

查看kernel代码和ss工具源码，send rate可能通过以下方式计算：

**方式1: 基于pacing_rate**
```c
send_rate = sk_pacing_rate
```

**方式2: 基于CWND和RTT**
```c
send_rate = (CWND * MSS * 8) / srtt_us  // bits per second
```

**方式3: 基于实际发送统计**（用户空间计算）
```c
send_rate = (bytes_sent_delta * 8) / time_delta  // bits per second
```

#### 2.3.3 实际建议

在TCP Socket分析工具中，建议：

1. **不要依赖"send_rate"字段**（如果数据源中没有）
2. **使用pacing_rate**作为发送速率的参考
3. **使用delivery_rate**作为实际吞吐量的测量

---

### 2.4 三种Rate的关系

#### 2.4.1 理论关系

**正常情况**:
```
pacing_rate >= delivery_rate
```

**理由**:
- `pacing_rate`: 理论允许的最大发送速率（基于CWND和RTT）
- `delivery_rate`: 实际网络交付速率（基于ACK测量）

#### 2.4.2 关系分析

| 场景 | pacing_rate | delivery_rate | 说明 |
|------|-------------|---------------|------|
| 正常传输 | 高 | 接近pacing | 网络良好，充分利用窗口 |
| 网络拥塞 | 高 | 明显低于pacing | 网络瓶颈，丢包或延迟 |
| App限制 | 高 | 低（标记app_limited） | 应用发送慢 |
| CWND限制 | 低 | 接近pacing | 拥塞窗口限制 |
| RWND限制 | 低 | 接近pacing | 接收窗口限制 |

#### 2.4.3 瓶颈识别

```python
def identify_bottleneck(pacing_rate, delivery_rate, cwnd, bdp):
    ratio = delivery_rate / pacing_rate

    if ratio > 0.9:
        return "正常 - 充分利用"
    elif ratio > 0.7:
        return "轻微瓶颈"
    elif ratio > 0.5:
        return "明显瓶颈 - 网络拥塞"
    else:
        return "严重瓶颈"

    if cwnd < bdp * 0.8:
        return "CWND限制"
```

---

## 3. Socket Memory和Buffer字段研究

### 3.1 核心Buffer字段

#### 3.1.1 Buffer大小限制

**sk_rcvbuf** (`sock.h:401`)
```c
int sk_rcvbuf;  // 接收buffer最大值（字节）
```
- **含义**: 接收buffer的大小限制
- **对应sysctl**: `net.ipv4.tcp_rmem` (min, default, max)
- **自动调整**: Kernel可以动态调整（tcp_moderate_rcvbuf）

**sk_sndbuf** (`sock.h:414`)
```c
int sk_sndbuf;  // 发送buffer最大值（字节）
```
- **含义**: 发送buffer的大小限制
- **对应sysctl**: `net.ipv4.tcp_wmem` (min, default, max)
- **自动调整**: 受tcp_wmem限制

#### 3.1.2 Buffer实际占用

**sk_rmem_alloc** (`sock.h:393`)
```c
#define sk_rmem_alloc sk_backlog.rmem_alloc  // atomic_t类型
```
- **含义**: 接收侧实际占用的内存（字节）
- **包含**: sk_receive_queue + sk_backlog中的数据
- **读取**: `atomic_read(&sk->sk_rmem_alloc)`

**sk_wmem_alloc** (`sock.h:418`)
```c
refcount_t sk_wmem_alloc;  // 发送侧占用内存
```
- **含义**: 发送侧实际占用的内存（字节）
- **包含**: sk_write_queue + 已发送但未ACK的数据
- **读取**: `refcount_read(&sk->sk_wmem_alloc) - 1` (初始值为1)

#### 3.1.3 队列管理

**sk_wmem_queued** (`sock.h:417`)
```c
int sk_wmem_queued;  // 发送队列中排队的字节数
```
- **含义**: 在sk_write_queue中等待发送的数据量
- **计算可用空间**: `sk_sndbuf - sk_wmem_queued`

**sk_forward_alloc** (`sock.h:395`)
```c
int sk_forward_alloc;  // 预分配的内存
```
- **含义**: 预先分配的内存池，避免频繁分配
- **机制**: 当需要内存时，先从forward_alloc获取；不足时再分配

### 3.2 队列结构

#### 3.2.1 接收侧队列

**sk_receive_queue** (`sock.h:378`)
```c
struct sk_buff_head sk_receive_queue;
```
- **含义**: 已接收、有序、等待应用读取的数据
- **对应**: ss命令中的 `Recv-Q`
- **计算**: `sk_receive_queue中的数据量`

**sk_backlog** (`sock.h:389-392`)
```c
struct {
    atomic_t    rmem_alloc;  // backlog占用内存
    int         len;          // backlog队列长度
    struct sk_buff *head;
    struct sk_buff *tail;
} sk_backlog;
```
- **含义**: 当socket被锁定时，临时存储接收的数据
- **触发**: Socket处理过程中收到新数据
- **处理**: Socket解锁后，backlog数据移到receive_queue

#### 3.2.2 发送侧队列

**sk_write_queue** (`sock.h:424`)
```c
struct sk_buff_head sk_write_queue;
```
- **含义**: 已发送但未被ACK的数据（重传队列）
- **包含**: 所有已发送、等待ACK的skb
- **对应**: ss命令中的 `Send-Q` 部分

**send_q的实际含义** (ss命令):
```c
// ss命令显示的Send-Q通常是:
Send-Q = sk_wmem_queued  // 等待发送的数据
// 或者（取决于版本）
Send-Q = sk_wmem_alloc   // 所有发送侧占用
```

### 3.3 采集数据字段映射

基于 `tcp_connection_analyzer.py` 采集的数据，字段映射如下：

| 采集字段 | Kernel字段 | 位置 | 含义 |
|---------|-----------|------|------|
| `recv_q` | `sk_receive_queue长度` | sock.h:378 | 等待应用读取的数据 |
| `send_q` | `sk_wmem_queued` | sock.h:417 | 等待发送的数据量 |
| `socket_rx_buffer` | `sk_rcvbuf` | sock.h:401 | 接收buffer大小限制 |
| `socket_tx_buffer` | `sk_sndbuf` | sock.h:414 | 发送buffer大小限制 |
| `socket_rx_queue` | `sk_rmem_alloc` | sock.h:393 | 接收侧实际占用 |
| `socket_tx_queue` | `sk_wmem_alloc` | sock.h:418 | 发送侧实际占用 |
| `socket_forward_alloc` | `sk_forward_alloc` | sock.h:395 | 预分配内存 |
| `socket_write_queue` | `sk_write_queue长度` | sock.h:424 | 未ACK数据量 |
| `socket_backlog` | `sk_backlog.len` | sock.h:389-392 | Backlog队列长度 |
| `socket_dropped` | `sk_drops` | sock.h:375 | 丢弃包数 |

### 3.4 Buffer压力分析

#### 3.4.1 接收侧压力点

**压力级别判断**:
```python
def analyze_rx_pressure(rx_queue, rx_buffer, dropped):
    utilization = rx_queue / rx_buffer

    if dropped > 0:
        return "严重 - 已发生丢包"
    elif utilization > 0.9:
        return "高压力 - 接近满"
    elif utilization > 0.7:
        return "中等压力"
    else:
        return "正常"
```

**压力来源**:
1. **应用读取慢**: recv_q持续累积
2. **接收速率高**: rx_queue快速增长
3. **Buffer配置小**: rx_buffer < BDP

#### 3.4.2 发送侧压力点

**压力级别判断**:
```python
def analyze_tx_pressure(tx_queue, tx_buffer, wmem_queued):
    utilization = tx_queue / tx_buffer

    if utilization > 0.9:
        return "高压力 - 发送受限"
    elif utilization > 0.7:
        return "中等压力"
    elif wmem_queued > tx_buffer * 0.5:
        return "应用发送快 - 排队中"
    else:
        return "正常"
```

**压力来源**:
1. **应用发送快**: wmem_queued累积
2. **网络发送慢**: CWND限制或网络拥塞
3. **Buffer配置小**: tx_buffer不足

---

## 4. Window字段研究

### 4.1 CWND (拥塞窗口)

#### 4.1.1 定义和位置

**字段定义** (`tcp.h:320`):
```c
u32 snd_cwnd;  // Sending congestion window
```

**单位**: 包数（packets，以MSS为单位）

**含义**: TCP拥塞控制算法维护的发送窗口，表示在不等待ACK的情况下可以发送的数据量。

#### 4.1.2 更新机制

CWND根据拥塞控制算法动态调整：

**慢启动阶段** (CWND < ssthresh):
```c
// 每收到一个ACK
snd_cwnd += 1  // 指数增长
```

**拥塞避免阶段** (CWND >= ssthresh):
```c
// 每个RTT
snd_cwnd += 1  // 线性增长
```

**快速恢复阶段**:
```c
// 检测到丢包
snd_ssthresh = max(snd_cwnd / 2, 2)
snd_cwnd = snd_ssthresh + 3  // 3个dup ACKs
```

#### 4.1.3 不同拥塞控制算法

| 算法 | CWND更新策略 | 特点 |
|------|-------------|------|
| **Reno** | 标准AIMD | 加性增、乘性减 |
| **Cubic** | Cubic函数增长 | 高带宽网络优化 |
| **BBR** | 基于BDP | 不依赖丢包 |

**Cubic示例** (`tcp_cubic.c`):
```c
// Cubic窗口增长函数
W_cubic(t) = C * (t - K)^3 + W_max
```

**BBR示例** (`tcp_bbr.c`):
```c
// BBR的CWND计算
cwnd = BDP + extra_buffer
BDP = bottleneck_bandwidth * RTprop
```

#### 4.1.4 限制因素

```c
// 实际CWND受以下限制
effective_cwnd = min(
    snd_cwnd,              // 拥塞窗口
    snd_cwnd_clamp,        // 用户设置的上限
    receiver_window        // 接收方窗口
)
```

### 4.2 RWND (接收窗口)

#### 4.2.1 定义和位置

**字段定义** (`tcp.h:338`):
```c
u32 rcv_wnd;  // Current receiver window
```

**单位**: 字节

**含义**: 接收方通告给发送方的窗口大小，表示接收方还能接收多少数据。

#### 4.2.2 计算方式

```c
// 接收窗口的计算
rcv_wnd = rcv_space - (rcv_nxt - copied_seq)

其中:
- rcv_space: 接收buffer可用空间
- rcv_nxt: 下一个期望接收的序列号
- copied_seq: 已复制给应用的序列号
```

#### 4.2.3 窗口自动调整

Linux实现了接收窗口自动调整（Window Auto-Tuning）：

**tcp_rcv_space_adjust()** (tcp_input.c):
```c
// 动态调整接收窗口
if (time_after(now, icsk->icsk_ack.lrcvtime + RTT)) {
    // 计算接收速率
    rcvmem = (rcvq - tp->rcv_wup);

    // 调整rcv_ssthresh
    if (rcvmem > tp->rcv_ssthresh) {
        tp->rcv_ssthresh = min(
            rcvmem * 2,
            sk->sk_rcvbuf
        );
    }
}
```

#### 4.2.4 Window Scale选项

**问题**: 16位窗口字段最大65535字节，不足以支持高带宽

**解决**: RFC 7323 Window Scale选项

```c
advertised_window = rcv_wnd << rcv_wscale

最大窗口 = 65535 << 14 = 1GB
```

**字段** (`tcp.h:314`):
```c
struct tcp_options_received rx_opt;
    u8 wscale_ok;      // Window scale协商成功
    u8 snd_wscale;     // 发送方的scale
    u8 rcv_wscale;     // 接收方的scale
```

### 4.3 SWND (发送窗口)

#### 4.3.1 定义和位置

**字段定义** (`tcp.h:243`):
```c
u32 snd_wnd;  // The window we expect to receive
```

**单位**: 字节

**含义**: 对端通告的接收窗口大小（对端的RWND）。

#### 4.3.2 实际发送窗口

实际可用的发送窗口是多个因素的最小值：

```c
// 实际发送窗口
actual_window = min(
    snd_cwnd * mss_cache,  // 拥塞窗口（转为字节）
    snd_wnd,               // 对端通告窗口
    sk_sndbuf              // 发送buffer限制
)
```

#### 4.3.3 窗口限制状态

**CWND Limited**:
```c
// 检测CWND限制
if (packets_out >= snd_cwnd) {
    tp->is_cwnd_limited = 1;
}
```
- **含义**: 在途数据达到CWND限制
- **影响**: 拥塞控制限制了发送

**RWND Limited**:
```c
// 检测RWND限制
if (tcp_wnd_end(tp) - snd_nxt < mss_cache) {
    // 对端窗口满
    rwnd_limited = true;
}
```
- **含义**: 对端接收窗口满
- **影响**: 接收方处理慢

**SNDBUF Limited**:
```c
// 检测发送buffer限制
if (sk_wmem_alloc >= sk_sndbuf) {
    sndbuf_limited = true;
}
```
- **含义**: 发送buffer已满
- **影响**: 本地buffer配置不足

### 4.4 窗口相关指标

#### 4.4.1 ssthresh (慢启动阈值)

**字段定义** (`tcp.h:319`):
```c
u32 snd_ssthresh;  // Slow start size threshold
```

**含义**: 慢启动和拥塞避免的分界点

**更新时机**:
```c
// 检测到拥塞（丢包）
snd_ssthresh = max(flight_size / 2, 2 * MSS)
```

#### 4.4.2 rcv_ssthresh

**字段定义** (`tcp.h:248`):
```c
u32 rcv_ssthresh;  // Current window clamp
```

**含义**: 接收窗口的clamp值，用于窗口自动调整

#### 4.4.3 采集数据映射

| 采集字段 | Kernel字段 | 单位 | 含义 |
|---------|-----------|------|------|
| `cwnd` | `snd_cwnd` | packets | 拥塞窗口 |
| `ssthresh` | `snd_ssthresh` | packets | 慢启动阈值 |
| `rcv_space` | `rcv_wnd` 或 `rcv_ssthresh` | bytes | 接收窗口 |
| `snd_wnd` | `snd_wnd` | bytes | 对端通告窗口 |

**注意**: `rcv_space` 的确切含义需要进一步确认，可能是：
- `tp->rcv_wnd`: 当前接收窗口
- `tp->rcv_ssthresh`: 接收窗口调整的目标值

---

## 5. TCP数据包Pipeline

### 5.1 发送路径Pipeline

```
应用层 (write/send)
    ↓
[1] tcp_sendmsg()
    ├─ 检查 sk_wmem_queued < sk_sndbuf
    ├─ 从用户空间复制数据
    └─ 数据加入 sk_write_queue
    ↓
    sk_wmem_queued 增加 ← [socket_tx_queue 增长]
    ↓
[2] tcp_push()
    └─ 触发实际发送
    ↓
[3] tcp_write_xmit()
    ├─ 检查发送条件:
    │   ├─ CWND限制: packets_out < snd_cwnd
    │   ├─ RWND限制: snd_wnd有空间
    │   └─ TSO/GSO限制
    ├─ 从 sk_write_queue 取skb
    └─ 调用 tcp_transmit_skb()
    ↓
    packets_out 增加 ← [inflight_data 增长]
    ↓
[4] tcp_transmit_skb()
    ├─ 构造TCP头部
    ├─ 计算校验和
    ├─ 调用 tcp_rate_skb_sent() ← [打标delivery rate时间戳]
    └─ 发送到IP层
    ↓
[5] ip_queue_xmit()
    └─ IP层处理
    ↓
[6] dev_queue_xmit()
    └─ 设备驱动层
    ↓
    网络物理层 → 发送出去
    ↓
    等待ACK (skb留在重传队列)
    ↓
[7] 收到ACK
    ├─ tcp_ack()
    ├─ tcp_clean_rtx_queue() ← 清理已ACK的skb
    ├─ tcp_rate_skb_delivered() ← [delivery rate采样]
    ├─ tcp_rate_gen() ← [生成delivery rate样本]
    ├─ packets_out 减少
    └─ sk_wmem_queued 减少
```

**关键点说明**:

1. **[socket_tx_queue]**: `sk_wmem_queued` - 在sk_write_queue中等待发送
2. **[socket_write_queue]**: sk_write_queue长度 - 未ACK的数据
3. **[inflight_data]**: `packets_out * MSS` - 已发送但未ACK
4. **[send_q]**: ss命令显示，通常是 sk_wmem_queued

### 5.2 接收路径Pipeline

```
网络物理层 → 接收数据包
    ↓
[1] 设备驱动
    └─ 中断/NAPI
    ↓
[2] ip_rcv()
    └─ IP层处理
    ↓
[3] tcp_v4_rcv()
    ├─ 查找socket
    ├─ 校验和验证
    └─ 根据状态调用处理函数
    ↓
[4] tcp_rcv_established()
    ├─ Fast path (快速路径)
    │   └─ 预测正确，直接处理
    └─ Slow path (慢速路径)
        └─ tcp_data_queue()
    ↓
[5] tcp_data_queue()
    ├─ 检查序列号
    ├─ 乱序处理 → out_of_order_queue
    └─ 有序数据处理
    ↓
    检查 sk_rmem_alloc < sk_rcvbuf ← [接收buffer压力]
    ↓
    如果Socket被锁定:
        └─ 加入 sk_backlog ← [socket_backlog增长]
    否则:
        └─ 加入 sk_receive_queue ← [recv_q增长]
    ↓
    sk_rmem_alloc 增加 ← [socket_rx_queue增长]
    ↓
[6] tcp_send_ack()
    └─ 发送ACK
    ↓
[7] 应用层读取
    ├─ tcp_recvmsg()
    ├─ 从 sk_receive_queue 取数据
    ├─ 复制到用户空间
    └─ sk_rmem_alloc 减少
    ↓
    recv_q 减少
```

**关键点说明**:

1. **[socket_rx_queue]**: `sk_rmem_alloc` - 接收侧总占用
2. **[recv_q]**: sk_receive_queue长度 - 等待应用读取
3. **[socket_backlog]**: sk_backlog.len - 临时队列
4. **[socket_dropped]**: 当 sk_rmem_alloc >= sk_rcvbuf 时递增

### 5.3 Buffer在Pipeline中的位置

#### 5.3.1 发送路径Buffer映射

```
应用 write()
    ↓
[A] sk_write_queue (未发送)
    占用: sk_wmem_queued
    查看: send_q
    ↓
    tcp_write_xmit()
    ↓
[B] 已发送未ACK (在途)
    占用: packets_out * MSS
    查看: inflight_data
    位置: 仍在sk_write_queue，但已发送
    ↓
    收到ACK
    ↓
    从队列清除
```

**关系验证**:
```python
# 理论关系
sk_wmem_alloc >= sk_wmem_queued + (packets_out * MSS)

# 因为 sk_wmem_alloc 包含所有占用（包括元数据）
```

#### 5.3.2 接收路径Buffer映射

```
网络接收
    ↓
[C] Backlog (临时)
    条件: Socket被锁定
    占用: sk_backlog.rmem_alloc
    长度: sk_backlog.len
    ↓
    Socket解锁
    ↓
[D] sk_receive_queue (有序)
    等待应用读取
    长度: recv_q
    ↓
    应用 read()
    ↓
    清除
```

**关系验证**:
```python
# 总接收占用
sk_rmem_alloc = receive_queue占用 + backlog占用 + ooo_queue占用

# 压力检测
if sk_rmem_alloc >= sk_rcvbuf:
    sk_drops++  # 丢包
```

### 5.4 实际数据验证方法

使用采集的tcpsocket数据验证理论关系：

```python
# 验证1: 发送侧关系
assert socket_tx_queue >= send_q
assert socket_tx_queue >= inflight_data

# 验证2: 接收侧关系
assert socket_rx_queue >= recv_q
assert socket_rx_queue <= socket_rx_buffer

# 验证3: 窗口关系
assert cwnd >= inflight_data / mss
```

---

## 6. 字段映射关系

### 6.1 完整映射表

| 采集字段 | Kernel结构体字段 | 文件位置 | 类型 | 单位 | 说明 |
|---------|-----------------|---------|------|------|------|
| **基础连接信息** | | | | | |
| `state` | `sk_state` | sock.h | enum | - | TCP状态 |
| `mss` | `mss_cache` | tcp.h:245 | u32 | bytes | 有效MSS |
| | | | | | |
| **RTT指标** | | | | | |
| `rtt` | `srtt_us >> 3` | tcp.h:292 | u32 | μs | 平滑RTT |
| `rttvar` | `rttvar_us` | tcp.h:295 | u32 | μs | RTT方差 |
| `minrtt` | `rtt_min.s[0].v` | tcp.h:297 | struct | μs | 最小RTT |
| | | | | | |
| **窗口指标** | | | | | |
| `cwnd` | `snd_cwnd` | tcp.h:320 | u32 | packets | 拥塞窗口 |
| `ssthresh` | `snd_ssthresh` | tcp.h:319 | u32 | packets | 慢启动阈值 |
| `rcv_space` | `rcv_wnd` | tcp.h:338 | u32 | bytes | 接收窗口 |
| `snd_wnd` | `snd_wnd` | tcp.h:243 | u32 | bytes | 对端通告窗口 |
| | | | | | |
| **速率指标** | | | | | |
| `pacing_rate` | `sk_pacing_rate` | sock.h | u64 | bps | Pacing速率 |
| `delivery_rate` | `rate_delivered/rate_interval_us` | tcp.h:335-336 | 计算 | bps | 交付速率 |
| | | | | | |
| **重传指标** | | | | | |
| `retrans` | `total_retrans` | tcp.h:381 | u32 | packets | 总重传数 |
| `dsack_dups` | `dsack_dups` | tcp.h:227 | u32 | packets | DSACK数 |
| `unacked` | `packets_out - sacked_out - lost_out + retrans_out` | 计算 | u32 | packets | 未确认包 |
| | | | | | |
| **队列/Buffer** | | | | | |
| `recv_q` | `sk_receive_queue长度` | sock.h:378 | - | bytes | 接收队列 |
| `send_q` | `sk_wmem_queued` | sock.h:417 | int | bytes | 发送队列 |
| `inflight_data` | `packets_out * MSS` | 计算 | - | bytes | 在途数据 |
| | | | | | |
| **Buffer大小** | | | | | |
| `socket_rx_buffer` | `sk_rcvbuf` | sock.h:401 | int | bytes | 接收buffer大小 |
| `socket_tx_buffer` | `sk_sndbuf` | sock.h:414 | int | bytes | 发送buffer大小 |
| | | | | | |
| **Buffer占用** | | | | | |
| `socket_rx_queue` | `sk_rmem_alloc` | sock.h:393 | atomic_t | bytes | 接收占用 |
| `socket_tx_queue` | `sk_wmem_alloc - 1` | sock.h:418 | refcount_t | bytes | 发送占用 |
| `socket_forward_alloc` | `sk_forward_alloc` | sock.h:395 | int | bytes | 预分配内存 |
| `socket_write_queue` | `sk_write_queue长度` | sock.h:424 | - | bytes | 写队列长度 |
| `socket_backlog` | `sk_backlog.len` | sock.h:389 | int | bytes | Backlog队列 |
| `socket_dropped` | `sk_drops` | sock.h:375 | atomic_t | packets | 丢包数 |
| | | | | | |
| **统计计数** | | | | | |
| `segs_out` | `segs_out` | tcp.h:214 | u32 | segments | 发送段数 |
| `segs_in` | `segs_in` | tcp.h:204 | u32 | segments | 接收段数 |
| `data_segs_out` | `data_segs_out` | tcp.h:217 | u32 | segments | 数据段发送 |
| `data_segs_in` | `data_segs_in` | tcp.h:207 | u32 | segments | 数据段接收 |

### 6.2 计算字段

某些字段需要通过kernel字段计算：

```c
// Delivery rate (bps)
delivery_rate = rate_delivered * mss_cache * 8 * 1000000 / rate_interval_us

// Unacked packets
unacked = packets_out - sacked_out - lost_out + retrans_out

// Inflight data (bytes)
inflight_data = packets_out * mss_cache

// 平滑RTT (ms)
rtt_ms = srtt_us / 8 / 1000

// TX buffer利用率
tx_utilization = sk_wmem_alloc / sk_sndbuf

// RX buffer利用率
rx_utilization = sk_rmem_alloc / sk_rcvbuf
```

### 6.3 采集来源

采集数据来源于以下kernel接口：

1. **ss命令**: 使用netlink INET_DIAG
2. **tcp_diag**: `tcp_diag.c` 导出的信息
3. **ss源码**: iproute2/misc/ss.c

关键采集函数（ss命令）：
```c
// ss命令通过netlink获取TCP信息
tcp_diag_get_info() → 返回 struct tcp_info
```

---

## 7. 分析工具设计建议

### 7.1 Summary模式统计

基于研究结果，Summary模式应该统计：

#### 7.1.1 RTT统计

```python
import numpy as np

def calculate_rtt_stats(rtt_samples):
    """
    rtt_samples: 时序RTT数据 (ms)
    """
    stats = {
        'min': np.min(rtt_samples),
        'max': np.max(rtt_samples),
        'mean': np.mean(rtt_samples),
        'std': np.std(rtt_samples),
        'cv': np.std(rtt_samples) / np.mean(rtt_samples),  # 变异系数
        'p50': np.percentile(rtt_samples, 50),
        'p95': np.percentile(rtt_samples, 95),
        'p99': np.percentile(rtt_samples, 99),
    }

    # 稳定性评估
    if stats['cv'] < 0.1:
        stats['stability'] = '稳定'
    elif stats['cv'] < 0.3:
        stats['stability'] = '中等'
    else:
        stats['stability'] = '不稳定'

    return stats
```

#### 7.1.2 窗口统计

```python
def calculate_window_stats(cwnd_samples, mss, bandwidth_bps, rtt_ms):
    """
    cwnd_samples: CWND时序数据 (packets)
    mss: MSS (bytes)
    bandwidth_bps: 物理带宽 (bps)
    rtt_ms: 平均RTT (ms)
    """
    # 基础统计
    stats = {
        'min': np.min(cwnd_samples),
        'max': np.max(cwnd_samples),
        'mean': np.mean(cwnd_samples),
        'std': np.std(cwnd_samples),
        'cv': np.std(cwnd_samples) / np.mean(cwnd_samples),
        'p50': np.percentile(cwnd_samples, 50),
        'p95': np.percentile(cwnd_samples, 95),
        'p99': np.percentile(cwnd_samples, 99),
    }

    # 理论最优CWND
    bdp_bytes = bandwidth_bps * (rtt_ms / 1000) / 8
    optimal_cwnd = bdp_bytes / mss

    stats['theoretical_optimal'] = optimal_cwnd
    stats['utilization'] = stats['mean'] / optimal_cwnd

    # 判断是否受限
    if stats['utilization'] < 0.8:
        stats['limitation'] = 'CWND受限'
    else:
        stats['limitation'] = '正常'

    return stats
```

#### 7.1.3 速率统计

```python
def calculate_rate_stats(delivery_rate_samples, bandwidth_bps):
    """
    delivery_rate_samples: delivery_rate时序 (bps)
    bandwidth_bps: 物理带宽 (bps)
    """
    stats = {
        'min': np.min(delivery_rate_samples),
        'max': np.max(delivery_rate_samples),
        'mean': np.mean(delivery_rate_samples),
        'std': np.std(delivery_rate_samples),
        'cv': np.std(delivery_rate_samples) / np.mean(delivery_rate_samples),
        'p50': np.percentile(delivery_rate_samples, 50),
        'p95': np.percentile(delivery_rate_samples, 95),
        'p99': np.percentile(delivery_rate_samples, 99),
    }

    # 带宽利用率
    stats['bandwidth_utilization'] = stats['mean'] / bandwidth_bps

    # 稳定性
    if stats['cv'] < 0.1:
        stats['stability'] = '稳定'
    elif stats['cv'] < 0.3:
        stats['stability'] = '波动'
    else:
        stats['stability'] = '不稳定'

    return stats
```

### 7.2 Detailed模式分析

#### 7.2.1 窗口限制识别

```python
def identify_window_limitation(cwnd, packets_out, snd_wnd, mss,
                              sk_wmem_alloc, sk_sndbuf):
    """
    识别窗口限制类型
    """
    cwnd_bytes = cwnd * mss
    inflight_bytes = packets_out * mss

    limitations = []

    # CWND限制
    if packets_out >= cwnd * 0.95:
        limitations.append({
            'type': 'CWND_LIMITED',
            'severity': 'HIGH',
            'description': f'在途数据({packets_out})接近CWND限制({cwnd})'
        })

    # RWND限制
    if inflight_bytes >= snd_wnd * 0.95:
        limitations.append({
            'type': 'RWND_LIMITED',
            'severity': 'HIGH',
            'description': f'在途数据({inflight_bytes}B)接近对端窗口限制({snd_wnd}B)'
        })

    # SNDBUF限制
    if sk_wmem_alloc >= sk_sndbuf * 0.95:
        limitations.append({
            'type': 'SNDBUF_LIMITED',
            'severity': 'HIGH',
            'description': f'发送buffer占用({sk_wmem_alloc}B)接近限制({sk_sndbuf}B)'
        })

    if not limitations:
        limitations.append({
            'type': 'NO_LIMITATION',
            'severity': 'INFO',
            'description': '未检测到窗口限制'
        })

    return limitations
```

#### 7.2.2 重传分析

```python
def analyze_retransmission(retrans_timeline, dsack_dups, segs_out):
    """
    重传深度分析

    retrans_timeline: [(timestamp, retrans_count), ...]
    """
    # 计算总重传
    total_retrans = retrans_timeline[-1][1] - retrans_timeline[0][1]

    # 计算重传率
    retrans_rate = total_retrans / segs_out if segs_out > 0 else 0

    # 虚假重传率
    spurious_rate = dsack_dups / total_retrans if total_retrans > 0 else 0

    # 检测重传突发
    bursts = []
    for i in range(1, len(retrans_timeline)):
        delta_time = retrans_timeline[i][0] - retrans_timeline[i-1][0]
        delta_retrans = retrans_timeline[i][1] - retrans_timeline[i-1][1]

        # 定义突发: 2秒内重传>10个
        if delta_time <= 2 and delta_retrans > 10:
            bursts.append({
                'time': retrans_timeline[i][0],
                'count': delta_retrans
            })

    analysis = {
        'total_retrans': total_retrans,
        'retrans_rate': retrans_rate,
        'spurious_count': dsack_dups,
        'spurious_rate': spurious_rate,
        'burst_events': len(bursts),
        'bursts': bursts,
    }

    # 告警
    if retrans_rate > 0.01:
        analysis['alert'] = 'HIGH'
        analysis['message'] = f'高重传率: {retrans_rate:.2%}'
    elif spurious_rate > 0.3:
        analysis['alert'] = 'MEDIUM'
        analysis['message'] = f'虚假重传率过高: {spurious_rate:.2%}'
    else:
        analysis['alert'] = 'NORMAL'
        analysis['message'] = '重传情况正常'

    return analysis
```

#### 7.2.3 Buffer压力分析

```python
def analyze_buffer_pressure(timeline_data):
    """
    Buffer压力分析

    timeline_data: [
        {
            'time': timestamp,
            'recv_q': ...,
            'send_q': ...,
            'rx_queue': ...,
            'rx_buffer': ...,
            'tx_queue': ...,
            'tx_buffer': ...,
            'dropped': ...,
        },
        ...
    ]
    """
    rx_pressures = []
    tx_pressures = []

    for sample in timeline_data:
        # 接收侧压力
        rx_util = sample['rx_queue'] / sample['rx_buffer']
        rx_pressures.append(rx_util)

        # 发送侧压力
        tx_util = sample['tx_queue'] / sample['tx_buffer']
        tx_pressures.append(tx_util)

    analysis = {
        'rx': {
            'max_utilization': np.max(rx_pressures),
            'avg_utilization': np.mean(rx_pressures),
            'p95_utilization': np.percentile(rx_pressures, 95),
            'dropped_total': timeline_data[-1]['dropped'],
        },
        'tx': {
            'max_utilization': np.max(tx_pressures),
            'avg_utilization': np.mean(tx_pressures),
            'p95_utilization': np.percentile(tx_pressures, 95),
        }
    }

    # 接收侧判断
    if analysis['rx']['dropped_total'] > 0:
        analysis['rx']['pressure'] = 'CRITICAL'
        analysis['rx']['message'] = f"发生丢包{analysis['rx']['dropped_total']}次"
    elif analysis['rx']['p95_utilization'] > 0.9:
        analysis['rx']['pressure'] = 'HIGH'
        analysis['rx']['message'] = 'P95利用率>90%'
    elif analysis['rx']['avg_utilization'] > 0.7:
        analysis['rx']['pressure'] = 'MEDIUM'
        analysis['rx']['message'] = '平均利用率>70%'
    else:
        analysis['rx']['pressure'] = 'NORMAL'
        analysis['rx']['message'] = '压力正常'

    # 发送侧判断
    if analysis['tx']['p95_utilization'] > 0.9:
        analysis['tx']['pressure'] = 'HIGH'
        analysis['tx']['message'] = 'P95利用率>90%'
    elif analysis['tx']['avg_utilization'] > 0.7:
        analysis['tx']['pressure'] = 'MEDIUM'
        analysis['tx']['message'] = '平均利用率>70%'
    else:
        analysis['tx']['pressure'] = 'NORMAL'
        analysis['tx']['message'] = '压力正常'

    return analysis
```

### 7.3 关系验证

在工具中实现关系验证，确保理解正确：

```python
def verify_kernel_relationships(sample):
    """
    验证kernel字段关系
    """
    warnings = []

    # 验证1: TX buffer关系
    if sample['socket_tx_queue'] < sample['send_q']:
        warnings.append(
            f"异常: socket_tx_queue({sample['socket_tx_queue']}) "
            f"< send_q({sample['send_q']})"
        )

    # 验证2: RX buffer关系
    if sample['socket_rx_queue'] < sample['recv_q']:
        warnings.append(
            f"异常: socket_rx_queue({sample['socket_rx_queue']}) "
            f"< recv_q({sample['recv_q']})"
        )

    # 验证3: CWND和inflight关系
    inflight_packets = sample['inflight_data'] / sample['mss']
    if inflight_packets > sample['cwnd'] * 1.1:  # 允许10%误差
        warnings.append(
            f"异常: inflight({inflight_packets:.0f}包) "
            f"> cwnd({sample['cwnd']}包)"
        )

    # 验证4: Buffer限制
    if sample['socket_rx_queue'] > sample['socket_rx_buffer']:
        warnings.append(
            f"异常: RX queue({sample['socket_rx_queue']}) "
            f"> buffer({sample['socket_rx_buffer']})"
        )

    if warnings:
        print("⚠️  检测到异常关系:")
        for w in warnings:
            print(f"   - {w}")
    else:
        print("✓ 字段关系验证通过")

    return len(warnings) == 0
```

### 7.4 报告格式建议

**Summary报告模板**:

```
===== TCP Socket 性能分析报告 =====

[基本信息]
分析时间范围: 2025-11-12 14:19:47 ~ 14:25:32 (343秒)
物理链路带宽: 10 Gbps
连接信息: 100.100.103.205:53910 -> 100.100.103.201:5001
总采样点数: 172

[RTT分析]
指标          Min      Max      Mean     Std      CV      P50      P95      P99
RTT (ms)      4.23     12.45    5.67     1.23     21.7%   5.34     8.92     11.23
RTTVar (ms)   1.02     15.32    3.45     2.11     61.2%   2.87     9.12     13.45
稳定性: 中等 (CV=21.7%)

[窗口分析]
指标              Min      Max      Mean     Std      CV      P50      P95      P99
CWND (packets)    2847     5846     4523     623      13.8%   4512     5621     5798
ssthresh (pkts)   7        7        7        0        0%      7        7        7

理论最优CWND: 4412 packets (BDP=64.6MB, RTT=5.67ms, BW=10Gbps)
实际平均CWND: 4523 packets
CWND利用率: 102.5%
结论: CWND配置合理，略高于理论最优

[速率分析]
指标                 Min        Max        Mean       Std        P50        P95
Pacing Rate (Gbps)   3.42       9.87       7.23       1.45       7.18       9.23
Delivery Rate (Gbps) 3.21       9.54       6.98       1.52       6.89       8.92

带宽利用率: 69.8% (avg delivery rate / 10Gbps)
速率稳定性: 波动 (CV=21.8%)

[重传分析]
总重传: 234 packets (0.23% of 101,234 sent)
虚假重传: 12 packets (5.1% of retrans)
重传趋势: 稳定
重传突发事件: 2次

[Buffer分析]
接收侧:
  - Buffer大小: 8 MB
  - P95占用: 2.3 MB (28.7%)
  - 压力: 正常
  - 丢包: 0次

发送侧:
  - Buffer大小: 16 MB
  - P95占用: 15.2 MB (95%)
  - 压力: 高
  - 建议: 考虑增大发送buffer

[瓶颈识别]
主要瓶颈: 发送Buffer压力高
次要瓶颈: 无
建议措施:
  1. 增大tcp_wmem配置
  2. 检查应用发送模式
  3. 考虑启用TCP_NODELAY
```

---

## 8. 附录

### 8.1 关键Kernel函数索引

| 功能 | 函数名 | 文件位置 | 行号 |
|------|--------|---------|------|
| Delivery rate采样(发送) | `tcp_rate_skb_sent()` | net/ipv4/tcp_rate.c | 39 |
| Delivery rate采样(接收) | `tcp_rate_skb_delivered()` | net/ipv4/tcp_rate.c | 78 |
| Delivery rate生成 | `tcp_rate_gen()` | net/ipv4/tcp_rate.c | 114 |
| Pacing rate更新 | `tcp_update_pacing_rate()` | net/ipv4/tcp_input.c | 873 |
| 发送数据 | `tcp_sendmsg()` | net/ipv4/tcp.c | 1200 |
| 实际发送 | `tcp_write_xmit()` | net/ipv4/tcp_output.c | 2594 |
| 接收数据 | `tcp_recvmsg()` | net/ipv4/tcp.c | 1967 |
| 数据入队 | `tcp_data_queue()` | net/ipv4/tcp_input.c | 4885 |
| ACK处理 | `tcp_ack()` | net/ipv4/tcp_input.c | - |
| 清理RTX队列 | `tcp_clean_rtx_queue()` | net/ipv4/tcp_input.c | - |

### 8.2 重要sysctl参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `net.ipv4.tcp_rmem` | 4096 131072 6291456 | TCP接收buffer (min default max) |
| `net.ipv4.tcp_wmem` | 4096 16384 4194304 | TCP发送buffer (min default max) |
| `net.ipv4.tcp_moderate_rcvbuf` | 1 | 接收buffer自动调整 |
| `net.ipv4.tcp_pacing_ss_ratio` | 200 | 慢启动pacing比率 |
| `net.ipv4.tcp_pacing_ca_ratio` | 120 | 拥塞避免pacing比率 |
| `net.core.rmem_max` | 212992 | Socket接收buffer最大值 |
| `net.core.wmem_max` | 212992 | Socket发送buffer最大值 |
| `net.ipv4.tcp_congestion_control` | cubic | 拥塞控制算法 |

### 8.3 参考文献

1. **Linux Kernel源码**
   - https://github.com/torvalds/linux
   - 本研究使用版本: 4.18.0

2. **RFC文档**
   - RFC 793: TCP
   - RFC 2018: SACK
   - RFC 2883: D-SACK
   - RFC 5681: TCP Congestion Control
   - RFC 7323: TCP Extensions for High Performance (Window Scale, Timestamps)

3. **BBR论文**
   - "BBR: Congestion-Based Congestion Control" (ACM Queue 2016)

4. **Kernel文档**
   - Documentation/networking/ip-sysctl.txt

---

**文档结束**
