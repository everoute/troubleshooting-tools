# TCP Socket Buffer 完整关系梳理

**基于 Linux Kernel 源码分析**

---

## 1. TCP 序号空间

```
       snd_una          snd_nxt          write_seq
          |                |                 |
          v                v                 v
   -------+----------------+-----------------+-------
          |<-- in_flight-->|<--- notsent --->|
          |                |                 |
          |<------------ send_q ------------>|
```

### 字段说明 (来自 include/linux/tcp.h)

| 字段 | 内核定义位置 | 含义 |
|------|-------------|------|
| `snd_una` | tcp.h:230 | "First byte we want an ack for" - 第一个等待ACK的字节 |
| `snd_nxt` | tcp.h:213 | "Next sequence we send" - 下一个要发送的序号 |
| `write_seq` | tcp_sk(sk)->write_seq | 应用写入的最后序号 + 1 |

---

## 2. 关键公式 (来自内核代码)

### 2.1 send_q (ss 显示的 Send-Q)

**来源**: `net/ipv4/tcp_diag.c:34`

```c
r->idiag_wqueue = READ_ONCE(tp->write_seq) - tp->snd_una;
```

```
┌─────────────────────────────────────────────────────────┐
│  send_q = write_seq - snd_una                          │
│                                                        │
│  含义: 应用写入但未确认的总字节数                        │
│  (ss 显示的 Send-Q 字段)                                │
└─────────────────────────────────────────────────────────┘
```

### 2.2 notsent (未发送字节数)

**来源**: `net/ipv4/tcp.c:3366`

```c
info->tcpi_notsent_bytes = max_t(int, 0, tp->write_seq - tp->snd_nxt);
```

```
┌─────────────────────────────────────────────────────────┐
│  notsent = max(0, write_seq - snd_nxt)                 │
│                                                        │
│  含义: 应用已写入但尚未发送的字节数                      │
│  (tcpi_notsent_bytes, ss 显示的 notsent 字段)          │
└─────────────────────────────────────────────────────────┘
```

### 2.3 in_flight (在途字节数)

**推导公式**:

```
┌─────────────────────────────────────────────────────────┐
│  in_flight_bytes = snd_nxt - snd_una                   │
│                  = send_q - notsent                    │
│                                                        │
│  含义: 已发送到网络但未确认的字节数                      │
└─────────────────────────────────────────────────────────┘
```

### 2.4 公式验证

```
send_q = notsent + in_flight

证明:
  (write_seq - snd_una) = (write_seq - snd_nxt) + (snd_nxt - snd_una)
                        = notsent + in_flight  ✓
```

---

## 3. packets_out vs in_flight (包级别)

**来源**: `include/net/tcp.h:1195-1198`

```c
static inline unsigned int tcp_packets_in_flight(const struct tcp_sock *tp)
{
    return tp->packets_out - tcp_left_out(tp) + tp->retrans_out;
}
```

其中 `tcp_left_out` 定义在 `tcp.h:1176-1178`:

```c
static inline unsigned int tcp_left_out(const struct tcp_sock *tp)
{
    return tp->sacked_out + tp->lost_out;
}
```

```
┌─────────────────────────────────────────────────────────┐
│  in_flight (pkts) = packets_out - left_out + retrans   │
│                                                        │
│  其中:                                                  │
│    packets_out: 已发送未确认的包 (ss 显示为 unacked)    │
│    left_out = sacked_out + lost_out                    │
│    retrans_out: 重传的包                                │
└─────────────────────────────────────────────────────────┘
```

**简化理解**:
- `packets_out` ≈ `unacked` (ss 显示的)
- `in_flight` ≈ `packets_out` (当没有 SACK/丢包时)

---

## 4. Socket Memory 字段

**来源**: `include/uapi/linux/sock_diag.h` + `net/core/sock.c:3342-3355`

```c
void sk_get_meminfo(const struct sock *sk, u32 *mem)
{
    memset(mem, 0, sizeof(*mem) * SK_MEMINFO_VARS);

    mem[SK_MEMINFO_RMEM_ALLOC] = sk_rmem_alloc_get(sk);
    mem[SK_MEMINFO_RCVBUF] = sk->sk_rcvbuf;
    mem[SK_MEMINFO_WMEM_ALLOC] = sk_wmem_alloc_get(sk);
    mem[SK_MEMINFO_SNDBUF] = sk->sk_sndbuf;
    mem[SK_MEMINFO_FWD_ALLOC] = sk->sk_forward_alloc;
    mem[SK_MEMINFO_WMEM_QUEUED] = READ_ONCE(sk->sk_wmem_queued);
    mem[SK_MEMINFO_OPTMEM] = atomic_read(&sk->sk_omem_alloc);
    mem[SK_MEMINFO_BACKLOG] = sk->sk_backlog.len;
    mem[SK_MEMINFO_DROPS] = atomic_read(&sk->sk_drops);
}
```

### Socket Memory 字段对照表

| ss 显示 | 内核变量 | 含义 |
|---------|----------|------|
| `r` | `sk_rmem_alloc` | 接收队列已分配内存 |
| `rb` | `sk_rcvbuf` | 接收缓冲区大小上限 |
| `t` | `sk_wmem_alloc` | 已交给协议栈的发送内存 |
| `tb` | `sk_sndbuf` | 发送缓冲区大小上限 |
| `f` | `sk_forward_alloc` | 预分配未使用内存 |
| `w` | `sk_wmem_queued` | 写队列总内存 (含 skb overhead) |
| `o` | `sk_omem_alloc` | 选项/其他内存 |
| `bl` | `sk_backlog.len` | backlog 队列长度 |
| `d` | `sk_drops` | 丢弃的包数 |

### Socket Memory 含义详解

**sk_wmem_alloc (t)**:
- 已分配给待发送 skb 的内存 (包括 skb 结构体和数据)
- 当 skb 被网卡驱动确认发送完成后才会释放
- 反映的是"交给协议栈/网卡还未完成发送"的数据量

**sk_wmem_queued (w)**:
- 写队列中所有 skb 占用的内存
- 从应用 write() 到 TCP ACK 确认期间累积
- 与 send_q 语义相似，但包含 skb overhead

**sk_sndbuf (tb)**:
- 发送缓冲区上限 (SO_SNDBUF 设置)

**sk_forward_alloc (f)**:
- 预分配但未使用的内存
- 用于加速后续分配

---

## 5. 数据流与内存关系图

```
   应用 write()
         │
         ▼
   ┌─────────────────────────────────────────────────────────┐
   │          Socket Send Buffer (sk_wmem_queued)           │
   │                                                        │
   │  ┌───────────────────────┬────────────────────────┐    │
   │  │       notsent         │       in_flight        │    │
   │  │   (write_seq-snd_nxt) │   (snd_nxt-snd_una)    │    │
   │  │                       │                        │    │
   │  │  等待TCP发送的数据     │   已发送等待ACK的数据   │    │
   │  └───────────────────────┴────────────────────────┘    │
   │              ▲                       │                 │
   │              │                       ▼                 │
   │         等待发送              sk_wmem_alloc (t)        │
   │                          (已交给协议栈/网卡的skb)       │
   └─────────────────────────────────────────────────────────┘
                                          │
                                          ▼
                                   ┌─────────────┐
                                   │   Network   │
                                   │  (packets   │
                                   │   _out)     │
                                   └─────────────┘
                                          │
                                          ▼
                                   收到 ACK
                                   snd_una 前进
                                   释放 sk_wmem_queued
```

---

## 6. 完整数据流程图

```
   ┌─────────────────────────────────────────────────────────────────┐
   │                        Application Layer                        │
   │                                                                 │
   │                         write()/send()                          │
   └─────────────────────────────┬───────────────────────────────────┘
                                 │
                                 ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │                      Socket Layer                               │
   │  ┌───────────────────────────────────────────────────────────┐  │
   │  │                Socket Send Buffer                         │  │
   │  │                                                           │  │
   │  │   sk_wmem_queued (w): 写队列总内存                         │  │
   │  │   sk_sndbuf (tb): 缓冲区上限                               │  │
   │  │                                                           │  │
   │  │   ┌─────────────────────┬─────────────────────┐           │  │
   │  │   │      notsent        │     in_flight       │           │  │
   │  │   │  (write_seq-snd_nxt)│  (snd_nxt-snd_una)  │           │  │
   │  │   │                     │                     │           │  │
   │  │   │   等待发送的数据     │   已发送待确认       │           │  │
   │  │   └─────────────────────┴─────────────────────┘           │  │
   │  │   <─────────────── send_q ───────────────────>            │  │
   │  │                    (write_seq - snd_una)                  │  │
   │  └───────────────────────────────────────────────────────────┘  │
   └─────────────────────────────┬───────────────────────────────────┘
                                 │
                                 │ tcp_write_xmit()
                                 │ snd_nxt 前进
                                 ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │                       TCP Layer                                 │
   │                                                                 │
   │   - CWND 检查: packets_out < cwnd?                              │
   │   - RWND 检查: snd_wnd 足够?                                    │
   │   - Pacing 检查: 是否需要延迟发送?                               │
   │                                                                 │
   │   sk_wmem_alloc (t): 已交给协议栈的 skb 内存                     │
   │   packets_out (unacked): 已发送未确认的包数                      │
   └─────────────────────────────┬───────────────────────────────────┘
                                 │
                                 │ dev_queue_xmit()
                                 ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │                      Qdisc Layer                                │
   │                                                                 │
   │   - fq/fq_codel: 公平队列/延迟控制                               │
   │   - htb/tbf: 带宽限速                                           │
   │   - pfifo_fast: 默认队列                                        │
   └─────────────────────────────┬───────────────────────────────────┘
                                 │
                                 ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │                      Driver/NIC Layer                           │
   │                                                                 │
   │   - TX Ring Buffer                                              │
   │   - TSO/GSO Segmentation                                        │
   │   - Hardware Offload                                            │
   └─────────────────────────────┬───────────────────────────────────┘
                                 │
                                 ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │                        Network                                  │
   │                                                                 │
   │                    Physical Transmission                        │
   └─────────────────────────────┬───────────────────────────────────┘
                                 │
                                 ▼
                           Receiver ACK
                                 │
                                 ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │                      ACK Processing                             │
   │                                                                 │
   │   - snd_una 前进                                                │
   │   - 释放已确认数据的 sk_wmem_queued                              │
   │   - 更新 cwnd (拥塞控制)                                        │
   └─────────────────────────────────────────────────────────────────┘
```

---

## 7. ss 输出字段对应关系

### ss -tinm 输出示例

```
ESTAB  0 45840784  1.1.1.3:39428  1.1.1.2:5201
       skmem:(r0,rb87380,t265760,tb134217728,f931440,w46741904,o0,bl3072,d0)
       cubic wscale:12,12 rto:201 rtt:0.806/0.256 ato:40 mss:1448 pmtu:1500
       rcvmss:536 advmss:1448 cwnd:8484 ssthresh:7646 bytes_sent:236147006613
       bytes_acked:236121771102 segs_out:163085091 segs_in:2877316
       data_segs_out:163085089 send 121.93Gbps lastsnd:4 lastack:4
       pacing_rate 145.09Gbps delivery_rate 22.94Gbps delivered:163067666
       busy:141590ms unacked:1491 retrans:0/15941 dsack_dups:8 rcv_space:14480
       rcv_ssthresh:42242 notsent:43041360 minrtt:0.032
```

### 字段对照表

| ss 字段 | 内核来源 | 计算公式 | 含义 |
|---------|----------|----------|------|
| Send-Q (45840784) | tcp_diag.c:34 | `write_seq - snd_una` | 应用写入但未确认的总字节数 |
| `r` (0) | sock.c:3346 | `sk_rmem_alloc` | 接收队列已分配内存 |
| `rb` (87380) | sock.c:3347 | `sk_rcvbuf` | 接收缓冲区上限 |
| `t` (265760) | sock.c:3348 | `sk_wmem_alloc` | 已交给协议栈的发送内存 |
| `tb` (134217728) | sock.c:3349 | `sk_sndbuf` | 发送缓冲区上限 |
| `f` (931440) | sock.c:3350 | `sk_forward_alloc` | 预分配未使用内存 |
| `w` (46741904) | sock.c:3351 | `sk_wmem_queued` | 写队列总内存 |
| `o` (0) | sock.c:3352 | `sk_omem_alloc` | 选项内存 |
| `bl` (3072) | sock.c:3353 | `sk_backlog.len` | backlog 长度 |
| `d` (0) | sock.c:3354 | `sk_drops` | 丢弃包数 |
| `unacked` (1491) | tcp.h:299 | `packets_out` | 已发送未确认的包数 |
| `notsent` (43041360) | tcp.c:3366 | `write_seq - snd_nxt` | 未发送字节数 |

---

## 8. 实际数据分析 (Bind Test)

### 原始数据

```
send_q:             97.24 MB  (write_seq - snd_una)
notsent:            95.62 MB  (write_seq - snd_nxt)
计算 in_flight:      1.62 MB  (send_q - notsent = snd_nxt - snd_una)

socket_write_queue: 99.16 MB  (sk_wmem_queued, 含 skb overhead)
socket_tx_queue:     0.16 MB  (sk_wmem_alloc, 已交给协议栈)
```

### 包数换算 (MSS=1448)

```
cwnd:               8865 pkts  (拥塞窗口)
packets_out:        2335 pkts  (unacked, 已发送未确认)
notsent/mss:       69243 pkts  (等待发送)
```

### 关键比率

```
notsent / send_q:   97.3%  (97% 数据在 socket buffer 等待!)
in_flight / send_q:  2.7%  (只有 2.7% 在网络中)
unacked / cwnd:     27.0%  (CWND 利用率很低)
```

### 数据可视化

```
send_q 组成 (97.24 MB):
┌────────────────────────────────────────────────────┬──┐
│                    notsent (95.62 MB, 97.3%)       │IF│
│                    等待发送                         │  │
└────────────────────────────────────────────────────┴──┘
                                                      │
                                              in_flight
                                              (1.62 MB, 2.7%)

CWND 利用率:
┌──────────┬────────────────────────────────────────────┐
│  used    │              unused                        │
│  27.0%   │              73.0%                         │
│  2335pkt │              6530 pkts                     │
└──────────┴────────────────────────────────────────────┘
```

---

## 9. 瓶颈分析

### 现象

```
notsent 高 (95 MB) + unacked/cwnd 低 (27%) = 数据发不出去
```

### 数据流瓶颈位置

```
   App write() ─────────────┐
                            ▼
                  ┌─────────────────┐
                  │  notsent        │  <- 95 MB 堆积在这里!
                  │  (socket buf)   │
                  └────────┬────────┘
                           │
                           │ ← 瓶颈在这里！数据发不出去
                           │
                           ▼
                  ┌─────────────────┐
                  │  TCP Stack      │
                  │  (cwnd/pacing)  │  <- CWND=8865 但只用了 2335
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  qdisc/NIC      │
                  │  tx_queue       │
                  └────────┬────────┘
                           │
                           ▼
                       Network
```

### 可能原因

| 原因 | 说明 |
|------|------|
| TCP pacing 限速 | BBR/fq_codel 等拥塞控制算法的 pacing |
| qdisc 队列限速 | tc qdisc 配置的带宽限制或队列满 |
| NIC tx ring | 网卡发送队列满 |
| 虚拟化层瓶颈 | virtio/vhost 数据传输延迟 |
| GSO/TSO 处理 | 大包分段需要时间/资源 |

### 为什么 TCP 层指标都是 0%

这些瓶颈都在 TCP 协议栈"下面"，所以:

```
cwnd_limited_ratio  = 0%  (TCP 认为 cwnd 足够)
rwnd_limited_ratio  = 0%  (TCP 认为 rwnd 足够)
sndbuf_limited_ratio = 0%  (TCP 认为 sndbuf 足够)
```

TCP 层"看不到"底层的瓶颈，它只知道窗口都是充足的，但数据就是从 notsent 发不出去。

---

## 10. 总结

### 核心公式

```
send_q = write_seq - snd_una     // 应用写入但未确认的总量
notsent = write_seq - snd_nxt    // 应用写入但未发送的量
in_flight = snd_nxt - snd_una    // 已发送但未确认的量
         = send_q - notsent

packets_out ≈ in_flight / MSS    // 包级别的在途数量 (即 unacked)
```

### 关键指标含义

| 指标 | 高值含义 | 低值含义 |
|------|----------|----------|
| notsent / send_q | 数据堆积在 socket，发送受阻 | 数据能及时发出 |
| unacked / cwnd | CWND 被充分利用 | CWND 未充分利用 |
| socket_tx_queue | 协议栈/网卡有待发数据 | 发送路径畅通 |

### 诊断思路

1. **notsent 高 + unacked/cwnd 低**: 瓶颈在 TCP 层以下 (qdisc/NIC/虚拟化)
2. **unacked/cwnd 高**: 可能是 CWND 受限
3. **socket_tx_queue 高**: 网卡/驱动发送能力不足
4. **cwnd_limited/rwnd_limited 高**: TCP 层确认的窗口受限

---

## 11. TCP 发送 Pipeline 模型

### 11.1 Pipeline 概述

TCP 发送路径可以建模为一个多阶段的 pipeline，每个阶段都有其 buffer/queue：

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          TCP Send Pipeline Model                            │
└─────────────────────────────────────────────────────────────────────────────┘

  Stage 1         Stage 2              Stage 3           Stage 4        Stage 5
 ┌───────┐      ┌───────────┐       ┌───────────┐     ┌─────────┐    ┌────────┐
 │  App  │─────>│  Socket   │──────>│   TCP     │────>│  Qdisc  │───>│  NIC   │
 │ Buffer│      │  Write Q  │       │ TSQ/Pacing│     │  Queue  │    │ TX Ring│
 └───────┘      └───────────┘       └───────────┘     └─────────┘    └────────┘
     │               │                    │                │              │
     │           notsent              sk_wmem_alloc    q->qlen        tx_ring
     │         (write_seq              (t field)                     desc_cnt
     │          -snd_nxt)
     └───────────────────────────────────────────────────────────────────────┘
                              send_q (write_seq - snd_una)
```

### 11.2 各阶段 Buffer 详解

#### Stage 1: Application Buffer (应用层)
```
内核位置: 用户空间
含义:     应用程序的数据缓冲区
监控:     应用自行管理
```

#### Stage 2: Socket Write Queue (套接字写队列)
```
内核位置: net/ipv4/tcp_output.c - tcp_queue_skb()
内核变量:
  - sk_wmem_queued: 写队列总内存 (ss 中的 w 字段)
  - write_seq - snd_nxt: notsent 字节数

关键代码 (tcp_output.c:1447-1456):
  static void tcp_queue_skb(struct sock *sk, struct sk_buff *skb)
  {
      struct tcp_sock *tp = tcp_sk(sk);
      WRITE_ONCE(tp->write_seq, TCP_SKB_CB(skb)->end_seq);
      __skb_header_release(skb);
      tcp_add_write_queue_tail(sk, skb);
      sk_wmem_queued_add(sk, skb->truesize);  // 增加 w
      sk_mem_charge(sk, skb->truesize);
  }

监控指标:
  - notsent (ss -i 输出)
  - w (skmem 字段)
```

#### Stage 3: TCP Small Queue (TSQ) 限制层
```
内核位置: net/ipv4/tcp_output.c - tcp_small_queue_check()
内核变量:
  - sk_wmem_alloc: 已交给协议栈的内存 (ss 中的 t 字段)
  - TSQ limit: max(2*skb->truesize, pacing_rate >> pacing_shift)

关键代码 (tcp_output.c:2507-2536):
  static bool tcp_small_queue_check(struct sock *sk, ...)
  {
      unsigned int limit;
      limit = max(2 * skb->truesize, sk->sk_pacing_rate >> sk->sk_pacing_shift);
      limit = min_t(u32, limit, sysctl_tcp_limit_output_bytes);  // 默认 256KB

      if (refcount_read(&sk->sk_wmem_alloc) > limit) {
          if (tcp_rtx_queue_empty(sk))
              return false;  // 重传队列空时允许发送
          set_bit(TSQ_THROTTLED, &sk->sk_tsq_flags);  // 设置 TSQ throttled
          return true;  // 阻止发送更多
      }
      return false;
  }

作用:
  - 限制进入 qdisc/device 队列的数据量
  - 减少 bufferbloat，降低 RTT
  - 当 sk_wmem_alloc > limit 时，阻止 tcp_write_xmit 发送更多数据

监控指标:
  - t (skmem 字段, sk_wmem_alloc)
  - TSQ limit ≈ pacing_rate / 1000 (默认 pacing_shift=10)
```

#### Stage 4: Qdisc Queue (队列规则层)
```
内核位置: net/core/dev.c - __dev_xmit_skb()
内核变量:
  - q->qlen: qdisc 队列长度
  - txq->qdisc: 绑定到 TX queue 的 qdisc

关键代码 (dev.c:3888-3898):
  static int dev_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *q, ...)
  {
      int rc;
      rc = q->enqueue(skb, q, to_free) & NET_XMIT_MASK;
      if (rc == NET_XMIT_SUCCESS)
          trace_qdisc_enqueue(q, txq, skb);
      return rc;
  }

监控:
  - tc -s qdisc show
  - /sys/class/net/<dev>/queues/tx-*/tx_packets
```

#### Stage 5: NIC TX Ring (网卡发送环)
```
内核位置: 驱动层 (如 drivers/net/virtio_net.c)
内核变量:
  - tx_ring.desc: TX 描述符环
  - free_count: 可用描述符数量

关键路径:
  dev_hard_start_xmit() -> ndo_start_xmit() -> driver TX

监控:
  - ethtool -S <dev> | grep tx
  - /sys/class/net/<dev>/queues/tx-*/tx_timeout
```

### 11.3 tcp_write_xmit() 中的检查点

```c
// net/ipv4/tcp_output.c:2594-2700 (简化版)
static bool tcp_write_xmit(struct sock *sk, ...)
{
    while ((skb = tcp_send_head(sk))) {

        // 检查点1: Pacing 限制
        if (tcp_pacing_check(sk))                    // line 2630
            break;

        // 检查点2: CWND 限制
        cwnd_quota = tcp_cwnd_test(tp, skb);         // line 2636
        if (!cwnd_quota)
            break;

        // 检查点3: RWND 限制
        if (unlikely(!tcp_snd_wnd_test(tp, skb, mss_now))) {  // line 2645
            is_rwnd_limited = true;
            break;
        }

        // 检查点4: Nagle/TSO defer
        if (tso_segs == 1) {
            if (!tcp_nagle_test(tp, skb, ...))       // line 2651
                break;
        } else {
            if (tcp_tso_should_defer(sk, skb, ...))  // line 2657
                break;
        }

        // 检查点5: TSQ 限制 (最后检查)
        if (tcp_small_queue_check(sk, skb, 0))       // line 2675
            break;

        // 实际发送
        tcp_transmit_skb(sk, skb, 1, gfp);           // line 2686
    }
}
```

### 11.4 Pipeline Buffer 大小分析

#### Bind Test 数据 (实测平均值)

```
Stage/Buffer              Size        Percentage    Notes
─────────────────────────────────────────────────────────────────
send_q (total)           97.24 MB     100.0%       write_seq - snd_una

├─ notsent               95.62 MB      97.3%       ★ 堆积点!
│  (Socket Write Queue)                            write_seq - snd_nxt
│
├─ in_flight              1.62 MB       2.7%       snd_nxt - snd_una
│  ├─ sk_wmem_alloc       0.16 MB       0.2%       t field (TSQ controlled)
│  │  (TSQ stage)
│  └─ [qdisc + NIC]       ~1.46 MB      2.5%       q->qlen + tx_ring
│
└─ acked                  0.00 MB       0.0%       已确认释放
```

#### 关键发现

```
Buffer 梯度:
  notsent (95.62 MB) >> sk_wmem_alloc (0.16 MB) >> qdisc/NIC (~1.46 MB)
                    ^^
                    │
          瓶颈点: notsent → TSQ 阶段
          (前一个 buffer 显著大于后一个)
```

### 11.5 瓶颈定位方法论

#### 方法: 相邻 Buffer 大小比较

```
原理:
  - 如果 Buffer_N >> Buffer_N+1，说明 Stage_N → Stage_N+1 存在瓶颈
  - 数据在 Buffer_N 堆积，无法快速流向 Buffer_N+1

公式:
  Bottleneck_Ratio(N) = Buffer_N / Buffer_N+1

  如果 Bottleneck_Ratio >> 1，则瓶颈在 Stage_N 到 Stage_N+1 之间
```

#### Bind Test 瓶颈分析

```
Stage Transition          Buffer Ratio     Analysis
─────────────────────────────────────────────────────────────────
notsent → sk_wmem_alloc   95.62/0.16 = 597x   ★ 严重瓶颈!
sk_wmem_alloc → qdisc/NIC 0.16/1.46 ≈ 0.1x   正常 (下游充足)

结论: 瓶颈在 Socket Write Queue → TSQ 阶段
      即 tcp_write_xmit() 被某个检查点阻止
```

#### 进一步排查 tcp_write_xmit() 检查点

```
Check Point         Kernel Metric            Bind Test Value    Blocked?
─────────────────────────────────────────────────────────────────────────
Pacing Check        pacing_rate              3.04 Gbps (low!)   可能★
CWND Check          cwnd_limited_ratio       0.0%               No
RWND Check          rwnd_limited_ratio       0.0%               No
Nagle/TSO Defer     -                        -                  可能
TSQ Check           sk_wmem_alloc/limit      0.16MB/~0.3MB      可能★

分析:
  - pacing_rate 平均只有 3.04 Gbps，远低于 25 Gbps 目标
  - 85.3% 的时间 "Pacing Limited"
  - TSQ limit ≈ pacing_rate/1000 ≈ 0.3 MB
```

### 11.6 最终诊断

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Bind Test 瓶颈定位结果                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  瓶颈位置: tcp_write_xmit() 中的 tcp_pacing_check() / tcp_small_queue_check │
│                                                                             │
│  证据:                                                                      │
│    1. notsent/send_q = 97.3% (数据堆积在 socket buffer)                     │
│    2. sk_wmem_alloc 很低 (0.16 MB)，说明 TSQ 限制了发送                      │
│    3. pacing_rate 很低 (3.04 Gbps)，说明 pacing 在限速                       │
│    4. Pacing Limited = 85.3%                                                │
│    5. cwnd_limited = 0%, rwnd_limited = 0% (TCP 窗口充足)                    │
│                                                                             │
│  根因分析:                                                                   │
│    BBR/fq 等拥塞控制算法的 pacing 机制限制了发送速率                          │
│    TSQ (TCP Small Queue) 基于 pacing_rate 计算 limit                        │
│    limit = max(2*truesize, pacing_rate >> 10) ≈ pacing_rate/1024            │
│    当 pacing_rate 低时，TSQ limit 也低，导致数据堆积在 notsent                │
│                                                                             │
│  可能原因:                                                                   │
│    1. 拥塞控制算法 (BBR/Cubic) 保守估计了可用带宽                             │
│    2. RTT 波动导致 pacing_rate 计算不准                                      │
│    3. 网络路径中的瓶颈导致 delivery_rate 受限                                │
│    4. 虚拟化环境的额外延迟影响了带宽估计                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 11.7 Pipeline 监控命令

```bash
# 1. Socket buffer status
ss -tinm | grep -A2 "1.1.1.2:5201"
# 看 Send-Q, notsent, skmem(w,t)

# 2. Pacing rate
ss -ti | grep pacing_rate
# 看 pacing_rate 与 delivery_rate

# 3. Qdisc status
tc -s qdisc show dev eth0
# 看 backlog, drops, overlimits

# 4. NIC TX ring
ethtool -g eth0                    # ring size
ethtool -S eth0 | grep tx          # tx stats

# 5. TSQ sysctl
sysctl net.ipv4.tcp_limit_output_bytes  # 默认 262144 (256KB)
```

---

## 12. Nobind vs Bind 对比分析

### 12.1 Pipeline Buffer 对比

```
Buffer              Bind Test       Nobind Test     Difference
───────────────────────────────────────────────────────────────
send_q              97.24 MB        62.53 MB        -34.71 MB
notsent             95.62 MB        61.18 MB*       -34.44 MB
sk_wmem_alloc       0.16 MB         0.13 MB*        -0.03 MB
───────────────────────────────────────────────────────────────
notsent/send_q      97.3%           ~98%            Similar
pacing_rate         3.04 Gbps       1.68 Gbps       -1.36 Gbps
delivery_rate       15.45 Gbps      15.60 Gbps      +0.15 Gbps

*估算值 (socket_write_queue - in_flight 近似)
```

### 12.2 两个场景的瓶颈差异

```
┌───────────────────────────────────────────────────────────────┐
│                      Bind Test                                │
├───────────────────────────────────────────────────────────────┤
│ 主要瓶颈: Pacing/TSQ (发送端)                                  │
│ 次要瓶颈: 无                                                   │
│                                                               │
│ 特征:                                                         │
│   - rwnd_limited = 0%                                         │
│   - cwnd_limited = 0%                                         │
│   - notsent 高, pacing_rate 低                                │
└───────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────┐
│                     Nobind Test                               │
├───────────────────────────────────────────────────────────────┤
│ 主要瓶颈: RWND Limited (接收端) + Pacing/TSQ                   │
│ 次要瓶颈: Server RX buffer pressure                           │
│                                                               │
│ 特征:                                                         │
│   - rwnd_limited = 24.5%                                      │
│   - cwnd_limited = 0%                                         │
│   - notsent 高, pacing_rate 更低                              │
│   - server_dropped = 374 pkts (vs 10 pkts in bind)           │
└───────────────────────────────────────────────────────────────┘
```

### 12.3 结论

两个测试的共同点是 **Pacing/TSQ 限制**，这导致了 notsent 堆积。但 nobind 测试额外受到 **RWND 限制**（接收端应用读取慢），这进一步降低了吞吐量。

```
Pipeline 瓶颈总结:

                 Bind Test              Nobind Test
                 ──────────             ───────────
App ──────────>  正常                    正常
                    │                       │
Socket WQ ────>  正常                    正常
                    │                       │
TCP Pacing ───>  ★瓶颈 (85%)            ★瓶颈 (90%)
                    │                       │
CWND Check ───>  正常 (0%)              正常 (0%)
                    │                       │
RWND Check ───>  正常 (0%)              ★瓶颈 (24.5%)
                    │                       │
TSQ Check ────>  ★瓶颈                   ★瓶颈
                    │                       │
Qdisc ────────>  正常                    正常
                    │                       │
NIC ──────────>  正常                    正常
```
