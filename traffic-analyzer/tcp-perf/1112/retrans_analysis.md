# DupACK 与重传类型深度分析

## 核心发现验证

### 1. DupACK 与快速重传的数学关系 ✅

**理论**: 快速重传次数 × 3 ≤ DupACK 总数

**服务器端验证**:

| 连接 | 快速重传 | DupACK | 理论最小值 | 实际比率 | 验证 |
|------|---------|--------|-----------|---------|------|
| 48266 | 538 | 2,564 | 1,614 | 4.76 | ✅ |
| 48264 | 1,220 | 4,102 | 3,660 | 3.36 | ✅ |
| 48270 | 597 | 2,605 | 1,791 | 4.36 | ✅ |
| 48268 | 865 | 3,218 | 2,595 | 3.72 | ✅ |

**客户端验证** (注意异常！):

| 连接 | 快速重传 | DupACK | 理论最小值 | 实际比率 | 验证 |
|------|---------|--------|-----------|---------|------|
| 48266 | 8 | 4,298 | 24 | **537.25** | ⚠️ |
| 48264 | 9 | 4,067 | 27 | **451.88** | ⚠️ |
| 48270 | 6 | 3,696 | 18 | **616.00** | ⚠️ |
| 48268 | 2 | 3,785 | 6 | **1,892.50** | ⚠️ |

**客户端异常解释**：
- 客户端发送了大量 DupACK（3,696 - 4,298 个）
- 但客户端自己的快速重传极少（2 - 9 次）
- 说明：**客户端在接收方向遇到大量乱序，但发送方向正常**
- DupACK 是客户端作为**接收端**发出的
- 快速重传是客户端作为**发送端**触发的

---

## 2. 重传类型详细分析

### 2.1 内核常量定义

```c
// include/net/tcp.h:82
#define TCP_FASTRETRANS_THRESH 3  // 快速重传阈值

// include/net/tcp.h:865-872
#define TCPCB_SACKED_RETRANS  0x02  // SKB 已重传标记
#define TCPCB_EVER_RETRANS    0x80  // SKB 曾被重传标记
```

### 2.2 Wireshark 可识别的重传类型

1. **`tcp.analysis.retransmission`** - 所有重传（总和）
2. **`tcp.analysis.fast_retransmission`** - 快速重传（收到 3 个 DupACK）
3. **`tcp.analysis.spurious_retransmission`** - 虚假重传（不必要的重传）
4. **RTO 重传** - 超时重传（总重传 - 快速重传 - 虚假重传）

### 2.3 重传类型分布对比

#### 服务器端（发送大量数据）

| 连接 | 总重传 | 快速重传 | 快速% | RTO重传 | RTO% | 虚假重传 |
|------|--------|---------|-------|---------|------|---------|
| 48266 | 2,317 | 538 | **23.2%** | 1,779 | **76.7%** | 0 |
| 48264 | 3,580 | 1,220 | **34.0%** | 2,360 | **65.9%** | 0 |
| 48270 | 2,358 | 597 | **25.3%** | 1,761 | **74.6%** | 0 |
| 48268 | 2,816 | 865 | **30.7%** | 1,951 | **69.2%** | 0 |
| **平均** | **2,768** | **805** | **28.3%** | **1,963** | **71.6%** | **0** |

#### 客户端（主要接收数据）

| 连接 | 总重传 | 快速重传 | 快速% | RTO重传 | RTO% | 虚假重传 |
|------|--------|---------|-------|---------|------|---------|
| 48266 | 1,312 | 8 | **0.6%** | 1,304 | **99.3%** | 0 |
| 48264 | 1,074 | 9 | **0.8%** | 1,065 | **99.1%** | 0 |
| 48270 | 1,374 | 6 | **0.4%** | 1,368 | **99.5%** | 0 |
| 48268 | 1,141 | 2 | **0.1%** | 1,139 | **99.8%** | 0 |
| **平均** | **1,225** | **6** | **0.5%** | **1,219** | **99.4%** | **0** |

---

## 3. 关键发现

### 🔴 发现 1: 服务器端 RTO 重传占主导（71.6%）

**含义**：
- 大部分重传是因为 **RTO 超时**，而不是快速重传
- RTO 超时说明丢包非常严重，连续多个包丢失
- 快速重传需要后续包到达触发 DupACK，但如果连续丢包，无法触发

**示例场景**：
```
发送: [1000] [2000] [3000] [4000] [5000] [6000]
丢失:   X      X      X      X    (连续丢包)
接收: [1000]                              [6000]
       ↓                                    ↓
     ACK 2000                          DupACK 2000 (仅 1 个)

结果: 无法收到 3 个 DupACK → 无法触发快速重传 → 等待 RTO 超时
```

### 🔴 发现 2: 客户端几乎全是 RTO 重传（99.4%）

**含义**：
- 客户端→服务器方向丢包极其严重
- 基本无法触发快速重传机制
- 每次重传都要等待 RTO 超时（性能极差）

**RTO 超时的代价**：
```c
// 典型 RTO 计算
RTO = SRTT + 4 × RTTVAR

// 您的数据（客户端）
RTT ≈ 0.3 ms
初始 RTO ≈ 200 ms (最小值)

// 性能影响
快速重传延迟: 约 1 RTT (0.3 ms)
RTO 重传延迟: 约 200 - 400 ms

差距: 667 - 1333 倍！
```

### ✅ 发现 3: 无虚假重传

**含义**：
- RTO 估计相对准确
- 没有因为 RTO 过小而导致不必要的重传
- 问题确实是真实丢包，不是错误判断

### 🔴 发现 4: DupACK 数量远超快速重传理论值

**客户端最极端情况**：
```
48268: 3,785 DupACK / 2 快速重传 = 1,892 倍！
```

**原因**：
1. **同一个丢包持续产生 DupACK**：
   ```
   丢失 Seq 2000，后续每个包都产生 DupACK：
   Seq 3000 → DupACK 2000
   Seq 4000 → DupACK 2000
   Seq 5000 → DupACK 2000
   ...
   Seq N    → DupACK 2000 (持续到重传到达)
   ```

2. **客户端接收大量乱序包**：
   - 客户端看到服务器发来的包严重乱序
   - 每个乱序包都触发 DupACK
   - 但客户端自己发送数据时丢包少，所以自己的快速重传少

---

## 4. 重传类型触发机制（内核代码）

### 4.1 快速重传触发条件

```c
// net/ipv4/tcp_input.c:2871
static void tcp_fastretrans_alert(...) {
    // 检查是否收到足够的 DupACK
    if (num_dupack >= TCP_FASTRETRANS_THRESH) {  // >= 3
        // 进入 Recovery 状态
        tcp_enter_recovery(sk, flag & FLAG_ECE);
        fast_rexmit = 1;
    }

    // 标记需要重传
    *rexmit = REXMIT_LOST;
}
```

**限制条件**：
1. 必须收到 ≥3 个 DupACK
2. 连接状态允许（非 Loss 状态）
3. 有后续包到达触发 DupACK
4. CWND 允许发送数据

### 4.2 RTO 超时重传

```c
// net/ipv4/tcp_timer.c
void tcp_retransmit_timer(struct sock *sk) {
    struct tcp_sock *tp = tcp_sk(sk);

    // RTO 超时
    if (tcp_write_timeout(sk)) {
        return;
    }

    // 进入 Loss 状态
    tcp_enter_loss(sk);

    // 重传第一个未确认的包
    if (tcp_retransmit_skb(sk, tcp_rtx_queue_head(sk), 1) > 0) {
        // 重传失败，指数退避
        icsk->icsk_rto = min(icsk->icsk_rto << 1, TCP_RTO_MAX);
    }
}
```

### 4.3 重传标记

```c
// net/ipv4/tcp_output.c:3281
if (likely(!err)) {
    // 标记 SKB 被重传过
    TCP_SKB_CB(skb)->sacked |= TCPCB_EVER_RETRANS;

    // 追踪重传事件
    trace_tcp_retransmit_skb(sk, skb);
}
```

---

## 5. 诊断结论

### 主要问题

1. **服务器→客户端方向严重丢包**：
   - 71.6% 的重传是 RTO 超时
   - 连续丢包导致无法触发快速重传
   - 客户端收到大量乱序包（DupACK 4,000+）

2. **客户端→服务器方向极其严重**：
   - 99.4% 的重传是 RTO 超时
   - 几乎无法触发快速重传
   - 每次重传等待 200-400ms

3. **性能影响巨大**：
   ```
   RTO 重传占比高 → 重传延迟大 → 吞吐量低

   服务器端: 2.35 Gbps (应该能到 10 Gbps)
   客户端: 3.76 Gbps (应该能到 10 Gbps)
   ```

### 根本原因

**网络路径问题**，不是 TCP 配置问题：
- ✅ SACK 已启用（帮助快速恢复）
- ✅ 时间戳已启用（帮助 RTT 测量）
- ✅ RTO 估计准确（无虚假重传）
- 🔴 **丢包率太高**（导致 RTO 重传为主）

### 建议检查

1. **网络设备**：
   ```bash
   # 交换机丢包统计
   # Bond 配置
   # 网卡队列溢出
   ```

2. **抓包更上游位置**：
   - 在交换机镜像端口抓包
   - 确认丢包发生位置

3. **检查 CPU 和中断**：
   ```bash
   mpstat -P ALL 1
   cat /proc/interrupts | grep eth
   ```

---

## 6. Wireshark 过滤器

### 查看不同类型重传

```bash
# 所有重传
tcp.analysis.retransmission

# 仅快速重传
tcp.analysis.fast_retransmission

# 仅 RTO 超时重传（近似）
tcp.analysis.retransmission and not tcp.analysis.fast_retransmission and not tcp.analysis.spurious_retransmission

# 虚假重传
tcp.analysis.spurious_retransmission

# 特定连接的快速重传
tcp.srcport == 48264 and tcp.analysis.fast_retransmission
```

### 提取重传时间序列

```bash
# 提取重传时间戳
tshark -r server1112 -Y "tcp.analysis.retransmission" \
  -T fields -e frame.time_relative -e tcp.srcport \
  -e tcp.analysis.fast_retransmission \
  > retrans_timeline.txt
```

---

## 总结

您的观察**完全正确**：

1. ✅ **快速重传必须有 ≥3 个 DupACK**
2. ✅ **可以区分重传类型**：
   - 快速重传（Fast Retransmission）
   - RTO 超时重传（Timeout Retransmission）
   - 虚假重传（Spurious Retransmission）

3. 🔴 **您的数据揭示了严重问题**：
   - RTO 重传占比过高（71.6% - 99.4%）
   - 说明网络丢包严重，无法触发快速恢复机制
   - 性能大幅下降

**下一步**：重点排查网络路径和设备，而非 TCP 参数调优。
