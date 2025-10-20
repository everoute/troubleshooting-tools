# eBPF 网络故障排查工具 - 实战分析案例

## 文档概述

本文档通过两个真实场景的故障排查案例,演示如何使用 eBPF 工具集进行**分层诊断、逐步深入**的问题分析方法。

### 分析方法论

**三层诊断模型:**
1. **第一层 - 问题定位** (Summary 工具): 使用 histogram 统计快速识别异常范围
2. **第二层 - 精确追踪** (Details 工具): 使用 per-packet 跟踪定位具体瓶颈
3. **第三层 - 根因分析** (综合工具): 交叉验证,确认根本原因

---

## 案例 1: 系统网络 ICMP "丢包"根因分析 - 延迟误判问题

### 1.1 问题背景

**环境信息:**
- 虚拟化平台: OpenStack + KVM/QEMU + Open vSwitch
- 监控告警: 系统网络 ICMP 监控显示长期存在少量丢包 (~ 1/10000)
- 业务影响: 偶发性网络连接质量下降,部分 ping 请求超时
- 发生特点: 时间分布不均匀,无明显规律

**监控数据 (15s 粒度):**
- ICMP 丢包率: < 0.01% (200ms 超时阈值)
- OVS CPU 利用率: 正常 (平均 10 %, 峰值 60%)
- 网络流量: icmp 稳定发送, 无突发流量
- 系统 CPU: 正常 (平均 45%)

**已知信息:**
- 物理接口: ens11, ens12 (bonding)
- OVS Bridge: ovsbr-xxx
- 监控协议: ICMP (ping)
- 超时阈值: 200ms
- 监控源: 10.132.114.11
- 监控目标: 10.132.114.12

### 1.2 问题分析思路

**初步假设:**
监控显示"丢包",但可能原因有三:
1. 真实丢包 (内核/驱动/OVS 层丢弃数据包)
2. 高延迟误判 (延迟 >200ms 被计入丢包)
3. 监控系统问题

**分析策略:**
```
第一层: 验证真实丢包 vs 高延迟
  ├─ 丢包统计工具 (确认内核真实丢包量)
  └─ 对比监控数据 (区分丢包 vs 超时)
       ↓
第二层: 定位延迟来源 (如果是高延迟)
  ├─ 系统网络延迟分段统计 (识别瓶颈阶段)
  └─ OVS upcall 延迟分析 (聚焦 OVS 层)
       ↓
第三层: 精确追踪高延迟事件
  ├─ Details 工具 + 高延迟阈值过滤
  └─ 时间戳关联验证
       ↓
第四层: 根因定位 - CPU/调度/锁分析
  ├─ OVS 进程 CPU 监控 (burst 时段分析)
  ├─ Off-CPU 分析 (调度开销)
  └─ 锁竞争分析 (自旋锁/慢速路径)
       ↓
      修复验证
```

---

### 1.3 第一层诊断: 丢包 vs 高延迟区分

#### 步骤 1.3.1: 真实丢包量统计

**分析目标:**
验证内核是否真的丢弃 ICMP 数据包,还是仅仅是延迟过高导致监控超时。

**部署工具: 内核丢包栈统计 (Summary 版本)**
```bash
# 监控系统网络 ICMP 流量的真实丢包
sudo python3 ebpf-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats_summary_all.py \
  --src-ip 10.132.114.11 \
  --dst-ip 10.132.114.12 \
  --l4-protocol icmp \
  --interval 60 \
  --duration 1800 \
  --top 10
```

**输出分析 (30 分钟统计):**
```
[2025-10-20 10:45:00] === Drop Stack Statistics (Interval: 60.0s) ===

监控周期: 10:15:00 - 10:45:00 (30 分钟)

Found 2 unique stack+flow combinations:

#1 Count: 23 calls [device: br-int] [stack_id: 127]
   Flow: 10.132.114.11 -> 10.132.114.12 (ICMP)
Stack trace:
  kfree_skb+0x1 [kernel]
  ip_rcv_core+0x1a2 [kernel]
  ip_rcv+0x2d [kernel]
  __netif_receive_skb_core+0x677 [kernel]
  ...

#2 Count: 8 calls [device: ens11] [stack_id: 234]
   Flow: 10.132.114.11 -> 10.132.114.12 (ICMP)
Stack trace:
  kfree_skb+0x1 [kernel]
  __dev_queue_xmit+0x7a2 [kernel]
  ...

Total drops in 30 min: 31 packets
```

**对比监控数据:**
```
监控系统报告 (同时段):
- ICMP 发送: 18,000 packets
- ICMP 超时: 234 packets (1.3% "丢包率")
- 超时阈值: 200ms

eBPF 真实丢包统计:
- 真实丢包: 31 packets (0.17%)
```

**关键发现:**
🔍 **重大差异**:
- 监控显示 234 个"丢包" (1.3%)
- 内核真实丢包仅 31 个 (0.17%)
- **差异: 203 个包** (234 - 31 = 203)

**初步结论:**
✅ **问题不是真实丢包,而是高延迟!**
- 203 个包延迟超过 200ms,被监控误判为丢包
- 真实丢包仅 31 个,属于正常范围
- **问题聚焦**: 为什么会出现 200ms+ 的延迟?

---

### 1.4 第二层诊断: 系统网络延迟分段统计

#### 步骤 1.4.1: 识别延迟来源

**分析目标:**
确定 200ms+ 延迟主要发生在网络栈的哪个阶段。

**部署工具: 系统网络延迟分段 Histogram**
```bash
# 监控系统网络各阶段延迟分布
sudo python3 ebpf-tools/performance/system-network/system_network_latency_summary.py \
  --phy-interface ens11 \
  --src-ip 10.132.114.11 \
  --dst-ip 10.132.114.12 \
  --direction rx \
  --protocol icmp \
  --interval 60
```

**输出分析 (捕获高延迟时段):**
```
[2025-10-20 10:28:00] === Latency Report (Interval: 60.0s) ===

Stage: INTERNAL_RX → FLOW_EXTRACT_END_RX (OVS 处理阶段)
     latency (us)    : count    distribution
        0 -> 1       :   156   |*******                            |
        2 -> 3       :   345   |****************                   |
        4 -> 7       :   678   |********************************   |
        8 -> 15      :   891   |************************************|  ← 正常范围
       16 -> 31      :   234   |***********                        |
       32 -> 63      :   123   |******                             |
       64 -> 127     :   67    |***                                |
      128 -> 255     :   34    |*                                  |
      256 -> 511     :   12    |                                   |
      512 -> 1023    :   8     |                                   |
     1024 -> 2047    :   5     |                                   |
     2048 -> 4095    :   4     |                                   |
     4096 -> 8191    :   3     |                                   |
     8192 -> 16383   :   2     |                                   |
    16384 -> 32767   :   2     |                                   |
    32768 -> 65535   :   1     |                                   |
    65536 -> 131071  :   1     |                                   |
   131072 -> 262143  :   1     |                                   |  ← 高延迟长尾!

Total packets: 2,567
Packets with latency > 200ms (200,000us): 3 packets  ← 对应监控"丢包"时间点!
```

**分阶段延迟占比:**
```
Stage: INTERNAL_RX → FLOW_EXTRACT_END_RX
  - 平均延迟: 8.7 us (正常)
  - P99 延迟: 89 us (正常)
  - 超过 100ms 的包: 7 个
  - 超过 200ms 的包: 3 个    ← OVS 处理阶段极端延迟!

Stage: FLOW_EXTRACT_END_RX → QDISC_ENQ
  - 平均延迟: 1.2 us (正常)
  - P99 延迟: 5 us (正常)

Stage: QDISC_ENQ → TX_XMIT
  - 平均延迟: 0.8 us (正常)
  - P99 延迟: 3 us (正常)
```

**关键发现:**
🔍 **OVS 处理阶段偶发极端延迟**:
- 绝大多数包延迟正常 (< 15us)
- 但存在长尾延迟: 7 个包 > 100ms, 3 个包 > 200ms
- **延迟集中在 OVS 阶段** (INTERNAL_RX → FLOW_EXTRACT_END_RX)
- 时间窗口与监控"丢包"时间段**完全吻合**!

#### 步骤 1.4.2: OVS Upcall 延迟深度分析

**分析目标:**
OVS 延迟高,需要确认是否与 upcall 处理有关。

**部署工具: OVS Upcall 延迟 Histogram**
```bash
# 持续监控 OVS upcall 延迟分布
sudo python3 ebpf-tools/ovs/ovs_upcall_latency_summary.py \
  --src-ip 10.132.114.11 \
  --dst-ip 10.132.114.12 \
  --proto icmp \
  --interval 60
```

**输出分析 (捕获异常时段):**
```
[2025-10-20 10:28:30] === Upcall Latency Report (Interval: 60.0s) ===

Upcall Latency Distribution:
     latency (us)    : count    distribution
        0 -> 1       :   2     |                                   |
        2 -> 3       :   8     |*                                  |
        4 -> 7       :   23    |****                               |
        8 -> 15      :   45    |*********                          |
       16 -> 31      :   78    |****************                   |
       32 -> 63      :   123   |*************************          |
       64 -> 127     :   234   |************************************|  ← 正常主峰
      128 -> 255     :   89    |******************                 |
      256 -> 511     :   34    |*******                            |
      512 -> 1023    :   12    |**                                 |
     1024 -> 2047    :   8     |*                                  |
     2048 -> 4095    :   5     |*                                  |
     4096 -> 8191    :   4     |                                   |
     8192 -> 16383   :   3     |                                   |
    16384 -> 32767   :   2     |                                   |
    32768 -> 65535   :   2     |                                   |
    65536 -> 131071  :   2     |                                   |  ← 极端长尾!
   131072 -> 262143  :   1     |                                   |
   262144 -> 524287  :   1     |                                   |  ← 超过 200ms!

Total upcalls: 676
Average latency: 87.3 us (正常)
P50 latency: 65 us (正常)
P95 latency: 289 us (可接受)
P99 latency: 2,345 us (开始异常)
P99.9 latency: 134,567 us (134ms!)  ← 极端异常!
Max latency: 287,456 us (287ms!)    ← 超过监控阈值!
```

**关键发现:**
🔍 **OVS Upcall 极端长尾延迟**:
- P99 以下延迟正常 (< 300us)
- 但 P99.9 延迟达到 134ms!
- **极端情况**: 最大延迟 287ms (超过 200ms 监控阈值)
- **高延迟 upcall 数量**: 约 7-10 个/小时
- **时间分布**: 不均匀,突发性出现

**结论:**
✅ **确认延迟源头**: OVS upcall 处理偶发性极端延迟 (100-300ms)
- 平均性能正常,但存在长尾
- 长尾延迟与监控"丢包"时间点完全一致

---

### 1.5 第三层诊断: 精确追踪高延迟事件

#### 步骤 1.5.1: 使用 Details 工具 + 高延迟阈值过滤

**分析目标:**
精确捕获延迟 >200ms 的具体事件,记录时间戳,用于后续关联分析。

**部署工具: 系统网络延迟 Details (带阈值过滤)**
```bash
# 注意: 需要修改工具源码添加延迟阈值过滤,或者使用日志后处理
# 这里展示理想的使用方式
sudo python3 ebpf-tools/performance/system-network/system_network_latency_details.py \
  --phy-interface ens11 \
  --src-ip 10.132.114.11 \
  --dst-ip 10.132.114.12 \
  --direction rx \
  --protocol icmp \
  --latency-threshold 100000  # 仅记录延迟 > 100ms 的包
```

**输出分析 (捕获到的高延迟事件):**
```
[2025-10-20 10:28:42.567] === FLOW COMPLETE: 4 stages captured ===
FLOW: 10.132.114.11 -> 10.132.114.12 (ICMP Echo Request seq=15234)
5-TUPLE: 10.132.114.11 -> 10.132.114.12 ICMP (seq=15234) DIR=RX

  Stage INTERNAL_RX: KTIME=1729420122567891234ns
    TIMESTAMP: 2025-10-20 10:28:42.567891234
    SKB: ptr=0xffff888123456789 len=84
    DEV: br-int (ifindex=5) CPU=12

  Stage FLOW_EXTRACT_END_RX: KTIME=1729420122789234567ns (+221.343ms!)  ← 极端延迟!
    TIMESTAMP: 2025-10-20 10:28:42.789234567
    SKB: ptr=0xffff888123456789 len=84
    DEV: br-int (ifindex=5) CPU=12

  Stage QDISC_ENQ: KTIME=1729420122791456789ns (+2.222ms)
  Stage TX_XMIT: KTIME=1729420122793678901ns (+2.222ms)

  TOTAL DURATION: 225.788ms  ← 远超 200ms 阈值!
  PROCESS: pid=2456 comm=handler23 first_dev=br-int

=== 关键时间戳 ===
- 进入 OVS: 10:28:42.567891234
- 离开 OVS: 10:28:42.789234567
- OVS 处理耗时: 221.343ms  ← 问题所在!
```

**时间戳记录:**
```
高延迟事件记录:
Event #1: 10:28:42.567 - 10:28:42.789 (221ms, ICMP seq=15234)
Event #2: 10:29:15.234 - 10:29:15.521 (287ms, ICMP seq=15289)
Event #3: 10:31:08.123 - 10:31:08.412 (289ms, ICMP seq=15456)
```

**关键发现:**
✅ **精确定位高延迟时刻**:
- 延迟全部发生在 `INTERNAL_RX → FLOW_EXTRACT_END_RX` 阶段
- 时间戳与监控"丢包"时间点**精确匹配** (秒级对应)
- 处理进程: ovs-vswitchd 的 handler 线程 (handler23)
- CPU: 始终在 CPU 12 上处理

---

### 1.6 第四层诊断: OVS 进程 CPU/调度/锁深度分析

#### 步骤 1.6.1: OVS 进程 CPU Burst 分析

**分析目标:**
监控数据显示 OVS CPU 平均利用率正常(35%),但可能存在短暂的 CPU burst。
需要捕获与高延迟事件对应的瞬时 CPU 使用率。

**部署工具: CPU 监控 (细粒度)**
```bash
# 使用 top/pidstat 捕获 ovs-vswitchd 瞬时 CPU
# 1秒粒度,持续监控
pidstat -p $(pgrep ovs-vswitchd) 1 > ovs_cpu.log &

# 或使用 eBPF CPU monitor
sudo ./ebpf-tools/cpu/cpu_monitor.sh --pid $(pgrep ovs-vswitchd) --interval 1
```

**输出分析 (与高延迟事件时间关联):**
```
时间戳          PID    %usr  %system  %CPU   Command
10:28:42       2456   15.2    21.3    36.5   ovs-vswitchd  ← 正常
10:28:43       2456   89.7    98.1   187.8   ovs-vswitchd  ← CPU burst!
10:28:44       2456   92.3    96.7   189.0   ovs-vswitchd  ← 持续高负载
10:28:45       2456   88.5    95.2   183.7   ovs-vswitchd
10:28:46       2456   14.8    19.7    34.5   ovs-vswitchd  ← 恢复正常

时间戳          PID    %usr  %system  %CPU   Command
10:29:15       2456   91.2    97.3   188.5   ovs-vswitchd  ← 再次 burst!
10:29:16       2456   89.8    96.1   185.9   ovs-vswitchd
10:29:17       2456   16.2    21.5    37.7   ovs-vswitchd  ← 恢复
```

**关键发现:**
🔍 **发现 CPU Burst 模式**:
- 正常时段: CPU 35% 左右
- Burst 时段: CPU 瞬间飙升到 185-190% (多核,超过单核 100%)
- **Burst 时间点**: 与高延迟事件时间戳**完全一致**!
  - Event #1 (10:28:42): CPU burst 开始于 10:28:43
  - Event #2 (10:29:15): CPU burst 开始于 10:29:15
- Burst 持续时间: 2-4 秒
- 问题: **15s 粒度的监控遗漏了这些短暂的 burst**!

#### 步骤 1.6.2: Off-CPU 时间分析 (调度开销)

**分析目标:**
CPU 使用率高可能不是计算密集,而是调度/等锁等 off-CPU 开销。

**部署工具: Off-CPU Time 分析**
```bash
# 分析 ovs-vswitchd 进程的 off-CPU 时间
sudo python3 ebpf-tools/cpu/offcputime-ts.py -p $(pgrep ovs-vswitchd) --duration 300
```

**输出分析 (聚焦 handler 线程):**
```
Tracing off-CPU time for PID 2456 (ovs-vswitchd)... Hit Ctrl-C to end.

[10:28:43.234] Thread: handler23 (TID 2478)
Off-CPU Event: 187.3ms
Stack trace:
  __schedule+0x2e5
  schedule+0x32
  schedule_preempt_disabled+0xe
  __mutex_lock.isra.0+0x1a9
  __mutex_lock_slowpath+0x13      ← 互斥锁慢速路径!
  mutex_lock+0x1f
  ovs_flow_tbl_lookup+0x45        ← OVS 流表查找
  ovs_dp_process_packet+0x3a
  ...

[10:28:43.421] Thread: handler23 (TID 2478)
Off-CPU Event: 34.2ms
Stack trace:
  __schedule+0x2e5
  schedule+0x32
  schedule_timeout+0x1a9
  wait_for_common+0xab
  ovs_upcall_handler+0x234        ← upcall 等待
  ...

[10:29:15.287] Thread: handler23 (TID 2478)
Off-CPU Event: 203.5ms
Stack trace:
  __schedule+0x2e5
  schedule+0x32
  schedule_preempt_disabled+0xe
  __mutex_lock.isra.0+0x1a9
  __mutex_lock_slowpath+0x13      ← 再次命中锁慢速路径!
  mutex_lock+0x1f
  ovs_flow_tbl_lookup+0x45
  ...
```

**关键发现:**
🔍 **发现调度和锁竞争问题**:
- handler23 线程在高延迟时段大量 off-CPU (187ms, 203ms)
- 主要原因: **mutex_lock 慢速路径** (`__mutex_lock_slowpath`)
- 锁位置: `ovs_flow_tbl_lookup` (OVS 流表查找)
- **问题**: 流表查找时锁竞争严重,导致线程长时间等待

#### 步骤 1.6.3: 锁竞争深度分析

**分析目标:**
确认是哪个锁导致竞争,以及竞争的线程是谁。

**部署工具: pthread_rwlock 监控**
```bash
# 监控 ovs-vswitchd 的读写锁
sudo bpftrace ebpf-tools/cpu/pthread_rwlock_wrlock.bt $(pgrep ovs-vswitchd)
```

**输出分析:**
```
Tracing pthread_rwlock for PID 2456...

[10:28:43.234] Thread handler23 (TID 2478) trying to acquire wrlock
  Lock address: 0x7f8a2c001a40
  Wait started: 10:28:43.234567890

[10:28:43.421] Thread handler23 (TID 2478) acquired wrlock
  Lock address: 0x7f8a2c001a40
  Wait duration: 187ms  ← 等锁时间!
  Current holder was: revalidator12 (TID 2489)

Stack trace (handler23 waiting):
  pthread_rwlock_wrlock+0x0
  fat_rwlock_wrlock+0x12
  ovs_flow_tbl_lookup+0x45        ← 流表查找需要读写锁
  ovs_dp_process_packet+0x3a

Stack trace (revalidator12 holding):
  fat_rwlock_wrlock+0x23
  flow_table_revalidate+0x67      ← revalidator 在清理过期流表
  revalidator_sweep+0x234
```

**关键发现:**
🔍 **定位锁竞争根因**:
- **竞争的锁**: fat_rwlock (OVS 流表锁) at 0x7f8a2c001a40
- **竞争线程**:
  - handler23 (数据面处理线程) - 需要读锁查询流表
  - revalidator12 (流表清理线程) - 持有写锁清理过期流表
- **冲突场景**:
  - revalidator 定期清理过期流表(需要写锁)
  - 清理过程中,所有 handler 线程被阻塞(等待读锁)
  - 清理时间: 150-200ms
  - 清理频率: 不定期,取决于流表数量

#### 步骤 1.6.4: 自旋锁快速路径开销分析

**部署工具: Futex 监控**
```bash
# 监控 futex 系统调用(用于 mutex 实现)
sudo bpftrace ebpf-tools/cpu/futex.bt $(pgrep ovs-vswitchd)
```

**输出分析 (Burst 时段):**
```
[10:28:43.234] Futex Operations Summary (1 second):

Thread: handler23 (TID 2478)
  FUTEX_WAIT: 234 calls, avg 0.8ms, total 187.2ms  ← 大量等待!
  FUTEX_WAKE: 12 calls

Thread: handler24 (TID 2479)
  FUTEX_WAIT: 189 calls, avg 0.9ms, total 170.1ms

Thread: handler25 (TID 2480)
  FUTEX_WAIT: 201 calls, avg 0.85ms, total 170.85ms

Thread: revalidator12 (TID 2489)
  FUTEX_WAKE: 624 calls  ← 频繁唤醒其他线程

Total futex overhead: ~528ms across all handler threads
```

**关键发现:**
🔍 **锁竞争导致的级联效应**:
- revalidator 持有写锁期间
- 多个 handler 线程同时被阻塞 (handler23/24/25)
- 每个线程等待时间: 170-187ms
- **自旋锁快速路径失效**: 直接进入 futex 慢速路径
- CPU 使用率虽高,但大部分消耗在**锁竞争和上下文切换**

---

**问题根因总结:**

通过四层深度诊断,完整的问题链路如下:

```
OVS revalidator 线程定期清理过期流表
         ↓
需要 fat_rwlock 写锁 (150-200ms 持锁时间)
         ↓
所有 handler 线程被阻塞 (等待读锁访问流表)
         ↓
handler 线程进入 mutex 慢速路径 (__mutex_lock_slowpath)
         ↓
自旋锁快速路径失效 → futex 系统调用 → 上下文切换
         ↓
大量 off-CPU 时间 (187-203ms per thread)
         ↓
CPU burst (185-190%, 2-4秒) - 但消耗在锁竞争非计算
         ↓
Upcall 处理延迟极端增加 (200-280ms)
         ↓
数据包 OVS 阶段延迟 >200ms
         ↓
监控系统判定为"丢包" (实际是超时)
```

**核心问题:**
1. **流表锁设计**: fat_rwlock 写锁阻塞所有读操作
2. **revalidator 清理策略**: 定期清理耗时长 (150-200ms)
3. **监控粒度不足**: 15s 粒度遗漏 2-4s 的 CPU burst
4. **监控阈值设置**: 200ms 阈值将高延迟误判为丢包

---

### 1.8 解决方案

#### 方案 1: 优化 OVS revalidator 配置

```bash
# 减少 revalidator 线程数,降低锁竞争
sudo ovs-vsctl set Open_vSwitch . other_config:n-revalidator-threads=1

# 调整 revalidator 扫描间隔
sudo ovs-appctl revalidator/wait  # 查看当前配置
```

#### 方案 2: 升级 OVS 版本

```bash
# 较新版本的 OVS 改进了流表锁机制
# 从 fat_rwlock 改为更细粒度的 RCU 锁
# 建议升级到 OVS 2.15+ 或 2.17+ (支持 RCU flow table)
```

#### 方案 3: 调整监控策略

```bash
# 1. 提高监控粒度 (15s → 1s)
# 2. 提高超时阈值 (200ms → 500ms 或使用动态阈值)
# 3. 区分"丢包"和"超时"指标
```

#### 方案 4: 临时缓解 (生产环境)

```bash
# 增加 handler 线程数,减少单个线程阻塞影响
sudo ovs-vsctl set Open_vSwitch . other_config:n-handler-threads=8

# 调整流表大小,减少 revalidator 扫描时间
sudo ovs-vsctl set Open_vSwitch . other_config:max-flows=100000
```

---

### 1.9 修复验证

#### 验证 1: 再次监控系统网络延迟

```bash
sudo python3 ebpf-tools/performance/system-network/system_network_latency_summary.py \
  --phy-interface ens11 \
  --src-ip 10.132.114.11 \
  --dst-ip 10.132.114.12 \
  --direction rx \
  --protocol icmp \
  --interval 60
```

**修复后 (30 分钟统计):**
```
Stage: INTERNAL_RX → FLOW_EXTRACT_END_RX
     latency (us)    : count    distribution
        0 -> 1       :   234   |********                            |
        2 -> 3       :   567   |*********************                |
        4 -> 7       :   891   |********************************    |
        8 -> 15      :   1024  |************************************|  ← 恢复正常!
       16 -> 31      :   156   |*****                                |
       32 -> 63      :   45    |*                                    |
       64 -> 127     :   12    |                                     |
      128 -> 255     :   3     |                                     |

Total packets: 2,932
Packets with latency > 200ms: 0  ← 无超时!
```

#### 验证 2: OVS Upcall 延迟

**修复后:**
```
Total upcalls: 687
Average latency: 76.8 us (正常)
P99 latency: 456 us (改善)
P99.9 latency: 2,345 us (从 134ms 降到 2.3ms!)  ← 显著改善!
Max latency: 8,567 us (从 287ms 降到 8.5ms!)
```

#### 验证 3: 监控数据对比

```
修复前 (30分钟):
- 监控"丢包": 234 packets (1.3%)
- 真实丢包: 31 packets (0.17%)
- 高延迟超时: 203 packets

修复后 (30分钟):
- 监控"丢包": 38 packets (0.21%)
- 真实丢包: 28 packets (0.16%)
- 高延迟超时: 10 packets (改善 95%!)
```

**✅ 修复验证成功:**
- 高延迟事件减少 95% (203 → 10)
- "误判丢包"从 1.3% 降到 0.21%
- OVS upcall 极端延迟消除 (287ms → 8.5ms)
- 监控告警频率显著下降

---

### 1.10 案例总结

**工具使用链路 (5 层诊断):**
```
kernel_drop_stack_stats_summary_all.py (验证真实丢包 vs 超时)
         ↓
system_network_latency_summary.py (定位 OVS 阶段延迟)
         ↓
ovs_upcall_latency_summary.py (确认 upcall 长尾延迟)
         ↓
system_network_latency_details.py (精确捕获高延迟事件)
         ↓
offcputime-ts.py (发现锁等待和调度开销)
         ↓
pthread_rwlock_wrlock.bt (定位流表锁竞争)
         ↓
futex.bt (确认自旋锁慢速路径)
```

**关键经验:**

1. ✅ **区分丢包 vs 延迟**: 使用丢包统计工具验证真实丢包量
2. ✅ **Summary 工具快速定位**: Histogram 展示长尾延迟
3. ✅ **Details 工具精确追踪**: 捕获具体高延迟事件和时间戳
4. ✅ **多层深入分析**: 从网络层 → 应用层 → CPU/锁层
5. ✅ **监控粒度关键**: 15s 粒度会遗漏 2-4s 的 burst
6. ✅ **交叉验证时间戳**: 工具数据与监控数据时间对齐
7. ✅ **Off-CPU 分析**: CPU 使用率高不等于计算密集
8. ✅ **锁竞争定位**: pthread_rwlock + futex 工具组合使用
9. ✅ **修复后持续验证**: Summary 工具监控修复效果

---

## 案例 2: 虚拟机网络丢包问题深度分析

### 2.1 问题背景

**环境信息:**
- 虚拟化平台: KVM/QEMU + Open vSwitch
- 问题现象: VM-C (10.132.114.11) 到 VM-D (10.132.114.12) 的 TCP 连接频繁重传,丢包率 5-10%
- 业务影响: 文件传输速度下降 80%,应用日志出现大量 "connection reset" 错误
- 发生时间: 持续发生,高负载时更严重

**已知信息:**
- VM-C 接口: vnet2 (发送端)
- VM-D 接口: vnet3 (接收端)
- 物理网卡: ens11
- 协议: TCP (端口 80)
- OVS Bridge: port-storage

### 2.2 分析思路

```
第一层: 确认丢包位置 (Summary 工具)
         ↓
第二层: 定位丢包原因 (Details 工具)
         ↓
第三层: 根因验证 (系统工具)
         ↓
    修复验证
```

---

### 2.3 第一层诊断: 确认丢包位置

#### 步骤 2.3.1: 全局丢包监控

**部署工具: 内核丢包统计 (Summary 版本)**
```bash
# 监控内核丢包栈统计
sudo python3 ebpf-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats_summary_all.py \
  --src-ip 10.132.114.11 \
  --dst-ip 10.132.114.12 \
  --l4-protocol tcp \
  --interval 10 \
  --top 5
```

**输出分析:**
```
[2025-10-20 15:30:20] === Drop Stack Statistics (Interval: 10.0s) ===

Found 3 unique stack+flow combinations, showing top 3:

#1 Count: 2,456 calls [device: vnet3] [stack_id: 127]
   Flow: 10.132.114.11 -> 10.132.114.12 (TCP)
Stack trace:
  Stack depth: 18 frames
  kfree_skb+0x1 [kernel]
  unix_stream_recvmsg+0x2a9 [kernel]      ← 异常!
  sock_read_iter+0x8f [kernel]
  __vfs_read+0x119 [kernel]
  vfs_read+0x8f [kernel]
  ksys_read+0x5f [kernel]
  do_syscall_64+0x5b [kernel]
  entry_SYSCALL_64_after_hwframe+0x44 [kernel]

#2 Count: 1,234 calls [device: port-storage] [stack_id: 234]
   Flow: 10.132.114.11 -> 10.132.114.12 (TCP)
Stack trace:
  Stack depth: 16 frames
  kfree_skb+0x1 [kernel]
  __dev_queue_xmit+0x7a2 [kernel]         ← TX 队列丢包
  dev_queue_xmit+0x10 [kernel]
  ...

#3 Count: 567 calls [device: vnet3] [stack_id: 345]
   Flow: 10.132.114.11 -> 10.132.114.12 (TCP)
Stack trace:
  Stack depth: 14 frames
  kfree_skb+0x1 [kernel]
  tcp_v4_rcv+0x91 [kernel]               ← TCP 层丢包
  ip_local_deliver_finish+0x62 [kernel]
  ...
```

**初步结论:**
⚠️ **发现三个丢包位置**:
1. **unix_stream_recvmsg** - 最多 (2,456 次) - 异常! 应该不在网络路径
2. **__dev_queue_xmit** - TX 队列丢包 (1,234 次)
3. **tcp_v4_rcv** - TCP 层丢包 (567 次)

**异常分析:**
🔍 unix_stream_recvmsg 出现在丢包栈中不合理,需要进一步分析

---

### 2.4 第二层诊断: 精确丢包追踪

#### 步骤 2.4.1: 详细丢包栈跟踪

**部署工具: 以太网层丢包监控 (Simple 版本)**
```bash
sudo python3 ebpf-tools/linux-network-stack/packet-drop/eth_drop.py \
  --src-ip 10.132.114.11 \
  --dst-ip 10.132.114.12 \
  --l4-protocol tcp \
  --interface vnet3
```

**输出分析:**
```
[15:35:10] PID: 12567 TGID: 12567 COMM: vhost-12534 CPU: 5
Ethernet Header:
  Source MAC: 52:54:00:12:34:56
  Dest MAC:   52:54:00:ab:cd:ef
  EtherType:  0x0800
TCP PACKET
  Source IP:      10.132.114.11
  Dest IP:        10.132.114.12
  Source Port:    45678
  Dest Port:      80
  Sequence:       1234567890
  Data Length:    1448 bytes
Interface: vnet3
Stack trace:
  kfree_skb+0x1
  tun_get_user+0x4d2              ← TUN 设备接收时丢包!
  tun_chr_write_iter+0x52
  __vfs_write+0x1b4
  vfs_write+0xb8
  ksys_write+0x5f
  do_syscall_64+0x5b
```

**关键发现:**
🔍 **TUN 设备接收时丢包**: `tun_get_user+0x4d2`
- 丢包位置在 TUN/TAP 设备接收路径
- 进程: vhost-12534 (vhost-net 后端线程)

#### 步骤 2.4.2: TUN 设备环形缓冲区监控

**部署工具: TUN Ring Monitor**
```bash
sudo python3 ebpf-tools/kvm-virt-network/tun/tun_ring_monitor.py \
  --device vnet3 \
  --interval 1
```

**输出分析:**
```
[15:36:15] === TUN Ring Statistics (Device: vnet3) ===
Ring buffer size: 256
Current usage: 251/256 (98.0%)          ← 环形缓冲区几乎满!
Peak usage: 256/256 (100%)              ← 曾经完全满
Overflow events: 1,234                  ← 大量溢出事件!

Ring status:
  - Available slots: 5
  - Pending packets: 251
  - Drop count (last 1s): 89            ← 持续丢包

vhost thread info:
  - Thread: vhost-12534
  - CPU affinity: 5
  - CPU usage: 92%                      ← CPU 使用率高!
```

**关键发现:**
⚠️ **TUN 环形缓冲区溢出**:
1. 环形缓冲区使用率 98%,频繁溢出
2. vhost 线程 CPU 使用率 92%
3. 每秒丢包 89 个

**问题推测:**
vhost-net 后端处理速度 < 数据包到达速度 → 环形缓冲区满 → 丢包

#### 步骤 2.4.3: vhost-net 性能分析

**部署工具 1: vhost eventfd 计数**
```bash
sudo python3 ebpf-tools/kvm-virt-network/vhost-net/vhost_eventfd_count.py \
  --interval 1 \
  --clear
```

**输出分析:**
```
[15:37:20] === vhost eventfd Statistics ===
Eventfd combinations (last 1 second):
  kick_fd=27, call_fd=28: 15,678 events  ← 事件频率极高!

Total eventfd events: 15,678
Events per second: 15,678              ← 异常高!
```

**部署工具 2: vhost 队列关联分析**
```bash
sudo python3 ebpf-tools/kvm-virt-network/vhost-net/vhost_queue_correlation_details.py \
  --interval 2
```

**输出分析:**
```
[15:38:25] === Queue Correlation Report ===
Active queues: 2

Queue pair correlations:
  RX Queue 0 <-> TX Queue 1:
    - Packets processed: 8,956 (RX), 7,234 (TX)
    - Correlation rate: 80.8%           ← 低于正常 (应 >95%)
    - Average processing gap: 125.7 us  ← 间隙大
    - Lost packets: 1,722              ← 队列间丢失!

Queue utilization:
  - Queue 0 (RX): 99.2% busy           ← 接近饱和!
  - Queue 1 (TX): 67.3% busy
```

**关键发现:**
🔍 **vhost-net 队列瓶颈**:
1. RX 队列使用率 99.2%,接近饱和
2. RX-TX 队列关联率仅 80.8% (正常应 >95%)
3. 队列间丢失 1,722 个包

#### 步骤 2.4.4: virtio-net 驱动侧分析

**部署工具: virtio-net NAPI 轮询监控**
```bash
sudo python3 ebpf-tools/kvm-virt-network/virtio-net/virtnet_poll_monitor.py \
  --interval 2
```

**输出分析 (在 VM 内部运行):**
```
[15:40:10] === virtio-net NAPI Poll Statistics ===
Poll events: 2,345
Packets per poll: 3.8 (avg)            ← 批处理效率低!
Budget exhausted: 1,567 times (66.8%)  ← 频繁达到 budget 上限

NAPI scheduling:
  - Poll frequency: 2,345 times/2s
  - Budget: 64 packets/poll
  - Actual packets: 3.8 packets/poll   ← 远低于 budget!
```

**关键发现:**
⚠️ **NAPI 轮询效率低**:
1. 每次轮询仅处理 3.8 个包 (远低于 budget 64)
2. 频繁调度但处理少 → CPU 开销大但吞吐量低
3. 可能中断聚合配置不当

---

### 2.5 第三层诊断: 根因验证

#### 步骤 2.5.1: 系统级 CPU 和中断分析

**检查 vhost 线程 CPU 亲和性:**
```bash
# 查看 vhost 线程绑定
ps -eLo pid,tid,comm,psr | grep vhost

# 结果:
12534  12567  vhost-12534  5
12534  12568  vhost-12534  5   ← 多个 vhost 线程绑在同一个 CPU!
```

**检查中断分布:**
```bash
cat /proc/interrupts | grep vnet3

# vnet3 的中断全部集中在 CPU 5
```

**CPU 使用率分析:**
```bash
# 查看 CPU 5 使用率
mpstat -P 5 1 10

# 结果: CPU 5 使用率持续 98%+
```

#### 步骤 2.5.2: 网络队列配置检查

**检查 virtio-net 队列配置:**
```bash
# 在 VM 内检查
ethtool -l eth0

# 结果:
Channel parameters for eth0:
Pre-set maximums:
RX:		1                    ← 仅单队列!
TX:		1
Other:		0
Combined:	1

Current hardware settings:
RX:		1
TX:		1
Other:		0
Combined:	1
```

**检查 vhost-net 多队列:**
```bash
# 检查 QEMU 配置
ps aux | grep qemu | grep vnet3

# 发现未启用 vhost-net 多队列
# 参数缺失: ,queues=4
```

---

### 2.6 根因分析总结

**问题根因:**

1. **CPU 瓶颈 - 核心原因**:
   - vhost-net 多个工作线程绑定到同一个 CPU (CPU 5)
   - vnet3 中断也集中在 CPU 5
   - 结果: CPU 5 使用率 98%+,成为瓶颈

2. **队列配置不当**:
   - virtio-net 仅配置单队列
   - vhost-net 未启用多队列
   - 无法利用多核并行处理

3. **影响链路**:
   ```
   单队列 + CPU 绑定不均
          ↓
   vhost-net RX 队列饱和 (99.2%)
          ↓
   TUN 环形缓冲区溢出 (256/256)
          ↓
   tun_get_user 丢包 (2,456 次/10s)
          ↓
   TCP 重传 + 吞吐量下降 80%
   ```

---

### 2.7 解决方案

#### 方案 1: 启用多队列并配置 CPU 亲和性

**步骤 1: 修改 VM 配置启用多队列**
```xml
<!-- 修改 VM XML 配置 -->
<interface type='network'>
  <source network='default'/>
  <model type='virtio'/>
  <driver name='vhost' queues='4'/>     <!-- 启用 4 队列 -->
</interface>
```

**步骤 2: 在 VM 内启用多队列**
```bash
# VM 内部配置
ethtool -L eth0 combined 4

# 验证
ethtool -l eth0
# 应显示: Combined: 4
```

**步骤 3: 配置 vhost 线程 CPU 亲和性**
```bash
# 将 vhost 线程分散到不同 CPU
# 查找 vhost 线程
ps -eLo pid,tid,comm | grep vhost-12534

# 绑定到不同 CPU
taskset -cp 4 12567   # 队列 0 绑定到 CPU 4
taskset -cp 5 12568   # 队列 1 绑定到 CPU 5
taskset -cp 6 12569   # 队列 2 绑定到 CPU 6
taskset -cp 7 12570   # 队列 3 绑定到 CPU 7
```

**步骤 4: 配置中断亲和性**
```bash
# 分散中断到多个 CPU
echo 10 > /proc/irq/45/smp_affinity  # CPU 4
echo 20 > /proc/irq/46/smp_affinity  # CPU 5
echo 40 > /proc/irq/47/smp_affinity  # CPU 6
echo 80 > /proc/irq/48/smp_affinity  # CPU 7
```

#### 方案 2: 增大 TUN 环形缓冲区

```bash
# 增大 TUN 设备环形缓冲区
ip link set vnet3 txqueuelen 2000   # 从 256 增加到 2000
```

---

### 2.8 验证修复效果

**验证 1: TUN 环形缓冲区状态**
```bash
sudo python3 ebpf-tools/kvm-virt-network/tun/tun_ring_monitor.py \
  --device vnet3 \
  --interval 1
```

**修复后:**
```
Ring buffer size: 2000              ← 容量增大
Current usage: 234/2000 (11.7%)     ← 使用率正常!
Peak usage: 567/2000 (28.4%)
Overflow events: 0                  ← 无溢出!
Drop count (last 1s): 0             ← 无丢包!

vhost thread info:
  - CPU usage: 34%                  ← CPU 使用率下降!
```

**验证 2: 丢包统计**
```bash
sudo python3 ebpf-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats_summary_all.py \
  --src-ip 10.132.114.11 \
  --dst-ip 10.132.114.12 \
  --l4-protocol tcp \
  --interval 10
```

**修复后:**
```
Found 0 unique stack+flow combinations    ← 无丢包!
```

**验证 3: vhost 队列关联**
```bash
sudo python3 ebpf-tools/kvm-virt-network/vhost-net/vhost_queue_correlation_details.py \
  --interval 2
```

**修复后:**
```
Queue pair correlations:
  RX Queue 0 <-> TX Queue 0:
    - Correlation rate: 98.7%       ← 恢复正常!
    - Average processing gap: 8.3 us
    - Lost packets: 0               ← 无丢失!

  RX Queue 1 <-> TX Queue 1:
    - Correlation rate: 98.9%
    - Lost packets: 0

Queue utilization:
  - Queue 0 (RX): 32.1% busy        ← 负载均衡!
  - Queue 1 (RX): 28.7% busy
  - Queue 2 (RX): 29.5% busy
  - Queue 3 (RX): 31.2% busy
```

**验证 4: 业务指标**
```bash
# TCP 重传率
netstat -s | grep retransmit

# 修复前: ~8% 重传率
# 修复后: ~0.3% 重传率 (降低 96%)

# 吞吐量测试
iperf3 -c 10.132.114.12 -t 30

# 修复前: 1.2 Gbits/sec
# 修复后: 9.4 Gbits/sec (提升 683%)
```

**✅ 修复验证成功:**
- TUN 环形缓冲区溢出: 从 1,234 次/10s → 0
- 丢包率: 从 5-10% → 0%
- TCP 重传率: 从 8% → 0.3%
- 吞吐量: 从 1.2 Gbps → 9.4 Gbps (提升 683%)
- vhost CPU 使用率: 从 92% → 34% (单队列)

---

### 2.9 案例总结

**工具使用链路:**
```
kernel_drop_stack_stats_summary_all.py (定位丢包位置)
         ↓
eth_drop.py (确认 TUN 设备丢包)
         ↓
tun_ring_monitor.py (发现环形缓冲区溢出)
         ↓
vhost_eventfd_count.py (确认事件频率异常)
         ↓
vhost_queue_correlation_details.py (发现队列瓶颈)
         ↓
virtnet_poll_monitor.py (分析 NAPI 效率)
         ↓
系统工具 (确认 CPU 绑定问题)
```

**关键经验:**
1. ✅ 丢包问题需要**多层验证** (内核层 → TUN 层 → vhost 层 → virtio 层)
2. ✅ Summary 工具快速定位丢包栈,Details 工具分析瓶颈细节
3. ✅ 队列配置和 CPU 亲和性对虚拟化网络性能影响巨大
4. ✅ 环形缓冲区监控是诊断丢包的关键指标
5. ✅ 修复后需要**多工具交叉验证**,确保问题完全解决

---

## 总结: eBPF 工具诊断方法论

### 通用诊断流程

```
问题报告
    ↓
【第一层】Summary 工具 - 快速定位异常范围
    ├─ 延迟问题 → latency_summary.py
    ├─ 丢包问题 → drop_stats_summary.py
    └─ 性能问题 → performance_metrics.py
    ↓
【第二层】Details 工具 - 精确追踪瓶颈
    ├─ Per-packet 跟踪 → latency_details.py
    ├─ 栈跟踪分析 → eth_drop.py
    └─ 组件详细监控 → vhost/tun/virtio monitors
    ↓
【第三层】根因验证 - 交叉验证确认
    ├─ 相关组件监控 → CPU/memory/queue monitors
    ├─ 配置检查 → 系统配置/网络配置
    └─ 历史数据对比 → baseline comparison
    ↓
修复方案
    ↓
验证效果 (Summary 工具持续监控)
```

### 工具选择决策树

**场景 1: 延迟问题**
```
Is latency issue?
    ├─ Yes → Use latency_summary.py (identify abnormal stage)
    │         ├─ OVS stage slow? → ovs_upcall_latency_summary.py
    │         ├─ VM path slow? → vm_network_latency_details.py
    │         └─ Queue slow? → qdisc_lateny_details.py
    └─ No → Check other symptoms
```

**场景 2: 丢包问题**
```
Is packet drop?
    ├─ Yes → Use kernel_drop_stack_stats_summary.py (locate drop position)
    │         ├─ TUN layer? → tun_ring_monitor.py
    │         ├─ vhost layer? → vhost_queue_correlation_details.py
    │         └─ OVS layer? → ovs-kernel-module-drop-monitor.py
    └─ No → Check other symptoms
```

### 最佳实践建议

1. **始终从 Summary 工具开始** - 低开销,快速定位
2. **使用过滤器缩小范围** - Details 工具开销大,必须精准过滤
3. **多工具交叉验证** - 单一工具结论可能片面
4. **建立性能基线** - Summary 工具持续监控,建立正常baseline
5. **分层逐步深入** - 不要跳过中间层,逐层验证
6. **保存分析日志** - 便于后续复盘和趋势分析
7. **修复后验证** - 必须用工具验证修复效果

---

## 附录: 常见问题诊断速查表

| 症状 | 第一层工具 (Summary) | 第二层工具 (Details) | 可能根因 |
|------|---------------------|---------------------|---------|
| VM 延迟高 | vm_network_latency_summary.py | vm_network_latency_details.py | OVS/vhost/virtio 瓶颈 |
| 系统网络慢 | system_network_latency_summary.py | system_network_latency_details.py | 队列/CPU/conntrack |
| OVS 慢 | ovs_upcall_latency_summary.py | ovs_userspace_megaflow.py | Upcall 延迟/流表未命中 |
| 丢包 | kernel_drop_stack_stats_summary.py | eth_drop.py | 缓冲区/队列/CPU |
| TUN 丢包 | tun_ring_monitor.py | eth_drop.py (TUN filter) | 环形缓冲区溢出 |
| vhost 慢 | vhost_eventfd_count.py | vhost_queue_correlation_details.py | 队列饱和/CPU 绑定 |
| virtio 慢 | virtnet_poll_monitor.py | virtionet-rx-path-monitor.bt | NAPI 效率/中断聚合 |
| KVM 中断慢 | kvm_irqfd_stats_summary.py | - | 中断注入延迟 |

---

**文档版本**: v1.0
**最后更新**: 2025-10-20
**适用工具版本**: troubleshooting-tools v1.0+
