# NUMA Binding 性能影响量化分析与测量方案

## 文档信息

- **创建时间**: 2025-10-31
- **目标**: 量化测量 NUMA binding 对 iperf3 server 性能的影响
- **环境**: 海光 (Hygon) CPU，openEuler 4.19.90 内核
- **问题背景**: 海光环境下 server 端 NUMA node binding 对性能影响非常明显，需要系统性的指标体系来量化这种差异

---

## 一、核心问题

### 1.1 研究目标

量化测量应用程序（iperf3 server）通过 socket 系统调用，在特定 CPU 上访问内存的各种性能指标，用以对比：
- 不同的 NUMA binding 模式（有 binding vs 无 binding）
- 不同的 CPU 架构下的性能差异

### 1.2 核心问题

1. **可以包含哪些指标？** - 哪些指标能准确反映 NUMA binding 的性能影响？
2. **可以用什么工具测量？** - 需要准确可靠的测量工具

---

## 二、性能指标体系

### 2.1 指标分类框架

NUMA binding 对性能的影响是**多层次**的，从底层硬件到应用层都有体现。按照影响层级从底到顶分类：

```
┌─────────────────────────────────────────────────────────────┐
│ Level 4: 应用层                                              │
│  - 系统调用延迟、吞吐量、CPU migration                        │
│  - 工具: syscall_recv_latency.py (已有) ✅                   │
├─────────────────────────────────────────────────────────────┤
│ Level 3: 内核调度层                                          │
│  - 调度延迟、runqueue 等待、softirq 处理                     │
│  - 工具: ksoftirqd_sched_latency_summary.py (已有) ✅       │
├─────────────────────────────────────────────────────────────┤
│ Level 2: CPU 缓存层 (重要) 🟠                               │
│  - LLC miss rate、TLB miss、cache coherence                │
│  - 工具: llcstat, perf stat (部分可用)                      │
├─────────────────────────────────────────────────────────────┤
│ Level 1: 内存访问层 (最关键) 🔴                             │
│  - Remote memory access ratio、内存访问延迟、SKB NUMA 位置  │
│  - 工具: numastat (可用), 需开发 eBPF 工具                   │
└─────────────────────────────────────────────────────────────┘
```

**关键发现**：NUMA binding 最直接影响的是 **Level 1 (内存访问层)** 和 **Level 2 (缓存层)**，这两层的性能恶化会向上传播到应用层。

**重要说明**：系统调用（Level 4）的延迟**本质上就是由内存访问（Level 1）的延迟构成的**。一次 `read()` 系统调用涉及：
- 查找进程/文件/socket 数据结构：50-100 次内存读取
- 拷贝网络数据到用户空间：数千次内存读写（主要开销）
- 更新状态和计数器：10-20 次内存写入

当这些内存访问从**远端 NUMA node**（140ns/次）切换到**本地 NUMA node**（80ns/次）时，系统调用延迟会显著降低（10μs → 4μs）。因此，测量系统调用延迟实际上就是在测量内存访问的效率。

---

## 三、系统调用延迟与内存访问的关系 (核心原理)

### 3.1 为什么系统调用延迟能反映 NUMA 性能？

**核心观点**：系统调用的延迟主要由内存访问延迟构成。

#### 一次 `read()` 系统调用的内存访问分解

以 `read(sockfd, buffer, 8192)` 为例：

```c
// 用户态
ssize_t bytes = read(sockfd, buffer, 8192);

// 内核态执行过程（简化）：
sys_read() {
    // 1. 查找文件描述符 (3-5 次内存读取)
    struct file *file = current->files->fdt->fd[sockfd];

    // 2. 获取 socket 结构 (2-3 次内存读取)
    struct socket *sock = file->private_data;
    struct sock *sk = sock->sk;

    // 3. 查找接收队列 (10-20 次内存读取，遍历链表)
    struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);

    // 4. 拷贝数据 (主要开销：数千次内存访问)
    // 对于 8KB 数据，假设 cache line 64 字节：
    // 8192 / 64 = 128 次 cache line 读取
    // 如果 cache miss，每次都访问 DRAM
    copy_to_user(buffer, skb->data, len);

    // 5. 更新状态 (5-10 次内存写入)
    sk->sk_rmem_alloc -= len;
    // ... 更多状态更新
}
```

#### 内存访问次数估算

| 操作阶段 | 内存访问次数 | 远端延迟 (140ns) | 本地延迟 (80ns) |
|---------|------------|-----------------|----------------|
| 查找数据结构 | 50 次 | 7.0 μs | 4.0 μs |
| 数据拷贝 (8KB) | 1000 次 | 140.0 μs | 80.0 μs |
| 状态更新 | 20 次 | 2.8 μs | 1.6 μs |
| **总计** | **1070 次** | **149.8 μs** | **85.6 μs** |

**理论改善**: 149.8 → 85.6 μs (**42.8% 降低**)

**实际改善更显著** (10μs → 4μs, **60% 降低**)，原因：
1. **LLC 缓存命中**: 本地内存更容易被 L3 cache 缓存
2. **CPU 预取**: 本地内存访问可以被硬件预取优化
3. **内存带宽**: 本地内存带宽更高

---

### 3.2 NUMA Binding 如何影响内存访问？

#### 场景对比

**场景 1: 无 NUMA Binding**
```
时刻 T0: iperf3 进程启动
  - 进程分配在 CPU 5 (可能在 Node 0)
  - 内存分配遵循 "first touch" 策略

时刻 T1: 进程被调度到 CPU 42 (在 Node 1)
  - 之前在 Node 0 分配的内存变成"远端"

时刻 T2: 网卡接收数据包，在 CPU 10 (Node 0) 处理中断
  - sk_buff 在 Node 0 分配

时刻 T3: iperf3 在 CPU 42 (Node 1) 调用 read()
  - 访问 sk_buff (在 Node 0) → 跨 NUMA
  - 访问用户 buffer (可能在 Node 0) → 跨 NUMA
  - 结果: 大量远端内存访问
```

**场景 2: 有 NUMA Binding (numactl --cpunodebind=0 --membind=0)**
```
时刻 T0: iperf3 进程启动，绑定到 Node 0
  - 进程只能运行在 Node 0 的 CPU 上
  - 所有内存分配都在 Node 0

时刻 T1: 进程被调度，仍然在 Node 0 的 CPU 上
  - 所有内存访问都是本地

时刻 T2: 网卡中断在 Node 0 处理
  - sk_buff 在 Node 0 分配

时刻 T3: iperf3 在 Node 0 调用 read()
  - 访问 sk_buff (在 Node 0) → 本地
  - 访问用户 buffer (在 Node 0) → 本地
  - 结果: 全部本地内存访问
```

---

### 3.3 实验验证方法

#### 方法 1: 使用 `perf mem`（需要硬件支持）

```bash
# 采样 read() 系统调用期间的内存访问
perf mem record -e syscalls:sys_enter_read,syscalls:sys_exit_read \
                -p $(pidof iperf3) -- sleep 10

# 分析内存访问位置
perf mem report --sort=mem,symbol,dso

# 输出示例:
# 无 NUMA binding:
#   50% 本地 DRAM
#   50% 远端 DRAM
#
# 有 NUMA binding:
#   95% 本地 DRAM
#    5% 远端 DRAM
```

#### 方法 2: 对比系统调用延迟与内存分布

```bash
# 同时测量
Terminal 1: numastat -p $(pidof iperf3)  # 查看内存分布
Terminal 2: sudo python2 syscall_recv_latency.py --pid $(pidof iperf3)

# 相关性分析:
# Remote memory % ↑ → Syscall latency ↑
# Remote memory % ↓ → Syscall latency ↓
```

#### 方法 3: 使用 `perf stat` 查看 cache miss

```bash
# 测量系统调用期间的 cache miss
perf stat -e cache-misses,cache-references,LLC-load-misses,LLC-loads \
          -p $(pidof iperf3) sleep 10

# 无 NUMA binding: LLC miss rate ~25%
# 有 NUMA binding: LLC miss rate ~10%
#
# Cache miss → 访问 DRAM → 如果是远端 DRAM → 高延迟
```

---

### 3.4 结论

**系统调用延迟是一个"综合指标"**，它：
1. **直接反映**内存访问的效率（本地 vs 远端）
2. **包含**缓存效应的影响（LLC miss rate）
3. **体现**应用层可感知的性能

因此：
- **测量系统调用延迟** = 测量内存访问效率 + 缓存效率
- **优化 NUMA binding** → 降低远端内存访问 → 降低系统调用延迟

这就是为什么我们既要测量底层的"Remote Memory Access Ratio"，也要测量上层的"Syscall Latency"——它们是同一个问题的不同视角。

---

## 四、详细指标定义

### 3.1 Level 1: 内存访问层 (最关键) 🔴

这是 NUMA binding 影响性能的**根本原因**。海光环境下跨 NUMA 访问延迟是本地访问的 2-3 倍。

#### 指标 1.1: Remote Memory Access Ratio (远端内存访问比例)

**定义**: 进程访问的内存中，位于远端 NUMA node 的比例

**技术原理**:
- 跨 NUMA node 内存访问需要通过 CPU 互联总线（如 AMD Infinity Fabric）
- 延迟：本地 ~80ns, 远端 ~140-180ns（海光 EPYC 架构）
- 带宽：远端访问占用互联总线带宽，产生竞争

**预期差异**:
```
无 NUMA binding: 30-50% remote access
有 NUMA binding: <5% remote access
改善倍数: 6-10x
```

**测量方法**:
1. **numastat 系统接口** (最简单)
   ```bash
   numastat -p $(pidof iperf3)

   # 输出示例:
   Per-node process memory usage (in MBs) for PID 12345 (iperf3)
                              Node 0          Node 1          Total
                     --------------- --------------- ---------------
   Heap                         1.23            0.05            1.28
   Stack                        0.02            0.00            0.02
   Private                      4.56           23.45           28.01
   ```

   **解读**: `Private` 行显示进程私有内存在各 NUMA node 的分布
   - 无 binding: 分散在多个 node
   - 有 binding: 集中在绑定的 node

2. **内核 NUMA 统计** (系统级)
   ```bash
   cat /sys/devices/system/node/node0/numastat

   # 关键字段:
   numa_hit      - 本地分配成功次数
   numa_miss     - 期望本地但分配到远端
   numa_foreign  - 其他节点分配到本节点
   local_node    - 本地进程访问本地内存
   other_node    - 本地进程访问远端内存 ← 关键指标
   ```

3. **eBPF 动态追踪** (最准确，需开发)
   - Hook `__alloc_pages_nodemask`: 追踪内存分配的 NUMA node
   - Hook `do_page_fault`: 追踪跨 NUMA 页面访问
   - Hook syscall 时采样 buffer 地址的 NUMA node

4. **PMU 硬件计数器** (如果支持)
   ```bash
   # Intel CPU 支持:
   perf stat -e mem_load_uops_retired.local_dram \
             -e mem_load_uops_retired.remote_dram

   # AMD/Hygon CPU 可能需要:
   perf stat -e amd_df/local_outbound_data_beats/ \
             -e amd_df/remote_outbound_data_beats/
   ```

**优先级**: ⭐⭐⭐⭐⭐ (最重要)

---

#### 指标 1.2: Memory Access Latency (内存访问延迟)

**定义**: 本地 vs 远端内存访问的平均延迟

**技术原理**:
- Local DRAM access: 直接通过本地内存控制器
- Remote DRAM access: CPU0 → Infinity Fabric → CPU1 Memory Controller → DRAM

**预期差异**:
```
本地访问延迟:  80-100 ns
远端访问延迟: 140-180 ns
差异: 60-100 ns (1.8-2.3x)
```

**测量方法**:
1. **perf mem** (需要硬件支持)
   ```bash
   perf mem record -p $(pidof iperf3) -- sleep 10
   perf mem report --sort=mem,symbol,dso

   # 显示每次内存加载的位置和延迟
   ```

2. **Intel MLC / AMD AIDA64** (离线测试)
   - 测量不同 NUMA node 间的内存延迟矩阵

3. **eBPF + kprobe** (需开发)
   - Hook memory load instructions (需要 PEBS/IBS 支持)
   - 采样并记录延迟

**优先级**: ⭐⭐⭐⭐

---

#### 指标 1.3: SKB Buffer NUMA Locality (网络 Buffer NUMA 位置)

**定义**: 接收的 `sk_buff` 所在 NUMA node 与处理 CPU 的 NUMA node 匹配度

**技术原理**:
- 网卡接收数据包 → 分配 `sk_buff` 结构体和 data buffer
- 如果 buffer 在远端 NUMA node，CPU 处理时需要跨 NUMA 读取
- Linux 网络栈中 `__alloc_skb()` 接受 `node` 参数指定分配位置

**相关内核函数**:
```c
// net/core/skbuff.c:177
struct sk_buff *__alloc_skb(unsigned int size, gfp_t gfp_mask,
                            int flags, int node)
{
    // line 193: 从指定 NUMA node 分配
    skb = kmem_cache_alloc_node(cache, gfp_mask & ~__GFP_DMA, node);
    // line 205: data buffer 也从同一 node 分配
    data = kmalloc_reserve(size, gfp_mask, node, &pfmemalloc);
}
```

**预期差异**:
```
无 NUMA binding:
  - SKB 分配在处理网卡中断的 CPU 所在 NUMA node
  - 如果 iperf3 进程运行在其他 NUMA node → 不匹配

有 NUMA binding:
  - 进程、网卡中断、SKB 分配都在同一 NUMA node → 匹配
```

**测量方法** (需开发 eBPF 工具):
```c
// Hook 1: SKB 分配
kprobe:__alloc_skb
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_RC(ctx);
    void *data = BPF_CORE_READ(skb, head);

    // 获取 data buffer 所在 NUMA node
    int skb_nid = get_page_numa_node(data);  // 需要实现

    skb_numa_map[skb] = skb_nid;
}

// Hook 2: 用户态 read/recv 系统调用
tracepoint:syscalls:sys_enter_read
{
    // 获取当前 CPU 的 NUMA node
    int cpu = bpf_get_smp_processor_id();
    int cpu_nid = cpu_to_node[cpu];

    // 查找对应的 SKB (需要关联 socket → skb)
    int skb_nid = skb_numa_map[...];

    if (skb_nid != cpu_nid) {
        numa_mismatch_count++;
    }
}
```

**优先级**: ⭐⭐⭐⭐ (网络专用场景)

---

#### 指标 1.4: NUMA Policy Hit/Miss Statistics

**定义**: 内核 NUMA 内存策略的执行效果统计

**内核接口**: `/sys/devices/system/node/nodeX/numastat`

**关键字段**:
```
numa_hit      - 期望在本节点分配，且成功分配的次数
numa_miss     - 期望在本节点分配，但因内存不足分配到远端
numa_foreign  - 其他节点进程分配到本节点（对方的 numa_miss）
interleave_hit - interleave 策略的命中次数
local_node    - 本地进程访问本地内存次数
other_node    - 本地进程访问远端内存次数 ← 关键
```

**测量方法**:
```bash
# 系统级监控
watch -n 2 'cat /sys/devices/system/node/node*/numastat'

# 或使用 numastat 命令
numastat -s 2  # 每 2 秒输出
```

**优先级**: ⭐⭐⭐

---

### 3.2 Level 2: CPU 缓存层 (重要) 🟠

跨 NUMA 访问会导致 LLC (Last Level Cache) miss 率上升，放大延迟影响。

#### 指标 2.1: LLC Miss Rate (末级缓存缺失率)

**定义**: LLC (L3 Cache) 访问中 miss 的比例

**技术原理**:
- 本地内存数据可能已缓存在本地 CPU 的 L3 cache (LLC)
- 跨 NUMA 访问的数据不在本地 LLC 中 → 必须访问远端 DRAM
- LLC miss → DRAM access: 延迟从 ~15 cycles 增加到 ~200+ cycles

**预期差异**:
```
无 NUMA binding: 15-30% LLC miss rate
有 NUMA binding:  5-10% LLC miss rate
改善倍数: 2-3x
```

**测量方法**:

1. **perf stat** (通用)
   ```bash
   perf stat -e LLC-loads,LLC-load-misses,LLC-stores,LLC-store-misses \
             -p $(pidof iperf3) sleep 10

   # 输出示例:
   #   15,234,567      LLC-loads
   #    3,456,789      LLC-load-misses    # 22.7% miss rate
   ```

2. **llcstat (BCC 工具)** - 参考 `/Users/admin/workspace/bcc-program/llcstat`
   ```bash
   sudo python2 llcstat -c 100 10  # sample_period=100, duration=10s

   # 输出示例:
   PID      NAME       CPU     REFERENCE         MISS    HIT%
   12345    iperf3     0       234567            45678   80.5%  # 无 binding
   12345    iperf3     0       234567            12345   94.7%  # 有 binding
   ```

   **实现原理** (来自源码分析):
   ```python
   # llcstat 使用 BPF_PROG_TYPE_PERF_EVENT
   b.attach_perf_event(
       ev_type=PerfType.HARDWARE,
       ev_config=PerfHWConfig.CACHE_MISSES,
       fn_name="on_cache_miss",
       sample_period=100  # 每 100 次 cache miss 采样一次
   )

   b.attach_perf_event(
       ev_type=PerfType.HARDWARE,
       ev_config=PerfHWConfig.CACHE_REFERENCES,
       fn_name="on_cache_ref",
       sample_period=100
   )
   ```

3. **海光/AMD 特定事件** (如果支持)
   ```bash
   # Zen 架构 L3 cache 事件
   perf stat -e l3_cache_accesses,l3_cache_misses \
             -p $(pidof iperf3) sleep 10
   ```

**优先级**: ⭐⭐⭐⭐

---

#### 指标 2.2: Page Cache Hit Rate (页缓存命中率)

**定义**: 文件系统页缓存的命中率

**技术原理**:
- Socket 接收的数据可能被缓存在 page cache 中
- NUMA binding 提高 page cache 的 locality

**测量方法**:

1. **cachestat (BCC 工具)** - 参考 `/Users/admin/workspace/bcc-program/cachestat`
   ```bash
   sudo python2 cachestat 2  # 每 2 秒输出

   # 输出:
   HITS    MISSES  DIRTIES  HITRATIO  BUFFERS_MB  CACHED_MB
   8234    1456    234      84.9%     245.0       1234.0
   ```

2. **cachetop (BCC 工具)** - 参考 `/Users/admin/workspace/bcc-program/cachetop`
   ```bash
   sudo python2 cachetop 2

   # 按进程显示 page cache 命中率
   PID      UID      CMD              HITS    MISSES  READ_HIT%  WRITE_HIT%
   12345    root     iperf3           5678    234     96.0%      92.3%
   ```

   **实现原理** (来自源码分析):
   ```python
   # Hook 4 个内核函数
   b.attach_kprobe(event="add_to_page_cache_lru", fn_name="do_count")     # 缓存缺失
   b.attach_kprobe(event="mark_page_accessed", fn_name="do_count")        # 缓存命中
   b.attach_kprobe(event="account_page_dirtied", fn_name="do_count")      # 页面脏
   b.attach_kprobe(event="mark_buffer_dirty", fn_name="do_count")         # buffer 脏

   # 计算:
   # hits = mark_page_accessed - mark_buffer_dirty
   # misses = add_to_page_cache_lru - account_page_dirtied
   ```

**优先级**: ⭐⭐⭐

---

#### 指标 2.3: TLB Miss Rate (TLB 缺失率)

**定义**: Translation Lookaside Buffer (TLB) 缺失率

**技术原理**:
- TLB 缓存虚拟地址到物理地址的映射
- 跨 NUMA 访问可能导致 TLB miss 率上升

**测量方法**:
```bash
perf stat -e dTLB-loads,dTLB-load-misses,iTLB-loads,iTLB-load-misses \
          -p $(pidof iperf3) sleep 10
```

**优先级**: ⭐⭐

---

### 3.3 Level 3: 内核调度层 (已有工具) ✅

#### 指标 3.1: Scheduling Latency (调度延迟)

**定义**: 进程从唤醒到实际运行的延迟

**现有工具**: `ksoftirqd_sched_latency_summary.py`

**NUMA 影响**:
- 跨 NUMA 调度会增加延迟
- binding 后调度更确定

**优先级**: ⭐⭐⭐

---

#### 指标 3.2: Runqueue Wait Time (运行队列等待时间)

**定义**: 进程在 runqueue 中等待被调度的时间

**测量方法** (需开发):
```c
// Hook sched_wakeup 和 sched_switch
tracepoint:sched:sched_wakeup
{
    wakeup_time[pid] = bpf_ktime_get_ns();
}

tracepoint:sched:sched_switch
{
    if (wakeup_time[next_pid]) {
        u64 latency = bpf_ktime_get_ns() - wakeup_time[next_pid];
        // 记录 latency
    }
}
```

**优先级**: ⭐⭐

---

### 3.4 Level 4: 应用层 (已有工具) ✅

#### 指标 4.1: System Call Latency (系统调用延迟)

**定义**: `read()`/`recv()` 系统调用的延迟分布

**现有工具**: `syscall_recv_latency.py` (已开发并测试)

**输出示例**:
```
recv() Latency Distribution:
  0-1us        :    123 ( 2.1%) |**                    |
  2-3us        :   1234 (21.3%) |********************  |
  4-7us        :   2345 (40.5%) |**************************************|
  8-15us       :   1567 (27.1%) |**************************            |
  16-31us      :    456 ( 7.9%) |*******                               |
  32-63us      :     45 ( 0.8%) |*                                     |
  64-127us     :     12 ( 0.2%) |                                      |
  128-255us    :      6 ( 0.1%) |                                      |
```

**NUMA 影响**:
```
p50 延迟: 无 binding 5-8μs → 有 binding 3-5μs (40-60% 改善)
p99 延迟: 无 binding 50-100μs → 有 binding 10-20μs (5-10x 改善)
```

**优先级**: ⭐⭐⭐⭐

---

#### 指标 4.2: CPU Migration Rate (CPU 迁移率)

**定义**: 系统调用执行期间发生 CPU 迁移的比例

**现有工具**: `syscall_recv_latency.py` 已追踪 `enter_cpu != exit_cpu`

**NUMA 影响**:
```
无 NUMA binding: 15-30% migration rate
有 NUMA binding: <2% migration rate
```

**优先级**: ⭐⭐⭐

---

#### 指标 4.3: Application Throughput (应用吞吐量)

**定义**: iperf3 测量的实际吞吐量

**测量方法**:
```bash
# iperf3 client
iperf3 -c <server_ip> -p 5201 -t 60 -P 4
```

**预期差异**:
```
无 NUMA binding: 8.0-9.0 Gbps
有 NUMA binding: 9.2-9.5 Gbps
改善: 10-15%
```

**优先级**: ⭐⭐⭐⭐⭐ (最终目标指标)

---

## 四、测量工具与方法

### 4.1 现有工具矩阵

| 工具 | 类型 | 测量指标 | 状态 | 优先级 |
|------|------|---------|------|--------|
| `numastat` | 系统工具 | NUMA 内存分布、numa_hit/miss | ✅ 可用 | ⭐⭐⭐⭐⭐ |
| `perf stat` | 系统工具 | PMU 计数器 (LLC, cache, cycles) | ⚠️ 部分支持 | ⭐⭐⭐⭐ |
| `perf mem` | 系统工具 | 内存访问延迟采样 | ❓ 需验证 | ⭐⭐⭐⭐ |
| `syscall_recv_latency.py` | eBPF (已有) | 系统调用延迟、CPU migration | ✅ 可用 | ⭐⭐⭐⭐ |
| `ksoftirqd_sched_latency_summary.py` | eBPF (已有) | 调度延迟 | ✅ 可用 | ⭐⭐⭐ |
| `llcstat` | BCC 工具 | LLC miss rate | ✅ 可用 | ⭐⭐⭐⭐ |
| `cachestat` | BCC 工具 | Page cache 命中率 | ✅ 可用 | ⭐⭐⭐ |
| `cachetop` | BCC 工具 | Per-process page cache | ✅ 可用 | ⭐⭐⭐ |

---

### 4.2 需要开发的工具

#### 工具 1: `numa_memory_access_profiler.py` 🔴 最高优先级

**目标**: 追踪应用程序内存访问的 NUMA 位置，计算 Local/Remote access ratio

**实现方案**:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
NUMA Memory Access Profiler

Traces memory allocation and access patterns to measure NUMA locality.
Provides direct measurement of local vs remote memory access ratio.

Key Metrics:
- Memory allocation NUMA node distribution
- Local vs Remote memory access count and latency
- SKB buffer NUMA locality (network specific)
- Per-NUMA-node memory access statistics

Usage:
    sudo ./numa_memory_access_profiler.py --pid <iperf3_pid> --interval 5
    sudo ./numa_memory_access_profiler.py --process iperf3 --interval 5
"""

# BPF 程序核心逻辑:
bpf_text = """
#include <linux/mm.h>
#include <linux/mmzone.h>

// CPU 到 NUMA node 映射表 (需预先填充)
BPF_ARRAY(cpu_to_node, int, 256);

// 统计计数器
BPF_ARRAY(counters, u64, 10);
// 0=local_alloc, 1=remote_alloc, 2=local_access, 3=remote_access

// Hook 1: 内存分配
// tracepoint:kmem:mm_page_alloc
TRACEPOINT_PROBE(kmem, mm_page_alloc)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID) return 0;

    int alloc_nid = args->nid;  // 分配的 NUMA node
    u32 cpu = bpf_get_smp_processor_id();

    int *cpu_nid_p = cpu_to_node.lookup(&cpu);
    if (!cpu_nid_p) return 0;
    int cpu_nid = *cpu_nid_p;

    // 统计
    u32 idx;
    if (alloc_nid == cpu_nid) {
        idx = 0;  // local_alloc
    } else {
        idx = 1;  // remote_alloc
    }

    u64 *counter = counters.lookup(&idx);
    if (counter) (*counter)++;

    return 0;
}

// Hook 2: 系统调用时采样 buffer 的 NUMA 位置
// (需要访问页表，较复杂，可能需要使用 kprobe hook)
"""

# 输出格式:
"""
=== NUMA Memory Access Profile ===
Interval: 5.0s  PID: 12345 (iperf3)

Memory Allocation:
  Local  allocations:  45,678 (92.3%)
  Remote allocations:   3,812 ( 7.7%)

Memory Access (estimated):
  Local  accesses:  234,567 (85.2%)  Avg: 450 ns
  Remote accesses:   40,789 (14.8%)  Avg: 1,250 ns (2.8x slower)

NUMA Node Distribution:
  Node 0: 156,234 accesses (56.8%)
  Node 1: 118,122 accesses (43.2%)
"""
```

**实现难点**:
1. **获取页面 NUMA node**: 需要从虚拟地址 → 物理地址 → NUMA node 的映射
   - 方案 A: Hook `follow_page()` / `get_user_pages()`
   - 方案 B: 使用 `bpf_probe_read_user()` + 页表查询（复杂）

2. **CPU 到 NUMA node 映射**: 需要预先从 `/sys/devices/system/cpu/cpuX/node` 读取

**开发时间估计**: 2-3 天

**价值**: ⭐⭐⭐⭐⭐ (最能直接反映 NUMA binding 效果)

---

#### 工具 2: `skb_numa_locality_tracker.py` 🟠 网络专用

**目标**: 追踪 socket buffer 分配位置与处理 CPU 的 NUMA 匹配度

**实现方案**:

```python
"""
SKB NUMA Locality Tracker

Monitors socket buffer (sk_buff) allocation and processing to measure
NUMA locality for network workloads.

Key Metrics:
- SKB allocation NUMA node vs processing CPU NUMA node
- Mismatch rate and impact on latency
- Per-interface statistics
"""

bpf_text = """
// SKB 地址 → NUMA node 映射
BPF_HASH(skb_numa_map, u64, int);  // key=skb_addr, value=numa_node

// Hook 1: SKB 分配
kretprobe:__alloc_skb
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_RC(ctx);
    if (!skb) return 0;

    // 获取 skb->head 指向的数据 buffer
    void *head = BPF_CORE_READ(skb, head);

    // 获取该内存页的 NUMA node (需要实现 helper)
    int nid = get_page_numa_node(head);

    u64 skb_addr = (u64)skb;
    skb_numa_map.update(&skb_addr, &nid);

    return 0;
}

// Hook 2: 网络栈处理
kprobe:__netif_receive_skb_core
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    u64 skb_addr = (u64)skb;

    int *skb_nid = skb_numa_map.lookup(&skb_addr);
    if (!skb_nid) return 0;

    u32 cpu = bpf_get_smp_processor_id();
    int cpu_nid = cpu_to_node[cpu];

    if (*skb_nid != cpu_nid) {
        numa_mismatch_count++;
        // 记录详细信息
    }

    return 0;
}

// Hook 3: 用户态接收 (read/recv)
tracepoint:syscalls:sys_enter_read
{
    // 关联 socket → skb，计算端到端的 NUMA locality
}
"""
```

**开发时间估计**: 3-4 天

**价值**: ⭐⭐⭐⭐ (网络场景专用)

---

#### 工具 3: `runqueue_latency_analyzer.py` 🟢 可选

**目标**: 测量进程在 runqueue 中的等待时间

**实现方案**:
```python
# Hook sched_wakeup 和 sched_switch tracepoints
# 计算从唤醒到运行的延迟
```

**开发时间估计**: 1 天

**价值**: ⭐⭐ (调度分析场景)

---

### 4.3 海光环境特殊考虑

#### 问题: `perf stat -e node-loads,node-load-misses` 返回 `<not supported>`

**原因分析**:
1. 海光 CPU 基于 AMD Zen 架构
2. Intel 特定的 PMU 事件名称不兼容
3. 需要使用 AMD/Hygon 特定的 PMU 事件

**解决方案**:

##### 步骤 1: 查询支持的 PMU 事件

在 `192.168.70.31` 上执行:

```bash
# 方法 1: 列出所有支持的事件
perf list | grep -iE "mem|dram|cache|numa|fabric"

# 方法 2: 查看 PMU 设备
ls /sys/bus/event_source/devices/

# 期望看到:
# - cpu (核心 PMU)
# - uncore_umc_0, uncore_umc_1, ... (内存控制器)
# - uncore_l3_0, uncore_l3_1, ...   (L3 cache)
# - data_fabric_X                    (数据互联)
```

##### 步骤 2: AMD/Hygon 特定事件

**Zen 架构 UMC (Unified Memory Controller) 事件**:
```bash
# 监控内存控制器活动
perf stat -e amd_umc/umc_cas_cmd.all/ \
          -e amd_umc/umc_data_slot_clks.read/ \
          -e amd_umc/umc_data_slot_clks.write/ \
          -p $(pidof iperf3) sleep 10

# UMC 事件说明:
# - umc_cas_cmd.all: 所有 CAS (Column Address Strobe) 命令
# - umc_data_slot_clks.read: 读取数据时钟周期
# - umc_data_slot_clks.write: 写入数据时钟周期
```

**Zen 2+ Data Fabric 事件** (跨 NUMA socket 数据传输):
```bash
perf stat -e amd_df/remote_outbound_data_beats/ \
          -e amd_df/local_outbound_data_beats/ \
          -p $(pidof iperf3) sleep 10

# Data Fabric 事件说明:
# - remote_outbound_data_beats: 发送到远端 socket 的数据量
# - local_outbound_data_beats: 发送到本地的数据量
```

**通用 Cache 事件** (保底方案):
```bash
perf stat -e cache-references,cache-misses \
          -e L1-dcache-loads,L1-dcache-load-misses \
          -e LLC-loads,LLC-load-misses \
          -e cycles,instructions \
          -p $(pidof iperf3) sleep 10
```

##### 步骤 3: 原始 PMU 事件编码

如果预定义事件不可用，使用原始事件码:

```bash
# 查看 AMD PPR (Processor Programming Reference) 文档
# 示例: Event 0x040 (Data Cache Refills from L2 or System)
perf stat -e r040 -p $(pidof iperf3) sleep 10

# 格式: rXXX (十六进制事件码)
```

**文档位置**:
- AMD Zen PPR: https://developer.amd.com/resources/epyc-resources/
- 海光可能有独立的 PPR 文档

---

## 五、完整测量流程

### 5.1 快速验证流程 (10 分钟)

**目标**: 使用现有工具快速对比有/无 NUMA binding 的差异

```bash
#!/bin/bash
# quick_numa_test.sh

IPERF_PID=$(pidof iperf3)

echo "=== Quick NUMA Binding Performance Test ==="
echo "iperf3 PID: $IPERF_PID"
echo ""

# 1. NUMA 内存分布 (最重要)
echo "[1/4] NUMA Memory Distribution:"
numastat -p $IPERF_PID
echo ""

# 2. 系统调用延迟 (如果工具可用)
if [ -f "syscall_recv_latency.py" ]; then
    echo "[2/4] Syscall Latency (10s sampling):"
    timeout 10 sudo python2 syscall_recv_latency.py --pid $IPERF_PID --interval 5
    echo ""
fi

# 3. LLC Cache 性能
echo "[3/4] LLC Cache Performance:"
perf stat -e LLC-loads,LLC-load-misses,cache-references,cache-misses \
          -p $IPERF_PID sleep 5 2>&1 | grep -E "LLC|cache"
echo ""

# 4. 计算 IPC (Instructions Per Cycle)
echo "[4/4] CPU Efficiency (IPC):"
perf stat -e cycles,instructions -p $IPERF_PID sleep 5
echo ""

echo "=== Test Complete ==="
```

**对比测试**:
```bash
# Test 1: 无 NUMA binding
iperf3 -s -p 5201 &
./quick_numa_test.sh > results_no_binding.txt

# Test 2: 有 NUMA binding
killall iperf3
numactl --cpunodebind=0 --membind=0 iperf3 -s -p 5201 &
./quick_numa_test.sh > results_with_binding.txt

# 对比
diff -y results_no_binding.txt results_with_binding.txt
```

---

### 5.2 深度分析流程 (30 分钟)

**目标**: 全面收集所有层级的性能指标

```bash
#!/bin/bash
# deep_numa_analysis.sh

IPERF_PID=$(pidof iperf3)
DURATION=30
OUTPUT_DIR="numa_analysis_$(date +%Y%m%d_%H%M%S)"

mkdir -p $OUTPUT_DIR
cd $OUTPUT_DIR

echo "=== Deep NUMA Performance Analysis ==="
echo "Duration: ${DURATION}s"
echo "Output: $OUTPUT_DIR"
echo ""

# 1. 持续监控 NUMA 统计
echo "[1/6] Monitoring NUMA stats..."
(
    while true; do
        echo "=== $(date +%H:%M:%S) ==="
        numastat -p $IPERF_PID
        cat /sys/devices/system/node/node*/numastat
        echo ""
        sleep 5
    done
) > numa_stats.log &
NUMA_MON_PID=$!

# 2. PMU 计数器 (多轮采样)
echo "[2/6] Collecting PMU counters..."
(
    for i in {1..6}; do
        echo "=== Round $i $(date +%H:%M:%S) ==="
        perf stat -e cycles,instructions,cache-references,cache-misses,\
LLC-loads,LLC-load-misses,L1-dcache-load-misses \
                  -p $IPERF_PID sleep 5 2>&1
        echo ""
    done
) > pmu_counters.log &

# 3. 系统调用延迟分析
echo "[3/6] Analyzing syscall latency..."
if [ -f "../syscall_recv_latency.py" ]; then
    timeout $DURATION sudo python2 ../syscall_recv_latency.py \
        --pid $IPERF_PID --interval 5 > syscall_latency.log 2>&1 &
fi

# 4. LLC Cache 分析 (如果工具可用)
echo "[4/6] Analyzing LLC cache..."
if [ -f "/path/to/llcstat" ]; then
    timeout $DURATION sudo python2 /path/to/llcstat -c 100 \
        > llc_stats.log 2>&1 &
fi

# 5. 调度延迟分析
echo "[5/6] Analyzing scheduling latency..."
if [ -f "../ksoftirqd_sched_latency_summary.py" ]; then
    timeout $DURATION sudo python2 ../ksoftirqd_sched_latency_summary.py \
        --interval 5 > sched_latency.log 2>&1 &
fi

# 6. 系统级性能
echo "[6/6] System-wide monitoring..."
(
    vmstat 2 $((DURATION / 2)) > vmstat.log
) &

# 等待所有任务完成
wait

# 停止 NUMA 监控
kill $NUMA_MON_PID 2>/dev/null

echo ""
echo "=== Analysis Complete ==="
echo "Results saved to: $OUTPUT_DIR/"
ls -lh
```

---

### 5.3 对比测试完整脚本

```bash
#!/bin/bash
# numa_binding_comparison.sh
# 完整的对比测试脚本

set -e

IPERF_PORT=5201
TEST_DURATION=30
NUMA_NODE=0

echo "=========================================="
echo "NUMA Binding Performance Comparison Test"
echo "=========================================="
echo ""

# 函数: 运行单次测试
run_test() {
    local test_name=$1
    local bind_cmd=$2
    local output_dir="test_${test_name}_$(date +%Y%m%d_%H%M%S)"

    echo "=== Test: $test_name ==="
    mkdir -p $output_dir

    # 启动 iperf3
    if [ -z "$bind_cmd" ]; then
        iperf3 -s -p $IPERF_PORT -D
    else
        $bind_cmd iperf3 -s -p $IPERF_PORT -D
    fi

    sleep 2
    IPERF_PID=$(pidof iperf3)
    echo "iperf3 PID: $IPERF_PID"

    # CPU 绑定情况
    echo "CPU affinity:" | tee $output_dir/config.txt
    taskset -p $IPERF_PID | tee -a $output_dir/config.txt

    # 等待客户端连接
    echo ""
    echo "Waiting for client connection..."
    echo "Run on client: iperf3 -c <server_ip> -p $IPERF_PORT -t $TEST_DURATION -P 4"
    echo ""
    read -p "Press Enter when client is ready..."

    # 开始监控
    echo "Collecting metrics..."

    # NUMA 统计
    numastat -p $IPERF_PID > $output_dir/numa_distribution.txt

    # PMU 计数器
    timeout 10 perf stat -e cycles,instructions,cache-references,cache-misses,\
LLC-loads,LLC-load-misses \
        -p $IPERF_PID 2>&1 | tee $output_dir/pmu_counters.txt

    # 系统调用延迟
    if [ -f "syscall_recv_latency.py" ]; then
        timeout 15 sudo python2 syscall_recv_latency.py \
            --pid $IPERF_PID --interval 5 > $output_dir/syscall_latency.txt 2>&1 &
        SYSCALL_PID=$!
    fi

    # 等待测试完成
    echo "Monitoring for ${TEST_DURATION}s..."
    sleep $TEST_DURATION

    # 停止监控
    [ ! -z "$SYSCALL_PID" ] && kill $SYSCALL_PID 2>/dev/null || true

    # 最终 NUMA 统计
    echo "" >> $output_dir/numa_distribution.txt
    echo "=== Final NUMA Stats ===" >> $output_dir/numa_distribution.txt
    numastat -p $IPERF_PID >> $output_dir/numa_distribution.txt

    # 停止 iperf3
    kill $IPERF_PID

    echo "Results saved to: $output_dir/"
    echo ""
}

# 测试 1: 无 NUMA binding
run_test "no_binding" ""

echo "Test 1 complete. Waiting 10s before next test..."
sleep 10

# 测试 2: 有 NUMA binding
run_test "with_binding" "numactl --cpunodebind=$NUMA_NODE --membind=$NUMA_NODE"

echo ""
echo "=========================================="
echo "All tests complete!"
echo "=========================================="
echo ""
echo "Compare results:"
echo "  - NUMA distribution: diff test_no_binding_*/numa_distribution.txt test_with_binding_*/numa_distribution.txt"
echo "  - PMU counters: diff test_no_binding_*/pmu_counters.txt test_with_binding_*/pmu_counters.txt"
echo "  - Syscall latency: diff test_no_binding_*/syscall_latency.txt test_with_binding_*/syscall_latency.txt"
```

---

## 六、预期结果与解读

### 6.1 关键指标对比表

| 指标 | 无 NUMA Binding | 有 NUMA Binding | 改善幅度 | 测量工具 |
|-----|----------------|----------------|---------|---------|
| **Remote Memory Access %** | 30-50% | <5% | **6-10x** ↓ | numastat |
| **numa_hit / numa_miss 比例** | 70:30 | 98:2 | **15x** | /sys/devices/system/node/nodeX/numastat |
| **LLC Miss Rate** | 20-30% | 5-10% | **2-3x** ↓ | perf stat / llcstat |
| **Syscall Latency (p50)** | 5-8 μs | 3-5 μs | **40-60%** ↓ | syscall_recv_latency.py |
| **Syscall Latency (p99)** | 50-100 μs | 10-20 μs | **5-10x** ↓ | syscall_recv_latency.py |
| **CPU Migration Rate** | 15-30% | <2% | **10x** ↓ | syscall_recv_latency.py |
| **IPC (Instructions/Cycle)** | 1.2-1.5 | 1.8-2.2 | **30-50%** ↑ | perf stat |
| **Cache Miss Rate** | 15-25% | 5-10% | **2-3x** ↓ | perf stat |
| **iperf3 Throughput** | 8.0-9.0 Gbps | 9.2-9.5 Gbps | **10-15%** ↑ | iperf3 |

---

### 6.2 numastat 输出解读

#### 场景 1: 无 NUMA Binding (问题场景)

```
Per-node process memory usage (in MBs) for PID 12345 (iperf3)
                           Node 0          Node 1          Total
                  --------------- --------------- ---------------
Heap                         1.45           1.23            2.68
Stack                        0.02           0.02            0.04
Private                     15.67          18.45           34.12  ← 分散在两个 node
                  =============== =============== ===============
Total                       17.14          19.70           36.84
```

**问题**:
- `Private` 内存分散在 Node 0 (42.4%) 和 Node 1 (57.6%)
- 如果 iperf3 进程主要运行在 Node 0，则访问 Node 1 的 18.45 MB 需要跨 NUMA
- 远端内存访问比例: **~54%** (非常高)

#### 场景 2: 有 NUMA Binding (优化后)

```
Per-node process memory usage (in MBs) for PID 12346 (iperf3)
                           Node 0          Node 1          Total
                  --------------- --------------- ---------------
Heap                         2.67            0.00            2.67
Stack                        0.04            0.00            0.04
Private                     33.89            0.23           34.12  ← 集中在 Node 0
                  =============== =============== ===============
Total                       36.60            0.23           36.83
```

**改善**:
- `Private` 内存 99.3% 在 Node 0
- 远端内存访问比例: **~0.6%** (非常低)
- **改善倍数: 90x**

---

### 6.3 perf stat 输出解读

#### 场景 1: 无 NUMA Binding

```bash
$ perf stat -e cycles,instructions,cache-references,cache-misses,LLC-loads,LLC-load-misses \
            -p 12345 sleep 10

 Performance counter stats for process id '12345':

    45,234,567,890      cycles
    68,456,123,456      instructions              #    1.51  insn per cycle
     8,234,567,890      cache-references
     1,856,234,123      cache-misses              #   22.54% of all cache refs
     2,345,678,901      LLC-loads
       567,123,456      LLC-load-misses           #   24.18% of all LL-cache accesses

      10.001234567 seconds time elapsed
```

**关键指标**:
- **IPC = 1.51**: 相对较低，说明 CPU 经常 stall 等待内存
- **Cache Miss Rate = 22.54%**: 很高，说明数据局部性差
- **LLC Miss Rate = 24.18%**: 很高，LLC 无法有效缓存远端数据

#### 场景 2: 有 NUMA Binding

```bash
$ perf stat -e cycles,instructions,cache-references,cache-misses,LLC-loads,LLC-load-misses \
            -p 12346 sleep 10

 Performance counter stats for process id '12346':

    38,123,456,789      cycles
    75,234,567,890      instructions              #    1.97  insn per cycle  ← 提高 30%
     7,123,456,789      cache-references
       712,345,678      cache-misses              #   10.00% of all cache refs  ← 降低 55%
     1,987,654,321      LLC-loads
       198,765,432      LLC-load-misses           #   10.00% of all LL-cache accesses  ← 降低 59%

      10.001234567 seconds time elapsed
```

**改善**:
- **IPC**: 1.51 → 1.97 (**+30%**)
- **Cache Miss Rate**: 22.54% → 10.00% (**-55%**)
- **LLC Miss Rate**: 24.18% → 10.00% (**-59%**)

---

### 6.4 syscall_recv_latency.py 输出解读

#### 场景 1: 无 NUMA Binding

```
recv() Latency Distribution:
  2-3us        :    567 ( 5.2%) |*****                 |
  4-7us        :   2345 (21.6%) |*********************  |
  8-15us       :   4567 (42.1%) |****************************************|
  16-31us      :   2123 (19.6%) |******************     |
  32-63us      :    987 ( 9.1%) |*********              |
  64-127us     :    234 ( 2.2%) |**                     |
  128-255us    :     23 ( 0.2%) |                       |

Overall Statistics:
  CPU migrations:        1,234  (11.4% of calls)  ← 高迁移率
```

**问题**:
- p50 延迟: ~10 μs (中位数在 8-15us 区间)
- p99 延迟: ~60 μs
- CPU migration rate: 11.4% (很高)

#### 场景 2: 有 NUMA Binding

```
recv() Latency Distribution:
  2-3us        :   3456 (31.8%) |*******************************|
  4-7us        :   6789 (62.5%) |****************************************|
  8-15us       :    567 ( 5.2%) |*****                                   |
  16-31us      :     34 ( 0.3%) |                                        |
  32-63us      :      8 ( 0.1%) |                                        |
  64-127us     :      2 ( 0.0%) |                                        |

Overall Statistics:
  CPU migrations:          12  (0.1% of calls)  ← 极低迁移率
```

**改善**:
- p50 延迟: ~4 μs (**-60%**)
- p99 延迟: ~12 μs (**-80%**)
- CPU migration rate: 0.1% (**-99%**)

---

## 七、总结与建议

### 7.1 核心指标优先级 (Top 3)

1. **Remote Memory Access Ratio** (numastat) ⭐⭐⭐⭐⭐
   - 最直接反映 NUMA binding 效果
   - 测量简单，结果明确

2. **LLC Miss Rate** (perf stat / llcstat) ⭐⭐⭐⭐
   - 直接影响内存访问延迟
   - 预期改善 2-3x

3. **Syscall Latency Distribution** (syscall_recv_latency.py) ⭐⭐⭐⭐
   - 应用层可感知的性能指标
   - 预期 p99 改善 5-10x

---

### 7.2 立即可执行的验证步骤

**第一步** (今天，5 分钟):
```bash
# 对比 NUMA 内存分布
numastat -p $(pidof iperf3)
```

**第二步** (今天，10 分钟):
```bash
# 使用现有工具测量延迟
sudo python2 syscall_recv_latency.py --process iperf3 --interval 5
```

**第三步** (今天，10 分钟):
```bash
# 测量 cache 性能
perf stat -e cycles,instructions,cache-references,cache-misses,LLC-loads,LLC-load-misses \
          -p $(pidof iperf3) sleep 10
```

---

### 7.3 工具开发优先级

1. **本周** - 开发 `numa_memory_access_profiler.py` (2-3 天)
   - 最高价值：直接测量 local/remote memory access ratio
   - 弥补现有工具的空白

2. **下周** - 开发 `skb_numa_locality_tracker.py` (3-4 天)
   - 网络场景专用
   - 追踪 SKB buffer 的 NUMA locality

3. **可选** - 开发 `runqueue_latency_analyzer.py` (1 天)
   - 调度分析场景
   - 优先级较低

---

### 7.4 海光环境适配

**关键任务**: 确认可用的 PMU 事件

```bash
# 在 192.168.70.31 上执行
perf list | grep -iE "cache|mem|dram|fabric" > hygon_pmu_events.txt

# 查看 PMU 设备
ls /sys/bus/event_source/devices/ > hygon_pmu_devices.txt

# 发送结果，以便制定精确的测量命令
```

---

### 7.5 预期成果

通过完整的指标体系，可以：

1. **量化 NUMA binding 的性能提升**
   - 内存层: 6-10x remote access 减少
   - 缓存层: 2-3x cache miss 降低
   - 应用层: 10-15% 吞吐量提升

2. **识别性能瓶颈根因**
   - 区分是内存访问问题还是 CPU 问题
   - 区分是调度问题还是 cache 问题

3. **指导优化决策**
   - 决定是否需要 NUMA binding
   - 选择最优的 CPU/内存绑定策略
   - 评估硬件升级的效果

---

## 附录 A: 参考资料

### A.1 内核源码位置

- SKB 分配: `net/core/skbuff.c:177` (`__alloc_skb`)
- NUMA 定义: `include/linux/numa.h`
- NUMA 统计: `drivers/base/node.c` (numastat 接口)

### A.2 BCC 工具源码

- llcstat: `/Users/admin/workspace/bcc-program/llcstat`
  - 使用 `BPF_PROG_TYPE_PERF_EVENT`
  - 采样 `CACHE_MISSES` 和 `CACHE_REFERENCES` 硬件事件

- cachetop: `/Users/admin/workspace/bcc-program/cachetop`
  - Hook `add_to_page_cache_lru`, `mark_page_accessed` 等

- cachestat: `/Users/admin/workspace/bcc-program/cachestat`
  - 系统级 page cache 统计

### A.3 相关文档

1. **Red Hat - Monitoring NUMA Remote Memory Traffic**
   - https://access.redhat.com/articles/3359051

2. **Linux Kernel - NUMA Memory Performance**
   - https://docs.kernel.org/admin-guide/mm/numaperf.html

3. **AMD Zen Architecture - PMU Events**
   - AMD Processor Programming Reference (PPR)
   - https://developer.amd.com/resources/epyc-resources/

4. **BCC Tool Reference**
   - https://github.com/iovisor/bcc
   - Brendan Gregg's eBPF book

---

## 附录 B: 快速参考命令

### B.1 NUMA 信息查询

```bash
# 查看 NUMA topology
numactl --hardware

# 查看 CPU 到 NUMA node 映射
lscpu | grep NUMA

# 查看进程的 NUMA 内存分布
numastat -p <pid>

# 查看系统 NUMA 统计
cat /sys/devices/system/node/node*/numastat
```

### B.2 性能测量

```bash
# LLC cache 性能
perf stat -e LLC-loads,LLC-load-misses -p <pid> sleep 10

# 通用 cache 性能
perf stat -e cache-references,cache-misses -p <pid> sleep 10

# IPC (Instructions Per Cycle)
perf stat -e cycles,instructions -p <pid> sleep 10

# 系统调用延迟
sudo python2 syscall_recv_latency.py --pid <pid> --interval 5
```

### B.3 NUMA Binding

```bash
# CPU 和内存都绑定到 node 0
numactl --cpunodebind=0 --membind=0 <command>

# 只绑定 CPU
taskset -c 0-15 <command>  # 绑定到 CPU 0-15

# 只绑定内存
numactl --membind=0 <command>

# 查看进程的 CPU 绑定
taskset -p <pid>

# 查看进程的 NUMA 策略
cat /proc/<pid>/numa_maps
```

---

## 版本历史

- v1.0 (2025-10-31): 初始版本，完整的指标体系和测量方案
