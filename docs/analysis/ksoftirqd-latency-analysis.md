# ksoftirqd 延迟分析指南

## 背景

在 Hygon 测试环境中观察到高延迟长尾（1-2ms），调用栈显示数据包处理通过 ksoftirqd 路径：

```
__netif_receive_skb+0x1
process_backlog+0x9b
net_rx_action+0x156
__softirqentry_text_start+0xe8
run_ksoftirqd+0x26        ← 关键：通过 ksoftirqd 处理
smpboot_thread_fn+0xef
kthread+0x113
ret_from_fork+0x22
```

## 问题1: 如何知道进入 ksoftirqd 的路径？

### softirq 处理的三种路径

Linux 内核处理 softirq 有三种主要路径：

#### 路径 1: 硬中断退出时立即处理（快速路径）
```
硬中断处理
  → irq_exit()
    → invoke_softirq()
      → __do_softirq()         ← 在中断上下文直接执行
        → net_rx_action()
```

**特征:**
- 延迟最低（通常 < 20us）
- 在硬中断上下文中执行
- 调用栈显示：`do_IRQ → irq_exit → __softirqentry_text_start`

**触发条件:**
- `in_interrupt()` 返回 false（不在中断嵌套中）
- `!force_irqthreads` （没有强制 IRQ 线程化）
- softirq 预算未耗尽

#### 路径 2: 进程上下文主动检查（中等路径）
```
系统调用/异常返回
  → local_bh_enable()
    → do_softirq()
      → __do_softirq()
        → net_rx_action()
```

**特征:**
- 延迟中等（20-100us）
- 在进程上下文执行
- 调用栈显示：`do_softirq_own_stack → __softirqentry_text_start`

#### 路径 3: ksoftirqd 延迟处理（慢速路径）
```
enqueue_to_backlog()
  → ____napi_schedule()
    → __raise_softirq_irqoff(NET_RX_SOFTIRQ)
      → 检查条件 → wakeup_softirqd()    ← 唤醒 ksoftirqd
        ↓
      [调度延迟]                         ← **主要延迟来源**
        ↓
      run_ksoftirqd()
        → __do_softirq()
          → net_rx_action()
```

**特征:**
- 延迟最高（可能 1-10ms+）
- 在 ksoftirqd 内核线程执行
- 调用栈显示：`run_ksoftirqd → smpboot_thread_fn → kthread`

**触发条件（进入 ksoftirqd）:**
1. **Softirq 预算耗尽**: `__do_softirq()` 执行时间超过 2ms
2. **Softirq 过载**: 单次 `__do_softirq()` 循环处理超过 10 轮
3. **强制推迟**: 当前在中断上下文中且 `need_resched()` 被设置

### 如何判断进入 ksoftirqd 的具体原因？

需要在以下关键点添加 kprobe：

#### 方法 1: 追踪 `wakeup_softirqd` 调用点

在内核源码 `kernel/softirq.c` 中，`wakeup_softirqd()` 有三个主要调用点：

```c
// 调用点 1: __do_softirq() 中预算耗尽
asmlinkage __visible void __softirq_entry __do_softirq(void)
{
    // ... 执行 softirq handlers ...

    if (pending) {  // 还有未处理的 softirq
        wakeup_softirqd();  // 唤醒 ksoftirqd 继续处理
    }
}

// 调用点 2: irq_exit() 中检测到需要调度
void irq_exit(void)
{
    if (!in_interrupt() && local_softirq_pending())
        invoke_softirq();
    else if (local_softirq_pending())
        wakeup_softirqd();  // 在中断上下文中，推迟到 ksoftirqd
}

// 调用点 3: raise_softirq_irqoff() - softirq 被触发但不能立即处理
void raise_softirq_irqoff(unsigned int nr)
{
    if (!in_interrupt())
        wakeup_softirqd();
}
```

**实现方案**: 在 `wakeup_softirqd` 入口添加 kprobe，记录调用栈和上下文信息

#### 方法 2: 追踪 NAPI schedule 标志

在 `enqueue_to_backlog()` 中检查是否设置了 NAPI_STATE_SCHED：

```c
if (!__test_and_set_bit(NAPI_STATE_SCHED, &sd->backlog.state)) {
    if (!rps_ipi_queued(sd))
        ____napi_schedule(sd, &sd->backlog);  // 触发 NET_RX_SOFTIRQ
}
```

**实现方案**: 在现有的 `kprobe__enqueue_to_backlog` 中添加标志记录

## 问题2: 如何测量 ksoftirqd 的调度延迟？

### ksoftirqd 调度延迟的定义

ksoftirqd 调度延迟 = `run_ksoftirqd() 开始执行时间` - `wakeup_softirqd() 调用时间`

这个延迟包括：
1. **唤醒延迟**: 从 `wakeup_softirqd()` 到 ksoftirqd 线程被标记为可运行
2. **调度延迟**: 从可运行到实际被调度器选中执行

### 测量方案

#### 方案 A: 追踪 wakeup → run 的完整路径

```
wakeup_softirqd()  [记录时间戳 T1]
    ↓
wake_up_process(tsk)
    ↓
try_to_wake_up()   [可选：记录唤醒事件]
    ↓
[调度器选择]
    ↓
run_ksoftirqd()    [记录时间戳 T2]
    ↓
调度延迟 = T2 - T1
```

**实现:**
- kprobe on `wakeup_softirqd`: 记录 per-CPU 唤醒时间戳
- kprobe on `run_ksoftirqd`: 计算延迟并输出

**挑战:**
- `wakeup_softirqd()` 是静态函数，可能无法直接 probe
- 需要处理并发（同一 CPU 多次唤醒）

#### 方案 B: 使用 sched tracepoints

利用内核调度器的 tracepoint：

```
tracepoint:sched:sched_wakeup      - ksoftirqd 被唤醒
tracepoint:sched:sched_switch      - ksoftirqd 开始运行
```

**实现:**
```c
// 追踪 ksoftirqd 唤醒
TRACEPOINT_PROBE(sched, sched_wakeup)
{
    char comm[TASK_COMM_LEN];
    bpf_probe_read_kernel(&comm, sizeof(comm), args->comm);

    // 检查是否是 ksoftirqd
    if (comm[0] == 'k' && comm[1] == 's' && comm[2] == 'o') {
        // 记录唤醒时间戳
        u32 pid = args->pid;
        u64 ts = bpf_ktime_get_ns();
        ksoftirqd_wakeup_ts.update(&pid, &ts);
    }
}

// 追踪 ksoftirqd 开始运行
TRACEPOINT_PROBE(sched, sched_switch)
{
    char next_comm[TASK_COMM_LEN];
    bpf_probe_read_kernel(&next_comm, sizeof(next_comm), args->next_comm);

    if (next_comm[0] == 'k' && next_comm[1] == 's' && next_comm[2] == 'o') {
        u32 pid = args->next_pid;
        u64 *wakeup_ts = ksoftirqd_wakeup_ts.lookup(&pid);

        if (wakeup_ts) {
            u64 now = bpf_ktime_get_ns();
            u64 sched_latency = now - *wakeup_ts;
            // 输出调度延迟
        }
    }
}
```

#### 方案 C: 简化方案 - 仅追踪 net_rx_action 前的等待时间

由于我们主要关心网络数据包处理的延迟：

```
enqueue_to_backlog()      [记录时间戳 T1]
    ↓
[等待 ksoftirqd 调度]
    ↓
net_rx_action()           [记录时间戳 T2]
    ↓
总延迟 = T2 - T1           ← 包含了 ksoftirqd 调度延迟
```

**实现:**
- kprobe on `enqueue_to_backlog`: 记录 per-CPU 时间戳（已有）
- kprobe on `net_rx_action`: 计算总延迟（新增）

**优势:**
- 实现简单，不需要追踪调度器
- 直接测量对数据包处理的影响
- 已经在现有的 `enqueue_to_iprec_latency_threshold.py` 中部分实现

**缺陷:**
- 无法区分 ksoftirqd 调度延迟 vs 其他开销
- 如果 packet 在 `net_rx_action` 之前就被其他路径处理，会丢失

### 推荐的实现方案

**短期方案（立即可用）:**
使用方案 C，在现有工具基础上添加 per-CPU 的 `net_rx_action` 入口时间戳测量。

**长期方案（精确分析）:**
使用方案 B，创建专门的 ksoftirqd 调度延迟分析工具，利用 sched tracepoints。

## 验证方法

### 1. 检查系统配置

```bash
# 查看 softirq 统计
cat /proc/softirqs

# 查看 ksoftirqd 进程
ps aux | grep ksoftirqd

# 查看 CPU 105 的 ksoftirqd
ps -p $(pgrep -f "ksoftirqd/105") -o pid,comm,pri,ni,psr,stat,wchan

# 查看调度延迟
perf record -e sched:sched_stat_wait -a -g -- sleep 10
perf script
```

### 2. 分析 perf 数据

```bash
# 记录 ksoftirqd 的调度事件
perf record -e sched:sched_wakeup -e sched:sched_switch \
  --filter 'next_comm ~ "ksoftirqd*"' -a -g -- sleep 10

# 分析延迟
perf script | grep -A 5 "ksoftirqd/105"
```

### 3. 使用 bpftrace 快速验证

```bash
# 测量 ksoftirqd 调度延迟
bpftrace -e '
  tracepoint:sched:sched_wakeup /strncmp(args->comm, "ksoftirqd", 9) == 0/ {
    @wakeup[args->pid] = nsecs;
  }

  tracepoint:sched:sched_switch /strncmp(args->next_comm, "ksoftirqd", 9) == 0/ {
    $wakeup_ts = @wakeup[args->next_pid];
    if ($wakeup_ts > 0) {
      $latency_us = (nsecs - $wakeup_ts) / 1000;
      @sched_latency_us = hist($latency_us);
      delete(@wakeup[args->next_pid]);
    }
  }
'
```

## 下一步行动

1. **快速验证**: 使用 bpftrace 脚本在 Hygon 环境验证 ksoftirqd 调度延迟假设
2. **工具增强**: 在 `enqueue_to_iprec_latency_threshold.py` 中添加 per-CPU net_rx_action 延迟测量
3. **深度分析**: 开发专门的 ksoftirqd 调度延迟分析工具，使用 sched tracepoints
4. **优化方案**: 根据测量结果，考虑调整：
   - CPU 亲和性设置
   - ksoftirqd 优先级（默认 SCHED_OTHER）
   - RPS/RFS 配置
   - Softirq 预算调整
