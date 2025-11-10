# eBPF CPU 分析工具使用指南

## 工具概览

`ebpf-tools/cpu/` 目录包含以下 CPU 性能分析工具：

| 工具 | 功能 | 主要用途 | 是否适用于 iperf3/ksoftirqd |
|-----|------|---------|---------------------------|
| **offcputime-ts.py** | Off-CPU 时间分析 | 分析进程阻塞原因和等待时间 | ✅ 适用 |
| **sched_latency_monitor.sh** | 调度延迟监控 | 监控进程调度延迟 | ✅ 适用 |
| **cpu_monitor.sh** | CPU 使用率监控 | 实时监控 CPU 使用率和热点 | ✅ 适用 |
| **fast_cpu_monitor.sh** | 轻量级 CPU 监控 | 快速 CPU 监控（无 perf） | ✅ 适用 |
| **nic_irq_numa_map.sh** | 网卡中断映射 | 显示网卡中断的 NUMA 分布 | ✅ 适用（网络相关） |
| **nic_irq_set_affinity.sh** | 设置中断亲和性 | 绑定网卡中断到指定 CPU | ✅ 适用（网络相关） |

---

## 1. offcputime-ts.py - Off-CPU 时间分析

### 功能描述

**Off-CPU Time** 是指进程**不在 CPU 上运行**的时间，即：
- 等待 I/O（磁盘、网络）
- 等待锁（mutex、spinlock、rwlock）
- 主动睡眠（sleep、poll、epoll_wait）
- 等待内存页交换
- 等待调度器调度

与 **On-CPU** 分析（CPU 使用率）不同，Off-CPU 分析揭示**为什么程序慢**而不是**哪里占用 CPU 多**。

### 核心原理

```
进程状态转换：
  Running (On-CPU)  →  Block/Sleep (Off-CPU)  →  Running (On-CPU)
      ↓                        ↓                       ↓
  perf/BPF 不关心      记录阻塞时间和栈回溯     累计总时间

输出：哪些函数调用栈导致了最多的阻塞时间
```

### 使用场景

| 场景 | 症状 | Off-CPU 可发现的问题 |
|------|------|---------------------|
| **网络 I/O** | iperf3 带宽低 | 阻塞在 `recv()`、`send()`、`epoll_wait()` |
| **锁竞争** | 多线程性能差 | 阻塞在 `pthread_mutex_lock()`、`futex()` |
| **调度延迟** | 进程响应慢 | 长时间处于 TASK_INTERRUPTIBLE 状态 |
| **内核软中断** | ksoftirqd 占用低但延迟高 | 等待网络包到达、等待调度 |

### 适用于 iperf3 和 ksoftirqd 吗？

#### ✅ **非常适用于 iperf3**

iperf3 是典型的 **I/O 密集型**应用：
- 大量时间花在等待网络包（`recv()/send()`）
- 使用 `epoll_wait()` 等待事件
- Off-CPU 分析可以揭示：
  - 网络栈延迟（从发送到实际传输）
  - 等待 socket buffer 可用的时间
  - 跨 NUMA 内存拷贝导致的延迟

#### ⚠️ **部分适用于 ksoftirqd**

ksoftirqd 是**内核线程**，处理软中断：
- **On-CPU 时间短**：只在有软中断待处理时运行
- **Off-CPU 分析有限**：
  - 可以看到 ksoftirqd 何时被唤醒
  - 可以看到调度延迟
  - **但无法看到网络包处理的微观细节**（需要其他工具）

**建议**：
- 对 ksoftirqd 使用 `sched_latency_monitor.sh` 更合适
- 结合 eBPF 网络工具分析软中断内部行为

### 使用方法

#### 基本用法

```bash
# 1. 追踪所有进程的 Off-CPU 时间（持续到 Ctrl+C）
sudo python offcputime-ts.py

# 2. 追踪 5 秒
sudo python offcputime-ts.py 5

# 3. 时间序列输出（每 1 秒输出一次，共 10 秒）
sudo python offcputime-ts.py -I 1 10

# 4. 只追踪特定进程（iperf3）
sudo python offcputime-ts.py -p $(pidof iperf3)

# 5. 只追踪特定线程
sudo python offcputime-ts.py -t <TID>

# 6. 只追踪用户态栈（排除内核）
sudo python offcputime-ts.py -U -p $(pidof iperf3)

# 7. 只追踪内核态栈
sudo python offcputime-ts.py -K -p $(pidof iperf3)

# 8. 过滤：只显示阻塞时间 > 1ms 的事件
sudo python offcputime-ts.py -m 1000 -p $(pidof iperf3)

# 9. 过滤：只显示阻塞时间 < 10ms 的事件
sudo python offcputime-ts.py -M 10000 -p $(pidof iperf3)

# 10. 火焰图格式输出（用于可视化）
sudo python offcputime-ts.py -f 30 > offcpu.folded
git clone https://github.com/brendangregg/FlameGraph
./FlameGraph/flamegraph.pl offcpu.folded > offcpu.svg
```

#### 针对 iperf3 的实战示例

```bash
# 场景1：分析 iperf3 为什么带宽低
# 启动 iperf3 服务端
numactl --cpunodebind=5 --membind=5 iperf3 -s &
IPERF_PID=$!

# 客户端连接并开始测试
numactl --cpunodebind=5 --membind=5 iperf3 -c <server_ip> -t 60 &

# 分析 iperf3 服务端的 Off-CPU 时间
sudo python ebpf-tools/cpu/offcputime-ts.py -I 5 60 -p $IPERF_PID

# 输出示例解读：
# 如果看到大量时间花在：
#   - epoll_wait() → 等待网络事件，正常
#   - futex()      → 线程同步开销
#   - page_fault   → 跨 NUMA 内存访问
#   - schedule()   → 调度延迟（可能被其他进程抢占）
```

#### 针对 ksoftirqd 的示例

```bash
# 场景2：分析 ksoftirqd 调度延迟
# 找到 ksoftirqd 线程（假设在 CPU 40 上）
ps -eLo pid,tid,comm,psr | grep ksoftirqd/40
# 输出：PID  TID  COMM            PSR
#       3    456  ksoftirqd/40    40

# 追踪该线程的 Off-CPU 时间
sudo python ebpf-tools/cpu/offcputime-ts.py -t 456 -I 2 30

# 输出解读：
# - 如果大量时间在 schedule() → 被调度器延迟
# - 如果大量时间在 smpboot_thread_fn() → 等待被唤醒（正常）
```

### 输出解读

#### 典型输出格式

```
    iperf3;entry_SYSCALL_64_fastpath;sys_epoll_wait;do_epoll_wait;schedule;__schedule
    3456789

解读：
- 调用栈：iperf3 → epoll_wait → schedule (从右到左读)
- 数值：3456789 微秒 (约 3.5 秒) 阻塞在此调用栈上
```

#### 关键指标

| 栈模式 | 含义 | 优化方向 |
|--------|------|---------|
| **epoll_wait** 高 | 等待 I/O 事件 | 检查网络延迟、TCP 参数 |
| **futex** 高 | 锁竞争 | 优化锁粒度、避免伪共享 |
| **page_fault** 高 | 内存访问延迟 | 检查 NUMA 亲和性 |
| **schedule** 高 | CPU 调度延迟 | 检查 CPU 绑定、负载均衡 |
| **do_wait** 高 | 等待子进程 | 进程模型问题 |

---

## 2. sched_latency_monitor.sh - 调度延迟监控

### 功能描述

监控进程的**调度延迟**，即进程从变为 Runnable 到实际获得 CPU 的时间间隔。

```
进程状态：
  Sleep → Runnable (进入运行队列) → Running (获得 CPU)
          ↑                           ↑
          t1                          t2

调度延迟 = t2 - t1
```

### 核心原理

使用 `perf sched record` 记录调度事件，然后用 `perf sched latency` 分析：
- **平均调度延迟 (Average)**
- **最大调度延迟 (Maximum)**
- **调度次数 (Switched)**

### 适用场景

| 场景 | 症状 | 调度延迟分析 |
|------|------|------------|
| CPU 超载 | 进程响应慢 | 高平均延迟（> 10ms） |
| 跨 NUMA 调度 | 性能抖动 | 进程在不同 NUMA 间迁移 |
| 实时性要求 | 延迟敏感应用 | 需要低且稳定的延迟 |

### 适用于 iperf3 和 ksoftirqd 吗？

#### ✅ **适用于 iperf3**

iperf3 对调度延迟敏感：
- 高延迟 → 网络包处理滞后 → 吞吐量下降
- 跨 NUMA 调度 → 缓存失效 → 性能下降

#### ✅ **非常适用于 ksoftirqd**

ksoftirqd 是高优先级内核线程：
- 理想情况下应该**立即被调度**
- 调度延迟高 → 网络包处理延迟 → 丢包
- 可以揭示 CPU 绑定是否生效

### 使用方法

#### 基本用法

```bash
# 监控 ovs-vswitchd 进程（默认）
sudo bash ebpf-tools/cpu/sched_latency_monitor.sh

# 监控 iperf3，每 1 秒采样一次，持续运行
sudo bash ebpf-tools/cpu/sched_latency_monitor.sh -p iperf3 -i 1 -t 1

# 输出到文件
sudo bash ebpf-tools/cpu/sched_latency_monitor.sh -p iperf3 -i 2 -t 1 -l iperf_sched.log

# 启用详细输出
sudo bash ebpf-tools/cpu/sched_latency_monitor.sh -p iperf3 -v
```

#### 参数说明

```bash
-p, --process PROCESS   # 目标进程名（默认：ovs-vswitchd）
-t, --period SECONDS    # 采样周期（默认：1 秒）
-i, --interval SECONDS  # 监控间隔（默认：1 秒）
-l, --log FILE          # 日志文件路径
-v, --verbose           # 详细输出
-h, --help              # 帮助信息
```

#### 实战示例：监控 iperf3

```bash
# 1. 启动 iperf3
numactl --cpunodebind=5 --membind=5 iperf3 -s &

# 2. 开始监控（另一终端）
sudo bash ebpf-tools/cpu/sched_latency_monitor.sh \
  -p iperf3 \
  -i 2 \
  -t 1 \
  -l iperf3_sched.log \
  -v

# 3. 运行客户端测试
iperf3 -c <server_ip> -t 60 -P 4

# 4. 停止监控（Ctrl+C）

# 5. 查看结果
cat iperf3_sched.log
```

#### 实战示例：监控 ksoftirqd

```bash
# ksoftirqd 进程名格式：ksoftirqd/N（N 为 CPU 编号）
# 例如监控 CPU 40 的 ksoftirqd

# 方法1：直接指定进程名（需要修改脚本支持，当前版本可能不支持斜杠）
# 方法2：使用 perf 直接监控
sudo perf sched record -p $(pidof ksoftirqd/40) -- sleep 10
sudo perf sched latency

# 输出示例：
# -----------------------------------------------------------------------------------------------------------------
#  Task                  |   Runtime ms  | Switches | Average delay ms | Maximum delay ms | Maximum delay at       |
# -----------------------------------------------------------------------------------------------------------------
#  ksoftirqd/40:456      |     123.45 ms |      456 |         0.123 ms |         2.456 ms | 123456.789012 s
```

### 输出解读

#### 关键指标

```
====================  #1 ====================
时间: 2025-01-03 10:30:15.123
进程: iperf3
PID: 12345
采样周期: 1 秒
采样次数: 1
==========================================================

-----------------------------------------------------------------------------------------------------------------
 Task                  |   Runtime ms  | Switches | Average delay ms | Maximum delay ms | Maximum delay at       |
-----------------------------------------------------------------------------------------------------------------
 iperf3:12345          |    987.65 ms  |      234 |         1.234 ms |        15.678 ms | 123456.789012 s
 iperf3:12346          |    876.54 ms  |      198 |         0.987 ms |        12.345 ms | 123456.790123 s
-----------------------------------------------------------------------------------------------------------------
```

**指标说明**：

| 指标 | 含义 | 良好范围 | 需优化 |
|-----|------|---------|--------|
| **Runtime ms** | CPU 实际运行时间 | 接近采样周期 | << 采样周期 |
| **Switches** | 上下文切换次数 | < 1000/秒 | > 5000/秒 |
| **Average delay** | 平均调度延迟 | < 1ms | > 5ms |
| **Maximum delay** | 最大调度延迟 | < 10ms | > 50ms |

**问题诊断**：

```
场景1：Average delay > 5ms
  原因：CPU 超载或绑定错误
  解决：检查 CPU 使用率、调整进程亲和性

场景2：Maximum delay > 50ms
  原因：瞬时 CPU 争抢或中断风暴
  解决：使用 cpu_monitor.sh 找出竞争者

场景3：Switches 很高（> 5000/秒）
  原因：频繁 I/O、锁竞争、或时间片过小
  解决：使用 offcputime-ts.py 分析阻塞原因

场景4：Runtime << 采样周期
  原因：进程大部分时间在等待（Off-CPU）
  解决：使用 offcputime-ts.py 分析
```

---

## 3. cpu_monitor.sh - CPU 使用率监控

### 功能描述

实时监控指定 CPU 的使用率，并：
- 显示每个 CPU 上的 Top N 进程
- 当 CPU 使用率超过阈值时自动触发 `perf record`
- 生成火焰图和热点分析报告

### 核心特性

```
监控流程：
  每 N 秒采样
    ↓
  检查 CPU 使用率
    ↓
  > 阈值？
    ├─ NO → 继续监控
    └─ YES → 启动 perf record
              ↓
              生成性能报告
              找出 CPU 热点函数
```

### 适用于 iperf3 和 ksoftirqd 吗？

#### ✅ **适用于 iperf3**

可以发现：
- iperf3 在哪些 CPU 上运行
- CPU 使用率分布是否均匀
- 热点函数（数据拷贝、校验和计算）

#### ✅ **适用于 ksoftirqd**

可以发现：
- ksoftirqd 的 CPU 占用情况
- 网络软中断处理热点
- 是否有 CPU 过载

### 使用方法

```bash
# 监控 CPU 0-3
sudo bash ebpf-tools/cpu/cpu_monitor.sh -c 0-3 -i 5

# 监控指定 CPU，使用率 > 80% 时自动 perf
sudo bash ebpf-tools/cpu/cpu_monitor.sh -c 40-43 -i 5 -t 80

# 输出到日志
sudo bash ebpf-tools/cpu/cpu_monitor.sh -c 40-47 -i 10 -l --log-file cpu.log

# 自定义 perf 输出目录
sudo bash ebpf-tools/cpu/cpu_monitor.sh -c 40-43 -t 70 --perf-output /data/perf
```

### 输出解读

```
========== CPU 40 (Total: 85.3%) ==========
PID      %CPU   AFFINITY    COMMAND
12345    65.2   40-43       iperf3
456      18.1   40          ksoftirqd/40
789      2.0    0-127       systemd

========== CPU 41 (Total: 45.1%) ==========
...
```

当 CPU 使用率超过阈值时，会自动生成：
```
/tmp/cpu_monitor_perf/
├── perf_cpu40_20250103_103015.data   # perf 原始数据
├── perf_cpu40_20250103_103015.txt    # 热点函数报告
└── ...
```

---

## 4. 实战：分析 iperf3 和 ksoftirqd

### 场景1：iperf3 网络性能低

**问题**：iperf3 带宽只有 5 Gbps，预期 10 Gbps

**分析步骤**：

```bash
# 1. 启动 iperf3（绑定到 NUMA 5，CPU 40-43）
numactl --physcpubind=40-43 --membind=5 iperf3 -s &
IPERF_PID=$!

# 2. 监控 CPU 使用率
sudo bash ebpf-tools/cpu/cpu_monitor.sh -c 40-43 -i 5 -t 70 &

# 3. 监控调度延迟
sudo bash ebpf-tools/cpu/sched_latency_monitor.sh -p iperf3 -i 2 -l iperf_sched.log &

# 4. 分析 Off-CPU 时间
sudo python ebpf-tools/cpu/offcputime-ts.py -I 5 60 -p $IPERF_PID > iperf_offcpu.txt &

# 5. 运行客户端
iperf3 -c <server_ip> -t 60 -P 4

# 6. 分析结果
# - cpu_monitor: 如果 CPU < 50% → 不是 CPU 瓶颈
# - sched_latency: 如果 Average delay > 5ms → 调度问题
# - offcputime: 如果大量时间在 epoll_wait → 网络栈延迟
#              如果大量时间在 futex → 锁竞争
#              如果大量时间在 page_fault → NUMA 问题
```

### 场景2：ksoftirqd CPU 占用高

**问题**：ksoftirqd/40 占用 100% CPU

**分析步骤**：

```bash
# 1. 确认 ksoftirqd TID
ps -eLo pid,tid,comm,psr | grep "ksoftirqd/40"
# 输出：3  456  ksoftirqd/40  40

# 2. 监控 CPU 40，自动 perf
sudo bash ebpf-tools/cpu/cpu_monitor.sh -c 40 -i 5 -t 80 &

# 3. 查看软中断统计
watch -n 1 'cat /proc/softirqs | grep NET'

# 4. 分析 perf 结果
cat /tmp/cpu_monitor_perf/perf_cpu40_*.txt

# 常见热点：
# - net_rx_action: 网络包接收处理
# - __netif_receive_skb_core: 协议栈处理
# - ip_rcv: IP 层处理
# - tcp_v4_rcv: TCP 层处理

# 5. 如果看到大量 cache miss
# 使用缓存分析工具
perf stat -e cache-misses,cache-references -C 40 -- sleep 10
```

### 场景3：跨 NUMA 性能问题

**问题**：iperf3 绑定到 NUMA 5，但性能仍然差

```bash
# 1. 检查内存分配
numastat -p $(pidof iperf3)
# 如果 numa_miss > 10% → 内存没有绑定到 NUMA 5

# 2. 检查中断分布
cat /proc/interrupts | grep ens43f0np0
# 如果中断分散在多个 NUMA 节点 → 中断亲和性问题

# 3. 使用 offcputime 检查跨 NUMA 延迟
sudo python ebpf-tools/cpu/offcputime-ts.py -p $(pidof iperf3) 30
# 如果看到大量 page_fault 和 migration → 跨 NUMA 访问

# 4. 修正：设置中断亲和性
sudo bash ebpf-tools/cpu/nic_irq_set_affinity.sh ens43f0np0 40-43

# 5. 重新测试
iperf3 -c <server_ip> -t 60
```

---

## 5. 工具对比与选择指南

| 目标 | 使用工具 | 关键指标 |
|-----|---------|---------|
| **找出为什么慢** | offcputime-ts.py | 阻塞时间最长的调用栈 |
| **调度是否及时** | sched_latency_monitor.sh | Average/Maximum delay |
| **CPU 是否瓶颈** | cpu_monitor.sh | CPU 使用率、热点函数 |
| **中断分布检查** | nic_irq_numa_map.sh | 中断在哪些 CPU 上 |
| **优化中断绑定** | nic_irq_set_affinity.sh | 绑定到目标 CPU |

### 组合使用建议

**完整性能分析流程**：
```bash
# 1. 宏观监控（实时）
cpu_monitor.sh -c 40-47 -i 5 &

# 2. 调度延迟（定期）
sched_latency_monitor.sh -p iperf3 -i 10 -l sched.log &

# 3. Off-CPU 深度分析（问题出现时）
offcputime-ts.py -p $(pidof iperf3) -I 5 30 > offcpu.txt

# 4. 结合缓存分析
perf stat -e cache-misses,LLC-load-misses -p $(pidof iperf3) -- sleep 30

# 5. 综合判断
# - CPU 高 + 热点明确 → On-CPU 瓶颈
# - CPU 低 + Off-CPU 时间高 → I/O 或锁瓶颈
# - 调度延迟高 → CPU 绑定或超载问题
# - Cache miss 高 → NUMA 或内存问题
```

---

## 6. 常见问题排查

### Q1: offcputime-ts.py 报错 "Failed to attach BPF program"

**原因**：内核不支持 eBPF 或权限不足

**解决**：
```bash
# 检查内核版本（需要 >= 4.1）
uname -r

# 检查 BPF 支持
zcat /proc/config.gz | grep CONFIG_BPF

# 提升权限
sudo sysctl -w kernel.perf_event_paranoid=-1
```

### Q2: sched_latency_monitor.sh 无输出

**原因**：进程名错误或进程不存在

**解决**：
```bash
# 确认进程名
ps aux | grep iperf3

# 使用正确的进程名
sudo bash sched_latency_monitor.sh -p iperf3
```

### Q3: cpu_monitor.sh 无法启动 perf

**原因**：没有 root 权限或 perf 未安装

**解决**：
```bash
# 安装 perf
sudo yum install perf  # CentOS/RHEL
sudo apt install linux-tools-$(uname -r)  # Ubuntu

# 使用 sudo 运行
sudo bash cpu_monitor.sh -c 40-43 -t 80
```

### Q4: 如何分析 ksoftirqd 内部的网络包处理？

**方案**：offcputime 对内核线程支持有限，建议使用：

```bash
# 1. 使用 eBPF 网络工具
sudo python ebpf-tools/performance/system-network/system_network_latency_details.py

# 2. 使用 bpftrace 追踪软中断
sudo bpftrace -e 'tracepoint:irq:softirq_entry /args->vec == 3/ { @[kstack] = count(); }'

# 3. 使用 perf 采样 CPU 40
sudo perf record -C 40 -g -- sleep 10
sudo perf report
```

---

## 总结

这些工具可以**全方位分析 iperf3 和 ksoftirqd** 的性能问题：

- **offcputime-ts.py**: 揭示**为什么慢**（阻塞原因）
- **sched_latency_monitor.sh**: 揭示**调度是否及时**
- **cpu_monitor.sh**: 揭示**CPU 热点**
- **中断工具**: 揭示**网络中断分布**

组合使用可以构建完整的性能分析链条：
```
宏观监控 → 调度分析 → Off-CPU分析 → 热点定位 → 优化验证
```