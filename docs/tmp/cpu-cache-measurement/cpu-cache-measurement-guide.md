CPU 与缓存/内存测量指南
=========================

概览
----
- 现代处理器的缓存与内存测量依赖硬件性能监控单元（PMU）、固件配置（BIOS/UEFI、microcode）、操作系统内核驱动（`perf_event`）的协同；任何一层缺失都会导致计数器无效或不可访问。
- 拓扑结构（socket → die/CCD → CCX → 核心/线程）和 NUMA 划分决定了数据路径、L3 共享范围及互连延迟；测量前必须先澄清硬件布局。
- Linux 通过 `/sys/bus/event_source/devices/` 揭露可用 PMU，每个目录下的 `events/` 与 `format/` 定义了事件编码，命令行工具（`perf`、pmu-tools、BCC/eBPF）基于这些接口编程硬件。

## 核心原理：PMU 工作机制

**性能监控单元 (PMU)** 是 CPU 内置的硬件计数器组，可在**近零开销**（计数模式 < 1%，采样模式 2-5%）下统计微架构事件：

- **工作模式**：
  - **计数模式 (Counting)**：累计事件总数，几乎无性能影响
  - **采样模式 (Sampling)**：按固定周期或事件数采样，可精确到指令地址

- **Intel PEBS vs AMD IBS**：
  ```
  Intel PEBS (Precise Event-Based Sampling)
    ├─ 采样数据存储在内存 buffer
    ├─ 精度更高，可记录 load latency
    ├─ 支持事件：MEM_TRANS_RETIRED.LOAD_LATENCY
    └─ perf mem record 依赖此特性

  AMD IBS (Instruction-Based Sampling)
    ├─ 采样数据存储在 MSR 寄存器
    ├─ 提供更丰富上下文（寄存器状态、分支预测）
    ├─ 精度和稳定性略低于 PEBS
    └─ 支持独立的 fetch/op sampling
  ```

- **可测量事件**：
  - L1/L2/L3 缓存访问与缺失
  - TLB 访问与缺失
  - 分支预测命中率
  - 内存读写延迟与带宽
  - 缓存一致性开销 (HITM)
  - Fabric/互连流量

硬件与固件前置条件
------------------

### CPU 架构与缓存层级

**Hygon C86 7000 系列（基于 AMD Zen1）**：
```
双路系统拓扑：
  Socket 0                           Socket 1
  ├─ CCD0 (NUMA 0)                   ├─ CCD0 (NUMA 4)
  │  ├─ CCX0: Core 0-3  + L3 8MB     │  ├─ CCX0: Core 32-35 + L3 8MB
  │  └─ CCX1: Core 4-7  + L3 8MB     │  └─ CCX1: Core 36-39 + L3 8MB
  ├─ CCD1 (NUMA 1)                   ├─ CCD1 (NUMA 5) ⭐
  │  ├─ CCX0: Core 8-11 + L3 8MB     │  ├─ CCX0: Core 40-43 + L3 8MB  ← 您的网卡
  │  └─ CCX1: Core 12-15+ L3 8MB     │  └─ CCX1: Core 44-47 + L3 8MB
  └─ CCD2/3 ...                      └─ CCD2/3 ...

关键延迟特征（cycles）：
  L1 hit:        ~4      (1-2 ns)
  L2 hit:        ~12     (6 ns)
  L3 hit (同CCX): ~40     (20 ns)
  跨CCX L3:       ~100    (50 ns)    ← 2.5倍惩罚
  跨CCD:         ~160    (80 ns)    ← 4倍惩罚
  本地DRAM:      ~150    (75 ns)
  远端NUMA:      ~300    (150 ns)   ← 7.5倍惩罚
  远端HITM:      ~400    (200 ns)   ← 缓存一致性开销
```

**其他架构差异**：
- Intel (Ice Lake/Sapphire Rapids): 单 die 共享 LLC，环形/Mesh 互连，延迟更均匀
- ARM (Neoverse): cluster 内共享 L2/L3，CMN 互连，需厂商 JSON 支持
- AMD Zen3+: 统一 CCX (8核共享32MB L3)，跨核延迟显著降低

### 固件配置检查清单

**BIOS/UEFI 必需设置**：
```bash
# 关键选项验证
dmidecode -t bios | grep Version    # 确保最新固件
dmidecode -t processor | grep "Max\|Current Speed"  # 检查频率

必须启用：
  ✓ NUMA (Node Interleaving = Disabled)
  ✓ SMT/Hyper-Threading = Enabled（除非专门优化单线程）
  ✓ IOMMU = Enabled
  ✓ Hardware Prefetcher = Enabled
  ✓ ACPI SRAT Table = Published

性能模式：
  ✓ C-states = Disabled (or C1E only)    # 降低唤醒延迟
  ✓ P-states = Performance Mode
  ✓ PCIe ASPM = Disabled                 # 降低 PCIe 延迟
  ✓ Memory Frequency = Max Supported

PMU 相关：
  ✓ Performance Monitoring = Enabled
  ✓ PEBS/IBS = Enabled（部分平台可配置）
```

**Microcode 验证**：
```bash
# 检查 microcode 版本
grep microcode /proc/cpuinfo | uniq
# 或
dmesg | grep microcode

# AMD/Hygon microcode 更新会解锁某些 PMU 事件
# 建议从发行版仓库安装最新版：
# apt install amd64-microcode  或  yum install microcode_ctl
```

### 操作系统内核要求

**内核配置检查**：
```bash
# 1. 验证 perf_event 支持
zcat /proc/config.gz | grep -E "PERF_EVENTS|PMU"
# 必需：
# CONFIG_PERF_EVENTS=y
# CONFIG_CPU_SUP_AMD=y  或  CONFIG_CPU_SUP_HYGON=y

# 2. 检查可用 PMU 设备
ls -l /sys/bus/event_source/devices/
# 应包含：
#   cpu/          ← 核心 PMU（L1/L2/cycles/instructions）
#   amd_l3/       ← L3 PMU (Zen1/Hygon，内核 ≥5.3)
#   amd_df/       ← Data Fabric PMU（Fabric流量）
#   amd_nb/       ← Northbridge PMU（内存控制器）
#   breakpoint/
#   power/        ← RAPL 能耗统计（内核 ≥6.0）

# 3. 检查 L3 事件可用性
ls /sys/bus/event_source/devices/amd_l3/events/
# 内核 ≥5.4 应包含：
#   l3_cache_accesses
#   l3_cache_misses
# 若为空，需升级内核或使用 raw 事件

# 4. 调整权限（调试用）
echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid
# -1: 允许普通用户访问所有 PMU 事件
#  0: 允许访问 CPU PMU（不含 kernel profiling）
#  1: 允许用户态采样
#  2: 禁止大部分访问（默认）

# 5. 验证符号解析（可选）
cat /proc/sys/kernel/kptr_restrict  # 应为 0 或 1
cat /proc/sys/kernel/perf_event_mlock_kb  # 采样 buffer 限制
```

**内核版本建议**：
- **Hygon/AMD Zen1**: 内核 ≥5.4（完整 `amd_l3` 支持）
- **AMD Zen2+**: 内核 ≥5.8（更新的事件表）
- **Intel**: 内核 ≥4.19（PEBS v4 支持）
- **ARM**: 内核 ≥5.10（CMN-600/650 支持）

**已知问题**：
- 旧版内核（< 5.3）的 `amd_l3` PMU 只有空壳，事件表未定义
- 某些发行版禁用了 `CONFIG_AMD_NB`，导致 `amd_nb` PMU 缺失
- 容器环境需要 `--privileged` 或 `--cap-add=SYS_ADMIN` 才能访问 PMU

拓扑识别与基础检查
------------------
- `lscpu -e=CPU,NODE,SOCKET,DIE,CORE,THREAD`／`hwloc-ls`／`lstopo`：确认 NUMA、CCX、SMT 配对关系。  
- `/sys/devices/system/cpu/cpu*/cache/index{0..3}/`：查看各级缓存容量与共享 CPU 列表，`index3/shared_cpu_list` 可识别 CCX 共享 L3。  
- `numactl --hardware`、`numastat`: 获取节点内存大小、远程访问统计。  
- NIC/IRQ 映射脚本：`ebpf-tools/cpu/nic_irq_numa_map.sh`、`ebpf-tools/cpu/nic_irq_set_affinity.sh` 辅助中断绑定；结合 `/proc/interrupts`、`/proc/softirqs` 验证。

常用测量工具
------------
- `perf stat`  
  - 快速统计硬件事件：`perf stat -e <pmu>/<event>/ -p <pid>`。  
  - `perf list --details` 与 `/sys/bus/event_source/devices/<pmu>/events/*` 显示事件编码。  
  - Hygon/Zen1 上 `cache-misses`=L2 miss (`event=0x64,umask=0x09`)，`cache-references`=L2 访问 (`event=0x60,umask=0xff`)。  
  - AMD L3 事件需 `amd_l3` PMU；若 `/sys/bus/event_source/devices/amd_l3/events/` 缺失，必须升级内核或手写 raw 事件并配置 SliceMask。
- `perf record`, `perf mem`, `perf c2c`  
  - 捕获热点、内存访问延迟、cache-to-cache 传输；适合分析跨 CCX 共享与远程访问。  
  - `perf mem record -p <pid>` + `perf mem report` 查看 load/store 路径。  
  - `perf c2c record -p <pid>` 定位 HITM、远程共享等问题。
- pmu-tools / ocperf.py  
  - 解析 pmu-events JSON，生成正确的事件编码；Intel 官方提供 `ocperf.py`，AMD 可借鉴 Zen 表格。  
- BCC / eBPF  
  - `cachetop`, `cachestat`, `numa-miss`, `memleak`, `runqlat` 等脚本实时观察缓存命中、NUMA 抖动、调度延迟。  
  - 可结合 cgroups / cpusets 做 per-service 监控。
- 其他工具  
  - `numastat -p`, `taskset`, `numactl`, cpuset cgroup：管理进程/线程与内存亲和性。  
  - `ethtool`, `RPS/XPS`、`irqbalance` 调整：保证 IO 线程、中断落在目标 CCX/NUMA。  
  - 基准：`lat_mem_rd`, `STREAM`, `perf bench numa`, `stress-ng --class cache` 评估基准性能。  
  - 供应商工具：Intel PCM、AMD μProf/`amd_smn_perf`（若支持）、ARM DS/Streamline 等。

指标解析与测量方法
------------------

## 一、缓存层级测量（分层方法）

### Level 1: L1/L2 缓存（核心 PMU）

**基本命令**：
```bash
# 测量 L1 数据缓存
perf stat -e L1-dcache-loads,L1-dcache-load-misses,L1-dcache-stores \
  -p <pid> -- sleep 10

# 输出示例：
#   1,234,567,890  L1-dcache-loads
#      12,345,678  L1-dcache-load-misses    # miss率 = 1.0%

# L2 缓存（通用事件，实际映射到 AMD event 0x64/0x60）
perf stat -e cache-references,cache-misses -p <pid> -- sleep 10
# Hygon/AMD: cache-references = L2访问, cache-misses = L2 miss
# Intel:     更接近 LLC 行为，需注意

# 详细的 L2 统计（AMD/Hygon）
perf stat -e r60ff,r6409 -p <pid>
# r60ff = L2 cache requests (所有类型)
# r6409 = L2 cache misses
```

**关键指标计算**：
```
L1 miss率 = L1-dcache-load-misses / L1-dcache-loads
  良好: < 3%
  可接受: 3-5%
  需优化: > 5%

L2 miss率 = cache-misses / cache-references
  良好: < 2%
  可接受: 2-5%
  严重: > 10%  ← L2 miss 直接进入 L3/DRAM，开销巨大
```

**问题诊断**：
- **L1 miss 高**：
  - 数据结构过大，无法装入 32KB L1
  - 访问模式不友好（stride 过大、随机访问）
  - 多线程竞争导致 cache line 失效

- **L2 miss 高**：
  - 工作集 > 512KB（Zen1 L2 大小）
  - 跨函数频繁调用，指令缓存不足
  - 需要检查 L3 命中情况

### Level 2: L3 缓存（LLC）

**Hygon/AMD Zen1 专用命令**：
```bash
# 方法1：使用 amd_l3 PMU（内核 ≥5.4）
perf stat -e amd_l3/l3_cache_accesses/,amd_l3/l3_cache_misses/ \
  -p <pid> -- sleep 10

# 方法2：原始事件（适用于所有内核版本）
perf stat -e r04C4,r04C1 -p <pid>
# r04C4 = L3 cache accesses (event=0x04, umask=0xC4)
# r04C1 = L3 cache misses

# 方法3：间接推断（L2 miss 即 L3 request）
perf stat -e cache-misses,instructions,cycles -p <pid>
# 结合 IPC 和 cache-misses 推断 L3 性能
```

**Intel 系统命令**：
```bash
# LLC 事件（Last Level Cache）
perf stat -e LLC-loads,LLC-load-misses,LLC-stores,LLC-store-misses \
  -p <pid> -- sleep 10

# Uncore 事件（更精确的 LLC 监控）
perf stat -e uncore_cha/event=0x35,umask=0x21/ \
  -e uncore_cha/event=0x36,umask=0x21/ \
  -a -- sleep 10
```

**关键指标**：
```
L3 miss率 = l3_cache_misses / l3_cache_accesses
  优秀: < 1%
  良好: 1-5%
  问题: > 10%  ← L3 miss 导致 DRAM 访问（150-300 cycles）

MPKI (Misses Per Kilo Instructions):
  MPKI = (cache-misses / instructions) × 1000
  优秀: < 1
  可接受: 1-10
  严重: > 10
```

**CCX 级分析**（Hygon 特有）：
```bash
# 查看 L3 切片命中分布（需要 PMU SliceMask 支持）
# 同 CCX 内命中: ~40 cycles
# 跨 CCX 命中: ~100 cycles

# 通过 perf c2c 观察跨 CCX 访问
perf c2c record -p <pid> -- sleep 10
perf c2c report --stdio | grep "Shared Data Cache Line"
```

### Level 3: 内存访问与 NUMA

**A. 基础 NUMA 统计**：
```bash
# 进程级 NUMA 统计
numastat -p <pid>
# 关键列：
#   numa_hit: 本地节点命中
#   numa_miss: 需要访问远端节点
#   numa_foreign: 其他进程访问本节点
#   interleave_hit: 交织策略命中

# NUMA miss率计算
numa_miss_rate = numa_miss / (numa_hit + numa_miss)
  优秀: < 1%
  可接受: 1-5%
  严重: > 10%  ← 远端访问延迟是本地的 2-3 倍
```

**B. 内存访问延迟剖析（Intel PEBS）**：
```bash
# 记录内存访问延迟（需要 PEBS 支持）
perf mem record -p <pid> -- sleep 10

# 分析报告
perf mem report --stdio --sort=mem,snoop

# 输出示例：
# Samples: 10K of event 'cpu/mem-loads,ldlat=30/'
# 45.2%  L3 or L3 hit         ← L3 命中
# 32.1%  Local RAM or RAM hit ← 本地内存
# 15.3%  Remote RAM (1 hop)   ← 远端 NUMA
#  7.4%  Remote cache (2 hops) ← 跨 socket + 远端缓存
```

**C. AMD IBS 采样**：
```bash
# AMD 系统使用 IBS (Instruction-Based Sampling)
perf record -e ibs_op/cnt_ctl=1/ -c 100000 -p <pid> -- sleep 10
perf report --stdio --sort=dso,symbol

# IBS 提供的额外信息：
# - DC miss (L1 data cache miss)
# - L2 miss
# - Branch misprediction
# - 延迟分布
```

**D. 专业工具 - Intel MLC**：
```bash
# Memory Latency Checker - 测量 NUMA 延迟矩阵
./mlc --latency_matrix

# 输出示例（单位：纳秒）：
#           node0   node1   node5   node7
# node0      81     132     157     203
# node5     156     159      78     134
#           ↑远端   ↑远端   ↑本地   ↑跨socket

# 测量带宽
./mlc --bandwidth_matrix
```

## 二、缓存一致性开销测量

### perf c2c - Cache-to-Cache Transfer

**核心功能**：检测 false sharing（伪共享）和 true sharing（真共享）导致的缓存行竞争

**使用方法**：
```bash
# 1. 记录缓存一致性事件（需要 PEBS/IBS）
sudo perf c2c record -ag -p <pid> -- sleep 10
# -a: 所有 CPU
# -g: 调用栈

# 2. 生成报告
sudo perf c2c report --stdio

# 或交互式分析
sudo perf c2c report
```

**报告解读**：
```
=== Trace Event Information ===
Total records                     :    234,567
Load Operations                   :    123,456
Loads - Miss                      :     12,345
Load Local HITM                   :        567  ← 本地缓存一致性开销
Load Remote HITM                  :      1,234  ← 远端 HITM（严重！）
LLC Misses to Local DRAM          :      2.3%
LLC Misses to Remote DRAM         :     15.7%  ← 跨 NUMA 访问比例
LLC Misses to Remote cache (HitM) :     82.0%  ← **伪共享指标**

关键阈值：
  Remote HITM < 5%:   正常
  Remote HITM 5-15%:  需关注
  Remote HITM > 15%:  严重问题，有伪共享或跨 NUMA 竞争
```

**热点缓存行定位**：
```
=== Shared Data Cache Line Table ===
# Index  Cacheline Address    Node  Records  Rmt HITM  Lcl HITM
      0  0x7f8c3d002fc0         5    12345       234        56
      1  0x7f8c3d002f80         5     8901       123        45

# 这显示了哪个内存地址（缓存行）有最多竞争
# 可结合符号表定位到具体变量
```

### 缓存一致性协议开销量化

**MESI/MOESI 状态转换代价**（Hygon/AMD）：
```
同核心访问 (L1):              4 cycles
同 CCX 共享 (Shared state):   40 cycles
跨 CCX Modified→Shared:       80-100 cycles
跨 NUMA Modified→Invalid:     200-400 cycles  ← 缓存行 bouncing
```

**性能影响估算**：
```
假设应用每秒执行 10^9 条指令，其中：
- 10% 是内存访问 (10^8 次)
- 其中 15% 触发 Remote HITM (1.5×10^7 次)
- 每次 HITM 额外开销 200 cycles

额外开销 = 1.5×10^7 × 200 = 3×10^9 cycles
在 2GHz CPU 上 ≈ 1.5 秒额外延迟
性能损失 ≈ 12-38%（文献数据）
```

## 三、综合测量策略

### 三层诊断方法

**Layer 1: 宏观统计（快速筛查）**
```bash
# 5秒快速测试
perf stat -e cycles,instructions,\
  L1-dcache-loads,L1-dcache-load-misses,\
  cache-references,cache-misses \
  -p <pid> -- sleep 5

# 计算关键比率：
# IPC = instructions / cycles       (目标 > 1.0)
# L1 miss% = L1-misses / L1-loads   (目标 < 5%)
# L2 miss% = cache-misses / cache-refs  (目标 < 3%)
```

**Layer 2: 热点定位（采样分析）**
```bash
# 找出哪些函数造成 cache miss
perf record -e cache-misses -c 10000 -g -p <pid> -- sleep 10
perf report --stdio --sort=symbol,dso

# 输出：
# 45.2%  libfoo.so  hot_function  ← 这个函数占 45% 的 cache miss
#        |--80% func_a+0x1234
#        |--20% func_b+0x5678
```

**Layer 3: 精确定位（指令级）**
```bash
# Intel: 使用 PEBS 定位到具体指令
perf record -e mem_inst_retired.all_loads:pp -c 100000 -p <pid>
perf annotate hot_function

# AMD: 使用 IBS
perf record -e ibs_op// -c 100000 -p <pid>
perf report --stdio
```

## 四、实战测量案例

### 案例：iperf3 网络性能分析

```bash
# 1. 启动 iperf3
numactl --cpunodebind=5 --membind=5 iperf3 -s &
IPERF_PID=$!

# 2. 采集 10 秒基线数据
perf stat -e cycles,instructions,\
  cache-references,cache-misses,\
  amd_l3/l3_cache_accesses/,amd_l3/l3_cache_misses/ \
  -p $IPERF_PID -- sleep 10

# 3. 并行监控 NUMA
numastat -p $IPERF_PID  # 每秒刷新

# 4. 检查缓存一致性
perf c2c record -p $IPERF_PID -- sleep 10
perf c2c report --stdio | head -100

# 5. 分析结果
# - IPC < 0.5: CPU 瓶颈
# - L2 miss > 10%: 工作集过大
# - NUMA miss > 10%: 内存亲和性问题
# - Remote HITM > 15%: 跨 NUMA/CCX 竞争
```

### 关键性能指标 (KPI) 总结表

| 指标 | 测量方法 | 优秀 | 良好 | 需优化 | 严重 |
|-----|---------|------|------|--------|------|
| **IPC** | instructions/cycles | >1.5 | 1.0-1.5 | 0.5-1.0 | <0.5 |
| **L1 miss%** | L1-misses/L1-loads | <3% | 3-5% | 5-10% | >10% |
| **L2 miss%** | cache-misses/cache-refs | <2% | 2-5% | 5-10% | >10% |
| **L3 miss%** | l3_misses/l3_accesses | <1% | 1-5% | 5-10% | >10% |
| **NUMA miss%** | numa_miss/total | <1% | 1-5% | 5-15% | >15% |
| **Remote HITM%** | perf c2c | <5% | 5-10% | 10-20% | >20% |
| **MPKI** | cache-misses/K-insn | <1 | 1-5 | 5-10 | >10 |
| **平均延迟** | perf mem | <50ns | 50-100ns | 100-200ns | >200ns |

Hygon/Zen1 细节与调优建议
------------------------
- L3 结构：每 CCX 8 MB（4×2 MB 切片），访问最近切片约 37 cycle，最远切片约 43 cycle；跨 CCX 需经 Infinity Fabric，多 6–8 cycle；跨 CCD/插槽附加 60–120 cycle，接近一次 DRAM 访问。  
- NUMA 策略：同一 NUMA node 内有两个 CCX，对网络/IO 的关键线程应锁定到同一 CCX（例如逻辑核 40–43 / 104–107），并确保中断、softirq、工作线程共享 L3。  
- 工具使用：  
  - 确认 `/sys/bus/event_source/devices/amd_l3/events` 是否存在；若无，升级内核或采用 raw 事件。  
  - `cache-misses`/`cache-references` 实际为 L2 指标；结合 `r20C4`（L3 请求状态）或 BCC `cachetop` 弥补。  
  - 使用 cpuset cgroup 或 `numactl --physcpubind` + `--membind`，确保进程与内存共处同 CCX/NUMA。  
  - `nic_irq_numa_map.sh`、`nic_irq_set_affinity.sh` 辅助中断对齐，`taskset -pc` 验证。  
  - 调整 `RPS/XPS`、禁用或配置 `irqbalance`，避免软中断迁移到其他 CCX。

跨架构差异概览
---------------
- Intel（Ice Lake / Sapphire Rapids）  
  - 单封装共享 L3，互连由环形总线或 Mesh 提供；`cache-misses` 更贴近 LLC，配合 `uncore_imc`, `uncore_cha` 事件精细分析。  
  - 多 tile 架构（Sapphire Rapids）将核心分布在多个 die 上，但内核通常仍视为 2–4 NUMA 节点；LLC 一般通过默认 PMU 即可访问。  
- ARM（Neoverse、定制 SoC）  
  - 核心按 cluster 共享 L2/L3，片上互连（CMN/CCN）负责一致性；PMU 多以 `arm_cmn`, `arm_spe` 暴露，需要厂商 JSON。  
  - NUMA 划分因厂商而异，常见 UMA 设计在单封装内只提供一个节点；测量时重点关注簇间带宽与 LLC 行为。  
- AMD Zen2/Zen3/Zen4  
  - Zen2 增大 CCX L3（16 MB），Zen3 把 CCD 合并成单 CCX（8 核共享 32 MB L3），跨核心延迟更平均；测量方法与 Zen1 类似，但 CCX 级绑定策略需调整。  
  - 新代 Infinity Fabric 支持更高频率，L3 事件表更完善，可直接用 `amd_l3` 别名。

测量与调优完整流程
------------------

## 阶段 0：环境准备与验证

### 0.1 硬件与固件检查

```bash
# 1. 验证 CPU 型号与拓扑
lscpu | grep -E "Model name|NUMA node|Thread|Socket"
cat /sys/devices/system/cpu/cpu*/cache/index3/shared_cpu_list | sort -u

# 2. 检查 BIOS 版本与设置
dmidecode -t bios
dmidecode -t processor | grep -E "Version|Speed|Core Count"

# 3. 确认 microcode 版本
grep microcode /proc/cpuinfo | head -1

# 4. 验证 NUMA 配置
numactl --hardware
cat /sys/devices/system/node/node*/cpulist
```

### 0.2 内核 PMU 能力检查

```bash
# 1. 检查可用 PMU 设备
ls -la /sys/bus/event_source/devices/
# 必需: cpu/, 推荐: amd_l3/, amd_df/, amd_nb/

# 2. 验证 L3 事件支持
ls /sys/bus/event_source/devices/amd_l3/events/
# 若为空，记录需要使用 raw events

# 3. 测试 perf 基本功能
perf list | head -20
perf stat -e cycles,instructions sleep 1

# 4. 调整权限（生产环境慎用）
echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid
```

### 0.3 生成系统拓扑报告

```bash
# 使用项目工具生成拓扑
python3 tools/hygon_ccx_topology_analyzer.py > topology_report.txt

# 手动验证关键信息
cat topology_report.txt | grep -E "CCX|NUMA|网卡"
```

## 阶段 1：建立基线（Baseline）

### 1.1 系统级基准测试

```bash
# A. 内存延迟基准（lmbench）
lat_mem_rd 1024 128   # 测量不同大小的访问延迟

# B. 内存带宽基准（STREAM）
./stream_c.exe

# C. NUMA 基准
perf bench numa mem -p 4 -t 8 -G 0 -P 1024 -s 1024 -l 10

# D. Cache 基准（stress-ng）
stress-ng --cache 8 --cache-ops 100000 --metrics-brief

# 记录所有基准结果到文件
echo "=== Baseline Metrics ===" > baseline.txt
date >> baseline.txt
```

### 1.2 应用级基线采集

```bash
# 假设测量 iperf3 性能
APP="iperf3 -s"
APP_NAME="iperf3"

# 1. 启动应用（使用推荐的 NUMA 绑定）
numactl --cpunodebind=5 --membind=5 $APP &
PID=$!
echo "Application PID: $PID"

# 2. 等待应用稳定
sleep 5

# 3. 采集 30 秒基线数据
perf stat -e cycles,instructions,\
  L1-dcache-loads,L1-dcache-load-misses,\
  cache-references,cache-misses,\
  dTLB-loads,dTLB-load-misses \
  -I 1000 -p $PID -o baseline_perf.txt -- sleep 30 &

# 4. 并行采集 NUMA 统计
for i in {1..30}; do
  numastat -p $PID | tail -n +3 >> baseline_numa.txt
  sleep 1
done

# 5. 如果内核支持 L3 PMU
perf stat -e amd_l3/l3_cache_accesses/,amd_l3/l3_cache_misses/ \
  -p $PID -- sleep 30 >> baseline_l3.txt 2>&1

# 6. 采集中断分布快照
cat /proc/interrupts > baseline_interrupts.txt
cat /proc/softirqs > baseline_softirqs.txt
mpstat -P ALL 1 10 > baseline_cpu.txt
```

### 1.3 深度分析（可选）

```bash
# A. 热点函数分析
perf record -e cache-misses -g -p $PID -- sleep 10
perf report --stdio > baseline_hotspots.txt

# B. 缓存一致性分析（需要 root）
sudo perf c2c record -ag -p $PID -- sleep 10
sudo perf c2c report --stdio > baseline_c2c.txt

# C. 内存访问模式（Intel 需要 PEBS，AMD 需要 IBS）
perf mem record -p $PID -- sleep 10
perf mem report --stdio > baseline_mem.txt
```

## 阶段 2：问题识别与定位

### 2.1 快速诊断检查表

```bash
# 使用基线数据计算关键指标
cat baseline_perf.txt | grep -A1 "cycles\|instructions\|cache"

# 自动计算脚本
cat > analyze_baseline.sh << 'EOF'
#!/bin/bash
PERF_FILE=$1

CYCLES=$(grep " cycles" $PERF_FILE | awk '{print $1}' | tr -d ',')
INSN=$(grep " instructions" $PERF_FILE | awk '{print $1}' | tr -d ',')
L1_LOADS=$(grep "L1-dcache-loads" $PERF_FILE | awk '{print $1}' | tr -d ',')
L1_MISSES=$(grep "L1-dcache-load-misses" $PERF_FILE | awk '{print $1}' | tr -d ',')
L2_REFS=$(grep "cache-references" $PERF_FILE | awk '{print $1}' | tr -d ',')
L2_MISSES=$(grep "cache-misses" $PERF_FILE | awk '{print $1}' | tr -d ',')

echo "=== 性能指标分析 ==="
echo "IPC: $(echo "scale=2; $INSN / $CYCLES" | bc)"
echo "L1 miss率: $(echo "scale=2; $L1_MISSES * 100 / $L1_LOADS" | bc)%"
echo "L2 miss率: $(echo "scale=2; $L2_MISSES * 100 / $L2_REFS" | bc)%"
echo "MPKI: $(echo "scale=2; $L2_MISSES * 1000 / $INSN" | bc)"
EOF

chmod +x analyze_baseline.sh
./analyze_baseline.sh baseline_perf.txt
```

### 2.2 问题分类决策树

```
开始诊断
    |
    ├─ IPC < 0.5?
    |   └─ YES → CPU 饥饿，检查：
    |       ├─ mpstat: CPU 是否被其他进程占用
    |       ├─ runqlat: 调度延迟
    |       └─ offcputime: 阻塞原因
    |
    ├─ L1 miss > 5%?
    |   └─ YES → L1 缓存问题，检查：
    |       ├─ 数据结构大小（是否 > 32KB）
    |       ├─ perf record: 热点函数访问模式
    |       └─ 考虑数据重组或预取优化
    |
    ├─ L2 miss > 10%?
    |   └─ YES → L2 缓存问题，检查：
    |       ├─ 工作集大小（是否 > 512KB）
    |       ├─ 是否有大量指令缓存 miss
    |       └─ 进入 L3 分析
    |
    ├─ L3 miss > 10%?
    |   └─ YES → 内存访问瓶颈，检查：
    |       ├─ numastat: NUMA miss 率
    |       ├─ perf mem: 远端访问比例
    |       └─ 内存亲和性配置
    |
    └─ Remote HITM > 15%?
        └─ YES → 缓存一致性问题，检查：
            ├─ perf c2c: 热点缓存行地址
            ├─ 是否有伪共享（false sharing）
            └─ 跨 CCX/NUMA 数据共享
```

## 阶段 3：针对性优化

### 3.1 CPU 绑定优化

```bash
# 场景1：单 CCX 绑定（推荐用于低并发应用）
numactl --physcpubind=40-43 --membind=5 $APP

# 场景2：整个 NUMA 节点（高并发应用）
numactl --cpunodebind=5 --membind=5 $APP

# 场景3：使用 cpuset cgroup（生产环境推荐）
cgcreate -g cpuset,memory:/high_perf
cgset -r cpuset.cpus=40-43 high_perf
cgset -r cpuset.mems=5 high_perf
cgset -r cpuset.cpu_exclusive=1 high_perf
cgexec -g cpuset,memory:high_perf $APP
```

### 3.2 中断亲和性优化

```bash
# 使用项目工具自动配置
sudo bash ebpf-tools/cpu/nic_irq_set_affinity.sh ens43f0np0 40-43

# 手动配置示例
IFACE=ens43f0np0
TARGET_CPUS="40-43"

for IRQ in $(grep $IFACE /proc/interrupts | awk '{print $1}' | sed 's/://'); do
    echo $TARGET_CPUS > /proc/irq/$IRQ/smp_affinity_list
done

# 配置 RPS/XPS
for RXQ in /sys/class/net/$IFACE/queues/rx-*/rps_cpus; do
    printf '%x' $((0xff << 40)) > $RXQ  # CPU 40-47 的掩码
done
```

### 3.3 内存优化

```bash
# 1. 禁用 NUMA 自动平衡
echo 0 | sudo tee /proc/sys/kernel/numa_balancing

# 2. 本地内存优先
echo 1 | sudo tee /proc/sys/vm/zone_reclaim_mode

# 3. 配置大页内存（为 NUMA 5）
echo 1024 | sudo tee /sys/devices/system/node/node5/hugepages/hugepages-2048kB/nr_hugepages

# 4. 使用大页运行应用
numactl --physcpubind=40-43 --membind=5 --huge $APP
```

## 阶段 4：效果验证

### 4.1 A/B 对比测试

```bash
# 脚本：对比优化前后性能
cat > compare_performance.sh << 'EOF'
#!/bin/bash
echo "=== 优化前（baseline）==="
cat baseline_perf.txt | grep -E "cycles|instructions|cache-misses"

echo -e "\n=== 优化后 ==="
perf stat -e cycles,instructions,cache-misses -p $1 -- sleep 30

echo -e "\n=== NUMA 对比 ==="
echo "优化前:"
tail -1 baseline_numa.txt
echo "优化后:"
numastat -p $1 | tail -1
EOF

chmod +x compare_performance.sh
./compare_performance.sh $PID
```

### 4.2 长期监控

```bash
# 使用 perf stat 持续监控
perf stat -e cycles,instructions,cache-misses,\
  amd_l3/l3_cache_accesses/,amd_l3/l3_cache_misses/ \
  -I 60000 -p $PID -o monitoring.log &

# 每分钟记录 NUMA 状态
while true; do
  date >> numa_monitoring.log
  numastat -p $PID >> numa_monitoring.log
  sleep 60
done &
```

## 阶段 5：文档化与固化

### 5.1 生成优化报告

```bash
cat > optimization_report.md << EOF
# 缓存与内存优化报告

## 系统信息
- CPU: $(lscpu | grep "Model name" | cut -d: -f2)
- 内核: $(uname -r)
- 应用: $APP_NAME

## 基线指标
$(cat baseline_perf.txt | grep -A1 "cycles\|cache")

## 优化措施
1. CPU 绑定: CCX 40-43, NUMA 5
2. 中断绑定: IRQs → CPU 40-43
3. 内存绑定: NUMA 5, 1024×2MB hugepages
4. 禁用 NUMA balancing

## 优化后指标
$(perf stat -e cycles,instructions,cache-misses -p $PID -- sleep 10 2>&1)

## 性能提升
- IPC: X.XX → Y.YY (+ZZ%)
- L2 miss率: X.X% → Y.Y% (-ZZ%)
- NUMA miss率: X.X% → Y.Y% (-ZZ%)

## 配置命令
\`\`\`bash
numactl --physcpubind=40-43 --membind=5 $APP
sudo bash ebpf-tools/cpu/nic_irq_set_affinity.sh ens43f0np0 40-43
\`\`\`
EOF

cat optimization_report.md
```

### 5.2 自动化脚本

```bash
# 将优化步骤固化为启动脚本
cat > start_optimized_app.sh << 'EOF'
#!/bin/bash
# 优化后的应用启动脚本

# 1. 系统优化
echo 0 > /proc/sys/kernel/numa_balancing
echo 1 > /proc/sys/vm/zone_reclaim_mode

# 2. 配置大页
echo 1024 > /sys/devices/system/node/node5/hugepages/hugepages-2048kB/nr_hugepages

# 3. 中断绑定
bash ebpf-tools/cpu/nic_irq_set_affinity.sh ens43f0np0 40-43

# 4. 启动应用
numactl --physcpubind=40-43 --membind=5 $@
EOF

chmod +x start_optimized_app.sh
```

## 总结：量化效果评估

完成优化后，使用以下公式评估效果：

```
性能提升 (%) = (优化后 IPC - 基线 IPC) / 基线 IPC × 100

缓存效率提升 (%) = (基线 L2 miss率 - 优化后 L2 miss率) / 基线 L2 miss率 × 100

NUMA 效率提升 (%) = (基线 NUMA miss率 - 优化后 NUMA miss率) / 基线 NUMA miss率 × 100

总体收益 (%) ≈ 性能提升 + 缓存效率提升×系数 + NUMA效率提升×系数
                （系数取决于应用特征，典型为 0.3-0.5）
```

**预期目标**：
- IPC 提升 > 20%
- L2 miss 率降低 > 30%
- NUMA miss 率降低 > 50%
- Remote HITM 率降低 > 60%
- **整体性能提升 30-60%**（对于内存密集型应用）

附加资源
--------
- AMD/Hygon Fam17h PPR（参考 L3 PMU `0xC4` 事件、`amd_l3` SliceMask 注册说明）。  
- Linux `tools/perf/pmu-events/arch/x86/amdzen*/*.json`：提供 Zen 事件表。  
- pmu-tools 项目：https://github.com/andikleen/pmu-tools  
- BCC 项目：https://github.com/iovisor/bcc  
- `perf` 文档：`man perf-stat`, `man perf-list`, `Documentation/admin-guide/perf-security.rst`
