# eBPF 网络故障排查工具 - 用户手册

## 目录

- [1. 项目结构](#1-项目结构)
  - [目录分类](#目录分类)
- [2. 工具测量类型分类](#2-工具测量类型分类)
  - [2.1 Details 版本 - 详细信息测量工具](#21-details-版本---详细信息测量工具)
  - [2.2 Summary 版本 - 汇总统计测量工具](#22-summary-版本---汇总统计测量工具)
  - [2.3 Simple 版本 - 简化版工具](#23-simple-版本---简化版工具)
  - [2.4 Standalone 工具 - 独立功能工具](#24-standalone-工具---独立功能工具)
  - [2.5 分层测量策略建议](#25-分层测量策略建议)
  - [2.6 Path Tracer 版本 - 边界检测路径追踪工具](#26-path-tracer-版本---边界检测路径追踪工具)
- [3. 模块特定工具详情](#3-模块特定工具详情)
  - [3.1 CPU 模块](#31-cpu-模块-cpu)
  - [3.2 KVM 虚拟化网络模块](#32-kvm-虚拟化网络模块-kvm-virt-network)
  - [3.3 Linux 网络栈模块](#33-linux-网络栈模块-linux-network-stack)
  - [3.4 Open vSwitch 模块](#34-open-vswitch-模块-ovs)
  - [3.5 性能模块](#35-性能模块-performance)
  - [3.6 其他工具模块](#36-其他工具模块-other)
  - [3.7 边界检测模块](#37-边界检测模块-boundary-detection)
- [4. 工具使用指南](#4-工具使用指南)
  - [4.1 基本使用模式](#41-基本使用模式)
  - [4.2 性能监控模块](#42-性能监控模块-performance)
  - [4.3 Linux 网络栈模块](#43-linux-网络栈模块-linux-network-stack)
  - [4.4 Open vSwitch 模块](#44-open-vswitch-模块-ovs)
  - [4.5 KVM 虚拟化网络模块](#45-kvm-虚拟化网络模块-kvm-virt-network)
  - [4.6 Bpftrace 脚本工具](#46-bpftrace-脚本工具)
  - [4.7 CPU 和调度器监控脚本](#47-cpu-和调度器监控脚本)
  - [4.8 参数模式总结](#48-参数模式总结)
  - [4.9 边界检测模块](#49-边界检测模块-boundary-detection)
- [5. 输出数据格式详解](#5-输出数据格式详解)
  - [5.1 性能监控工具输出格式](#51-性能监控工具输出格式)
  - [5.2 Linux 网络栈监控输出格式](#52-linux-网络栈监控输出格式)
  - [5.3 OVS 监控输出格式](#53-ovs-监控输出格式)
  - [5.4 KVM 虚拟化网络输出格式](#54-kvm-虚拟化网络输出格式)
  - [5.5 Bpftrace 脚本输出格式](#55-bpftrace-脚本输出格式)
  - [5.6 输出格式特点总结](#56-输出格式特点总结)
  - [5.7 边界检测工具输出格式](#57-边界检测工具输出格式)
- [6. 部署和环境](#6-部署和环境)
  - [6.1 系统要求](#61-系统要求)
  - [6.2 目标环境](#62-目标环境)
  - [6.3 安装部署步骤](#63-安装部署步骤)
  - [6.4 故障排查和支持](#64-故障排查和支持)
  - [6.5 版本兼容性](#65-版本兼容性)
- [7. 使用最佳实践](#7-使用最佳实践)
  - [7.1 监控最佳实践](#71-监控最佳实践)

## 1. 项目结构

项目按照系统组件和问题域进行模块化目录组织。主要结构由使用 Python（BCC）编写的 eBPF 工具和 bpftrace 脚本组成。

### 目录分类

```
measurement-tools/
├── boundary-detection/               # 网络边界丢包检测工具
│   ├── system-network/              # 系统级边界检测（主机端点场景）
│   └── vm-network/                  # 虚拟机级边界检测（转发路径场景）
├── cpu/                              # CPU 和调度器监控工具
├── kvm-virt-network/                 # KVM/QEMU 虚拟化网络栈工具
│   ├── kvm/                         # KVM 中断、IRQ 和 TX 延迟监控
│   ├── tun/                         # TUN/TAP 设备和中断链监控
│   ├── vhost-net/                   # vhost-net 后端监控
│   └── virtio-net/                  # virtio-net 客户机驱动监控
├── linux-network-stack/             # Linux 内核网络栈工具
│   └── packet-drop/                 # 丢包检测和分析
├── other/                           # 其他跟踪工具
├── ovs/                             # Open vSwitch 监控工具
└── performance/                     # 网络性能监控
    ├── system-network/              # 系统级网络性能
    │   ├── ovs-internal-port/       # OVS 内部端口延迟分析
    │   └── tcp-perf/                # TCP 性能分析工具集
    └── vm-network/                  # 虚拟机专用网络性能
```

## 2. 工具测量类型分类

除了按模块/子系统分类外,工具还可以按照测量方式和数据采集粒度分为以下几类:

### 2.1 Details 版本 - 详细信息测量工具

**特点:**

- 采集特定网络路径上每个数据包的完整元数据
- 实时输出,per-packet 级别跟踪
- 记录详细的时间戳、SKB 信息、设备信息、栈跟踪等
- 支持多种过滤器(五元组、接口、协议等)以缩小采集范围

**适用场景:**

- 精确问题定位和根因分析
- 详细数据包路径分析
- 异常流量的细粒度追踪
- 特定时段的深度性能分析

**性能开销:**

- 较高(per-packet 处理和输出)
- 建议使用过滤器限制采集范围
- 不适合长时间大范围监控

**典型工具:**

- `system_network_latency_details.py` - 系统网络延迟详细分析
- `vm_network_latency_details.py` - VM 网络延迟详细分析
- `vhost_queue_correlation_details.py` - vhost 队列关联详细统计
- `qdisc_lateny_details.py` - Qdisc 数据包排序详细跟踪

### 2.2 Summary 版本 - 汇总统计测量工具

**特点:**

- 基于 BPF_HISTOGRAM 的高效内核态聚合
- 按时间间隔输出统计结果(直方图分布)
- 统计延迟分布、计数分布、频率分布等
- 使用对数刻度的 bucket 划分: [0-1), [1-2), [2-4), [4-8), [8-16), [16-32), ...
- Bucket 计算公式: `bpf_log2l(value + 1)`

**适用场景:**

- 长时间性能监控和趋势分析
- 建立性能基线和识别异常时段
- 大范围流量特征分析
- 初步问题筛查和范围确定
- 生产环境持续监控

**性能开销:**

- 低(内核态聚合,定期输出)
- 适合长时间运行
- 可覆盖大量流量

**典型工具:**

- `system_network_latency_summary.py` - 系统网络相邻阶段延迟直方图
- `vm_network_latency_summary.py` - VM 网络相邻阶段延迟直方图
- `ovs_upcall_latency_summary.py` - OVS upcall 延迟分布统计
- `kvm_irqfd_stats_summary.py` - KVM 中断注入统计(直方图)
- `kernel_drop_stack_stats_summary_all.py` - 内核丢包栈统计(直方图)
- `tun_to_vhost_queue_stats_full_summary.py` - TUN 到 vhost 队列完整统计(直方图)
- `tun_to_vhost_queue_status_simple_summary.py` - TUN 到 vhost 队列状态简化统计(直方图)
- `enqueue_to_iprec_latency_summary.py` - OVS 内部端口 enqueue 到 ip_rcv 延迟直方图
- `tcp_rtt_inflight_summary.py` - TCP RTT/inflight/cwnd 三重直方图
- `syscall_recv_latency_summary.py` - recv 系统调用延迟直方图

### 2.3 Simple 版本 - 简化版工具

**特点:**

- 介于 details 和 summary 之间的轻量级跟踪
- 简化的 per-event 跟踪(非 histogram 聚合)
- 减少数据采集维度和输出信息量
- 通常基于关键事件或简化的数据结构

**适用场景:**

- 需要事件级跟踪但不需要完整元数据
- 快速验证某些行为模式
- 资源受限环境下的监控

**典型工具:**

- `vhost_queue_correlation_simple.py` - vhost 队列关联简化监控
- `eth_drop.py` - 全内核范围丢包监控（支持多协议、IP、端口、VLAN 过滤）

### 2.4 Standalone 工具 - 独立功能工具

**特点:**

- 无版本变体的专用工具
- 针对特定监控场景或功能
- 通常是 bpftrace 脚本或特殊用途工具

**典型工具:**

- `system_network_icmp_rtt.py` - ICMP RTT 专用测量
- `trace_conntrack.py` - 连接跟踪监控
- `ovs_userspace_megaflow.py` - OVS megaflow 跟踪
- `tcp_connection_analyzer.py` - TCP 连接综合分析（BDP、瓶颈检测）
- `deploy_full_mesh_icmp_tracer.py` - 集群全网格 ICMP RTT 部署编排
- 各类 bpftrace 脚本 (*.bt)

### 2.5 分层测量策略建议

**推荐的问题诊断流程:**

1. **第一阶段 - 问题筛查** (使用 Summary 工具)

   - 部署相关模块的 summary 版本工具
   - 设置合理的统计间隔(5-10 秒)
   - 建立性能基线,识别异常时段
   - 分析延迟分布、丢包分布等直方图
   - 确定需要深入分析的时间窗口和流量特征
2. **第二阶段 - 精确定位** (使用 Details 工具)

   - 根据 summary 结果提取异常五元组、时间段等
   - 使用这些信息作为 details 工具的过滤器
   - 部署对应的 details 版本工具
   - 采集精确的 per-packet 元数据
   - 分析具体数据包的处理路径和延迟
3. **第三阶段 - 持续监控** (使用 Summary 工具)

   - 问题修复后,部署 summary 工具持续监控
   - 低性能开销,可长时间运行
   - 验证问题是否复现
   - 支持自动化告警集成

**示例:**

```bash
# 阶段1: 使用 summary 工具建立基线
sudo python3 measurement-tools/performance/vm-network/vm_network_latency_summary.py \
  --vm-interface vnet0 --phy-interface ens4 \
  --protocol tcp --direction rx --interval 5

# 发现 P99 延迟异常,且主要来自 172.21.153.113 → 172.21.153.114

# 阶段2: 使用 details 工具精确分析
sudo python3 measurement-tools/performance/vm-network/vm_network_latency_details.py \
  --vm-interface vnet0 --phy-interface ens4 \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \
  --protocol tcp --direction rx

# 分析 per-packet 数据,定位到 OVS_RX 阶段延迟异常

# 阶段3: 修复后持续监控
sudo python3 measurement-tools/performance/vm-network/vm_network_latency_summary.py \
  --vm-interface vnet0 --phy-interface ens4 \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \
  --protocol tcp --direction rx --interval 10
```

### 2.6 Path Tracer 版本 - 边界检测路径追踪工具

**特点:**

- 在网络路径的关键边界点（物理网卡、内核协议栈入口/出口）设置探针，追踪数据包是否通过每个边界
- 通过对比相邻边界的包计数来定位丢包发生的区间
- 支持双向追踪（请求包和响应包的完整路径）
- 针对不同协议（TCP/UDP/ICMP）使用不同的包标识策略（ICMP ID/seq、TCP seq、UDP IP ID）

**适用场景:**

- 快速定位网络丢包发生在哪两个网络边界之间
- 区分物理网卡层、内核协议栈、OVS 数据路径等不同层面的丢包
- 虚拟化环境中定位丢包是发生在宿主机侧还是虚拟机侧
- 配合 Details/Summary 工具使用：先用 Path Tracer 定位丢包区间，再用对应阶段的详细工具分析根因

**性能开销:**

- 中等（每个边界点一个 eBPF 探针，per-packet 处理）
- 建议使用 IP 和端口过滤器缩小监控范围

**典型工具:**

- `system_icmp_path_tracer.py` - 系统级 ICMP 路径边界检测
- `system_tcp_path_tracer.py` - 系统级 TCP 路径边界检测
- `system_udp_path_tracer.py` - 系统级 UDP 路径边界检测（含 IP 分片处理）
- `icmp_path_tracer.py` - 虚拟机 ICMP 路径边界检测
- `tcp_path_tracer.py` - 虚拟机 TCP 路径边界检测
- `udp_path_tracer.py` - 虚拟机 UDP 路径边界检测（分片组跟踪）

## 3. 模块特定工具详情

### 3.1 CPU 模块 (`cpu/`)

**用途**：监控 CPU 调度、锁竞争和 off-CPU 时间分析

#### 工具：

- **offcputime-ts.py**：跟踪线程阻塞（off-CPU）时间

  - **使用场景**：识别由阻塞操作引起的性能瓶颈
  - **收集数据**：栈跟踪、阻塞时长、时间戳
- **futex.bt**：跟踪 futex 系统调用

  - **使用场景**：调试互斥锁/信号量竞争问题
  - **收集数据**：Futex 操作、等待时间
- **pthread_rwlock_wrlock.bt**：监控 pthread 读写锁写操作

  - **使用场景**：分析读写锁竞争
  - **收集数据**：锁获取尝试、等待时间、栈跟踪
- **cpu_monitor.sh**：综合 CPU 监控脚本

  - **使用场景**：系统范围 CPU 性能分析
  - **收集数据**：CPU 利用率、调度指标
- **sched_latency_monitor.sh**：调度器延迟监控

  - **使用场景**：检测调度延迟
  - **收集数据**：调度延迟直方图

### 3.2 KVM 虚拟化网络模块 (`kvm-virt-network/`)

**模块概述**：该模块包含针对 KVM/QEMU 虚拟化网络栈各层的监控工具，覆盖从 KVM 虚拟机中断注入、TUN/TAP 设备、vhost-net 后端到 virtio-net 客户机驱动的完整虚拟化网络路径。用于诊断虚拟机网络性能问题、中断延迟、队列关联和缓冲区管理等问题。

#### 3.2.1 KVM 子系统 (`kvm/`)

- **kvm_irqfd_stats_summary.py**：基于 histogram 的 KVM 中断注入统计工具

  - **使用场景**：监控特定虚拟机的中断注入性能，分析 vhost 数据平面和 QEMU 控制平面的中断分布，定位中断注入瓶颈
  - **收集数据**：IRQ 注入次数按 GSI 分组统计、中断类别（数据/控制）分布、每 CPU/每线程中断统计、kvm_arch_set_irq_inatomic 和 kvm_vcpu_kick 调用链分析
- **kvm_irqfd_stats_summary_arm.py**：ARM 架构特定的 KVM 中断监控

  - **使用场景**：ARM64 服务器虚拟化环境的中断分析，针对 ARM GIC 中断控制器特性优化
  - **收集数据**：ARM 特定 IRQ 统计、vGIC 中断注入数据
- **kvm_vhost_tun_latency_no_discovery_details.py**：KVM 主机侧 TX 延迟单阶段测量工具

  - **使用场景**：测量虚拟机发包路径中主机侧 TX 延迟，覆盖从 KVM ioeventfd 触发到 vhost 处理再到 TUN 设备发送到 netif_receive_skb 的完整 TX 路径
  - **收集数据**：ioeventfd_write → vhost handle_tx_kick → tun_sendmsg → netif_receive_skb 全路径延迟、按流分组的 per-packet 延迟详情
  - **参数**：`--device` 目标设备名（如 vnet94），`--qemu-pid` QEMU 进程 PID（可自动检测），`--flow` 流过滤器（proto/src/dst/sport/dport），`--warmup` 预热秒数（默认 2 秒用于学习 eventfd）
  - **特点**：自动发现 QEMU PID（通过 OVS/libvirt），通过 QEMU PID 过滤跟踪所有 vhost 线程

#### 3.2.2 TUN/TAP 子系统 (`tun/`)

- **tun_ring_monitor.py**：TUN 设备环形缓冲区实时监控工具

  - **使用场景**：监控 TUN 设备 tx_ring 和 rx 路径状态，检测缓冲区满导致的丢包，分析 vhost-net 与 TUN 之间的数据流瓶颈
  - **收集数据**：环形缓冲区利用率、ptr_ring 状态、队列满事件、每数据包流转详情
- **tun_to_vhost_queue_stats_full_summary.py**：TUN 到 vhost 队列完整统计（histogram 版本）

  - **使用场景**：全面分析 TUN 设备与 vhost-net 之间的队列关联和数据流，统计各队列的数据包处理量和延迟分布
  - **收集数据**：每队列数据包统计、TUN-vhost 队列映射、sock 指针关联、延迟直方图
- **tun_to_vhost_queue_status_simple_summary.py**：TUN 到 vhost 队列简化统计（histogram 版本）

  - **使用场景**：轻量级监控 TUN-vhost 队列状态，快速获取队列活跃度和基本统计
  - **收集数据**：简化的队列状态统计、基本计数器
- **tun-abnormal-gso-type.bt**：异常 GSO 类型检测脚本

  - **使用场景**：识别 GSO/TSO 卸载配置问题导致的网络异常，检测不支持的 GSO 类型
  - **收集数据**：无效 GSO 类型事件、SKB 信息、栈跟踪
- **tun-tx-ring-stas.bt**：TUN 发送环统计脚本

  - **使用场景**：TX 环性能分析，监控发送路径的吞吐量
  - **收集数据**：TX 环占用率、发送数据包计数、吞吐量统计
- **tun_tx_to_kvm_irq.py**：TUN TX 完整中断链路跟踪工具

  - **使用场景**：追踪 TUN 设备发包触发的完整中断注入链路，从 tun_net_xmit 到最终 posted interrupt 的 5 个阶段，用于诊断虚拟化网络中断延迟
  - **收集数据**：5 阶段延迟分解（tun_net_xmit → vhost_signal → eventfd_signal → irqfd_wakeup → posted_int）、socket 指针和 eventfd_ctx 指针关联
  - **参数**：`--device` 目标设备名，`--protocol` 协议过滤（tcp/udp/icmp/all），`--src-ip`/`--dst-ip` IP 过滤，`--src-port`/`--dst-port` 端口过滤，`--stats-interval` 统计输出间隔（默认 10 秒），`--analyze-chains` 启用中断链分析
  - **特点**：跨内核子系统（TUN/vhost/eventfd/KVM）关联跟踪，支持中断链完整性分析

#### 3.2.3 vhost-net 后端 (`vhost-net/`)

- **vhost_eventfd_count.py/bt**：vhost eventfd 信号计数工具

  - **使用场景**：分析虚拟机与主机之间的通知效率，检测过高的 eventfd 信号频率导致的 CPU 开销
  - **收集数据**：Eventfd 信号次数、频率、按队列分组统计
- **vhost_queue_correlation_simple.py**：简化版 vhost 队列关联分析

  - **使用场景**：快速理解 vhost 队列利用模式，监控队列之间的数据流关系
  - **收集数据**：队列对映射、基本利用率指标、简化的事件跟踪
- **vhost_queue_correlation_details.py**：详细 vhost 队列关联分析（details 版本）

  - **使用场景**：深度分析 vhost 队列性能，追踪每个数据包在 vhost 队列中的处理过程，定位队列瓶颈
  - **收集数据**：每队列详细统计、sock 指针关联、virtqueue 索引、完整事件元数据
- **vhost_buf_peek_stats.py**：vhost 缓冲区 peek 操作统计

  - **使用场景**：分析 vhost 缓冲区管理效率，检测缓冲区 peek 操作频率异常
  - **收集数据**：缓冲区 peek 次数、延迟统计
- **sort_vhost_queue_correlation_monitor_signals.py**：vhost 队列关联信号排序工具

  - **使用场景**：对 vhost 队列监控输出进行排序和分析，辅助关联分析结果的后处理
  - **收集数据**：排序后的队列关联信号、统计摘要

#### 3.2.4 virtio-net 客户机驱动 (`virtio-net/`)

- **virtnet_poll_monitor.py**：virtio-net NAPI 轮询监控

  - **使用场景**：分析 NAPI 轮询效率，检测轮询过于频繁或不足导致的性能问题
  - **收集数据**：轮询次数、每次轮询处理的数据包数量、批量大小分布
- **virtnet_irq_monitor.py**：virtio-net 中断监控

  - **使用场景**：评估中断合并（interrupt coalescing）的有效性，分析中断与 CPU 的亲和性配置
  - **收集数据**：IRQ 触发速率、CPU 亲和性分布、中断延迟
- **virtionet-rx-path-monitor.bt**：RX 路径详细监控脚本

  - **使用场景**：识别 virtio-net 接收路径中的处理瓶颈，追踪关键函数的执行延迟
  - **收集数据**：各阶段函数延迟、数据包流转详情、栈跟踪
- **virtionet-rx-path-summary.bt**：RX 路径汇总统计脚本

  - **使用场景**：整体评估 virtio-net 接收性能，获取聚合统计数据
  - **收集数据**：聚合 RX 指标、延迟分布直方图
- **trace_virtio_net_rcvbuf.bt**：接收缓冲区跟踪脚本

  - **使用场景**：诊断缓冲区分配相关问题，检测 OOM 或分配失败事件
  - **收集数据**：缓冲区大小分布、分配成功/失败计数

### 3.3 Linux 网络栈模块 (`linux-network-stack/`)

**模块概述**：该模块提供针对 Linux 内核网络栈的监控和诊断工具，包括连接跟踪（conntrack）、IP 分片重组、以及全面的丢包检测功能。用于诊断防火墙/NAT 问题、分片丢包、以及定位内核网络栈中的丢包位置和原因。

#### 核心网络栈工具

- **trace_conntrack.py**：连接跟踪（conntrack）监控工具

  - **使用场景**：诊断 NAT、防火墙相关的连接问题，追踪 conntrack 表项的状态变化，检测连接跟踪溢出
  - **收集数据**：连接状态（NEW/ESTABLISHED/RELATED/INVALID）、nfct 指针值、超时信息、支持多规则过滤
- **trace_ip_defrag.py**：IP 分片和重组跟踪工具

  - **使用场景**：诊断因 IP 分片导致的丢包问题，分析 MTU 配置不当造成的网络故障
  - **收集数据**：分片计数、重组成功/失败统计、分片超时

#### 丢包子系统 (`packet-drop/`)

- **eth_drop.py**：全内核范围数据包丢包监控工具

  - **使用场景**：监控全内核范围内的所有 kfree_skb 丢包事件，覆盖多种协议类型（ARP、RARP、IPv4、IPv6、LLDP、流控等），支持按二层协议类型、L4 协议（ICMP/TCP/UDP）、IP 地址、端口、VLAN ID、接口过滤，内置正常 kfree_skb 模式过滤
  - **收集数据**：丢包位置（kfree_skb 完整调用栈）、数据包二层/三层/四层信息、VLAN 标签、接口名称
  - **新增参数**：`--l4-protocol` 按 L4 协议过滤（icmp/tcp/udp/all），`--disable-normal-filter` 关闭正常丢包模式过滤（默认过滤 tcp_recvmsg 等正常释放事件）
- **kernel_drop_stack_stats_summary_all.py**：内核丢包栈统计分析（histogram 版本）

  - **使用场景**：按调用栈聚合统计内核中所有丢包事件，识别丢包热点位置，支持长时间监控
  - **收集数据**：丢包栈跟踪频率直方图、丢包计数按栈分组统计
- **kernel_drop_stack_stats.bt**：实时内核丢包栈跟踪脚本

  - **使用场景**：实时调试丢包问题，获取每次丢包事件的详细栈跟踪
  - **收集数据**：实时丢包事件、完整内核调用栈
- **qdisc_drop_trace.py**：Qdisc 队列规则丢包监控

  - **使用场景**：分析流量控制（TC）层面的丢包，诊断队列满导致的丢包，支持按设备和协议过滤
  - **收集数据**：Qdisc 丢包原因、队列深度、数据包信息、基于 histogram 的高效统计
  - **新增参数**：`--drops-only` 仅显示丢弃的数据包（return code != 0），`--summary` 仅输出汇总统计（适用于高流量场景）
  - **监控函数**：`__dev_queue_xmit`、`dev_hard_start_xmit`、`erspan_xmit`、`fq_codel_enqueue`

### 3.4 Open vSwitch 模块 (`ovs/`)

**模块概述**：该模块提供针对 Open vSwitch 数据路径的监控工具，包括内核模块丢包检测、用户空间 upcall 延迟分析、以及 megaflow 缓存效率监控。用于诊断 OVS 相关的网络性能问题和丢包问题。

- **ovs-kernel-module-drop-monitor.py**：OVS 数据路径丢包监控

  - **使用场景**：检测 OVS 内核模块中的丢包事件，定位 OVS 数据路径中的丢包位置
  - **收集数据**：丢包原因、流信息、丢包位置栈跟踪
- **ovs_upcall_latency_summary.py**：OVS upcall 延迟统计（histogram 版本）

  - **使用场景**：监控 OVS upcall 到用户空间的延迟分布，识别 upcall 处理瓶颈，评估 flow cache miss 的性能影响
  - **收集数据**：upcall 延迟直方图（ovs_dp_upcall 到 ovs_flow_key_extract_userspace）、完成率统计
- **ovs_userspace_megaflow.py**：OVS Megaflow 生成跟踪工具

  - **使用场景**：监控符合特定过滤条件的数据流触发的 upcall 事件以及 megaflow 的生成/添加过程，灵活统计特定流量的 megaflow 生成情况
  - **收集数据**：upcall 事件详情（五元组、时间戳、进程）、flow_cmd_new 事件（megaflow 添加）、Netlink 消息解析

### 3.5 性能模块 (`performance/`)

**模块概述**：该模块提供系统级和虚拟机级的网络性能监控工具，包括延迟测量（summary 和 details 版本）、RTT 测量、以及虚拟机间通信延迟分析。工具按照测量粒度分为 histogram 聚合（summary）和 per-packet 跟踪（details）两类，适用于不同的诊断阶段。

#### 系统网络性能 (`system-network/`)

- **system_network_latency_summary.py** [Summary 版本]

  - **使用场景**：长时间监控系统网络栈各阶段的延迟分布，建立性能基线，识别异常延迟时段
  - **测量方式**：基于 BPF_HISTOGRAM 的延迟统计，默认仅测量端到端总延迟（最小探针开销），可选开启逐阶段延迟分解
  - **收集数据**：延迟分布直方图（对数刻度 buckets）、端到端总延迟、可选各阶段对延迟、per-flow Top-N 统计
  - **性能开销**：低（默认总延迟模式），中等（`--stage-latency` 模式，约 10 个探针）
  - **监控阶段**：TX: ip_queue_xmit(TCP)/ip_send_skb(UDP) → internal_dev_xmit → ovs_dp_process_packet → ovs_vport_send → net_dev_xmit；RX: __netif_receive_skb → netdev_frame_hook → ovs_dp_process_packet → ovs_vport_send → tcp_v4_rcv/udp_rcv/icmp_rcv
  - **新增参数**：`--stage-latency` 开启逐阶段延迟分解，`--sort-by` (count/avg/p90/p99) 排序 per-flow 统计，`--top` 控制显示 Top-N 流
  - **注意**：upcall 延迟测量已分离到独立工具 `ovs_upcall_latency_summary.py`
- **system_network_latency_details.py** [Details 版本]

  - **使用场景**：精确问题定位，详细数据包路径分析，追踪特定流量的每包延迟
  - **测量方式**：Per-packet 实时跟踪
  - **收集数据**：每个数据包的完整元数据、精确时间戳、各阶段延迟、五元组信息
  - **性能开销**：较高（需使用过滤器控制监控范围）
- **system_network_icmp_rtt.py** [Standalone 工具]

  - **使用场景**：ICMP 网络延迟基准测试，测量端到端 RTT，验证网络连通性和延迟
  - **收集数据**：ICMP echo request/reply 往返时间、丢包率统计
- **kernel_icmp_rtt.py** [Standalone 工具]

  - **使用场景**：内核级 ICMP RTT 测量，支持本机发起 ping（TX 模式）和远端 ping 本机（RX 模式）两种方向，测量内核协议栈各阶段精确时间戳
  - **收集数据**：ICMP 往返时间（微秒级）、可选内核调用栈
  - **参数**：`--interface` 物理接口（支持逗号分隔的多接口用于 bond 场景），`--direction` (tx/rx) 选择测量方向，`--disable-kernel-stacks` 关闭栈跟踪输出
  - **监控阶段**：TX: ip_local_out → net_dev_xmit；RX: netif_receive_skb → icmp_rcv
- **deploy_full_mesh_icmp_tracer.py** [Standalone 部署工具]

  - **使用场景**：集群环境全网格 ICMP RTT 追踪部署，为 N 个节点自动生成 N*(N-1)*2 个追踪器（每对节点的 TX 和 RX 方向），用于集群网络延迟全面监控
  - **收集数据**：集群内任意两节点间的 ICMP RTT 数据
  - **参数**：`--nodes` 逗号分隔的节点管理 IP 列表，`--user` SSH 用户名（默认 smartx），`--network-type` 监控网络类型（默认 storage），`--tx-latency`/`--rx-latency` 延迟阈值（ms），`--dry-run` 预览模式，`--stop` 停止所有追踪器，`--status` 查看状态
  - **特点**：SSH 自动部署、支持 dry-run 预览、JSON 输出
- **system_network_perfomance_metrics.py** [Standalone 工具]

  - **使用场景**：整体系统网络性能评估，综合监控吞吐量和延迟
  - **收集数据**：完整数据流跟踪、吞吐量、延迟统计
  - **特点**：支持连接跟踪（`--enable-ct`）

##### OVS 内部端口延迟分析 (`ovs-internal-port/`)

- **enqueue_to_iprec_latency_summary.py** [Summary 版本]

  - **使用场景**：测量 OVS 内部端口关键异步边界延迟（enqueue_to_backlog → __netif_receive_skb → ip_rcv），诊断软中断处理延迟和 RX 路径瓶颈
  - **收集数据**：异步边界延迟直方图、可选高延迟事件跟踪
  - **参数**：`--interface` 目标接口（物理网卡或 OVS 内部端口如 br-int），`--protocol` (tcp/udp/all)，`--src-ip`/`--dst-ip`/`--src-port`/`--dst-port` 过滤，`--interval` 统计间隔（默认 5 秒），`--threshold` 高延迟阈值（微秒）
- **enqueue_to_iprec_latency_threshold.py** [Threshold 版本]

  - **使用场景**：当延迟超过阈值时捕获内核栈跟踪，用于定位造成异步边界高延迟的具体内核函数和上下文
  - **收集数据**：超阈值延迟事件、CPU 信息、队列深度、内核栈跟踪
  - **参数**：`--interface` 目标接口，`--threshold-us` 延迟阈值（微秒，默认 1000），`--protocol` (tcp/udp/all)，IP/端口过滤

##### TCP 性能分析 (`tcp-perf/`)

- **tcp_rtt_inflight_summary.py** [Summary 版本]

  - **使用场景**：TCP 性能综合分析，同时收集 RTT、inflight 包数和拥塞窗口三个关键指标的分布，用于快速识别 TCP 性能瓶颈
  - **收集数据**：RTT 直方图（微秒）、inflight 包数直方图、cwnd 直方图、可选带宽直方图
  - **参数**：`--laddr`/`--raddr` 本地/远端 IP 过滤，`--lport`/`--rport` 端口过滤，`--interval` 输出间隔（默认 1 秒），`--sample-rate` 采样率（降低开销），`--bw-hist` 启用带宽直方图
  - **特点**：三重直方图并行收集，支持 per-interval 时间序列输出
- **syscall_recv_latency_summary.py** [Summary 版本]

  - **使用场景**：诊断用户态应用接收性能，分析 read/recv/recvfrom/recvmsg 系统调用延迟，评估 CPU/NUMA 绑定对接收性能的影响
  - **收集数据**：系统调用延迟直方图、每次调用接收字节数、CPU 迁移次数、NUMA 节点信息
  - **参数**：`--process` 进程名，`--pid` 进程 PID，`--port` 端口过滤，`--interval` 统计间隔（默认 5 秒），`--high-latency-threshold` 高延迟阈值（微秒）
- **tcp_connection_analyzer.py** [Standalone 分析工具]

  - **使用场景**：TCP 连接全面分析，计算带宽延迟积（BDP）和推荐缓冲区大小，检测性能瓶颈（rwnd_limited/cwnd_limited）并提供可操作的优化建议
  - **收集数据**：TCP 连接详情、BDP 计算、缓冲区建议、瓶颈分类
  - **参数**：`--role` (client/server)，`--local-ip`/`--local-port`/`--remote-ip`/`--remote-port` 过滤，`--interval` 监控间隔（0=单次快照），`--target-bandwidth` 目标带宽（Gbps，默认 25），`--show-analysis` 显示瓶颈分析和建议，`--json` JSON 输出
  - **特点**：自动检测瓶颈类型并生成优化建议（调整缓冲区、拥塞控制等）

#### 虚拟机网络性能 (`vm-network/`)

- **vm_network_latency_summary.py** [Summary 版本]

  - **使用场景**：长时间监控虚拟机网络栈各阶段延迟，建立 VM 网络性能基线，识别瓶颈阶段
  - **测量方式**：基于 BPF_HISTOGRAM 的延迟统计，默认仅测量端到端总延迟，可选开启逐阶段延迟分解
  - **收集数据**：VM 网络栈各阶段延迟分布直方图、端到端总延迟、per-flow Top-N 统计
  - **性能开销**：低（默认总延迟模式），中等（`--stage-latency` 模式，约 10 个探针）
  - **监控阶段**：VM TX (VNET RX): VNET_RX → OVS_RX → FLOW_EXTRACT → CT → QDISC_ENQ → QDISC_DEQ → TX_QUEUE → TX_XMIT；VM RX (VNET TX): PHY_RX → OVS_TX → FLOW_EXTRACT → CT → VNET_QDISC_ENQ → VNET_QDISC_DEQ → VNET_TX
  - **新增参数**：`--vm-ip` VM IP 过滤，`--enable-ct` 启用 conntrack 测量，`--stage-latency` 开启逐阶段分解，`--sort-by` (count/avg/p90/p99) 排序 per-flow 统计，`--top` 显示 Top-N 流
  - **注意**：upcall 延迟测量已分离到独立工具 `ovs_upcall_latency_summary.py`
- **vm_network_latency_details.py** [Details 版本]

  - **使用场景**：虚拟机网络精确延迟分析，追踪特定 VM 流量的每包处理延迟
  - **测量方式**：Per-packet 级别跟踪
  - **收集数据**：主机-虚拟机-主机完整路径的详细延迟组件、五元组、SKB 指针
  - **性能开销**：较高（建议使用五元组过滤器限制范围）
- **vm_network_performance_metrics.py** [Standalone 工具]

  - **使用场景**：虚拟机网络性能全面监控，综合评估 VM 网络吞吐和延迟
  - **收集数据**：虚拟机特定吞吐量、PPS、完整流跟踪

#### 通用性能工具

- **qdisc_lateny_details.py** [Details 版本]

  - **使用场景**：Qdisc 层数据包排序详细跟踪，分析队列调度延迟
  - **收集数据**：队列规则处理时间、数据包入队出队延迟
  - **性能开销**：较高（per-packet 跟踪）

### 3.6 其他工具模块 (`other/`)

**模块概述**：该模块包含各类专用 bpftrace 脚本，用于特定场景的网络问题诊断，包括 ARP 异常检测、连接跟踪调试、卸载功能分析、以及流量控制监控。

- **trace-abnormal-arp.bt**：异常 ARP 检测

  - **使用场景**：检测 ARP 欺骗攻击、ARP 泛洪、或 ARP 配置问题
  - **收集数据**：可疑 ARP 数据包、源/目标 MAC 和 IP 地址
- **trace-ovs-ct-invalid.bt**：OVS 连接跟踪无效状态检测

  - **使用场景**：诊断 OVS 环境下连接跟踪相关问题，检测无效 CT 状态导致的丢包
  - **收集数据**：无效 CT 条目、关联流信息
- **trace_offloading_segment.bt**：分段卸载跟踪

  - **使用场景**：调试 TSO/GSO/UFO 卸载相关问题，验证卸载配置正确性
  - **收集数据**：卸载参数、段大小、SKB 信息
- **trace_vlanvm_udp_workload.bt**：VLAN 虚拟机 UDP 跟踪

  - **使用场景**：诊断 VLAN 环境下 UDP 流量问题，分析 VLAN 标签处理
  - **收集数据**：VLAN 标签、UDP 流信息、数据包路径
- **vpc-vm-udp-datapath.bt**：VPC 虚拟机 UDP 数据路径

  - **使用场景**：云环境下 UDP 数据路径分析，追踪 VPC 网络中的 UDP 流转
  - **收集数据**：VPC 流路径、延迟点
- **trace-qdisc-dequeue.bt**：Qdisc 出队操作跟踪

  - **使用场景**：分析队列调度器的出队行为，诊断调度延迟
  - **收集数据**：出队时间、队列深度、调度模式
- **trace_dev_queue_xmit.bt**：设备队列传输跟踪

  - **使用场景**：监控 TX 队列行为，检测队列满导致的丢包
  - **收集数据**：队列深度、传输延迟、丢包事件
- **trace_tc_qdisc.bt**：流量控制 qdisc 跟踪

  - **使用场景**：调试 TC（流量控制）配置，分析流量分类和整形行为
  - **收集数据**：TC 动作、分类结果、队列统计

### 3.7 边界检测模块 (`boundary-detection/`)

**模块概述**：该模块提供网络路径边界丢包检测工具，通过在网络路径的关键边界点（物理网卡、内核协议栈入口/出口）设置 eBPF 探针，追踪数据包是否通过每个边界。通过对比相邻边界的包计数来快速定位丢包发生的区间。分为系统级（system-network）和虚拟机级（vm-network）两个子类，分别适用于主机端点场景和虚拟化网络转发路径场景。

#### 系统级边界检测 (`system-network/`)

- **system_icmp_path_tracer.py** [Path Tracer]

  - **使用场景**：检测系统网络中 ICMP 数据包在物理网卡与协议栈之间的丢包位置，支持 RX 模式（本机回复远端 ping）和 TX 模式（本机发起 ping）
  - **监控阶段**：4 阶段：ReqRX@phy → ReqRcv@stack → RepSnd@stack → RepTX@phy
  - **收集数据**：每个边界的包计数、请求/响应匹配统计、丢包区间定位
  - **参数**：`--src-ip`/`--dst-ip`（必填）ICMP 请求的源/目标 IP，`--phy-iface`（必填）物理接口（逗号分隔支持 bond），`--direction` (rx/tx，默认 rx)，`--timeout-ms` 超时（默认 1000ms），`--verbose` 输出所有流事件
- **system_tcp_path_tracer.py** [Path Tracer]

  - **使用场景**：检测系统网络中 TCP 数据包在物理网卡与协议栈之间的丢包位置
  - **监控阶段**：4 阶段双向：RX@phy → tcp_v4_rcv → __ip_queue_xmit → TX@phy
  - **收集数据**：每个边界的包计数、TCP 序列号匹配、21-bucket 延迟直方图
  - **参数**：`--src-ip`/`--dst-ip`（必填），`--phy-iface`（必填），`--port` 本地服务端口过滤（默认 0=全部），`--timeout-ms`，`--verbose` per-packet 输出模式，`--stats-interval` 统计间隔（默认 10 秒）
- **system_udp_path_tracer.py** [Path Tracer]

  - **使用场景**：检测系统网络中 UDP 数据包在物理网卡与协议栈之间的丢包位置，支持 IP 分片处理
  - **监控阶段**：4 阶段：RX@phy → __udp4_lib_rcv → ip_send_skb → TX@phy
  - **收集数据**：每个边界的包计数、IP 分片的 port_map 关联、丢包区间定位
  - **参数**：`--src-ip`/`--dst-ip`（必填），`--phy-iface`（必填），`--port` 本地服务端口过滤，`--timeout-ms`，`--verbose`，`--stats-interval`
  - **特点**：通过 port_map 处理 IP 分片场景下非首片的端口信息丢失问题

#### 虚拟机级边界检测 (`vm-network/`)

- **icmp_path_tracer.py** [Path Tracer]

  - **使用场景**：追踪虚拟机环境中 ICMP 数据包在两个网络接口（如物理网卡和虚拟接口）之间的路径，定位转发路径上的丢包边界
  - **监控阶段**：4 阶段路径跟踪（ReqRX → ReqTX → RepRX → RepTX），支持请求/响应关联
  - **收集数据**：每个接口的包计数、请求/响应匹配、丢包区间（内部 vs 外部）
  - **参数**：`--src-ip`/`--dst-ip`（必填），`--rx-iface`（必填）请求接收接口（逗号分隔），`--tx-iface`（必填）请求发送接口（逗号分隔），`--timeout-ms`，`--verbose`
  - **特点**：支持 bond 接口和多 slave 网卡（每方向最多 8 个接口）
- **tcp_path_tracer.py** [Path Tracer]

  - **使用场景**：追踪虚拟机环境中 TCP 数据包在两个网络接口之间的路径，使用 TCP 序列号精确标识数据包
  - **收集数据**：TCP 序列号标识的包跟踪、每接口包计数、双向流跟踪
  - **参数**：`--src-ip`/`--dst-ip`（必填），`--rx-iface`/`--tx-iface`（必填），`--src-port`/`--dst-port` 端口过滤，`--timeout-ms`，`--verbose` per-packet 输出，`--stats-mode` 定期汇总模式，`--stats-interval`
  - **特点**：假定启用 TSO/GRO（TCP 无 IP 分片），`--verbose` 与 `--stats-mode` 互斥
- **udp_path_tracer.py** [Path Tracer]

  - **使用场景**：追踪虚拟机环境中 UDP 数据包路径，支持 IP 分片组跟踪（按 IP ID 分组），需在源和目标宿主机同时部署
  - **收集数据**：分片组完整跟踪、每阶段分片计数、丢包区间
  - **参数**：`--src-ip`/`--dst-ip`（必填），`--rx-iface`/`--tx-iface`（必填），`--src-port`/`--dst-port`，`--timeout-ms`，`--verbose`，`--stats-mode`，`--stats-interval`
  - **特点**：IP 分片组完整跟踪（通过 IP ID 关联），需要双端部署以完整覆盖转发路径

## 4. 工具使用指南

### 4.1 基本使用模式

**Python BCC 工具通用使用模式：**

```bash
sudo python3 <工具路径> [选项]
```

**Bpftrace 脚本通用使用模式：**

```bash
sudo bpftrace <脚本路径> [参数]
```

**注意事项：**

- 所有工具需要 root 权限执行
- 建议先在开发环境测试
- 推荐使用 Python 3（部分工具兼容 Python 2）
- 工具运行时会对系统性能产生一定影响

### 4.2 性能监控模块 (Performance)

#### 4.2.1 通用参数说明

**网络层过滤参数：**

- `--src-ip IP_ADDRESS`：源 IP 地址过滤器
- `--dst-ip IP_ADDRESS`：目标 IP 地址过滤器
- `--src-port PORT`：源端口过滤器（TCP/UDP）
- `--dst-port PORT`：目标端口过滤器（TCP/UDP）
- `--protocol PROTOCOL`：协议过滤器（tcp、udp、icmp、all）

**接口参数：**

- `--vm-interface INTERFACE`：虚拟机接口（如 tap0、vnet0）
- `--phy-interface INTERFACE`：物理接口（如 eth0、ens3）
- `--internal-interface INTERFACE`：内部接口（用于系统级工具）

**方向和行为控制：**

- `--direction DIRECTION`：数据方向（rx、tx、both）
- `--enable-ct`：启用连接跟踪
- `--verbose`：详细输出模式

#### 4.2.2 系统网络性能工具

**system_network_latency_summary.py** - 系统网络延迟直方图 [Summary 版本]

```bash
# 系统网络端到端延迟直方图统计（默认总延迟模式，低开销）
sudo python3 measurement-tools/performance/system-network/system_network_latency_summary.py \
  --phy-interface ens11 --src-ip 10.132.114.11 --dst-ip 10.132.114.12 \
  --direction rx --protocol tcp --interval 5

# 开启逐阶段延迟分解（较高开销，约 10 个探针）
sudo python3 measurement-tools/performance/system-network/system_network_latency_summary.py \
  --phy-interface ens11 --src-ip 10.132.114.11 --dst-ip 10.132.114.12 \
  --direction rx --protocol tcp --interval 5 --stage-latency

# 按平均延迟排序 Top 20 流
sudo python3 measurement-tools/performance/system-network/system_network_latency_summary.py \
  --phy-interface ens11 --protocol all --direction tx --interval 10 --sort-by avg --top 20
```

**system_network_latency_details.py** - 系统网络延迟详细分析 [Details 版本]

```bash
# 详细 per-packet 延迟分析
sudo python3 measurement-tools/performance/system-network/system_network_latency_details.py \
  --phy-interface ens11 --src-ip 10.132.114.12 --dst-ip 10.132.114.11 \
  --direction rx --protocol tcp

# 双向延迟监控
sudo python3 measurement-tools/performance/system-network/system_network_latency_details.py \
  --phy-interface eth0 --src-ip 192.168.1.100 --dst-ip 192.168.1.200 \
  --direction both --protocol udp
```

**system_network_perfomance_metrics.py** - 系统网络性能指标

```bash
# 监控系统网络性能指标
sudo python3 measurement-tools/performance/system-network/system_network_perfomance_metrics.py \
  --internal-interface port-storage --phy-interface ens11 \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 \
  --direction rx --protocol tcp

# 启用连接跟踪的性能监控
sudo python3 measurement-tools/performance/system-network/system_network_perfomance_metrics.py \
  --internal-interface br0 --phy-interface eth0 \
  --enable-ct --verbose
```

**system_network_icmp_rtt.py** - ICMP RTT 测量

```bash
# ICMP 往返时间测量
sudo python3 measurement-tools/performance/system-network/system_network_icmp_rtt.py \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 \
  --direction tx --phy-interface ens11
```

**kernel_icmp_rtt.py** - 内核级 ICMP RTT 测量

```bash
# TX 模式 - 本机发起 ping，测量内核栈延迟
sudo python3 measurement-tools/performance/system-network/kernel_icmp_rtt.py \
  --interface ens4 --direction tx

# RX 模式 - 远端 ping 本机，测量接收路径延迟
sudo python3 measurement-tools/performance/system-network/kernel_icmp_rtt.py \
  --interface ens4 --direction rx

# Bond 接口场景（逗号分隔多 slave）
sudo python3 measurement-tools/performance/system-network/kernel_icmp_rtt.py \
  --interface ens4f0,ens4f1 --direction tx --disable-kernel-stacks
```

**deploy_full_mesh_icmp_tracer.py** - 集群全网格 ICMP 部署

```bash
# 预览全网格部署命令（dry-run）
sudo python3 measurement-tools/performance/system-network/deploy_full_mesh_icmp_tracer.py \
  --nodes 10.132.114.11,10.132.114.12,10.132.114.13 --dry-run

# 实际部署全网格 ICMP 追踪
sudo python3 measurement-tools/performance/system-network/deploy_full_mesh_icmp_tracer.py \
  --nodes 10.132.114.11,10.132.114.12,10.132.114.13 --user smartx --network-type storage

# 检查追踪器状态
sudo python3 measurement-tools/performance/system-network/deploy_full_mesh_icmp_tracer.py \
  --nodes 10.132.114.11,10.132.114.12,10.132.114.13 --status

# 停止所有追踪器
sudo python3 measurement-tools/performance/system-network/deploy_full_mesh_icmp_tracer.py \
  --nodes 10.132.114.11,10.132.114.12,10.132.114.13 --stop
```

#### 4.2.2a OVS 内部端口延迟分析工具

**enqueue_to_iprec_latency_summary.py** - OVS 内部端口 RX 延迟

```bash
# OVS 内部端口 enqueue 到 ip_rcv 延迟统计
sudo python3 measurement-tools/performance/system-network/ovs-internal-port/enqueue_to_iprec_latency_summary.py \
  --interface br-int --interval 5

# 带流过滤和高延迟阈值
sudo python3 measurement-tools/performance/system-network/ovs-internal-port/enqueue_to_iprec_latency_summary.py \
  --interface br-int --protocol tcp --src-ip 192.168.1.100 --threshold 100 --interval 5
```

**enqueue_to_iprec_latency_threshold.py** - 延迟阈值栈跟踪

```bash
# 超过 1ms 时捕获内核栈跟踪
sudo python3 measurement-tools/performance/system-network/ovs-internal-port/enqueue_to_iprec_latency_threshold.py \
  --interface br-int --threshold-us 1000

# 指定协议和 IP 过滤
sudo python3 measurement-tools/performance/system-network/ovs-internal-port/enqueue_to_iprec_latency_threshold.py \
  --interface enp24s0f0np0 --protocol tcp --src-ip 10.0.0.1 --threshold-us 500
```

#### 4.2.2b TCP 性能分析工具

**tcp_rtt_inflight_summary.py** - TCP RTT/inflight/cwnd 三重直方图

```bash
# 基本 TCP 性能直方图（每秒输出）
sudo python3 measurement-tools/performance/system-network/tcp-perf/tcp_rtt_inflight_summary.py \
  --interval 1

# 带 IP/端口过滤和带宽直方图
sudo python3 measurement-tools/performance/system-network/tcp-perf/tcp_rtt_inflight_summary.py \
  --laddr 10.132.114.11 --raddr 10.132.114.12 --rport 5201 --interval 5 --bw-hist

# 高流量场景降低采样率
sudo python3 measurement-tools/performance/system-network/tcp-perf/tcp_rtt_inflight_summary.py \
  --sample-rate 10 --interval 5
```

**syscall_recv_latency_summary.py** - recv 系统调用延迟

```bash
# 按进程名监控
sudo python3 measurement-tools/performance/system-network/tcp-perf/syscall_recv_latency_summary.py \
  --process iperf3 --interval 5

# 按 PID 监控，设置高延迟阈值
sudo python3 measurement-tools/performance/system-network/tcp-perf/syscall_recv_latency_summary.py \
  --pid 12345 --interval 5 --high-latency-threshold 1000
```

**tcp_connection_analyzer.py** - TCP 连接综合分析

```bash
# 作为服务端分析连接
sudo python3 measurement-tools/performance/system-network/tcp-perf/tcp_connection_analyzer.py \
  --role server --local-port 5201 --show-analysis

# 作为客户端分析，指定目标带宽
sudo python3 measurement-tools/performance/system-network/tcp-perf/tcp_connection_analyzer.py \
  --role client --remote-ip 10.132.114.12 --remote-port 5201 --target-bandwidth 25 --show-analysis

# 持续监控模式（每 5 秒输出）
sudo python3 measurement-tools/performance/system-network/tcp-perf/tcp_connection_analyzer.py \
  --role server --local-port 5201 --interval 5 --show-analysis
```

#### 4.2.3 虚拟机网络性能工具

**vm_network_latency_summary.py** - VM 网络延迟直方图 [Summary 版本]

```bash
# VM 网络端到端延迟直方图统计（默认总延迟模式，低开销）
sudo python3 measurement-tools/performance/vm-network/vm_network_latency_summary.py \
  --vm-interface vnet0 --phy-interface ens4 \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \
  --direction rx --protocol tcp --interval 5

# 开启逐阶段延迟分解
sudo python3 measurement-tools/performance/vm-network/vm_network_latency_summary.py \
  --vm-interface vnet0 --phy-interface ens4 \
  --direction rx --protocol tcp --interval 5 --stage-latency

# 按 P99 排序 Top 20 流，指定 VM IP
sudo python3 measurement-tools/performance/vm-network/vm_network_latency_summary.py \
  --vm-interface vnet0 --phy-interface ens4 --vm-ip 172.21.153.113 \
  --direction rx --protocol tcp --interval 5 --sort-by p99 --top 20
```

**vm_network_latency_details.py** - VM 网络延迟详细分析 [Details 版本]

```bash
# 虚拟机延迟 per-packet 详细分解
sudo python3 measurement-tools/performance/vm-network/vm_network_latency_details.py \
  --vm-interface vnet0 --phy-interface ens4 \
  --src-ip 172.21.153.114 --dst-ip 172.21.153.113 \
  --direction tx --protocol udp
```

**vm_network_performance_metrics.py** - 虚拟机网络性能指标

```bash
# 虚拟机网络性能监控
sudo python3 measurement-tools/performance/vm-network/vm_network_performance_metrics.py \
  --vm-interface vnet0 --phy-interface ens4 \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \
  --direction rx --protocol tcp
```

### 4.3 Linux 网络栈模块 (Linux Network Stack)

#### 4.3.1 通用参数说明

**五元组过滤参数：**

- `--src-ip IP_ADDRESS`：源 IP 过滤器
- `--dst-ip IP_ADDRESS`：目标 IP 过滤器
- `--src-port PORT`：源端口过滤器
- `--dst-port PORT`：目标端口过滤器
- `--protocol PROTOCOL`：协议过滤器（tcp、udp、icmp、all）

**丢包监控特定参数：**

- `--type PROTOCOL_TYPE`：协议类型（arp、rarp、ipv4、ipv6、lldp、flow_control、other、all）
- `--l4-protocol PROTOCOL`：L4 协议过滤器
- `--vlan-id VLAN_ID`：VLAN ID 过滤器
- `--interface DEVICE`：网络接口过滤器

**输出控制参数：**

- `--verbose`：详细输出
- `--no-stack-trace`：禁用栈跟踪
- `--disable-normal-filter`：显示正常的 kfree 模式
- `--interval SECONDS`：报告间隔（默认：10）
- `--duration SECONDS`：总监控时长
- `--top NUMBER`：显示前 N 个栈（默认：5）

#### 4.3.2 丢包监控工具

**eth_drop.py** - 以太网层丢包监控

```bash
# 基本以太网丢包监控
sudo python3 measurement-tools/linux-network-stack/packet-drop/eth_drop.py \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 --l4-protocol tcp

# 指定接口和协议类型的丢包监控
sudo python3 measurement-tools/linux-network-stack/packet-drop/eth_drop.py \
  --type ipv4 --src-ip 192.168.1.100 --dst-port 80 \
  --interface eth0 --verbose

# 按 L4 协议过滤（仅 ICMP 丢包）
sudo python3 measurement-tools/linux-network-stack/packet-drop/eth_drop.py \
  --interface ens4 --type ipv4 --l4-protocol icmp

# 关闭正常丢包模式过滤，查看所有 kfree_skb 事件
sudo python3 measurement-tools/linux-network-stack/packet-drop/eth_drop.py \
  --interface ens4 --disable-normal-filter
```

**kernel_drop_stack_stats_summary_all.py** - 内核丢包栈统计

```bash
# 内核丢包栈统计分析
sudo python3 measurement-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats_summary_all.py \
  --src-ip 10.132.114.12 --dst-ip 10.132.114.11 --l4-protocol tcp

# 详细栈统计（指定设备和时间间隔）
sudo python3 measurement-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats_summary_all.py \
  --interval 5 --duration 60 --top 10 \
  --device br-int --src-ip 10.0.0.100 --l4-protocol tcp
```

**qdisc_drop_trace.py** - 队列规则丢包跟踪 (仅 kernel 4.19)

```bash
# 队列规则丢包监控
sudo python3 measurement-tools/linux-network-stack/packet-drop/qdisc_drop_trace.py

# 仅显示丢弃的数据包
sudo python3 measurement-tools/linux-network-stack/packet-drop/qdisc_drop_trace.py \
  --interface ens4 --drops-only

# 高流量场景仅输出汇总统计
sudo python3 measurement-tools/linux-network-stack/packet-drop/qdisc_drop_trace.py \
  --interface ens4 --summary
```

#### 4.3.3 连接跟踪和分片工具

**trace_conntrack.py** - 连接跟踪监控

```bash
# 基本连接跟踪
sudo python3 measurement-tools/linux-network-stack/trace_conntrack.py \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 --protocol tcp

# 相对时间显示的连接跟踪
sudo python3 measurement-tools/linux-network-stack/trace_conntrack.py \
  --src-ip 192.168.1.100 --protocol tcp --rel-time

# 使用过滤器文件的多过滤器连接跟踪
sudo python3 measurement-tools/linux-network-stack/trace_conntrack.py \
  --filters-file /path/to/filters.json --stack true
```

**trace_ip_defrag.py** - IP 分片重组跟踪

```bash
# IP 分片重组监控
sudo python3 measurement-tools/linux-network-stack/trace_ip_defrag.py \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 --protocol udp

# 带日志记录的 IP 分片监控
sudo python3 measurement-tools/linux-network-stack/trace_ip_defrag.py \
  --src-ip 192.168.1.100 --protocol udp --log-file /tmp/defrag.log
```

### 4.4 Open vSwitch 模块 (OVS)

#### 4.4.1 通用参数说明

**网络过滤参数：**

- `--src-ip IP_ADDRESS`：源 IP 过滤器
- `--dst-ip IP_ADDRESS`：目标 IP 过滤器
- `--src-port PORT`：源端口过滤器
- `--dst-port PORT`：目标端口过滤器
- `--protocol PROTOCOL`：协议过滤器

**OVS 特定参数：**

- `--interval SECONDS`：直方图报告间隔

**Megaflow 特定参数：**

- `--eth-src MAC_ADDRESS`：源 MAC 地址过滤器
- `--eth-dst MAC_ADDRESS`：目标 MAC 地址过滤器
- `--eth-type ETHERTYPE`：以太网类型过滤器
- `--ip-proto PROTOCOL`：IP 协议号
- `--l4-src-port PORT`：L4 源端口
- `--l4-dst-port PORT`：L4 目标端口

#### 4.4.2 OVS 工具使用

**ovs_upcall_latency_summary.py** - OVS Upcall 延迟分析 [Summary 版本]

```bash
# OVS upcall 延迟直方图统计 (注意: 使用 --proto 而非 --protocol)
sudo python3 measurement-tools/ovs/ovs_upcall_latency_summary.py \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 --proto tcp

# 指定报告间隔的 upcall 延迟监控
sudo python3 measurement-tools/ovs/ovs_upcall_latency_summary.py \
  --src-ip 192.168.76.198 --proto tcp --interval 5

# 监控所有协议的 upcall 延迟
sudo python3 measurement-tools/ovs/ovs_upcall_latency_summary.py \
  --proto all --interval 10
```

**参数说明:**

- `--src-ip IP`: 源 IP 过滤器
- `--dst-ip IP`: 目标 IP 过滤器
- `--proto PROTOCOL`: 协议过滤器 (tcp/udp/all) **注意:是 --proto 不是 --protocol**
- `--interval SECONDS`: 统计间隔 (默认 5)

**ovs_userspace_megaflow.py** - OVS 用户空间 Megaflow 跟踪

```bash
# 基本 megaflow 跟踪
sudo python3 measurement-tools/ovs/ovs_userspace_megaflow.py \
  --src-ip 172.21.153.114 --dst-ip 172.21.153.113 --protocol tcp

# 综合过滤的 megaflow 跟踪
sudo python3 measurement-tools/ovs/ovs_userspace_megaflow.py \
  --eth-src 00:11:22:33:44:55 --src-ip 10.0.0.100 \
  --l4-src-port 80 --ip-proto 6
```

**ovs-kernel-module-drop-monitor.py** - OVS 内核模块丢包监控

```bash
# OVS 内核丢包监控
sudo python3 measurement-tools/ovs/ovs-kernel-module-drop-monitor.py \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 --protocol udp
```

### 4.5 KVM 虚拟化网络模块 (KVM Virt Network)

#### 4.5.1 通用参数说明

**基本监控参数：**

- `--interval SECONDS`：输出间隔（默认：1）
- `--clear`：输出后清空计数器
- `--device DEVICE_NAME`：设备名称过滤器
- `--queue-id ID`：特定队列 ID
- `--threshold VALUE`：各种阈值参数

**TUN/TAP 特定参数：**

- `--tun-device DEVICE`：TUN 设备名称
- `--ring-size SIZE`：环形缓冲区大小

#### 4.5.2 vhost-net 工具

**vhost_eventfd_count.py** - vhost eventfd 监控

```bash
# 监控 vhost eventfd 信号
sudo python3 measurement-tools/kvm-virt-network/vhost-net/vhost_eventfd_count.py \
  --interval 5 --clear
```

**vhost_queue_correlation_details.py** - vhost 队列关联分析

```bash
# 详细 vhost 队列关联分析
sudo python3 measurement-tools/kvm-virt-network/vhost-net/vhost_queue_correlation_details.py \
  --device vhost-1 --interval 2
```

**vhost_buf_peek_stats.py** - vhost 缓冲区 peek 统计

```bash
# vhost 缓冲区 peek 操作监控
sudo python3 measurement-tools/kvm-virt-network/vhost-net/vhost_buf_peek_stats.py \
  --interval 1
```

#### 4.5.3 TUN/TAP 工具

**tun_ring_monitor.py** - TUN 环形缓冲区监控

```bash
# TUN 设备环形缓冲区监控
sudo python3 measurement-tools/kvm-virt-network/tun/tun_ring_monitor.py \
  --device tun0 --interval 1
```

**tun_to_vhost_queue_stats_full_summary.py** - TUN 到 vhost 队列完整统计 [Summary 版本]

```bash
# TUN 到 vhost 队列完整统计（基于 histogram 聚合）
sudo python3 measurement-tools/kvm-virt-network/tun/tun_to_vhost_queue_stats_full_summary.py \
  --device tap0 --interval 3
```

**tun_to_vhost_queue_status_simple_summary.py** - TUN 到 vhost 队列简化统计 [Summary 版本]

```bash
# TUN 到 vhost 队列简化统计
sudo python3 measurement-tools/kvm-virt-network/tun/tun_to_vhost_queue_status_simple_summary.py \
  --device tap0 --interval 5
```

#### 4.5.4 virtio-net 工具

**virtnet_poll_monitor.py** - virtio-net NAPI 轮询监控

```bash
# virtio-net NAPI 轮询效率监控
sudo python3 measurement-tools/kvm-virt-network/virtio-net/virtnet_poll_monitor.py \
  --interval 2
```

**virtnet_irq_monitor.py** - virtio-net 中断监控

```bash
# virtio-net 中断合并监控
sudo python3 measurement-tools/kvm-virt-network/virtio-net/virtnet_irq_monitor.py \
  --interval 1 --device virtio0
```

#### 4.5.5 KVM IRQ 工具

**kvm_irqfd_stats_summary.py** - KVM 中断注入统计 [Summary 版本]

```bash
# KVM 中断注入性能监控 (qemu_pid 是位置参数，必须提供)
sudo python3 measurement-tools/kvm-virt-network/kvm/kvm_irqfd_stats_summary.py \
  12345 --interval 5

# 监控特定 QEMU 进程的中断统计
sudo python3 measurement-tools/kvm-virt-network/kvm/kvm_irqfd_stats_summary.py \
  $(pgrep -f "qemu.*vm-name") --interval 5

# 仅监控数据平面中断 (vhost 线程)
sudo python3 measurement-tools/kvm-virt-network/kvm/kvm_irqfd_stats_summary.py \
  12345 --category data --interval 3

# 监控特定 vhost 线程的中断
sudo python3 measurement-tools/kvm-virt-network/kvm/kvm_irqfd_stats_summary.py \
  12345 --category data --vhost-pid 12400 --interval 5
```

**参数说明:**

- `qemu_pid`: QEMU 进程 PID（位置参数，必需）
- `--interval SECONDS`: 统计输出间隔（默认 5 秒）
- `--vhost-pid PID`: 过滤特定 vhost 线程（仅当 --category=data 时有效）
- `--category {data,control}`: 中断类别过滤（data=vhost 线程，control=QEMU 进程）
- `--subcategory {rx,tx}`: 子类别过滤（仅当 --category=data 时有效）

#### 4.5.5 KVM TX 延迟和中断链工具

**kvm_vhost_tun_latency_no_discovery_details.py** - KVM 主机侧 TX 延迟

```bash
# 测量指定设备的 TX 延迟（自动检测 QEMU PID）
sudo python3 measurement-tools/kvm-virt-network/kvm/kvm_vhost_tun_latency_no_discovery_details.py \
  --device vnet94

# 指定 QEMU PID 和流过滤
sudo python3 measurement-tools/kvm-virt-network/kvm/kvm_vhost_tun_latency_no_discovery_details.py \
  --device vnet94 --qemu-pid 12345 --flow "proto=tcp,dst=192.168.1.100,dport=5201"

# 仅统计模式（不输出 per-packet 详情）
sudo python3 measurement-tools/kvm-virt-network/kvm/kvm_vhost_tun_latency_no_discovery_details.py \
  --device vnet0 --no-detail --duration 60
```

**tun_tx_to_kvm_irq.py** - TUN TX 中断链跟踪

```bash
# 跟踪指定设备的完整中断链
sudo python3 measurement-tools/kvm-virt-network/tun/tun_tx_to_kvm_irq.py \
  --device vnet0 --stats-interval 10

# 带协议和 IP 过滤
sudo python3 measurement-tools/kvm-virt-network/tun/tun_tx_to_kvm_irq.py \
  --device vnet0 --protocol tcp --dst-ip 192.168.1.100 --dst-port 5201

# 启用中断链分析
sudo python3 measurement-tools/kvm-virt-network/tun/tun_tx_to_kvm_irq.py \
  --device vnet0 --analyze-chains --stats-interval 5
```

### 4.6 Bpftrace 脚本工具

#### 4.6.1 网络异常检测脚本

```bash
# 跟踪异常 ARP 数据包
sudo bpftrace measurement-tools/other/trace-abnormal-arp.bt

# 监控 OVS 连接跟踪无效状态
sudo bpftrace measurement-tools/other/trace-ovs-ct-invalid.bt

# 跟踪卸载分段问题
sudo bpftrace measurement-tools/other/trace_offloading_segment.bt
```

#### 4.6.2 virtio-net 路径监控脚本

```bash
# virtio-net RX 路径详细监控
sudo bpftrace measurement-tools/kvm-virt-network/virtio-net/virtionet-rx-path-monitor.bt

# virtio-net RX 路径汇总统计
sudo bpftrace measurement-tools/kvm-virt-network/virtio-net/virtionet-rx-path-summary.bt

# 跟踪 virtio-net 接收缓冲区
sudo bpftrace measurement-tools/kvm-virt-network/virtio-net/trace_virtio_net_rcvbuf.bt
```

#### 4.6.3 TUN/TAP 监控脚本

```bash
# TUN 异常 GSO 类型检测
sudo bpftrace measurement-tools/kvm-virt-network/tun/tun-abnormal-gso-type.bt

# TUN TX 环形缓冲区统计
sudo bpftrace measurement-tools/kvm-virt-network/tun/tun-tx-ring-stas.bt
```

#### 4.6.4 内核丢包分析脚本

```bash
# 实时内核丢包栈跟踪
sudo bpftrace measurement-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats.bt

# 队列规则出队操作跟踪
sudo bpftrace measurement-tools/other/trace-qdisc-dequeue.bt

# 设备队列传输跟踪
sudo bpftrace measurement-tools/other/trace_dev_queue_xmit.bt
```

### 4.7 CPU 和调度器监控脚本

```bash
# 综合 CPU 监控
sudo ./measurement-tools/cpu/cpu_monitor.sh

# 调度器延迟分析
sudo ./measurement-tools/cpu/sched_latency_monitor.sh --interval 1 --duration 60

# off-CPU 时间分析
sudo python3 measurement-tools/cpu/offcputime-ts.py
```

### 4.8 参数模式总结

#### 4.8.1 通用参数（大多数工具支持）

```bash
--src-ip IP_ADDRESS        # 源 IP 过滤器
--dst-ip IP_ADDRESS        # 目标 IP 过滤器
--src-port PORT           # 源端口过滤器
--dst-port PORT           # 目标端口过滤器
--protocol PROTOCOL       # 协议过滤器（tcp/udp/icmp/all）
--verbose                 # 详细输出模式
--interval SECONDS        # 报告间隔
--duration SECONDS        # 总监控时长
```

#### 4.8.2 主题特定参数

| 主题                  | 特有参数                                                                                                                                          |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Performance** | `--vm-interface`, `--phy-interface`, `--internal-interface`, `--direction`, `--enable-ct`, `--vm-ip`, `--threshold`, `--interval` |
| **Linux Stack** | `--type`, `--l4-protocol`, `--vlan-id`, `--rel-time`, `--filters-file`, `--stack`, `--log-file`, `--device`, `--top`            |
| **OVS**         | `--eth-src`, `--eth-dst`, `--eth-type`, `--ip-proto`, `--proto` (注意不是 --protocol), `--interval`                                   |
| **KVM Virt**    | `--device`, `--queue-id`, `--clear`, `--tun-device`, `--ring-size`, `qemu_pid` (KVM IRQ 位置参数,必需), `--category`, `--vhost-pid`  |

#### 4.8.3 输出控制参数

```bash
--verbose                 # 详细输出模式
--interval SECONDS        # 报告间隔
--duration SECONDS        # 总监控时长
--log-file FILE          # 输出到日志文件
--no-stack-trace         # 禁用栈跟踪
--clear                  # 清空计数器（部分工具）
--top NUMBER             # 显示前 N 项（统计工具）
--stage-latency          # 开启逐阶段延迟分解（latency summary 工具）
--sort-by METRIC         # 排序 per-flow 统计（count/avg/p90/p99）
--l4-protocol PROTO      # L4 协议过滤（icmp/tcp/udp/all，丢包工具）
--drops-only             # 仅显示丢弃的数据包（qdisc_drop_trace）
--disable-normal-filter  # 关闭正常丢包过滤（eth_drop）
--vm-ip IP               # VM IP 地址过滤（vm_network_latency_summary）
```

### 4.9 边界检测模块 (Boundary Detection)

边界检测工具通过在网络路径关键点设置 eBPF 探针，快速定位丢包发生的区间。工具分为系统级（主机端点场景）和虚拟机级（转发路径场景）两类。

#### 4.9.1 系统级边界检测

**system_icmp_path_tracer.py** - 系统 ICMP 路径追踪

```bash
# RX 模式 - 远端 ping 本机，检测回复路径丢包
sudo python3 measurement-tools/boundary-detection/system-network/system_icmp_path_tracer.py \
  --src-ip 10.132.114.12 --dst-ip 10.132.114.11 --phy-iface ens4 --direction rx

# TX 模式 - 本机发起 ping，检测发送路径丢包
sudo python3 measurement-tools/boundary-detection/system-network/system_icmp_path_tracer.py \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 --phy-iface ens4 --direction tx

# Bond 接口（逗号分隔多 slave），verbose 输出
sudo python3 measurement-tools/boundary-detection/system-network/system_icmp_path_tracer.py \
  --src-ip 10.132.114.12 --dst-ip 10.132.114.11 --phy-iface ens4f0,ens4f1 --direction rx --verbose
```

**system_tcp_path_tracer.py** - 系统 TCP 路径追踪

```bash
# 基本 TCP 边界检测（stats 模式，每 10 秒输出）
sudo python3 measurement-tools/boundary-detection/system-network/system_tcp_path_tracer.py \
  --src-ip 10.132.114.12 --dst-ip 10.132.114.11 --phy-iface ens4

# 指定端口过滤和 verbose per-packet 输出
sudo python3 measurement-tools/boundary-detection/system-network/system_tcp_path_tracer.py \
  --src-ip 10.132.114.12 --dst-ip 10.132.114.11 --phy-iface ens4 --port 5201 --verbose
```

**system_udp_path_tracer.py** - 系统 UDP 路径追踪（含分片处理）

```bash
# 基本 UDP 边界检测
sudo python3 measurement-tools/boundary-detection/system-network/system_udp_path_tracer.py \
  --src-ip 10.132.114.12 --dst-ip 10.132.114.11 --phy-iface ens4

# 指定端口和统计间隔
sudo python3 measurement-tools/boundary-detection/system-network/system_udp_path_tracer.py \
  --src-ip 10.132.114.12 --dst-ip 10.132.114.11 --phy-iface ens4 --port 4789 --stats-interval 5
```

#### 4.9.2 虚拟机级边界检测

**icmp_path_tracer.py** - VM ICMP 路径追踪

```bash
# 追踪 ICMP 包在两个接口之间的路径
sudo python3 measurement-tools/boundary-detection/vm-network/icmp_path_tracer.py \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \
  --rx-iface ens4 --tx-iface vnet0

# Bond 接口场景
sudo python3 measurement-tools/boundary-detection/vm-network/icmp_path_tracer.py \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \
  --rx-iface ens4f0,ens4f1 --tx-iface vnet0 --verbose
```

**tcp_path_tracer.py** - VM TCP 路径追踪

```bash
# TCP 边界检测（stats 模式）
sudo python3 measurement-tools/boundary-detection/vm-network/tcp_path_tracer.py \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \
  --rx-iface ens4 --tx-iface vnet0 --stats-mode --stats-interval 10

# 带端口过滤的 verbose 模式
sudo python3 measurement-tools/boundary-detection/vm-network/tcp_path_tracer.py \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \
  --rx-iface ens4 --tx-iface vnet0 --dst-port 5201 --verbose
```

**udp_path_tracer.py** - VM UDP 路径追踪（需双端部署）

```bash
# UDP 边界检测（含分片组跟踪）
sudo python3 measurement-tools/boundary-detection/vm-network/udp_path_tracer.py \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \
  --rx-iface ens4 --tx-iface vnet0 --stats-mode --stats-interval 10

# 带端口过滤
sudo python3 measurement-tools/boundary-detection/vm-network/udp_path_tracer.py \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \
  --rx-iface ens4 --tx-iface vnet0 --dst-port 4789 --verbose
```

## 5. 输出数据格式详解

### 5.1 性能监控工具输出格式

#### 5.1.1 Summary 工具输出格式 (直方图统计)

Summary 版本工具使用 BPF_HISTOGRAM 进行内核态聚合统计,输出延迟分布直方图。

**system_network_latency_summary.py 输出格式:**

```
=== System Network Latency Summary Tool ===
Protocol filter: TCP
Direction filter: RX
Source IP filter: 10.132.114.11
Destination IP filter: 10.132.114.12
Physical interface: ens11 (ifindex 2)
Statistics interval: 5 seconds

Tracing system network latency... Hit Ctrl-C to end.

[2025-10-20 14:30:15] === Latency Report (Interval: 5.0s) ===

相邻阶段延迟分布 (Adjacent Stage Latency Distribution):

Stage: INTERNAL_RX → FLOW_EXTRACT_END_RX
     latency (us)    : count    distribution
        0 -> 1       :   156   |**************************        |
        2 -> 3       :   234   |************************************|
        4 -> 7       :   89    |*************                      |
        8 -> 15      :   23    |***                                |
       16 -> 31      :   5     |                                   |
       32 -> 63      :   1     |                                   |

Stage: FLOW_EXTRACT_END_RX → QDISC_ENQ
     latency (us)    : count    distribution
        0 -> 1       :   45    |**************                     |
        2 -> 3       :   123   |**************************************|
        4 -> 7       :   256   |************************************|
        8 -> 15      :   67    |********************               |
       16 -> 31      :   12    |***                                |

Stage: QDISC_ENQ → TX_QUEUE
     latency (us)    : count    distribution
        0 -> 1       :   234   |************************************|
        2 -> 3       :   198   |******************************     |
        4 -> 7       :   45    |******                             |
        8 -> 15      :   8     |*                                  |

Stage: TX_QUEUE → TX_XMIT
     latency (us)    : count    distribution
        0 -> 1       :   412   |************************************|
        2 -> 3       :   76    |******                             |
        4 -> 7       :   12    |*                                  |

Total packets analyzed: 508
```

**vm_network_latency_summary.py 输出格式:**

```
=== VM Network Latency Summary Tool ===
Protocol filter: TCP
Direction filter: RX
Source IP filter: 172.21.153.113
Destination IP filter: 172.21.153.114
VM interface: vnet0 (ifindex 22)
Physical interface: ens4 (ifindex 2)
Statistics interval: 5 seconds

Tracing VM network latency... Hit Ctrl-C to end.

[2025-10-20 14:35:20] === Latency Report (Interval: 5.0s) ===

相邻阶段延迟分布 (Adjacent Stage Latency Distribution):

Stage: VNET_RX → OVS_RX
     latency (us)    : count    distribution
        0 -> 1       :   12    |***                                |
        2 -> 3       :   45    |*************                      |
        4 -> 7       :   123   |************************************|
        8 -> 15      :   89    |**************************         |
       16 -> 31      :   34    |**********                         |
       32 -> 63      :   8     |**                                 |

Stage: OVS_RX → FLOW_EXTRACT_END_RX
     latency (us)    : count    distribution
        0 -> 1       :   23    |*******                            |
        2 -> 3       :   78    |*************************          |
        4 -> 7       :   145   |************************************|
        8 -> 15      :   45    |***********                        |
       16 -> 31      :   12    |***                                |

Stage: FLOW_EXTRACT_END_RX → QDISC_ENQ
     latency (us)    : count    distribution
        0 -> 1       :   56    |******************                 |
        2 -> 3       :   112   |************************************|
        4 -> 7       :   98    |*******************************    |
        8 -> 15      :   34    |***********                        |
       16 -> 31      :   5     |*                                  |

[继续输出后续阶段的直方图...]

Total packets analyzed: 311
```

**Histogram Bucket 说明:**

- Bucket 使用对数刻度: [0-1), [1-2), [2-4), [4-8), [8-16), [16-32), [32-64), ...
- 计算公式: `bucket_id = bpf_log2l(latency_us + 1)`
- 延迟单位: 微秒 (us)
- Distribution 列: ASCII 字符绘制的分布图,最长条对应最大计数

**ovs_upcall_latency_summary.py 输出格式:**

```
=== OVS Upcall Latency Histogram Tool ===
Protocol filter: TCP
Source IP filter: 172.21.153.113
Destination IP filter: 172.21.153.114
Statistics interval: 5 seconds

Collecting OVS upcall latency data... Hit Ctrl-C to end.

[2025-10-20 14:40:30] === Upcall Latency Report (Interval: 5.0s) ===

Upcall Latency Distribution:
     latency (us)    : count    distribution
        0 -> 1       :   5     |**                                 |
        2 -> 3       :   12    |*****                              |
        4 -> 7       :   34    |***************                    |
        8 -> 15      :   67    |******************************     |
       16 -> 31      :   89    |************************************|
       32 -> 63      :   45    |********************               |
       64 -> 127     :   23    |**********                         |
      128 -> 255     :   8     |***                                |
      256 -> 511     :   2     |                                   |

Total upcalls: 285
Average latency: 34.5 us
P50 latency: 28 us
P95 latency: 98 us
P99 latency: 234 us
```

#### 5.1.2 系统网络性能指标输出 (Details 工具)

**system_network_performance_metrics.py 输出格式：**

```
=== System Network Performance Tracer ===
Protocol filter: TCP
Direction filter: RX (1=VNET_RX/VM_TX, 2=VNET_TX/VM_RX)
Source IP filter: 10.132.114.12
Destination IP filter: 10.132.114.11
Internal interface: port-storage (ifindex 15)
Physical interface: ens11 (ifindex 2)
Conntrack measurement: DISABLED

BPF program loaded successfully

Tracing system network performance... Hit Ctrl-C to end.
Format: [YYYY-MM-DD HH:MM:SS.mmm] PKT_ID DIR STAGE DEV KTIME=ns
        FLOW: src -> dst (protocol_identifier)
        QUEUE/CT/QDISC metrics
        Complete flow summary at last stage

[2025-09-22 18:08:45.123] === FLOW COMPLETE: 5 stages captured ===
FLOW: 10.132.114.12 -> 10.132.114.11 (TCP 45678->80 seq=1234567890)
5-TUPLE: 10.132.114.12:45678 -> 10.132.114.11:80 TCP (seq=1234567890) DIR=INTERNAL_RX
  Stage INTERNAL_RX: KTIME=1579019845123456789ns
    SKB: ptr=0xffff888123456789 len=1500 data_len=1448 queue_mapping=2 hash=0x12345678
    DEV: port-storage (ifindex=15) CPU=3
  Stage FLOW_EXTRACT_END_RX: KTIME=1579019845125456789ns (+2.000us)
    SKB: ptr=0xffff888123456789 len=1514 data_len=1448 queue_mapping=2 hash=0x12345678
    DEV: port-storage (ifindex=15) CPU=3
  Stage QDISC_ENQ: KTIME=1579019845128456789ns (+3.000us)
    SKB: ptr=0xffff888123456789 len=1514 data_len=1448 queue_mapping=5 hash=0x87654321
    DEV: ens11 (ifindex=2) CPU=3
  Stage TX_QUEUE: KTIME=1579019845131456789ns (+3.000us)
    SKB: ptr=0xffff888123456789 len=1514 data_len=1448 queue_mapping=5 hash=0x87654321
    DEV: ens11 (ifindex=2) CPU=3
  Stage TX_XMIT: KTIME=1579019845134456789ns (+3.000us)
    SKB: ptr=0xffff888123456789 len=1514 data_len=1448 queue_mapping=5 hash=0x87654321
    DEV: ens11 (ifindex=2) CPU=3
  TOTAL DURATION: 11.000us
  PACKET: len=1500 data_len=1448 queue_mapping=2 skb_hash=0x12345678
  PROCESS: pid=12345 comm=ksoftirqd/3 first_dev=port-storage
  FINAL_STAGE: dev=ens11(ifindex=2) cpu=3
```

**输出字段说明：**

- **FLOW COMPLETE**: 完整数据流跟踪的阶段数
- **5-TUPLE**: 五元组信息（源IP:Port -> 目标IP:Port 协议）
- **Stage**: 数据包在网络栈中的处理阶段
- **KTIME**: 内核时间戳（纳秒）
- **SKB**: socket buffer 信息（指针、长度、数据长度、队列映射、哈希值）
- **DEV**: 网络设备信息（设备名、接口索引、CPU）
- **TOTAL DURATION**: 整个数据流的处理时间

#### 5.1.3 虚拟机网络性能输出

**vm_network_performance_metrics.py 输出格式：**

```
=== VM Network Performance Tracer ===
Protocol filter: TCP
Direction filter: RX (1=VNET_RX/VM_TX, 2=VNET_TX/VM_RX)
Source IP filter: 172.21.153.114
Destination IP filter: 172.21.153.113
VM interface: vnet0 (ifindex 22)
Physical interface: ens4 (ifindex 2)
Conntrack measurement: DISABLED

[2025-09-22 18:25:29.132] === FLOW COMPLETE: 6 stages captured ===
FLOW: 172.21.153.114 -> 172.21.153.113 (TCP 40040->5001 seq=3649330686)
5-TUPLE: 172.21.153.114:40040 -> 172.21.153.113:5001 TCP (seq=3649330686) DIR=VNET_RX
  Stage VNET_RX: KTIME=1579020094156218ns
    SKB: ptr=0xffff888569f5ec00 len=7292 data_len=5784 queue_mapping=1 hash=0x0
    DEV: vnet0 (ifindex=22) CPU=19
  Stage OVS_RX: KTIME=1579020094183298ns (+27.080us)
    SKB: ptr=0xffff888569f5ec00 len=7306 data_len=5784 queue_mapping=1 hash=0x0
    DEV: vnet0 (ifindex=22) CPU=19
  Stage FLOW_EXTRACT_END_RX: KTIME=1579020094189943ns (+6.645us)
    SKB: ptr=0xffff888569f5ec00 len=7306 data_len=5784 queue_mapping=1 hash=0x0
    DEV: vnet0 (ifindex=22) CPU=19
  Stage QDISC_ENQ: KTIME=1579020094201422ns (+11.479us)
    SKB: ptr=0xffff888569f5ec00 len=7306 data_len=5784 queue_mapping=15 hash=0xf3621051
    DEV: ens4 (ifindex=2) CPU=19
  Stage TX_QUEUE: KTIME=1579020094208923ns (+7.501us)
    SKB: ptr=0xffff888569f5ec00 len=7306 data_len=5784 queue_mapping=15 hash=0xf3621051
    DEV: ens4 (ifindex=2) CPU=19
  Stage TX_XMIT: KTIME=1579020094214416ns (+5.493us)
    SKB: ptr=0xffff888569f5ec00 len=7306 data_len=5784 queue_mapping=15 hash=0xf3621051
    DEV: ens4 (ifindex=2) CPU=19
  TOTAL DURATION: 58.198us
  PACKET: len=7292 data_len=5784 queue_mapping=1 skb_hash=0x0
  PROCESS: pid=688598 comm=vhost-688571 first_dev=vnet0
  FINAL_STAGE: dev=ens4(ifindex=2) cpu=19

=== Performance Statistics ===
Event counts by probe point:
  Probe 1: 18 events
  Probe 2: 18 events
  Probe 3: 18 events
  Probe 8: 18 events
  Probe 10: 18 events
  Probe 11: 18 events
```

**虚拟机网络栈阶段说明：**

- **VNET_RX**: 虚拟机网络接口接收阶段
- **OVS_RX**: Open vSwitch 接收处理阶段
- **FLOW_EXTRACT_END_RX**: OVS 流提取结束阶段
- **QDISC_ENQ**: 队列规则入队阶段
- **TX_QUEUE**: 发送队列阶段
- **TX_XMIT**: 物理设备发送阶段

#### 5.1.4 延迟汇总统计输出 (旧版 - 已弃用)

**vm_network_latency_summary.py 输出格式：**

```
=== VM Network Latency Summary Tool ===
Protocol filter: TCP
Direction filter: RX
Source IP filter: 172.21.153.114
Destination IP filter: 172.21.153.113
VM interface: vnet0 (ifindex 22)
Physical interface: ens4 (ifindex 2)

Tracing VM network latency... Hit Ctrl-C to end.
Interval: 5 seconds

[2025-09-22 18:15:30] === Latency Report (Interval: 5.2s) ===
Packets analyzed: 234
Latency distribution:
  - Min: 12.3 us
  - Average: 45.7 us
  - Median (P50): 42.1 us
  - P95: 78.9 us
  - P99: 125.6 us
  - Max: 234.5 us

Stage-wise latency breakdown:
  - VNET_RX to OVS_RX: 15.2 us (33.2%)
  - OVS_RX to FLOW_EXTRACT: 8.3 us (18.2%)
  - FLOW_EXTRACT to QDISC_ENQ: 12.1 us (26.5%)
  - QDISC_ENQ to TX_QUEUE: 5.8 us (12.7%)
  - TX_QUEUE to TX_XMIT: 4.3 us (9.4%)

Flow summary:
  - Total flows: 45
  - Complete flows: 43
  - Incomplete flows: 2

CPU distribution:
  - CPU 13: 156 packets (66.7%)
  - CPU 15: 45 packets (19.2%)
  - CPU 16: 18 packets (7.7%)
  - CPU 19: 15 packets (6.4%)
```

### 5.2 Linux 网络栈监控输出格式

#### 5.2.1 丢包监控输出

**eth_drop.py 输出格式：**

```
--------------------------------------------------------------------------------
Starting packet drop monitoring... Press Ctrl+C to stop
[17:46:56] PID: 0 TGID: 0 COMM: swapper/0 CPU: 0
Ethernet Header:
  Source MAC: 9a:b9:0a:b6:d2:7a
  Dest MAC:   ff:ff:ff:ff:ff:ff
  EtherType:  0x0806
ARP PACKET
ARP Header:
  Hardware Type: 0x0001
  Protocol Type: 0x0800
  Operation:     Request
  Sender MAC:    9a:b9:0a:b6:d2:7a
  Sender IP:     10.42.213.89
  Target MAC:    00:00:00:00:00:00
  Target IP:     10.42.213.91
Interface: ovsbr-bbfi49amm
Stack trace:
  kfree_skb+0x1
  ovs_vport_send+0x9d
  do_output+0x57
  do_execute_actions+0x362
  ovs_execute_actions+0x4f
  ovs_dp_process_packet+0x9d
  ovs_vport_receive+0x76
  netdev_frame_hook+0xc2
  __netif_receive_skb_core+0x225
  __netif_receive_skb_list_core+0x129
  netif_receive_skb_list_internal+0x1f8
  gro_normal_list.part.141+0x1e
  napi_complete_done+0x8a
  virtnet_poll+0x376
  net_rx_action+0x12d
  __softirqentry_text_start+0x91
  irq_exit+0xa3
  do_IRQ+0x59
  ret_from_intr+0x0
  default_idle+0x35
  arch_cpu_idle+0x15
  default_idle_call+0x26
  do_idle+0x1b4
  cpu_startup_entry+0x1d
  rest_init+0xae
  arch_call_rest_init+0xe
  start_kernel+0x4ce
  x86_64_start_reservations+0x24
  x86_64_start_kernel+0xa4
  secondary_startup_64+0xb6
```

**kernel_drop_stack_stats_summary_all.py 输出格式：**

```
 Stack trace failures by device:
    port-storage: 1 failed
  Found 5 unique stack+flow combinations, showing top 5:

  #1 Count: 76 calls [device: port-storage] [stack_id: 2]
     Flow: 10.132.114.12 -> 10.132.114.11 (ICMP)
  Stack trace:
    Stack depth: 21 frames
    kfree_skb+0x1 [kernel]
    ip_protocol_deliver_rcu+0x1a9 [kernel]
    ip_local_deliver_finish+0x48 [kernel]
    ip_local_deliver+0xcd [kernel]
    ip_rcv_finish+0x84 [kernel]
    ... (16 more frames)

  #2 Count: 3 calls [device: port-storage] [stack_id: 344]
     Flow: 10.132.114.12 -> 10.132.114.11 (ICMP)
  Stack trace:
    Stack depth: 21 frames
    kfree_skb+0x1 [kernel]
  ...
```

#### 5.2.2 连接跟踪输出

**trace_conntrack.py 输出格式：**

```
DATETIME: 2025-09-22 17:57:33.760 COMM: swapper/19       FUNC: __nf_ct_refresh_acct      DEV: port-storage[18]
PKTINFO: 10.132.114.12:37323 -> 10.132.114.11:5201 (UDP) IP_ID:0x5013
OVS_CT_INFO: OvsConInfoNFCT:N/A(Init) OvsCommit:N/A(Init) OvsZoneID:N/A(Init) OvsZoneDir:N/A(Init)
SKB_CT_INFO: CT_STATUS:0x18e(NOT_TEMPLATE) CTINFO:0(IP_CT_ESTABLISHED) NFCT_PTR:0xffff88816bac30c0 SKBZoneID:0(KernelDefaultZone) SKBZoneDir:N/A(NoCfg) CT_LABEL:0x00000000000000000000000000000000
  b'__nf_ct_refresh_acct+0x1'
  b'nf_conntrack_in+0x3cd'
  b'ipv4_conntrack_in+0x14'
  b'nf_hook_slow+0x49'
  ...
```

### 5.3 OVS 监控输出格式

#### 5.3.1 OVS Upcall 延迟输出

**ovs_upcall_latency_summary.py 输出格式：**

```
=== OVS Upcall Latency Histogram Tool ===
Protocol filter: TCP
Source IP filter: 172.21.153.113
Destination IP filter: 172.21.153.114
Statistics interval: 5 seconds
BPF program loaded successfully

Collecting OVS upcall latency data... Hit Ctrl-C to end.
Statistics will be displayed every 5 seconds

[2025-09-22 18:10:30] OVS Upcall Latency Report (Interval: 5.0s)
================================================================================
Upcall Statistics:
  Total upcalls: 234
  Completed upcalls: 230
  Pending upcalls: 4

Latency Distribution (microseconds):
     [0, 10)     ████████████████████  56 (24.3%)
    [10, 20)     ██████████████████████████████  78 (33.9%)
    [20, 50)     ████████████████████  67 (29.1%)
    [50, 100)    ██████████  23 (10.0%)
   [100, 200)    ███  5 (2.2%)
   [200, +)      █  1 (0.4%)

Statistics:
  - Min latency: 2.3 us
  - Average latency: 23.4 us
  - Median (P50): 18.7 us
  - P95 latency: 67.8 us
  - P99 latency: 123.4 us
  - Max latency: 234.5 us

Upcall types:
  - MISS: 156 (67.8%)
  - ACTION: 45 (19.6%)
  - SLOW_PATH: 29 (12.6%)

Active upcall sessions: 4

[2025-09-22 18:10:35] OVS Upcall Latency Report (Interval: 5.0s)
...
```

#### 5.3.2 OVS Megaflow 输出

**ovs_userspace_megaflow.py 输出格式：**

```
OVS Megaflow Tracker V8
Filter Configuration:
  IP Source: 172.21.153.113
  IP Destination: 172.21.153.114
  IP Protocol: TCP (6)
Filter mode: only showing matching events

Attached to ovs_dp_upcall
Starting monitoring...

[18:25:30.123] UPCALL_EVENT:
  Netlink PID: 12345
  Upcall type: MISS
  Packet info:
    - Ethernet: 52:54:00:12:34:56 -> 52:54:00:ab:cd:ef
    - IP: 172.21.153.113 -> 172.21.153.114
    - TCP: 45678 -> 80
    - Packet length: 1500 bytes
  Kernel timestamp: 1579021145610018ns

[18:25:30.156] FLOW_INSTALL:
  Netlink PID: 12345
  Flow key:
    - in_port: 1
    - eth_src: 52:54:00:12:34:56
    - eth_dst: 52:54:00:ab:cd:ef
    - eth_type: 0x0800
    - ip_src: 172.21.153.113/32
    - ip_dst: 172.21.153.114/32
    - ip_proto: 6
    - tcp_src: 45678
    - tcp_dst: 80
  Actions: output:2

[18:25:30.234] UPCALL_EVENT:
  Netlink PID: 12345
  Upcall type: ACTION
  Packet info:
    - Ethernet: 52:54:00:ab:cd:ef -> 52:54:00:12:34:56
    - IP: 172.21.153.114 -> 172.21.153.113
    - TCP: 80 -> 45678
    - Packet length: 64 bytes
  Kernel timestamp: 1579021145692345ns

```

### 5.4 KVM 虚拟化网络输出格式

#### 5.4.1 vhost-net 监控输出

**vhost_eventfd_count.py 输出格式：**

```
=== vhost eventfd Monitor ===
Interval: 5 seconds
Clear counters: enabled

Starting vhost eventfd monitoring...

[2025-09-22 16:30:15] === vhost eventfd Statistics ===
Eventfd combinations (last 5 seconds):
  kick_fd=25, call_fd=26: 1234 events
  kick_fd=27, call_fd=28: 567 events
  kick_fd=29, call_fd=30: 89 events

Total eventfd events: 1890
Unique fd combinations: 3
Average events per combination: 630

Top combinations by frequency:
1. kick_fd=25, call_fd=26: 1234 events (65.3%)
2. kick_fd=27, call_fd=28: 567 events (30.0%)
3. kick_fd=29, call_fd=30: 89 events (4.7%)

[2025-09-22 16:30:20] === vhost eventfd Statistics ===
Eventfd combinations (last 5 seconds):
  kick_fd=25, call_fd=26: 1456 events
  kick_fd=27, call_fd=28: 623 events
  kick_fd=29, call_fd=30: 112 events

Total eventfd events: 2191
Unique fd combinations: 3
Average events per combination: 730
```

**vhost_queue_correlation_details.py 输出格式：**

```
=== vhost Queue Correlation Monitor ===
Device filter: vhost-1
Interval: 2 seconds

Attaching to vhost functions...
BPF program loaded successfully

[2025-09-22 17:15:30] === Queue Correlation Report ===
Monitored device: vhost-1
Active queues: 4

Queue pair correlations:
  RX Queue 0 <-> TX Queue 1:
    - Packets processed: 1234 (RX), 1189 (TX)
    - Correlation rate: 96.4%
    - Average processing gap: 12.3 us

  RX Queue 2 <-> TX Queue 3:
    - Packets processed: 567 (RX), 545 (TX)
    - Correlation rate: 96.1%
    - Average processing gap: 15.7 us

Queue utilization:
  - Queue 0 (RX): 67.8% busy
  - Queue 1 (TX): 65.4% busy
  - Queue 2 (RX): 31.2% busy
  - Queue 3 (TX): 29.8% busy

Load balancing efficiency: 78.5%
Overall queue correlation rate: 96.3%
```

### 5.5 Bpftrace 脚本输出格式

#### 5.5.1 事件跟踪输出

**virtionet-rx-path-monitor.bt 输出格式：**

```
Attaching 6 probes...
Tracing virtio-net RX path. Hit Ctrl-C to end.

TIME     PID    COMM           FUNC                    DETAILS
18:45:23 1234   vhost-1234     virtqueue_get_buf      vq=0 len=1500
18:45:23 1234   vhost-1234     virtqueue_kick         vq=0
18:45:23 0      swapper/5      virtnet_poll           napi=0xffff888123456789 budget=64
18:45:23 0      swapper/5      receive_buf            skb=0xffff888abcdef012 len=1500
18:45:23 0      swapper/5      virtnet_receive        packets=1 bytes=1500
18:45:23 1234   vhost-1234     vhost_add_used_and_signal vq=0 head=15 len=1500

TIME     PID    COMM           FUNC                    DETAILS
18:45:23 1234   vhost-1234     virtqueue_get_buf      vq=2 len=64
18:45:23 1234   vhost-1234     virtqueue_kick         vq=2
18:45:23 0      swapper/3      virtnet_poll           napi=0xffff888123456789 budget=64
18:45:23 0      swapper/3      receive_buf            skb=0xffff888abcdef345 len=64
18:45:23 0      swapper/3      virtnet_receive        packets=1 bytes=64
18:45:23 1234   vhost-1234     vhost_add_used_and_signal vq=2 head=23 len=64
```

**kernel_drop_stack_stats.bt 输出格式：**

```
Attaching 1 probe...
Tracing kernel packet drops. Hit Ctrl-C to end.

@drop_stacks[
    kfree_skb+0
    tcp_v4_rcv+564
    ip_local_deliver_finish+291
    ip_local_deliver+69
    ip_rcv_finish+103
    ip_rcv+137
    __netif_receive_skb_one_core+134
    __netif_receive_skb+21
    process_backlog+137
    __napi_poll+298
    net_rx_action+564
    __do_softirq+342
]: 15

@drop_stacks[
    kfree_skb+0
    netif_receive_skb_core+325
    __netif_receive_skb_one_core+134
    __netif_receive_skb+21
    netif_rx+298
    loopback_xmit+105
    dev_hard_start_xmit+232
    __dev_queue_xmit+1456
    dev_queue_xmit+15
    ip_finish_output2+567
    ip_finish_output+234
    ip_output+123
]: 8

@drop_locations[
    tcp_v4_rcv+564
]: 15

@drop_locations[
    netif_receive_skb_core+325
]: 8
```

### 5.6 输出格式特点总结

#### 5.6.1 时间戳格式

- **绝对时间**: `[YYYY-MM-DD HH:MM:SS.mmm]` 格式
- **相对时间**: `[    0.000]` 格式（从启动开始的秒数）
- **内核时间戳**: `KTIME=1579020094156218ns` 格式

#### 5.6.2 网络信息格式

- **五元组**: `src_ip:src_port -> dst_ip:dst_port protocol`
- **MAC 地址**: `52:54:00:12:34:56` 格式
- **接口信息**: `device_name (ifindex=N) CPU=N`

#### 5.6.3 性能指标格式

- **延迟**: 以微秒 (us) 为单位
- **吞吐量**: 以 pps、Mbps、GB 等单位
- **百分比**: P50、P95、P99 等百分位数
- **直方图**: 使用 ASCII 字符绘制的分布图

#### 5.6.4 错误和异常信息

- **返回值**: 特定函数返回值常量
- **栈跟踪**: 函数名+偏移量 格式
- **错误码**: BPF 程序加载错误信息

这些输出格式提供了丰富的网络性能和问题诊断信息，帮助用户全面理解系统网络状态和性能特征。

### 5.7 边界检测工具输出格式

边界检测工具提供两种输出模式：统计模式（默认）和 verbose 模式。

#### 5.7.1 统计模式输出

统计模式按时间间隔输出每个监控阶段的包计数，通过对比相邻阶段的计数差异定位丢包区间：

```
=== Stats interval 10s ===
Stage               | FWD count | REV count | FWD drop% | REV drop%
RX@phy              |      1000 |       998 |     0.00% |     0.00%
tcp_v4_rcv          |       998 |           |     0.20% |
__ip_queue_xmit     |           |       995 |           |     0.30%
TX@phy              |       995 |       993 |     0.30% |     0.50%
```

#### 5.7.2 Verbose 模式输出

Verbose 模式输出每个数据包通过各边界点的事件：

```
[2024-01-15 10:30:15.123] ICMP req 10.0.0.1→10.0.0.2 id=1234 seq=1 stage=ReqRX@phy latency=0us
[2024-01-15 10:30:15.125] ICMP req 10.0.0.1→10.0.0.2 id=1234 seq=1 stage=ReqRcv@stack latency=2us
[2024-01-15 10:30:15.126] ICMP rep 10.0.0.2→10.0.0.1 id=1234 seq=1 stage=RepSnd@stack latency=3us
[2024-01-15 10:30:15.128] ICMP rep 10.0.0.2→10.0.0.1 id=1234 seq=1 stage=RepTX@phy latency=5us
```

#### 5.7.3 延迟直方图（TCP/UDP Path Tracer）

TCP 和 UDP path tracer 在 stats 模式下额外输出 21-bucket 延迟直方图：

```
Latency histogram (us):
  [0-1)     : ######### 450
  [1-2)     : ############ 600
  [2-4)     : ###### 300
  [4-8)     : ### 150
  ...
```

## 6. 部署和环境

### 6.1 系统要求

#### 6.1.1 基本要求

- **内核版本**: Linux 内核 4.19.90+ （推荐 openEuler 20.03 LTS 或更高版本）
- **BPF 支持**: 内核必须编译启用 CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y
- **权限要求**: 所有 eBPF 工具需要 root 权限执行
- **安装包要求**: 所有 eBPF 工具运行需要安装 kernel-devel && kernel-header , 此外推荐安装内核调试符号包 (kernel-debuginfo)

#### 6.1.2 依赖组件

- **BCC 工具链**: BPF Compiler Collection 0.18.0+
- **bpftrace**: bpftrace 0.10.0+
- **Python 环境**: Python 3.6+ （支持 Python 2.7 兼容）

#### 6.1.3 内核配置验证

```bash
# 检查 BPF 支持
zgrep CONFIG_BPF /proc/config.gz
zgrep CONFIG_BPF_SYSCALL /proc/config.gz
zgrep CONFIG_BPF_JIT /proc/config.gz

# 检查 BPF 文件系统
ls /sys/fs/bpf

# 检查 BCC 安装
python3 -c "import bcc; print('BCC version:', bcc.__version__)"

# 检查 bpftrace 安装
bpftrace --version
```

### 6.2 目标环境

#### 6.2.1 虚拟化环境

- **Hypervisor**: KVM/QEMU 4.0+
- **虚拟网卡**: virtio-net 驱动
- **网络后端**: vhost-net
- **多队列支持**: 启用 virtio-net 多队列 && vhost-net 多线程

#### 6.2.2 网络环境

- **虚拟网络**: Open vSwitch 2.13+ 或 Linux Bridge
- **网络协议**: 支持 TCP/UDP/ICMP IPv4/IPv6
- **VLAN 支持**: 802.1Q VLAN 标签
- **Conntrace 支持**: 协议栈 conntrack 模块
- **流量控制**: TC (Traffic Control) qdisc 支持

#### 6.2.3 操作系统支持

- **主要支持**: openEuler 20.03 LTS+
- **测试支持**: CentOS 7+, Ubuntu 18.04+, RHEL 8+
- **内核版本**: 4.19.90 && tecentos tls 5.4 && 5.10 为主要适配目标

### 6.3 安装部署步骤

#### 6.3.1 openEuler 系统安装

```bash
# 安装 BCC 工具
sudo yum install -y bcc-tools python3-bcc

# 安装 bpftrace
sudo yum install -y bpftrace

# 安装其他依赖
sudo yum install -y kernel-devel-$(uname -r) kernel-header-$(uname -r) 

# 克隆项目
git clone https://github.com/your-org/troubleshooting-tools.git
cd troubleshooting-tools
```

#### 6.3.2 Ubuntu 系统安装

```bash
# 更新包管理器
sudo apt update

# 安装 BCC
sudo apt install -y bcc-tools python3-bcc

# 安装 bpftrace
sudo apt install -y bpftrace

# 安装其他依赖
sudo apt install -y linux-headers-$(uname -r)

# 克隆项目
git clone https://github.com/echkenluo/troubleshooting-tools.git
cd troubleshooting-tools
```

#### 6.3.3 环境验证

```bash
# 测试基本 BPF 功能
sudo python3 -c "from bcc import BPF; print('BCC import successful')"
# oe 系统上
sudo python3 -c "from bpfcc import BPF; print('BCC import successful')"

# 测试简单 eBPF 程序
sudo bpftrace -e 'BEGIN { printf("bpftrace is working\\n"); exit(); }'

# 测试项目工具
cd troubleshooting-tools
sudo python3 measurement-tools/performance/system-network/system_network_icmp_rtt.py --help
```

### 6.4 故障排查和支持

#### 6.4.1 常见错误和解决方案

**BPF 程序加载失败**

- **错误信息**: `bpf: Failed to load program: Permission denied`
- **解决方案**:
  1. 检查是否使用 root 权限
  2. 检查内核版本是否支持 BPF
  3. 检查 BCC 安装是否完整

**程序挂起**

- **错误信息**: `Cannot attach to function: No such file or directory`
- **解决方案**:
  1. 检查内核符号表是否可用
  2. 检查函数名是否正确
  3. 检查内核模块是否加载

**数据采集异常**

- **现象**: 无数据或数据不完整
- **解决方案**:
  1. 检查网络流量是否匹配过滤器
  2. 调整采样间隔和时长
  3. 检查系统资源使用情况

#### 6.4.2 BCC 和环境问题解决

**BCC 导入错误**:

```bash
# 检查 Python 路径
sudo python3 -c "import sys; print(sys.path)"
sudo find /usr -name "*bcc*" -type d

# 重新安装 BCC
sudo yum reinstall python3-bcc bcc-tools  # CentOS/RHEL
sudo apt reinstall python3-bpfcc bpfcc-tools  # Ubuntu/Debian 
```

**内核符号问题**:

```bash
# 检查内核符号表
sudo ls -la /proc/kallsyms
sudo cat /proc/kallsyms | grep "netif_receive_skb"

# 安装内核调试信息
sudo yum install kernel-debuginfo-$(uname -r) kernel-devel-$(uname -r) kernel-headers-$(uname -r) # openEuler/CentOS
```

### 6.5 版本兼容性

#### 6.5.1 内核版本支持

| 内核版本            | 支持状态                          | 说明                                 |
| ------------------- | --------------------------------- | ------------------------------------ |
| 4.19.90 (openEuler) | 全面支持                          | 主要适配目标                         |
| 5.4.x               | 支持                              | 所有功能可用                         |
| 5.10.x LTS          | 支持                              | 推荐使用                             |
| 4.18.x              | 部分支持                          | 部分新特性不可用                     |
| < 4.18              | 不支持(redhat 系系统部分工具支持) | BPF 功能不完整，仅 redhat 系部分支持 |

#### 6.5.2 工具版本支持

| 组件     | 最低版本 | 推荐版本 | 说明                                                                            |
| -------- | -------- | -------- | ------------------------------------------------------------------------------- |
| BCC      | 0.15.0   | 0.25.0+  | 较新版本更好                                                                    |
| bpftrace | 0.10.0   | 0.16.0+  | 支持更多语言特性,部分实现优化                                                   |
| Python   | 2.7      | 3.8+     | 推荐使用 Python 3, 依赖 package: python-bcc 或 python3-bcc，oe 系统 python3-bcc |
| LLVM     | 6.0      | 12.0+    | 更好的 BPF 编译支持                                                             |

## 7. 使用最佳实践

### 7.1 监控最佳实践

#### 7.1.1 生产环境监控

**分层测量**:

1. **基线性能采集** : 使用若干问题域/模块的 summary 版本测量工具，获取问题初筛结果，确定需要做精细 detail 信息测量的范围，即如何进一步过滤
2. **问题时段详细分析** : 部署特定问题域的 details 版测量工具，使用 summary 筛查结果作为过滤器，进一步减小对 workload 影响
3. **持续监控和报警** : 合理设计的 summary metric ， histogram 形式统计， 部署关键模块，核心指标测量。

#### 7.1.2 权限管理

- **Root 权限**: 所有 eBPF 工具需要 root 权限
- **Capability 管理**: 可考虑使用 CAP_BPF 和 CAP_SYS_ADMIN
- **用户隔离**: 建议使用专用的监控用户账号

#### 7.1.3 性能影响控制

- **资源限制**: 监控 CPU 和内存使用情况
- **并发数量**: 同时运行的工具数量不超过 3-5 个

该项目为虚拟化环境的网络性能监控和故障排查提供了全面的 eBPF 工具集，通过合理的部署和使用，可以有效提升网络问题诊断的效率和准确性。
