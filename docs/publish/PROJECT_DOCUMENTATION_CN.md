# eBPF 网络故障排查工具 - 项目文档

## 1. 项目结构

项目按照系统组件和问题域进行模块化目录组织。主要结构由使用 Python（BCC）编写的 eBPF 工具和 bpftrace 脚本组成。

### 目录分类

```
ebpf-tools/
├── cpu/                              # CPU 和调度器监控工具
├── kvm-virtualization-network/      # KVM/QEMU 虚拟化网络栈工具
│   ├── kvm/                         # KVM 中断和 IRQ 监控
│   ├── tun/                         # TUN/TAP 设备监控
│   ├── vhost-net/                   # vhost-net 后端监控
│   └── virtio-net/                  # virtio-net 客户机驱动监控
├── linux-network-stack/             # Linux 内核网络栈工具
│   └── packet-drop/                 # 丢包检测和分析
├── other/                           # 其他跟踪工具
├── ovs/                             # Open vSwitch 监控工具
└── performance/                     # 网络性能监控
    ├── system-network/              # 系统级网络性能
    └── vm-network/                  # 虚拟机专用网络性能
        └── vm_pair_latency/         # 虚拟机间延迟监控
```

## 2. 模块特定工具详情

### 2.1 CPU 模块 (`cpu/`)

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

### 2.2 KVM 虚拟化网络模块 (`kvm-virtualization-network/`)

#### 2.2.1 KVM 子系统 (`kvm/`)
- **kvm_irqfd_stats_summary.py**：KVM 中断注入统计
  - **使用场景**：监控虚拟中断传递性能
  - **收集数据**：IRQ 注入次数、延迟、每虚拟机统计
  
- **kvm_irqfd_stats_summary_arm.py**：ARM 特定 KVM 中断监控
  - **使用场景**：ARM 虚拟化中断分析
  - **收集数据**：ARM 特定 IRQ 统计

#### 2.2.2 TUN/TAP 子系统 (`tun/`)
- **tun_ring_monitor.py**：TUN 设备环形缓冲区监控
  - **使用场景**：检测 TUN 设备缓冲区问题
  - **收集数据**：环形缓冲区利用率、溢出事件
  
- **tun-abnormal-gso-type.bt**：异常 GSO 类型检测
  - **使用场景**：识别 GSO 卸载问题
  - **收集数据**：无效 GSO 类型、数据包详情
  
- **tun-tx-ring-stas.bt**：TUN 发送环统计
  - **使用场景**：TX 环性能分析
  - **收集数据**：TX 环占用率、吞吐量

#### 2.2.3 vhost-net 后端 (`vhost-net/`)
- **vhost_eventfd_count.py/bt**：vhost eventfd 信号监控
  - **使用场景**：分析客户机-主机通知效率
  - **收集数据**：Eventfd 信号次数、频率
  
- **vhost_queue_correlation_simple.py**：简单队列关联分析
  - **使用场景**：理解队列利用模式
  - **收集数据**：队列对映射、利用率指标
  
- **vhost_queue_correlation_details.py**：详细队列关联
  - **使用场景**：深度队列性能分析
  - **收集数据**：每队列统计、关联指标
  
- **vhost_buf_peek_stats.py**：vhost 缓冲区 peek 操作
  - **使用场景**：缓冲区管理效率
  - **收集数据**：缓冲区 peek 次数、延迟

#### 2.2.4 virtio-net 客户机驱动 (`virtio-net/`)
- **virtnet_poll_monitor.py**：virtio-net NAPI 轮询监控
  - **使用场景**：NAPI 轮询效率分析
  - **收集数据**：轮询次数、数据包批量大小
  
- **virtnet_irq_monitor.py**：virtio-net 中断监控
  - **使用场景**：中断合并有效性
  - **收集数据**：IRQ 速率、CPU 亲和性
  
- **virtionet-rx-path-monitor.bt**：RX 路径详细监控
  - **使用场景**：RX 处理瓶颈识别
  - **收集数据**：函数延迟、数据包流
  
- **virtionet-rx-path-summary.bt**：RX 路径汇总统计
  - **使用场景**：整体 RX 性能评估
  - **收集数据**：聚合 RX 指标
  
- **trace_virtio_net_rcvbuf.bt**：接收缓冲区跟踪
  - **使用场景**：缓冲区分配问题
  - **收集数据**：缓冲区大小、分配失败

#### 2.2.5 跨层工具
- **tun_to_vhost_queue_status_simple.py**：TUN 到 vhost 队列映射
  - **使用场景**：理解层间数据流
  - **收集数据**：队列映射、流统计
  
- **tun_to_vhost_queue_stats_details.py**：详细队列统计
  - **使用场景**：性能关联分析
  - **收集数据**：详细每队列指标
  
- **tun_tx_to_kvm_irq.py**：TX 到 IRQ 注入关联
  - **使用场景**：端到端延迟分析
  - **收集数据**：TX 到 IRQ 延迟、注入速率

### 2.3 Linux 网络栈模块 (`linux-network-stack/`)

#### 核心网络栈工具
- **trace_conntrack.py**：连接跟踪监控
  - **使用场景**：NAT/防火墙连接问题
  - **收集数据**：连接状态、超时
  
- **trace_ip_defrag.py**：IP 分片/重组
  - **使用场景**：分片相关丢包
  - **收集数据**：分片计数、重组失败

#### 丢包子系统 (`packet-drop/`)
- **drop_monitor_controller.py**：集中式丢包监控
  - **使用场景**：系统范围丢包检测
  - **收集数据**：丢包位置、原因、计数
  
- **eth_drop.py**：以太网层丢包监控
  - **使用场景**：网卡驱动丢包检测
  - **收集数据**：驱动丢包统计
  
- **kernel_drop_stack_stats_summary.py**：内核丢包栈分析
  - **使用场景**：识别内核中的丢包位置
  - **收集数据**：栈跟踪、丢包频率
  
- **kernel_drop_stack_stats.bt**：实时丢包栈跟踪
  - **使用场景**：实时丢包调试
  - **收集数据**：实时栈跟踪
  
- **qdisc_drop_trace.py**：队列规则丢包监控
  - **使用场景**：流量控制丢包分析
  - **收集数据**：Qdisc 丢包原因、队列深度

### 2.4 Open vSwitch 模块 (`ovs/`)

- **ovs-kernel-module-drop-monitor.py**：OVS 数据路径丢包监控
  - **使用场景**：OVS 内核模块丢包
  - **收集数据**：丢包原因、流信息
  
- **ovs_userspace_megaflow.py**：Megaflow 缓存监控
  - **使用场景**：流缓存效率分析
  - **收集数据**：缓存命中/未命中率、流计数

### 2.5 性能模块 (`performance/`)

#### 系统网络性能 (`system-network/`)
- **system_network_icmp_rtt.py**：ICMP RTT 测量
  - **使用场景**：网络延迟基准测试
  - **收集数据**：RTT 统计、丢包率
  
- **system_network_latency_details.py**：详细延迟分解
  - **使用场景**：组件级延迟分析
  - **收集数据**：每层延迟测量
  
- **system_network_perfomance_metrics.py**：综合指标
  - **使用场景**：整体网络性能评估
  - **收集数据**：吞吐量、延迟、CPU 使用率

#### 虚拟机网络性能 (`vm-network/`)
- **vm_network_latency_details.py**：虚拟机网络延迟分解
  - **使用场景**：虚拟机特定延迟分析
  - **收集数据**：主机-虚拟机-主机延迟组件
  
- **vm_network_latency_summary.py**：虚拟机延迟汇总
  - **使用场景**：快速虚拟机网络评估
  - **收集数据**：聚合延迟统计
  
- **vm_network_performance_metrics.py**：虚拟机性能指标
  - **使用场景**：虚拟机网络性能监控
  - **收集数据**：虚拟机特定吞吐量、PPS

##### 虚拟机对延迟分析 (`vm_pair_latency/`)
- **vm_pair_latency.py**：基本虚拟机间延迟
  - **使用场景**：虚拟机间通信延迟
  - **收集数据**：点对点延迟
  
- **multi_vm_pair_latency.py**：多虚拟机对监控
  - **使用场景**：多租户延迟分析
  - **收集数据**：每对延迟矩阵
  
- **multi_vm_pair_latency_pairid.py**：标识对延迟
  - **使用场景**：特定虚拟机对跟踪
  - **收集数据**：标识对指标

##### 延迟间隙分析 (`vm_pair_latency_gap/`)
- **vm_pair_gap.py**：虚拟机对延迟间隙
  - **使用场景**：延迟变化分析
  - **收集数据**：间隙统计、抖动
  
- **multi_port_gap.py**：多端口延迟间隙
  - **使用场景**：端口特定延迟分析
  - **收集数据**：每端口间隙指标
  
- **multi_vm_pair_multi_port_gap.py**：综合间隙分析
  - **使用场景**：复杂拓扑延迟分析
  - **收集数据**：多维间隙数据

#### 通用性能工具
- **iface_netstat.py**：接口统计监控
  - **使用场景**：网络接口性能
  - **收集数据**：RX/TX 计数器、错误
  
- **ovs_upcall_latency_summary.py**：OVS upcall 延迟
  - **使用场景**：OVS 慢路径性能
  - **收集数据**：Upcall 延迟、频率
  
- **qdisc_lateny_details.py**：Qdisc 延迟分析
  - **使用场景**：流量控制性能
  - **收集数据**：Qdisc 处理时间

### 2.6 其他工具模块 (`other/`)

- **trace-abnormal-arp.bt**：异常 ARP 检测
  - **使用场景**：ARP 欺骗/问题检测
  - **收集数据**：可疑 ARP 数据包
  
- **trace-ovs-ct-invalid.bt**：OVS 连接跟踪无效状态
  - **使用场景**：连接跟踪问题
  - **收集数据**：无效 CT 条目
  
- **trace_offloading_segment.bt**：分段卸载跟踪
  - **使用场景**：TSO/GSO 问题调试
  - **收集数据**：卸载参数
  
- **trace_vlanvm_udp_workload.bt**：VLAN 虚拟机 UDP 跟踪
  - **使用场景**：VLAN 特定 UDP 问题
  - **收集数据**：VLAN 标签、UDP 流
  
- **vpc-vm-udp-datapath.bt**：VPC 虚拟机 UDP 数据路径
  - **使用场景**：云网络 UDP 分析
  - **收集数据**：VPC 流路径
  
- **trace-qdisc-dequeue.bt**：Qdisc 出队操作
  - **使用场景**：队列调度分析
  - **收集数据**：出队模式
  
- **trace_dev_queue_xmit.bt**：设备队列传输
  - **使用场景**：TX 队列行为
  - **收集数据**：队列深度、丢包
  
- **trace_tc_qdisc.bt**：流量控制 qdisc 跟踪
  - **使用场景**：TC 配置调试
  - **收集数据**：TC 动作、分类

## 3. 工具使用指南

### 3.1 Python BCC 工具

**通用使用模式：**
```bash
sudo python2 <工具路径> [选项]
```

**常用参数：**
- `-i, --interval`：采样间隔（秒）
- `-d, --duration`：总监控时长
- `-c, --count`：采集样本数量
- `--src-ip`：源 IP 地址过滤器
- `--dst-ip`：目标 IP 地址过滤器
- `-p, --pid`：进程 ID 过滤器
- `-v, --verbose`：详细输出模式

**使用示例：**

```bash
# 监控虚拟机网络延迟 60 秒
sudo python2 ebpf-tools/performance/vm-network/vm_network_latency_summary.py -d 60

# 跟踪特定虚拟机对延迟
sudo python2 ebpf-tools/performance/vm-network/vm_pair_latency/vm_pair_latency.py \
    --src-ip 192.168.1.10 --dst-ip 192.168.1.20 -i 1

# 监控 OVS 丢包
sudo python2 ebpf-tools/ovs/ovs-kernel-module-drop-monitor.py -v

# 分析 vhost 队列关联
sudo python2 ebpf-tools/kvm-virtualization-network/vhost-net/vhost_queue_correlation_details.py \
    --vm-name test-vm -i 5
```

### 3.2 Bpftrace 脚本

**通用使用模式：**
```bash
sudo bpftrace <脚本路径> [参数]
```

**常见用法：**

```bash
# 跟踪异常 ARP 数据包
sudo bpftrace ebpf-tools/other/trace-abnormal-arp.bt

# 监控 virtio-net RX 路径
sudo bpftrace ebpf-tools/kvm-virtualization-network/virtio-net/virtionet-rx-path-monitor.bt

# 跟踪内核丢包及栈跟踪
sudo bpftrace ebpf-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats.bt
```

### 3.3 Shell 脚本

**CPU 监控：**
```bash
# 综合 CPU 监控
sudo ./ebpf-tools/cpu/cpu_monitor.sh

# 调度器延迟分析
sudo ./ebpf-tools/cpu/sched_latency_monitor.sh --interval 1 --duration 60
```

## 4. 输出数据格式

### 4.1 Python BCC 工具输出

大多数 Python 工具提供以下格式的结构化输出：

**延迟工具：**
```
时间戳: 1234567890.123
源: 192.168.1.10:5000 -> 目标: 192.168.1.20:8080
延迟分解:
  - 内核 TX: 12.5 us
  - OVS 处理: 8.3 us
  - vhost-net: 15.2 us
  - 客户机 RX: 10.1 us
  总计: 46.1 us
```

**丢包监控工具：**
```
丢包位置: netif_receive_skb_core+0x123
原因: NETDEV_DROP_REASON_NO_BUFFER
计数: 150
栈跟踪:
  netif_receive_skb_core+0x123
  __netif_receive_skb+0x45
  process_backlog+0x89
  ...
```

**性能指标：**
```
接口: eth0
RX 数据包: 1234567 (1.2M pps)
TX 数据包: 987654 (987K pps)
RX 字节数: 1.5 GB
TX 字节数: 1.2 GB
错误: 0
丢包: 5
```

### 4.2 Bpftrace 输出

Bpftrace 脚本通常输出：

**事件跟踪：**
```
时间     PID    命令           事件           详情
10:15:23 1234   qemu-kvm       virtio_rx       长度=1500 队列=0
10:15:23 1234   qemu-kvm       virtio_notify   vq=0 
```

**直方图：**
```
@延迟_us:
[0, 1)          1234 |@@@@@@@@@@                    |
[1, 2)          5678 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@  |
[2, 4)          2345 |@@@@@@@@@@@                   |
[4, 8)          890  |@@@@                          |
```

**栈计数：**
```
@栈计数[
    kfree_skb+0x0
    tcp_v4_rcv+0x123
    ip_local_deliver+0x45
]: 250
```

### 4.3 汇总报告

许多工具生成汇总报告：

```
========== 虚拟机网络性能汇总 ==========
监控时长: 60 秒
总数据包: 1,234,567
平均延迟: 45.2 us
P50 延迟: 42.1 us
P95 延迟: 78.3 us
P99 延迟: 125.6 us
最大延迟: 1,234.5 us

延迟主要贡献者:
1. vhost-net 处理: 35%
2. OVS 转发: 25%
3. 客户机驱动: 20%
4. 其他: 20%
=========================================
```

## 5. 部署和要求

### 系统要求
- Linux 内核 4.19+ 且启用 BPF 支持
- 已安装 BCC（BPF 编译器集合）
- 已安装 bpftrace
- Python 2.7 或 Python 3.6+
- BPF 程序加载需要 root 权限

### 目标环境
- 虚拟化：KVM/QEMU 配合 virtio-net
- 网络：Open vSwitch 2.10+
- 操作系统：openEuler、CentOS 7+、Ubuntu 18.04+

### 安全考虑
- 所有工具需要 root 访问权限
- 运行时可能影响系统性能
- 建议先在开发环境测试
- 使用采样间隔以减少开销
- 工具运行时监控系统负载