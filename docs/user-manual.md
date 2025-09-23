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
        └── vm_pair_latency/         # 同节点虚拟机间延迟监控
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

### 3.1 基本使用模式

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

### 3.2 性能监控模块 (Performance)

#### 3.2.1 通用参数说明

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

#### 3.2.2 系统网络性能工具

**system_network_perfomance_metrics.py** - 系统网络性能指标
```bash
# 监控系统网络性能指标
sudo python3 ebpf-tools/performance/system-network/system_network_perfomance_metrics.py \
  --internal-interface port-storage --phy-interface ens11 \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 \
  --direction rx --protocol tcp

# 启用连接跟踪的性能监控
sudo python3 ebpf-tools/performance/system-network/system_network_perfomance_metrics.py \
  --internal-interface br0 --phy-interface eth0 \
  --enable-ct --verbose
```

**system_network_latency_details.py** - 系统网络延迟分解
```bash
# 详细延迟分析
sudo python3 ebpf-tools/performance/system-network/system_network_latency_details.py \
  --phy-interface ens11 --src-ip 10.132.114.12 --dst-ip 10.132.114.11 \
  --direction rx --protocol tcp

# 双向延迟监控
sudo python3 ebpf-tools/performance/system-network/system_network_latency_details.py \
  --phy-interface eth0 --src-ip 192.168.1.100 --dst-ip 192.168.1.200 \
  --direction both --protocol udp
```

**system_network_icmp_rtt.py** - ICMP RTT 测量
```bash
# ICMP 往返时间测量
sudo python3 ebpf-tools/performance/system-network/system_network_icmp_rtt.py \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 \
  --direction tx --phy-iface1 ens11
```

#### 3.2.3 虚拟机网络性能工具

**vm_network_latency_summary.py** - 虚拟机网络延迟汇总
```bash
# 虚拟机网络延迟监控
sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_summary.py \
  --vm-interface vnet0 --phy-interface ens4 \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \
  --direction rx --protocol tcp

# 指定虚拟机 IP 的延迟监控
sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_summary.py \
  --vm-interface tap0 --phy-interface eth0 \
  --vm-ip 10.0.0.100 --protocol tcp --direction rx
```

**vm_network_latency_details.py** - 虚拟机网络延迟详细分析
```bash
# 虚拟机延迟详细分解
sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_details.py \
  --vm-interface vnet0 --phy-interface ens4 \
  --src-ip 172.21.153.114 --dst-ip 172.21.153.113 \
  --direction tx --protocol udp
```

**vm_network_performance_metrics.py** - 虚拟机网络性能指标
```bash
# 虚拟机网络性能监控
sudo python3 ebpf-tools/performance/vm-network/vm_network_performance_metrics.py \
  --vm-interface vnet0 --phy-interface ens4 \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \
  --direction rx --protocol tcp
```

#### 3.2.4 虚拟机对延迟分析工具

**vm_pair_latency.py** - 虚拟机间延迟分析
```bash
# 基本虚拟机对延迟监控
sudo python3 ebpf-tools/performance/vm-network/vm_pair_latency/vm_pair_latency.py \
  --send-dev tap0 --recv-dev tap1

# 多端口延迟监控
sudo python3 ebpf-tools/performance/vm-network/vm_pair_latency/multi_vm_pair_latency.py \
  --send-dev tap0 --recv-dev tap1 --ports 22 80 443
```

**vm_pair_gap.py** - 延迟间隙分析
```bash
# 延迟间隙分析（设定阈值）
sudo python3 ebpf-tools/performance/vm-network/vm_pair_latency_gap/vm_pair_gap.py \
  --threshold 100 --ports 22 80

# 多端口延迟间隙分析
sudo python3 ebpf-tools/performance/vm-network/vm_pair_latency_gap/multi_port_gap.py \
  --threshold 50 --ports 22 80 443 8080
```

### 3.3 Linux 网络栈模块 (Linux Network Stack)

#### 3.3.1 通用参数说明

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

#### 3.3.2 丢包监控工具

**eth_drop.py** - 以太网层丢包监控
```bash
# 基本以太网丢包监控
sudo python3 ebpf-tools/linux-network-stack/packet-drop/eth_drop.py \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 --l4-protocol tcp

# 指定接口和协议类型的丢包监控
sudo python3 ebpf-tools/linux-network-stack/packet-drop/eth_drop.py \
  --type ipv4 --src-ip 192.168.1.100 --dst-port 80 \
  --interface eth0 --verbose
```

**kernel_drop_stack_stats_summary.py** - 内核丢包栈统计
```bash
# 内核丢包栈统计分析
sudo python3 ebpf-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats_summary.py \
  --src-ip 10.132.114.12 --dst-ip 10.132.114.11 --l4-protocol tcp

# 详细栈统计（指定设备和时间间隔）
sudo python3 ebpf-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats_summary.py \
  --interval 5 --duration 60 --top 10 \
  --device br-int --src-ip 10.0.0.100 --l4-protocol tcp
```

**kernel_drop_stack_stats_summary_all.py** - 增强型丢包统计
```bash
# 全面的内核丢包统计
sudo python3 ebpf-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats_summary_all.py \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 --l4-protocol udp
```

**qdisc_drop_trace.py** - 队列规则丢包跟踪
```bash
# 队列规则丢包监控
sudo python3 ebpf-tools/linux-network-stack/packet-drop/qdisc_drop_trace.py
```

#### 3.3.3 连接跟踪和分片工具

**trace_conntrack.py** - 连接跟踪监控
```bash
# 基本连接跟踪
sudo python3 ebpf-tools/linux-network-stack/trace_conntrack.py \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 --protocol tcp

# 相对时间显示的连接跟踪
sudo python3 ebpf-tools/linux-network-stack/trace_conntrack.py \
  --src-ip 192.168.1.100 --protocol tcp --rel-time

# 使用过滤器文件的多过滤器连接跟踪
sudo python3 ebpf-tools/linux-network-stack/trace_conntrack.py \
  --filters-file /path/to/filters.json --stack true
```

**trace_ip_defrag.py** - IP 分片重组跟踪
```bash
# IP 分片重组监控
sudo python3 ebpf-tools/linux-network-stack/trace_ip_defrag.py \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 --protocol udp

# 带日志记录的 IP 分片监控
sudo python3 ebpf-tools/linux-network-stack/trace_ip_defrag.py \
  --src-ip 192.168.1.100 --protocol udp --log-file /tmp/defrag.log
```

### 3.4 Open vSwitch 模块 (OVS)

#### 3.4.1 通用参数说明

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

#### 3.4.2 OVS 工具使用

**ovs_upcall_latency_summary.py** - OVS Upcall 延迟分析
```bash
# OVS upcall 延迟监控
sudo python3 ebpf-tools/ovs/ovs_upcall_latency_summary.py \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 --protocol tcp

# 指定报告间隔的 upcall 延迟监控
sudo python3 ebpf-tools/ovs/ovs_upcall_latency_summary.py \
  --src-ip 192.168.76.198 --protocol tcp --interval 5
```

**ovs_userspace_megaflow.py** - OVS 用户空间 Megaflow 跟踪
```bash
# 基本 megaflow 跟踪
sudo python3 ebpf-tools/ovs/ovs_userspace_megaflow.py \
  --src-ip 172.21.153.114 --dst-ip 172.21.153.113 --protocol tcp

# 综合过滤的 megaflow 跟踪
sudo python3 ebpf-tools/ovs/ovs_userspace_megaflow.py \
  --eth-src 00:11:22:33:44:55 --src-ip 10.0.0.100 \
  --l4-src-port 80 --ip-proto 6
```

**ovs-kernel-module-drop-monitor.py** - OVS 内核模块丢包监控
```bash
# OVS 内核丢包监控
sudo python3 ebpf-tools/ovs/ovs-kernel-module-drop-monitor.py \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 --protocol udp
```

### 3.5 KVM 虚拟化网络模块 (KVM Virt Network)

#### 3.5.1 通用参数说明

**基本监控参数：**
- `--interval SECONDS`：输出间隔（默认：1）
- `--clear`：输出后清空计数器
- `--device DEVICE_NAME`：设备名称过滤器
- `--queue-id ID`：特定队列 ID
- `--threshold VALUE`：各种阈值参数

**TUN/TAP 特定参数：**
- `--tun-device DEVICE`：TUN 设备名称
- `--ring-size SIZE`：环形缓冲区大小

#### 3.5.2 vhost-net 工具

**vhost_eventfd_count.py** - vhost eventfd 监控
```bash
# 监控 vhost eventfd 信号
sudo python3 ebpf-tools/kvm-virt-network/vhost-net/vhost_eventfd_count.py \
  --interval 5 --clear
```

**vhost_queue_correlation_details.py** - vhost 队列关联分析
```bash
# 详细 vhost 队列关联分析
sudo python3 ebpf-tools/kvm-virt-network/vhost-net/vhost_queue_correlation_details.py \
  --device vhost-1 --interval 2
```

**vhost_buf_peek_stats.py** - vhost 缓冲区 peek 统计
```bash
# vhost 缓冲区 peek 操作监控
sudo python3 ebpf-tools/kvm-virt-network/vhost-net/vhost_buf_peek_stats.py \
  --interval 1
```

#### 3.5.3 TUN/TAP 工具

**tun_ring_monitor.py** - TUN 环形缓冲区监控
```bash
# TUN 设备环形缓冲区监控
sudo python3 ebpf-tools/kvm-virt-network/tun/tun_ring_monitor.py \
  --device tun0 --interval 1
```

**tun_to_vhost_queue_stats_details.py** - TUN 到 vhost 队列统计
```bash
# TUN 到 vhost 队列详细统计
sudo python3 ebpf-tools/kvm-virt-network/tun/tun_to_vhost_queue_stats_details.py \
  --tun-device tap0 --interval 3
```

#### 3.5.4 virtio-net 工具

**virtnet_poll_monitor.py** - virtio-net NAPI 轮询监控
```bash
# virtio-net NAPI 轮询效率监控
sudo python3 ebpf-tools/kvm-virt-network/virtio-net/virtnet_poll_monitor.py \
  --interval 2
```

**virtnet_irq_monitor.py** - virtio-net 中断监控
```bash
# virtio-net 中断合并监控
sudo python3 ebpf-tools/kvm-virt-network/virtio-net/virtnet_irq_monitor.py \
  --interval 1 --device virtio0
```

#### 3.5.5 KVM IRQ 工具

**kvm_irqfd_stats_summary.py** - KVM 中断注入统计
```bash
# KVM 中断注入性能监控
sudo python3 ebpf-tools/kvm-virt-network/kvm/kvm_irqfd_stats_summary.py \
  --interval 5
```

### 3.6 Bpftrace 脚本工具

#### 3.6.1 网络异常检测脚本

```bash
# 跟踪异常 ARP 数据包
sudo bpftrace ebpf-tools/other/trace-abnormal-arp.bt

# 监控 OVS 连接跟踪无效状态
sudo bpftrace ebpf-tools/other/trace-ovs-ct-invalid.bt

# 跟踪卸载分段问题
sudo bpftrace ebpf-tools/other/trace_offloading_segment.bt
```

#### 3.6.2 virtio-net 路径监控脚本

```bash
# virtio-net RX 路径详细监控
sudo bpftrace ebpf-tools/kvm-virt-network/virtio-net/virtionet-rx-path-monitor.bt

# virtio-net RX 路径汇总统计
sudo bpftrace ebpf-tools/kvm-virt-network/virtio-net/virtionet-rx-path-summary.bt

# 跟踪 virtio-net 接收缓冲区
sudo bpftrace ebpf-tools/kvm-virt-network/virtio-net/trace_virtio_net_rcvbuf.bt
```

#### 3.6.3 TUN/TAP 监控脚本

```bash
# TUN 异常 GSO 类型检测
sudo bpftrace ebpf-tools/kvm-virt-network/tun/tun-abnormal-gso-type.bt

# TUN TX 环形缓冲区统计
sudo bpftrace ebpf-tools/kvm-virt-network/tun/tun-tx-ring-stas.bt
```

#### 3.6.4 内核丢包分析脚本

```bash
# 实时内核丢包栈跟踪
sudo bpftrace ebpf-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats.bt

# 队列规则出队操作跟踪
sudo bpftrace ebpf-tools/other/trace-qdisc-dequeue.bt

# 设备队列传输跟踪
sudo bpftrace ebpf-tools/other/trace_dev_queue_xmit.bt
```

### 3.7 CPU 和调度器监控脚本

```bash
# 综合 CPU 监控
sudo ./ebpf-tools/cpu/cpu_monitor.sh

# 调度器延迟分析
sudo ./ebpf-tools/cpu/sched_latency_monitor.sh --interval 1 --duration 60

# off-CPU 时间分析
sudo python3 ebpf-tools/cpu/offcputime-ts.py
```

### 3.8 参数模式总结

#### 3.8.1 通用参数（大多数工具支持）
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

#### 3.8.2 主题特定参数

| 主题 | 特有参数 |
|------|----------|
| **Performance** | `--vm-interface`, `--phy-interface`, `--direction`, `--enable-ct`, `--vm-ip`, `--threshold` |
| **Linux Stack** | `--type`, `--l4-protocol`, `--vlan-id`, `--rel-time`, `--filters-file`, `--stack`, `--log-file` |
| **OVS** | `--eth-src`, `--eth-dst`, `--eth-type`, `--ip-proto`, `--interval` |
| **KVM Virt** | `--device`, `--queue-id`, `--clear`, `--tun-device`, `--ring-size` |

#### 3.8.3 输出控制参数
```bash
--verbose                 # 详细输出模式
--interval SECONDS        # 报告间隔
--duration SECONDS        # 总监控时长
--log-file FILE          # 输出到日志文件
--no-stack-trace         # 禁用栈跟踪
--clear                  # 清空计数器（部分工具）
--top NUMBER             # 显示前 N 项（统计工具）
```

## 4. 输出数据格式详解

### 4.1 性能监控工具输出格式

#### 4.1.1 系统网络性能指标输出

**system_network_perfomance_metrics.py 输出格式：**
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

#### 4.1.2 虚拟机网络性能输出

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

#### 4.1.3 延迟汇总统计输出

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

### 4.2 Linux 网络栈监控输出格式

#### 4.2.1 丢包监控输出

**eth_drop.py 输出格式：**
```
=== Enhanced Packet Drop Monitor ===
Filter configuration:
  Type filter: IPV4
  Source IP: 10.132.114.11
  Destination IP: 10.132.114.12
  L4 Protocol: TCP
  Interface: eth0

Starting packet drop monitoring...

[2025-09-22 15:30:45.123] DROP DETECTED:
Location: netif_receive_skb_core+0x145
Reason: NETDEV_DROP_REASON_NO_BUFFER
Packet info:
  - Source: 10.132.114.11:45678
  - Destination: 10.132.114.12:80
  - Protocol: TCP
  - Length: 1500 bytes
  - Interface: eth0 (ifindex=2)
  - CPU: 3

Stack trace:
  netif_receive_skb_core+0x145
  __netif_receive_skb+0x67
  process_backlog+0x89
  __napi_poll+0x12a
  net_rx_action+0x234
  __do_softirq+0x156

[2025-09-22 15:30:47.456] DROP DETECTED:
Location: tcp_v4_rcv+0x234
Reason: NETDEV_DROP_REASON_SOCKET_FILTER
Packet info:
  - Source: 10.132.114.11:34567
  - Destination: 10.132.114.12:443
  - Protocol: TCP
  - Length: 64 bytes
  - Interface: eth0 (ifindex=2)
  - CPU: 1

=== Drop Statistics Summary ===
Total monitoring time: 120 seconds
Total drops detected: 15

Drop reasons:
  - NO_BUFFER: 8 (53.3%)
  - SOCKET_FILTER: 4 (26.7%)
  - CHECKSUM_ERROR: 2 (13.3%)
  - OTHER: 1 (6.7%)

Drop locations:
  - netif_receive_skb_core: 10 (66.7%)
  - tcp_v4_rcv: 4 (26.7%)
  - ip_local_deliver: 1 (6.6%)

Affected protocols:
  - TCP: 12 (80.0%)
  - UDP: 3 (20.0%)
```

**kernel_drop_stack_stats_summary.py 输出格式：**
```
=== Kernel Drop Stack Statistics Tool ===
Filters: src_ip=10.132.114.11, dst_ip=10.132.114.12, protocol=TCP
Interval: 5 seconds, Duration: 60 seconds
Top stacks to show: 10

Attaching kprobe to kfree_skb...
BPF program loaded successfully

[2025-09-22 16:45:30] === Stack Statistics Report (Interval: 5.0s) ===
Total kfree_skb calls: 45
Filtered kfree_skb calls: 12

Top stack traces by count:

1. Count: 8 (66.7%)
   netif_receive_skb_core+0x145
   __netif_receive_skb+0x67
   process_backlog+0x89
   __napi_poll+0x12a
   net_rx_action+0x234
   __do_softirq+0x156

2. Count: 3 (25.0%)
   tcp_v4_rcv+0x234
   ip_local_deliver_finish+0x123
   ip_local_deliver+0x45
   ip_rcv_finish+0x67
   ip_rcv+0x89

3. Count: 1 (8.3%)
   udp_queue_rcv_skb+0x156
   __udp4_lib_rcv+0x234
   udp_rcv+0x67
   ip_local_deliver_finish+0x123
   ip_local_deliver+0x45

[2025-09-22 16:45:35] === Stack Statistics Report (Interval: 5.0s) ===
Total kfree_skb calls: 23
Filtered kfree_skb calls: 5

=== Final Summary ===
Total monitoring time: 60 seconds
Total intervals: 12
Overall filtered drops: 67
Average drops per interval: 5.6

Most frequent drop locations:
1. netif_receive_skb_core: 42 occurrences (62.7%)
2. tcp_v4_rcv: 18 occurrences (26.9%)
3. udp_queue_rcv_skb: 7 occurrences (10.4%)
```

#### 4.2.2 连接跟踪输出

**trace_conntrack.py 输出格式：**
```
=== Connection Tracking Monitor ===
Filter: src_ip=10.132.114.11, dst_ip=10.132.114.12, protocol=TCP
Relative time: enabled
Stack traces: enabled

Attaching to conntrack functions...
BPF program loaded successfully

Starting connection tracking...

[    0.000] CONNTRACK_NEW: 10.132.114.11:45678 -> 10.132.114.12:80 TCP
  State: NEW -> ESTABLISHED
  Timeout: 300 seconds
  Zone: 0
  Mark: 0x0

[    2.345] CONNTRACK_UPDATE: 10.132.114.11:45678 -> 10.132.114.12:80 TCP
  State: ESTABLISHED -> ESTABLISHED
  Timeout: 299 seconds
  Bytes: tx=1234, rx=5678
  Packets: tx=15, rx=23

[   45.678] CONNTRACK_DESTROY: 10.132.114.11:45678 -> 10.132.114.12:80 TCP
  State: ESTABLISHED -> DESTROYED
  Duration: 45.678 seconds
  Final stats: tx_bytes=12340, rx_bytes=56780, tx_packets=150, rx_packets=230

[   46.123] CONNTRACK_NEW: 10.132.114.11:34567 -> 10.132.114.12:443 TCP
  State: NEW -> SYN_SENT
  Timeout: 120 seconds
  Zone: 0
  Mark: 0x0

=== Connection Summary ===
Total connections tracked: 15
Active connections: 3
Completed connections: 12

Connection states distribution:
  - ESTABLISHED: 8 (53.3%)
  - SYN_SENT: 3 (20.0%)
  - TIME_WAIT: 2 (13.3%)
  - CLOSE_WAIT: 1 (6.7%)
  - FIN_WAIT: 1 (6.7%)

Average connection duration: 32.4 seconds
Total data transferred: 1.2 MB
```

### 4.3 OVS 监控输出格式

#### 4.3.1 OVS Upcall 延迟输出

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

#### 4.3.2 OVS Megaflow 输出

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

============================================================
=== Statistics Summary ===

Statistics:
   Total upcalls: 156
   Filtered upcalls: 45 (28.8%)
   Total flows: 23
   Filtered flows: 12 (52.2%)
   Upcall filter rate: 28.85%

Upcall types:
   MISS: 34 (75.6%)
   ACTION: 8 (17.8%)
   SLOW_PATH: 3 (6.7%)

Flow installation rate: 89.4% (flows/upcalls)
Average flow lifetime: 45.6 seconds
============================================================
```

### 4.4 KVM 虚拟化网络输出格式

#### 4.4.1 vhost-net 监控输出

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

### 4.5 Bpftrace 脚本输出格式

#### 4.5.1 事件跟踪输出

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

### 4.6 统计报告和汇总输出

#### 4.6.1 综合性能报告

```
================================================================================
                    eBPF 网络性能监控报告
================================================================================
监控时间: 2025-09-22 18:00:00 - 18:30:00 (30 分钟)
监控范围: 172.21.153.0/24 网段
协议: TCP, UDP, ICMP

=== 系统性能指标 ===
总数据包: 2,345,678
总数据量: 3.2 GB
平均 PPS: 1,303
平均吞吐量: 1.8 Mbps

=== 延迟统计 ===
平均延迟: 42.3 us
P50 延迟: 38.7 us
P95 延迟: 76.5 us
P99 延迟: 134.2 us
最大延迟: 456.7 us

=== 网络栈延迟分解 ===
1. VNET_RX 到 OVS_RX: 14.2 us (33.6%)
2. OVS_RX 到 FLOW_EXTRACT: 8.7 us (20.6%)
3. FLOW_EXTRACT 到 QDISC_ENQ: 11.3 us (26.7%)
4. QDISC_ENQ 到 TX_QUEUE: 4.9 us (11.6%)
5. TX_QUEUE 到 TX_XMIT: 3.2 us (7.6%)

=== 丢包统计 ===
总丢包: 45
丢包率: 0.0019%

丢包原因分布:
- NO_BUFFER: 23 (51.1%)
- SOCKET_FILTER: 12 (26.7%)
- CHECKSUM_ERROR: 7 (15.6%)
- OTHER: 3 (6.7%)

丢包位置分布:
- netif_receive_skb_core: 28 (62.2%)
- tcp_v4_rcv: 12 (26.7%)
- udp_queue_rcv_skb: 5 (11.1%)

=== OVS 性能指标 ===
Upcall 次数: 1,234
平均 Upcall 延迟: 23.4 us
Megaflow 命中率: 94.7%
Flow 安装成功率: 98.3%

=== 虚拟化性能指标 ===
vhost eventfd 事件: 5,678
Virtio-net 中断: 2,345
平均队列利用率: 67.8%
队列关联率: 96.4%

=== CPU 利用率 ===
网络处理 CPU 利用率:
- CPU 13: 45.6%
- CPU 15: 38.9%
- CPU 16: 23.4%
- CPU 19: 18.7%

=== 建议和优化方向 ===
1. 网络性能整体良好，延迟在正常范围内
2. 丢包率较低，主要由缓冲区不足引起
3. OVS Megaflow 命中率高，性能优良
4. 建议优化 VNET_RX 到 OVS_RX 阶段的延迟
5. 可考虑增加网络缓冲区大小以减少丢包
================================================================================
```

### 4.7 输出格式特点总结

#### 4.7.1 时间戳格式
- **绝对时间**: `[YYYY-MM-DD HH:MM:SS.mmm]` 格式
- **相对时间**: `[    0.000]` 格式（从启动开始的秒数）
- **内核时间戳**: `KTIME=1579020094156218ns` 格式

#### 4.7.2 网络信息格式
- **五元组**: `src_ip:src_port -> dst_ip:dst_port protocol`
- **MAC 地址**: `52:54:00:12:34:56` 格式
- **接口信息**: `device_name (ifindex=N) CPU=N`

#### 4.7.3 性能指标格式
- **延迟**: 以微秒 (us) 为单位
- **吞吐量**: 以 pps、Mbps、GB 等单位
- **百分比**: P50、P95、P99 等百分位数
- **直方图**: 使用 ASCII 字符绘制的分布图

#### 4.7.4 错误和异常信息
- **返回值**: 特定函数返回值常量
- **栈跟踪**: 函数名+偏移量 格式
- **错误码**: BPF 程序加载错误信息

这些输出格式提供了丰富的网络性能和问题诊断信息，帮助用户全面理解系统网络状态和性能特征。

## 5. 问题诊断和故障排查指南

### 5.1 常见问题诊断流程

#### 5.1.1 网络延迟问题诊断

**问题现象**: 网络访问反应慢、延迟高

**诊断步骤**:
1. **系统级延迟分析**
   ```bash
   # 整体网络延迟测量
   sudo python3 ebpf-tools/performance/system-network/system_network_latency_details.py \
     --src-ip SOURCE_IP --dst-ip DEST_IP --protocol tcp --direction both
   ```

2. **虚拟机网络延迟分解**
   ```bash
   # 虚拟机网络栈延迟分析
   sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_details.py \
     --vm-interface vnet0 --phy-interface eth0 \
     --src-ip VM_IP --dst-ip TARGET_IP --protocol tcp
   ```

3. **OVS 延迟分析**
   ```bash
   # OVS upcall 延迟监控
   sudo python3 ebpf-tools/ovs/ovs_upcall_latency_summary.py \
     --src-ip SOURCE_IP --dst-ip DEST_IP --protocol tcp
   ```

**延迟分析指标**:
- 正常范围: < 50us (局域网)
- 需要关注: 50-100us
- 异常情况: > 100us

#### 5.1.2 网络丢包问题诊断

**问题现象**: 数据包丢失、连接中断、吞吐量下降

**诊断步骤**:
1. **基本丢包检测**
   ```bash
   # 以太网层丢包监控
   sudo python3 ebpf-tools/linux-network-stack/packet-drop/eth_drop.py \
     --src-ip SOURCE_IP --dst-ip DEST_IP --l4-protocol tcp --verbose
   ```

2. **内核丢包栈分析**
   ```bash
   # 详细内核丢包栈统计
   sudo python3 ebpf-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats_summary_all.py \
     --src-ip SOURCE_IP --dst-ip DEST_IP --interval 5 --duration 60
   ```

3. **OVS 丢包监控**
   ```bash
   # OVS 数据路径丢包监控
   sudo python3 ebpf-tools/ovs/ovs-kernel-module-drop-monitor.py \
     --src-ip SOURCE_IP --dst-ip DEST_IP --protocol tcp
   ```

**常见丢包原因及解决方案**:
- `NO_BUFFER`: 缓冲区不足 → 调整 ring buffer 大小
- `SOCKET_FILTER`: 过滤器拦截 → 检查防火墙规则
- `CHECKSUM_ERROR`: 校验和错误 → 检查网卡卸载配置

#### 5.1.3 虚拟化网络问题诊断

**问题现象**: 虚拟机网络性能下降、中断延迟高

**诊断步骤**:
1. **vhost-net 性能分析**
   ```bash
   # vhost 队列关联分析
   sudo python3 ebpf-tools/kvm-virt-network/vhost-net/vhost_queue_correlation_details.py \
     --device vhost-1 --interval 2

   # vhost eventfd 监控
   sudo python3 ebpf-tools/kvm-virt-network/vhost-net/vhost_eventfd_count.py \
     --interval 5
   ```

2. **virtio-net 驱动分析**
   ```bash
   # virtio-net 轮询效率监控
   sudo python3 ebpf-tools/kvm-virt-network/virtio-net/virtnet_poll_monitor.py

   # virtio-net 中断监控
   sudo python3 ebpf-tools/kvm-virt-network/virtio-net/virtnet_irq_monitor.py
   ```

3. **TUN/TAP 设备分析**
   ```bash
   # TUN 环形缓冲区监控
   sudo python3 ebpf-tools/kvm-virt-network/tun/tun_ring_monitor.py \
     --device tun0
   ```

### 5.2 监控最佳实践

#### 5.2.1 生产环境监控

**性能影响最小化**:
```bash
# 使用较大的采样间隔
sudo python3 ebpf-tools/performance/system-network/system_network_perfomance_metrics.py \
  --interval 10 --duration 300

# 禁用详细栈跟踪
sudo python3 ebpf-tools/linux-network-stack/packet-drop/eth_drop.py \
  --no-stack-trace
```

**分层测量**:
1. **基线性能采集** : 使用若干问题域/模块的 summary 版本测量工具，获取问题初筛结果，确定需要做精细 detail 信息测量的范围，即如何进一步过滤
2. **问题时段详细分析** : 部署特定问题域的 details 版测量工具，使用 summary 筛查结果作为过滤器，进一步减小对 workload 影响
3. **持续监控和报警** : 合理设计的 summary metric ， histogram 形式统计， 部署关键模块，核心指标测量。 

#### 5.2.2 数据分析工作流

**数据收集**:
```bash
# 将输出保存到文件
sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_details.py \
  --vm-interface vnet0 --phy-interface eth0 \
  --src-ip 172.21.153.114 --dst-ip 172.21.153.113 \
  --duration 300 > latency_analysis_$(date +%Y%m%d_%H%M%S).log
```

**数据关联分析**:
1. 将性能数据与系统负载关联
2. 将丢包事件与网络流量关联
3. 将虚拟化指标与客户机性能关联

### 5.3 故障排查检查单

#### 5.3.1 网络延迟高检查单

□ **基础检查**
- [ ] 检查系统 CPU 利用率
- [ ] 检查网卡队列状态
- [ ] 检查内存使用情况

□ **网络栈分析**
- [ ] 使用 system_network_latency_details.py 分析各阶段延迟
- [ ] 检查 OVS upcall 延迟
- [ ] 分析 virtio-net 中断处理，vring 信息统计

□ **虚拟化检查**
- [ ] 检查 vhost-net 线程详情，关联 tun 队列 && virtio-net 队列详情
- [ ] 分析 virtio-net 中断合并
- [ ] 检查 TUN/TAP 环形缓冲区

#### 5.3.2 网络丢包检查单

□ **丢包检测**
- [ ] 使用 eth_drop.py 检测丢包详情全量信息
- [ ] 使用 kernel_drop_stack_stats_summary_all.py 分析详细丢包栈, 分层按流量/dev 等聚合的丢包 rootcause 统计
- [ ] 检查 qdisc 队列丢包

□ **丢包原因分析**
- [ ] 缓冲区不足 (NO_BUFFER)
- [ ] 过滤器拦截 (SOCKET_FILTER)
- [ ] 校验和错误 (CHECKSUM_ERROR)
- [ ] 其他原因分析

□ **OVS 相关检查**
- [ ] 检查 OVS 数据路径丢包
- [ ] 分析 megaflow 生命周期
- [ ] 检查 kernel megaflow table 表项状态更新

#### 5.3.3 虚拟化性能检查单

□ **vhost-net 检查**
- [ ] 检查 vhost worker 线程 CPU 亲和性
- [ ] 分析 eventfd 通知频率
- [ ] 检查队列对关联性

□ **virtio-net 检查**
- [ ] 检查 NAPI 轮询效率
- [ ] 分析中断合并效果
- [ ] 检查多队列配置

□ **TUN/TAP 检查**
- [ ] 检查环形缓冲区利用率
- [ ] 分析 GSO/TSO 卸载状态
- [ ] 检查设备队列映射

### 5.4 常见错误和解决方案

#### 5.4.1 BPF 程序加载失败

**错误信息**: `bpf: Failed to load program: Permission denied`

**解决方案**:
1. 检查是否使用 root 权限
2. 检查内核版本是否支持 BPF
3. 检查 BCC 安装是否完整

#### 5.4.2 程序挂起

**错误信息**: `Cannot attach to function: No such file or directory`

**解决方案**:
1. 检查内核符号表是否可用
2. 检查函数名是否正确
3. 检查内核模块是否加载

#### 5.4.3 数据采集异常

**现象**: 无数据或数据不完整

**解决方案**:
1. 检查网络流量是否匹配过滤器
2. 调整采样间隔和时长
3. 检查系统资源使用情况

## 6. 部署和要求

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
sudo apt install -y kernel-devel-$(uname -r) kernel-header-$(uname -r) 

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
sudo python3 ebpf-tools/performance/system-network/system_network_icmp_rtt.py --help
```

### 6.4 安全考虑和最佳实践

#### 6.4.1 权限管理
- **Root 权限**: 所有 eBPF 工具需要 root 权限
- **Capability 管理**: 可考虑使用 CAP_BPF 和 CAP_SYS_ADMIN
- **用户隔离**: 建议使用专用的监控用户账号

#### 6.4.2 性能影响控制
- **采样间隔**: 生产环境建议使用 5-10 秒间隔
- **监控时长**: 单次监控不超过 5 分钟
- **资源限制**: 监控 CPU 和内存使用情况
- **并发数量**: 同时运行的工具数量不超过 3-5 个

#### 6.4.3 生产环境建议
```bash
# 生产环境监控示例
sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_summary.py \
  --vm-interface vnet0 --phy-interface eth0 \
  --src-ip 10.0.0.100 --dst-ip 10.0.0.200 \
  --interval 10 --duration 300 \
  > /var/log/network-latency-$(date +%Y%m%d_%H%M%S).log 2>&1 &

# 设置资源限制
sudo systemd-run --scope -p MemoryLimit=512M -p CPUQuota=50% \
  python3 ebpf-tools/linux-network-stack/packet-drop/eth_drop.py \
  --src-ip 10.0.0.100 --interval 5 --duration 300
```

### 6.5 故障排查和支持

#### 6.5.1 常见问题解决

**BCC 导入错误**:
```bash
# 检查 Python 路径
sudo python3 -c "import sys; print(sys.path)"
sudo find /usr -name "*bcc*" -type d

# 重新安装 BCC
sudo yum reinstall python3-bcc bcc-tools  # openEuler/CentOS
sudo apt reinstall python3-bpfcc bpfcc-tools  # Ubuntu
```

**内核符号问题**:
```bash
# 检查内核符号表
sudo ls -la /proc/kallsyms
sudo cat /proc/kallsyms | grep "netif_receive_skb"

# 安装内核调试信息
sudo yum install kernel-debuginfo-$(uname -r)  # openEuler/CentOS
sudo apt install linux-image-$(uname -r)-dbg  # Ubuntu
```

#### 6.5.2 日志和调试

**启用详细日志**:
```bash
# BCC 调试模式
export BCC_DEBUG=1
sudo -E python3 ebpf-tools/performance/system-network/system_network_latency_details.py \
  --src-ip 10.0.0.100 --dst-ip 10.0.0.200 --verbose

# bpftrace 调试模式
sudo bpftrace -v ebpf-tools/other/trace-abnormal-arp.bt
```

**性能分析**:
```bash
# 监控工具资源使用
perf top -p $(pgrep python3)
top -p $(pgrep bpftrace)

# 内核性能分析
sudo perf record -g -a -- sleep 30
sudo perf report
```

#### 6.5.3 社区支持

- **项目仓库**: 提交 Issue 和 Pull Request
- **文档反馈**: 报告文档错误或改进建议
- **技术交流**: 参与 eBPF 和网络性能监控技术讨论
- **贡献指南**: 查看 CONTRIBUTING.md 了解如何贡献代码

### 6.6 版本兼容性

#### 6.6.1 内核版本支持

| 内核版本 | 支持状态 | 说明 |
|------------|-----------|------|
| 4.19.90 (openEuler) | 全面支持 | 主要适配目标 |
| 5.4.x | 支持 | 所有功能可用 |
| 5.10.x LTS | 支持 | 推荐使用 |
| 4.18.x | 部分支持 | 部分新特性不可用 |
| < 4.18 | 不支持(redhat 系系统部分工具支持) | BPF 功能不完整，仅 redhat 系部分支持 |

#### 6.6.2 工具版本支持

| 组件 | 最低版本 | 推荐版本 | 说明 |
|------|----------|----------|------|
| BCC | 0.15.0 | 0.25.0+ | 较新版本更好 |
| bpftrace | 0.10.0 | 0.16.0+ | 支持更多语言特性,部分实现优化 |
| Python | 2.7 | 3.8+ | 推荐使用 Python 3, 依赖 package: python-bcc 或 python3-bcc，oe 系统 python3-bcc |
| LLVM | 6.0 | 12.0+ | 更好的 BPF 编译支持 |

该项目为虚拟化环境的网络性能监控和故障排查提供了全面的 eBPF 工具集，通过合理的部署和使用，可以有效提升网络问题诊断的效率和准确性。