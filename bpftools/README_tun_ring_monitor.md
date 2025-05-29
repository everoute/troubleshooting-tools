# TUN Ring Monitor 🔍

## 概述

`tun_ring_monitor.py` 是一个基于 BCC/eBPF 的工具，用于监控 TUN 设备的 ptr_ring 状态，特别是检测环满(ring full)条件。该工具使用验证过的逻辑组件，能够精准地检测 TUN 设备传输队列中的瓶颈问题。

## 核心功能

- ✅ **设备过滤**: 基于 `iface_netstat.c` 验证过的高效设备过滤逻辑
- ✅ **环满检测**: 基于内核 `__ptr_ring_full` 逻辑的精确检测
- ✅ **5-tuple过滤**: 支持源/目标IP、端口、协议的精细过滤
- ✅ **包头解析**: 基于 `icmp_rtt_latency.py` 验证过的解析逻辑
- ✅ **多队列支持**: 自动检测和监控多队列 TUN 设备

## 技术架构

### 设备过滤逻辑 (iface_netstat.c)
使用64位整数比较代替字符串比较，提供高效的设备名过滤：
```c
union name_buf {
    char name[IFNAMSIZ];
    struct { u64 hi; u64 lo; } name_int;
};
```

### 环满检测逻辑 (内核 __ptr_ring_full)
```c
// Ring 满的条件：queue[producer] != NULL
void *producer_slot = queue[producer];
bool ring_full = (producer_slot != NULL);
```

### 包头解析 (icmp_rtt_latency.py)
- 支持 IPv4 TCP/UDP 协议
- 正确处理可变长度 IP 头部
- 安全的内核内存访问

## 用法示例

### 基本监控 (仅环满事件)
```bash
# 监控所有 TUN 设备的环满条件
sudo ./tun_ring_monitor.py --device vnet12

# 输出结果只有当 ptr_ring 满时才会显示
```

### 详细监控 (所有事件)
```bash
# 显示指定设备的所有传输事件
sudo ./tun_ring_monitor.py --device vnet12 --all

# 会显示每个 tun_net_xmit 调用的详细信息
```

### 5-tuple 过滤
```bash
# 监控特定源IP的流量
sudo ./tun_ring_monitor.py --device vnet12 --src-ip 192.168.1.100 --all

# 监控特定端口
sudo ./tun_ring_monitor.py --device vnet11 --dst-port 80

# 多条件组合
sudo ./tun_ring_monitor.py --device vnet12 --src-ip 10.0.0.1 --dst-port 443 --protocol tcp --all
```

## 输出解释

### 正常状态输出
```
================================================================================
📊 TUN Ring Status
Time: 14:25:30.123
Process: qemu-kvm (PID: 12345)
Device: vnet12
Queue: 0
SKB Address: 0xffff888123456789

PTR Ring Details:
  Size: 1024
  Producer: 100
  Consumer Head: 95
  Consumer Tail: 95
  Queue[Producer] Ptr: 0x0
  Status: ✅ Available (queue[producer] == NULL), 5% used
================================================================================
```

### 环满警告输出
```
================================================================================
🚨 TUN RING FULL DETECTED! 🚨
Time: 14:25:30.456
Process: qemu-kvm (PID: 12345)
Device: vnet12
Queue: 1
SKB Address: 0xffff888987654321

5-Tuple Info:
  Source: 192.168.1.100:12345
  Destination: 10.0.0.1:80
  Protocol: TCP

PTR Ring Details:
  Size: 1024
  Producer: 512
  Consumer Head: 256
  Consumer Tail: 256
  Queue[Producer] Ptr: 0xffff888abcdef123
  Status: ⚠️ FULL (queue[producer] != NULL)
================================================================================
```

## 参数说明

| 参数 | 类型 | 说明 |
|------|------|------|
| `--device, -d` | 字符串 | 目标设备名 (如 vnet12) |
| `--src-ip` | IP地址 | 源IP过滤 |
| `--dst-ip` | IP地址 | 目标IP过滤 |
| `--src-port` | 数字 | 源端口过滤 |
| `--dst-port` | 数字 | 目标端口过滤 |
| `--protocol` | tcp/udp | 协议过滤 |
| `--all` | 布尔 | 显示所有事件 (不仅仅是环满) |
| `--verbose, -v` | 布尔 | 详细输出 |

## 故障排除

### 权限问题
```bash
# 确保以 root 权限运行
sudo ./tun_ring_monitor.py --device vnet12
```

### BCC 依赖
```bash
# Ubuntu/Debian
sudo apt-get install bpfcc-tools python-bpfcc

# CentOS/RHEL
sudo yum install bcc-tools python-bcc
```

### 设备名检查
```bash
# 查看当前 TUN 设备
ip link show type tun

# 确认设备名正确
```

### 内核支持检查
```bash
# 检查内核是否支持 eBPF
ls /sys/kernel/debug/tracing/events/syscalls/

# 检查 kprobe 支持
echo 'p:test_probe tun_net_xmit' > /sys/kernel/debug/tracing/kprobe_events
```

## 性能考虑

- **低开销**: 仅在环满或符合过滤条件时输出
- **高效过滤**: 使用64位整数比较设备名
- **安全访问**: 使用 `bpf_probe_read_kernel` 安全访问内核内存
- **智能偏移**: 使用多个偏移量自动适配不同内核版本

## 技术细节

### ptr_ring 结构体定位
程序使用多个可能的偏移量来定位 `tfile` 结构中的 `ptr_ring`：
```c
int ring_offsets[] = {400, 440, 480, 520, 560, 600, 640, 680};
```

### 环状态验证
- 检查环大小是否为2的幂
- 验证生产者/消费者指针范围
- 确保队列指针非空

### 兼容性
- 支持多队列 TUN 设备
- 兼容不同内核版本的结构体布局
- 自动回退到默认值当结构体访问失败时

## 参考实现

该工具基于以下验证过的实现：
- **设备过滤**: `iface_netstat.c` 的 union name_buf 方法
- **包头解析**: `icmp_rtt_latency.py` 的 skb 解析逻辑  
- **结构体定义**: `tun-vhost.bt` 的 TUN 结构体布局

## 远程测试

推荐在以下环境进行测试：
```bash
# 远程测试环境
smartx@192.168.70.33:/home/smartx/lcc/

# 使用 tcpdump 验证流量
sudo tcpdump -i vnet12 -c 10

# 同时运行监控工具
sudo ./tun_ring_monitor.py --device vnet12 --all
``` 