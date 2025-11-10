# Crash Vmcore 网络数据包分析指南

## 概述

本指南用于分析网络相关的内核崩溃，特别是从 vmcore 中提取数据包信息和线程数据路径。

## 前提条件

- 已安装 crash 工具
- 有匹配的 vmlinux 内核符号文件
- 已打开 vmcore: `crash /usr/lib/debug/lib/modules/$(uname -r)/vmlinux /path/to/vmcore`

## 分析步骤

### 1. 线程数据路径信息分析

#### 1.1 查看当前线程/进程信息

```bash
# 查看崩溃时的进程信息
crash> ps

# 查看当前 CPU 和进程上下文
crash> sys

# 查看所有 CPU 状态
crash> sys -c

# 查看当前线程详细信息
crash> bt -f
```

#### 1.2 查看中断上下文

从你的调用栈看，这是在软中断 (softirq) 上下文中处理网络数据包：

```bash
# 查看软中断统计
crash> p per_cpu__softirq_stat

# 查看 NAPI 状态
crash> p softnet_data

# 对于每个 CPU 查看 softnet_data
crash> p &softnet_data:0
crash> p &softnet_data:1
# ... 根据 CPU 数量继续
```

#### 1.3 查看网络设备状态

从调用栈中提取网络设备信息：

```bash
# 在调用栈帧 #27 (virtnet_poll) 中查看参数
crash> bt -f
# 找到 virtnet_poll 的栈帧，查看 napi_struct 参数

# 假设 napi_struct 地址为 0xXXXXXXXX
crash> struct napi_struct 0xXXXXXXXX

# 从 napi_struct 获取 net_device
# 查看 net_device 结构
crash> struct net_device <地址>
```

#### 1.4 完整数据路径时间线

```bash
# 查看最近的 trace 事件（如果启用了）
crash> log | grep -A 5 -B 5 "net\|skb\|virtio"

# 查看 jiffies 和时间戳
crash> p jiffies
crash> p jiffies_64
```

### 2. 提取数据包完整信息

#### 2.1 定位 sk_buff 地址

关键是从调用栈中提取 sk_buff 指针。重点关注以下栈帧：

```bash
# 显示详细的栈帧和参数
crash> bt -f

# 重点关注这些函数的第一个参数（都是 struct sk_buff *skb）：
# - tcp_gso_segment (#8)
# - inet_gso_segment (#9, #12)
# - skb_mac_gso_segment (#10, #13)
# - skb_udp_tunnel_segment (#11)
# - __skb_gso_segment (#14)
# - validate_xmit_skb (#15)
```

#### 2.2 从栈帧提取 sk_buff 地址

**方法 1：使用 bt -f 查看详细栈信息**

```bash
# 显示所有栈帧的详细信息（包括参数和局部变量）
crash> bt -f

# 在输出中查找相关函数的栈帧，例如：
# #15 [ff3ca05846b449a8] validate_xmit_skb at ffffffffaa04d15e
#     ff3ca05846b449b0: skb = 0xffff8880a1234567
#
# 或者显示为：
#     ff3ca05846b449b0: 0xffff8880a1234567 (第一个参数通常是 skb)
```

**方法 2：从栈地址直接读取**

对于 x86_64 架构，函数的第一个参数（skb 指针）传递方式：
- 前 6 个参数通过寄存器传递：RDI, RSI, RDX, RCX, R8, R9
- 第一个参数（struct sk_buff *skb）在 RDI 寄存器，但可能已被保存到栈上

```bash
# 从 bt 输出中获取栈帧地址，例如 #15 的地址是 ff3ca05846b449a8
# 读取栈上的内容（通常前几个字是参数）
crash> rd ff3ca05846b449a8 20

# 输出示例：
# ff3ca05846b449a8:  0000000000000000 ffff8880a1234567  ................
# ff3ca05846b449b8:  0000000000000001 ff3ca05846b449e0  ................
#
# 第二个 8 字节（0xffff8880a1234567）通常是 skb 指针
```

**方法 3：反汇编函数查看参数使用**

```bash
# 反汇编函数开头部分，查看如何使用参数
crash> dis tcp_gso_segment | head -30

# 查找类似的指令：
# mov %rdi, -0x8(%rbp)    # 将第一个参数（RDI）保存到栈上
# 或
# mov %rdi, %rbx          # 将第一个参数移到其他寄存器
```

**方法 4：使用符号信息（如果可用）**

```bash
# 有些 crash 版本支持查看特定地址处的局部变量
# 使用栈帧地址查询
crash> sym <函数名>
crash> rd -s <栈帧地址> 20
```

#### 2.3 分析 sk_buff 结构体

一旦获得 sk_buff 地址（假设为 `0xffff888012345678`）：

```bash
# 查看完整的 sk_buff 结构
crash> struct sk_buff 0xffff888012345678

# 关键字段：
# - len: 数据包总长度
# - data_len: 分片数据长度
# - mac_header: MAC 头偏移
# - network_header: IP 头偏移
# - transport_header: 传输层头偏移
# - head, data, tail, end: 缓冲区指针
```

#### 2.4 提取数据包头部信息

```bash
# 假设 skb 地址为 0xffff888012345678
crash> struct sk_buff.head 0xffff888012345678
crash> struct sk_buff.data 0xffff888012345678
crash> struct sk_buff.mac_header 0xffff888012345678
crash> struct sk_buff.network_header 0xffff888012345678
crash> struct sk_buff.transport_header 0xffff888012345678

# 读取实际数据包内容
# data 指针指向当前层的开始
# 读取 MAC 头 (14 字节 Ethernet II)
crash> rd -8 <data地址> 14

# 读取 IP 头 (通常 20 字节，但要检查 IHL)
crash> rd -8 <network_header地址> 20

# 读取 TCP/UDP 头
crash> rd -8 <transport_header地址> 20
```

#### 2.5 解析具体协议头

**解析 IP 头：**

```bash
# 假设 IP 头地址为 head + network_header
# 计算实际地址
crash> eval <head地址> + <network_header偏移>

# 以 iphdr 结构体方式查看
crash> struct iphdr <IP头地址>

# 手动解析关键字段（以十六进制显示）
crash> rd -8 <IP头地址> 20
# 字节 0: 版本和头长度 (0x45 表示 IPv4, 20字节头)
# 字节 9: 协议 (6=TCP, 17=UDP, 1=ICMP)
# 字节 12-15: 源 IP
# 字节 16-19: 目的 IP
```

**解析 TCP 头：**

```bash
# 计算 TCP 头地址
crash> eval <head地址> + <transport_header偏移>

# 以 tcphdr 结构体方式查看
crash> struct tcphdr <TCP头地址>

# 关键字段：
# - source: 源端口
# - dest: 目的端口
# - seq: 序列号
# - ack_seq: 确认号
# - flags: TCP 标志位
```

**解析隧道头（如 VXLAN）：**

从调用栈看有 `skb_udp_tunnel_segment`，可能是 VXLAN 或其他 UDP 隧道：

```bash
# 检查 skb 的封装类型
crash> struct sk_buff.encapsulation 0xffff888012345678
crash> struct sk_buff.inner_network_header 0xffff888012345678
crash> struct sk_buff.inner_transport_header 0xffff888012345678

# 如果有内部头，计算并读取
crash> eval <head地址> + <inner_network_header偏移>
crash> struct iphdr <内部IP头地址>
```

#### 2.6 提取完整数据包二进制内容

```bash
# 确定数据包总长度
crash> struct sk_buff.len 0xffff888012345678
# 假设 len = 1500

# 从 MAC 头开始读取整个数据包
# 计算 MAC 头地址
crash> eval <head地址> + <mac_header偏移>

# 读取完整数据包（以 16 进制）
crash> rd -8 <MAC头地址> <len>

# 或者保存到文件（如果 crash 支持）
# 你可能需要手动复制输出，然后用脚本转换为 pcap 格式
```

#### 2.7 转换为 PCAP 格式（可选）

将提取的十六进制数据转换为 pcap 格式以便用 Wireshark 分析：

```bash
# 创建 pcap 文件头（在宿主机上执行）
# PCAP 格式参考：https://wiki.wireshark.org/Development/LibpcapFileFormat

# 1. 保存 crash 输出的十六进制数据
crash> rd -8 <数据包地址> <长度> > /tmp/packet_hex.txt

# 2. 在宿主机创建转换脚本（见后续 Python 脚本）
```

### 3. GSO 相关信息分析

由于崩溃发生在 GSO 分段过程中，需要特别关注：

```bash
# 查看 skb 的 GSO 信息
crash> struct sk_buff.gso_size 0xffff888012345678
crash> struct sk_buff.gso_segs 0xffff888012345678
crash> struct sk_buff.gso_type 0xffff888012345678

# gso_type 的常见值：
# SKB_GSO_TCPV4 = 0x01
# SKB_GSO_UDP = 0x02
# SKB_GSO_DODGY = 0x04
# SKB_GSO_TCP_ECN = 0x08
# SKB_GSO_TCPV6 = 0x10
# SKB_GSO_UDP_TUNNEL = 0x40
# SKB_GSO_UDP_TUNNEL_CSUM = 0x80

# 查看分片信息
crash> struct sk_buff.frag_list 0xffff888012345678
crash> struct sk_buff.nr_frags 0xffff888012345678
crash> struct sk_buff.frags 0xffff888012345678
```

### 4. 辅助脚本

#### 4.1 十六进制转 PCAP 的 Python 脚本

创建 `hex_to_pcap.py`：

```python
#!/usr/bin/env python3
import struct
import sys

def hex_to_pcap(hex_file, pcap_file):
    # PCAP 全局头（24 字节）
    pcap_header = struct.pack(
        'IHHiIII',
        0xa1b2c3d4,  # magic_number
        2,           # version_major
        4,           # version_minor
        0,           # thiszone (GMT to local correction)
        0,           # sigfigs (accuracy of timestamps)
        65535,       # snaplen (max length of captured packets)
        1            # network (1 = Ethernet)
    )

    # 读取十六进制数据
    with open(hex_file, 'r') as f:
        hex_data = ''.join(f.read().split())

    # 转换为字节
    packet_data = bytes.fromhex(hex_data)
    packet_len = len(packet_data)

    # PCAP 包头（16 字节）
    packet_header = struct.pack(
        'IIII',
        0,           # ts_sec (timestamp seconds)
        0,           # ts_usec (timestamp microseconds)
        packet_len,  # incl_len (number of octets of packet saved)
        packet_len   # orig_len (actual length of packet)
    )

    # 写入 PCAP 文件
    with open(pcap_file, 'wb') as f:
        f.write(pcap_header)
        f.write(packet_header)
        f.write(packet_data)

    print(f"Created {pcap_file} with {packet_len} bytes packet")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <hex_file> <output.pcap>")
        sys.exit(1)
    hex_to_pcap(sys.argv[1], sys.argv[2])
```

#### 4.2 Crash 辅助命令脚本

创建 `crash_commands.txt`：

```bash
# 自动化分析脚本，在 crash 中使用: < crash_commands.txt

# 1. 系统和进程信息
sys
ps
bt

# 2. 查找 sk_buff
bt -f

# 3. 网络设备信息
p softnet_data

# 注意：需要手动替换 <skb_addr> 为实际地址
# struct sk_buff <skb_addr>
# rd -8 <data_addr> 1500
```

## 实际分析示例

假设你的崩溃调用栈是：

```
#8 [ff3ca05846b447e0] tcp_gso_segment at ffffffffaa1219c5
```

### 步骤 1：获取 skb 地址

```bash
crash> frame 8
crash> p skb
$1 = (struct sk_buff *) 0xffff8880a1234567
```

### 步骤 2：查看 skb 结构

```bash
crash> struct sk_buff 0xffff8880a1234567
struct sk_buff {
  len = 9014,
  data_len = 0,
  mac_header = 0,
  network_header = 14,
  transport_header = 34,
  head = 0xffff8880b7654000,
  data = 0xffff8880b7654000,
  ...
  gso_size = 1448,
  gso_segs = 0,
  gso_type = 65,  # SKB_GSO_TCPV4 | SKB_GSO_UDP_TUNNEL
  encapsulation = 1,
  ...
}
```

### 步骤 3：提取 IP 和 TCP 头

```bash
# 外部 IP 头地址 = head + network_header
crash> eval 0xffff8880b7654000 + 14
0xffff8880b765400e

crash> struct iphdr 0xffff8880b765400e
struct iphdr {
  ihl = 5,
  version = 4,
  tos = 0,
  tot_len = 9000,
  id = 12345,
  frag_off = 0,
  ttl = 64,
  protocol = 17,  # UDP (隧道)
  check = 0x1234,
  saddr = 0x0a846e0b,  # 10.132.110.11
  daddr = 0x0a846e0c,  # 10.132.110.12
}

# TCP 头地址 = head + transport_header
crash> eval 0xffff8880b7654000 + 34
0xffff8880b7654022

crash> struct tcphdr 0xffff8880b7654022
# 或者如果是 UDP 隧道
crash> struct udphdr 0xffff8880b7654022

# 内部 IP 头（如果有封装）
crash> eval 0xffff8880b7654000 + <inner_network_header>
crash> struct iphdr <内部IP地址>
```

### 步骤 4：提取完整数据包

```bash
# 从 MAC 头开始读取 100 字节（查看头部信息）
crash> rd -8 0xffff8880b7654000 100

# 读取整个数据包
crash> rd -8 0xffff8880b7654000 9014
```

## 常见问题

### Q1: 无法找到 sk_buff 地址

A: 尝试：
- 使用 `bt -f` 显示完整栈帧
- 查看寄存器内容 `info registers`
- 检查栈上的指针 `rd <栈地址> 50`

### Q2: 数据包被分段（frag_list）

A: 需要遍历分片链表：

```bash
crash> struct sk_buff.frag_list 0xffff8880a1234567
frag_list = 0xffff8880a9876543

crash> struct sk_buff 0xffff8880a9876543
# 继续查看下一个分片
```

### Q3: 数据包在 page frags 中

A: 查看 `skb_shared_info`：

```bash
# skb_shared_info 位于 skb->end
crash> struct sk_buff.end 0xffff8880a1234567
end = 0xffff8880b7654800

crash> struct skb_shared_info 0xffff8880b7654800
```

## 参考资料

- Linux 内核文档：`Documentation/networking/skbuff.txt`
- Crash 工具手册：`man crash`
- PCAP 文件格式：https://wiki.wireshark.org/Development/LibpcapFileFormat
- sk_buff 结构定义：`include/linux/skbuff.h`

## 相关工具

此仓库中的相关 eBPF 工具可用于预防和捕获类似问题：

- `ebpf-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats_summary.py` - 监控内核丢包
- `ebpf-tools/performance/system-network/tcp_connection_analyzer.py` - 分析 TCP 连接
- `ebpf-tools/kvm-virt-network/tun/tun-abnormal-gso-type.bt` - 检测异常 GSO 类型

---

## 附录：实际案例分析

### 案例：GSO 元数据不一致导致的崩溃

**症状**：
- 崩溃发生在 `validate_xmit_skb` → `__skb_gso_segment` → `tcp_gso_segment`
- 数据包从 virtio_net 接收，经过 IP 转发后在输出时崩溃

**关键发现**：

1. **数据包基本信息**：
   ```
   skb->len = 10 (线性数据)
   skb->data_len = 31370 (分片数据)
   总大小 ≈ 31KB
   ```

2. **多层封装结构**（从外到内）：
   - **外层**：TCP 数据流（10.90.10.44:24173 → 10.70.89.82:80）
   - **第一层内封装**：IPIP 隧道（10.70.2.22 → 10.70.2.24）
   - **第二层内封装**：TCP 连接（172.16.52.70:34885 → 172.16.168.54:49458）
   - **应用层**：Istio/Envoy 服务网格遥测数据（Protobuf 格式）

3. **GSO 配置**：
   ```
   gso_type = 0x403 (1027)
     = SKB_GSO_TCPV4 (0x01)
     + SKB_GSO_DODGY (0x02)
     + SKB_GSO_UDP_TUNNEL (0x400)
   gso_size = 1348
   gso_segs = 0
   ```

4. **致命问题 - 元数据不一致**：
   ```
   ✗ encapsulation = 0         (应该为 1！)
   ✗ inner_mac_header = 128    (等于 mac_header，不正确！)
   ✗ inner_network_header = 142 (等于 network_header，不正确！)
   ✓ gso_type 包含 SKB_GSO_UDP_TUNNEL
   ```

**根本原因**：

skb 的 GSO 类型标记为 UDP_TUNNEL（隧道封装），但 `encapsulation` 标志为 0，且内部头部偏移与外部头部相同。这导致 GSO 分段代码尝试按隧道包处理，但找不到正确的内部头部位置，最终访问无效内存导致崩溃。

可能的触发场景：
1. 从虚拟机接收的数据包，GSO offload 被标记为 DODGY（不可信）
2. 数据包经过某种隧道处理但元数据未正确更新
3. 在 IP 转发过程中，skb 元数据被错误修改
4. 驱动程序或虚拟化层的 bug 导致 GSO 元数据不一致

**完整的数据包结构**：

```
[外层以太网头] (offset 128)
  dst_mac: 00:00:00:00:00:00 (异常 - 全0)
  src_mac: 00:00:00:00:00:00 (异常 - 全0)
  ethertype: 0x0800 (IP)

[外层 IP 头] (offset 142)
  src: 10.90.10.44
  dst: 10.70.89.82
  protocol: TCP
  length: 31422

[外层 TCP 头] (offset 162)
  src_port: 24173
  dst_port: 80
  flags: PSH+ACK
  tcp_header_len: 32 (8 * 4)

[TCP Payload - IPIP 隧道]
  [第一层内 IP 头]
    src: 10.70.2.22
    dst: 10.70.2.24
    protocol: IPIP (4)
    length: 1467

  [第二层内 IP 头]
    src: 172.16.52.70
    dst: 172.16.168.54
    protocol: TCP (6)
    length: 1447

  [内部 TCP 头]
    src_port: 34885
    dst_port: 49458
    flags: PSH+ACK

  [应用数据 - Istio 遥测]
    destination_principal: spiffe://cluster...
    destination_workload: contents-pr...
    on_version: unknown
```

**预防措施**：

1. 在接收路径检测 GSO 元数据一致性：
   ```c
   if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL) {
       WARN_ON(!skb->encapsulation);
       WARN_ON(skb->inner_network_header == skb->network_header);
   }
   ```

2. 使用此仓库的 eBPF 工具监控：
   ```bash
   # 检测异常的 GSO 类型
   sudo bpftrace ebpf-tools/kvm-virt-network/tun/tun-abnormal-gso-type.bt

   # 监控 GSO 分段
   sudo python3 ebpf-tools/performance/system-network/gso_monitor.py
   ```

3. 在虚拟化环境中禁用不稳定的 GSO offload：
   ```bash
   ethtool -K ens4 tx-udp-tnl-segmentation off
   ethtool -K ens4 tx-udp-tnl-csum-segmentation off
   ```
