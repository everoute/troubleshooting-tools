# 系统网络TCP/UDP延迟测量工具设计文档

## 概述

本文档描述了一个专门针对系统网络的TCP/UDP协议单向延迟分段测量工具的设计。该工具基于成功的ICMP延迟测量工具（icmp_rtt_latency.py）的架构，结合虚拟机网络延迟工具（vm_network_latency.py）的TCP/UDP数据包唯一标识技术，实现对系统网络环境下TCP和UDP流量的精确数据包级延迟追踪。

## 1. 系统架构设计

### 1.1 数据路径分析

系统网络数据路径与虚拟机网络的主要区别在于不涉及TUN设备，直接通过系统协议栈进行处理：

```
应用程序 <-> 协议栈 <-> OVS内核模块 <-> OVS用户态(可选) <-> 物理网卡
```

**TX方向（系统发出）：**
```
应用程序 → 协议栈 → IP层发送 → OVS处理 → 物理网卡发送
```

**RX方向（系统接收）：**
```
物理网卡接收 → OVS处理 → 协议栈接收 → 应用程序
```

### 1.2 与现有工具的对比

| 特性 | icmp_rtt_latency.py | vm_network_latency.py | system_tcp_udp_latency |
|------|-------------------|---------------------|----------------------|
| 协议支持 | 仅ICMP | TCP/UDP/ICMP | **TCP/UDP** |
| 网络环境 | 系统网络 | 虚拟机网络 | **系统网络** |
| 数据包标识 | ICMP ID/SEQ | 协议特定唯一标识 | **TCP/UDP特定标识** |
| 起始点 | ip_send_skb | netif_receive_skb(vnet) | **ip_send_skb** |
| 终点 | icmp_rcv | tun_net_xmit(vnet) | **tcp_v4_rcv/udp_rcv** |
| 测量类型 | 往返延迟 | 单向延迟 | **单向延迟** |

### 1.3 关键探测点设计

#### TX方向探测点序列（系统发出）：
1. **STAGE_0**: `ip_send_skb` - IP层发送数据包
2. **STAGE_1**: `internal_dev_xmit` - 内部设备发送
3. **STAGE_2**: `ovs_dp_process_packet` - OVS数据路径处理
4. **STAGE_3**: `ovs_dp_upcall` - OVS upcall处理（可选）
5. **STAGE_4**: `ovs_flow_key_extract_userspace` - 用户态流表键提取（仅在有upcall时）
6. **STAGE_5**: `ovs_vport_send` - OVS虚拟端口发送
7. **STAGE_6**: `dev_queue_xmit` - 物理网卡发送队列

#### RX方向探测点序列（系统接收）：
1. **STAGE_7**: `__netif_receive_skb` - 物理网卡接收数据包
2. **STAGE_8**: `netdev_frame_hook` - 网络设备帧处理钩子
3. **STAGE_9**: `ovs_dp_process_packet` - OVS数据路径处理
4. **STAGE_10**: `ovs_dp_upcall` - OVS upcall处理（可选）
5. **STAGE_11**: `ovs_flow_key_extract_userspace` - 用户态流表键提取（仅在有upcall时）
6. **STAGE_12**: `ovs_vport_send` - OVS虚拟端口发送
7. **STAGE_13**: 协议特定接收点
   - TCP: `tcp_v4_rcv` - TCP协议接收处理
   - UDP: `udp_rcv` 或 `__udp4_lib_rcv` - UDP协议接收处理

#### 关键点说明：
- **TX方向**：起始于IP层发送，结束于物理网卡发送
- **RX方向**：起始于物理网卡接收，结束于协议栈接收
- **OVS处理路径**：与ICMP工具完全相同
  - 无upcall时：STAGE_2 → STAGE_5（跳过STAGE_3和STAGE_4）
  - 有upcall时：STAGE_2 → STAGE_3 → STAGE_4 → STAGE_5

## 2. TCP/UDP数据包唯一标识机制

### 2.1 统一的数据包标识结构

```c
// 统一的数据包唯一标识结构 - 支持TCP/UDP协议
struct packet_key_t {
    __be32 src_ip;      // 源IP地址
    __be32 dst_ip;      // 目标IP地址
    u8 protocol;        // 协议类型 (TCP=6, UDP=17)
    
    // 协议特定的标识字段
    union {
        // TCP协议标识 - 最可靠的数据包级追踪
        struct {
            __be16 src_port;    // TCP源端口
            __be16 dst_port;    // TCP目标端口
            __be32 seq;         // TCP序列号（数据包级唯一标识）
            __be16 payload_len; // TCP载荷长度（区分不同段）
        } tcp;
        
        // UDP协议标识 - 处理分片场景
        struct {
            __be16 src_port;    // UDP源端口
            __be16 dst_port;    // UDP目标端口
            __be16 ip_id;       // IP标识字段（数据包级唯一标识）
            __be16 frag_off;    // 分片偏移（区分同一IP ID的不同分片）
        } udp;
    };
    
    // 时间戳辅助标识（处理重传、重复等场景）
    u64 first_seen_ns;  // 首次捕获时间戳
};
```

### 2.2 协议特定标识策略

#### 2.2.1 TCP协议标识机制
- **主要标识**: `{五元组 + seq + payload_len + first_seen_ns}`
- **唯一性保证**: TCP序列号在网络路径中保持稳定，提供最可靠的数据包级追踪
- **分段处理**: 通过序列号+载荷长度唯一标识每个TCP段
- **重传处理**: 时间戳区分同一段的重传
- **可靠性**: 🟢 极高（序列号在系统网络路径中基本不变）

#### 2.2.2 UDP协议标识机制
- **分片判断**: 使用More Fragment位和Fragment Offset判断
- **未分片包标识**: `{五元组 + ip_id + first_seen_ns}`  
- **分片包标识**: `{五元组 + ip_id + frag_offset + first_seen_ns}`
- **分片处理策略**: 
  - MF=1 或 Offset>0 表示分片
  - 通过IP ID关联同一数据报的所有分片
  - 通过偏移量区分不同分片
  - 首个分片（Offset=0）包含UDP头信息
  - 后续分片的端口信息不可用
- **重传处理**: 时间戳区分重传分片
- **可靠性**: 🟡 中等（依赖IP ID字段的唯一性）

### 2.3 数据包解析实现

#### 2.3.1 TCP协议解析函数

```c
// TCP协议解析 - 直接复用vm_network_latency.py的实现
static __always_inline int parse_tcp_key(
    struct sk_buff *skb, 
    struct packet_key_t *key, 
    u8 stage_id
) {
    struct tcphdr tcp;
    if (get_transport_header(skb, &tcp, sizeof(tcp), stage_id) != 0) return 0;
    
    key->tcp.src_port = tcp.source;
    key->tcp.dst_port = tcp.dest;
    key->tcp.seq = tcp.seq;
    
    // 计算TCP载荷长度以区分不同的段
    struct iphdr ip;
    if (get_ip_header(skb, &ip, stage_id) == 0) {
        u16 ip_len = ntohs(ip.tot_len);
        u16 ip_hdr_len = (ip.ihl & 0x0F) * 4;
        u16 tcp_hdr_len = ((tcp.doff >> 4) & 0x0F) * 4;
        key->tcp.payload_len = ip_len - ip_hdr_len - tcp_hdr_len;
    }
    
    return 1;
}
```

#### 2.3.2 UDP协议解析函数

```c
// UDP协议解析 - 直接复用vm_network_latency.py的实现
static __always_inline int parse_udp_key(
    struct sk_buff *skb, 
    struct packet_key_t *key, 
    u8 stage_id
) {
    struct iphdr ip;
    if (get_ip_header(skb, &ip, stage_id) != 0) return 0;
    
    key->udp.ip_id = ip.id;
    
    // 获取分片信息
    u16 frag_off_flags = ntohs(ip.frag_off);
    u8 more_frag = (frag_off_flags & 0x2000) ? 1 : 0;  // More Fragments bit
    u16 frag_offset = frag_off_flags & 0x1FFF;          // Fragment offset (8-byte units)
    
    // 判断是否为分片包
    u8 is_fragment = (more_frag || frag_offset) ? 1 : 0;
    
    if (is_fragment) {
        // 分片包：使用 frag_offset 区分不同分片
        key->udp.frag_off = frag_offset * 8;  // 转换为字节偏移
        
        // 只有首个分片才有UDP头
        if (frag_offset == 0) {
            struct udphdr udp;
            if (get_transport_header(skb, &udp, sizeof(udp), stage_id) == 0) {
                key->udp.src_port = udp.source;
                key->udp.dst_port = udp.dest;
            }
        } else {
            // 后续分片：端口信息不可用
            key->udp.src_port = 0;
            key->udp.dst_port = 0;
        }
    } else {
        // 未分片包：frag_off = 0，正常解析UDP头
        key->udp.frag_off = 0;
        struct udphdr udp;
        if (get_transport_header(skb, &udp, sizeof(udp), stage_id) == 0) {
            key->udp.src_port = udp.source;
            key->udp.dst_port = udp.dest;
        }
    }
    
    return 1;
}
```

## 3. 核心数据结构设计

### 3.1 流状态跟踪结构

```c
#define MAX_STAGES 14    // TX(7个阶段) + RX(7个阶段)
#define IFNAMSIZ 16
#define TASK_COMM_LEN 16

struct flow_data_t {
    // 时间戳和跟踪信息
    u64 ts[MAX_STAGES];           // 各阶段时间戳
    u64 skb_ptr[MAX_STAGES];      // SKB指针（用于验证）
    int kstack_id[MAX_STAGES];    // 内核栈ID（调试用）
    
    // Path1路径信息（TX for outgoing, RX for incoming）
    u32 p1_pid;                   // Path1起始进程ID
    char p1_comm[TASK_COMM_LEN];  // Path1进程名
    char p1_ifname[IFNAMSIZ];     // Path1接口名
    
    // Path2路径信息（RX for outgoing, TX for incoming）  
    u32 p2_pid;                   // Path2起始进程ID
    char p2_comm[TASK_COMM_LEN];  // Path2进程名
    char p2_ifname[IFNAMSIZ];     // Path2接口名
    
    // 协议特定信息
    u8 tcp_flags;                 // TCP标志位（如果是TCP）
    u16 udp_len;                  // UDP长度（如果是UDP）
    
    // 流状态标记
    u8 saw_path1_start:1;         // Path1开始
    u8 saw_path1_end:1;           // Path1结束
    u8 saw_path2_start:1;         // Path2开始
    u8 saw_path2_end:1;           // Path2结束
};
```

### 3.2 事件输出结构

```c
struct event_data_t {
    struct packet_key_t key;      // 协议特定数据包标识
    struct flow_data_t data;      // 流跟踪数据
};
```

### 3.3 BPF映射表设计

```c
// 流会话存储 - 支持10K并发流
BPF_TABLE("lru_hash", struct packet_key_t, struct flow_data_t, flow_sessions, 10240);

// 内核栈跟踪
BPF_STACK_TRACE(stack_traces, 10240);

// 性能事件输出
BPF_PERF_OUTPUT(events);

// 临时事件缓冲区
BPF_PERCPU_ARRAY(event_scratch_map, struct event_data_t, 1);
```

## 4. 关键探测点实现

### 4.1 TX方向起始点（ip_send_skb）

```c
int kprobe__ip_send_skb(struct pt_regs *ctx, struct net *net, struct sk_buff *skb) {
    struct packet_key_t key = {};
    
    // 解析TCP/UDP数据包
    if (!parse_packet_key(skb, &key, TX_STAGE_0)) return 0;
    
    // 应用协议过滤
    if (PROTOCOL_FILTER != 0 && key.protocol != PROTOCOL_FILTER) return 0;
    
    // 创建新的流会话
    struct flow_data_t zero = {};
    flow_sessions.delete(&key);  // 清理可能的旧会话
    struct flow_data_t *flow = flow_sessions.lookup_or_try_init(&key, &zero);
    if (!flow) return 0;
    
    // 记录TX起始信息
    flow->ts[TX_STAGE_0] = bpf_ktime_get_ns();
    flow->p1_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&flow->p1_comm, sizeof(flow->p1_comm));
    flow->saw_path1_start = 1;
    
    // 记录协议特定信息
    if (key.protocol == IPPROTO_TCP) {
        // 从TCP头获取标志位
        struct tcphdr tcp;
        if (get_transport_header(skb, &tcp, sizeof(tcp), TX_STAGE_0) == 0) {
            flow->tcp_flags = tcp.rst << 2 | tcp.syn << 1 | tcp.fin;
        }
    } else if (key.protocol == IPPROTO_UDP) {
        // 从UDP头获取长度
        struct udphdr udp;
        if (get_transport_header(skb, &udp, sizeof(udp), TX_STAGE_0) == 0) {
            flow->udp_len = ntohs(udp.len);
        }
    }
    
    flow_sessions.update(&key, flow);
    return 0;
}
```

### 4.2 RX方向终点（协议特定接收）

```c
// TCP协议接收处理
int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    struct packet_key_t key = {};
    if (!parse_packet_key(skb, &key, RX_STAGE_6)) return 0;
    
    // 只处理TCP协议
    if (key.protocol != IPPROTO_TCP) return 0;
    
    // 查找流会话
    struct flow_data_t *flow = flow_sessions.lookup(&key);
    if (!flow) return 0;
    
    // 更新RX终点信息
    flow->ts[RX_STAGE_6] = bpf_ktime_get_ns();
    flow->p2_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&flow->p2_comm, sizeof(flow->p2_comm));
    flow->saw_path2_end = 1;
    
    // 检查是否完成全部追踪
    if (flow->saw_path1_start && flow->saw_path1_end && 
        flow->saw_path2_start && flow->saw_path2_end) {
        submit_event(ctx, &key, flow);
        flow_sessions.delete(&key);
    } else {
        flow_sessions.update(&key, flow);
    }
    
    return 0;
}

// UDP协议接收处理
int kprobe____udp4_lib_rcv(struct pt_regs *ctx, struct sk_buff *skb, 
                          struct udp_table *udptable) {
    struct packet_key_t key = {};
    if (!parse_packet_key(skb, &key, RX_STAGE_6)) return 0;
    
    // 只处理UDP协议
    if (key.protocol != IPPROTO_UDP) return 0;
    
    // 查找流会话
    struct flow_data_t *flow = flow_sessions.lookup(&key);
    if (!flow) return 0;
    
    // 更新RX终点信息
    flow->ts[RX_STAGE_6] = bpf_ktime_get_ns();
    flow->p2_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&flow->p2_comm, sizeof(flow->p2_comm));
    flow->saw_path2_end = 1;
    
    // 检查是否完成全部追踪
    if (flow->saw_path1_start && flow->saw_path1_end && 
        flow->saw_path2_start && flow->saw_path2_end) {
        submit_event(ctx, &key, flow);
        flow_sessions.delete(&key);
    } else {
        flow_sessions.update(&key, flow);
    }
    
    return 0;
}
```

### 4.3 OVS用户态解析（ovs_flow_key_extract_userspace）

```c
// 直接复用vm_network_latency.py的用户态解析逻辑
int kprobe__ovs_flow_key_extract_userspace(struct pt_regs *ctx, 
    struct net *net, const struct nlattr *attr, struct sk_buff *skb) {
    
    if (!skb) return 0;
    
    struct packet_key_t key = {};
    
    // 使用专门的用户态解析函数
    if (!parse_packet_key_userspace(skb, &key, TX_STAGE_4)) {
        // 尝试RX方向
        if (!parse_packet_key_userspace(skb, &key, RX_STAGE_4)) {
            return 0;
        }
        // RX方向处理
        handle_stage_event_userspace(ctx, skb, RX_STAGE_4, &key);
    } else {
        // TX方向处理
        handle_stage_event_userspace(ctx, skb, TX_STAGE_4, &key);
    }
    
    return 0;
}
```

## 5. 数据包关联机制

### 5.1 基于协议特定标识的流会话管理

```c
// 使用LRU哈希表存储流状态，支持10K并发流
BPF_TABLE("lru_hash", struct packet_key_t, struct flow_data_t, flow_sessions, 10240);

// 流会话生命周期：
// 1. TX STAGE_0：创建新会话（ip_send_skb）
// 2. 各阶段：通过协议特定标识查找并更新会话
// 3. RX STAGE_6：完成追踪后删除会话释放资源（tcp_v4_rcv/udp_rcv）
```

### 5.2 数据包追踪流程

1. **TX方向起始（STAGE_0 - ip_send_skb）**：
   - 解析TCP/UDP协议特定标识，创建新的flow_session
   - 记录起始时间戳和进程信息
   - 标记saw_path1_start = 1

2. **中间阶段更新（STAGE_1-5, STAGE_7-12）**：
   - 通过协议特定标识查找已存在的flow_session
   - 更新对应阶段的时间戳
   - 跳过已记录的阶段（防止重复）

3. **RX方向终点（STAGE_6 - tcp_v4_rcv/udp_rcv）**：
   - 通过协议特定标识查找flow_session
   - 记录终点时间戳和进程信息
   - 标记saw_path2_end = 1

4. **流完成检测**：
   - 检查是否收集完整路径（path1_start && path1_end && path2_start && path2_end）
   - 满足条件时提交到用户空间
   - 清理flow_session释放资源

## 6. 过滤机制设计

### 6.1 基本过滤条件

```c
// 用户定义的过滤器
#define SRC_IP_FILTER 0x%x        // 源IP过滤
#define DST_IP_FILTER 0x%x        // 目标IP过滤
#define SRC_PORT_FILTER %d        // 源端口过滤
#define DST_PORT_FILTER %d        // 目标端口过滤
#define PROTOCOL_FILTER %d        // 协议过滤 (6=TCP, 17=UDP, 0=all)
#define TARGET_IFINDEX1 %d        // 目标接口1
#define TARGET_IFINDEX2 %d        // 目标接口2
#define DIRECTION_FILTER %d       // 方向过滤 (0=both, 1=outgoing, 2=incoming)
```

### 6.2 多协议过滤逻辑

```c
// 统一的过滤检查函数
static __always_inline bool should_trace_packet(
    struct packet_key_t *key, 
    u8 stage_id
) {
    // 协议过滤
    if (PROTOCOL_FILTER != 0 && key->protocol != PROTOCOL_FILTER) {
        return false;
    }
    
    // IP地址过滤
    if (SRC_IP_FILTER != 0 && 
        key->src_ip != SRC_IP_FILTER && key->dst_ip != SRC_IP_FILTER) {
        return false;
    }
    
    if (DST_IP_FILTER != 0 && 
        key->src_ip != DST_IP_FILTER && key->dst_ip != DST_IP_FILTER) {
        return false;
    }
    
    // 端口过滤（仅对TCP/UDP有效，且需要考虑UDP分片）
    if (key->protocol == IPPROTO_TCP) {
        if (SRC_PORT_FILTER != 0 && 
            key->tcp.src_port != htons(SRC_PORT_FILTER) && 
            key->tcp.dst_port != htons(SRC_PORT_FILTER)) {
            return false;
        }
        
        if (DST_PORT_FILTER != 0 && 
            key->tcp.src_port != htons(DST_PORT_FILTER) && 
            key->tcp.dst_port != htons(DST_PORT_FILTER)) {
            return false;
        }
    } else if (key->protocol == IPPROTO_UDP) {
        // UDP分片处理：只有首个分片或未分片包才检查端口
        if (key->udp.frag_off == 0) {  // 首个分片或未分片
            if (SRC_PORT_FILTER != 0 && 
                key->udp.src_port != htons(SRC_PORT_FILTER) && 
                key->udp.dst_port != htons(SRC_PORT_FILTER)) {
                return false;
            }
            
            if (DST_PORT_FILTER != 0 && 
                key->udp.src_port != htons(DST_PORT_FILTER) && 
                key->udp.dst_port != htons(DST_PORT_FILTER)) {
                return false;
            }
        }
        // 后续分片不检查端口过滤，依赖IP ID关联
    }
    
    return true;
}
```

## 7. 性能优化策略

### 7.1 高效流查找
- 使用BPF_LRU_HASH_MAP进行流状态存储
- 基于协议特定标识的哈希索引
- 自动老化机制防止内存泄漏

### 7.2 条件过滤
- 在BPF层面进行早期过滤
- 减少用户态事件传输
- 支持多维度组合过滤

### 7.3 内存管理
- 使用percpu数组避免锁竞争
- 合理设置map大小限制
- 及时清理完成的流状态

### 7.4 解析优化
- 标准解析：使用skb header偏移（大部分阶段）
- 特殊解析：ovs_flow_key_extract_userspace使用直接数据访问
- 支持VLAN标签的正确处理

## 8. 错误处理机制

### 8.1 数据包解析错误
- 畸形数据包检测
- Header偏移验证
- 协议类型验证
- UDP分片一致性检查

### 8.2 探测点错误
- 函数不存在的处理
- 参数变化的兼容性
- 内核版本适配

### 8.3 资源限制
- Map容量限制处理
- 栈空间溢出保护
- 事件丢失处理

## 9. 输出格式设计

### 9.1 TCP流延迟报告格式

#### 无OVS Upcall场景
```
=== System Network TCP/UDP Latency Trace: 2025-01-15 10:30:45.123 ===
Flow: 192.168.1.10:8080 -> 192.168.1.20:80 (TCP)
Direction: Outgoing (Local -> Remote)
TCP Segment: seq=12345678, payload=1460 bytes, flags=ACK

TX Path Latencies (us):
  [0->1] STAGE_0 (ip_send_skb) -> STAGE_1 (internal_dev_xmit): 12.345 us
  [1->2] STAGE_1 (internal_dev_xmit) -> STAGE_2 (ovs_dp_process_packet): 8.234 us
  [2->5] STAGE_2 (ovs_dp_process_packet) -> STAGE_5 (ovs_vport_send): 15.678 us [Kernel Path]
  [5->6] STAGE_5 (ovs_vport_send) -> STAGE_6 (dev_queue_xmit@eth0): 5.123 us

RX Path Latencies (us):
  [7->8] STAGE_7 (__netif_receive_skb@eth0) -> STAGE_8 (netdev_frame_hook): 10.234 us
  [8->9] STAGE_8 (netdev_frame_hook) -> STAGE_9 (ovs_dp_process_packet): 7.456 us
  [9->12] STAGE_9 (ovs_dp_process_packet) -> STAGE_12 (ovs_vport_send): 14.567 us [Kernel Path]
  [12->13] STAGE_12 (ovs_vport_send) -> STAGE_13 (tcp_v4_rcv): 4.890 us

Total TX Latency: 41.380 us
Total RX Latency: 37.147 us
Total One-Way Latency: 78.527 us
```

#### 有OVS Upcall场景
```
=== System Network TCP/UDP Latency Trace: 2025-01-15 10:31:23.456 ===
Flow: 192.168.1.10:8080 -> 192.168.1.20:443 (TCP)
Direction: Outgoing (Local -> Remote)
TCP Segment: seq=87654321, payload=512 bytes, flags=PSH|ACK

TX Path Latencies (us):
  [0->1] STAGE_0 (ip_send_skb) -> STAGE_1 (internal_dev_xmit): 11.234 us
  [1->2] STAGE_1 (internal_dev_xmit) -> STAGE_2 (ovs_dp_process_packet): 9.456 us
  [2->3] STAGE_2 (ovs_dp_process_packet) -> STAGE_3 (ovs_dp_upcall): 5.789 us
  [3->4] STAGE_3 (ovs_dp_upcall) -> STAGE_4 (ovs_flow_key_extract_userspace): 125.678 us
  [4->5] STAGE_4 (ovs_flow_key_extract_userspace) -> STAGE_5 (ovs_vport_send): 45.234 us
  [5->6] STAGE_5 (ovs_vport_send) -> STAGE_6 (dev_queue_xmit@eth0): 6.890 us

Total TX Latency: 204.281 us [Userspace Path]
```

### 9.2 UDP流延迟报告格式

#### 未分片UDP包
```
=== System Network TCP/UDP Latency Trace: 2025-01-15 11:15:30.789 ===
Flow: 192.168.1.10:53123 -> 192.168.1.20:53 (UDP)
Direction: Outgoing (Local -> Remote)
UDP Packet: ip_id=12345, length=64 bytes, no fragmentation

TX Path Latencies (us):
  [0->1] STAGE_0 (ip_send_skb) -> STAGE_1 (internal_dev_xmit): 8.123 us
  [1->2] STAGE_1 (internal_dev_xmit) -> STAGE_2 (ovs_dp_process_packet): 6.456 us
  [2->5] STAGE_2 (ovs_dp_process_packet) -> STAGE_5 (ovs_vport_send): 12.789 us [Kernel Path]
  [5->6] STAGE_5 (ovs_vport_send) -> STAGE_6 (dev_queue_xmit@eth0): 4.234 us

Total TX Latency: 31.602 us
```

#### 分片UDP包
```
=== System Network TCP/UDP Latency Trace: 2025-01-15 11:20:45.123 ===
Flow: 192.168.1.10:12345 -> 192.168.1.20:8080 (UDP)
Direction: Outgoing (Local -> Remote)
UDP Fragment: ip_id=54321, frag_offset=1480 bytes, more_fragments=true

TX Path Latencies (us):
  [0->1] STAGE_0 (ip_send_skb) -> STAGE_1 (internal_dev_xmit): 9.876 us
  [1->2] STAGE_1 (internal_dev_xmit) -> STAGE_2 (ovs_dp_process_packet): 7.543 us
  [2->5] STAGE_2 (ovs_dp_process_packet) -> STAGE_5 (ovs_vport_send): 13.210 us [Kernel Path]
  [5->6] STAGE_5 (ovs_vport_send) -> STAGE_6 (dev_queue_xmit@eth0): 5.147 us

Total TX Latency: 35.776 us
Note: This is a UDP fragment (offset=1480), port information not available
```

## 10. 使用示例

### 10.1 基本用法

```bash
# 监控TCP流量（最可靠的数据包级追踪）
sudo ./system_tcp_udp_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
                                 --protocol tcp --direction outgoing \
                                 --phy-interface eth0

# 监控UDP流量（包括分片处理）
sudo ./system_tcp_udp_latency.py --src-ip 192.168.1.10 --dst-port 53 \
                                 --protocol udp --direction both \
                                 --phy-interface eth0,eth1

# 监控特定TCP连接的数据包级延迟
sudo ./system_tcp_udp_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
                                 --src-port 12345 --dst-port 80 \
                                 --protocol tcp --direction both \
                                 --phy-interface bond0

# 监控所有TCP/UDP协议
sudo ./system_tcp_udp_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
                                 --protocol all \
                                 --phy-interface eth0,eth1
```

### 10.2 高级过滤

```bash
# 仅监控高延迟流量（超过100ms）
sudo ./system_tcp_udp_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
                                 --latency-threshold 100 \
                                 --protocol tcp --direction both \
                                 --phy-interface bond0

# 监控特定端口范围的UDP流量
sudo ./system_tcp_udp_latency.py --src-ip 192.168.1.10 \
                                 --dst-port 8080-8090 \
                                 --protocol udp --direction outgoing \
                                 --phy-interface eth0,eth1

# 仅监控incoming方向的TCP流量
sudo ./system_tcp_udp_latency.py --dst-ip 192.168.1.10 \
                                 --protocol tcp --direction incoming \
                                 --phy-interface eth0
```

## 11. 与现有工具的关系

### 11.1 与ICMP工具的继承关系
- **探测点复用**: 直接使用icmp_rtt_latency.py验证成功的探测点
- **架构继承**: 保持Path1/Path2的双路径设计
- **OVS处理**: 完全复用OVS相关的探测点和处理逻辑

### 11.2 与VM网络工具的技术复用
- **数据包标识**: 直接复用TCP/UDP协议特定的唯一标识机制
- **解析函数**: 复用parse_tcp_key、parse_udp_key和用户态解析函数
- **数据结构**: 复用union-based的packet_key_t设计

### 11.3 技术优势对比

| 特性 | icmp_rtt_latency.py | vm_network_latency.py | system_tcp_udp_latency |
|------|-------------------|---------------------|----------------------|
| 协议支持 | 仅ICMP | TCP/UDP/ICMP | **TCP/UDP** |
| 网络环境 | 系统网络 | 虚拟机网络 | **系统网络** |
| 数据包标识 | ICMP ID/SEQ | 协议特定 | **协议特定** |
| TCP标识 | 不支持 | 序列号（最可靠） | **序列号（最可靠）** |
| UDP标识 | 不支持 | IP ID + 分片处理 | **IP ID + 分片处理** |
| 分片支持 | 不涉及 | 完整支持 | **完整支持** |
| 起始点 | ip_send_skb | netif_receive_skb(vnet) | **ip_send_skb** |
| 终点 | icmp_rcv | tun_net_xmit(vnet) | **tcp_v4_rcv/udp_rcv** |
| 测量精度 | ICMP包级 | 数据包级 | **数据包级** |
| 应用场景 | 网络连通性 | 虚拟机性能 | **系统网络性能** |

## 12. 实现优先级

### 12.1 第一阶段（核心功能）
- [ ] 基础BPF程序框架搭建
- [ ] TCP协议数据包解析和唯一标识
- [ ] TX方向完整链路追踪（ip_send_skb → tcp_v4_rcv）
- [ ] 基本的延迟输出格式

### 12.2 第二阶段（UDP支持）
- [ ] UDP协议数据包解析和唯一标识
- [ ] UDP分片处理机制
- [ ] UDP TX/RX方向链路追踪
- [ ] UDP延迟输出格式

### 12.3 第三阶段（完善功能）
- [ ] 高级过滤机制（端口范围、延迟阈值）
- [ ] 双向延迟测量支持
- [ ] OVS upcall路径的详细分析
- [ ] 性能优化和错误处理完善

### 12.4 第四阶段（增强功能）
- [ ] 统计分析功能
- [ ] 多接口同时监控
- [ ] 与现有工具的集成
- [ ] 图形化输出支持

## 13. 测试验证计划

### 13.1 功能测试
- TCP/UDP协议支持验证
- 数据包唯一标识准确性测试
- 延迟测量精度验证
- UDP分片处理正确性测试
- 边界条件测试

### 13.2 性能测试
- 高流量场景下的性能影响
- 内存使用情况监控
- CPU开销测量
- 丢包率分析

### 13.3 兼容性测试
- 不同内核版本测试
- 不同网络配置验证
- OVS版本兼容性测试

### 13.4 对比验证
- 与icmp_rtt_latency.py的架构一致性验证
- 与vm_network_latency.py的解析逻辑一致性验证
- 与网络工具（如ss、netstat）的数据对比

## 14. 设计总结

### 14.1 核心创新点

1. **系统网络专用设计**：针对系统级网络环境，避免TUN设备处理开销
2. **协议特定数据包级追踪**：
   - TCP：基于序列号的最可靠追踪机制
   - UDP：基于IP ID的分片感知追踪机制
3. **成熟技术整合**：结合icmp_rtt_latency.py的成功架构和vm_network_latency.py的先进解析技术
4. **OVS路径完整支持**：支持内核快速路径和用户态慢速路径的完整分析

### 14.2 技术可靠性保证

- **避免SKB指针依赖**：基于协议内容而非SKB地址进行追踪
- **分片处理完整性**：UDP分片场景下的完整追踪支持
- **重传识别机制**：通过时间戳区分重传数据包
- **探测点稳定性**：基于成功验证的icmp_rtt_latency.py探测点

### 14.3 应用价值

- **精确性**：提供数据包级别的延迟测量，而非连接级
- **完整性**：覆盖系统网络的完整数据路径
- **实用性**：支持现网最常用的TCP/UDP协议
- **可扩展性**：设计支持未来添加更多协议和功能

### 14.4 与现有生态的关系

本工具是对现有网络延迟测量工具生态的重要补充：

- **icmp_rtt_latency.py**: 系统网络ICMP往返延迟测量
- **vm_network_latency.py**: 虚拟机网络多协议单向延迟测量  
- **system_tcp_udp_latency**: 系统网络TCP/UDP单向延迟测量 ⭐

形成了覆盖不同网络环境和协议的完整测量工具矩阵。

---

*本设计文档完整描述了系统网络TCP/UDP延迟测量工具的设计思路、技术实现和验证计划。该工具将为系统网络环境提供精确的TCP/UDP协议数据包级延迟分析能力。*