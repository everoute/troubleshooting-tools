# 系统网络性能测量系统 PRD

## 0. 项目概述与环境

### 0.1 目标
设计一个**逐包测量系统**，用于系统网络的性能问题定位。系统将：
- 支持五元组 + devname 过滤，仅输出命中包的详细路径信息
- 在数据路径各关键点采集性能指标（Queue/CPU、QueueLen、Buffer、Lookup）
- 不做聚合，直接输出原始测量数据

### 0.2 环境规格
- **内核版本**：4.19.90（openEuler）
- **虚拟化**：KVM + vhost-net 后端
- **网络模式**：系统网络：Host协议栈 → OVS internal port → 物理网卡
- **Qdisc**：fq_codel（uplink）
- **可选组件**：OVS CT（使用kernel nf_conntrack）、RPS

---

## 1. 数据结构定义

### 1.1 包唯一标识键（Packet Key）

```c
// 支持TCP/UDP/ICMP的统一包标识结构
struct packet_key_t {
    __be32 src_ip;      // 源IP地址
    __be32 dst_ip;      // 目标IP地址
    u8 protocol;        // 协议类型：IPPROTO_TCP/UDP/ICMP
    
    union {
        // TCP包特征字段
        struct {
            __be16 src_port;      // 源端口
            __be16 dst_port;      // 目标端口
            __be32 seq;           // 序列号
            __be16 payload_len;   // 负载长度
        } tcp;
        
        // UDP包特征字段
        struct {
            __be16 src_port;      // 源端口
            __be16 dst_port;      // 目标端口
            __be16 ip_id;         // IP标识
            __be16 frag_off;      // 分片偏移
        } udp;
        
        // ICMP包特征字段
        struct {
            __be16 id;            // ICMP ID
            __be16 seq;           // ICMP序列号
            u8 type;              // ICMP类型
            u8 code;              // ICMP代码
        } icmp;
    };
};
```

### 1.2 事件数据结构

```c
// 每个包在路径上各点的事件记录
struct pkt_event {
    // 包标识信息
    u64 pkt_id;                  // 包唯一ID（skb指针值）
    struct packet_key_t key;     // 包特征键（首次解析填充，后续查缓存）
    
    // 时间和位置信息
    u64 t_ns;                    // 事件时间戳（单调时钟）
    u32 cpu;                     // 当前CPU ID
    char dev[16];                // 设备名称
    u8 dir;                      // 方向：2=LOC→UP, 3=UP→LOC
    u8 stage;                    // 处理阶段（见§2.1）
    
    // Queue/CPU信息
    s16 rxq;                     // RX队列号（skb->queue_mapping，-1表示无效）
    s16 txq;                     // TX队列号（net_dev_queue，-1表示无效）
    u8 has_hash;                 // 是否有hash值
    u8 has_sk;                   // 是否有socket
    u32 skb_hash;                // skb->hash（用于CPU/队列选择）
    
    // Queue深度信息
    s32 backlog_qlen;            // softnet_data.input_pkt_queue.qlen
    s32 qdisc_qlen;              // fq_codel: sch->q.qlen
    s32 flow_qlen;               // fq_codel: 单flow队列长度
    u64 sojourn_ns;              // fq_codel: 包在队列中的停留时间
    
    // Buffer信息（socket相关）
    u32 sk_wmem;                 // 发送缓冲区已用大小
    u32 sk_wmem_lim;             // 发送缓冲区限制
    u32 sk_rmem;                 // 接收缓冲区已用大小
    u32 sk_rmem_lim;             // 接收缓冲区限制
    
    // Lookup信息（查表开销）
    u8 ct_hit;                   // conntrack查表结果：0=new, 1=found
    u32 ct_lookup_ns;            // conntrack查表耗时（纳秒）
    u8 fib_hit;                  // 路由查表结果
    u32 fib_lookup_ns;           // 路由查表耗时
};
```

---

## 2. 处理阶段定义

### 2.1 系统网络相关阶段枚举（基于VM网络经验简化设计）

```c
// Stage definitions - internal port perspective（基于internal port视角）
// 系统 TX 路径（Local→Uplink，系统发送到外部）
#define STG_SOCK_SEND        1   // tcp_sendmsg/udp_sendmsg - 系统发送起点
#define STG_IP_OUTPUT        2   // ip_output - IP输出处理
#define STG_OVS_TX           3   // ovs_vport_receive (internal port)
#define STG_FLOW_EXTRACT_TX  4   // ovs_ct_update_key (flow extract phase)
#define STG_CT_TX            5   // nf_conntrack_in
#define STG_CT_OUT_TX        6   // ovs_ct_update_key (conntrack action)
#define STG_PHY_QDISC_ENQ    7   // qdisc_enqueue (physical dev)
#define STG_PHY_QDISC_DEQ    8   // qdisc_dequeue (physical dev)
#define STG_PHY_TX           9   // dev_hard_start_xmit (physical) - LAST POINT

// 系统 RX 路径（Uplink→Local，外部到系统接收）
#define STG_PHY_RX           11  // netif_receive_skb (physical) - FIRST POINT
#define STG_OVS_RX           12  // ovs_vport_receive (from physical to internal)
#define STG_FLOW_EXTRACT_RX  13  // ovs_ct_update_key (flow extract phase)
#define STG_CT_RX            14  // nf_conntrack_in
#define STG_CT_OUT_RX        15  // ovs_ct_update_key (conntrack action)
#define STG_INTERNAL_RX      16  // netif_receive_skb (internal port) - 注意：internal port无qdisc
#define STG_IP_RCV           17  // ip_rcv - IP层接收
#define STG_TCP_UDP_RCV      18  // tcp_v4_rcv/udp_rcv - 传输层处理
#define STG_SOCK_RECV        19  // socket接收完成 - LAST POINT
```

---

## 3. 系统网络数据路径（基于VM网络经验简化设计）

### 3.1 系统 TX 路径（Local→Uplink，系统发送到外部）

| 阶段 | 函数 | 说明 | 重要度 |
|------|------|------|--------|
| **STG_SOCK_SEND (1)** | tcp_sendmsg/udp_sendmsg | 系统应用发送起点，解析五元组 | **HIGH** |
| **STG_IP_OUTPUT (2)** | ip_output | IP层输出处理 | **HIGH** |
| **STG_OVS_TX (3)** | ovs_vport_receive | OVS internal port接收（从系统协议栈） | **HIGH** |
| **STG_FLOW_EXTRACT_TX (4)** | ovs_ct_update_key | OVS流提取阶段 | MED |
| **STG_CT_TX (5)** | nf_conntrack_in | 连接跟踪入口 | MED |
| **STG_CT_OUT_TX (6)** | ovs_ct_update_key | 连接跟踪动作阶段 | MED |
| **STG_PHY_QDISC_ENQ (7)** | qdisc_enqueue | 物理网卡qdisc入队 | **HIGH** |
| **STG_PHY_QDISC_DEQ (8)** | qdisc_dequeue | 物理网卡qdisc出队 | **HIGH** |
| **STG_PHY_TX (9)** | dev_hard_start_xmit | 物理网卡最终发送 - **最后阶段** | **HIGH** |

### 3.2 系统 RX 路径（Uplink→Local，外部到系统接收）

| 阶段 | 函数 | 说明 | 重要度 |
|------|------|------|--------|
| **STG_PHY_RX (11)** | netif_receive_skb | 物理网卡接收 - **首个阶段** | **HIGH** |
| **STG_OVS_RX (12)** | ovs_vport_receive | OVS处理（从物理到internal port） | **HIGH** |
| **STG_FLOW_EXTRACT_RX (13)** | ovs_ct_update_key | OVS流提取阶段 | MED |
| **STG_CT_RX (14)** | nf_conntrack_in | 连接跟踪入口 | MED |
| **STG_CT_OUT_RX (15)** | ovs_ct_update_key | 连接跟踪动作阶段 | MED |
| **STG_INTERNAL_DEV_RECV (16)** | internal_dev_recv | internal port设备接收入口 | **HIGH** |
| **STG_INTERNAL_SOFTIRQ (17)** | netif_receive_skb | internal port软中断处理 | **HIGH** |
| **STG_IP_RCV (18)** | ip_rcv | IP层接收处理 | **HIGH** |
| **STG_TCP_UDP_RCV (19)** | tcp_v4_rcv/udp_rcv | 传输层处理 | **HIGH** |
| **STG_SOCK_RECV (20)** | socket接收完成 | 系统应用接收终点 - **最后阶段** | **HIGH** |

### 3.3 关键差异（vs VM网络）

1. **internal port无qdisc但有软中断处理**：
   - internal port设置了`IFF_NO_QUEUE`标志，无qdisc队列
   - 但在RX方向使用`netif_rx()`进入backlog队列，由软中断处理
   - `internal_dev_recv()` → `netif_rx()` → `enqueue_to_backlog()` → 软中断 → `process_backlog()` → `netif_receive_skb()`

2. **实际internal port RX流程**：
   ```
   OVS processing → internal_dev_recv() → netif_rx_internal() 
   → enqueue_to_backlog() → NET_RX_SOFTIRQ → net_rx_action() 
   → process_backlog() → __netif_receive_skb() → ip_rcv
   ```

3. **双向路径不对称**：
   - TX路径：系统协议栈→internal port（作为OVS入口）→物理网卡
   - RX路径：物理网卡→OVS→internal port（通过软中断处理）→系统协议栈

4. **CT/conntrack处理**：完全类似VM网络实现，区分flow extract和conntrack action阶段

5. **软中断延迟测量**：`internal_dev_recv` 到 `netif_receive_skb` 之间可以测量internal port的软中断处理延迟

---

## 4. 关键字段读取方法

### 4.1 Backlog队列深度读取

```c
// 在netif_receive_skb中读取当前CPU的backlog深度
static inline s32 read_backlog_qlen(void) {
    struct softnet_data *sd;
    s32 qlen = -1;
    
    // 获取当前CPU的softnet_data
    sd = this_cpu_ptr(&softnet_data);
    if (sd) {
        // input_pkt_queue是sk_buff_head类型，包含qlen字段
        bpf_probe_read(&qlen, sizeof(qlen), 
                       &sd->input_pkt_queue.qlen);
    }
    return qlen;
}
```

### 4.2 fq_codel队列信息读取

```c
// fq_codel_enqueue中读取队列深度
static inline void read_fq_codel_qlen(struct Qdisc *sch, 
                                      struct pkt_event *evt) {
    struct fq_codel_sched_data *q;
    
    // 读取qdisc总队列长度
    bpf_probe_read(&evt->qdisc_qlen, sizeof(evt->qdisc_qlen), 
                   &sch->q.qlen);
    
    // 读取fq_codel私有数据
    q = qdisc_priv(sch);
    // 读取单flow队列长度（需要根据4.19.90具体结构偏移调整）
    // ...
}
```

### 4.3 Socket缓冲区信息读取

```c
// 读取socket发送缓冲区信息
static inline void read_sk_wmem(struct sock *sk, 
                                struct pkt_event *evt) {
    bpf_probe_read(&evt->sk_wmem, sizeof(evt->sk_wmem), 
                   &sk->sk_wmem_queued);
    bpf_probe_read(&evt->sk_wmem_lim, sizeof(evt->sk_wmem_lim), 
                   &sk->sk_sndbuf);
}

// 读取socket接收缓冲区信息
static inline void read_sk_rmem(struct sock *sk, 
                                struct pkt_event *evt) {
    bpf_probe_read(&evt->sk_rmem, sizeof(evt->sk_rmem), 
                   &sk->sk_rmem_alloc.counter);
    bpf_probe_read(&evt->sk_rmem_lim, sizeof(evt->sk_rmem_lim), 
                   &sk->sk_rcvbuf);
}
```

---

## 5. 过滤机制实现

### 5.1 过滤键定义

```c
// 过滤条件结构
struct filter_key_t {
    __be32 src_ip;      // 源IP（0表示任意）
    __be32 dst_ip;      // 目标IP（0表示任意）
    __be16 src_port;    // 源端口（0表示任意）
    __be16 dst_port;    // 目标端口（0表示任意）
    u8 protocol;        // 协议（0表示任意）
    char dev_prefix[8]; // 设备名前缀（空表示任意）
};
```

### 5.2 过滤执行点

- **RX路径**：在`STG_RX_IN`（netif_receive_skb）解析包后立即过滤
- **TX路径**：在`STG_SOCK_SEND`（tcp/udp_sendmsg）解析包后立即过滤
- **传递标记**：通过BPF map标记`pkt_id`为已通过过滤
- **后续阶段**：检查`pkt_id`是否在通过列表中

### 5.3 方向判定规则

```c
static inline u8 determine_direction(u8 stage, const char *dev) {
    if (stage == STG_SOCK_SEND)
        return 2;  // LOC→UP
    if (stage == STG_SOCK_RECV)
        return 3;  // UP→LOC（确认）
    
    // 继承之前的方向
    return get_cached_direction(pkt_id);
}
```

---

## 6. 性能优化策略

### 6.1 缓存机制
- **Packet Key缓存**：首次解析后缓存，后续查询使用
- **过滤结果缓存**：已通过过滤的pkt_id缓存，避免重复判断
- **方向信息缓存**：包的方向确定后缓存，后续直接使用

### 6.2 Map设计

```c
// 核心数据缓存Map
// Packet key缓存（LRU，10000条目）
BPF_HASH(pkt_key_cache, u64, struct packet_key_t, 10000);

// 过滤通过列表（LRU，5000条目）
BPF_HASH(filter_passed, u64, u8, 5000);

// 方向缓存（LRU，5000条目）
BPF_HASH(dir_cache, u64, u8, 5000);

// 性能测量相关Map
// CT查表时间记录（用于计算耗时）
BPF_HASH(ct_start_time, u64, u64, 1000);
// FIB查表时间记录
BPF_HASH(fib_start_time, u64, u64, 1000);
// OVS处理时间记录
BPF_HASH(ovs_start_time, u64, u64, 1000);
// Qdisc sojourn时间基准
BPF_HASH(qdisc_enqueue_time, u64, u64, 2000);

// 统计和监控Map
// 各阶段事件计数
BPF_ARRAY(stage_counters, u64, 100);
// 丢包统计按原因分类
BPF_HASH(drop_stats, u32, u64, 50);
// 性能指标统计
BPF_HASH(perf_stats, u8, struct perf_metrics, 20);

// 配置控制Map
// 动态配置控制
BPF_ARRAY(config_map, struct trace_config, 1);
// probe点启用状态控制
BPF_ARRAY(probe_enable_map, u8, 100);

// 高级功能Map
// 包路径追踪状态
BPF_HASH(pkt_path_state, u64, struct path_state, 5000);
```

### 6.3 开销控制
- **提前退出**：未通过过滤的包立即返回
- **选择性采集**：根据配置决定是否采集某些字段
- **批量输出**：使用perf buffer批量传输数据到用户态

---

## 7. 输出格式设计

### 7.1 二进制格式（推荐）
直接输出`struct pkt_event`二进制数据到perf buffer，用户态解析。

### 7.2 文本格式（调试用）
```
[时间戳] PKT_ID=xxx DIR=LOC→UP STAGE=SOCK_SEND DEV=ovs-internal
  KEY: TCP 10.0.0.1:8080->192.168.1.10:80 SEQ=12345 LEN=1460
  QUEUE: RXQ=2 TXQ=1 HASH=0xabcd1234
  QLEN: BACKLOG=5 QDISC=10 FLOW=2 SOJOURN=120us
  BUFFER: WMEM=65536/262144 RMEM=32768/131072
  LOOKUP: CT=HIT/25us FIB=HIT/10us
```

---

## 8. 使用示例

### 8.1 命令行接口
```bash
# 追踪系统网络所有UDP流量
./sys_net_trace --proto=udp --dev=ovs-internal

# 追踪本地到外部的TCP流量
./sys_net_trace --dir=tx --proto=tcp \
               --src-ip=10.0.0.1 --dst-ip=192.168.1.10

# 详细追踪带conntrack的流量
./sys_net_trace --enable-ct --enable-fib --verbose
```

### 8.2 输出解析工具
```python
# 解析二进制输出，生成时序图
./parse_sys_trace.py trace.bin --format=timeline

# 统计各阶段延迟
./parse_sys_trace.py trace.bin --stats --group-by=stage

# 导出为CSV
./parse_sys_trace.py trace.bin --export=csv > sys_trace.csv
```

---

## 9. 测试验证计划

### 9.1 功能测试
- [ ] 系统网络双向路径追踪验证
- [ ] 五元组过滤准确性测试
- [ ] 设备名过滤测试（ovs-internal）
- [ ] Socket缓冲区监控验证
- [ ] 协议栈各层处理验证

### 9.2 性能测试
- [ ] 10Gbps系统流量下的CPU开销
- [ ] 内存使用情况监控
- [ ] Map容量压力测试
- [ ] 丢包率影响评估

### 9.3 兼容性测试
- [ ] RPS开启/关闭场景
- [ ] OVS CT开启/关闭场景
- [ ] 不同qdisc配置测试
- [ ] GSO/TSO场景验证

---

## 10. 注意事项与限制

### 10.1 内核版本兼容性
- **Kernel 4.19.90特定注意事项**：
  - 某些函数可能有`.isra.XX`后缀，需要动态符号查找
  - netfilter：使用`ipt_do_table`而非新版本的`ipt_do_table_legacy`
  - XDP支持有限，仅支持generic XDP
  - 内核符号信息必须可用（`/proc/kallsyms`或debuginfo）

### 10.2 性能影响
- **低流量（<1Gbps）**：CPU开销 < 1%
- **中等流量（1-5Gbps）**：CPU开销 1-3%
- **高流量（5-10Gbps）**：CPU开销 3-8%
- **极高流量（>10Gbps）**：建议使用采样模式

### 10.3 probe点可靠性分级

**HIGH可靠性（推荐生产使用）**：
- `netif_receive_skb` - 核心接收点
- `__dev_queue_xmit` - 核心发送点
- `ip_rcv`, `tcp_v4_rcv`, `udp_rcv` - 协议栈入口
- tracepoint类探测点（稳定性高）

**MEDIUM可靠性（测试环境推荐）**：
- OVS相关函数 - 依赖OVS版本
- netfilter相关 - 版本差异较大
- qdisc相关 - 依赖具体qdisc类型

**LOW可靠性（调试时使用）**：
- 内部辅助函数 - 可能被内联或优化掉
- 特定协议处理函数 - 实现可能变化

---

## 附录A：关键数据结构偏移（Kernel 4.19.90）

```c
// struct softnet_data偏移
#define SOFTNET_INPUT_QUEUE_OFFSET 0x68  // input_pkt_queue字段偏移

// struct sk_buff关键字段偏移
#define SKB_QUEUE_MAPPING_OFFSET 0x34
#define SKB_HASH_OFFSET 0x38
#define SKB_SK_OFFSET 0x18

// struct sock缓冲区字段偏移
#define SK_WMEM_QUEUED_OFFSET 0x108
#define SK_SNDBUF_OFFSET 0x110
#define SK_RMEM_ALLOC_OFFSET 0x118
#define SK_RCVBUF_OFFSET 0x120
```

---

*文档版本：1.0（系统网络专用版）*  
*更新日期：2024年*  
*基于Kernel 4.19.90验证，专注系统网络协议栈追踪*