# VM网络性能测量系统 PRD

## 0. 项目概述与环境

### 0.1 目标
设计一个**逐包测量系统**，用于虚拟机网络的性能问题定位。系统将：
- 支持五元组 + devname 过滤，仅输出命中包的详细路径信息
- 在数据路径各关键点采集性能指标（Queue/CPU、QueueLen、Buffer、Lookup）
- 不做聚合，直接输出原始测量数据

### 0.2 环境规格
- **内核版本**：4.19.90（openEuler）
- **虚拟化**：KVM + vhost-net 后端
- **网络模式**：VM网络：TUN（TAP mode）接口 → OVS（kernel mode）→ 物理网卡
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
    u8 dir;                      // 方向：0=VM→UP, 1=UP→VM
    u8 stage;                    // 处理阶段（见§2.1）
    
    // Queue/CPU信息
    s16 rxq;                     // RX队列号（skb->queue_mapping，-1表示无效）
    s16 txq;                     // TX队列号（net_dev_queue，-1表示无效）
    u8 has_hash;                 // 是否有hash值
    u8 has_sk;                   // 是否有socket
    u32 skb_hash;                // skb->hash（用于CPU/队列选择）
    
    // Queue深度信息（软中断路径）
    s32 backlog_qlen;            // softnet_data.input_pkt_queue.qlen（backlog输入队列）
    s32 process_qlen;            // softnet_data.process_queue.qlen（处理队列）
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

### 2.1 VM网络相关阶段枚举（stage）

```c
enum pkt_stage {
    // RX软中断路径阶段
    STG_RX_IN        = 1,   // netif_receive_skb - 统一接收入口
    STG_RX_BACKLOG   = 2,   // enqueue_to_backlog - 包进入backlog队列
    STG_RX_PROCESS   = 3,   // process_backlog - 从backlog队列处理
    STG_RX_GRO_IN    = 4,   // dev_gro_receive - GRO聚合入口
    STG_RX_GRO_OUT   = 5,   // dev_gro_receive退出
    
    // 协议栈处理阶段
    STG_IP_RCV       = 10,  // ip_rcv - IP层接收
    STG_IP_LOCAL_IN  = 11,  // ip_local_deliver_finish - IP本地交付
    STG_TCP_V4_RCV   = 12,  // tcp_v4_rcv - TCP接收
    STG_UDP_RCV      = 13,  // udp_rcv - UDP接收
    
    // VM网络专用阶段  
    STG_OVS_IN       = 20,  // ovs_vport_receive - OVS入口
    STG_OVS_ACT_IN   = 21,  // ovs_execute_actions进入
    STG_OVS_ACT_OUT  = 22,  // ovs_execute_actions退出
    STG_OVS_UPCALL   = 25,  // ovs_upcall - OVS用户态调用
    STG_CT_IN        = 23,  // nf_conntrack_in进入
    STG_CT_OUT       = 24,  // nf_conntrack_in退出
    
    // TX路径阶段
    STG_QDISC_ENQ    = 60,  // fq_codel_enqueue - Qdisc入队
    STG_QDISC_DEQ    = 61,  // fq_codel_dequeue - Qdisc出队
    STG_DEV_Q_XMIT   = 70,  // dev_queue_xmit - 通用发送入口
    STG_TX_QUEUE     = 72,  // net_dev_queue - 设备队列
    STG_TX_XMIT      = 73,  // net_dev_start_xmit - 设备发送
    
    // SKB生命周期
    STG_SKB_CLONE    = 80,  // skb_clone - 包克隆
    STG_SKB_FREE     = 82,  // kfree_skb - 包释放（正常）
    STG_SKB_DROP     = 83,  // kfree_skb - 包丢弃（异常）
    STG_SKB_CONSUME  = 84,  // consume_skb - 包消费完成
};
```

---

## 3. VM网络数据路径（VM ↔ OVS ↔ Uplink）

### 3.1 VM→Uplink 发送路径

| 阶段 | Probe点 | 函数签名 | 采集字段 |
|------|---------|----------|----------|
| **STG_RX_IN** | TP:net:netif_receive_skb | `netif_receive_skb(skb)` | • 解析packet_key<br>• rxq = skb->queue_mapping<br>• skb_hash = skb->hash<br>• read_backlog_info()：backlog_qlen, process_qlen<br>• dev = "vnet*" |
| **STG_RX_BACKLOG** | kprobe:enqueue_to_backlog | `enqueue_to_backlog(skb, cpu, qtail)` | • 记录backlog入队<br>• 更新backlog_qlen（入队后）<br>• cpu = 目标CPU ID |
| **STG_RX_PROCESS** | kprobe:process_backlog | `process_backlog(work, quota)` | • 记录backlog处理开始<br>• 更新process_qlen<br>• quota = 处理配额 |
| **STG_RX_GRO_IN** | kprobe:dev_gro_receive | `dev_gro_receive(list, skb)` | • 记录GRO聚合入口 |
| **STG_RX_GRO_OUT** | kretprobe:dev_gro_receive | 返回值 | • gro_result = 聚合结果<br>• 计算GRO处理耗时 |
| **STG_OVS_IN** | kprobe:ovs_vport_receive | `ovs_vport_receive(vport, skb, tun_info)` | • has_sk = (skb->sk != NULL)<br>• 查缓存获取packet_key |
| **STG_OVS_ACT_IN** | kprobe:ovs_execute_actions | `ovs_execute_actions(dp, skb, acts, key)` | • 记录进入时间戳 |
| **STG_OVS_ACT_OUT** | kretprobe:ovs_execute_actions | 返回值 | • 计算OVS处理耗时 |
| **STG_CT_IN** | kprobe:nf_conntrack_in | `nf_conntrack_in(net, pf, hooknum, skb)` | • 记录进入时间戳 |
| **STG_CT_OUT** | kretprobe:nf_conntrack_in | 返回值 | • ct_hit = (ret == NF_ACCEPT && existing)<br>• ct_lookup_ns = 出入时间差 |
| **STG_QDISC_ENQ** | kprobe:fq_codel_enqueue | `fq_codel_enqueue(skb, sch, to_free)` | • qdisc_qlen = sch->q.qlen<br>• flow_qlen = flow->head计数<br>• dev = uplink |
| **STG_QDISC_DEQ** | kprobe:fq_codel_dequeue | `fq_codel_dequeue(sch)` | • sojourn_ns = now - flow->time_next_packet<br>• dev = uplink |
| **STG_TX_QUEUE** | TP:net:net_dev_queue | `net_dev_queue(skb)` | • txq = queue_mapping<br>• skb_hash = skb->hash<br>• dev = uplink |
| **STG_TX_XMIT** | TP:net:net_dev_start_xmit | `net_dev_start_xmit(skb, dev)` | • 记录实际发送<br>• dev = uplink |

### 3.2 Uplink→VM 接收路径

| 阶段 | Probe点 | 函数签名 | 采集字段 |
|------|---------|----------|----------|
| **STG_RX_IN** | TP:net:netif_receive_skb | `netif_receive_skb(skb)` | • 解析packet_key<br>• rxq = skb->queue_mapping<br>• skb_hash = skb->hash<br>• read_backlog_info()：backlog_qlen, process_qlen<br>• dev = uplink |
| **STG_RX_BACKLOG** | kprobe:enqueue_to_backlog | `enqueue_to_backlog(skb, cpu, qtail)` | • 记录backlog入队<br>• 更新backlog_qlen（入队后）<br>• cpu = 目标CPU ID |
| **STG_RX_PROCESS** | kprobe:process_backlog | `process_backlog(work, quota)` | • 记录backlog处理开始<br>• 更新process_qlen<br>• quota = 处理配额 |
| **STG_RX_GRO_IN** | kprobe:dev_gro_receive | `dev_gro_receive(list, skb)` | • 记录GRO聚合入口 |
| **STG_RX_GRO_OUT** | kretprobe:dev_gro_receive | 返回值 | • gro_result = 聚合结果<br>• 计算GRO处理耗时 |
| **STG_IP_RCV** | kprobe:ip_rcv | `ip_rcv(skb, dev, pt, orig_dev)` | • 记录IP层接收<br>• 协议栈处理开始 |
| **STG_OVS_IN** | kprobe:ovs_vport_receive | `ovs_vport_receive(vport, skb, tun_info)` | • has_sk状态<br>• 查缓存获取packet_key |
| **STG_OVS_ACT_IN** | kprobe:ovs_execute_actions | `ovs_execute_actions(dp, skb, acts, key)` | • 记录进入时间戳 |
| **STG_OVS_ACT_OUT** | kretprobe:ovs_execute_actions | 返回值 | • 计算OVS处理耗时 |
| **STG_CT_IN** | kprobe:nf_conntrack_in | `nf_conntrack_in(net, pf, hooknum, skb)` | • 记录进入时间戳 |
| **STG_CT_OUT** | kretprobe:nf_conntrack_in | 返回值 | • ct_hit = (ret == NF_ACCEPT && existing)<br>• ct_lookup_ns = 出入时间差 |
| **STG_DEV_Q_XMIT** | kprobe:dev_queue_xmit | `dev_queue_xmit(skb)` | • 记录发送意图<br>• dev = "vnet*" |
| **STG_TX_QUEUE** | TP:net:net_dev_queue | `net_dev_queue(skb)` | • txq = 0（TAP通常单队列）<br>• dev = "vnet*" |

### 3.3 软中断处理路径详细说明

软中断(softirq)是VM网络性能的关键环节，需要重点监控：

#### 3.3.1 软中断处理流程

```
硬中断 → NET_RX_SOFTIRQ → net_rx_action() → process_backlog() → netif_receive_skb()
```

#### 3.3.2 关键监控点

| 监控点 | 函数 | 关键指标 | 性能意义 |
|--------|------|----------|----------|
| **Backlog入队** | `enqueue_to_backlog` | • 入队成功率<br>• CPU间分布<br>• 队列长度变化 | 包是否因backlog队列满而丢弃 |
| **Backlog处理** | `process_backlog` | • 处理配额利用率<br>• 队列消费速度<br>• CPU调度延迟 | 软中断处理效率 |
| **GRO聚合** | `dev_gro_receive` | • 聚合比例<br>• 聚合延迟<br>• 聚合失败率 | GRO对性能的影响 |
| **RPS调度** | `get_rps_cpu` | • CPU选择结果<br>• 负载均衡效果 | 多CPU处理分布 |

#### 3.3.3 性能瓶颈识别

```c
// 软中断性能监控结构
struct softirq_metrics {
    u64 backlog_drops;           // backlog队列满丢包数
    u64 process_quota_exceed;    // 处理配额超限次数
    u64 gro_merged_packets;      // GRO聚合包数
    u64 rps_cpu_migrations;      // RPS引起的CPU迁移数
    u32 max_backlog_qlen;        // 最大backlog队列长度
    u32 avg_process_latency_us;  // 平均处理延迟
};
```

---

## 4. 关键字段读取方法

### 4.1 Backlog队列深度读取

基于kernel 4.19.90的兼容实现方法（避免使用BTF CO-RE）：

```c
// 软中断路径中的backlog队列信息读取
static inline void read_backlog_info(struct pkt_event *evt) {
    int cpu = bpf_get_smp_processor_id();
    void *softnet_data_ptr;
    u32 backlog_qlen = 0, process_qlen = 0;
    
    // 直接从内核符号获取softnet_data per-CPU变量地址
    // 需要在用户态通过/proc/kallsyms获取softnet_data地址
    // 然后通过bpf_probe_read读取per-CPU数据
    
    // 方法1: 在netif_receive_skb中通过参数获取softnet_data
    // 通过当前执行上下文推导softnet_data位置
    
    evt->cpu = cpu;
    evt->backlog_qlen = -1;    // 默认无效值
    evt->process_qlen = -1;
}

// 实用方法：通过现有函数参数间接获取队列信息
static inline s32 read_backlog_from_context(struct pt_regs *ctx) {
    // 在enqueue_to_backlog函数中，可以从函数参数获取队列信息
    // enqueue_to_backlog(struct sk_buff *skb, int cpu, unsigned int *qtail)
    // 其中qtail指向当前CPU的backlog队列尾部计数
    
    unsigned int *qtail = (unsigned int *)PT_REGS_PARM3(ctx);
    if (qtail) {
        unsigned int qlen;
        if (bpf_probe_read(&qlen, sizeof(qlen), qtail) == 0) {
            return qlen;
        }
    }
    return -1;
}

// 内核4.19.90关键结构偏移（通过pahole工具获取）
// 这些偏移需要根据具体内核版本调整
#define SOFTNET_DATA_INPUT_PKT_QUEUE_OFFSET    248  // input_pkt_queue偏移
#define SOFTNET_DATA_PROCESS_QUEUE_OFFSET      32   // process_queue偏移  
#define SK_BUFF_HEAD_QLEN_OFFSET               16   // sk_buff_head.qlen偏移

// 替代方案：通过kprobe函数参数直接获取队列长度
BPF_KPROBE(enqueue_to_backlog, struct sk_buff *skb, int cpu, unsigned int *qtail)
{
    struct pkt_event evt = {};
    unsigned int qlen = 0;
    
    // 直接从函数参数获取当前队列长度
    if (qtail && bpf_probe_read(&qlen, sizeof(qlen), qtail) == 0) {
        evt.backlog_qlen = qlen;
    }
    
    evt.cpu = cpu;
    evt.stage = STG_RX_BACKLOG;
    // ... 其他字段处理
    
    return 0;
}

// process_backlog函数中获取处理队列信息
BPF_KPROBE(process_backlog, struct napi_struct *napi, int quota)
{
    struct pkt_event evt = {};
    
    // napi参数就是softnet_data.backlog，可以通过它访问队列
    // 通过container_of宏的逆向思路计算softnet_data地址
    // 但在eBPF中需要使用固定偏移
    
    evt.cpu = bpf_get_smp_processor_id();
    evt.stage = STG_RX_PROCESS;
    // quota表示本次处理配额
    
    return 0;
}

// 推荐方案：利用现有tracepoint获取队列统计
// 通过/sys/kernel/debug/tracing/events/net/下的tracepoint
TRACEPOINT_PROBE(net, netif_rx) {
    // 在netif_rx tracepoint中可能有队列相关信息
    struct pkt_event evt = {};
    evt.cpu = bpf_get_smp_processor_id();
    return 0;
}

// 实际可行方案：通过/proc/net/softnet_stat补充验证
// 在用户态程序中读取/proc/net/softnet_stat来验证队列统计
// 示例输出: 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
// 字段含义: processed dropped time_squeeze cpu_collision received_rps flow_limit_count ...

// 最实用的backlog监控方法：
// 1. 在enqueue_to_backlog的kprobe中从函数参数获取队列长度
// 2. 在netif_receive_skb中记录包接收，但不强求精确的队列长度
// 3. 通过/proc/net/softnet_stat在用户态定期采样作为补充验证
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
- **传递标记**：通过BPF map标记`pkt_id`为已通过过滤
- **后续阶段**：检查`pkt_id`是否在通过列表中

### 5.3 方向判定规则

```c
static inline u8 determine_direction(u8 stage, const char *dev) {
    if (stage == STG_RX_IN) {
        if (strncmp(dev, "vnet", 4) == 0)
            return 0;  // VM→UP
        else
            return 1;  // UP→VM（待后续确认）
    }
    
    // 继承之前的方向
    return get_cached_direction(pkt_id);
}
```

---

## 6. 克隆包处理

### 6.1 克隆检测

```c
// 监控skb_clone创建克隆包
BPF_KRETPROBE(skb_clone) {
    struct sk_buff *parent = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct sk_buff *child = (struct sk_buff *)PT_REGS_RC(ctx);
    
    if (child) {
        // 建立子包到父包的映射
        u64 parent_id = (u64)parent;
        u64 child_id = (u64)child;
        bpf_map_update_elem(&clone_map, &child_id, &parent_id, BPF_ANY);
    }
}
```

### 6.2 统一ID查询

```c
static inline u64 get_unified_pkt_id(struct sk_buff *skb) {
    u64 pkt_id = (u64)skb;
    u64 *parent_id;
    
    // 查询是否为克隆包
    parent_id = bpf_map_lookup_elem(&clone_map, &pkt_id);
    if (parent_id)
        return *parent_id;  // 使用父包ID
    
    return pkt_id;  // 使用自身ID
}
```

---

## 7. 性能优化策略

### 7.1 缓存机制
- **Packet Key缓存**：首次解析后缓存，后续查询使用
- **过滤结果缓存**：已通过过滤的pkt_id缓存，避免重复判断
- **方向信息缓存**：包的方向确定后缓存，后续直接使用

### 7.2 Map设计

```c
// 核心数据缓存Map
// Packet key缓存（LRU，10000条目）
BPF_HASH(pkt_key_cache, u64, struct packet_key_t, 10000);

// 过滤通过列表（LRU，5000条目）
BPF_HASH(filter_passed, u64, u8, 5000);

// 克隆映射表（LRU，1000条目）
BPF_HASH(clone_map, u64, u64, 1000);

// 方向缓存（LRU，5000条目）
BPF_HASH(dir_cache, u64, u8, 5000);

// 性能测量相关Map
// CT查表时间记录（用于计算耗时）
BPF_HASH(ct_start_time, u64, u64, 1000);
// OVS处理时间记录
BPF_HASH(ovs_start_time, u64, u64, 1000);
// Qdisc sojourn时间基准
BPF_HASH(qdisc_enqueue_time, u64, u64, 2000);

// 统计和监控Map
// 各阶段事件计数
BPF_ARRAY(stage_counters, u64, 20);
// 丢包统计按原因分类
BPF_HASH(drop_stats, u32, u64, 50);

// 配置控制Map
// 动态配置控制
BPF_ARRAY(config_map, struct trace_config, 1);
// probe点启用状态控制
BPF_ARRAY(probe_enable_map, u8, 20);
```

### 7.3 开销控制
- **提前退出**：未通过过滤的包立即返回
- **选择性采集**：根据配置决定是否采集某些字段
- **批量输出**：使用perf buffer批量传输数据到用户态

---

## 8. 输出格式设计

### 8.1 二进制格式（推荐）
直接输出`struct pkt_event`二进制数据到perf buffer，用户态解析。

### 8.2 文本格式（调试用）
```
[时间戳] PKT_ID=xxx DIR=VM→UP STAGE=RX_IN DEV=vnet0
  KEY: TCP 192.168.1.10:8080->10.0.0.1:80 SEQ=12345 LEN=1460
  QUEUE: RXQ=2 TXQ=-1 HASH=0xabcd1234
  QLEN: BACKLOG=5 QDISC=10 FLOW=2 SOJOURN=120us
  LOOKUP: CT=HIT/25us OVS=15us
```

---

## 9. 使用示例

### 9.1 命令行接口
```bash
# 追踪VM到外部的TCP流量
./vm_net_trace --dir=tx --proto=tcp \
               --src-ip=192.168.1.10 --dst-ip=10.0.0.1

# 追踪指定VM设备的所有流量
./vm_net_trace --dev=vnet0 --verbose

# 追踪带conntrack的流量
./vm_net_trace --dev=vnet1 --enable-ct
```

### 9.2 输出解析工具
```python
# 解析二进制输出，生成时序图
./parse_vm_trace.py trace.bin --format=timeline

# 统计各阶段延迟
./parse_vm_trace.py trace.bin --stats --group-by=stage

# 导出为CSV
./parse_vm_trace.py trace.bin --export=csv > vm_trace.csv
```

---

## 10. 测试验证计划

### 10.1 功能测试
- [ ] VM网络双向路径追踪验证
- [ ] 五元组过滤准确性测试
- [ ] 设备名过滤测试（vnet*）
- [ ] 克隆包处理验证
- [ ] OVS conntrack处理验证

### 10.2 性能测试
- [ ] 10Gbps VM流量下的CPU开销
- [ ] 内存使用情况监控
- [ ] Map容量压力测试
- [ ] 丢包率影响评估

### 10.3 兼容性测试
- [ ] OVS CT开启/关闭场景
- [ ] 不同qdisc配置测试
- [ ] vhost-net配置验证

---

## 11. 注意事项与限制

### 11.1 内核版本兼容性
- **Kernel 4.19.90特定注意事项**：
  - 某些函数可能有`.isra.XX`后缀，需要动态符号查找
  - OVS相关函数依赖OVS版本
  - 内核符号信息必须可用（`/proc/kallsyms`或debuginfo）

### 11.2 性能影响
- **低流量（<1Gbps）**：CPU开销 < 1%
- **中等流量（1-5Gbps）**：CPU开销 1-3%
- **高流量（5-10Gbps）**：CPU开销 3-8%

### 11.3 probe点可靠性分级

**HIGH可靠性（推荐生产使用）**：
- `netif_receive_skb` - 核心接收点
- `dev_queue_xmit` - 核心发送点
- tracepoint类探测点（稳定性高）

**MEDIUM可靠性（测试环境推荐）**：
- OVS相关函数 - 依赖OVS版本
- qdisc相关 - 依赖具体qdisc类型

**LOW可靠性（调试时使用）**：
- 内部辅助函数 - 可能被内联或优化掉

---

## 附录A：关键数据结构偏移（Kernel 4.19.90）

```c
// struct softnet_data偏移
#define SOFTNET_INPUT_QUEUE_OFFSET 0x68  // input_pkt_queue字段偏移

// struct sk_buff关键字段偏移
#define SKB_QUEUE_MAPPING_OFFSET 0x34
#define SKB_HASH_OFFSET 0x38
#define SKB_SK_OFFSET 0x18
```

---

*文档版本：1.0（VM网络专用版）*  
*更新日期：2024年*  
*基于Kernel 4.19.90验证，专注VM网络路径追踪*