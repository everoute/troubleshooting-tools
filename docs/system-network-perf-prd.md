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

### 2.1 系统网络相关阶段枚举（stage）

```c
enum pkt_stage {
    // 链路层接收路径
    STG_RX_IN        = 1,   // netif_receive_skb - 统一接收入口
    STG_GRO_IN       = 2,   // napi_gro_receive - GRO处理
    STG_RPS_ENQ      = 3,   // enqueue_to_backlog - RPS入队（可选）
    STG_RPS_DEQ      = 4,   // process_backlog - RPS出队（可选）
    STG_XDP_PROC     = 5,   // netif_receive_generic_xdp - XDP处理
    
    // 网络层处理（IP协议栈）
    STG_IP_RCV       = 10,  // ip_rcv - IP层接收入口
    STG_IP_RCV_CORE  = 11,  // ip_rcv_core - IP核心处理
    STG_IP_RCV_FIN   = 12,  // ip_rcv_finish - IP接收完成
    STG_IP_LOCAL_DEL = 13,  // ip_local_deliver - 本地投递
    STG_IP_FORWARD   = 14,  // ip_forward - IP转发
    STG_FIB_LOOKUP   = 15,  // fib_table_lookup - 路由查询
    
    // OVS虚拟化处理
    STG_OVS_IN       = 20,  // ovs_vport_receive - OVS入口
    STG_OVS_ACT_IN   = 21,  // ovs_execute_actions进入
    STG_OVS_ACT_OUT  = 22,  // ovs_execute_actions退出
    STG_CT_IN        = 23,  // nf_conntrack_in进入
    STG_CT_OUT       = 24,  // nf_conntrack_in退出
    
    // netfilter处理
    STG_NF_HOOK      = 30,  // nf_hook_slow - netfilter钩子
    STG_IPTABLES     = 31,  // ipt_do_table - iptables规则
    STG_IPT6_TABLE   = 32,  // ip6t_do_table - ip6tables规则
    STG_NAT_MANIP    = 33,  // nf_nat_manip_pkt - NAT转换
    
    // 传输层处理
    STG_TCP_RCV      = 40,  // tcp_v4_rcv - TCP接收
    STG_TCP_EST_RCV  = 41,  // tcp_rcv_established - TCP已建立连接处理
    STG_UDP_RCV      = 42,  // udp_rcv - UDP接收
    STG_ICMP_RCV     = 43,  // icmp_rcv - ICMP接收
    STG_SOCK_LOOKUP  = 44,  // __inet_lookup_listener - socket查找
    
    // 发送路径起始
    STG_SOCK_SEND    = 50,  // tcp_sendmsg/udp_sendmsg - 本地发送起点
    STG_TCP_XMIT     = 51,  // __tcp_transmit_skb - TCP发送
    STG_UDP_SEND     = 52,  // udp_send_skb - UDP发送
    STG_IP_QUEUE     = 53,  // __ip_queue_xmit - IP队列发送
    STG_IP_OUTPUT    = 54,  // ip_output - IP输出
    STG_IP_FIN_OUT   = 55,  // ip_finish_output - IP输出完成
    STG_IP_FIN_OUT2  = 56,  // ip_finish_output2 - IP输出最终处理
    
    // Qdisc流控处理
    STG_QDISC_ENQ    = 60,  // fq_codel_enqueue - Qdisc入队
    STG_QDISC_DEQ    = 61,  // fq_codel_dequeue - Qdisc出队
    STG_TC_CLASSIFY  = 62,  // tcf_classify - TC分类
    STG_TC_ACTION    = 63,  // tcf_action - TC动作
    
    // 设备发送路径
    STG_DEV_Q_XMIT   = 70,  // dev_queue_xmit - 通用发送入口
    STG_DEV_HARD_TX  = 71,  // dev_hard_start_xmit - 硬件发送启动
    STG_TX_QUEUE     = 72,  // net_dev_queue - 设备队列
    STG_TX_XMIT      = 73,  // net_dev_start_xmit - 设备发送
    
    // 应用层终点
    STG_SOCK_RECV    = 90,  // tcp_cleanup_rbuf/udp_queue_rcv_skb - 本地接收终点
    STG_SOCK_QUEUE   = 91,  // sock_queue_rcv_skb - socket队列入队
};
```

---

## 3. 系统网络数据路径（Local ↔ OVS Internal ↔ Uplink）

### 3.1 Local→Uplink 发送路径（基于协议栈完整链路）

| 阶段 | Probe点 | 函数签名 | 采集字段 | 优先级 |
|------|---------|----------|----------|--------|
| **STG_SOCK_SEND** | kprobe:tcp_sendmsg_locked<br>kprobe:udp_send_skb<br>kprobe:ping_v4_sendmsg | `tcp_sendmsg_locked(sk, msg, size)`<br>`udp_send_skb(sk, skb, fl4)`<br>`ping_v4_sendmsg()` | • 解析packet_key（从sk和msg）<br>• sk_wmem = sk->sk_wmem_queued<br>• sk_wmem_lim = sk->sk_sndbuf<br>• has_sk = 1<br>• protocol类型识别 | **HIGH** |
| **STG_TCP_XMIT** | kprobe:__tcp_transmit_skb | `__tcp_transmit_skb(sk, skb, clone_it, gfp_mask, rcv_nxt)` | • TCP特有字段：seq、ack、窗口<br>• 重传标记<br>• 拥塞控制状态 | MED |
| **STG_IP_QUEUE** | kprobe:__ip_queue_xmit | `__ip_queue_xmit(sk, skb, fl, opt_len)` | • IP层处理开始<br>• 路由查找准备 | **HIGH** |
| **STG_FIB_LOOKUP** | kprobe:fib_table_lookup<br>kprobe:ip_route_output_key_hash | `fib_table_lookup(tb, flp, res)`<br>`ip_route_output_key_hash()` | • 路由查找耗时<br>• 路由缓存命中状态<br>• fib_hit标记 | MED |
| **STG_IP_OUTPUT** | kprobe:ip_output | `ip_output(net, sk, skb)` | • IP输出处理<br>• TTL处理<br>• 分片标记 | MED |
| **STG_IP_FIN_OUT** | kprobe:ip_finish_output | `ip_finish_output(net, sk, skb)` | • 输出完成处理<br>• GSO检查 | **HIGH** |
| **STG_IP_FIN_OUT2** | kprobe:ip_finish_output2 | `ip_finish_output2(net, sk, skb)` | • 邻居子系统处理<br>• ARP查询（如需要） | MED |
| **STG_OVS_IN** | kprobe:ovs_vport_receive | 同上 | • dev = internal port名称<br>• 绑定pkt_id<br>• OVS datapath信息 | **HIGH** |
| **STG_OVS_ACT_IN/OUT** | 同上 | 同上 | • OVS actions执行<br>• flow table查找 | MED |
| **STG_CT_IN/OUT** | kprobe:nf_conntrack_in<br>kretprobe:nf_conntrack_in | `nf_conntrack_in(net, pf, hooknum, skb)` | • conntrack状态<br>• NAT转换（如有）<br>• ct_lookup_ns耗时 | MED |
| **STG_IPTABLES** | kprobe:ipt_do_table<br>kprobe:ipt_do_table_legacy | `ipt_do_table(skb, state, table)` | • iptables规则匹配<br>• 规则链遍历耗时<br>• verdict结果 | LOW |
| **STG_QDISC_ENQ** | kprobe:fq_codel_enqueue<br>TP:qdisc:qdisc_enqueue | `fq_codel_enqueue(skb, sch, to_free)` | • qdisc队列状态<br>• flow队列选择<br>• 拥塞控制状态 | **HIGH** |
| **STG_TC_CLASSIFY** | kprobe:tcf_classify | `tcf_classify(skb, tp, res)` | • TC规则匹配<br>• 流量整形决策 | LOW |
| **STG_QDISC_DEQ** | kprobe:fq_codel_dequeue<br>TP:qdisc:qdisc_dequeue | `fq_codel_dequeue(sch)` | • 出队延迟（sojourn time）<br>• CoDel算法状态 | **HIGH** |
| **STG_DEV_Q_XMIT** | kprobe:__dev_queue_xmit | `__dev_queue_xmit(skb, sb_dev)` | • 设备发送入口<br>• 队列选择逻辑 | **HIGH** |
| **STG_TX_QUEUE** | TP:net:net_dev_queue | `net_dev_queue(skb)` | • 设备队列状态<br>• 多队列分发 | **HIGH** |
| **STG_DEV_HARD_TX** | kprobe:dev_hard_start_xmit | `dev_hard_start_xmit(skb, dev, txq, more)` | • 驱动发送准备<br>• DMA映射状态 | **HIGH** |
| **STG_TX_XMIT** | TP:net:net_dev_start_xmit | `net_dev_start_xmit(skb, dev)` | • 最终硬件发送<br>• 发送完成确认 | **HIGH** |

### 3.2 Uplink→Local 接收路径（基于协议栈完整链路）

| 阶段 | Probe点 | 函数签名 | 采集字段 | 优先级 |
|------|---------|----------|----------|--------|
| **STG_RX_IN** | TP:net:netif_receive_skb<br>kprobe:netif_receive_skb | `netif_receive_skb(skb)` | • dev = uplink<br>• 解析packet_key<br>• 接收队列信息<br>• GRO状态 | **HIGH** |
| **STG_GRO_IN** | TP:net:napi_gro_receive_entry<br>kprobe:napi_gro_receive | `napi_gro_receive(napi, skb)` | • GRO合并状态<br>• NAPI处理状态 | MED |
| **STG_RPS_ENQ** | kprobe:enqueue_to_backlog | `enqueue_to_backlog(skb, cpu, qlen)` | • RPS队列状态<br>• CPU负载均衡 | LOW |
| **STG_XDP_PROC** | kprobe:netif_receive_generic_xdp | `netif_receive_generic_xdp(skb)` | • XDP程序处理结果<br>• 包重定向状态 | LOW |
| **STG_IP_RCV** | kprobe:ip_rcv | `ip_rcv(skb, dev, pt, orig_dev)` | • IP层接收开始<br>• IP头校验状态 | **HIGH** |
| **STG_IP_RCV_CORE** | kprobe:ip_rcv_core | `ip_rcv_core(skb, net)` | • IP核心处理<br>• 包过滤检查 | MED |
| **STG_IPTABLES** | kprobe:ipt_do_table | `ipt_do_table(skb, state, table)` | • iptables PREROUTING<br>• 防火墙规则检查 | MED |
| **STG_FIB_LOOKUP** | kprobe:fib_validate_source<br>kprobe:ip_route_input_slow | `fib_validate_source()`<br>`ip_route_input_slow()` | • 路由有效性检查<br>• 反向路径过滤（rp_filter）<br>• fib_lookup_ns耗时 | MED |
| **STG_IP_RCV_FIN** | kprobe:ip_rcv_finish | `ip_rcv_finish(net, sk, skb)` | • 路由决策结果<br>• 本地投递vs转发 | **HIGH** |
| **STG_IP_LOCAL_DEL** | kprobe:ip_local_deliver<br>kprobe:ip_local_deliver_finish | `ip_local_deliver(skb)`<br>`ip_local_deliver_finish(net, sk, skb)` | • 本地投递确认<br>• 传输层准备 | **HIGH** |
| **STG_OVS_IN** | kprobe:ovs_vport_receive | 同上 | • dev = internal port<br>• OVS流表查找 | **HIGH** |
| **STG_OVS_ACT_IN/OUT** | 同上 | 同上 | • OVS actions执行<br>• VLAN处理（如有） | MED |
| **STG_CT_IN/OUT** | 同发送路径 | 同上 | • conntrack状态确认<br>• 已有连接匹配 | MED |
| **STG_TCP_RCV** | kprobe:tcp_v4_rcv | `tcp_v4_rcv(skb)` | • TCP协议处理<br>• socket查找准备 | **HIGH** |
| **STG_SOCK_LOOKUP** | kprobe:__inet_lookup_listener<br>kprobe:inet6_lookup_listener | `__inet_lookup_listener()`<br>`inet6_lookup_listener()` | • socket查找耗时<br>• 监听端口匹配结果 | MED |
| **STG_TCP_EST_RCV** | kprobe:tcp_rcv_established<br>kprobe:tcp_v4_do_rcv | `tcp_rcv_established(sk, skb)`<br>`tcp_v4_do_rcv(sk, skb)` | • 已建立连接处理<br>• 序列号检查<br>• 窗口更新 | MED |
| **STG_UDP_RCV** | kprobe:udp_rcv<br>kprobe:udp_unicast_rcv_skb | `udp_rcv(skb)`<br>`udp_unicast_rcv_skb()` | • UDP协议处理<br>• 校验和验证 | MED |
| **STG_ICMP_RCV** | kprobe:icmp_rcv<br>kprobe:ping_rcv | `icmp_rcv(skb)`<br>`ping_rcv(skb)` | • ICMP协议处理<br>• ping响应处理 | MED |
| **STG_SOCK_QUEUE** | kprobe:sock_queue_rcv_skb | `sock_queue_rcv_skb(sk, skb)` | • socket缓冲区入队<br>• 接收缓冲区状态检查 | **HIGH** |
| **STG_SOCK_RECV** | kprobe:tcp_cleanup_rbuf<br>kprobe:udp_queue_rcv_skb<br>kprobe:__ping_queue_rcv_skb | `tcp_cleanup_rbuf(sk, copied)`<br>`udp_queue_rcv_skb(sk, skb)`<br>`__ping_queue_rcv_skb()` | • sk_rmem = sk->sk_rmem_alloc<br>• sk_rmem_lim = sk->sk_rcvbuf<br>• has_sk = 1<br>• 应用层读取准备完成 | **HIGH** |

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