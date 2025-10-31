# Kernel RX Path Analysis: enqueue_to_backlog → __netif_receive_skb

## Question

在物理网卡收包（挂在 OVS 上的上联网卡）与 OVS 处理完后 OVS internal port 处理收包到协议栈这两个流程中，是否都存在 `enqueue_to_backlog` → `__netif_receive_skb` 这个流程？

## Answer: 是的，两个流程都经过这个路径

基于 kernel 4.19.90 源码分析，**两个流程都会经过 `enqueue_to_backlog` → `__netif_receive_skb`**，但具体路径略有不同。

---

## 详细分析

### 流程 1: 物理网卡收包路径

**调用链:**

```
驱动 NAPI poll
  → netif_receive_skb()           // net/core/dev.c:5221
      → netif_receive_skb_internal()  // net/core/dev.c:5146
          → [RPS enabled] enqueue_to_backlog()  // net/core/dev.c:5162
          → [RPS disabled] __netif_receive_skb()  // net/core/dev.c:5168

[Later, in softirq context:]
process_backlog()  // net/core/dev.c:5840
  → __netif_receive_skb()  // net/core/dev.c:5860
```

**关键代码 (net/core/dev.c:5146-5171):**

```c
static int netif_receive_skb_internal(struct sk_buff *skb)
{
    int ret;

    net_timestamp_check(READ_ONCE(netdev_tstamp_prequeue), skb);

    if (skb_defer_rx_timestamp(skb))
        return NET_RX_SUCCESS;

    rcu_read_lock();
#ifdef CONFIG_RPS
    if (static_key_false(&rps_needed)) {
        struct rps_dev_flow voidflow, *rflow = &voidflow;
        int cpu = get_rps_cpu(skb->dev, skb, &rflow);

        if (cpu >= 0) {
            // RPS enabled: 走 enqueue_to_backlog
            ret = enqueue_to_backlog(skb, cpu, &rflow->last_qtail);
            rcu_read_unlock();
            return ret;
        }
    }
#endif
    // RPS disabled: 直接走 __netif_receive_skb
    ret = __netif_receive_skb(skb);
    rcu_read_unlock();
    return ret;
}
```

### 流程 2: OVS Internal Port 收包路径

**调用链:**

```
OVS datapath 处理
  → internal_dev_recv()  // net/openvswitch/vport-internal_dev.c:276
      → netif_rx()  // net/core/dev.c:4526
          → netif_rx_internal()  // net/core/dev.c:4476
              → enqueue_to_backlog()  // ALWAYS! (net/core/dev.c:4496 or 4505)

[Later, in softirq context:]
process_backlog()  // net/core/dev.c:5840
  → __netif_receive_skb()  // net/core/dev.c:5860
```

**关键代码 1 - OVS internal port (net/openvswitch/vport-internal_dev.c:276):**

```c
static netdev_tx_t internal_dev_recv(struct sk_buff *skb)
{
    // ... packet processing ...

    netif_rx(skb);  // 总是调用 netif_rx
    return NETDEV_TX_OK;
}
```

**关键代码 2 - netif_rx_internal (net/core/dev.c:4476-4509):**

```c
static int netif_rx_internal(struct sk_buff *skb)
{
    int ret;

    net_timestamp_check(READ_ONCE(netdev_tstamp_prequeue), skb);
    trace_netif_rx(skb);

#ifdef CONFIG_RPS
    if (static_key_false(&rps_needed)) {
        struct rps_dev_flow voidflow, *rflow = &voidflow;
        int cpu;

        preempt_disable();
        rcu_read_lock();

        cpu = get_rps_cpu(skb->dev, skb, &rflow);
        if (cpu < 0)
            cpu = smp_processor_id();

        // RPS enabled: enqueue to target CPU
        ret = enqueue_to_backlog(skb, cpu, &rflow->last_qtail);

        rcu_read_unlock();
        preempt_enable();
    } else
#endif
    {
        unsigned int qtail;

        // RPS disabled: enqueue to current CPU
        ret = enqueue_to_backlog(skb, get_cpu(), &qtail);
        put_cpu();
    }
    return ret;
}
```

---

## 关键区别

| 特性 | 物理网卡路径 | OVS Internal Port 路径 |
|------|------------|----------------------|
| 入口函数 | `netif_receive_skb()` | `netif_rx()` |
| 是否总是 enqueue | **否** (RPS 未启用时直接调用 `__netif_receive_skb`) | **是** (总是调用 `enqueue_to_backlog`) |
| RPS 影响 | 决定是否走 backlog | 仅决定 enqueue 到哪个 CPU |
| 处理上下文 | NAPI softirq (可能同步) | 总是异步 (需要 backlog NAPI poll) |

---

## 为什么 OVS Internal Port 总是走 enqueue_to_backlog?

**设计原因:**

1. **上下文隔离**: OVS datapath 可能在任意上下文执行（硬中断、softirq、进程上下文），使用 `netif_rx()` 确保统一的异步处理路径

2. **避免栈溢出**: OVS 处理可能已经消耗了较多栈空间，不适合直接同步调用协议栈

3. **CPU 调度灵活性**: 允许通过 RPS 将包调度到其他 CPU 处理，提高并发性

4. **历史设计**: `netif_rx()` 是传统的 "从中断上下文接收包" 的 API，而 `netif_receive_skb()` 是为 NAPI 优化的 API

---

## 对 eBPF 工具的影响

### 问题根源

当前的 eBPF 工具 (`enqueue_to_iprec_latency.py` 和 `enqueue_to_iprec_latency_threshold.py`) 在两个 kprobe 点都使用相同的 interface 过滤逻辑:

```c
// Stage 1: enqueue_to_backlog
int kprobe__enqueue_to_backlog(...) {
    if (!is_target_ifindex(skb)) {
        return 0;  // 过滤掉
    }
    // ...
}

// Stage 2: __netif_receive_skb
int kprobe____netif_receive_skb(...) {
    if (!is_target_ifindex(skb)) {
        return 0;  // 过滤掉
    }
    // ...
}
```

### 问题场景

**场景**: 物理网卡 (enp24s0f0np0) → OVS bridge → OVS internal port (br-int)

1. **物理网卡收包**:
   - `enqueue_to_backlog`: `skb->dev` = enp24s0f0np0 ✓ (匹配)
   - `__netif_receive_skb`: `skb->dev` = enp24s0f0np0 ✓ (匹配)
   - **结果**: 正常测量

2. **OVS internal port 收包**:
   - `enqueue_to_backlog`: `skb->dev` = br-int ✓ (如果配置了 internal-interface)
   - `__netif_receive_skb`: `skb->dev` = br-int ✓ (如果配置了 internal-interface)
   - **结果**: 正常测量

3. **问题情况 - 只指定 phy-interface**:
   - 物理网卡包在 `enqueue_to_backlog` 时被记录 (dev=enp24s0f0np0)
   - 但该包后续被 OVS 转发到 internal port
   - OVS 创建**新的 skb** 调用 `netif_rx()` 时 dev=br-int
   - 原始包的 flow 在 `__netif_receive_skb` 时找不到匹配 (因为被过滤了)
   - **结果**: flow lookup failure

### 验证方法

运行工具并查看计数器:

```bash
sudo ./enqueue_to_iprec_latency.py \
    --phy-interface enp24s0f0np0 \
    --dst-port 2181 --protocol tcp --debug
```

如果看到:
- `Enqueued packets: 1000`
- `Flow lookup failures: 950`

说明大部分包在 enqueue 阶段被记录了，但在 receive 阶段因为 interface 变化而找不到。

---

## 建议修复方案

### 方案 1: 同时监控两个 interface (推荐)

```python
parser.add_argument('--phy-interface', required=True,
                    help='Physical interface')
parser.add_argument('--internal-interface', required=False,
                    help='OVS internal interface (optional)')

# 在 BPF 代码中
#define TARGET_IFINDEX1 %d  // phy interface
#define TARGET_IFINDEX2 %d  // internal interface (same as ifindex1 if not specified)

static __always_inline bool is_target_ifindex(const struct sk_buff *skb) {
    // ... existing code ...
    return (ifindex == TARGET_IFINDEX1 || ifindex == TARGET_IFINDEX2);
}
```

**当前工具已经实现了这个方案**，但文档不清楚使用场景。

### 方案 2: 仅在 enqueue 阶段过滤 interface

```c
// Stage 1: enqueue_to_backlog - 过滤 interface
int kprobe__enqueue_to_backlog(...) {
    if (!is_target_ifindex(skb)) {
        return 0;
    }
    // ... 创建 flow ...
}

// Stage 2: __netif_receive_skb - 不过滤 interface，依赖 flow lookup
int kprobe____netif_receive_skb(...) {
    // 移除 interface 检查
    // if (!is_target_ifindex(skb)) { return 0; }

    // 直接解析包并 lookup flow
    struct packet_key_t key = {};
    if (!parse_packet_key(skb, &key, STAGE_RECEIVE)) {
        return 0;
    }

    struct flow_data_t *flow_ptr = flow_sessions.lookup(&key);
    if (!flow_ptr) {
        return 0;  // 不是我们跟踪的 flow
    }
    // ... 测量 latency ...
}
```

**优点**: 更灵活，自动跟踪跨 interface 的包
**缺点**: 可能引入更多噪音

### 方案 3: 基于 flow 而不是 interface 过滤

完全移除 interface 过滤，仅依赖 IP/Port/Protocol 过滤来识别目标流量。

---

## 总结

1. ✅ **两个流程都存在 `enqueue_to_backlog` → `__netif_receive_skb`**
2. ⚠️ **OVS internal port 总是走 `enqueue_to_backlog`** (通过 `netif_rx`)
3. ⚠️ **物理网卡可能直接走 `__netif_receive_skb`** (RPS 未启用时)
4. 🐛 **当前工具的 interface 过滤逻辑需要优化**:
   - 用户必须同时指定 `--phy-interface` 和 `--internal-interface` 来正确测量 OVS 场景
   - 或者修改工具在 receive 阶段不过滤 interface

## 建议的工具使用方式

**正确用法 (OVS 环境):**

```bash
# 测量物理网卡 → OVS internal port 的完整路径
sudo ./enqueue_to_iprec_latency.py \
    --phy-interface enp24s0f0np0 \
    --internal-interface br-int \
    --dst-port 2181 --protocol tcp
```

**文档改进建议:**

在工具的帮助信息中明确说明:
- OVS 环境下必须指定 `--internal-interface`
- 解释为什么需要两个 interface (因为包会经过两次 enqueue/receive 循环)
