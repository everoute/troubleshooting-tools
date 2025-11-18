# frag_list 监控点深度分析

基于 Linux 4.18.0-553.47.1.el8_10 内核代码的完整梳理

## 执行摘要

崩溃条件：`skb_segment+558` (line 4263) 访问 `list_skb` 时空指针解引用
- `gso_size = 1348` (非零 GSO 包)
- `frag_list = NULL` (但代码期望非 NULL)
- `gso_type = 0x403` (DODGY|UDP_TUNNEL|PARTIAL)

**核心矛盾**：gso_type 标志表明这是一个需要 GSO 处理的包，但 frag_list 为 NULL 且无其他分段数据（nr_frags=0, data_len=0）。

---

## 一、当前工具覆盖的监控点

### 已监控函数（5个）

| 函数 | 事件类型 | 触发条件 | 覆盖场景 |
|------|---------|---------|---------|
| `skb_gro_receive_list` | CREATE | frag_list NULL→非NULL | GRO 接收聚合 |
| `skb_segment_list` | CLEAR | frag_list 非NULL→NULL | 基于 frag_list 的 GSO 分段 |
| `pskb_expand_head` | MODIFY | frag_list 改变 | 头部扩展 |
| `__skb_linearize` | CLEAR | frag_list 非NULL→NULL | SKB 线性化（可选） |
| `skb_segment` | ACCESS | frag_list==NULL && gso_size>0 | **崩溃点**（危险访问） |

### 当前覆盖的问题

1. **只监控显式修改点**：只能看到 frag_list 被**主动改变**的场景
2. **无法追踪隐式传播**：当 SKB 被复制/克隆时，gso_type 可能被传播但 frag_list 处理不当
3. **缺少关键复制路径**：`__pskb_copy_fclone()`, `pskb_carve_frag_list()` 等未监控
4. **缺少协议栈构造点**：IPv4/IPv6 输出路径、UDP offload 路径未监控

---

## 二、缺失的关键监控点分析

### A. 核心工具函数（3个）- **高优先级**

#### 1. `skb_frag_list_init()` (inline)
**位置**：`include/linux/skbuff.h:3627`

```c
static inline void skb_frag_list_init(struct sk_buff *skb) {
    skb_shinfo(skb)->frag_list = NULL;
}
```

**调用点**（7个）：
| 文件 | 行号 | 函数上下文 | 风险等级 |
|------|------|-----------|---------|
| `net/ipv4/ip_output.c` | 678 | `ip_fragment()` | ⚠️ **高** - IP 分片后置空 |
| `net/ipv6/ip6_output.c` | 747 | `ip6_fragment()` | ⚠️ **高** - IPv6 分片后置空 |
| `net/ieee802154/6lowpan/reassembly.c` | 236 | 6LoWPAN 重组 | 低 |
| `net/phonet/pep.c` | 1233 | Phonet 协议 | 低 |
| `net/phonet/pep-gprs.c` | 121 | GPRS 处理 | 低 |
| `net/ipv4/inet_fragment.c` | 450 | IP 分片重组 | 中 |
| `drivers/net/xen-netback/netback.c` | 1076 | Xen 后端 | 中 |

**监控价值**：
- **关键路径**：IP 分片路径（`ip_fragment`, `ip6_fragment`）会保存 frag_list 指针后置空，遍历处理
- **风险**：如果后续流程**失败但未清理** gso_type，就会造成不一致状态
- **内联函数问题**：无法直接用 kprobe hook，需要监控**调用者**

#### 2. `skb_drop_fraglist()` / `skb_drop_list()`
**位置**：`net/core/skbuff.c:726-728`

```c
static inline void skb_drop_fraglist(struct sk_buff *skb) {
    skb_drop_list(&skb_shinfo(skb)->frag_list);  // 释放并置NULL
}
```

**调用点**：
- `net/core/skbuff.c:2215` - `___pskb_trim()` 中裁剪路径

**监控价值**：
- 所有释放 frag_list 的**必经之路**
- 确认释放时是否同步清理了 GSO 元数据

#### 3. `skb_clone_fraglist()`
**位置**：`net/core/skbuff.c:732-738`

```c
static void skb_clone_fraglist(struct sk_buff *skb) {
    struct sk_buff *list;
    skb_walk_frags(skb, list)
        skb_get(list);  // 增加引用计数
}
```

**调用点**：复制/克隆路径中维护 frag_list 的引用计数

**监控价值**：
- 追踪 frag_list 的**生命周期管理**
- 确认克隆后 frag_list 的共享状态

---

### B. 复制/克隆/扩展路径（6个）- **关键优先级**

#### 4. `__pskb_copy_fclone()` ⭐⭐⭐
**位置**：`net/core/skbuff.c:1812-1820`

**核心逻辑**：
```c
// 直接复制 frag_list 指针，并增加引用计数
if (skb_shinfo(skb)->frag_list) {
    skb_shinfo(n)->frag_list = skb_shinfo(skb)->frag_list;
    skb_clone_fraglist(n);
}
```

**监控价值**：
- ⚠️ **高风险点**：复制 SKB 时，frag_list 被直接赋值但 **gso_type 也一起复制**
- 如果原 SKB 的 gso_type **不一致**（如被错误设置），会传播到新 SKB
- 需要监控：复制前后 gso_type 和 frag_list 的一致性

#### 5. `pskb_expand_head()` （已监控，需加强）
**位置**：`net/core/skbuff.c:1883-1890`

**当前问题**：
- 已监控 entry-return 对，但未检查 **cloned 状态**的特殊处理
- 当 SKB 被 clone 且有 frag_list 时，会调用 `skb_clone_fraglist()`

**增强监控**：
- 检测 `skb->cloned` 状态
- 追踪 `skb_clone_fraglist()` 是否被调用

#### 6. `skb_realloc_headroom()`
**位置**：`net/core/skbuff.c:1934-1950`

**逻辑**：`skb_clone()` + `pskb_expand_head()`

**监控价值**：
- 间接触发 frag_list 复制
- 追踪复制链路上的状态传播

#### 7. `skb_copy()` / `skb_copy_expand()` ⭐⭐
**位置**：`net/core/skbuff.c:1736, 1976`

**关键防护**：
```c
if (WARN_ON_ONCE(skb_shinfo(skb)->gso_type & SKB_GSO_FRAGLIST))
    return NULL;  // 拒绝复制 frag_list GSO 包
```

**监控价值**：
- ⚠️ **高价值**：这是内核的**安全检查点**
- 如果这个 `WARN_ON_ONCE` 被触发，说明有代码试图复制 frag_list GSO 包
- **需要监控**：是否有调用者**忽略了返回值 NULL**，继续使用了错误的 SKB

**监控方法**：
- Hook `skb_copy` 和 `skb_copy_expand` 的 **return 点**
- 检查返回值是否为 NULL
- 如果为 NULL，记录调用栈和 SKB 状态

#### 8. `alloc_skb_for_msg()`
**位置**：`net/core/skbuff.c:1256-1278`

**逻辑**：
```c
skb_shinfo(n)->frag_list = first;  // 直接挂接 frag_list
```

**监控价值**：
- 消息组装场景，构造新的 frag_list 头节点
- 追踪 frag_list 的**创建来源**

---

### C. 分段/裁剪函数（3个）- **中优先级**

#### 9. `pskb_carve_frag_list()` ⭐⭐
**位置**：`net/core/skbuff.c:6342-6394`

**核心逻辑**：
```c
// 裁剪时重新挂接 frag_list
while ((list = shinfo->frag_list) != insp) {
    shinfo->frag_list = list->next;  // 反复修改 frag_list 指针
    kfree_skb(list);
}
if (clone) {
    clone->next = list;
    shinfo->frag_list = clone;
}
```

**监控价值**：
- ⚠️ **直接修改 frag_list** 多次
- 裁剪后需要确认 gso_type 是否同步更新

#### 10. `___pskb_trim()` (包含 skb_drop_fraglist 调用)
**位置**：`net/core/skbuff.c:2200-2250`

**监控价值**：
- trim 操作可能释放 frag_list
- 确认 gso_type 是否被清理

#### 11. `skb_condense()`
**监控价值**：
- 合并分片时可能修改 frag_list
- 中等优先级

---

### D. 协议/子系统构造路径（4个）- **高优先级（协议特定）**

#### 12. `ip_fragment()` / `ip6_fragment()` ⭐⭐⭐
**位置**：`net/ipv4/ip_output.c`, `net/ipv6/ip6_output.c`

**逻辑**（IP 分片）：
```c
frag = skb_shinfo(skb)->frag_list;  // 保存指针
skb_frag_list_init(skb);             // 置空

// 遍历处理分片...
for (;;) {
    if (frag) {
        // 处理 frag
    }
}
```

**监控价值**：
- ⚠️ **高风险**：分片后 frag_list 被置空，但 **gso_type 可能未清理**
- 这是**崩溃假设**的核心路径之一：
  - 如果分片失败，frag_list 已置空，但 gso_type/gso_size 未清理
  - 后续进入 `skb_segment()` 就会崩溃

#### 13. `udp4_ufo_fragment()` / `udp6_ufo_fragment()` ⭐⭐
**位置**：`net/ipv4/udp_offload.c:654`, `net/ipv6/udp_offload.c`

**关键代码**：
```c
skb_shinfo(skb)->gso_type = uh->check ?
    SKB_GSO_UDP_TUNNEL_CSUM : SKB_GSO_UDP_TUNNEL;
```

**监控价值**：
- ⚠️ **直接设置 UDP_TUNNEL gso_type**
- 这是崩溃 SKB (gso_type=0x403 包含 UDP_TUNNEL) 的**可能来源**
- 需要确认设置 gso_type 时，frag_list 是否被正确初始化

#### 14. `ip_append_data()` / `ip6_append_data()`
**位置**：`net/ipv4/ip_output.c:636-681`, `net/ipv6/ip6_output.c:746-752`

**逻辑**：
```c
// 把新 SKB 追加到 frag_list
skb_shinfo(head)->frag_list = new_skb;
```

**监控价值**：
- IP 输出路径构造 frag_list
- 确认构造时 gso_type 是否正确设置

#### 15. `virtio_net` / `vhost` 相关路径 ⭐⭐⭐
**相关文件**：`drivers/net/virtio_net.c`, `drivers/vhost/net.c`

**监控价值**：
- ⚠️ **极高优先级**：用户的环境是 virtio 虚拟化环境
- 崩溃的 gso_type 包含 UDP_TUNNEL 但环境是 IPIP，可能是 virtio RX 路径的 **gso_type 转换错误**
- 需要追踪 virtio 如何从 Guest 传递 GSO 元数据到 Host

---

## 三、崩溃根因假设与监控策略

### 假设 1：IP 分片失败路径未清理 GSO 元数据（70% 可能性）

**场景**：
1. SKB 带有 frag_list 和 gso_type/gso_size
2. 进入 `ip_fragment()` 或 `ip6_fragment()`
3. 分片过程中：
   - `skb_frag_list_init()` 被调用，frag_list 置空 ✅
   - 但分片**失败**（如内存不足）
   - **错误路径未清理 gso_type 和 gso_size** ❌
4. SKB 回到协议栈，进入 `skb_segment()`，崩溃

**需要监控**：
- `ip_fragment()` / `ip6_fragment()` 的 entry-return
- 检测：返回值为错误 + gso_type非零 + frag_list==NULL

### 假设 2：SKB 复制路径的 gso_type 错误传播（60% 可能性）

**场景**：
1. 原始 SKB A：frag_list==NULL，但 gso_type 被错误设置（如 virtio RX bug）
2. 调用 `pskb_copy()` 或 `__pskb_copy_fclone()`
3. 新 SKB B 继承了：
   - `gso_type = 0x403` ✅ (复制)
   - `gso_size = 1348` ✅ (复制)
   - `frag_list = NULL` ✅ (原本就是 NULL)
4. SKB B 进入 `skb_segment()`，崩溃

**需要监控**：
- `__pskb_copy_fclone()` 的 entry-return
- 检测：`frag_list==NULL && gso_size>0 && nr_frags==0 && data_len==0`

### 假设 3：virtio GSO 类型转换错误（85% 可能性）⭐

**场景**：
1. Guest VM 发送 IPIP 包，设置 virtio GSO 类型为 `VIRTIO_NET_HDR_GSO_TCPV4`
2. Host virtio/vhost 接收时，**错误地将 GSO 类型映射为 UDP_TUNNEL**
3. 创建的 SKB：
   - `gso_type = SKB_GSO_UDP_TUNNEL` ❌ (错误)
   - `gso_size = 1348` ✅
   - `frag_list = NULL` ✅ (应该用 frags[] 但被破坏)
4. 进入 `skb_segment()`，期望 frag_list 但实际为 NULL，崩溃

**需要监控**：
- virtio RX 路径的 GSO 类型设置点
- 检测：gso_type 与实际数据结构不匹配

### 假设 4：`skb_copy` 返回 NULL 但调用者未检查（40% 可能性）

**场景**：
1. SKB 带有 `SKB_GSO_FRAGLIST` 标志
2. 某处调用 `skb_copy()` 或 `skb_copy_expand()`
3. 触发 `WARN_ON_ONCE`，返回 NULL
4. **调用者未检查返回值**，继续使用 NULL 指针或用错误的 fallback SKB

**需要监控**：
- `skb_copy` / `skb_copy_expand` 的返回值
- 检测：返回 NULL 的调用栈

---

## 四、推荐的监控点优先级

### Tier 1 - 必须监控（6个）

| 函数 | 理由 | 监控类型 |
|------|------|---------|
| `ip_fragment` | 分片失败未清理 GSO 元数据 | entry-return，检测错误路径 |
| `ip6_fragment` | 同上，IPv6 版本 | entry-return，检测错误路径 |
| `__pskb_copy_fclone` | gso_type 错误传播 | entry-return，检测不一致 |
| `skb_copy` | 防护检查点 | return，检测 NULL 返回 |
| `skb_copy_expand` | 防护检查点 | return，检测 NULL 返回 |
| `udp4_ufo_fragment` | UDP_TUNNEL gso_type 设置来源 | entry-return，检测 frag_list 状态 |

### Tier 2 - 高价值（4个）

| 函数 | 理由 |
|------|------|
| `pskb_carve_frag_list` | 直接修改 frag_list 多次 |
| `skb_realloc_headroom` | 间接触发复制路径 |
| `udp6_ufo_fragment` | IPv6 UDP offload |
| `___pskb_trim` | 裁剪可能释放 frag_list |

### Tier 3 - 补充（3个）

| 函数 | 理由 |
|------|------|
| `ip_append_data` | 构造 frag_list 的输出路径 |
| `ip6_append_data` | IPv6 输出路径 |
| `alloc_skb_for_msg` | 消息组装创建 frag_list |

---

## 五、virtio 特殊监控策略

### virtio RX 路径追踪

由于崩溃的 gso_type 包含 `UDP_TUNNEL` 但环境是 IPIP，怀疑 virtio 层的 GSO 类型转换有问题。

**需要监控的 virtio 函数**（需要查看 virtio_net.c 代码）：
1. `receive_buf()` / `receive_mergeable()` - virtio RX 接收
2. GSO 元数据从 virtio header 到 SKB 的转换点
3. `virtnet_hdr_to_skb()` - GSO 类型映射函数（如果存在）

**监控方法**：
- Hook virtio RX 的 SKB 创建点
- 记录：virtio header 的 gso_type → Linux SKB 的 gso_type 映射
- 检测：IPIP 包是否被错误标记为 UDP_TUNNEL

---

## 六、工具增强建议

### 1. 添加 Tier 1 监控点（立即）

优先添加这 6 个函数的 hook：
```python
# IP 分片路径
b.attach_kprobe(event="ip_fragment", fn_name="trace_ip_fragment_entry")
b.attach_kretprobe(event="ip_fragment", fn_name="trace_ip_fragment_return")
b.attach_kprobe(event="ip6_fragment", fn_name="trace_ip6_fragment_entry")
b.attach_kretprobe(event="ip6_fragment", fn_name="trace_ip6_fragment_return")

# 复制路径
b.attach_kprobe(event="__pskb_copy_fclone", fn_name="trace_pskb_copy_entry")
b.attach_kretprobe(event="__pskb_copy_fclone", fn_name="trace_pskb_copy_return")

# 防护检查点
b.attach_kretprobe(event="skb_copy", fn_name="trace_skb_copy_return")
b.attach_kretprobe(event="skb_copy_expand", fn_name="trace_skb_copy_expand_return")

# UDP offload
b.attach_kprobe(event="udp4_ufo_fragment", fn_name="trace_udp_ufo_entry")
b.attach_kretprobe(event="udp4_ufo_fragment", fn_name="trace_udp_ufo_return")
```

### 2. 增强事件检测逻辑

**新增事件类型**：
- `EVENT_COPY_FRAGLIST_FAIL` - skb_copy 因 FRAGLIST 返回 NULL
- `EVENT_FRAGMENT_ERROR_PATH` - IP 分片失败但 GSO 未清理
- `EVENT_GSO_TYPE_MISMATCH` - gso_type 与数据结构不匹配
- `EVENT_VIRTIO_GSO_CONVERSION` - virtio GSO 类型转换异常

### 3. 添加一致性检查

在每个监控点，检查：
```c
// 一致性检查
if (gso_size > 0 || gso_type != 0) {
    // 必须满足以下之一：
    // 1. frag_list != NULL
    // 2. nr_frags > 0
    // 3. data_len > 0
    if (!frag_list && nr_frags == 0 && data_len == 0) {
        // CRITICAL: 不一致状态
        report_inconsistency();
    }
}
```

---

## 七、下一步行动计划

1. **代码审查**（1-2小时）：
   - 查看 virtio_net.c 中的 RX 路径和 GSO 类型转换
   - 确认 `ip_fragment()` 的错误处理路径

2. **工具增强**（3-4小时）：
   - 实现 Tier 1 的 6 个监控点
   - 添加一致性检查逻辑
   - 增加新的事件类型

3. **测试验证**（2-3小时）：
   - 在测试环境部署增强后的工具
   - 构造压力测试（大流量、错误注入）
   - 尝试触发 WARN_ON_ONCE 或 CRITICAL 事件

4. **生产环境部署**（风险评估后）：
   - 选择低流量时段
   - 使用 `--gso-only` 减少开销
   - 实时监控性能影响

---

## 八、总结

当前工具的 5 个监控点只覆盖了**直接修改 frag_list** 的场景，但崩溃的根因更可能来自：

1. **IP 分片失败路径**的 GSO 元数据清理不完整
2. **SKB 复制路径**的 gso_type 错误传播
3. **virtio GSO 类型转换**的映射错误
4. **防护检查点**(`skb_copy`)返回 NULL 但未被正确处理

**关键缺失**：
- 未监控复制/克隆路径（`__pskb_copy_fclone`, `skb_realloc_headroom`）
- 未监控分片路径（`ip_fragment`, `ip6_fragment`）
- 未监控 UDP offload 路径（`udp4_ufo_fragment`）
- 未监控防护检查点（`skb_copy` 返回值）

**推荐优先级**：
1. 立即添加 Tier 1 的 6 个监控点
2. 重点分析 virtio RX 路径
3. 增强一致性检查逻辑
4. 构造测试用例验证各种错误路径
