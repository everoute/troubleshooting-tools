# BCC/eBPF 调试框架设计指南

## 概述

本文档总结了一个高效的 BCC/eBPF 程序调试框架，特别适用于具有复杂处理流水线的程序调试。该框架在 VM 网络延迟测量工具开发过程中得到验证，能够快速定位数据包在多阶段处理中的丢失点。

## 核心设计思想

### 1. 统一的调试统计架构

使用 **stage_id + code_point** 的二维编码方式，将调试信息标准化：

```c
// 使用 BPF histogram 进行统一统计
BPF_HISTOGRAM(debug_stage_stats, u32);  // Key: (stage_id << 8) | code_point

// 调试记录函数
static __always_inline void debug_inc(u8 stage_id, u8 code_point) {
    u32 key = ((u32)stage_id << 8) | code_point;
    debug_stage_stats.increment(key);
}
```

### 2. 标准化的代码点定义

定义通用的代码执行关键点：

```c
// 代码点定义 (code_point)
#define CODE_PROBE_ENTRY            1   // Probe 函数入口
#define CODE_INTERFACE_FILTER       2   // 接口过滤
#define CODE_DIRECTION_FILTER       3   // 方向过滤  
#define CODE_HANDLE_CALLED          4   // 处理函数调用
#define CODE_HANDLE_ENTRY           5   // 处理函数入口
#define CODE_PARSE_ENTRY            6   // 解析函数入口
#define CODE_PARSE_SUCCESS          7   // 解析成功
#define CODE_PARSE_IP_FILTER        8   // IP过滤
#define CODE_PARSE_PROTO_FILTER     9   // 协议过滤
#define CODE_PARSE_PORT_FILTER     10   // 端口过滤
#define CODE_FLOW_CREATE           14   // 流创建
#define CODE_FLOW_LOOKUP           15   // 流查找
#define CODE_FLOW_FOUND            16   // 流找到
#define CODE_FLOW_NOT_FOUND        17   // 流未找到
#define CODE_PERF_SUBMIT           19   // 性能事件提交
```

## 使用方法

### 1. 在关键代码点添加调试

```c
int kprobe__netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    debug_inc(TX_STAGE_0, CODE_PROBE_ENTRY);  // 入口计数
    
    if (!is_target_vm_interface(skb)) {
        debug_inc(TX_STAGE_0, CODE_INTERFACE_FILTER);  // 接口过滤计数
        return 0;
    }
    
    debug_inc(TX_STAGE_0, CODE_HANDLE_CALLED);  // 处理调用计数
    handle_stage_event(ctx, skb, TX_STAGE_0);
    return 0;
}

static __always_inline void handle_stage_event(..., u8 stage_id) {
    debug_inc(stage_id, CODE_HANDLE_ENTRY);  // 处理入口计数
    
    if (!parse_packet_key(skb, &key, stage_id)) {
        return;  // 解析失败，在 parse_packet_key 内部已计数
    }
    
    // 流查找
    debug_inc(stage_id, CODE_FLOW_LOOKUP);
    flow_ptr = flow_sessions.lookup(&key);
    if (!flow_ptr) {
        debug_inc(stage_id, CODE_FLOW_NOT_FOUND);
        return;
    }
    debug_inc(stage_id, CODE_FLOW_FOUND);
    
    // 最终提交
    if (complete_condition) {
        debug_inc(stage_id, CODE_PERF_SUBMIT);
        events.perf_submit(ctx, event_data_ptr, sizeof(*event_data_ptr));
    }
}
```

### 2. Python 用户空间解析

```python
def print_debug_statistics(b):
    # 定义阶段名称映射
    stage_names = {
        0: "TX0_netif_receive_skb",
        1: "TX1_netdev_frame_hook", 
        7: "RX0___netif_receive_skb",
        8: "RX1_netdev_frame_hook",
        # ... 更多阶段
    }
    
    # 定义代码点名称映射
    code_names = {
        1: "PROBE_ENTRY",
        2: "INTERFACE_FILTER", 
        4: "HANDLE_CALLED",
        5: "HANDLE_ENTRY",
        16: "FLOW_FOUND",
        17: "FLOW_NOT_FOUND",
        # ... 更多代码点
    }
    
    print("Stage Statistics:")
    stage_stats = b["debug_stage_stats"]
    for k, v in sorted(stage_stats.items(), key=lambda x: x[0].value):
        if v.value > 0:
            stage_id = k.value >> 8
            code_point = k.value & 0xFF
            stage_name = stage_names.get(stage_id, "UNKNOWN_%d" % stage_id)
            code_name = code_names.get(code_point, "CODE_%d" % code_point)
            print("  %s.%s: %d" % (stage_name, code_name, v.value))
```

## 调试流程

### 1. 渐进式调试策略

**第一步：宏观分析**
- 检查各阶段的 `PROBE_ENTRY` 计数，确认探针是否触发
- 检查各阶段的 `HANDLE_CALLED` 计数，确认数据包是否到达处理函数

**第二步：精细定位**
- 对比 `HANDLE_ENTRY` 和 `HANDLE_CALLED` 的差异
- 检查 `FLOW_LOOKUP` vs `FLOW_FOUND` 的比例
- 分析各种过滤器的计数 (IP_FILTER, PROTO_FILTER, etc.)

**第三步：根因分析**
- 根据计数差异定位具体问题点
- 添加更细粒度的调试点
- 使用二分法缩小问题范围

### 2. 典型问题模式识别

**模式1：探针未触发**
```
TX0_netif_receive_skb.PROBE_ENTRY: 0
```
→ 检查探针函数名、参数、内核符号是否正确

**模式2：接口过滤问题**
```
TX0_netif_receive_skb.PROBE_ENTRY: 10000
TX0_netif_receive_skb.INTERFACE_FILTER: 9999
TX0_netif_receive_skb.HANDLE_CALLED: 1
```
→ 检查接口索引、接口名称匹配逻辑

**模式3：数据包解析失败**
```
TX0_netif_receive_skb.HANDLE_CALLED: 100
TX0_netif_receive_skb.HANDLE_ENTRY: 100
TX0_netif_receive_skb.PARSE_ENTRY: 100
TX0_netif_receive_skb.PARSE_SUCCESS: 0
```
→ 检查 IP 头解析、协议解析逻辑

**模式4：流查找失败**
```
TX1_netdev_frame_hook.FLOW_LOOKUP: 50
TX1_netdev_frame_hook.FLOW_FOUND: 0
TX1_netdev_frame_hook.FLOW_NOT_FOUND: 50
```
→ 检查数据包 key 一致性、流创建逻辑

**模式5：阶段间传递断裂**
```
TX0: FLOW_FOUND: 10
TX1: FLOW_FOUND: 3  
TX2: FLOW_FOUND: 0
```
→ 检查不同阶段看到的数据包是否为同一个流

## 高级调试技巧

### 1. 接口调试辅助

```c
BPF_HISTOGRAM(ifindex_seen, u32);  // 记录看到的接口索引

// 在接口检查函数中添加
u32 idx = (u32)ifindex;
ifindex_seen.increment(idx);
```

### 2. 最小化测试程序

创建简化版本验证基础功能：

```c
// 最小测试程序示例
int kprobe__netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    debug_inc(0, CODE_PROBE_ENTRY);
    return 0;
}
```

### 3. 远程测试框架

```python
# 自动化远程测试脚本
def run_remote_test(duration=10):
    # 1. 清理旧进程
    # 2. 启动 BCC 程序
    # 3. 等待指定时间
    # 4. 发送中断信号
    # 5. 收集调试统计
    # 6. 清理资源
```

## 最佳实践

### 1. 调试代码组织

- **分层设计**：探针层 → 处理层 → 解析层 → 流管理层
- **统一接口**：所有调试都使用 `debug_inc(stage_id, code_point)`
- **清晰命名**：stage 和 code_point 都有明确的语义

### 2. 性能考虑

- 调试代码对性能影响极小（只是简单的计数器递增）
- 生产环境可以保留关键调试点
- 使用条件编译在发布版本中移除调试代码

### 3. 扩展性

- 框架支持任意数量的 stage 和 code_point
- 易于添加新的调试点
- 支持不同类型的调试信息（计数器、直方图等）

## 总结

这个调试框架的核心价值在于：

1. **标准化**：统一的调试接口和输出格式
2. **可视化**：清晰的数据流追踪和问题定位
3. **渐进式**：支持从宏观到微观的逐步调试
4. **可扩展**：易于适配不同的 BCC 程序

通过这个框架，复杂的 BCC 程序调试从"黑盒子"变成了"透明管道"，大大提高了开发效率和问题定位能力。