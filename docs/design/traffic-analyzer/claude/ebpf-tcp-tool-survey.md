# eBPF/BCC TCP 相关工具调研

## 目的
评估社区现有的 TCP 性能观测工具可复用程度，识别可直接借鉴的探针与数据结构，为新工具设计提供基线。

## 工具纵览

| 工具 | 来源 | 主要能力 | 机制 | 适用度 | 局限 |
|------|------|----------|------|--------|------|
| `tcptop` | BCC tools | 按远端地址统计 send/recv 吞吐率 | kprobe `tcp_sendmsg` / `tcp_cleanup_rbuf` 计数 | 高：可复用吞吐计算思路 | 无 RTT/重传信息；按秒采样，缺乏细粒度时序 |
| `tcpstates` | BCC tools | 连接状态转移计数、驻留时间 | tracepoint `tcp:tcp_set_state` 记录 | 高：直接获取状态跃迁 | 无 RTT/重传字段；无 per-flow 过滤 citeturn1search1 |
| `tcplife` | BCC tools | 每条连接的建立耗时与传输字节 | kprobe `tcp_set_state`，记录首尾 | 中：可参考连接生命周期计时 | 仅首尾，无法捕捉中途异常 |
| `tcpconnlat` | BCC tools | TCP 三次握手到 ESTABLISHED 的延迟直方图 | tracepoint `tcp:tcp_connect` / `tcp:tcp_rcv_state_process` | 高：可直接复用握手时延直方图 | 仅 client 侧；无后续 RTT/重传 |
| `tcprtt` | BCC tools | RTT 分布直方图，支持 per-addr 统计 | kprobe `tcp_rcv_established` 读取 `srtt_us` | 高：提供低开销 RTT histogram | 仅 histogram，无事件详情，靠 kprobe 采样 citeturn1search2 |
| `tcpretrans` | BCC tools | 重传事件计数及 top 会话 | kprobe `tcp_retransmit_skb` | 高：重传触发点可直接借鉴 | 不含队列/窗口信息，无法判别原因 citeturn1search0turn1search1 |
| `tcpdrop` | BCC tools | 内核主动 drop 的原因统计 | tracepoint `tcp:tcp_drop` | 高：可复用 drop_reason 分类 | 无时序/阈值触发 |
| `bpftrace` 示例 `tcpretrans.bt` | bpftrace | 单事件打印重传 | tracepoint/kprobe | 低：示例性质 | 无聚合与限流 |
| Cilium/Hubble 流日志 | Cilium | eBPF 流量审计，含 TCP flags、重传与 RTT 抽样 | eBPF + ring buffer | 中：思路可借鉴（流事件+指标） | 依赖整套 CNI/agent，不适合裸机单体工具 |

## 关键发现
- BCC 已有的 `tcprtt`, `tcpconnlat`, `tcpretrans`, `tcpstates`, `tcpdrop` 覆盖了**RTT、握手、重传、状态、丢包**等基础指标，且多采用 histogram，符合“低开销 summary”的需求。
- 现有工具普遍缺少**细粒度 detail 事件**与**可配置采样/限流**，无法满足“少量关键事件”上送的要求。
- 队列、pacing_rate、cwnd、ZeroWindow 等高级指标目前社区工具覆盖不足，需要新增 probe 或对内核 struct 做版本分支。
- 现有工具多为单功能脚本，缺少统一 CLI / 输出格式；融合使用需要手工组合。

## 可直接复用的技术点
- 直方图实现：参考 `tcprtt` 的 `BPF_HISTOGRAM` 实现，per-CPU 累积，周期拉取打印。
- 状态跃迁与生命周期：`tcpstates` 的 tracepoint 逻辑可复用并扩展字段。
- 重传/Drop 触发：`tcp_retransmit_skb`、`tcp:tcp_drop` 是低噪声的 detail 触发入口。

## 差距与改进方向
- 需要统一入口，将多指标整合为 summary+detail 的双通道。
- 需要事件限流/采样策略以避免 ring buffer 过载。
- 需要按连接维度的过滤、分桶以及限速，兼容多网卡/容器。
- 输出格式需与现有 `tcpsocket_analyzer` 对齐（JSONL），便于 pipeline 复用。
