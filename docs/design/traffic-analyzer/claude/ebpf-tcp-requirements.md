# eBPF TCP 性能测量需求梳理

## 背景与目标
- 现有 `pcap` 抓包在长时间场景开销大、字段有限；`tcpsocket` 基于离散采样，易错过瞬时细节。
- 目标：在可控开销前提下，提供持续的 TCP 关键性能可观测性，用于故障定位与量化对比，补齐现有工具盲区。

## 覆盖范围
- 主机侧 TCP 栈观测（物理/虚拟机，容器网络均可）。
- 覆盖 IPv4/IPv6，前后台流量，监听/主动连接。
- 单机运行，必要时由远程执行框架触发（参考 `test/tools/bpf_remote_executor.py`）。

## 功能需求
### Summary（周期直方图/计数）
- RTT/RTTVAR 分布：基于 `tcp_rcv_established` 获取 srtt/us，输出 N 秒滚动直方图。
- 连接建立时延：三次握手到 ESTABLISHED 的耗时直方图。
- 拥塞与重传事件：
  - 重传次数、TLP 次数直方图。
  - RTO 触发计数。
- 吞吐/滑动窗口：
  - send/recv bytes 速率分位数（按连接与总体）。
  - cwnd/pacing_rate 分布（采样）。
- 状态跃迁：CLOSE → ESTABLISHED → FIN_WAIT/RESET 的转移计数与平均驻留时间。
- 队列/零窗口：send/recv 队列长度直方图，ZeroWindow 触发计数。
- 错误与丢包：`tcp_drop` tracepoint 计数、原因分布。

### Details（按策略输出的事件样本）
- 触发条件（满足其一）：
  - RTT 超阈值或跳变（如 >p99 或 >固定阈值）。
  - 重传突发 / RTO / TLP。
  - cwnd 快速下降或 pacing_rate=0。
  - ZeroWindow / SYN backlog 溢出 / RST 率异常。
- 事件限流策略：
  - 全局每秒最大事件数可配置（如默认 200/sec）。
  - 按连接的采样比（如 1/N）或前 K flows。
  - 支持“只记录首尾 N 个事件”，避免雪崩。
- 事件字段：时间戳、pid/comm、role（client/server）、五元组、srtt/RTTVAR、cwnd、ssthresh、pacing_rate、rtt_sample、in_flight、bytes_in_flight、retrans_reason、drop_reason、queue_metrics、tcp_state、上游触发阈值。

### CLI 与输出
- CLI 统一与 `tcpsocket_analyzer.py` 风格：`--mode summary|detail|both --interval 1 --duration 60 --iface eth0 ...`
- 输出：
  - Summary：文本表+可选 JSON/Prometheus（便于时序接入）。
  - Detail：JSON Lines，支持写文件或 stdout；可选 ring-buffer drop 计数。
- 过滤：`--lport/--rport/--laddr/--raddr/--pid/--cgroup/--netns`。
- 安全：默认脱敏可选（隐藏 IP/端口）。

### 运行与环境
- 依赖：Python 3 + BCC 或 libbpf bootstrap，内核需开启 BPF+kprobe/tracepoint+`CONFIG_BPF_EVENTS`。
- 权限：root 或具备 `CAP_SYS_ADMIN`。
- 兼容范围：优先支持 4.19+ 内核；检测版本差异并降级（如无 pacing_rate 字段）。
- 资源约束：内存上限可配置（maps 大小、直方图桶数量）；CPU 采样上限。

## 非功能需求
- 开销受控：纯 histogram 采集为主；detail 事件限流/采样；使用 per-CPU map 聚合降低锁竞争。
- 可降级运行：若缺少特定内核字段或 tracepoint，自动关闭对应指标并提示。
- 稳定性：探针加载/卸载容错，异常退出时清理 eBPF 程序和 maps。
- 可测试性：提供 `--help`、`--dry-run`（仅生成 BPF 代码），以及最小 10s 冒烟命令。

## 与现有工具的衔接
- 与 `tcpsocket_analyzer`：复用过滤参数与输出格式；通过 detail 事件填补采样盲区。
- 与 PCAP 工具：提供关键时间片标记（高 RTT、重传突发），便于对齐 PCAP 片段。
- 与远程执行：支持 `test/tools/bpf_remote_executor.py` 直接调用，输出路径可指定以便回收。

## 交付物
- 工具代码：放置于 `ebpf-tools/performance/system-network/` 下的独立子目录。
- 文档：设计、CLI 用法、内核前提写入 `docs/`；在 README 示例中给出最小命令。
