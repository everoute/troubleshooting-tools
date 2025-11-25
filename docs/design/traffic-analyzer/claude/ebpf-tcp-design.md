# eBPF TCP 性能测量工具初步设计

## 设计目标
- 在低开销的前提下，提供 TCP 关键性能指标的持续 summary+少量 detail 事件。
- 与现有 `tcpsocket_analyzer`/`pcap_analyzer` 协同：同类过滤参数，JSONL 输出，易于远程执行。
- 内核适配友好：针对不同版本的字段差异提供兜底降级。

## 交付物与目录建议
- 目录：`ebpf-tools/performance/system-network/tcp_perf_observer/`
  - `tcp_perf_observer.py`：主 CLI，BCC 入口。
  - `bpf/`：拆分的 BPF 片段（summary/detail）。
  - `README.md`：运行示例/依赖。
- 文档：本设计 + 使用说明写入 `docs/`.

## 体系架构
```
┌────────────┐   ring buffer (detail)   ┌──────────────┐
│  Kernel    │ ───────────────────────▶ │ User-space   │
│  eBPF prog │                         │  dispatcher  │
│            │ ◀─────────────────────── │ (Python)     │
│            │   periodic map dump      └──────────────┘
└────────────┘          │                    │
   ^ tracepoints/kprobes │                    │
   └──── sys events ─────┘        ┌───────────▼───────────┐
                                  │  formatter/exporter   │
                                  ├─────────┬─────────────┤
                                  │ summary │  detail     │
                                  └─────────┴─────────────┘
```

## 探针与指标映射
- 握手时延：`tracepoint tcp:tcp_connect` 记录起点，`tracepoint tcp:tcp_rcv_state_process` 结束；结果写 histogram+可选 detail。
- RTT：`kprobe tcp_rcv_established` 读取 `srtt_us`，累积 per-CPU 直方图；可选按 remote addr 分桶。
- 重传/TLP/RTO：`kprobe tcp_retransmit_skb` 计数；提取 `icsk_retransmits`、`icsk_ca_state`；异常触发 detail。
- Drop 原因：`tracepoint tcp:tcp_drop` 分类计数；当 `reason` 属于 `RESET`, `TIMEWAIT`, `FIN_WAIT` 相关时上送 detail。
- 状态转移：`tracepoint tcp:tcp_set_state` 记录前后状态与持续时间，写入计数表和驻留直方图。
- 拥塞窗口/速率：在 `tcp_ack`（或 `tcp_update_pacing_rate` 若存在）读取 `snd_cwnd`, `snd_ssthresh`, `pacing_rate`; 采用采样（如 1/128 包）。
- ZeroWindow/队列：在 `tcp_data_queue` 检查 `rcv_wnd==0` 或 `sk_rmem_alloc` 逼近 `rcvbuf`; detail 触发并在 summary 计数。
- Backlog/SYN 队列：`tracepoint tcp:tcp_listen_overflow`（若可用）统计溢出计数。

## 数据结构
- per-CPU `BPF_HISTOGRAM`：`rtt`, `connlat`, `retrans`, `pacing_rate`, `snd_cwnd`, `queue_depth`.
- LRU 哈希：按五元组缓存上次状态/时间，用于驻留时间与跳变检测。
- 全局计数器：drop/retrans/backlog 等。
- ring buffer（detail 通道）：承载事件 `struct tcp_event { ts, pid, comm, role, tuple, state, srtt, rtt_sample, cwnd, ssthresh, pacing, bytes_in_flight, retrans_reason, drop_reason, queue, trigger }`.

## 事件限流策略
- 全局令牌桶：默认 200 事件/秒；CLI 可调。
- per-flow 配额：默认每连接 10 个 detail；超限只记计数。
- 轻量采样：对高频路径（如 `tcp_ack`）按概率采样，避免环形缓冲放大。
- 直方图路径始终开启；detail 可以 `--no-detail` 关闭。

## 输出与 CLI
- `--mode summary|detail|both`；`--interval` 控制 summary 拉取频率，`--duration` 控制总时间。
- 过滤与脱敏：`--{l,r}{addr,port}`，`--pid`，`--cgroup`，`--netns`；`--anonymize` 隐去地址。
- 输出：
  - Summary：控制台表格 + `--json` 导出 JSON; 预留 `--prom` 兼容 pushgateway。
  - Detail：JSONL；包含 `drop_count` 字段反映 ring buffer 丢弃。

## 开销控制
- 全部直方图 map 使用 per-CPU，减少锁竞争。
- 关键探针可用 `--lite` 关闭（如 cwnd/pacing/queue）以降低字段访问带来的 BTF 访问开销。
- 初始 bucket 数受限（如 64 桶），可根据内存预算调整；提供 `--max-map-bytes`。

## 兼容性与降级
- 字段检查：在加载时通过 BCC `BPF.get_kprobe_functions`/`BPF.tracepoint_exists` 判断是否存在 `tcp_update_pacing_rate`、`tcp_listen_overflow` 等；缺失时禁用相关指标并提示。
- 内核版本判定：不同版本 `struct tcp_sock` 字段偏移变化，使用 BCC struct helpers 或 `BPF_CORE_READ`（如切到 libbpf 版本）避免硬编码。

## 与现有工具的协同
- 参数对齐：沿用 `tcpsocket_analyzer` 的过滤与输出格式，便于脚本/可视化复用。
- 事件锚点：detail 事件时间戳可用于截断 PCAP 抓包窗口，减少抓包时长。
- 远程执行：保持对 `test/tools/bpf_remote_executor.py` 的兼容（stdout/文件路径可指定）。

## 验证计划（骨架）
- `--help` 运行不加载 BPF，检查参数。
- 冒烟：本地回环 `iperf3`，运行 20s，验证 summary 输出 RTT/吞吐直方图。
- 压测：高并发连接 + 人为注入 `tcpretrans`，观察 detail 限流是否生效。
- 兼容性：在 4.19 与 5.15+ 分别跑 `--lite` 与全量模式，确认降级提示。
