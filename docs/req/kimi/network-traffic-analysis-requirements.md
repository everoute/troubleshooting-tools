# Network Traffic Analysis Tools - Requirements Document

## 文档说明

本文档详细定义了两个网络流量分析工具的需求：
- **工具1：PCAP 分析工具** - 用于分析 tcpdump 抓取的 pcap 文件
- **工具2：TCPSocket 分析工具** - 用于分析通过 `tcp_connection_analyzer.py` 采集的 socket 时序数据

数据样例位于 `/Users/echken/workspace/troubleshooting-tools/traffic-analyzer/tcp-perf/` 目录下（如 1111、1112 等日期目录）

---

## 工具 1：PCAP 分析工具

### 1.1 概述

PCAP 分析工具用于分析 tcpdump 抓取的 pcap 文件，提供多层协议统计、TCP/UDP/ICMP 详细分析以及智能化问题识别功能。

**数据位置**：`traffic-analyzer/tcp-perf/{date}/pcap/`（client 或 server 文件）

### 1.2 运行模式

工具提供两种运行模式：

1. **Summary 模式（默认）**
   - 仅输出汇总统计信息
   - 提供整体网络流量概览

2. **Details 模式**（指定过滤条件自动开启）
   - 提供协议级别的详细统计分析
   - 默认输出基础详情
   - 可选 `--analysis` 参数启用智能分析

### 1.3 Summary 模式 - 功能需求

#### 1.3.1 多层协议统计

**L2 层统计**：
- 以太网帧总数
- 按以太网类型统计（IPv4、IPv6、ARP、VLAN 等）
- VLAN 标签统计（如存在）
- 帧大小分布统计（<64, 64, 65-127, 128-255, 256-511, 512-1023, 1024-1518, >1518 字节）

**L3 层统计**：
- IP 数据包总数
- IPv4 vs IPv6 分布
- 按 IP 协议类型的流量统计（TCP、UDP、ICMP、ICMPv6、其他）
- IP 分片统计
- TTL 分布统计（按 IP 对聚合）
- IP 头部选项统计

**L4 层统计**：
- 按协议类型的数据包数
- TCP、UDP、ICMP、其他协议分布
- 按协议类型统计字节数

#### 1.3.2 数据流聚合统计

**TCP 数据流**（按 5 元组聚合）：
- 总 TCP 流数量
- 每个流的：数据包数、字节数、持续时间、平均包大小
- 按端口/服务的 Top N 流（如 HTTP、HTTPS、SSH 等）

**UDP 数据流**（按 5 元组聚合）：
- 总 UDP 流数量
- 每个流的：数据包数、字节数
- 常见 UDP 服务识别（DNS、DHCP、NTP 等）

**ICMP 数据流**（按 Type/Code + 源目标 IP 聚合）：
- ICMP 请求/响应数量
- 按 ICMP 类型的统计（Echo Request/Reply、Destination Unreachable、Time Exceeded 等）
- 每个 ICMP "流" 的：数据包数、RTT（针对 Echo Request/Reply）

**其他协议**：
- ARP 请求/响应统计
- LLDP、STP 等二层控制协议统计

#### 1.3.3 补充统计信息

- 抓包时间范围（首包时间、末包时间）
- 总持续时间
- 平均包速率（pps）
- 平均比特率（bps）
- 数据包大小分布直方图
- 协议分布饼图（文本形式）

### 1.4 Details 模式 - TCP 详细分析

**适用场景**：指定 `--proto tcp` 或过滤条件（如 `--src-ip`、`--dst-ip`、`--port`）

#### 1.4.1 TCP 基础统计（按连接）

**连接识别**：
- 5 元组（源 IP、源端口、目标 IP、目标端口、协议）
- 连接状态（SYN、SYN-ACK、ACK、FIN、RST 等）
- 连接持续时间

**数据包统计**：
- 总数据包数（发送/接收）
- 总字节数（发送/接收）
- 平均包大小
- 重传数据包数
- 乱序数据包数
- 丢包估算

#### 1.4.2 TCP 重传分析

**重传分类统计**：
- 总重传数
- 快速重传（Fast Retransmit）数量
- 超时重传（RTO-based）数量
- SACK 重传数量
- TLP 探测重传数量

**重传模式识别**：
- 重传时间分布
- 重传突发分析
- 重传率计算

#### 1.4.3 TCP 窗口分析

- Zero Window 事件统计
- Window Full 事件统计
- Window Scale 选项分析
- 实际窗口大小变化曲线
- 窗口探测包统计

#### 1.4.4 TCP 选项与特性分析

- MSS 协商值
- SACK 启用与 SACK 块统计
- Timestamps 启用与 RTT 估算
- Window Scale 因子
- Selective Acknowledgment 统计

#### 1.4.5 延迟与丢包分析

- RTT 估算（基于 Timestamp 选项）
- RTT 分布统计（最小、最大、平均）
- 重传率 = 重传包数 / 总发送包数
- 丢包率估算
- DupACK 统计

#### 1.4.6 吞吐量分析

- 每个连接的吞吐量
- 吞吐量随时间变化曲线
- 带宽利用率（需配合物理链路带宽参数）

### 1.5 Details 模式 - UDP 详细分析

**适用场景**：指定 `--proto udp`

#### 1.5.1 UDP 基础统计（按流）

- 5 元组识别
- 数据包数、字节数
- 平均包大小
- 包大小分布

#### 1.5.2 UDP 特性分析

- 包间隔时间分布
- 突发性检测（Burst Detection）
- 丢包估算（基于序列号，如果应用层有序列号）
- 重复包检测

#### 1.5.3 应用层识别

- 常见 UDP 协议识别：DNS、DHCP、NTP、QUIC、VoIP（RTP）等
- 按应用协议的统计
- DNS 延迟分析（Query/Response 时间差）
- RTP 抖动估算（针对 VoIP）

### 1.6 Details 模式 - ICMP 详细分析

**适用场景**：指定 `--proto icmp`

#### 1.6.1 ICMP 基础统计

- 按 Type/Code 的统计
- 源目标 IP 分布
- Echo Request/Reply 配对统计

#### 1.6.2 ICMP 详细分析

- RTT 统计（针对 Echo Request/Reply）
- RTT 分布（最小、最大、平均、标准差）
- 丢包率（未收到 Reply 的请求占比）
- TTL 超时路径分析（Time Exceeded）
- 不可达消息分析（Destination Unreachable）
- 重定向消息统计（Redirect）

### 1.7 Details 模式 - 过滤条件

支持以下过滤选项：

```bash
# 协议过滤
--proto tcp|udp|icmp  # 指定协议类型

# 地址过滤
--src-ip IP_ADDRESS     # 源 IP 地址
--dst-ip IP_ADDRESS     # 目标 IP 地址
--ip IP_ADDRESS         # 任意方向 IP 地址

# 端口过滤
--src-port PORT         # 源端口
--dst-port PORT         # 目标端口
--port PORT             # 任意方向端口

# 组合过滤
# 支持多条件组合（逻辑 AND）
```

### 1.8 Details 模式 - 智能分析 (--analysis)

当指定 `--analysis` 参数时，对选定的连接/流进行智能问题识别：

#### 1.8.1 TCP 智能分析

**重传问题**：
- 高重传率（>1%）告警
- 突发重传识别
- TLP 比例过高告警（>30%）
- 快速重传 vs 超时重传比例分析

**窗口问题**：
- Zero Window 频繁（>5 次）告警
- Window Full 事件分析
- 窗口过小导致的吞吐量瓶颈

**性能问题**：
- RTT 异常高（>100ms）告警
- 吞吐量过低（低于预期带宽的 50%）
- 乱序包过多（>5%）告警
- DupACK 风暴检测

**连接问题**：
- SYN 重传过多（连接建立问题）
- RST 异常（连接异常终止）
- FIN 超时（连接关闭问题）

#### 1.8.2 UDP 智能分析

- 高丢包率告警（>5%）
- 抖动过大（VoIP 质量下降）
- 突发流量导致缓冲区溢出风险

#### 1.8.3 ICMP 智能分析

- 高丢包率告警
- RTT 异常波动
- TTL 超时路径中断告警
- 不可达消息分析（网络配置问题）

#### 1.8.4 通用问题识别

- 小包过多（协议效率低）
- 异常流量模式（DDoS 征兆）
- 协议分布异常

### 1.9 输出格式

**文本输出（默认）**：
- 结构化文本报告
- 表格形式展示统计结果
- 分级标题组织内容

**JSON 输出（--json）**：
- 机器可读格式
- 便于后续自动化处理
- 包含所有原始统计数据

### 1.10 性能要求

- 支持大文件分析（>10GB pcap 文件）
- 内存使用优化（流式处理）
- 多核并行处理支持（可选）
- 进度显示（大文件处理时）

### 1.11 依赖工具

主要依赖：
- tshark（Wireshark 命令行版本）- 首选
- tcpdump（用于某些特定场景）

实现逻辑：
- 使用 tshark 提取原始包数据
- 使用 Python 代码进行协议解析和统计

### 1.12 命令行示例

```bash
# Summary 模式 - 基本统计
python3 pcap_analyzer.py --input pcap/client

# Summary 模式 - 显示 L2/L3/L4 统计
python3 pcap_analyzer.py --input pcap/client --layers all

# Details 模式 - TCP 分析
python3 pcap_analyzer.py --input pcap/client --proto tcp

# Details 模式 - 指定连接的 TCP 深度分析
python3 pcap_analyzer.py --input pcap/client --src-ip 10.0.0.1 --dst-ip 10.0.0.2 --port 5201

# Details + Analysis 模式 - 智能问题识别
python3 pcap_analyzer.py --input pcap/client --proto tcp --analysis

# UDP 分析
python3 pcap_analyzer.py --input pcap/client --proto udp

# ICMP 分析
python3 pcap_analyzer.py --input pcap/client --proto icmp

# JSON 输出（机器可读）
python3 pcap_analyzer.py --input pcap/client --proto tcp --json > analysis_result.json
```

---

## 工具 2：TCPSocket 信息分析工具

### 2.1 概述

TCPSocket 分析工具用于分析通过 `tcp_connection_analyzer.py` 采集的 socket 时序数据，提供 TCP 性能指标的深度分析和瓶颈识别。

**数据位置**：`traffic-analyzer/tcp-perf/{date}/tcpsocket/{client|server}/`

**数据格式**：每个文件包含时间戳 + `ss -tinopm` 输出快照

### 2.2 核心概念

**物理链路带宽**：用户必须指定的参数，表示数据采集环境的物理链路最大带宽（单位：Gbps 或 Mbps）。用于计算：
- 带宽延迟积（BDP）
- 期望窗口大小
- 带宽利用率
- 性能瓶颈判断

**时序数据分析**：工具需要处理多个时间点的 socket 数据，分析指标随时间的变化趋势。

### 2.3 输入参数

```bash
# 必需参数
--input-dir DIR          # tcpsocket 数据目录（client 或 server）
--bandwidth VALUE        # 物理链路带宽（支持单位：Gbps、Mbps，如 "10Gbps" 或 "1000Mbps"）

# 可选过滤
--connection-filter IP:PORT-IP:PORT  # 指定分析特定连接

# 可选参数
--time-range START END   # 分析时间范围（相对时间或绝对时间）
--output-format {text|json}  # 输出格式，默认 text
--output-dir DIR         # 结果输出目录
```

### 2.4 Summary 模式 - 总体性能指标

对目录下所有采集文件进行汇总统计。

#### 2.4.1 连接识别与基本信息

- 分析期间存在的唯一连接数
- 每个连接的 5 元组信息
- 连接持续时间
- 连接状态变化（如适用）

#### 2.4.2 RTT 指标统计（所有采集点）

对每个连接的 RTT 进行全局统计：

- 最小值、最大值、平均值
- 标准差（波动程度量化）
- 50/95/99 分位数（P50、P95、P99）
- 时间序列上的变化趋势（上升/下降/稳定）
- RTT 异常点检测（>平均值 + 3×标准差）

#### 2.4.3 RTTVar（RTT 方差）统计

- 最小值、最大值、平均值
- 50/95/99 分位数
- RTT 稳定性评估

#### 2.4.4 窗口大小统计

**CWND（拥塞窗口）**：
- 最小值、最大值、平均值
- 50/95/99 分位数
- 窗口增长趋势分析

**RWND（接收窗口）**：
- 最小值、最大值、平均值
- 通告窗口稳定性
- 窗口满事件统计

**SWND（发送窗口）**：
- 最小值、最大值、平均值
- 实际可用窗口分析

#### 2.4.5 速率指标统计

**发送速率（send_rate）**：
- 单位：bps
- 最小值、最大值、平均值
- 50/95/99 分位数
- 速率稳定性分析（变异系数 CV）

**Pacing 速率（pacing_rate）**：
- 单位：bps
- 最小值、最大值、平均值
- 50/95/99 分位数
- 速率与 CWND 的关系分析

**传输速率（delivery_rate）**：
- 单位：bps
- 最小值、最大值、平均值
- 50/95/99 分位数
- 反映实际有效吞吐量

#### 2.4.6 重传统计

- 总重传数
- 重传率（重传包 / 总发送包）
- 50/95/99 分位数
- 重传趋势（递增/稳定）

#### 2.4.7 Socket 内存统计

- 最小值、最大值、平均值
- 50/95/99 分位数
- 高水位标记（High Water Mark）

### 2.5 Details 模式 - 深度分析

#### 2.5.1 CWND/RWND/SWND 值分析

**理论计算**：
- 带宽延迟积（BDP）= 带宽（bps）× RTT（秒） / 8
- 期望 CWND（包数）= BDP / MSS
- 期望 RWND（字节）= BDP × 2（保留余量）

**实际 vs 期望对比**：
- 实际 CWND 平均值 vs 期望 CWND
- CWND 不足比例 =（期望 CWND - 实际 CWND）/ 期望 CWND
- 如果 >20%，说明 CWND 成为瓶颈

**各类窗口详细说明**：
- **CWND（拥塞窗口）**：
  - TCP 拥塞控制算法计算值
  - NewReno/Cubic 算法：慢启动、拥塞避免、快速恢复
  - BBR 算法：基于带宽和 RTT 探测
  - ss 输出中的 cwnd 字段直接来自 `tp->snd_cwnd`

- **RWND（接收窗口）**：
  - 接收方通告的窗口大小
  - ss 中的 rcv_space 来自 `tp->rcv_space`
  - rcv_ssthresh 是接收窗口的慢启动阈值
  - 由接收方的 tcp_rmem 系统参数和应用程序读取速度决定

- **SWND（发送窗口）**：
  - 实际可用发送窗口 = min(CWND, RWND)
  - ss 中的 snd_wnd 来自 `tp->snd_wnd`
  - 反映发送方当前可发送的数据量

**窗口瓶颈识别**：
- **CWND Limited**：cwnd_limited_ratio > 50%
  - 表示拥塞控制限制了发送
  - 可能原因：网络丢包、RTT 波动大

- **RWND Limited**：rwnd_limited_ratio > 50%
  - 表示接收窗口限制了吞吐量
  - 可能原因：接收方 tcp_rmem 过小、应用读取慢

- **sndbuf Limited**：sndbuf_limited_ratio > 50%
  - 表示发送缓冲区限制
  - 可能原因：tcp_wmem 过小

#### 2.5.2 各类速率的意义与计算方式

**调研结果**：详见附录 B《Kernel 代码调研报告》

**结论**：
- **delivery_rate**：在 kernel `tcp_rate.c` 中基于 RTT 采样计算，估算网络有效吞吐量能力
- **pacing_rate**：在 kernel `tcp_input.c` 中计算，公式明确：`pacing_rate = pacing_ratio × (mss × cwnd / srtt)`
- **send_rate**：没有找到明确的 kernel 计算代码，可能是用户空间估算值，作为参考指标

**详细说明**：

**传输速率（delivery_rate）**：
- 来源：基于 ACK 测量，在 `tcp_rate.c:tcp_rate_gen()` 中计算
- 计算方式：每个 ACK 采样，计算交付速率
  ```
  delivery_rate = delivered_packets × MSS × 8 / interval_us
  ```
- interval_us = max(send_interval, ack_interval)
- 意义：**估算网络实际能传输的有效吞吐量能力**
- 特点：
  - 使用较长阶段（发送或 ACK）确保准确性
  - 不受应用限制（app_limited）的数据影响
  - 用于 BBR 等拥塞控制算法

**Pacing 速率（pacing_rate）**：
- 来源：存储在 `sk->sk_pacing_rate`（struct sock 字段）
- 计算公式（tcp_input.c）：
  ```
  rate = mss_cache × (USEC_PER_SEC / 100) << 3  // 基础值

  // 慢启动 (cwnd < ssthresh/2):
  pacing_rate = rate × tcp_pacing_ss_ratio / srtt_us
  // pacing_ss_ratio 默认值: 200 (%)

  // 拥塞避免:
  pacing_rate = rate × tcp_pacing_ca_ratio / srtt_us
  // pacing_ca_ratio 默认值: 120 (%)

  // 最终值
  pacing_rate = min(pacing_rate, sk_max_pacing_rate)
  ```
- 更新时机：每个 ACK 到达时
- 意义：控制数据包发送节奏，减少突发，使流量更平滑
- 机制：与 FQ（Fair Queue）调度器配合，限制队列长度

**发送速率（send_rate）**：
- 调研结果：在 kernel 代码中未找到明确的计算函数
- 推测来源：ss 命令在用户空间估算
- 可能计算方式：基于最近时间窗口的实际发送速率
- 建议：作为参考指标，重点分析 pacing_rate 和 delivery_rate

**三类 Rate 的关系与对比分析**：

```
                    pacing_rate              delivery_rate
                        |                         |
                        ↓ (上限)                  ↑ (实际能力)
                  ┌─────┴─────┐            ┌──────┴──────┐
                  ↓           ↓            ↓             ↓
               发送队列 → 网络排队 → 网络传输 → 到达对端 → ACK
                  ↑                                               ↑
                  └─────────────────────────────────────────────┘
                                    |
                                send_rate (估算)
```

- **pacing_rate**：**计划发送速率**，拥塞控制计算，用于控制发送节奏
- **delivery_rate**：**网络交付速率**，测量网络实际能传输的速率，反映网络瓶颈
- **send_rate**：**实际观测发送速率**（估算值）

**对比分析结论**：
- **理想情况**：`delivery_rate ≈ pacing_rate × 0.8-1.0`（网络充分利用）
- **异常情况 1**：`delivery_rate << pacing_rate` → 网络瓶颈（丢包、拥塞、对端接收慢）
- **异常情况 2**：`send_rate << pacing_rate` → 应用限制（app_limited）

**带宽利用率**：
```
带宽利用率 = (平均 delivery_rate / 物理链路带宽) × 100%
```
- < 30%：利用率低，需要优化
- 30%-70%：正常范围
- > 70%：利用率良好

**pacing_rate vs delivery_rate 对比**：
```
比值 = delivery_rate / pacing_rate
- > 0.8：网络状况良好，充分利用
- 0.5-0.8：网络有一定压力但仍可接受
- < 0.5：网络瓶颈严重或存在拥塞
```

**更新频率**：
- **delivery_rate**：每个 ACK 触发（约 RTT 间隔）
- **pacing_rate**：每个 ACK 触发（约 RTT 间隔）
- **send_rate**：ss 命令显示时刻的估算值

#### 2.5.3 重传深度分析

**总重传统计**：
- 采样期间 retrans_total 总增量
- 每个采样点的重传率 = 周期重传数 / 周期发送数

**虚假重传（Spurious Retransmission）**：
- 通过 D-SACK（dsack_dups）识别
- 虚假重传率 = dsack_dups / retrans_total
- >5% 告警，>20% 严重

**DupACK 统计**：
- 从 tcp_connection_analyzer.py 输出中提取
- DupACK 风暴识别（连续 >3 个 DupACK）
- 与快速重传的关联分析

**重传类型分析**（如果数据可用）：
- RTO 超时重传
- 快速重传
- TLP 探测重传
- 重传时间分布

#### 2.5.4 Buffer 状态深度分析

**需要调研**：
- `ss -m` 输出中的 skmem 字段来源（来自 kernel `struct tcp_sock` 中的 `sk->sk_mem_*` 字段）
- 每个字段的精确意义
- 在数据包收发 pipeline 中的位置和关系

**skmem 字段详细说明**：
```
skmem:(r<r>,rb<rb>,t<t>,tb<tb>,f<f>,w<w>,o<o>,bl<bl>,d<d>)
```

- **r**：sk_rmem_alloc - RX 队列中已分配内存
  - 位置：在 skb 从网络层传递到传输层后
  - 意义：socket 接收队列中累积的数据量
  - 与 Recv-Q 的关系：Recv-Q 是未读数据，r 是已接收但未处理的数据

- **rb**：sk_rcvbuf - RX 缓冲区大小上限
  - 来源：由 tcp_rmem[1] 或 setsockopt(SO_RCVBUF) 设置
  - 意义：接收缓冲区的最大容量
  - 溢出判断：如果 r 接近 rb，接收缓冲区压力高

- **t**：sk_wmem_alloc - TX 队列中已分配内存
  - 位置：数据从发送队列进入网络层前
  - 意义：socket 发送队列中待发送的数据量
  - 与 Send-Q 的关系：t 包含已发送未确认 + 未发送数据

- **tb**：sk_sndbuf - TX 缓冲区大小上限
  - 来源：由 tcp_wmem[1] 或 setsockopt(SO_SNDBUF) 设置
  - 意义：发送缓冲区的最大容量
  - 溢出判断：如果 t 接近 tb，发送缓冲区压力高

- **f**：sk_forward_alloc - 预分配内存
  - 位置：为 socket 预留的内存池
  - 意义：用于快速分配 skb，避免每包分配开销

- **w**：sk_wmem_queued - 写队列中排队的内存
  - 位置：TCP 写队列（包括发送中 + 待发送）
  - 与 t 的关系：w <= t，因为 t 包含所有分配

- **o**：sk_omem_alloc - 选项内存分配
  - 用于 TCP 选项存储
  - 通常很小

- **bl**：sk_ack_backlog - ACK 积压队列
  - 位置：等待用户 accept() 的连接
  - 意义：在监听 socket 上，已完成三次握手但未被 accept 的队列

- **d**：sk_drops - 丢包计数
  - 发生位置：从网络层传递到传输层时
  - 原因：接收队列满（r >= rb）、socket buffer 过小
  - 最关键字段：>0 表示有数据丢失！

**Receive Path 数据流**：
```
NIC → 网络层 → 传输层(skb队列) → socket接收队列(r) → Recv-Q → 应用程序
                       ↑                                    ↑
                  压力点1                              压力点2
                     sk_drops                            Recv-Q
```

- **压力点1（sk_drops）**：
  - 条件：`sk_drops > 0`
  - 原因：接收缓冲区 rb 太小、kernel tcp_rmem[2] 太小、应用读取慢导致 r 累积
  - 解决方案：
    ```bash
    sudo sysctl -w net.core.rmem_max=134217728
    sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"
    # 或增大应用读取速度
    ```

- **压力点2（Recv-Q）**：
  - 条件：`Recv-Q > 0` 且持续增大
  - 原因：应用读取速度慢于数据到达速度
  - 查因方法：
    ```bash
    # 查看进程状态
    pidstat -p <pid> -r 1
    # 查看进程阻塞情况
    ps -eo pid,state,command | grep <pid>
    # D 状态：I/O 等待
    # S 状态：睡眠（正常）
    ```

**Send Path 数据流**：
```
应用程序 → Recv-Q → socket发送缓冲区(t/w) → CWND → 网络排队的数据 → 网络发送
                       ↑                       ↑
                  压力点3                 压力点4
                    Send-Q              unacked_cwnd
```

- **压力点3（Send-Q）**：
  - 含义：应用已发送但 TCP 未读取的数据（内核与应用层之间的队列）
  - 位置：用户空间到内核空间的边界
  - 条件：`Send-Q > 0` 且持续增大
  - 原因：应用写入过快，超过 TCP 发送能力

- **压力点4（unacked）**：
  - 含义：已发送但未确认的数据量
  - 约束：`unacked <= CWND`
  - 条件：`unacked ≈ CWND` 持续多个 RTT
  - 原因：网络瓶颈、对端接收慢、RWND 小

**压力点5（CWND < 预期）**：
- 原因：丢包、ECN、网络拥塞
- 分析：见 2.5.1 窗口分析

**Buffer 压力分析可视化**：
- 时序图：r、rb、t、tb 随时间变化
- 堆积图：Send-Q、socket 缓冲区、网络中数据（unacked）的比例
- 热图：按时间段的 buffer 使用率分布

#### 2.5.5 其他补充分析

**RTO（Retransmission Timeout）分析**：
- RTO 值的分布
- RTO 与 RTT 的关系
- RTO 超时次数统计

**SACK（Selective Acknowledgment）分析**：
- SACK 块数量统计
- SACK 恢复事件数

**TCP 状态机分析**：
- 每个连接的 TCP 状态变化
- 状态持续时间统计

**慢启动与拥塞避免分析**：
- 慢启动阶段识别
- 拥塞避免阶段识别
- ssthresh 值变化

### 2.6 输出格式

**文本报告**：
- Summary 章节：整体性能指标
- 连接详情：每个连接的详细分析
- 瓶颈识别：自动识别的性能问题
- 优化建议：针对性的调优建议

**JSON 格式**：
- summary 对象：全局统计
- connections 数组：每个连接的详细数据
- analysis 对象：智能分析结果
- recommendations 数组：优化建议

### 2.7 性能要求

- 支持分析长时间采集的数据（文件数 >1000）
- 内存使用优化（流式读取、增量计算）
- 采样级别可调（--sample-rate）用于超大采集集

### 2.8 依赖

- Python 3.6+（支持 dataclass、typing）
- 无需额外的 eBPF/kernel 工具（纯数据分析）

### 2.9 命令行示例

```bash
# Summary 模式 - 分析所有连接
python3 tcpsocket_analyzer.py --input-dir tcpsocket/client/ --bandwidth 10Gbps

# Summary 模式 - 指定连接
python3 tcpsocket_analyzer.py --input-dir tcpsocket/client/ --bandwidth 10Gbps \
  --connection-filter 10.0.0.1:48270-10.0.0.2:5201

# Summary 模式 - JSON 输出
python3 tcpsocket_analyzer.py --input-dir tcpsocket/client/ --bandwidth 10Gbps \
  --output-format json > analysis.json

# Details 模式 - 完整报告
python3 tcpsocket_analyzer.py --input-dir tcpsocket/client/ --bandwidth 10Gbps \
  --connection-filter 10.0.0.1:48270-10.0.0.2:5201 \
  --output-dir ./tcpsocket_analysis/
```

---

## 附录 A：实施优先级建议

### 第一阶段（基础功能）

**PCAP 分析工具**：
- Summary 模式：多层协议统计
- Details 模式：TCP 基础统计、重传分析、窗口分析
- 文本输出格式

**TCPSocket 分析工具**：
- Summary 模式：RTT、窗口、速率的基本统计
- Details 模式：窗口分析、速率分析
- 文本输出格式

### 第二阶段（增强分析）

- PCAP Details 模式：智能分析 (--analysis)
- TCPSocket Details 模式：Buffer 深度分析
- JSON 输出格式
- 可视化图表支持（可选）

### 第三阶段（高级功能）

- UDP、ICMP 的深度分析
- 性能优化（大文件、大数据集）
- 更多自动化问题识别规则
- 与 ebpf 工具集成

---

## 附录 B：Kernel 代码调研任务

在实现 TCPSocket 分析工具前，需要完成以下调研：

1. **调研 pacing_rate 的精确计算方式**：
   - 文件：`include/net/tcp.h`, `net/ipv4/tcp_rate.c`, `net/ipv4/tcp_cong.c`
   - 函数：`tcp_update_pacing_rate()`, `tcp_set_pacing_rate()`
   - 记录：更新时机、计算公式、与 CWND 的关系

2. **调研 delivery_rate 的精确计算方式**：
   - 文件：`net/ipv4/tcp_rate.c`
   - 函数：`tcp_rate_skb_delivered()`, `tcp_rate_gen()`
   - 记录：采样窗口、时间区间、平滑算法

3. **调研 send_rate 的精确计算方式**：
   - 文件：`net/ipv4/tcp.c`, `net/ipv4/tcp_output.c`
   - 函数：需要搜索 `send_rate` 相关代码
   - 确认：是瞬时测量还是统计值，更新频率

4. **调研 skmem 各字段的详细意义**：
   - 文件：`include/net/sock.h`, `include/linux/skmem.h`
   - 结构体：struct sock, struct tcp_sock
   - 字段：sk_rmem_alloc, sk_wmem_alloc, sk_forward_alloc 等
   - 绘制：数据包收发路径中各字段的访问位置图

5. **调研 Recv-Q 与 r 的关系**：
   - 文件：net/ipv4/tcp_input.c
   - 函数：tcp_rcv_established(), tcp_data_queue()
   - 理解数据从网络层到 socket 接收队列的完整路径

调研结果需要补充到 2.5.2 和 2.5.4 章节，必要时更新分析逻辑。

---

## 附录 C：数据格式示例

### C.1 tcpsocket 数据文件格式

```bash
# 文件名格式：{role}.{port} 或 role.{pid}
# 示例：client.48270

cat tcpsocket/client/client.48270
```

内容：
```
2024-01-01 12:00:00.123
State    Recv-Q Send-Q    Local:Port     Peer:Port
ESTAB    0      0         10.0.0.1:48270  10.0.0.2:5201
	 ts sack cubic wscale:9,9 rtt:78.4/36.2 rto:201 mss:1448 pmtu:1500
	 rcv_space:14480 rcv_ssthresh:65535 snd_wnd:14480
	 send 148512820bps pacing_rate 257809520bps delivery_rate 3200000000bps
	 retrans:0/1195 lost:5 unacked:675 sacked:10 dsack_dups:9
	 segs_out:10000 segs_in:9500 data_segs_out:9000 data_segs_in:8500
	 lastsnd:100 lastrcv:100 lastack:100
	 busy:60000ms rwnd_limited:157971ms(95.6%) sndbuf_limited:1000ms(5.0%)
	 cwnd_limited:500ms(2.5%)
	 skmem:(r0,rb87380,t0,tb87040,f0,w0,o0,bl0,d0)
2024-01-01 12:00:02.456
State    Recv-Q Send-Q    Local:Port     Peer:Port
ESTAB    0      0         10.0.0.1:48270  10.0.0.2:5201
	 ts sack cubic wscale:9,9 rtt:79.1/37.1 rto:201 mss:1448 pmtu:1500
	 ...
```

**需要解析的字段**：
- 时间戳
- Recv-Q/Send-Q
- 连接信息（IP:Port）
- TCP 状态（rtt、rttvar、rto、cwnd、rwnd 等）
- 速率（send_rate、pacing_rate、delivery_rate）
- 重传（retrans、lost、unacked、sacked、dsack_dups）
- 窗口限制（*limited）
- Socket 内存（skmem）

---

## 附录 D：术语表

| 术语 | 全称 | 说明 |
|-----|------|------|
| BDP | Bandwidth-Delay Product | 带宽延迟积 |
| CWND | Congestion Window | 拥塞窗口 |
| RWND | Receive Window | 接收窗口 |
| SWND | Send Window | 发送窗口 |
| MSS | Maximum Segment Size | 最大段大小 |
| RTT | Round-Trip Time | 往返时间 |
| RTO | Retransmission Timeout | 重传超时 |
| SACK | Selective Acknowledgment | 选择性确认 |
| TLP | Tail Loss Probe | 尾部丢失探测 |
| D-SACK | D-SACK | 重复选择性确认 |
| P50 | 50th Percentile | 中位数 |
| P95 | 95th Percentile | 95分位数 |
| P99 | 99th Percentile | 99分位数 |
