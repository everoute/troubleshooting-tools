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

#### 2.5.2 各类速率的意义与计算方式（已调研）

**调研结果**：详见附录 B《Kernel 代码调研报告》

**结论**：
- **delivery_rate**：在 kernel `tcp_rate.c` 中基于 ACK 采样计算，估算网络有效吞吐量能力
- **pacing_rate**：在 kernel `tcp_input.c` 中计算，公式明确：`pacing_rate = pacing_ratio × (mss × cwnd / srtt)`
- **send_rate**：不是内核计算值，ss命令显示的是**发送缓冲区内存使用量**（来自`inet_diag_meminfo.idiag_wmem`）

**详细说明**：

**传输速率（delivery_rate）**：
- **内核实现**：`net/ipv4/tcp_rate.c:tcp_rate_gen()`
- **采样时机**：每个 ACK 到达时触发（约 RTT 间隔）
- **计算公式**：
  ```
  delivery_rate = delivered_packets × MSS × 8 / interval_us
  interval_us = max(send_interval, ack_interval)
  ```
- **平滑机制**：
  - 只保留非 app_limited 或带宽更高的样本
  - 受 tcp_min_rtt 约束（丢弃小于 min_rtt 的异常样本）
- **意义**：估算网络实际能传输的有效吞吐量能力（BBR等算法使用）
- **特点**：
  - 使用较长阶段（发送或 ACK）确保准确性
  - 不受应用限制（app_limited）的数据影响
  - 每个 ACK 采样一次

**Pacing 速率（pacing_rate）**：
- **内核实现**：`net/ipv4/tcp_input.c:tcp_update_pacing_rate()`
- **更新时机**：每个 ACK 到达时（约 RTT 间隔）
- **计算公式**：
  ```
  // 基础值：mss × cwnd / srtt
  rate = (u64)tp->mss_cache × ((USEC_PER_SEC / 100) << 3);

  // 慢启动阶段（cwnd < ssthresh/2）:
  // pacing_ss_ratio = 200 (200%)
  pacing_rate = rate × 200 / srtt_us

  // 拥塞避免阶段:
  // pacing_ca_ratio = 120 (120%)
  pacing_rate = rate × 120 / srtt_us

  // 最终值（上限限制）
  pacing_rate = min(pacing_rate, sk->sk_max_pacing_rate)
  ```
- **sysctl 参数**：
  ```bash
  net.ipv4.tcp_pacing_ss_ratio = 200  # 慢启动系数
  net.ipv4.tcp_pacing_ca_ratio = 120  # 拥塞避免系数
  ```
- **意义**：控制数据包发送节奏，减少突发，使流量更平滑
- **机制**：与 FQ（Fair Queue）调度器配合，限制队列长度

**发送速率（send_rate）**：
- **调研结果**：在 kernel 代码中未找到明确的计算代码
- **ss命令显示**："send"字段实际是**发送缓冲区内存使用量**（单位：bytes），不是速率
- **数据来源**：`inet_diag_meminfo.idiag_wmem`（通过Netlink INET_DIAG_MEMINFO获取）
- **与tcpi_bytes_acked关系**：无直接关系，tcpi_bytes_acked是累计确认字节数
- **建议**：在TCPSocket分析工具中，send_rate作为**参考值**，重点分析 pacing_rate 和 delivery_rate

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
- **delivery_rate**：**网络交付速率**，测量网络实际能传输的速率，反映网络瓶颈的真实能力
- **send_rate**：SS命令显示的发送缓冲区内存使用量（单位：bytes）

**对比分析结论**：
- **理想情况**：`delivery_rate ≈ pacing_rate × 0.8-1.0`（网络充分利用）
- **异常情况 1**：`delivery_rate << pacing_rate` → 网络瓶颈（丢包、拥塞、对端接收慢）
- **异常情况 2**：`delivery_rate >> pacing_rate` → ACK压缩导致的异常样本（会被tcp_min_rtt过滤）

**带宽利用率分析**：
```
带宽利用率 = (平均 delivery_rate / 物理链路带宽) × 100%

分析标准：
- < 30%：利用率低，可能存在CWND限制、RWND限制或应用受限
- 30%-70%：正常范围
- > 70%：利用率良好
- > 90%：接近带宽上限，可能存在排队和延迟
```

**pacing_rate vs delivery_rate 对比**：
```
比值 = delivery_rate / pacing_rate

分析标准：
- > 0.8：网络状况良好，带宽充分利用
- 0.5-0.8：网络有一定压力但仍可接受
- < 0.5：网络瓶颈严重或存在拥塞、丢包
- > 1.0：异常值（通常由ACK压缩引起），会被tcp_min_rtt过滤
```

**更新频率**：
- **delivery_rate**：每个 ACK 触发（约 RTT 间隔）
- **pacing_rate**：每个 ACK 触发（约 RTT 间隔）
- **send_rate**：即时快照（当前发送缓冲区内存使用）

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

#### 2.5.4 Buffer 状态深度分析（已调研）

**调研结果**：skmem 字段来源于 kernel `struct sock` 结构，详见附录 B《Kernel 代码调研报告》

**内核数据结构说明**：

**skmem 字段完整说明**：
```
skmem:(r<r>,rb<rb>,t<t>,tb<tb>,f<f>,w<w>,o<o>,bl<bl>,d<d>)
```

- **r** (`sk_rmem_alloc`): Receive Queue 中已分配内存
  - **类型**: `atomic_t`
  - **位置**: `include/net/sock.h:394`
  - **含义**: 已通过校验和验证、TCP序列号检查、放入socket接收队列的数据
  - **单位**: bytes
  - **增加位置**: `tcp_data_queue()` → `atomic_add(skb->truesize, &sk->sk_rmem_alloc)`
  - **减少位置**: `tcp_recvmsg()` → `atomic_sub(skb->truesize, &sk->sk_rmem_alloc)`
  - **与 Recv-Q 的关系**: r = 接收队列总量，Recv-Q = 未读部分
    - 数值关系: `r >= Recv-Q`
    - Recv-Q很小但r很大: 应用已读取数据，但内核未释放内存（延迟释放优化）
    - Recv-Q和r都很大: 应用读取慢

- **rb** (`sk_rcvbuf`): RX 缓冲区大小上限
  - **类型**: `int`
  - **来源**:
    1. 系统默认值: `net.core.rmem_default`
    2. TCP 默认值: `tcp_rmem[1]`
    3. 用户设置: `setsockopt(SO_RCVBUF)`
  - **sysctl 参数**: `net.ipv4.tcp_rmem = "4096 87380 6291456"`

- **t** (`sk_wmem_alloc`): TX 队列中已分配内存
  - **类型**: `refcount_t`
  - **位置**: `include/net/sock.h:419`
  - **含义**: 已发送但未确认 + 待发送的数据（已分配内存）
  - **注意事项**: 初始值为1（占位符），实际使用 `sk_wmem_alloc_get() - 1`
  - **增加位置**: `tcp_transmit_skb()` → `skb_set_owner_w(skb, sk)`
  - **减少位置**: `tcp_clean_rtx_queue()` → `tcp_free_skb()`

- **tb** (`sk_sndbuf`): TX 缓冲区大小上限
  - **类型**: `int`
  - **来源**:
    1. 系统默认值: `net.core.wmem_default`
    2. TCP 默认值: `tcp_wmem[1]`
    3. 用户设置: `setsockopt(SO_SNDBUF)`
  - **sysctl 参数**: `net.ipv4.tcp_wmem = "4096 16384 4194304"`

- **f** (`sk_forward_alloc`): 预分配内存
  - **类型**: `int`
  - **位置**: `include/net/sock.h:396`
  - **作用**: 为socket预分配的内存池，提高内存分配效率
  - **机制**: 需要用内存时从forward_alloc扣除，不足时再申请大块内存
  - **典型值**: 几百KB到几MB

- **w** (`sk_wmem_queued`): 写队列中排队的内存
  - **类型**: `int`
  - **位置**: `include/net/sock.h:418`
  - **含义**: TCP写队列中排队待发送的数据（persistent queue size）
  - **与t的关系**: `w <= t`（t包含已发送未确认，w仅包含待发送）
  - **数值关系**: `w = t - unacked_memory`
  - **增加位置**: `tcp_write_xmit()` → `sk->sk_wmem_queued += skb->truesize`
  - **减少位置**: `tcp_transmit_skb()` → `sk->sk_wmem_queued -= skb->truesize`
  - **监控意义**: w值持续高表示应用写入快于网络发送速度
  - **典型值**:
    - 低速网络（1Gbps）: w通常 < 100KB
    - 高速网络（10Gbps+）: w可达几百KB到几MB
    - 应用受限（app_limited）: w接近0

- **o** (`sk_omem_alloc`): Options Memory Allocation（选项内存分配）
  - **类型**: `atomic_t`
  - **用途**: 存储TCP选项相关的内存
  - **典型值**: 很小（几十到几百bytes）

- **bl** (`sk_ack_backlog`): ACK Backlog 队列长度
  - **类型**: `u32`
  - **应用场景**: **仅用于监听socket（Listen Socket）**
  - **含义**: 已完成三次握手但尚未被accept()的连接数量
  - **对于已连接socket**: 该值始终为0

- **d** (`sk_drops`): 丢包计数
  - **类型**: `unsigned long`
  - **发生位置**: 数据包从网络层传递到传输层时
  - **原因**:
    1. 接收队列满（r >= rb）→ **最常见**
    2. 内存分配失败（罕见）
    3. socket locked（罕见）
  - **影响**: **d > 0 表示确定有数据丢失！**
  - **解决方案**: 立即增大接收缓冲区
    ```bash
    sudo sysctl -w net.core.rmem_max=134217728
    sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"
    ```
  - **与其他指标区别**:
    - `sk_drops`: 在socket层丢弃（应用读取慢导致）
    - `TCPBacklogDrop`: 在网络层丢弃（TCP协议栈）

**数据包收发 Pipeline 与 Buffer 关系**：

**接收路径（Receive Path）**：
```
NIC收到数据包
    ↓
硬件中断 → NAPI/softirq处理
    ↓
netif_receive_skb()        # 网络层入口
    ↓
ip_rcv()                  # IP层处理
    ↓
tcp_v4_rcv()              # TCP层入口
    ↓
tcp_v4_do_rcv() → tcp_rcv_established()
    ↓
TCP校验和、序列号、窗口检查
    ↓
tcp_data_queue()          # 数据包排队
    ↓
atomic_add(skb->truesize, &sk->sk_rmem_alloc)  # r增加
    ↓
__skb_queue_tail(&sk->sk_receive_queue, skb)
    ↓
socket层
    ↓
tcp_recvmsg()             # 应用读取
    ↓
__skb_unlink(skb, &sk->sk_receive_queue)
    ↓
atomic_sub(skb->truesize, &sk->sk_rmem_alloc)  # r减少
    ↓
copy_to_user()            # 复制到用户空间
    ↓
应用程序缓冲区
```

**关键压力点分析**：

**压力点1：sk_drops（socket层丢包，最重要！）**
```
位置: tcp_data_queue() 函数
条件: if (atomic_read(&sk->sk_rmem_alloc) >= sk->sk_rcvbuf)
       {
           sk->sk_drops++;  // 丢包计数增加
           goto drop;       // 丢弃数据包
       }
本质: 接收缓冲区不足（r >= rb）
优先级: **最高（确定有数据丢失）**
影响: 数据在socket层被丢弃，应用永远不会收到
解决方案: 立即增大接收缓冲区
解决方案优先级:
  1. 增大tcp_rmem上限（sysctl）
  2. 增大net.core.rmem_max
  3. 优化应用读取速度
检测命令:
  ss -tm | grep skmem  # 查看d值
  # d>0 表示有丢包！
```

**压力点2：TCPBacklogDrop（协议栈丢包）**
```
位置: tcp_v4_rcv() 之前的网络层
原因: 半连接队列（SYN Queue）或全连接队列（Accept Queue）满
查看方法:
  netstat -s | grep TCPBacklogDrop
解决方案:
  sysctl -w net.core.somaxconn=4096  # 增大accept队列
  sysctl -w net.ipv4.tcp_max_syn_backlog=8192  # 增大SYN队列
```

**压力点3：Application Recv-Q堆积**
```
位置: socket接收队列 → 应用层边界
现象: Recv-Q持续增大，r接近rb
原因: 应用读取慢于数据到达速度
排查方法:
  # 1. 查看应用状态
  pidstat -p <pid> -r 1    # 查看内存使用
  pidstat -p <pid> -d 1    # 查看IO等待
  # 2. 查看系统调用延迟
  strace -p <pid> -T -c   # 统计系统调用耗时
  # 3. 查看进程状态
  ps -eo pid,state,wchan:20,command | grep <pid>
  # D状态: I/O等待（可能是存储慢）
  # S状态: 睡眠（可能是锁等待）
```

**压力点4：NIC/Ring Buffer丢包**
```
位置: 网卡层、Ring Buffer
查看方法:
  ethtool -S eth0 | grep -E "drop|miss|error|fault"
  # 常见指标:
  # rx_missed_errors: RX ring满，数据包到达但无可用buffer
  # rx_fifo_errors: RX FIFO溢出
  # rx_crc_errors: CRC校验错误
解决方案:
  1. 增大Ring Buffer:
     ethtool -G eth0 rx 4096 tx 4096
  2. 检查CPU负载（NAPI处理不及时）
     mpstat -P ALL 1
  3. 检查软中断分布:
     cat /proc/softirqs
```

**发送路径（Send Path）与 Buffer 关系**：
```
应用程序 send()/write()
    ↓
socket层（write系统调用）
    ↓
tcp_sendmsg()            # TCP发送入口
    ↓
数据放入sk_send_queue
    ↓
tcp_push_one() → tcp_push_pending_frames()
    ↓
tcp_write_xmit()         # 构建数据包
    ↓
tcp_transmit_skb()       # 发送skb
    ↓
skb_set_owner_w(skb, sk)
    ↓
sk->sk_wmem_alloc += skb->truesize      # t增加
    ↓
sk->sk_wmem_queued += skb->truesize     # w增加（排队）
    ↓
构建网络层头部
    ↓
邻居子系统（ARP）
    ↓
Qdisc（流量控制）sch_fq / sch_htb
    ↓ (pacing_rate在此生效)
NIC发送Ring Buffer
    ↓
网卡硬件队列
    ↓
网络物理链路
    ↓
对端接收
    ↓
对端发送ACK
    ↓
数据返回
    ↓
tcp_ack()                # 处理ACK
    ↓
tcp_clean_rtx_queue()    # 清理重传队列
    ↓
tcp_free_skb()
    ↓
sk->sk_wmem_alloc -= skb->truesize      # t减少（已确认）
sk->sk_wmem_queued -= skb->truesize     # w减少（已发送）
    ↓
重传定时器更新
```

**发送端压力点分析**：

**压力点1：Send-Q堆积**
```
条件: Send-Q > 0 且持续增长
本质: 应用发送快于内核TCP处理速度
排查方法:
  ss -tm  # 查看Send-Q值
  # 正常情况: < 100KB
  # 异常情况: > 1MB 且持续增长

压力分析:
  如果 CWND 正常（> 10）:
    → 应用写入过快（正常现象）
  如果 CWND 很小（< 5）:
    → 网络或拥塞控制限制了发送
    分析: pacing_rate、delivery_rate、丢包率
```

**压力点2：Socket Buffer压力（t）**
```
优先级: **中高**
本质: 发送缓冲区配置不足
条件: t >= tb × 0.8
现象:
  1. 应用write()阻塞或返回EAGAIN/EWOULDBLOCK
  2. 吞吐量下降
  3. sndbuf_limited比例高

解决方案:
  1. 增大发送缓冲区:
     sysctl -w net.ipv4.tcp_wmem="4096 16384 4194304"
     sysctl -w net.core.wmem_max=212992
  2. 或应用层设置SO_SNDBUF

检查方法:
  ss -tm | grep skmem
  # 输出: skmem:(r0,rb87380,t81920,tb87040,f0,w40960,o0,bl0,d0)
  # t=81920, tb=87040 (94%使用率)
```

**压力点3：Write Queue堆积（w）**
```
本质: 应用写入快于网络发送速度
条件: w持续较高（> tb × 0.5）
诊断意义:
  w值高 + delivery_rate低:
    → 网络瓶颈（丢包、RTT高、带宽不足）

  w值高 + delivery_rate高:
    → 网络正常，pacing_rate限制发送
    → 检查pacing_rate vs delivery_rate

  w值高 + pacing_rate >> delivery_rate:
    → 应用写入过快，网络无法及时处理
    → 正常现象，或需要应用层限流

理想状态:
  w < tb × 0.3  # 低水位
  w ≈ unacked  # 排队数据 ≈ 已发送未确认数据
```

**压力点4：窗口限制**

**A. CWND限制（拥塞窗口）**
```
条件: unacked ≈ cwnd 持续多个RTT
原因: 网络拥塞、丢包、ECN标记
特征: delivery_rate可能突然下降

排查方法:
  # 1. 查看cwnd大小
  ss -ti | grep cwnd
  # 2. 查看重传率
  ss -ti | grep retrans
  # 3. 查看各阶段受限时间
  ss -ti | grep limited
  # 输出示例:
  # rwnd_limited:157971ms(95.6%)
  # sndbuf_limited:1000ms(5.0%)
  # cwnd_limited:500ms(2.5%)

如果 cwnd_limited 比例高:
  → 检查丢包率
  → 检查ECN（Explicit Congestion Notification）
  → 检查RTT波动
```

**B. RWND限制（接收窗口）**
```
条件: snd_wnd < cwnd 持续多个RTT
本质: 对端接收缓冲区不足
原因:
  1. 对端应用读取慢
  2. 对端tcp_rmem配置小
  3. 接收方CPU负载高

诊断:
  分析server端和client端的rwnd_limited比例

  client端rwnd_limited高:
    → server端发送快于client接收
    → 优化client端应用或增大client tcp_rmem

  server端rwnd_limited高:
    → client端发送快于server接收
    → 优化server端应用或增大server tcp_rmem

解决:
  无法直接控制，需要优化对端配置或应用
```

**C. sndbuf限制（发送缓冲区）**
```
条件: t >= tb
本质: 发送缓冲区配置不足
现象: send_rate下降，应用可能阻塞

解决方案:
  1. 增大发送缓冲区:
     sysctl -w net.ipv4.tcp_wmem="4096 131072 16777216"
  2. 应用层设置SO_SNDBUF（需root权限或<=net.core.wmem_max）
```

**压力点5：内存分配失败**
```
条件: 分配skb失败（罕见）
查看方法:
  dmesg | grep -i "tcp.*oom\|tcp.*memory"
原因:
  1. 系统内存不足
  2. TCP内存配额耗尽（tcp_mem）

    tcp_mem参数（sysctl）:
    net.ipv4.tcp_mem = "min pressure max"（单位: page）
    - 当tcp内存使用量 > pressure: TCP开始限制内存分配
    - 当tcp内存使用量 > max: TCP拒绝分配新内存

解决:
  1. 释放系统内存
  2. 或增大tcp_mem（不建议，可能导致OOM）
```

**压力点6：Qdisc/NIC队列满**
```
现象: pacing_rate受限，发送延迟增加
检查方法:
  # 1. 查看Qdisc队列长度
  tc -s qdisc show dev eth0
  # 2. 查看网卡队列统计
  ethtool -S eth0 | grep -E "drop|fifo|miss"
  # 3. 查看网卡Ring Buffer
  ethtool -g eth0

可能问题:
  1. tx_queue_len太小
     → 增大: ifconfig eth0 txqueuelen 1000
  2. Ring Buffer太小
     → 增大: ethtool -G eth0 tx 4096
  3. 驱动或硬件限速
```

**Buffer 压力分析可视化（工具应提供）**：

**1. 时序图（时间序列）**
```
X轴: 时间
Y轴: 内存使用量（bytes）

曲线:
  - r（sk_rmem_alloc，接收队列）
  - rb（sk_rcvbuf，接收上限，参考线）
  - t（sk_wmem_alloc，发送队列）
  - tb（sk_sndbuf，发送上限，参考线）
  - w（sk_wmem_queued，写队列）

用途:
  - 识别buffer压力爆发时间点
  - 对比r/rb、t/tb关系
  - 观察w与t的差值变化
```

**2. 阶段堆积图（堆栈图）**
```
X轴: 时间
Y轴: 数据量比例（%）

堆栈:
  [底层] Send-Q（应用→内核）
  [中层] Socket Buffer w（内核排队）
  [上层] Unacked（网络中待确认）

用途:
  - 识别瓶颈位置
  - 如果底层占比大: 应用写入快
  - 如果中层占比大: 网络发送慢
  - 如果上层占比大: 网络延迟高或CWND小
```

**3. Buffer使用率热图**
```
X轴: 时间段（小时）
Y轴: buffer使用率区间
颜色: 采样点数量（颜色越深表示时间越长）

分类:
  - r/rb 接收buffer使用率热图
  - t/tb 发送buffer使用率热图
  - w/tb 写队列使用率热图

用途:
  - 识别长期的buffer压力模式
  - 找出压力高峰的时间段
  - 评估调优效果
```

**4. 窗口限制饼图**
```
数据: rwnd_limited、sndbuf_limited、cwnd_limited的时间占比

示例:
  rwnd_limited: 95.6%
  sndbuf_limited: 5.0%
  cwnd_limited: 2.5%

用途:
  - 快速识别主要限制因素
  - 指导优化方向
```

**Buffer 健康度评估（自动化打分）**：

```python
def buffer_health_score(conn_stats):
    """评估buffer健康度（0-100分）"""
    score = 100

    # 丢包惩罚（最严重）
    if conn_stats.sk_drops > 0:
        score -= 50  # 直接扣50分

    # 接收缓冲区压力
    r_ratio = conn_stats.r / conn_stats.rb
    if r_ratio > 0.9:
        score -= 20
    elif r_ratio > 0.8:
        score -= 10
    elif r_ratio > 0.7:
        score -= 5

    # 发送缓冲区压力
    t_ratio = conn_stats.t / conn_stats.tb
    if t_ratio > 0.9:
        score -= 15
    elif t_ratio > 0.8:
        score -= 7
    elif t_ratio > 0.7:
        score -= 3

    # 写队列堆积
    w_ratio = conn_stats.w / conn_stats.tb
    if w_ratio > 0.8:
        score -= 10
    elif w_ratio > 0.6:
        score -= 5

    return max(0, score)

# 健康度解释
90-100: 优秀（无压力，配置合理）
70-89: 良好（轻度压力，可接受）
50-69: 一般（中度压力，建议关注）
30-49: 较差（重度压力，需要优化）
0-29: 严重（有丢包或严重堆积，立即处理）
```

**Buffer 调优建议（自动化）**：

```python
def buffer_tuning_recommendations(conn):
    """基于统计数据生成调优建议"""
    recs = []

    # 检查丢包
    if conn.sk_drops > 0:
        recs.append({
            'priority': 'HIGH',
            'issue': 'Socket层丢包',
            'evidence': f'sk_drops={conn.sk_drops}',
            'recommendation': '立即增大接收缓冲区',
            'commands': [
                'sysctl -w net.core.rmem_max=134217728',
                'sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"'
            ]
        })

    # 检查接收缓冲区压力
    r_ratio = conn.r / conn.rb
    if r_ratio > 0.9:
        recs.append({
            'priority': 'HIGH',
            'issue': '接收缓冲区压力严重',
            'evidence': f'r/rb={r_ratio:.1%}',
            'recommendation': '增大tcp_rmem上限，并检查应用读取性能',
            'metrics_to_check': ['Recv-Q', '应用CPU使用率', '系统调用延迟']
        })
    elif r_ratio > 0.8:
        recs.append({
            'priority': 'MEDIUM',
            'issue': '接收缓冲区压力较高',
            'evidence': f'r/rb={r_ratio:.1%}',
            'recommendation': '建议增大tcp_rmem或优化应用读取'
        })

    # 检查发送缓冲区压力
    t_ratio = conn.t / conn.tb
    if t_ratio > 0.9:
        recs.append({
            'priority': 'MEDIUM',
            'issue': '发送缓冲区压力高',
            'evidence': f't/tb={t_ratio:.1%}',
            'recommendation': '增大tcp_wmem上限',
            'commands': [
                'sysctl -w net.ipv4.tcp_wmem="4096 16384 4194304"',
                'sysctl -w net.core.wmem_max=212992'
            ]
        })

    # 检查写队列堆积
    w_ratio = conn.w / conn.tb
    if w_ratio > 0.8 and conn.delivery_rate < conn.pacing_rate * 0.5:
        recs.append({
            'priority': 'MEDIUM',
            'issue': '网络瓶颈导致写队列堆积',
            'evidence': f'w/tb={w_ratio:.1%}, delivery_rate={conn.delivery_rate}bps',
            'recommendation': '检查网络质量（丢包、RTT波动）',
            'metrics_to_check': ['重传率', 'RTT', 'delivery_rate/pacing_rate比值']
        })
    elif w_ratio > 0.8:
        recs.append({
            'priority': 'LOW',
            'issue': '写队列堆积',
            'evidence': f'w/tb={w_ratio:.1%}',
            'recommendation': '正常现象（应用写入快于网络发送）'
        })

    return recs
```

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

## 附录 B：Kernel 代码调研任务（✅ 已完成）

**调研状态**: 已完成（2024-11-16）

**调研结果**: 详见《附录-Kernel代码调研报告.md》，主要结论如下：

### 调研成果总结

1. ✅ **pacing_rate 精确计算方式**（附录B 1.2节）
   - 文件：`net/ipv4/tcp_input.c:tcp_update_pacing_rate()`
   - 公式：`pacing_rate = pacing_ratio × (mss × cwnd / srtt)`
   - 慢启动系数：200%（`tcp_pacing_ss_ratio`）
   - 拥塞避免系数：120%（`tcp_pacing_ca_ratio`）

2. ✅ **delivery_rate 精确计算方式**（附录B 1.1节）
   - 文件：`net/ipv4/tcp_rate.c:tcp_rate_gen()`
   - 采样时机：每个ACK到达时
   - 时间间隔：`max(send_interval, ack_interval)`
   - 平滑算法：保留非app_limited或带宽更高的样本
   - 约束：受tcp_min_rtt限制（丢弃异常样本）

3. ✅ **send_rate 确切计算方式**（附录B 1.3节 & 4.4.2节）
   - 调研结论：send_rate **不是内核计算值**
   - ss命令显示："send"字段是**发送缓冲区内存使用量**（来自`inet_diag_meminfo.idiag_wmem`）
   - 与tcpi_bytes_acked：无直接关系
   - 建议：作为参考值，重点分析pacing_rate和delivery_rate

4. ✅ **skmem 各字段详细意义**（附录B 2.2节 & 4.4.1节）
   - r (`sk_rmem_alloc`): 接收队列已分配内存
   - t (`sk_wmem_alloc`): 发送队列已分配内存
   - w (`sk_wmem_queued`): 写队列排队内存（新增详细调研）
   - f (`sk_forward_alloc`): 预分配内存
   - d (`sk_drops`): 丢包计数（最高优先级）
   - bl (`sk_ack_backlog`): ACK积压队列（仅监听socket）

5. ✅ **w字段精确含义**（附录B 4.4.1节）
   - 位置：`include/net/sock.h:418`
   - 定义：`int sk_wmem_queued;  // persistent queue size`
   - 与t关系：`w = t - unacked_memory`
   - 监控意义：反映应用写入 vs 网络发送的速度差

6. ✅ **Recv-Q 与 r 的关系**（附录B 2.3节）
   - 数值关系：`r >= Recv-Q`
   - r：接收队列总量（已分配内存）
   - Recv-Q：未读数据量

7. ✅ **ss命令实现细节**（附录B 4.4.4节）
   - 源码：`iproute2/misc/ss.c`
   - 数据获取：Netlink INET_DIAG_INFO + INET_DIAG_MEMINFO
   - 字段映射：完整梳理（见4.4.4章节）

### 调研成果应用

调研结果已应用到本文档的以下章节：

- **2.5.2**: 补充完整的pacing_rate、delivery_rate计算方式，澄清send_rate真相
- **2.5.4**: 补充skmem所有字段的详细说明，w字段精确含义，压力点分析，可视化需求
- **附录B**: 完整的Kernel代码调研报告，包含源码位置、计算公式、数据路径

### 关键发现

1. **w字段**: 表示`sk_wmem_queued`（写队列排队内存），反映应用写入 vs 网络发送速度差
2. **send_rate**: ss命令显示的是发送缓冲区内存使用量（单位：bytes），不是速率
3. **delivery_rate采样**: 每个ACK触发，受tcp_min_rtt约束，平滑算法保留高质量样本
4. **sk_drops**: 最重要的指标，>0表示确定有数据丢失，需要立即处理

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
