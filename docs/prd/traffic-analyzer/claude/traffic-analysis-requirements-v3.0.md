# 网络流量分析工具需求规格书 (SRS)

**Software Requirements Specification**

**文档版本**: 3.0
**创建日期**: 2025-11-17
**状态**: Draft
**作者**: Claude Code
**项目**: Traffic Analyzer - 通用网络分析工具集

---

## 修订历史

| 版本 | 日期 | 作者 | 变更说明 |
|------|------|------|----------|
| 1.0 | 2025-11-13 | Claude | 初始版本 |
| 2.0 | 2025-11-14 | Claude | 增加kernel研究任务 |
| 3.0 | 2025-11-17 | Claude | 重构为标准SRS格式，分离研究内容 |

---

## 目录

1. [引言](#1-引言)
2. [总体描述](#2-总体描述)
3. [系统特性](#3-系统特性)
   - 3.A [PCAP分析工具特性](#3a-pcap分析工具特性)
   - 3.B [TCP Socket分析工具特性](#3b-tcp-socket分析工具特性)
4. [外部接口需求](#4-外部接口需求)
5. [非功能需求](#5-非功能需求)
6. [其他需求](#6-其他需求)
7. [附录](#附录)

---

## 1. 引言

### 1.1 目的

本文档规定了网络流量分析工具集的软件需求。该工具集包含两个独立但互补的分析工具：
- **PCAP分析工具**：从数据包层面分析网络行为和问题
- **TCP Socket分析工具**：从内核socket状态层面分析TCP性能瓶颈

本文档的目标读者包括：
- 工具开发人员
- 测试工程师
- 项目管理人员
- 最终用户（网络工程师、性能分析师）

### 1.2 文档约定

- **必须（SHALL/MUST）**：强制性需求，必须实现
- **应该（SHOULD）**：推荐性需求，强烈建议实现
- **可以（MAY）**：可选性需求，可根据资源情况决定
- **【扩展点】**：标识可扩展的功能点
- `代码样式`：用于命令、参数、文件名等

### 1.3 项目范围

#### 1.3.1 范围内

- 开发两个独立的命令行分析工具
- 支持离线分析（基于已采集的数据）
- 提供多层次的分析输出（Summary/Details/Analysis）
- 生成文本和JSON格式的报告

#### 1.3.2 范围外

- 实时流量捕获（使用现有工具如tcpdump）
- 图形界面（GUI）
- 实时监控和告警
- 自动化修复建议的执行

### 1.4 参考资料

**标准和RFC**:
- RFC 793: Transmission Control Protocol
- RFC 2018: TCP Selective Acknowledgment Options
- RFC 2883: An Extension to the Selective Acknowledgement (SACK) Option for TCP
- RFC 5681: TCP Congestion Control
- RFC 7323: TCP Extensions for High Performance

**技术文档**:
- Linux Kernel TCP实现研究报告：`docs/research/kernel-tcp-code-research.md`
- Wireshark用户手册
- tshark参考文档

**相关项目**:
- tcp_connection_analyzer.py：现有的TCP Socket数据采集工具
- tcpdump/tshark：PCAP数据采集工具

### 1.5 术语和定义

详见 [附录A：术语表](#附录a术语表)

---

## 2. 总体描述

### 2.1 产品视角

本工具集是一个独立的离线分析系统，用于处理和分析已采集的网络流量数据。它不依赖于特定的网络监控平台，可以独立部署和使用。

```
┌─────────────────────────────────────────────────────────┐
│              网络流量分析工具集                         │
├──────────────────────┬──────────────────────────────────┤
│  PCAP分析工具        │  TCP Socket分析工具              │
│                      │                                  │
│  输入: .pcap文件     │  输入: tcpsocket采样数据         │
│  引擎: tshark        │  引擎: pandas/numpy              │
│  输出: 协议分析报告  │  输出: 性能分析报告              │
└──────────────────────┴──────────────────────────────────┘
         ▲                           ▲
         │                           │
    ┌────┴────┐                 ┌────┴────┐
    │ tcpdump │                 │ tcp_    │
    │         │                 │ conn_   │
    │         │                 │ analyzer│
    └─────────┘                 └─────────┘
```

### 2.2 产品功能概述

#### 2.2.1 PCAP分析工具

**核心功能**：
1. 多层协议统计（L2/L3/L4）
2. 流聚合分析（TCP/UDP/ICMP）
3. TCP深度分析（重传、窗口、SACK等）
4. 智能问题识别和诊断

**运行模式**：
- Summary模式：仅输出汇总统计
- Details模式：过滤条件下的详细分析
- Analysis模式：智能问题识别

#### 2.2.2 TCP Socket分析工具

**核心功能**：
1. 时序性能指标统计
2. 窗口和速率深度分析
3. Buffer压力分析
4. 性能瓶颈识别

**运行模式**：
- Summary模式：性能摘要
- Detailed模式：深度分析

### 2.3 用户类和特性

| 用户类型 | 描述 | 技能水平 | 主要使用场景 |
|---------|------|---------|-------------|
| 网络工程师 | 负责网络故障排查 | 中级-高级 | 定位网络问题、分析连接异常 |
| 性能分析师 | 负责系统性能优化 | 高级 | TCP性能调优、瓶颈分析 |
| 开发人员 | 应用开发者 | 中级 | 应用网络行为分析 |
| 研究人员 | 网络协议研究 | 高级 | 协议行为分析、实验验证 |

### 2.4 运行环境

#### 2.4.1 硬件环境

- **CPU**: x86_64, ARM64
- **内存**: 最小2GB，推荐4GB+（处理大文件时）
- **存储**: 足够空间存储输入数据和分析报告

#### 2.4.2 软件环境

**操作系统**:
- Linux（推荐）: openEuler, CentOS, Ubuntu, Debian
- 其他UNIX-like系统（部分功能可能受限）

**Python环境**:
- Python 3.6+

**依赖软件**:
- tshark（PCAP工具必需）
- tcpdump（可选，用于验证）

**Python依赖库**:
```
pandas>=1.0.0
numpy>=1.18.0
scipy>=1.4.0
```

### 2.5 设计和实现约束

#### 2.5.1 技术约束

- **必须**使用Python 3.6+实现，保证兼容性
- **必须**支持命令行接口，不依赖GUI
- PCAP分析**必须**使用tshark作为底层引擎
- **应该**遵循PEP 8代码风格规范
- **应该**使用类型提示（type hints）

#### 2.5.2 性能约束

- PCAP工具**必须**能处理10GB+的pcap文件
- TCP Socket工具**必须**能处理1000+采样点
- 内存占用**应该**可控，避免一次性加载所有数据
- **应该**提供处理进度提示

#### 2.5.3 安全约束

- 工具**不得**修改输入文件
- **不得**在未经授权的情况下收集或上传分析数据
- **应该**对异常输入进行校验，避免注入攻击

### 2.6 假设和依赖

#### 2.6.1 假设

- 输入数据是由可信来源采集的
- PCAP文件格式符合libpcap标准
- TCP Socket数据由tcp_connection_analyzer.py采集
- 用户具备基本的网络协议知识

#### 2.6.2 依赖

**外部工具依赖**:
- tshark已正确安装且在PATH中
- Python依赖库已安装

**数据依赖**:
- PCAP文件：标准pcap格式，无损坏
- TCP Socket数据：特定格式的文本文件

**文档依赖**:
- Kernel研究报告（docs/research/kernel-tcp-code-research.md）提供字段映射

---

## 3. 系统特性

本节按功能特性组织需求，每个特性包含：
- 描述
- 优先级
- 输入规格
- 处理流程
- 输出规格
- 功能需求

### 3.0 通用约束与补充（PCAP 与 TCP Socket）

- 输入过滤与单连接定位：PCAP 工具必须支持 BPF/五元组过滤参数以聚焦单连接；TCP Socket 工具必须强制双端同一连接，检测到多个连接时需报错并终止。
- 输出格式：所有模式必须支持 JSON 机读输出（text 仅为展示），在需求中明确字段字典；Summary/Detailed/Analysis/Pipeline 需保持报告字段的一致性。
- 时间对齐：Detailed/Pipeline 场景必须基于双端时间对齐后的数据；若对齐样本不足需给出错误或警告。
- 瓶颈一致性：Summary 与 Pipeline 的瓶颈结论应一致；如不一致必须输出差异原因和证据。
- 带宽参数：Pipeline/利用率相关规则必须使用用户提供的带宽参数，禁止使用固定阈值推断网络饱和。
- 证据与验证：问题/瓶颈输出需给出证据（时间区间/报文或采样值）和验证步骤。
- 交叉验证：在附录新增 PCAP 与 tcp_info 指标的重叠/差异清单及交叉验证方法，避免误读。
- 数据质量：输入验证必须覆盖文件存在/可读、格式、单连接约束、字段缺失、时间覆盖不足与对齐失败的处理。

---

## 3.A PCAP分析工具特性

PCAP分析工具从数据包层面分析网络行为，包含以下功能特性：

- **特性3.1**: Summary模式 - 完整汇总统计
- **特性3.2**: Details模式（TCP）- 深度协议分析
- **特性3.3**: Analysis模式 - 智能问题识别
- **特性3.4**: UDP/ICMP分析 - 其他协议支持

### 3.1 【特性3.1】PCAP分析工具 - Summary模式

#### 3.1.1 描述

在不指定任何过滤条件时，工具以Summary模式运行，输出PCAP文件的完整汇总统计信息。

**优先级**: 高（P0）

#### 3.1.2 输入规格

**必需参数**:
```bash
--input <pcap_file>    # PCAP文件路径
```

**可选参数**:
```bash
--output <file>        # 输出文件路径（默认：stdout）
--format <text|json>   # 输出格式（默认：text，必须支持json机读）
--filter <bpf>         # BPF/五元组过滤，仅分析匹配的单连接或流
--verbose              # 详细输出模式
```

**输入验证**:
- 文件**必须**存在且可读
- 文件**必须**是有效的pcap格式
- 文件大小**应该**在合理范围内（警告>10GB）

#### 3.1.3 处理流程

```
1. 验证输入文件
   ├─ 检查文件存在性
   ├─ 检查文件格式（使用tshark验证）
   └─ 检查文件大小

2. 执行多层协议统计
   ├─ L2层统计（以太网类型、帧大小）
   ├─ L3层统计（IP协议、分片、TTL）
   └─ L4层统计（TCP/UDP/ICMP）

3. 执行流聚合统计
   ├─ TCP流（按五元组）
   ├─ UDP流（按五元组）
   ├─ ICMP流（按type/code）
   └─ 其他协议流

4. 执行时间和质量分析
   ├─ 时间维度统计
   ├─ 质量指标统计
   └─ Top Talkers分析

5. （若指定过滤/单连接）执行深度提取
   ├─ 握手协商：MSS/WS/ECN/SACK 启用情况
   ├─ 窗口/可靠性：零窗口、重传/乱序、快速重传 vs 超时
   ├─ 时间序列：基于 TS/握手的 RTT、吞吐/pps、抖动
   └─ 路径 MTU/DF 异常检测
   └─ 若指定过滤，则仅针对过滤后的单连接输出事件线/吞吐/窗口/重传

6. 格式化输出
   └─ 按选定格式输出结果
```

#### 3.1.4 输出规格

**文本格式输出结构**:
```
===== PCAP文件信息 =====
文件路径: /path/to/file.pcap
文件大小: 1.2 GB
数据包总数: 1,234,567
抓包时间范围: 2025-11-12 14:19:47 ~ 14:25:32 (5分45秒)

===== L2层统计 =====
以太网类型:
  IPv4:          1,200,000 packets (97.2%)
  IPv6:             30,000 packets (2.4%)
  ARP:               4,567 packets (0.4%)

帧大小分布:
  <64 bytes:         1,234 packets (0.1%)
  64-127 bytes:    123,456 packets (10.0%)
  128-255 bytes:   234,567 packets (19.0%)
  256-511 bytes:   345,678 packets (28.0%)
  512-1023 bytes:  234,567 packets (19.0%)
  1024-1518 bytes: 295,065 packets (23.9%)

===== L3层统计 =====
IP协议分布:
  TCP:           1,100,000 packets (89.1%)
  UDP:             95,000 packets (7.7%)
  ICMP:             5,000 packets (0.4%)
  其他:            34,567 packets (2.8%)

IP版本:
  IPv4:          1,200,000 packets (97.2%)
  IPv6:             30,000 packets (2.4%)

分片统计:
  非分片包:      1,225,000 packets (99.2%)
  分片包:            9,567 packets (0.8%)
    - 首片:          4,783 packets
    - 后续片:        4,784 packets

===== L4层统计 =====
TCP:
  数据包数: 1,100,000
  字节数: 1,456,789,012 (1.36 GB)
连接数: 1,234
  端口分布 (Top 5):
    - 443:   450,000 packets (40.9%)
    - 80:    234,567 packets (21.3%)
    - 22:    123,456 packets (11.2%)
    ...

UDP:
  数据包数: 95,000
  字节数: 45,678,901 (43.5 MB)
  流数: 456
  端口分布 (Top 5):
    - 53:    45,000 packets (47.4%)
    - 123:   12,345 packets (13.0%)
    ...

ICMP:
  数据包数: 5,000
  字节数: 420,000 (410 KB)
  类型分布:
    - Echo Request (8):  2,500 packets (50.0%)
    - Echo Reply (0):    2,500 packets (50.0%)

===== 流聚合统计 =====
TCP连接:
  总连接数: 1,234
  连接持续时间:
    - 最小: 0.1 秒
    - 最大: 345.6 秒
    - 平均: 12.3 秒
    - 中位数: 5.6 秒

  每连接数据包数:
    - 最小: 3
    - 最大: 12,345
    - 平均: 891.2
    - 中位数: 234

  每连接字节数:
    - 最小: 180 bytes
    - 最大: 12,345,678 bytes
    - 平均: 1,180,682 bytes
    - 中位数: 234,567 bytes

UDP流:
  总流数: 456
  单向流: 123 (27.0%)
  双向流: 333 (73.0%)

===== 时间维度分析 =====
抓包起止时间: 2025-11-12 14:19:47 ~ 14:25:32
总时长: 5分45秒 (345秒)
平均包速率: 3,578 pps
平均带宽: 28.5 Mbps

===== 质量指标 =====
校验和错误: 0 packets
格式错误包: 0 packets
重复包: 12 packets (0.001%)

===== Top Talkers =====
Top 5 发送方IP (按数据包数):
  1. 192.168.1.100: 567,890 packets (46.0%)
  2. 192.168.1.101: 234,567 packets (19.0%)
  3. 192.168.1.102: 123,456 packets (10.0%)
  ...

Top 5 接收方IP (按数据包数):
  1. 10.0.0.1: 456,789 packets (37.0%)
  2. 10.0.0.2: 234,567 packets (19.0%)
  ...

Top 5 端口 (按数据包数):
  1. 443: 450,000 packets (36.4%)
  2. 80: 234,567 packets (19.0%)
  ...
```

**JSON格式输出结构**:
```json
{
  "file_info": {
    "path": "/path/to/file.pcap",
    "size_bytes": 1288490188,
    "total_packets": 1234567,
    "time_range": {
      "start": "2025-11-12T14:19:47.123",
      "end": "2025-11-12T14:25:32.456",
      "duration_seconds": 345.333
    }
  },
  "l2_stats": {
    "ethernet_types": {
      "IPv4": {"packets": 1200000, "percentage": 97.2},
      "IPv6": {"packets": 30000, "percentage": 2.4},
      "ARP": {"packets": 4567, "percentage": 0.4}
    },
    "frame_size_distribution": {
      "<64": 1234,
      "64-127": 123456,
      "128-255": 234567,
      ...
    }
  },
  "l3_stats": {...},
  "l4_stats": {...},
  "flow_stats": {...},
  "time_stats": {...},
  "quality_stats": {...},
  "top_talkers": {...}
}
```

#### 3.1.5 功能需求

**FR-PCAP-SUM-001**: 工具**必须**能够解析标准pcap格式文件
**FR-PCAP-SUM-002**: 工具**必须**输出L2/L3/L4三层协议统计
**FR-PCAP-SUM-003**: 工具**必须**按五元组聚合TCP/UDP流
**FR-PCAP-SUM-004**: 工具**必须**计算时间维度统计（pps, bps）
**FR-PCAP-SUM-005**: 工具**必须**识别Top N发送/接收方IP
**FR-PCAP-SUM-006**: 工具**应该**支持JSON格式输出
**FR-PCAP-SUM-007**: 工具**应该**在处理大文件时显示进度

---

### 3.2 【特性2】PCAP分析工具 - Details模式（TCP）

#### 3.2.1 描述

当指定过滤条件时，工具进入Details模式，对匹配的TCP连接进行深度分析。

**优先级**: 高（P0）

#### 3.2.2 输入规格

**必需参数**:
```bash
--input <pcap_file>      # PCAP文件路径
```

**过滤参数（至少指定一个）**:
```bash
--src-ip <ip>            # 源IP地址
--dst-ip <ip>            # 目标IP地址
--ip <ip>                # 任意方向IP
--src-port <port>        # 源端口
--dst-port <port>        # 目标端口
--port <port>            # 任意方向端口
--proto <tcp|udp|icmp>   # 协议类型
--five-tuple <5tuple>    # 完整五元组（格式: ip1:port1-ip2:port2-proto）
```

**可选参数**:
```bash
--output <file>          # 输出文件路径
--format <text|json>     # 输出格式
--time-start <time>      # 开始时间
--time-end <time>        # 结束时间
```

**参数组合规则**:
- `--proto tcp` **必须**与IP或端口过滤参数组合使用
- `--five-tuple` 不能与其他过滤参数同时使用
- 时间过滤是可选的附加条件

#### 3.2.3 处理流程

```
1. 解析过滤条件
   └─ 构建tshark display filter

2. 提取匹配的连接
   ├─ 识别所有符合条件的TCP流
   └─ 统计每个流的基本信息

3. 对每个流执行详细分析
   ├─ 重传分析
   │   ├─ 快速重传
   │   ├─ 超时重传
   │   └─ 虚假重传（D-SACK）
   ├─ DupACK分析
   ├─ 窗口分析
   │   ├─ Zero Window事件
   │   ├─ Window Full事件
   │   └─ 窗口大小统计
   ├─ SACK/D-SACK分析
   └─ 协议特性协商分析

4. 生成汇总统计

5. 格式化输出
```

#### 3.2.4 输出规格

**文本格式输出结构**:
```
===== 过滤条件 =====
协议: TCP
源IP: 192.168.1.100
目标IP: 10.0.0.1
目标端口: 443

===== 匹配的连接列表 =====
找到 3 个匹配的TCP连接

连接 #1: 192.168.1.100:52341 -> 10.0.0.1:443
  数据包数: 12,345
  字节数: 8,901,234 (8.5 MB)
  持续时间: 125.6 秒
  状态: ESTABLISHED -> FIN_WAIT -> CLOSED

连接 #2: 192.168.1.100:52342 -> 10.0.0.1:443
  ...

===== 连接 #1 详细分析 =====

--- 基本信息 ---
五元组: 192.168.1.100:52341 -> 10.0.0.1:443 (TCP)
开始时间: 2025-11-12 14:19:47.123
结束时间: 2025-11-12 14:21:52.789
持续时间: 125.666 秒

--- 重传分析 ---
总重传数: 234 packets (1.9% of 12,345)
重传字节数: 351,000 bytes (3.9% of 8,901,234)

重传类型分布:
  快速重传 (Fast Retransmit): 178 packets (76.1%)
  超时重传 (RTO): 45 packets (19.2%)
  虚假重传 (Spurious): 11 packets (4.7%)

重传模式:
  重传突发事件: 5 次
    - @14:20:12.345: 45 packets in 2.1 seconds
    - @14:20:45.678: 23 packets in 1.3 seconds
    ...

--- DupACK分析 ---
Duplicate ACK总数: 534 packets
连续DupACK序列: 178 次
  - 触发快速重传: 178 次 (100%)

DupACK风暴检测: 未检测到异常

--- 窗口分析 ---
Zero Window事件:
  发生次数: 12 次
  总持续时间: 3.45 秒 (2.7% of connection time)
  平均持续时间: 0.29 秒
  最长持续时间: 0.85 秒 (@14:20:30.123)

  Zero Window Probe: 36 packets
  恢复时间统计:
    - 最小: 0.05 秒
    - 最大: 0.85 秒
    - 平均: 0.29 秒

Window Full事件: 45 次

窗口大小统计:
  通告窗口 (Receive Window):
    - 最小: 0 bytes (Zero Window)
    - 最大: 524,288 bytes (512 KB)
    - 平均: 262,144 bytes (256 KB)
    - Window Scale: 7 (128x)

  拥塞窗口估算:
    - 推测CWND范围: 10 ~ 500 packets
    - 可能的限制: RWND限制占主导

--- SACK/D-SACK分析 ---
SACK协商: 成功
SACK使用统计:
  SACK块总数: 1,234
  每个ACK的SACK块数:
    - 平均: 1.2 块
    - 最大: 4 块
  SACK恢复的段数: 890 packets

D-SACK:
  D-SACK块数: 23
  识别的虚假重传: 11 packets
  D-SACK类型:
    - 重复数据: 18 blocks
    - 重复ACK: 5 blocks

--- 协议特性协商 ---
MSS: 1460 bytes
Window Scale: 7 (发送方), 7 (接收方)
SACK Permitted: Yes
Timestamps: Yes
ECN: Not negotiated
TCP Fast Open: Not used

--- 连接质量摘要 ---
整体重传率: 1.9% (低)
虚假重传率: 4.7% of retrans (正常)
Zero Window频率: 12 events in 125.6s (中等)
主要问题: 接收方窗口限制导致的性能下降

===== 连接 #2 详细分析 =====
...

===== 汇总统计 =====
（所有匹配连接的聚合统计）

总连接数: 3
总数据包: 45,678
总字节数: 34,567,890 (33.0 MB)

重传统计:
  总重传: 456 packets (1.0%)
  快速重传: 345 packets (75.7%)
  超时重传: 89 packets (19.5%)
  虚假重传: 22 packets (4.8%)

窗口统计:
  Zero Window事件: 45 次
  Window Full事件: 123 次
```

#### 3.2.5 功能需求

**FR-PCAP-DET-001**: 工具**必须**支持按IP地址过滤
**FR-PCAP-DET-002**: 工具**必须**支持按端口过滤
**FR-PCAP-DET-003**: 工具**必须**支持按协议类型过滤
**FR-PCAP-DET-004**: 工具**必须**支持按五元组过滤
**FR-PCAP-DET-005**: 工具**必须**分析TCP重传（快速重传、RTO、虚假重传）
**FR-PCAP-DET-006**: 工具**必须**分析DupACK
**FR-PCAP-DET-007**: 工具**必须**分析Zero Window事件
**FR-PCAP-DET-008**: 工具**必须**分析SACK和D-SACK
**FR-PCAP-DET-009**: 工具**必须**统计协议特性协商结果
**FR-PCAP-DET-010**: 工具**应该**支持时间范围过滤
**FR-PCAP-DET-011**: 工具**应该**检测重传突发事件
**FR-PCAP-DET-012**: 工具**应该**检测DupACK风暴

---

### 3.3 【特性3】PCAP分析工具 - Analysis模式

#### 3.3.1 描述

在Details模式基础上，显式指定`--analysis`参数时，工具进行智能问题识别和诊断。

**优先级**: 中（P1）

#### 3.3.2 输入规格

**必需参数**:
```bash
--input <pcap_file>      # PCAP文件路径
--analysis               # 启用Analysis模式
```

**过滤参数**: 同Details模式

**可选参数**:
```bash
--output <file>          # 输出文件路径
--format <text|json>     # 输出格式
--severity <all|critical|warning|info>  # 问题严重级别过滤
```

#### 3.3.3 处理流程

```
1. 执行Details模式分析
   └─ 获取所有详细统计数据

2. 问题识别
   ├─ 应用问题识别规则
   │   ├─ 重传相关问题
   │   ├─ 窗口相关问题
   │   ├─ 连接质量问题
   │   └─ 协议配置问题
   └─ 评估严重程度

3. 原因分析
   ├─ 关联统计数据
   └─ 推断可能原因

4. 生成建议
   └─ 提供解决方向

5. 格式化输出
```

#### 3.3.4 输出规格

在Details模式输出基础上，增加：

```
===== 问题诊断 =====

【严重】高重传率
连接: 192.168.1.100:52341 -> 10.0.0.1:443
重传率: 5.2% (阈值: >1%)
证据:
  - 总重传: 642 packets
  - 快速重传: 489 packets (76.2%)
  - 超时重传: 143 packets (22.3%)
  - 虚假重传: 10 packets (1.6%)
可能原因:
  - 网络丢包率高
  - 网络延迟大导致超时
建议措施:
  - 检查网络链路质量
  - 检查中间网络设备（交换机、路由器）
  - 考虑调整TCP重传超时参数

【警告】频繁Zero Window
连接: 192.168.1.100:52341 -> 10.0.0.1:443
Zero Window事件: 45 次 (平均每2.8秒一次)
总持续时间: 12.3 秒 (9.8% of connection time)
可能原因:
  - 接收方应用处理慢，未及时读取数据
  - 接收方buffer配置过小
建议措施:
  - 检查接收方应用性能
  - 增大接收buffer大小 (net.ipv4.tcp_rmem)
  - 优化接收方应用的数据处理逻辑

【信息】SACK未启用
连接: 192.168.1.100:52342 -> 10.0.0.1:443
SACK协商: 失败
影响:
  - 可能导致不必要的重传
  - 降低丢包恢复效率
建议措施:
  - 在双方启用SACK支持 (net.ipv4.tcp_sack = 1)

===== 优化建议 =====

1. 网络层面
   - 检查网络链路质量，丢包率较高
   - 排查中间网络设备配置

2. 系统配置层面
   - 增大TCP接收buffer: sysctl net.ipv4.tcp_rmem="4096 87380 16777216"
   - 启用SACK: sysctl net.ipv4.tcp_sack=1
   - 考虑启用Window Scale

3. 应用层面
   - 优化接收方应用的数据处理性能
   - 及时读取socket数据，避免接收buffer满

===== 问题统计 =====
严重问题: 2 个
警告问题: 5 个
信息问题: 3 个
```

#### 3.3.5 功能需求

**FR-PCAP-ANA-001**: 工具**必须**识别高重传率问题（阈值>1%）
**FR-PCAP-ANA-002**: 工具**必须**识别频繁Zero Window问题
**FR-PCAP-ANA-003**: 工具**必须**识别高虚假重传率问题（阈值>10%）
**FR-PCAP-ANA-004**: 工具**必须**识别重传突发问题
**FR-PCAP-ANA-005**: 工具**必须**识别连接建立失败问题
**FR-PCAP-ANA-006**: 工具**必须**识别异常RST终止问题
**FR-PCAP-ANA-007**: 工具**必须**识别关键特性未启用问题（SACK/Timestamps/Window Scale）
**FR-PCAP-ANA-008**: 工具**应该**提供问题的可能原因分析
**FR-PCAP-ANA-009**: 工具**应该**提供解决建议
**FR-PCAP-ANA-010**: 工具**应该**按严重程度对问题分类

---

### 3.4 【特性4】PCAP分析工具 - UDP/ICMP分析

#### 3.4.1 描述

支持对UDP和ICMP协议的基本分析。

**优先级**: 中（P1）

#### 3.4.2 输入规格

**必需参数**:
```bash
--input <pcap_file>      # PCAP文件路径
--proto <udp|icmp>       # 协议类型
```

**过滤参数**: 同TCP过滤参数

#### 3.4.3 UDP分析输出规格

```
===== UDP流详细分析 =====

连接 #1: 192.168.1.100:53421 -> 8.8.8.8:53 (DNS)
  数据包数: 234
  字节数: 45,678
  持续时间: 12.3 秒
  流方向: 双向

--- 应用层协议识别 ---
协议: DNS
类型分布:
  Query: 117 packets (50.0%)
  Response: 117 packets (50.0%)

--- DNS分析 ---
Query/Response配对: 117 pairs (100% 成功)
响应时间统计:
  - 最小: 5 ms
  - 最大: 234 ms
  - 平均: 45 ms
  - P95: 123 ms
  - P99: 189 ms

查询类型分布:
  A: 89 queries (76.1%)
  AAAA: 23 queries (19.7%)
  PTR: 5 queries (4.3%)

--- 质量分析 ---
丢包检测: 无明显丢包（所有query有response）
乱序包: 12 packets (5.1%)
重复包: 0 packets

--- 性能分析 ---
平均包速率: 19 pps
突发流量检测: 3 个突发事件
  - @14:20:12: 45 packets in 0.5s (90 pps)
```

#### 3.4.4 ICMP分析输出规格

```
===== ICMP流详细分析 =====

--- ICMP消息类型分析 ---
类型分布:
  Echo Request (8): 1,000 packets (50.0%)
  Echo Reply (0): 1,000 packets (50.0%)

--- Ping分析 ---
Echo Request/Reply配对: 1,000 pairs (100%)

RTT统计:
  - 最小: 1.2 ms
  - 最大: 45.6 ms
  - 平均: 5.3 ms
  - 中位数: 4.8 ms
  - 抖动 (Jitter): 2.1 ms
  - P95: 12.3 ms
  - P99: 23.4 ms

丢包率: 0% (0/1000)

序列号分析:
  序列号范围: 1 - 1000
  缺失序列号: 无

--- 时间序列分析 ---
Ping间隔:
  - 平均间隔: 1.0 秒
  - 间隔标准差: 0.05 秒
```

#### 3.4.5 功能需求

**FR-PCAP-UDP-001**: 工具**必须**识别DNS流量并进行专门分析
**FR-PCAP-UDP-002**: 工具**必须**计算DNS响应时间
**FR-PCAP-UDP-003**: 工具**应该**识别DHCP流量
**FR-PCAP-UDP-004**: 工具**应该**检测UDP丢包（基于序列号）
**FR-PCAP-UDP-005**: 工具**应该**检测UDP乱序和重复包

**FR-PCAP-ICMP-001**: 工具**必须**分析Echo Request/Reply配对
**FR-PCAP-ICMP-002**: 工具**必须**计算ICMP RTT统计
**FR-PCAP-ICMP-003**: 工具**必须**计算丢包率
**FR-PCAP-ICMP-004**: 工具**应该**检测Traceroute行为
**FR-PCAP-ICMP-005**: 工具**应该**分析ICMP错误消息

---

## 3.B TCP Socket分析工具特性

TCP Socket分析工具从内核socket状态层面分析TCP性能，包含以下功能特性：

- **特性3.5**: Summary模式 - 性能摘要统计
- **特性3.6**: Detailed模式 - 深度性能分析
- **特性3.7**: Pipeline瓶颈分析 - 整体瓶颈识别 🆕

**核心价值**：基于Kernel研究成果，分析TCP数据包在整个软件转发Pipeline中的流动和瓶颈。

### 3.5 【特性3.5】TCP Socket分析工具 - Summary模式

#### 3.5.1 描述

对TCP Socket时序数据进行汇总统计分析，生成性能摘要报告。

**优先级**: 高（P0）

#### 3.5.2 输入规格

**必需参数**:
```bash
--client-dir <directory>     # Client端TCP Socket数据目录
--server-dir <directory>     # Server端TCP Socket数据目录
--bandwidth <bandwidth>      # 物理链路带宽（如：10Gbps, 1000Mbps）
```

**可选参数**:
```bash
--output <file>              # 输出文件路径
--format <text|json>         # 输出格式（默认text，必须支持json机读）
--connection <5tuple>        # 连接过滤（必须唯一；多连接存在时应报错）
--time-start <time>          # 开始时间
--time-end <time>            # 结束时间
```

**输入数据格式**:
```
目录结构:
<client-dir>/                # Client端数据目录
  ├── client.1               # 第1个采样点
  ├── client.2               # 第2个采样点
  └── ...

<server-dir>/                # Server端数据目录
  ├── server.1               # 第1个采样点
  ├── server.2               # 第2个采样点
  └── ...

每个文件格式（text）:
================================================================================
TCP Connection Analysis - 2025-11-12 14:19:47.320
================================================================================
Connection: 100.100.103.205:53910 -> 100.100.103.201:5001
State: ESTAB

Metrics:
--------------------------------------------------------------------------------
  recv_q                   : 0
  send_q                   : 16494848
  rtt                      : 5.349 ms
  rttvar                   : 10.200 ms
  cwnd                     : 5846
  ssthresh                 : 7
  pacing_rate              : 9.5 Gbps
  delivery_rate            : 9.2 Gbps
  ...

说明:
- Client端和Server端数据必须同时提供，用于完整的双向Pipeline分析
- 两端的采样时间应当基本同步（误差<1秒可接受）
- 采样点数量可以不完全一致，工具会进行时间对齐
- 若解析到多个连接，必须报错并中止；仅支持单连接分析
```

#### 3.5.3 处理流程

```
1. 验证输入
   ├─ 检查client-dir和server-dir存在性
   ├─ 检查采样文件格式
   ├─ 解析带宽参数
   └─ 验证带宽格式（支持：Gbps, Mbps, Kbps, bps）

2. 解析Client端采样文件
   ├─ 读取时间戳
   ├─ 解析连接信息（五元组）
   ├─ 解析所有指标
   └─ 构建Client端时序数据结构

3. 解析Server端采样文件
   ├─ 读取时间戳
   ├─ 解析连接信息（五元组）
   ├─ 解析所有指标
   └─ 构建Server端时序数据结构

4. 双端数据对齐
   ├─ 验证连接五元组匹配（考虑方向）
   ├─ 按时间戳对齐Client和Server数据
   ├─ 处理时间偏差（插值或最近邻）
   └─ 合并为统一的双端时序数据

5. 执行统计分析
   ├─ Client端：RTT、CWND、发送速率等统计
   ├─ Server端：RTT、CWND、发送速率等统计
   ├─ 双向对比分析（RTT差异、窗口差异等）
   ├─ 重传统计（双端）
   └─ Buffer/队列统计（双端）

6. 理论计算
   ├─ BDP计算（基于平均RTT）
   ├─ 理论最优CWND计算（双向）
   └─ 带宽利用率计算（双向）

7. 瓶颈识别
   ├─ Client端瓶颈分析
   ├─ Server端瓶颈分析
   └─ 双向综合瓶颈评估（需要与Summary瓶颈保持一致或解释差异）

8. 跨源校验（PCAP/tcp_info）【新增，若提供PCAP可选】
   ├─ RTT/重传/窗口的交叉验证
   ├─ 吞吐/带宽利用率对比
   └─ 输出一致性/差异说明

9. 格式化输出（text + json）
```

#### 3.5.4 输出规格

Summary 模式输出（text + json 必须一致）至少包含：

- 摘要头：连接、对齐样本、带宽、主要瓶颈、吞吐/利用率一句话概览。
- Rate Analysis：pacing_rate、delivery_rate、send_rate（如有）三者统计（min/max/mean/std/CV/P50/P95/P99），带宽利用率；明确“发送侧”/“接收侧”来源。
- Window Analysis：
  - BDP、理论/实际 CWND 与利用率；
  - cwnd/ssthresh 平均比值；新增“按采样点的 cwnd/ssthresh 比值分布”，输出 `<1` 占比（慢启动）、`>=1` 占比（拥塞避免/快速恢复）。
- RTT Analysis：client/server 各自统计与 jitter；输出 client-server RTT 差异及判定（对称/不对称）。
- Buffer Analysis：send_q/recv_q 与 socket_tx/rx_queue/buffer 的统计与压力占比；新增 socket_write_queue、socket_backlog、socket_dropped（或同义字段）压力/事件占比，并给出“压力大/正常”判定。
- Retrans Analysis：client 与 server 各自的重传累计值、周期增量计算出的重传率/重传字节率；需标注来源端；若无法分类 fast/timeout/spurious，需说明计算依据（如全部按增量统计）。
- 对比分析：双端 RTT/CWND/利用率/重传的差异说明。
- 瓶颈与建议：与 Pipeline 结论保持一致；提供证据字段（时间区间/样本值）。

示例结构（简化）：
```
[摘要]
  带宽 25Gbps，主瓶颈: CWND_LIMITED，利用率 53%
[Rate]
  pacing/delivery/send_rate 统计...
[Window]
  BDP=..., CWND利用率=..., cwnd/ssthresh<1 占比=xx%，>=1 占比=yy%
[RTT]
  Client均值/Server均值/差异=...
[Buffer]
  send_q/tx_queue/tx_buffer 压力 ...；write_queue/backlog/dropped 事件占比 ...
[Retrans]
  Client: 总=..., Rate=...%; Server: 总=..., Rate=...%
[瓶颈/建议]
  ...
```

#### 3.5.5 功能需求

**FR-SOCKET-SUM-001**: 工具**必须**解析TCP Socket采样数据文件
**FR-SOCKET-SUM-002**: 工具**必须**对所有数值型指标进行完整统计（min/max/mean/std/CV/P50/P95/P99）
**FR-SOCKET-SUM-003**: 工具**必须**计算BDP和理论最优CWND
**FR-SOCKET-SUM-004**: 工具**必须**计算带宽利用率
**FR-SOCKET-SUM-005**: 工具**必须**分析RTT稳定性
**FR-SOCKET-SUM-006**: 工具**必须**分析窗口利用率
**FR-SOCKET-SUM-007**: 工具**必须**分析速率关系（pacing vs delivery）
**FR-SOCKET-SUM-008**: 工具**必须**分析重传率和虚假重传率
**FR-SOCKET-SUM-009**: 工具**必须**分析Buffer压力
**FR-SOCKET-SUM-010**: 工具**必须**识别性能瓶颈
**FR-SOCKET-SUM-011**: 工具**必须**提供配置建议
**FR-SOCKET-SUM-012**: 工具**必须**支持带宽参数（Gbps/Mbps/Kbps/bps）
**FR-SOCKET-SUM-013**: 工具**应该**支持时间范围过滤
**FR-SOCKET-SUM-014**: 工具**应该**验证采集数据的一致性

---

### 3.6 【特性6】TCP Socket分析工具 - Detailed模式

#### 3.6.1 描述

在Summary模式基础上，提供更详细的深度分析，包括时序图数据、详细的窗口/速率/Buffer分析。

**优先级**: 中（P1）

#### 3.6.2 输入规格

同Summary模式，增加：
```bash
--detailed              # 启用Detailed模式
--plot-data <dir>       # 导出绘图数据到指定目录（可选）
```

#### 3.6.3 输出规格

在Summary模式输出基础上，增加：

```
===== 详细分析 =====

[窗口深度分析]

理论计算:
  BDP = 带宽 × RTT = 10 Gbps × 5.67 ms / 8 = 7.09 MB
  理论最优CWND = BDP / MSS = 7.09 MB / 1460 bytes = 5085 packets
  建议Buffer大小 >= 2 × BDP = 14.18 MB

实际值对比:
  实际平均CWND: 4523 packets (6.60 MB)
  理论最优CWND: 5085 packets (7.42 MB)
  差距: -562 packets (-11.1%)

结论: CWND略低于理论最优，有提升空间

窗口限制时间占比分析:
  CWND Limited: 23.5% (81/343 samples)
    - 定义: inflight_data >= CWND × MSS × 95%
    - 说明: 约四分之一时间受CWND限制

  RWND Limited: 0% (0/343 samples)
    - 定义: inflight_data >= snd_wnd × 95%
    - 说明: 未检测到RWND限制

  SNDBUF Limited: 67.3% (231/343 samples)
    - 定义: socket_tx_queue >= socket_tx_buffer × 95%
    - 说明: 大部分时间受发送buffer限制

主导限制因素: 发送Buffer (SNDBUF)

CWND变化模式分析:
  慢启动阶段: 未检测到（连接已建立）
  拥塞避免阶段: 占主导（ssthresh=7, CWND均值4523）
  窗口恢复事件: 检测到 3 次
    - @14:20:12: CWND: 5846 -> 2923 (下降50%)
    - @14:21:45: CWND: 5234 -> 2617 (下降50%)
    - @14:23:18: CWND: 4982 -> 2491 (下降50%)
  分析: 可能的丢包触发快速恢复

[速率深度分析]

Pacing Rate详细统计:
  时间序列分析:
    - 上升趋势时段: 14:19:47 ~ 14:20:30 (平稳增长)
    - 波动时段: 14:20:30 ~ 14:23:00 (较大波动)
    - 稳定时段: 14:23:00 ~ 14:25:32 (相对稳定)

  与CWND的关系:
    - 相关系数: 0.89 (强相关)
    - 说明: Pacing Rate主要由CWND决定

  与RTT的关系:
    - 相关系数: -0.62 (中等负相关)
    - 说明: RTT上升时Pacing Rate下降

Delivery Rate详细统计:
  时间序列分析:
    - 平均速率: 6.98 Gbps
    - 峰值速率: 9.54 Gbps (@14:20:25)
    - 谷值速率: 3.21 Gbps (@14:21:50)
    - 波动性: 中等 (CV=21.8%)

  与Pacing Rate的差距:
    - 平均差距: 0.25 Gbps (3.6%)
    - 最大差距: 1.23 Gbps (@14:21:50)
    - 差距分析: 正常范围，网络瓶颈不明显

  App-limited时间占比:
    - 检测方法: 根据is_app_limited标记
    - 占比: 5.2% (18/343 samples)
    - 说明: 偶尔受应用发送限制

Rate限制识别:
  Pacing限制: 12.5% (43/343 samples)
    - 定义: |Delivery Rate - Pacing Rate| < 5%
    - 说明: 部分时间Pacing是主要限制

  网络限制: 5.8% (20/343 samples)
    - 定义: Delivery Rate << Pacing Rate (差距>20%)
    - 说明: 偶尔出现网络瓶颈

  应用限制: 5.2% (18/343 samples)
    - 基于app_limited标记
    - 说明: 应用偶尔发送不足

带宽利用率时序:
  高利用率时段 (>80%): 45.2% (155/343 samples)
  中利用率时段 (50-80%): 38.5% (132/343 samples)
  低利用率时段 (<50%): 16.3% (56/343 samples)

[重传深度分析]

逐周期增量分析:
  采样点  时间             重传增量  累计重传  瞬时重传率
  ---------------------------------------------------------------
  1       14:19:47.320     0         0         0%
  2       14:19:49.340     0         0         0%
  ...
  45      14:20:35.120     15        87        2.1%  <- 重传突发
  46      14:20:37.140     12        99        1.8%
  47      14:20:39.160     3         102       0.4%
  ...
  172     14:25:32.100     1         234       0.1%

重传突发检测:
  突发事件 #1: @14:20:35 ~ 14:20:41 (6秒)
    - 重传包数: 45 packets
    - 平均重传率: 6.2%
    - 与RTT变化关联: RTT上升 4.5ms -> 8.9ms
    - 与CWND变化关联: CWND下降 5846 -> 2923
    - 分析: 可能的网络拥塞导致丢包

  突发事件 #2: @14:21:45 ~ 14:21:53 (8秒)
    - 重传包数: 52 packets
    - 平均重传率: 5.8%

虚假重传时间分布:
  (基于D-SACK检测)
  @14:20:12: 3 packets
  @14:21:18: 5 packets
  @14:23:45: 4 packets

虚假重传与RTT关系:
  - 虚假重传时RTT均值: 8.9 ms
  - 全局RTT均值: 5.67 ms
  - 分析: 虚假重传多发生在RTT较高时

[Buffer状态深度分析]

发送侧详细分析:

send_q (等待发送数据):
  时序统计:
    - 持续高位时间: 87.2% (299/343 samples > 10MB)
    - 最高峰: 16.8 MB (@14:20:15)
    - 最低谷: 8.9 MB (@14:22:30)

  与发送速率关系:
    - 当send_q > 15MB时，delivery_rate平均: 8.2 Gbps
    - 当send_q < 12MB时，delivery_rate平均: 5.1 Gbps
    - 分析: send_q高时发送更充分

socket_tx_queue (发送侧总占用):
  时序统计:
    - 平均: 18.9 MB
    - P95: 20.1 MB
    - 上限: 21 MB (socket_tx_buffer)

  压力分析:
    - 高压力时间 (>90%): 67.3% (231/343 samples)
    - 中压力时间 (70-90%): 23.5% (81/343 samples)
    - 低压力时间 (<70%): 9.2% (31/343 samples)

  结论: 发送buffer长期处于高压力状态

接收侧详细分析:

recv_q (等待应用读取):
  统计: 全部采样点均为 0
  分析: 应用及时读取数据，无积压

socket_rx_queue (接收侧总占用):
  平均: 2.1 MB
  上限: 8 MB (socket_rx_buffer)
  利用率: 26.3%
  分析: 接收侧压力低，无瓶颈

socket_dropped (丢包计数):
  全部采样点: 0
  结论: 未发生buffer丢包

Buffer配置建议:
  基于实际压力和BDP:
    - 当前发送buffer: ~21 MB
    - 当前接收buffer: 8 MB
    - BDP: 7.09 MB

  建议配置:
    发送buffer: 32 MB (当前的1.5倍，约 4.5 × BDP)
      sysctl -w net.ipv4.tcp_wmem="4096 16384 33554432"

    接收buffer: 保持 (16 MB，约 2 × BDP，已足够)
      sysctl -w net.ipv4.tcp_rmem="4096 131072 16777216"

[拥塞控制状态分析]

ssthresh变化:
  全部采样点: ssthresh = 7 packets (constant)
  分析: 连接建立后快速进入拥塞避免阶段，未再触发慢启动

CWND阶段识别:
  慢启动阶段: 未检测到
  拥塞避免阶段: 100% (343/343 samples)
  快速恢复阶段: 检测到 3 次窗口减半事件

拥塞控制算法行为:
  (推测为Cubic算法)
  - CWND增长: 缓慢线性增长 (拥塞避免特征)
  - CWND减少: 丢包时减半 (Cubic快速恢复)

[应用行为分析]

应用发送模式:
  App-limited时间: 5.2%
  分析: 应用大部分时间持续发送

应用读取模式:
  recv_q持续为0
  分析: 应用及时读取数据

[时序数据导出]
(如果指定了 --plot-data 参数)

已导出以下CSV文件到 /path/to/plot-data/:
  - rtt_timeseries.csv
  - cwnd_timeseries.csv
  - rate_timeseries.csv
  - buffer_timeseries.csv
  - retrans_timeseries.csv

格式示例 (rtt_timeseries.csv):
timestamp,rtt_ms,rttvar_ms,minrtt_ms
2025-11-12 14:19:47.320,5.349,10.200,4.230
2025-11-12 14:19:49.340,5.412,9.876,4.230
...
```

#### 3.6.4 功能需求

**FR-SOCKET-DET-001**: 工具**必须**提供窗口限制时间占比分析
**FR-SOCKET-DET-002**: 工具**必须**分析CWND变化模式
**FR-SOCKET-DET-003**: 工具**必须**提供速率时序分析
**FR-SOCKET-DET-004**: 工具**必须**识别Rate限制类型
**FR-SOCKET-DET-005**: 工具**必须**分析重传突发事件
**FR-SOCKET-DET-006**: 工具**必须**分析虚假重传分布
**FR-SOCKET-DET-007**: 工具**必须**提供Buffer压力时序分析
**FR-SOCKET-DET-008**: 工具**必须**基于BDP和实际压力给出Buffer配置建议
**FR-SOCKET-DET-009**: 工具**应该**导出时序数据用于绘图
**FR-SOCKET-DET-010**: 工具**应该**分析指标之间的相关性

---

### 3.7 【特性3.7】TCP Socket分析工具 - Pipeline瓶颈分析 🆕

#### 3.7.1 描述

基于Linux Kernel TCP代码研究成果，分析数据包在整个软件转发Pipeline中的流动情况，识别各环节的瓶颈点，给出整体的瓶颈诊断视图。

**核心价值**：
- 提供端到端的Pipeline视图，而非孤立的指标分析
- 明确识别瓶颈环节（应用层、Socket层、TCP层、网络层）
- 给出整体性能优化方向

**优先级**: 高（P0）

**设计依据**: `docs/research/kernel-tcp-code-research.md` 第5节 TCP数据包Pipeline

#### 3.7.2 Pipeline架构

```
┌─────────────────────────────────────────────────────────────────┐
│                    TCP 数据包转发 Pipeline                       │
├──────────┬──────────────┬──────────────┬──────────────┬─────────┤
│ 应用层   │  Socket层    │   TCP层      │  网络层      │ 设备层  │
└──────────┴──────────────┴──────────────┴──────────────┴─────────┘

【发送路径】
应用 write()
    ↓ [瓶颈点1: 应用发送速率]
Socket层 (sk_wmem_queued)
    ↓ [瓶颈点2: Socket发送buffer]
    send_q 队列
    ↓ [瓶颈点3: TCP发送窗口]
TCP层 (tp->snd_cwnd)
    ↓ [瓶颈点4: 拥塞窗口]
    packets_out (在途数据)
    ↓ [瓶颈点5: 对端接收窗口]
网络层/设备层
    ↓ [瓶颈点6: 网络带宽]

【接收路径】
网络层/设备层
    ↓ [瓶颈点7: 网络接收能力]
TCP层 (tcp_data_queue)
    ↓ [瓶颈点8: TCP接收buffer]
Socket层 (sk_receive_queue)
    ↓ [瓶颈点9: 接收buffer]
    recv_q 队列
    ↓ [瓶颈点10: 应用读取速率]
应用 read()
```

#### 3.7.3 瓶颈点识别规则

**发送路径瓶颈点**:

| 瓶颈点 | 检测指标 | 判断条件 | 严重级别 |
|--------|----------|----------|----------|
| **应用发送速率** | app_limited标记 | app_limited > 5%时间 | INFO |
| **Socket发送buffer** | send_q, socket_tx_queue | socket_tx_queue > 90% socket_tx_buffer | CRITICAL |
| **TCP发送窗口** | socket_write_queue | write_queue持续高位 | WARNING |
| **拥塞窗口CWND** | packets_out, cwnd | packets_out >= cwnd * 95% | WARNING |
| **对端接收窗口RWND** | inflight_data, snd_wnd | inflight >= snd_wnd * 95% | WARNING |
| **网络带宽** | delivery_rate, 物理带宽 | delivery_rate < pacing_rate * 80% | WARNING |

**接收路径瓶颈点**:

| 瓶颈点 | 检测指标 | 判断条件 | 严重级别 |
|--------|----------|----------|----------|
| **网络接收能力** | 丢包率、错误率 | socket_dropped > 0 | CRITICAL |
| **TCP接收buffer** | socket_rx_queue | socket_rx_queue > 90% socket_rx_buffer | WARNING |
| **接收buffer** | recv_q | recv_q持续积压 | WARNING |
| **应用读取速率** | recv_q增长速率 | recv_q增长 > 网络接收速率 | WARNING |

#### 3.7.4 整体瓶颈判断逻辑

```python
# 伪代码
def analyze_pipeline_bottleneck(data):
    bottlenecks = []

    # 发送路径分析
    if check_socket_tx_buffer_pressure(data):
        bottlenecks.append({
            'layer': 'Socket层',
            'component': '发送Buffer',
            'severity': 'CRITICAL',
            'evidence': {
                'socket_tx_queue_avg': data['socket_tx_queue'].mean(),
                'socket_tx_buffer': data['socket_tx_buffer'][0],
                'utilization': '95.7%'
            },
            'impact': '限制发送吞吐量',
            'recommendation': '增大tcp_wmem配置'
        })

    if check_cwnd_limitation(data):
        bottlenecks.append({
            'layer': 'TCP层',
            'component': '拥塞窗口',
            'severity': 'WARNING',
            'evidence': {
                'cwnd_limited_time': '23.5%',
                'avg_cwnd': 4523,
                'theoretical_cwnd': 5085
            },
            'impact': 'CWND利用率88.9%，有11%提升空间',
            'recommendation': '检查网络丢包情况'
        })

    # ... 其他瓶颈点检测

    # 综合判断主要瓶颈
    primary_bottleneck = identify_primary(bottlenecks)

    return {
        'bottlenecks': bottlenecks,
        'primary': primary_bottleneck,
        'optimization_priority': rank_optimization_actions(bottlenecks)
    }
```

#### 3.7.4 输入规格

**必需参数**:
```bash
--client-dir <directory>     # Client端TCP Socket数据目录
--server-dir <directory>     # Server端TCP Socket数据目录
--bandwidth <bandwidth>      # 物理链路带宽
--pipeline                   # 启用Pipeline瓶颈分析模式
```

**说明**:
- Pipeline分析**必须**同时提供Client端和Server端数据
- 完整的Pipeline视图需要双向数据才能全面分析：
  - **发送路径分析**：需要发送方（Client或Server）的cwnd、send_q、packets_out等指标
  - **接收路径分析**：需要接收方（Server或Client）的recv_q、socket_rx_queue等指标
  - **双向综合分析**：对比双端瓶颈，识别整体性能限制因素
- 工具会根据连接方向自动识别哪一端是发送方/接收方
- 对于双向流量，会分别分析两个方向的Pipeline
- 带宽参数是必需输入，网络瓶颈判定必须使用该参数（禁止固定阈值）

#### 3.7.5 输出规格

输出要求：必须同时提供 text 与 json；每个瓶颈需给出证据（时间区间/样本值）与验证步骤，且与 Summary 瓶颈保持一致或说明差异原因。

```
===== Pipeline 瓶颈分析 =====

[基本信息]
分析时间范围: 2025-11-12 14:19:47 ~ 14:25:32 (343秒)
连接信息: 100.100.103.205:53910 -> 100.100.103.201:5001
数据来源: Client端 172样本, Server端 168样本, 对齐后 165样本

[Pipeline 健康度总览]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
              TCP 数据包转发 Pipeline - 双向视图
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

┌─────────────────────────────────────────────────────────────┐
│ Client → Server 方向 (主要流量方向)                         │
└─────────────────────────────────────────────────────────────┘

【发送路径 - Client端】                             状态    压力
────────────────────────────────────────────────────────────
应用层 (Client)
  └─ 应用发送速率                                   ✓       低 (5.2%)
     │
Socket层 (Client)
  ├─ send_q 队列                                    ⚠       高 (平均15.2MB)
  └─ Socket发送Buffer (socket_tx_buffer)            ✗       严重 (95.7%)
     │                                              ^^^^^^^^
     │                                              主要瓶颈
TCP层 (Client)
  ├─ socket_write_queue (未ACK数据)                 ✓       正常
  ├─ 拥塞窗口 CWND                                  ⚠       中等 (88.9%利用)
  └─ 对端接收窗口 RWND (Server通告)                 ✓       未限制
     │
网络层
  └─ 网络带宽                                       ✓       正常 (69.8%利用)

【接收路径 - Server端】                             状态    压力
────────────────────────────────────────────────────────────
网络层
  └─ 网络接收能力                                   ✓       正常 (无丢包)
     │
TCP层 (Server)
  └─ TCP接收Buffer                                  ✓       低 (26.3%)
     │
Socket层 (Server)
  ├─ Socket接收Buffer (socket_rx_buffer)            ✓       正常
  └─ recv_q 队列                                    ✓       无积压 (0)
     │
应用层 (Server)
  └─ 应用读取速率                                   ✓       及时读取

┌─────────────────────────────────────────────────────────────┐
│ Server → Client 方向 (反向流量)                             │
└─────────────────────────────────────────────────────────────┘

【发送路径 - Server端】                             状态    压力
────────────────────────────────────────────────────────────
应用层 (Server)
  └─ 应用发送速率                                   ✓       低 (3.1%)
Socket层 (Server)
  └─ Socket发送Buffer                               ✓       正常 (42.3%)
TCP层 (Server)
  └─ 拥塞窗口 CWND                                  ✓       正常 (76.5%利用)
网络层
  └─ 网络带宽                                       ✓       正常

【接收路径 - Client端】                             状态    压力
────────────────────────────────────────────────────────────
网络层
  └─ 网络接收能力                                   ✓       正常
TCP/Socket层 (Client)
  └─ 接收Buffer                                     ✓       正常
应用层 (Client)
  └─ 应用读取速率                                   ✓       及时读取

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[双向综合评估]
- 主要流量方向: Client → Server (占比 92.3%)
- 主要瓶颈: Client端Socket发送Buffer (严重)
- 次要瓶颈: Client端CWND利用不足 (警告)
- 反向流量: 无明显瓶颈，性能良好
- 整体健康度: 62分 (中等) - 主要受发送Buffer限制

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[瓶颈点详细诊断]

【严重】Socket发送Buffer压力
─────────────────────────────────────────────────────────
位置: Socket层 → Socket发送Buffer
检测指标:
  - socket_tx_queue平均: 18.9 MB
  - socket_tx_buffer限制: 21 MB
  - 平均利用率: 90.0%
  - P95利用率: 95.7%
  - 高压力时间: 67.3% (231/343 samples)

影响分析:
  - 限制了发送吞吐量
  - 导致send_q队列积压
  - 影响应用发送性能

证据:
  时序分析显示socket_tx_queue长期处于高位(>18MB)，
  P95达到20.1MB，接近21MB上限，说明Buffer成为发送瓶颈。

根本原因:
  - Buffer配置不足: 当前21MB < 建议值(4.5 × BDP = 32MB)
  - 发送速率高: 平均7 Gbps，需要更大buffer吸收突发

优化建议:
  1. [立即] 增大发送buffer:
     sysctl -w net.ipv4.tcp_wmem="4096 16384 33554432"
  2. [可选] 检查应用发送模式，是否可以优化突发

预期效果:
  - 提升发送吞吐量 10-15%
  - 减少send_q队列积压
  - 提高buffer利用效率

【警告】拥塞窗口CWND利用不足
─────────────────────────────────────────────────────────
位置: TCP层 → 拥塞窗口
检测指标:
  - 实际平均CWND: 4523 packets (6.60 MB)
  - 理论最优CWND: 5085 packets (7.42 MB)
  - CWND利用率: 88.9%
  - CWND Limited时间: 23.5%

影响分析:
  - 未充分利用网络带宽
  - 约11%的性能提升空间

证据:
  基于BDP计算(10Gbps × 5.67ms = 7.09MB)，理论最优CWND
  应为5085 packets，但实际仅4523 packets。

根本原因:
  - 可能存在偶发丢包触发窗口恢复
  - 检测到3次窗口减半事件
  - 拥塞控制算法较保守

优化建议:
  1. 检查网络丢包情况 (当前重传率0.23%，正常)
  2. 考虑调整拥塞控制算法参数
  3. 评估是否可以使用BBR算法

预期效果:
  - 理论上可提升吞吐量约11%

【信息】应用偶尔发送受限
─────────────────────────────────────────────────────────
位置: 应用层 → 应用发送速率
检测指标:
  - App-limited时间: 5.2% (18/343 samples)

影响分析:
  - 轻微影响，大部分时间应用持续发送

建议:
  - 应用发送行为整体良好，无需优化

[Pipeline瓶颈矩阵]

环节            瓶颈组件              严重度    压力值    限制时间    优先级
─────────────────────────────────────────────────────────────────────
应用层          应用发送速率          INFO      5.2%      5.2%       P3
Socket层        Socket发送Buffer      CRITICAL  95.7%     67.3%      P0 ★
Socket层        send_q队列            WARNING   72.4%     87.2%      P1
TCP层           拥塞窗口CWND          WARNING   88.9%     23.5%      P2
TCP层           对端接收窗口RWND      -         -         0%         -
网络层          网络带宽              -         69.8%     -          -
TCP层(接收)     TCP接收Buffer         -         26.3%     0%         -
Socket层(接收)  Socket接收Buffer      -         26.3%     0%         -
Socket层(接收)  recv_q队列            -         0%        0%         -
应用层(接收)    应用读取速率          -         -         0%         -

★ 主要瓶颈

[优化行动优先级]

优先级 P0 (立即执行):
  1. 增大Socket发送Buffer (tcp_wmem)
     预期收益: 提升吞吐量10-15%

优先级 P1 (短期优化):
  2. 监控send_q队列行为
     预期收益: 验证P0优化效果

优先级 P2 (中期优化):
  3. 调查CWND利用率低的原因
     预期收益: 额外提升5-10%

优先级 P3 (长期监控):
  4. 持续监控应用发送模式
     预期收益: 维持性能稳定

[整体评估]

主要瓶颈: Socket层发送Buffer (CRITICAL)
次要瓶颈: TCP层拥塞窗口利用不足 (WARNING)
整体健康度: 60/100 (中等)
  - 发送路径: 55/100 (受Buffer限制)
  - 接收路径: 95/100 (优秀)

优化潜力: 15-25% 吞吐量提升
关键措施: 增大发送buffer配置

建议下一步:
  1. 立即执行P0优化措施
  2. 重新采样数据验证优化效果
  3. 基于新数据进行P1/P2优化
```

#### 3.7.6 可视化输出（可选）

如果指定`--plot-pipeline`参数，工具**应该**生成Pipeline瓶颈可视化数据：

**输出文件**: `pipeline_analysis.txt` (ASCII图)

```
Pipeline压力热图 (时序)

时间轴 →
14:20  14:21  14:22  14:23  14:24  14:25
  │      │      │      │      │      │
应用层    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  5.2%   低压力
Socket层  ██████████████████████████████  95.7%  ★严重★
TCP层     ████████░░░░██████░░░░████████  65.3%  中等压力
网络层    ████████████████████░░░░██████  69.8%  正常
接收路径  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  26.3%  低压力

图例: ░ 0-30%  ▒ 30-60%  ▓ 60-80%  █ 80-100%  ★ 主要瓶颈
```

#### 3.7.7 功能需求

**FR-SOCKET-PIPE-001**: 工具**必须**识别发送路径的6个瓶颈点
**FR-SOCKET-PIPE-002**: 工具**必须**识别接收路径的4个瓶颈点
**FR-SOCKET-PIPE-003**: 工具**必须**计算每个瓶颈点的压力值
**FR-SOCKET-PIPE-004**: 工具**必须**判断主要瓶颈和次要瓶颈
**FR-SOCKET-PIPE-005**: 工具**必须**输出Pipeline健康度总览
**FR-SOCKET-PIPE-006**: 工具**必须**输出瓶颈点详细诊断
**FR-SOCKET-PIPE-007**: 工具**必须**输出优化行动优先级列表
**FR-SOCKET-PIPE-008**: 工具**必须**给出整体评估和建议下一步
**FR-SOCKET-PIPE-009**: 工具**应该**支持Pipeline瓶颈矩阵输出
**FR-SOCKET-PIPE-010**: 工具**应该**支持ASCII图形化展示Pipeline压力
**FR-SOCKET-PIPE-011**: 工具**可以**支持导出可视化数据用于绘图工具

#### 3.7.8 与其他特性的关系

- **基于Summary模式**: Pipeline分析使用Summary模式的统计数据
- **增强Detailed模式**: Detailed模式的深度分析为Pipeline分析提供证据
- **整体视图**: Pipeline分析提供跨层次的整体瓶颈视图

---

## 4. 外部接口需求

### 4.1 用户接口

#### 4.1.1 命令行接口

**PCAP分析工具**:
```bash
pcap_analyzer [OPTIONS] --input <pcap_file>
```

**TCP Socket分析工具**:
```bash
tcpsocket_analyzer [OPTIONS] --input-dir <directory> --bandwidth <bw>
```

#### 4.1.2 帮助信息

工具**必须**提供`--help`参数显示使用帮助：
```bash
pcap_analyzer --help
```

帮助信息**必须**包含：
- 工具描述
- 所有参数说明
- 使用示例
- 输出格式说明

#### 4.1.3 版本信息

工具**必须**提供`--version`参数显示版本信息：
```bash
pcap_analyzer --version
Output: pcap_analyzer v1.0.0
```

### 4.2 软件接口

#### 4.2.1 tshark接口

PCAP工具**必须**通过subprocess调用tshark：
```python
import subprocess

# 示例
cmd = ['tshark', '-r', 'input.pcap', '-T', 'fields', '-e', 'ip.src']
result = subprocess.run(cmd, capture_output=True, text=True)
```

**要求**:
- **必须**检查tshark是否在PATH中
- **必须**处理tshark错误返回
- **必须**支持tshark 2.0+版本

#### 4.2.2 Python库接口

**必需库**:
- pandas >= 1.0.0
- numpy >= 1.18.0
- scipy >= 1.4.0 (用于统计计算)

**可选库**:
- matplotlib >= 3.0.0 (如果实现绘图功能)

### 4.3 文件接口

#### 4.3.1 输入文件

**PCAP文件**:
- 格式: libpcap标准格式
- 扩展名: .pcap, .pcapng
- 编码: 二进制
- 最大大小: 理论上无限制，实际建议<100GB

**TCP Socket文件**:
- 格式: 文本格式
- 编码: UTF-8
- 命名规则: `{prefix}.{number}` (如: client.1, client.2)

#### 4.3.2 输出文件

**文本输出**:
- 格式: UTF-8纯文本
- 编码: UTF-8
- 扩展名: .txt

**JSON输出**:
- 格式: JSON
- 编码: UTF-8
- 扩展名: .json
- 规范: 符合JSON标准，支持pretty-print

**CSV导出（Detailed模式）**:
- 格式: CSV
- 编码: UTF-8
- 分隔符: 逗号
- 包含表头

---

## 5. 非功能需求

### 5.1 性能需求

#### 5.1.1 处理能力

**NFR-PERF-001**: PCAP工具**必须**能在10分钟内处理10GB的PCAP文件（在标准硬件上）
**NFR-PERF-002**: TCP Socket工具**必须**能在1分钟内处理1000个采样文件
**NFR-PERF-003**: 工具**应该**使用流式处理，避免一次性加载所有数据到内存

#### 5.1.2 内存占用

**NFR-PERF-004**: PCAP工具内存占用**应该**不超过4GB（处理10GB文件时）
**NFR-PERF-005**: TCP Socket工具内存占用**应该**不超过2GB（处理1000采样点时）

#### 5.1.3 响应时间

**NFR-PERF-006**: 工具**应该**在1秒内完成参数验证
**NFR-PERF-007**: 工具**应该**在5秒内开始输出（对于Summary模式）
**NFR-PERF-008**: 工具**应该**每5秒更新一次处理进度（对于大文件）

### 5.2 可靠性需求

#### 5.2.1 错误处理

**NFR-REL-001**: 工具**必须**对所有用户输入进行验证
**NFR-REL-002**: 工具**必须**提供清晰的错误消息，而非堆栈跟踪
**NFR-REL-003**: 工具**必须**在遇到损坏的数据时优雅失败，而非崩溃
**NFR-REL-004**: 工具**应该**记录警告和错误到日志文件（可选参数启用）

#### 5.2.2 数据完整性

**NFR-REL-005**: 工具**不得**修改输入文件
**NFR-REL-006**: 工具**必须**在输出文件写入失败时报错
**NFR-REL-007**: 工具**应该**提供数据校验选项（如：验证采样文件格式）

### 5.3 可用性需求

#### 5.3.1 易用性

**NFR-USA-001**: 工具**必须**提供详细的帮助文档（--help）
**NFR-USA-002**: 错误消息**必须**清晰且可操作
**NFR-USA-003**: 工具**应该**提供使用示例（在帮助或README中）
**NFR-USA-004**: 参数命名**应该**直观且符合Unix惯例

#### 5.3.2 进度反馈

**NFR-USA-005**: 处理大文件时**应该**显示进度条或百分比
**NFR-USA-006**: 工具**应该**支持`--quiet`模式抑制非关键输出
**NFR-USA-007**: 工具**应该**支持`--verbose`模式显示详细处理信息

### 5.4 可维护性需求

#### 5.4.1 代码质量

**NFR-MAIN-001**: 代码**必须**遵循PEP 8风格规范
**NFR-MAIN-002**: 所有公共函数和类**必须**包含docstring
**NFR-MAIN-003**: 代码**应该**使用类型提示（type hints）
**NFR-MAIN-004**: 复杂逻辑**应该**包含注释说明

#### 5.4.2 可扩展性

**NFR-MAIN-005**: 工具架构**应该**支持添加新的分析维度
**NFR-MAIN-006**: 输出格式**应该**易于扩展（如：添加XML格式）
**NFR-MAIN-007**: 协议分析**应该**模块化，便于添加新协议支持

#### 5.4.3 可测试性

**NFR-MAIN-008**: 核心分析逻辑**必须**与I/O分离，便于单元测试
**NFR-MAIN-009**: 工具**应该**提供测试数据集
**NFR-MAIN-010**: 工具**应该**包含集成测试用例

### 5.5 可移植性需求

**NFR-PORT-001**: 工具**必须**在Linux系统上运行
**NFR-PORT-002**: 工具**应该**在其他Unix-like系统上运行（如macOS）
**NFR-PORT-003**: 工具**必须**支持Python 3.6+
**NFR-PORT-004**: 工具**应该**避免使用特定Linux发行版的特性

---

## 6. 其他需求

### 6.1 开发环境和工具

**工具链**:
- Python 3.6+
- Git (版本控制)
- pytest (测试框架)
- black (代码格式化，可选)
- pylint/flake8 (代码检查，可选)

### 6.2 文档需求

**必需文档**:
- README.md: 项目概述、快速开始
- 用户手册: 详细使用说明和示例
- 开发文档: 架构设计、代码结构

**可选文档**:
- 贡献指南
- 变更日志

### 6.3 测试需求

#### 6.3.1 单元测试

- **必须**对核心分析逻辑进行单元测试
- 测试覆盖率**应该**达到80%以上

#### 6.3.2 集成测试

- **必须**提供端到端集成测试
- **必须**包含正常场景和异常场景测试

#### 6.3.3 性能测试

- **应该**验证性能需求（处理速度、内存占用）
- **应该**测试大文件处理能力

---

## 附录

### 附录A：术语表

| 术语 | 全称 | 说明 |
|------|------|------|
| BDP | Bandwidth-Delay Product | 带宽延迟积 |
| CWND | Congestion Window | 拥塞窗口 |
| RWND | Receive Window | 接收窗口（通告窗口） |
| SWND | Send Window | 发送窗口 |
| MSS | Maximum Segment Size | 最大段大小 |
| MTU | Maximum Transmission Unit | 最大传输单元 |
| RTT | Round-Trip Time | 往返时间 |
| RTO | Retransmission Timeout | 重传超时 |
| SACK | Selective Acknowledgment | 选择性确认 |
| D-SACK | Duplicate SACK | 重复SACK，用于检测虚假重传 |
| TLP | Tail Loss Probe | 尾部丢失探测 |
| DupACK | Duplicate Acknowledgment | 重复确认 |
| ssthresh | Slow Start Threshold | 慢启动阈值 |
| P50/P95/P99 | Percentile | 分位数 |
| CV | Coefficient of Variation | 变异系数（标准差/均值） |
| pps | Packets Per Second | 每秒包数 |
| bps | Bits Per Second | 每秒比特数 |

### 附录B：参考文档

**研究文档**:
- [Linux Kernel TCP代码研究报告](../research/kernel-tcp-code-research.md)

**外部标准**:
- IEEE 830: IEEE Recommended Practice for Software Requirements Specifications
- RFC 793: Transmission Control Protocol
- RFC 5681: TCP Congestion Control

**相关工具**:
- tshark: https://www.wireshark.org/docs/man-pages/tshark.html
- tcp_connection_analyzer.py: 现有的TCP Socket数据采集工具

### 附录C：需求优先级定义

| 优先级 | 标记 | 说明 | 实现时间 |
|--------|------|------|----------|
| P0 | 高 | 核心功能，必须实现 | 第一阶段 |
| P1 | 中 | 重要功能，强烈建议实现 | 第二阶段 |
| P2 | 低 | 可选功能，资源允许时实现 | 第三阶段 |

### 附录D：功能需求索引

**PCAP分析工具**:
- Summary模式: FR-PCAP-SUM-001 ~ FR-PCAP-SUM-007
- Details模式（TCP）: FR-PCAP-DET-001 ~ FR-PCAP-DET-012
- Analysis模式: FR-PCAP-ANA-001 ~ FR-PCAP-ANA-010
- UDP分析: FR-PCAP-UDP-001 ~ FR-PCAP-UDP-005
- ICMP分析: FR-PCAP-ICMP-001 ~ FR-PCAP-ICMP-005

**TCP Socket分析工具**:
- Summary模式: FR-SOCKET-SUM-001 ~ FR-SOCKET-SUM-014
- Detailed模式: FR-SOCKET-DET-001 ~ FR-SOCKET-DET-010

**非功能需求**:
- 性能: NFR-PERF-001 ~ NFR-PERF-008
- 可靠性: NFR-REL-001 ~ NFR-REL-007
- 可用性: NFR-USA-001 ~ NFR-USA-007
- 可维护性: NFR-MAIN-001 ~ NFR-MAIN-010
- 可移植性: NFR-PORT-001 ~ NFR-PORT-004

---

**文档结束**
