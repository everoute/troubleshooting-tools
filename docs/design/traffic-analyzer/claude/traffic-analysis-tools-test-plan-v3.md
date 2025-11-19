# 网络流量分析工具 - 测试验收计划 (Test & Acceptance Plan) v3.0

**Test Specification Document**

**文档版本**: 3.0
**创建日期**: 2025-11-17
**更新日期**: 2025-11-19
**状态**: Active
**作者**: Claude Code
**项目**: Traffic Analyzer - 通用网络分析工具集

---

## 修订历史

| 版本 | 日期 | 作者 | 变更说明 |
|------|------|------|------------|
| 1.0 | 2025-11-17 | Claude | 初始版本 |
| 2.0 | 2025-11-19 | Claude | 根据实现情况调整测试范围，标记未实现功能 |
| 3.0 | 2025-11-19 | Claude | 激活所有测试用例，实现已100%完成 |

---

## ✅ V3.0 更新说明

### 实现状态总览

根据实现验证 (`IMPLEMENTATION_VERIFICATION.md`)，**所有功能已100%实现**:

| 工具 | 完成度 | 测试状态 |
|------|--------|----------|
| **PCAP Analyzer** | 100% | ✓ 可进行完整测试 |
| **TCP Socket Analyzer - Summary模式** | 100% | ✓ 可进行完整测试 |
| **TCP Socket Analyzer - Detailed模式** | 100% | ✓ 可进行完整测试 |
| **TCP Socket Analyzer - Pipeline模式** | 100% | ✓ 可进行完整测试 |

### V3.0 测试范围

本版本测试计划包含**全部功能模块**:

1. **PCAP Analyzer**: 全部3个模式 (Summary/Details/Analysis) - **完整测试** (20个测试用例)
2. **TCP Socket Analyzer**: 全部3个模式 (Summary/Detailed/Pipeline) - **完整测试** (26个测试用例)
3. **总计**: 46个测试用例全部激活

### V3.0 主要变更

- ✅ 激活 Detailed 模式所有测试用例 (7个)
- ✅ 激活 Pipeline 模式所有测试用例 (8个)
- ✅ 更新验收标准为100%功能覆盖
- ✅ 更新验收计划包含所有功能

---

## 目录

1. [测试策略](#1-测试策略)
2. [测试环境](#2-测试环境)
3. [测试数据准备](#3-测试数据准备)
4. [Layer 0: 实际数据基本功能测试](#4-layer-0-实际数据基本功能测试)
5. [Part 1: PCAP分析工具测试](#5-part-1-pcap分析工具测试)
6. [Part 2: TCP Socket分析工具测试](#6-part-2-tcp-socket分析工具测试)
7. [性能测试](#7-性能测试)
8. [验收标准](#8-验收标准)
9. [验收计划](#9-验收计划)

---

## 1. 测试策略

### 1.1 测试层次

```
┌─────────────────────────────────────────┐
│         验收测试 (Acceptance)            │
│  ├─ 端到端场景测试                       │
│  └─ 用户验收测试 (UAT)                   │
└─────────────────────────────────────────┘
                   ▲
┌─────────────────────────────────────────┐
│         集成测试 (Integration)           │
│  ├─ 组件协作测试                         │
│  └─ 数据流测试                           │
└─────────────────────────────────────────┘
                   ▲
┌─────────────────────────────────────────┐
│         单元测试 (Unit)                  │
│  ├─ 类方法测试                           │
│  ├─ 算法正确性测试                       │
│  └─ 边界条件测试                         │
└─────────────────────────────────────────┘
                   ▲
┌─────────────────────────────────────────┐
│   Layer 0: 实际数据基本功能测试          │
│  ├─ 使用真实生产数据验证                 │
│  ├─ 输出内容正确性校验                   │
│  ├─ 输出格式完整性校验                   │
│  └─ 基本功能smoke testing                │
└─────────────────────────────────────────┘
```

### 1.2 测试类型

| 测试类型 | 覆盖率目标 | 优先级 | V3.0 状态 |
|---------|-----------|--------|----------|
| **功能测试** | 100% FR覆盖 | P0 | ✓ 全部功能 |
| **集成测试** | 100% 组件交互 | P0 | ✓ 全部组件 |
| **性能测试** | 关键路径 | P1 | ✓ 全部模式 |
| **兼容性测试** | 2种Python版本 | P1 | ✓ 保持不变 |
| **错误处理测试** | 100% 异常路径 | P0 | ✓ 保持不变 |
| **回归测试** | 100% 已修复bug | P0 | N/A (初版) |

### 1.3 测试方法

- **黑盒测试**: 验证功能需求
- **白盒测试**: 代码覆盖率 > 80%
- **数据驱动测试**: 使用真实PCAP和Socket数据
- **自动化测试**: 使用pytest框架

---

## 2. 测试环境

### 2.1 硬件环境

| 组件 | 要求 | 备注 |
|------|------|------|
| CPU | 4核以上 | 并发测试 |
| 内存 | 8GB以上 | PCAP大文件处理 |
| 磁盘 | 50GB可用空间 | 测试数据存储 |

### 2.2 软件环境

| 软件 | 版本要求 | 用途 |
|------|---------|------|
| Python | 3.8 / 3.9 / 3.10+ | 运行环境 |
| tshark | 3.x | PCAP解析后端 |
| pandas | >= 1.3.0 | 数据处理 |
| numpy | >= 1.21.0 | 统计计算 |
| pytest | >= 7.0.0 | 测试框架 |

### 2.3 测试数据环境

```
test-data/
├── pcap/
│   ├── small_1mb.pcap      # 小文件测试
│   ├── medium_10mb.pcap    # 中等文件测试
│   ├── large_100mb.pcap    # 性能测试
│   ├── tcp_normal.pcap     # TCP正常流量
│   ├── tcp_retrans.pcap    # TCP重传场景
│   ├── tcp_zero_window.pcap # 零窗口场景
│   └── udp_icmp.pcap       # UDP/ICMP流量
├── socket/
│   ├── client_normal/      # Summary模式客户端数据
│   ├── server_normal/      # Summary模式服务端数据
│   ├── client_cwnd_limited/ # Detailed模式客户端数据
│   ├── server_cwnd_limited/ # Detailed模式服务端数据
│   ├── client_buffer_full/  # Pipeline模式客户端数据
│   ├── server_buffer_full/  # Pipeline模式服务端数据
│   └── mismatched/         # 错误处理测试数据
└── expected_outputs/       # 预期输出
    ├── pcap_summary.json
    ├── pcap_details.json
    ├── socket_summary.json
    ├── socket_detailed.json
    └── socket_pipeline.json
```

---

## 3. 测试数据准备

### 3.1 PCAP数据准备

#### 3.1.1 捕获真实流量

```bash
# 捕获正常TCP流量 (5分钟)
tcpdump -i eth0 -w tcp_normal.pcap -s 0 tcp and port 80

# 捕获包含重传的流量
tcpdump -i eth0 -w tcp_retrans.pcap -s 0 tcp

# 捕获UDP/ICMP流量
tcpdump -i eth0 -w udp_icmp.pcap -s 0 'udp or icmp'
```

#### 3.1.2 生成测试PCAP

```python
# 使用scapy生成测试流量
from scapy.all import *

# 生成TCP三次握手
packets = [
    Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/
    TCP(sport=12345, dport=80, flags="S", seq=1000),
    # ... SYN-ACK, ACK
]

wrpcap('test_handshake.pcap', packets)
```

### 3.2 Socket数据准备

#### 3.2.1 使用eBPF工具采集

```bash
# 在客户端采集
sudo python tcp_connection_analyzer.py \
  --src-ip 192.168.1.1 \
  --dst-ip 192.168.1.2 \
  --output-dir ./client_normal/

# 在服务端采集
sudo python tcp_connection_analyzer.py \
  --src-ip 192.168.1.2 \
  --dst-ip 192.168.1.1 \
  --output-dir ./server_normal/
```

#### 3.2.2 数据文件格式

```
timestamp connection state rtt cwnd ssthresh rwnd pacing_rate delivery_rate socket_tx_queue socket_tx_buffer socket_rx_queue socket_rx_buffer packets_out retrans retrans_rate
1699999999.123 192.168.1.1:12345->192.168.1.2:80 ESTABLISHED 45.2 1000 2000 16384 1200000000 1150000000 0 16384 0 87380 10 0 0.0
```

### 3.3 预期输出准备

为每个测试场景准备预期输出文件（JSON格式），用于自动化验证。

---

## 4. Layer 0: 实际数据基本功能测试

### 4.1 测试目标

**Layer 0测试是使用真实生产数据进行的基本功能验证测试，目的是在进入正式单元测试、集成测试之前，先用实际数据进行smoke testing，快速发现基础问题。**

测试重点：
- ✓ 基本功能是否可以正常运行
- ✓ 输出内容的正确性校验
- ✓ 输出格式的完整性校验
- ✓ 发现实际数据处理中的问题

### 4.2 测试数据

使用实际生产环境采集的数据进行测试：

**数据源目录**: `/Users/admin/workspace/troubleshooting-tools/traffic-analyzer/traffic-analyzer-original/tcp-perf/1119/`

**数据内容**:
- **PCAP数据**:
  - `pcap/client.pcap` (279M) - 客户端抓包数据
  - `pcap/server.pcap` (209M) - 服务端抓包数据
- **TCP Socket数据**:
  - `tcpsocket/client-socket.log` (137KB) - 客户端socket监控数据（原始格式）
  - `tcpsocket/server-socket.log` (125KB) - 服务端socket监控数据（原始格式）
  - `tcpsocket-csv/client-socket.csv` (68条记录) - 转换后的CSV格式
  - `tcpsocket-csv/server-socket.csv` (68条记录) - 转换后的CSV格式

**测试连接信息**:
- Client: 192.168.70.32:41656
- Server: 192.168.70.31:5201
- 监控时长: 约136秒 (68 samples × 2s interval)
- 流量类型: TCP bulk transfer (iperf测试)

### 4.3 测试用例

#### 4.3.1 PCAP Analyzer Layer 0测试

| 测试用例ID | 测试模式 | 测试目标 | 优先级 | 状态 |
|-----------|---------|---------|--------|------|
| **TC-L0-PCAP-001** | Summary | 基本解析和统计 | P0 | PENDING |
| **TC-L0-PCAP-002** | Details | 连接详细分析 | P0 | PENDING |
| **TC-L0-PCAP-003** | Analysis | TCP性能分析 | P0 | PENDING |

**TC-L0-PCAP-001: Summary模式基本功能**
- **测试命令**:
  ```bash
  python3 pcap_analyzer.py --mode summary --pcap \
    /Users/admin/workspace/troubleshooting-tools/traffic-analyzer/traffic-analyzer-original/tcp-perf/1119/pcap/client.pcap
  ```
- **验证项**:
  - [ ] 程序正常运行，无崩溃
  - [ ] 输出包含L2/L3/L4统计信息
  - [ ] 总包数、字节数统计合理
  - [ ] 流统计信息存在
  - [ ] 输出格式完整，无乱码

**TC-L0-PCAP-002: Details模式基本功能**
- **测试命令**:
  ```bash
  python3 pcap_analyzer.py --mode details --pcap \
    /Users/admin/workspace/troubleshooting-tools/traffic-analyzer/traffic-analyzer-original/tcp-perf/1119/pcap/client.pcap \
    --filter "ip.src==192.168.70.32 and ip.dst==192.168.70.31"
  ```
- **验证项**:
  - [ ] 程序正常运行，无崩溃
  - [ ] 输出包含指定连接的详细信息
  - [ ] 包序列详细列表存在
  - [ ] RTT测量值合理
  - [ ] 时间戳解析正确

**TC-L0-PCAP-003: Analysis模式基本功能**
- **测试命令**:
  ```bash
  python3 pcap_analyzer.py --mode analysis --pcap \
    /Users/admin/workspace/troubleshooting-tools/traffic-analyzer/traffic-analyzer-original/tcp-perf/1119/pcap/client.pcap \
    --filter "tcp.stream eq 0"
  ```
- **验证项**:
  - [ ] 程序正常运行，无崩溃
  - [ ] 输出包含TCP性能分析
  - [ ] 重传分析结果存在
  - [ ] 窗口缩放分析结果存在
  - [ ] 乱序分析结果存在

#### 4.3.2 TCP Socket Analyzer Layer 0测试

| 测试用例ID | 测试模式 | 测试目标 | 优先级 | 状态 |
|-----------|---------|---------|--------|------|
| **TC-L0-SOCKET-001** | Summary | 基本解析和分析 | P0 | PENDING |
| **TC-L0-SOCKET-002** | Detailed | 详细指标分析 | P0 | PENDING |
| **TC-L0-SOCKET-003** | Pipeline | 瓶颈诊断 | P0 | PENDING |

**TC-L0-SOCKET-001: Summary模式基本功能**
- **测试命令**:
  ```bash
  python3 tcpsocket_analyzer.py --mode summary \
    --client-dir /Users/admin/workspace/troubleshooting-tools/traffic-analyzer/traffic-analyzer-original/tcp-perf/1119/tcpsocket-csv \
    --server-dir /Users/admin/workspace/troubleshooting-tools/traffic-analyzer/traffic-analyzer-original/tcp-perf/1119/tcpsocket-csv \
    --bandwidth 10gbps
  ```
- **验证项**:
  - [ ] 程序正常运行，无崩溃
  - [ ] 成功解析客户端和服务端数据
  - [ ] 连接五元组匹配验证通过
  - [ ] 时间对齐成功（68条记录对齐）
  - [ ] Window分析结果存在（BDP、CWND、利用率）
  - [ ] Rate分析结果存在（带宽利用率、delivery rate）
  - [ ] RTT分析结果存在（min/avg/max RTT）
  - [ ] Buffer分析结果存在（send/recv buffer压力）
  - [ ] Retrans分析结果存在（重传统计）
  - [ ] Bottleneck识别结果存在
  - [ ] Recommendation建议存在
  - [ ] 输出格式完整，无格式错误

**TC-L0-SOCKET-002: Detailed模式基本功能**
- **测试命令**:
  ```bash
  python3 tcpsocket_analyzer.py --mode detailed \
    --client-dir /Users/admin/workspace/troubleshooting-tools/traffic-analyzer/traffic-analyzer-original/tcp-perf/1119/tcpsocket-csv \
    --server-dir /Users/admin/workspace/troubleshooting-tools/traffic-analyzer/traffic-analyzer-original/tcp-perf/1119/tcpsocket-csv \
    --bandwidth 10gbps \
    --export-timeseries --output /tmp/tcpsocket-timeseries.csv
  ```
- **验证项**:
  - [ ] 程序正常运行，无崩溃
  - [ ] Summary部分输出存在
  - [ ] Window详细分析存在：
    - CWND/RWND/SNDBUF限制时间比例
    - CWND恢复事件检测
    - 拥塞避免时间比例
  - [ ] Rate详细分析存在：
    - Pacing rate趋势分析
    - Delivery rate趋势分析
    - Rate限制类型识别
    - 指标相关性分析
  - [ ] Retrans详细分析存在：
    - Burst事件检测
  - [ ] Buffer详细分析存在：
    - 高压力时间比例
    - Buffer耗尽事件
  - [ ] Time-series数据成功导出到CSV
  - [ ] 导出CSV格式正确，包含所有时间序列指标

**TC-L0-SOCKET-003: Pipeline模式基本功能**
- **测试命令**:
  ```bash
  python3 tcpsocket_analyzer.py --mode pipeline \
    --client-dir /Users/admin/workspace/troubleshooting-tools/traffic-analyzer/traffic-analyzer-original/tcp-perf/1119/tcpsocket-csv \
    --server-dir /Users/admin/workspace/troubleshooting-tools/traffic-analyzer/traffic-analyzer-original/tcp-perf/1119/tcpsocket-csv \
    --bandwidth 10gbps
  ```
- **验证项**:
  - [ ] 程序正常运行，无崩溃
  - [ ] Pipeline健康总览存在：
    - Health Score计算结果
    - Health Grade评级
  - [ ] Send path瓶颈检测：
    - 检测到的瓶颈数量
    - 瓶颈类型识别（APP_SEND/SOCKET_TX/TCP_WRITE/CWND/RWND/NETWORK）
    - 压力值计算
    - 严重级别评估
  - [ ] Recv path瓶颈检测：
    - 检测到的瓶颈数量
    - 瓶颈类型识别（NETWORK_RECV/TCP_RX/SOCKET_RX/APP_READ）
  - [ ] Primary bottleneck识别：
    - 主要瓶颈确定
    - 严重性排序正确
  - [ ] Optimization priority排序：
    - 优化优先级列表
  - [ ] 诊断信息：
    - Impact分析
    - Root cause分析
    - Recommendations建议
  - [ ] 输出格式完整，结构清晰

### 4.4 测试执行流程

```
1. 数据准备
   └─> 确认测试数据存在
   └─> 转换Socket Log为CSV格式（如需要）

2. PCAP Analyzer测试
   ├─> TC-L0-PCAP-001 (Summary)
   ├─> TC-L0-PCAP-002 (Details)
   └─> TC-L0-PCAP-003 (Analysis)

3. TCP Socket Analyzer测试
   ├─> TC-L0-SOCKET-001 (Summary)
   ├─> TC-L0-SOCKET-002 (Detailed)
   └─> TC-L0-SOCKET-003 (Pipeline)

4. 问题记录
   └─> 记录所有执行问题、输出问题、格式问题
   └─> 生成完整测试报告
```

### 4.5 测试结果记录

测试结果将记录在独立的测试报告文档中：`Layer0-Test-Report-<date>.md`

**记录内容**:
- 每个测试用例的执行状态（PASS/FAIL/BLOCKED）
- 发现的问题详细描述
- 错误日志和堆栈信息
- 输出内容截图或完整输出
- 问题分类（解析错误、计算错误、格式问题、性能问题等）
- 修复建议

---

## 5. Part 1: PCAP分析工具测试

### 4.1 特性3.1: Summary模式测试

**测试目标**: 验证L2/L3/L4统计、流聚合、时序分析功能

#### 4.1.1 测试用例矩阵

| 测试用例ID | 需求ID | 测试场景 | 优先级 | 状态 |
|-----------|--------|---------|--------|------|
| **TC-PCAP-SUM-001** | FR-PCAP-SUM-001 | L2层统计 | P0 | ✓ ACTIVE |
| **TC-PCAP-SUM-002** | FR-PCAP-SUM-002 | L3层统计 | P0 | ✓ ACTIVE |
| **TC-PCAP-SUM-003** | FR-PCAP-SUM-003 | L4层统计 | P0 | ✓ ACTIVE |
| **TC-PCAP-SUM-004** | FR-PCAP-SUM-004 | 流聚合 | P0 | ✓ ACTIVE |
| **TC-PCAP-SUM-005** | FR-PCAP-SUM-005 | 时序分析 | P0 | ✓ ACTIVE |
| **TC-PCAP-SUM-006** | FR-PCAP-SUM-006 | Top Talkers | P1 | ✓ ACTIVE |
| **TC-PCAP-SUM-007** | FR-PCAP-SUM-007 | 过滤功能 | P1 | ✓ ACTIVE |

#### 4.1.2 详细测试用例

**TC-PCAP-SUM-001: L2层统计**

- **前置条件**: 准备包含以太网帧的PCAP文件
- **测试步骤**:
  1. 执行命令: `python pcap_analyzer.py --mode summary --pcap tcp_normal.pcap`
  2. 验证输出包含L2统计
- **预期结果**:
  - 总帧数统计正确
  - MAC地址分布正确
  - 帧大小分布统计正确
- **验收标准**: 统计值与tshark对比误差<1%

**TC-PCAP-SUM-002: L3层统计**

- **测试步骤**: 验证IP协议统计
- **预期结果**:
  - IPv4/IPv6包数统计正确
  - IP协议分布正确（TCP/UDP/ICMP）
  - 总字节数统计正确

**TC-PCAP-SUM-003: L4层统计**

- **测试步骤**: 验证传输层协议统计
- **预期结果**:
  - TCP包数和字节数统计正确
  - UDP包数和字节数统计正确
  - 端口分布统计正确

**TC-PCAP-SUM-004: 流聚合**

- **测试步骤**: 验证TCP/UDP流识别和聚合
- **预期结果**:
  - 流数量统计正确（五元组唯一）
  - 每流统计正确（包数、字节数、持续时间）

**TC-PCAP-SUM-005: 时序分析**

- **测试步骤**: 验证时间序列统计
- **预期结果**:
  - 平均pps和峰值pps计算正确
  - 平均bps和峰值bps计算正确
  - 时间窗口划分正确

**TC-PCAP-SUM-006: Top Talkers识别**

- **测试步骤**: 验证Top发送方和接收方识别
- **预期结果**:
  - Top发送方IP排序正确
  - Top接收方IP排序正确
  - 字节数统计正确

**TC-PCAP-SUM-007: 过滤功能**

- **测试步骤**: 测试IP和端口过滤
- **预期结果**:
  - `--src-ip` 过滤正确
  - `--dst-ip` 过滤正确
  - `--src-port` 和 `--dst-port` 过滤正确
  - 过滤后统计仅包含匹配流量

---

### 4.2 特性3.2: Details模式测试

**测试目标**: 验证TCP深度分析功能

#### 4.2.1 测试用例矩阵

| 测试用例ID | 需求ID | 测试场景 | 优先级 | 状态 |
|-----------|--------|---------|--------|------|
| **TC-PCAP-DET-001** | FR-PCAP-DET-001 | 重传检测 | P0 | ✓ ACTIVE |
| **TC-PCAP-DET-002** | FR-PCAP-DET-002 | DupACK检测 | P0 | ✓ ACTIVE |
| **TC-PCAP-DET-003** | FR-PCAP-DET-003 | 零窗口检测 | P0 | ✓ ACTIVE |
| **TC-PCAP-DET-004** | FR-PCAP-DET-004 | SACK分析 | P1 | ✓ ACTIVE |
| **TC-PCAP-DET-005** | FR-PCAP-DET-005 | TCP特性检测 | P1 | ✓ ACTIVE |
| **TC-PCAP-DET-006** | FR-PCAP-DET-006 | RTT估算 | P1 | ✓ ACTIVE |
| **TC-PCAP-DET-007** | FR-PCAP-DET-007 | 流完整性分析 | P1 | ✓ ACTIVE |

#### 4.2.2 详细测试用例

**TC-PCAP-DET-001: 重传检测**

- **测试步骤**: 使用包含重传的PCAP文件
- **预期结果**:
  - 重传包数统计正确
  - 重传率计算正确
  - 快速重传和超时重传区分正确

**TC-PCAP-DET-002: DupACK检测**

- **测试步骤**: 验证重复ACK识别
- **预期结果**:
  - DupACK事件统计正确
  - 触发快速重传的DupACK识别正确

**TC-PCAP-DET-003: 零窗口检测**

- **测试步骤**: 验证零窗口事件识别
- **预期结果**:
  - 零窗口事件统计正确
  - 零窗口持续时间计算正确

**TC-PCAP-DET-004: SACK分析**

- **测试步骤**: 验证SACK选项解析
- **预期结果**:
  - SACK许可检测正确
  - SACK块统计正确

**TC-PCAP-DET-005: TCP特性检测**

- **测试步骤**: 验证TCP选项识别
- **预期结果**:
  - Window Scale检测正确
  - Timestamp检测正确
  - MSS值提取正确

**TC-PCAP-DET-006: RTT估算**

- **测试步骤**: 从握手和数据包估算RTT
- **预期结果**:
  - RTT估算值在合理范围
  - RTT统计（min/avg/max）正确

**TC-PCAP-DET-007: 流完整性分析**

- **测试步骤**: 验证TCP流状态分析
- **预期结果**:
  - 完整连接（三次握手+四次挥手）识别正确
  - 不完整连接标记正确
  - RST终止连接识别正确

---

### 4.3 特性3.3: Analysis模式测试

**测试目标**: 验证问题检测、诊断和优化建议功能

#### 4.3.1 测试用例矩阵

| 测试用例ID | 需求ID | 测试场景 | 优先级 | 状态 |
|-----------|--------|---------|--------|------|
| **TC-PCAP-ANA-001** | FR-PCAP-ANA-001 | 问题检测 | P0 | ✓ ACTIVE |
| **TC-PCAP-ANA-002** | FR-PCAP-ANA-002 | 原因分析 | P0 | ✓ ACTIVE |
| **TC-PCAP-ANA-003** | FR-PCAP-ANA-003 | 严重性判断 | P0 | ✓ ACTIVE |
| **TC-PCAP-ANA-004** | FR-PCAP-ANA-004 | 问题分类 | P1 | ✓ ACTIVE |
| **TC-PCAP-ANA-005** | FR-PCAP-ANA-005 | 优化建议 | P1 | ✓ ACTIVE |
| **TC-PCAP-ANA-006** | FR-PCAP-ANA-006 | 问题优先级 | P1 | ✓ ACTIVE |

#### 4.3.2 详细测试用例

**TC-PCAP-ANA-001: 问题检测**

- **测试步骤**: 使用包含各种问题的PCAP
- **预期结果**:
  - 重传问题检测正确
  - 零窗口问题检测正确
  - 连接失败问题检测正确

**TC-PCAP-ANA-002: 原因分析**

- **测试步骤**: 验证根因分析
- **预期结果**:
  - 网络丢包原因识别正确
  - 接收端缓冲区满原因识别正确

**TC-PCAP-ANA-003: 严重性判断**

- **测试步骤**: 验证问题严重性评估
- **预期结果**:
  - CRITICAL/HIGH/MEDIUM/LOW分级正确
  - 严重性基于影响程度

**TC-PCAP-ANA-004: 问题分类**

- **测试步骤**: 验证问题分类
- **预期结果**:
  - 按类别分组正确（网络/性能/配置）

**TC-PCAP-ANA-005: 优化建议**

- **测试步骤**: 验证优化建议生成
- **预期结果**:
  - 针对问题的建议合理
  - 配置示例准确

**TC-PCAP-ANA-006: 问题优先级排序**

- **测试步骤**: 验证问题优先级排序
- **预期结果**:
  - 按严重性+影响排序正确

---

## 5. Part 2: TCP Socket分析工具测试

### 5.1 特性3.5: Summary模式测试

**测试目标**: 验证窗口、速率、RTT、Buffer、瓶颈分析功能

#### 5.1.1 测试用例矩阵

| 测试用例ID | 需求ID | 测试场景 | 优先级 | 状态 |
|-----------|--------|---------|--------|------|
| **TC-SOCKET-SUM-001** | FR-SOCKET-SUM-001 | 双端数据解析 | P0 | ✓ ACTIVE |
| **TC-SOCKET-SUM-002** | FR-SOCKET-SUM-002 | 完整统计 | P0 | ✓ ACTIVE |
| **TC-SOCKET-SUM-003** | FR-SOCKET-SUM-003 | BDP计算 | P0 | ✓ ACTIVE |
| **TC-SOCKET-SUM-004** | FR-SOCKET-SUM-004 | 带宽利用率 | P0 | ✓ ACTIVE |
| **TC-SOCKET-SUM-005** | FR-SOCKET-SUM-005 | RTT稳定性 | P0 | ✓ ACTIVE |
| **TC-SOCKET-SUM-006** | FR-SOCKET-SUM-006 | 瓶颈识别 | P0 | ✓ ACTIVE |
| **TC-SOCKET-SUM-007** | FR-SOCKET-SUM-011 | 配置建议 | P1 | ✓ ACTIVE |
| **TC-SOCKET-SUM-008** | FR-SOCKET-SUM-014 | 连接验证 | P0 | ✓ ACTIVE |

#### 5.1.2 详细测试用例

**TC-SOCKET-SUM-001: 双端数据解析**

- **测试步骤**:
  ```bash
  python tcpsocket_analyzer.py --mode summary \
    --client-dir ./client_normal/ \
    --server-dir ./server_normal/ \
    --bandwidth 1gbps
  ```
- **预期结果**:
  - Client端数据解析成功
  - Server端数据解析成功
  - 时间对齐成功
  - 连接五元组匹配验证通过

**TC-SOCKET-SUM-002: 完整统计**

- **测试步骤**: 验证所有指标的Min/Max/Mean/Std/CV/P50/P95/P99统计
- **预期结果**:
  - CWND统计正确
  - RTT统计正确
  - pacing_rate和delivery_rate统计正确

**TC-SOCKET-SUM-003: BDP计算**

- **测试步骤**: 验证BDP和最优CWND计算
- **预期结果**:
  - BDP = bandwidth × RTT 计算正确
  - Optimal CWND = BDP / MSS 计算正确
  - CWND利用率 = Actual CWND / Optimal CWND 正确

**TC-SOCKET-SUM-004: 带宽利用率**

- **测试步骤**: 验证带宽利用率计算
- **预期结果**:
  - 平均带宽利用率 = avg(delivery_rate) / bandwidth 正确
  - 峰值带宽利用率 = max(delivery_rate) / bandwidth 正确

**TC-SOCKET-SUM-005: RTT稳定性分析**

- **测试步骤**: 验证RTT稳定性判断
- **预期结果**:
  - CV < 0.1: STABLE
  - 0.1 <= CV < 0.3: UNSTABLE
  - CV >= 0.3: HIGHLY_VARIABLE

**TC-SOCKET-SUM-006: 瓶颈识别**

- **测试步骤**: 验证性能瓶颈识别
- **预期结果**:
  - CWND_LIMITED识别正确
  - BUFFER_LIMITED识别正确
  - NETWORK_LIMITED识别正确
  - APP_LIMITED识别正确

**TC-SOCKET-SUM-007: 配置建议**

- **测试步骤**: 验证优化建议生成
- **预期结果**:
  - 建议合理且可执行
  - 配置示例准确

**TC-SOCKET-SUM-008: 连接验证**

- **测试步骤**: 使用不匹配的client/server数据
- **预期结果**:
  - ConnectionMismatchError异常抛出
  - 错误信息明确指出不匹配

---

### 5.2 特性3.6: Detailed模式测试 ✓ ACTIVE

**测试目标**: 验证窗口深度分析、速率时序分析、Buffer压力分析功能

#### 5.2.1 测试用例矩阵

| 测试用例ID | 需求ID | 测试场景 | 优先级 | 状态 |
|-----------|--------|---------|--------|------|
| **TC-SOCKET-DET-001** | FR-SOCKET-DET-001 | 窗口限制时间占比 | P0 | ✓ ACTIVE |
| **TC-SOCKET-DET-002** | FR-SOCKET-DET-002 | CWND变化模式识别 | P0 | ✓ ACTIVE |
| **TC-SOCKET-DET-003** | FR-SOCKET-DET-003 | 速率时序分析 | P0 | ✓ ACTIVE |
| **TC-SOCKET-DET-004** | FR-SOCKET-DET-004 | Rate限制类型识别 | P0 | ✓ ACTIVE |
| **TC-SOCKET-DET-005** | FR-SOCKET-DET-005 | 重传突发事件 | P0 | ✓ ACTIVE |
| **TC-SOCKET-DET-006** | FR-SOCKET-DET-007 | Buffer压力时序 | P0 | ✓ ACTIVE |
| **TC-SOCKET-DET-009** | FR-SOCKET-DET-009 | 时序数据导出 | P0 | ✓ ACTIVE |
| **TC-SOCKET-DET-010** | FR-SOCKET-DET-010 | 指标相关性分析 | P0 | ✓ ACTIVE |

#### 5.2.2 详细测试用例

**TC-SOCKET-DET-001: 窗口限制时间占比**

- **测试步骤**:
  ```bash
  python tcpsocket_analyzer.py --mode detailed \
    --client-dir ./client_cwnd_limited/ \
    --server-dir ./server_cwnd_limited/ \
    --bandwidth 1gbps
  ```
- **预期结果**:
  - CWND限制时间占比计算正确（packets_out >= cwnd × 0.95）
  - RWND限制时间占比计算正确
  - SNDBUF限制时间占比计算正确

**TC-SOCKET-DET-002: CWND变化模式识别**

- **测试步骤**: 验证CWND模式检测
- **预期结果**:
  - 慢启动阶段检测正确（CWND < ssthresh）
  - 拥塞避免阶段检测正确（CWND >= ssthresh）
  - 快速恢复事件统计正确（CWND减半事件）
  - CWND增长速率计算正确（线性回归斜率）

**TC-SOCKET-DET-003: 速率时序分析**

- **测试步骤**: 验证速率趋势分析
- **预期结果**:
  - 上升时段识别正确
  - 下降时段识别正确
  - 稳定时段识别正确
  - 波动性（volatility）计算正确

**TC-SOCKET-DET-004: Rate限制类型识别**

- **测试步骤**: 验证速率限制类型
- **预期结果**:
  - Pacing限制识别正确（pacing_rate < delivery_rate）
  - Network限制识别正确（delivery_rate >= bandwidth × 0.9）
  - App限制识别正确（delivery_rate << bandwidth）

**TC-SOCKET-DET-005: 重传突发事件检测**

- **测试步骤**: 验证重传突发检测
- **预期结果**:
  - 突发事件识别正确（单次retrans增量 >= 5）
  - 突发严重性评估正确（HIGH/MEDIUM/LOW）
  - 突发时间段记录正确

**TC-SOCKET-DET-006: Buffer压力时序分析**

- **测试步骤**: 验证Buffer压力分析
- **预期结果**:
  - 发送Buffer压力序列计算正确（queue/buffer）
  - 接收Buffer压力序列计算正确
  - 高压力时间占比计算正确（> 90%）
  - Buffer耗尽事件统计正确（>= 99%）

**TC-SOCKET-DET-009: 时序数据导出**

- **测试步骤**: 测试CSV导出功能
- **预期结果**:
  - 使用 `--export-timeseries` 参数导出成功
  - CSV文件包含所有关键指标
  - 数据格式正确

**TC-SOCKET-DET-010: 指标相关性分析**

- **测试步骤**: 验证指标间相关性
- **预期结果**:
  - CWND与delivery_rate相关性计算正确
  - RTT与delivery_rate相关性计算正确
  - pacing_rate与delivery_rate相关性计算正确

---

### 5.3 特性3.7: Pipeline瓶颈分析测试 ✓ ACTIVE

**测试目标**: 验证10条瓶颈检测规则、健康度评分、优化建议功能

#### 5.3.1 测试用例矩阵

| 测试用例ID | 需求ID | 测试场景 | 优先级 | 状态 |
|-----------|--------|---------|--------|------|
| **TC-SOCKET-PIPE-001** | FR-SOCKET-PIPE-001 | 发送路径瓶颈识别 | P0 | ✓ ACTIVE |
| **TC-SOCKET-PIPE-002** | FR-SOCKET-PIPE-002 | 接收路径瓶颈识别 | P0 | ✓ ACTIVE |
| **TC-SOCKET-PIPE-003** | FR-SOCKET-PIPE-003 | 瓶颈压力值计算 | P0 | ✓ ACTIVE |
| **TC-SOCKET-PIPE-004** | FR-SOCKET-PIPE-004 | 主要瓶颈判断 | P0 | ✓ ACTIVE |
| **TC-SOCKET-PIPE-005** | FR-SOCKET-PIPE-005 | Pipeline健康度总览 | P0 | ✓ ACTIVE |
| **TC-SOCKET-PIPE-006** | FR-SOCKET-PIPE-006 | 瓶颈详细诊断 | P0 | ✓ ACTIVE |
| **TC-SOCKET-PIPE-007** | FR-SOCKET-PIPE-007 | 优化优先级排序 | P0 | ✓ ACTIVE |
| **TC-SOCKET-PIPE-008** | FR-SOCKET-PIPE-008 | 整体评估和建议 | P0 | ✓ ACTIVE |

#### 5.3.2 详细测试用例

**TC-SOCKET-PIPE-001: 发送路径瓶颈识别（6个检测点）**

- **测试步骤**:
  ```bash
  python tcpsocket_analyzer.py --mode pipeline \
    --client-dir ./client_buffer_full/ \
    --server-dir ./server_buffer_full/ \
    --bandwidth 1gbps
  ```
- **预期结果**: 6条规则正确检测
  1. ✓ App发送限制（delivery_rate << bandwidth）
  2. ✓ Socket发送Buffer满（tx_queue > 90% tx_buffer）
  3. ✓ TCP写队列积压（packets_out高）
  4. ✓ CWND限制（packets_out >= cwnd × 0.95，时间占比 > 50%）
  5. ✓ RWND限制（rwnd < cwnd，时间占比 > 30%）
  6. ✓ 网络带宽饱和（delivery_rate >= bandwidth × 0.9）

**TC-SOCKET-PIPE-002: 接收路径瓶颈识别（4个检测点）**

- **预期结果**: 4条规则正确检测
  7. ✓ 网络接收问题（retrans_rate > 1%）
  8. ✓ TCP接收Buffer满（服务端数据）
  9. ✓ Socket接收Buffer满（rx_queue > 90% rx_buffer）
  10. ✓ App读取限制（rx_queue持续 > 50% rx_buffer）

**TC-SOCKET-PIPE-003: 瓶颈压力值计算**

- **测试步骤**: 验证压力值（0-1）计算
- **预期结果**:
  - Buffer利用率作为压力值（queue/buffer）
  - CWND限制时间占比作为压力值
  - 压力值在 [0, 1] 范围内

**TC-SOCKET-PIPE-004: 主要瓶颈判断**

- **测试步骤**: 验证主要瓶颈识别
- **预期结果**:
  - 严重性优先：CRITICAL > HIGH > MEDIUM > LOW
  - 同级别按压力值排序
  - 主要瓶颈唯一

**TC-SOCKET-PIPE-005: Pipeline健康度总览**

- **测试步骤**: 验证健康度评分
- **预期结果**:
  - 评分公式：100 - CRITICAL×30 - HIGH×20 - MEDIUM×10 - LOW×5
  - 健康等级：EXCELLENT(90-100) / GOOD(70-89) / FAIR(50-69) / POOR(30-49) / CRITICAL(0-29)
  - 瓶颈数量统计正确

**TC-SOCKET-PIPE-006: 瓶颈详细诊断**

- **测试步骤**: 验证根因分析和影响评估
- **预期结果**:
  - 根因分析准确（网络拥塞/Buffer配置/应用性能）
  - 影响评估合理（性能下降百分比）
  - 行动项具体可执行

**TC-SOCKET-PIPE-007: 优化优先级排序**

- **测试步骤**: 验证瓶颈排序
- **预期结果**:
  - CRITICAL瓶颈排在前面
  - 同级别按压力值降序
  - 发送路径略优于接收路径（更易修复）

**TC-SOCKET-PIPE-008: 整体评估和建议**

- **测试步骤**: 验证优化行动计划
- **预期结果**:
  - Top 3-5 优化建议
  - 预期影响评估（性能提升百分比）
  - 工作量评估（LOW/MEDIUM/HIGH）
  - 配置示例准确（sysctl命令）

---

## 6. 性能测试

### 6.1 性能测试场景

| 测试场景 | 数据规模 | 性能指标 | 目标 |
|---------|---------|---------|------|
| PCAP小文件 | 1MB (~1K包) | 处理时间 | < 5秒 |
| PCAP中等文件 | 10MB (~10K包) | 处理时间 | < 15秒 |
| PCAP大文件 | 100MB (~100K包) | 处理时间 | < 30秒 |
| Socket小数据集 | 100个采样点 | 处理时间 | < 1秒 |
| Socket中等数据集 | 1K个采样点 | 处理时间 | < 3秒 |
| Socket大数据集 | 10K个采样点 | 处理时间 | < 5秒 |

### 6.2 性能测试用例

**TC-PERF-001: PCAP大文件处理**

- **测试步骤**:
  ```bash
  time python pcap_analyzer.py --mode summary --pcap large_100mb.pcap
  ```
- **验收标准**: 处理时间 < 30秒

**TC-PERF-002: Socket大数据集处理**

- **测试步骤**:
  ```bash
  time python tcpsocket_analyzer.py --mode detailed \
    --client-dir ./client_10k/ --server-dir ./server_10k/
  ```
- **验收标准**: 处理时间 < 5秒

**TC-PERF-003: 内存占用测试**

- **测试步骤**: 使用 `memory_profiler` 监控内存
  ```bash
  mprof run python pcap_analyzer.py --mode summary --pcap large_100mb.pcap
  mprof plot
  ```
- **验收标准**: 峰值内存 < 2GB

**TC-PERF-004: 并发处理能力**

- **测试步骤**: 同时处理8个PCAP文件
- **验收标准**: 8个任务在1分钟内完成

---

## 7. 验收标准

### 7.1 功能验收标准

#### 7.1.1 必须通过的测试 (P0)

**PCAP工具** (全部可测试):
- [ ] 所有TC-PCAP-SUM-* 测试通过 (7个)
- [ ] 所有TC-PCAP-DET-* 测试通过 (7个)
- [ ] 所有TC-PCAP-ANA-* 测试通过 (6个)

**Socket工具** (全部可测试):
- [ ] 所有TC-SOCKET-SUM-* 测试通过 (8个)
- [ ] 所有TC-SOCKET-DET-* 测试通过 (8个)
- [ ] 所有TC-SOCKET-PIPE-* 测试通过 (8个)

#### 7.1.2 功能完整性

| 功能模块 | 需求总数 | 已实现 | 可测试 | 验收标准 |
|---------|---------|--------|--------|---------|
| **PCAP Summary** | 7 | 7 | 7 | 7/7 通过 (100%) ✓ |
| **PCAP Details** | 12 | 12 | 7 | 7/7 通过 (100%) ✓ |
| **PCAP Analysis** | 10 | 10 | 6 | 6/6 通过 (100%) ✓ |
| **Socket Summary** | 14 | 14 | 8 | 8/8 通过 (100%) ✓ |
| **Socket Detailed** | 10 | 10 | 8 | 8/8 通过 (100%) ✓ |
| **Socket Pipeline** | 11 | 11 | 8 | 8/8 通过 (100%) ✓ |
| **总计** | **64** | **64** | **44** | **44/44 通过 (100%)** |

#### 7.1.3 代码质量标准

- [ ] **代码覆盖率**: >= 80%
- [ ] **单元测试通过率**: 100%
- [ ] **集成测试通过率**: 100%
- [ ] **Pylint评分**: >= 8.0/10
- [ ] **无Critical安全漏洞** (Bandit扫描)

### 7.2 性能验收标准

| 性能指标 | 验收标准 | 适用工具 |
|---------|---------| ---------|
| PCAP解析速度 (100MB) | < 30秒 | PCAP Analyzer |
| Socket分析速度 (10K点) | < 5秒 | Socket Analyzer (所有模式) |
| 内存占用峰值 | < 2GB | 两个工具 |
| 并发处理能力 | >= 8任务/分钟 | PCAP Analyzer |

### 7.3 兼容性验收标准

- [ ] **Python 3.8** 测试通过
- [ ] **Python 3.9** 测试通过
- [ ] **Python 3.10+** 测试通过
- [ ] **Linux (openEuler)** 测试通过
- [ ] **macOS** 测试通过 (开发环境)

### 7.4 文档验收标准

- [ ] **README.md** 完整且准确
- [ ] **IMPLEMENTATION_VERIFICATION.md** 已创建并准确
- [ ] **用户手册** 包含所有功能
- [ ] **示例代码** 可运行且有效

---

## 8. 验收计划

### 8.1 验收阶段

```
阶段1: 单元测试验收 (Week 1-2)
├─ PCAP Analyzer完整测试
├─ Socket Analyzer Summary模式测试
├─ Socket Analyzer Detailed模式测试
├─ Socket Analyzer Pipeline模式测试
└─ 单元测试覆盖率检查

阶段2: 集成测试验收 (Week 3-4)
├─ PCAP端到端场景测试
├─ Socket Summary模式集成测试
├─ Socket Detailed模式集成测试
├─ Socket Pipeline模式集成测试
└─ 性能测试

阶段3: 系统测试验收 (Week 5)
├─ PCAP完整功能测试
├─ Socket完整功能测试
└─ 兼容性测试

阶段4: 用户验收测试 (Week 6)
├─ UAT环境部署
├─ 用户试用
└─ 反馈收集
```

### 8.2 验收流程

#### 阶段1: 单元测试验收

**负责人**: 开发工程师
**时间**: 开发完成后立即执行
**准入条件**:
- 代码编写完成
- 所有函数有docstring

**执行步骤**:
1. 运行单元测试套件
   ```bash
   pytest tests/unit/ -v --cov=. --cov-report=html
   ```
2. 检查代码覆盖率 >= 80%
3. 修复所有失败测试
4. 代码审查

**退出标准**:
- [ ] 所有单元测试通过
- [ ] 代码覆盖率 >= 80%
- [ ] Pylint评分 >= 8.0

#### 阶段2: 集成测试验收

**负责人**: 测试工程师
**时间**: 单元测试完成后
**准入条件**:
- 阶段1通过
- 测试数据准备完成

**执行步骤**:
1. 部署测试环境
2. 准备测试数据
3. 执行集成测试套件
   ```bash
   pytest tests/integration/ -v
   ```
4. 执行性能测试
5. 记录测试结果

**退出标准**:
- [ ] 所有集成测试通过
- [ ] 性能指标达标
- [ ] 无阻塞性缺陷

#### 阶段3: 系统测试验收

**负责人**: 质量保证工程师
**时间**: 集成测试完成后
**准入条件**:
- 阶段2通过
- 文档完整

**执行步骤**:
1. 端到端场景测试
2. 兼容性测试（多Python版本）
3. 错误处理测试
4. 文档验证

**退出标准**:
- [ ] 所有功能测试通过
- [ ] 兼容性测试通过
- [ ] 文档准确完整

#### 阶段4: 用户验收测试

**负责人**: 产品经理 + 最终用户
**时间**: 系统测试完成后
**准入条件**:
- 阶段3通过
- UAT环境就绪

**执行步骤**:
1. UAT环境部署
2. 用户培训
3. 用户试用（真实数据）
4. 收集反馈
5. 问题修复

**退出标准**:
- [ ] 用户满意度 >= 80%
- [ ] 无P0/P1缺陷
- [ ] 文档用户反馈良好

### 8.3 缺陷管理

#### 缺陷严重性定义

| 严重性 | 定义 | 处理时限 |
|-------|------|---------|
| **P0 - Blocker** | 核心功能无法使用 | 24小时 |
| **P1 - Critical** | 重要功能受影响 | 3天 |
| **P2 - Major** | 次要功能问题 | 1周 |
| **P3 - Minor** | 界面/提示问题 | 2周 |
| **P4 - Trivial** | 优化建议 | 下一版本 |

#### 缺陷处理流程

```
1. 发现缺陷 → 记录到Issue Tracker
2. 分类和评估 → 分配严重性和优先级
3. 分配给开发 → 开发修复
4. 验证修复 → 测试工程师验证
5. 关闭缺陷 → 验证通过后关闭
```

---

## 附录A: 测试数据清单

### PCAP文件

| 文件名 | 大小 | 包数 | 用途 | 状态 |
|-------|------|------|------|------|
| small_1mb.pcap | 1MB | ~1K | 基础功能测试 | ✓ 需要准备 |
| medium_10mb.pcap | 10MB | ~10K | 中等规模测试 | ✓ 需要准备 |
| large_100mb.pcap | 100MB | ~100K | 性能测试 | ✓ 需要准备 |
| tcp_normal.pcap | 5MB | ~5K | TCP正常流量 | ✓ 需要准备 |
| tcp_retrans.pcap | 10MB | ~10K | TCP重传场景 | ✓ 需要准备 |
| tcp_zero_window.pcap | 5MB | ~5K | 零窗口场景 | ✓ 需要准备 |
| tcp_sack.pcap | 5MB | ~5K | SACK测试 | ✓ 需要准备 |
| udp_icmp.pcap | 5MB | ~5K | UDP/ICMP测试 | ✓ 需要准备 |

### Socket数据目录

| 目录 | 文件数 | 用途 | 状态 |
|------|--------|------|------|
| client_normal/ | ~100 | Summary模式测试 | ✓ 需要采集 |
| server_normal/ | ~100 | Summary模式测试 | ✓ 需要采集 |
| client_cwnd_limited/ | ~100 | Detailed模式测试 | ✓ 需要采集 |
| server_cwnd_limited/ | ~100 | Detailed模式测试 | ✓ 需要采集 |
| client_buffer_full/ | ~100 | Pipeline模式测试 | ✓ 需要采集 |
| server_buffer_full/ | ~100 | Pipeline模式测试 | ✓ 需要采集 |
| mismatched/ | ~10 | 错误处理测试 | ✓ 需要准备 |

---

## 附录B: 自动化测试脚本示例

### B.1 单元测试示例

```python
# tests/unit/test_window_analyzer.py
import pytest
from tcpsocket_analyzer.analyzers import WindowAnalyzer
import pandas as pd

def test_detect_cwnd_patterns():
    """测试CWND模式识别"""
    analyzer = WindowAnalyzer()

    # 构造测试数据
    data = pd.DataFrame({
        'cwnd': [10, 20, 40, 80, 160, 80, 40, 60, 80, 100],
        'ssthresh': [100] * 10
    })

    patterns = analyzer.detect_cwnd_patterns(data)

    # 验证
    assert patterns.slow_start_detected == True
    assert patterns.fast_recovery_count >= 1
    assert patterns.cwnd_growth_rate > 0

def test_analyze_window_limits():
    """测试窗口限制分析"""
    analyzer = WindowAnalyzer()

    data = pd.DataFrame({
        'packets_out': [95, 98, 99, 100, 100],
        'cwnd': [100] * 5,
        'rwnd': [200] * 5,
        'socket_tx_queue': [15000, 15500, 15800, 16000, 16000],
        'socket_tx_buffer': [16384] * 5
    })

    limits = analyzer.analyze_window_limits(data)

    assert limits.cwnd_limited_ratio >= 0.6  # 60% of time
    assert limits.sndbuf_limited_ratio >= 0.6
```

### B.2 集成测试示例

```python
# tests/integration/test_socket_analyzer_e2e.py
import pytest
from tcpsocket_analyzer.parser import SocketDataParser
from tcpsocket_analyzer.analyzers import SummaryAnalyzer

def test_summary_mode_end_to_end(test_data_dir):
    """测试Summary模式端到端流程"""
    # 解析数据
    parser = SocketDataParser()
    client_df, server_df, aligned_df = parser.parse_dual_directories(
        f"{test_data_dir}/client_normal",
        f"{test_data_dir}/server_normal"
    )

    # 分析
    analyzer = SummaryAnalyzer()
    connection = parser._parse_connection_str(client_df['connection'].iloc[0])
    result = analyzer.analyze(client_df, server_df, aligned_df, 1e9, connection)

    # 验证结果
    assert result.connection is not None
    assert result.window_analysis.bdp > 0
    assert 0 <= result.window_analysis.cwnd_utilization <= 2
    assert result.bottleneck.primary_bottleneck in [
        'CWND_LIMITED', 'BUFFER_LIMITED', 'NETWORK_LIMITED', 'APP_LIMITED'
    ]
```

---

## 附录C: V3.0 变更总结

### 主要调整

1. **测试范围扩展**:
   - 激活 Socket Detailed 模式全部测试用例 (8个)
   - 激活 Socket Pipeline 模式全部测试用例 (8个)
   - 总计从 28 个激活用例增加到 46 个

2. **验收标准提升**:
   - 功能完整性从"已实现功能100%"提升为"所有功能100%"
   - 需求覆盖从 42/64 提升到 64/64
   - 可测试用例从 28 个增加到 46 个

3. **文档同步**:
   - 参考 IMPLEMENTATION_VERIFICATION.md
   - 删除 V2.0 "⚠ 重要说明" 部分
   - 更新实现状态总览为 100%

4. **测试计划优化**:
   - 扩展验收阶段包含所有模式
   - 更新性能测试覆盖所有分析器
   - 补充 Detailed 和 Pipeline 模式详细测试步骤

### 下一步行动

1. **立即执行** (Week 1-2):
   - 准备测试数据（PCAP + Socket）
   - 执行单元测试验收
   - 检查代码覆盖率

2. **短期执行** (Week 3-4):
   - 执行集成测试验收
   - 运行性能测试
   - 修复发现的问题

3. **中期执行** (Week 5-6):
   - 系统测试验收
   - 用户验收测试
   - 收集反馈并优化

---

**文档结束**
