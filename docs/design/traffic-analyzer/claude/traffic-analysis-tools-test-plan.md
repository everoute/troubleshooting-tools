# 网络流量分析工具 - 测试验收计划 (Test & Acceptance Plan)

**Test Specification Document**

**文档版本**: 1.0
**创建日期**: 2025-11-17
**状态**: Draft
**作者**: Claude Code
**项目**: Traffic Analyzer - 通用网络分析工具集

---

## 修订历史

| 版本 | 日期 | 作者 | 变更说明 |
|------|------|------|----------|
| 1.0 | 2025-11-17 | Claude | 初始版本 |

---

## 目录

1. [测试策略](#1-测试策略)
2. [测试环境](#2-测试环境)
3. [测试数据准备](#3-测试数据准备)
4. [Part 1: PCAP分析工具测试](#4-part-1-pcap分析工具测试)
5. [Part 2: TCP Socket分析工具测试](#5-part-2-tcp-socket分析工具测试)
6. [性能测试](#6-性能测试)
7. [验收标准](#7-验收标准)
8. [验收计划](#8-验收计划)

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
```

### 1.2 测试类型

| 测试类型 | 覆盖率目标 | 优先级 |
|---------|-----------|--------|
| **功能测试** | 100% FR覆盖 | P0 |
| **集成测试** | 100% 组件交互 | P0 |
| **性能测试** | 关键路径 | P1 |
| **兼容性测试** | 2种Python版本 | P1 |
| **错误处理测试** | 100% 异常路径 | P0 |
| **回归测试** | 100% 已修复bug | P0 |

### 1.3 测试方法

- **黑盒测试**: 验证功能需求
- **白盒测试**: 代码覆盖率 > 80%
- **数据驱动测试**: 使用真实PCAP和Socket数据
- **自动化测试**: 使用pytest框架
- **探索性测试**: 发现边界场景

---

## 2. 测试环境

### 2.1 硬件要求

| 组件 | 最低配置 | 推荐配置 |
|------|---------|---------|
| CPU | 2 cores | 4 cores |
| 内存 | 4GB | 8GB |
| 磁盘 | 10GB | 20GB |

### 2.2 软件环境

**操作系统**:
- Linux (openEuler 4.19.90 / Ubuntu 20.04+)
- macOS 12+ (开发测试)

**Python环境**:
- Python 3.8+
- Python 2.7 (PCAP工具向后兼容测试)

**依赖工具**:
- tshark (Wireshark CLI) >= 3.0
- pandas >= 1.3.0
- numpy >= 1.20.0

**测试框架**:
- pytest >= 7.0
- pytest-cov (覆盖率)
- pytest-mock (模拟)

### 2.3 测试数据集

**标准测试数据集位置**: `test/data/`

```
test/data/
├── pcap/
│   ├── tcp_normal.pcap           # 正常TCP流
│   ├── tcp_retrans.pcap          # 含重传
│   ├── tcp_zero_window.pcap      # Zero Window
│   ├── tcp_sack.pcap             # SACK/D-SACK
│   ├── tcp_handshake_fail.pcap   # 握手失败
│   ├── udp_normal.pcap           # 正常UDP
│   ├── icmp_ping.pcap            # ICMP ping
│   └── mixed_protocols.pcap      # 混合协议
│
└── socket/
    ├── client_normal/            # 正常Client端数据
    ├── server_normal/            # 正常Server端数据
    ├── client_cwnd_limited/      # CWND受限
    ├── server_cwnd_limited/
    ├── client_buffer_limited/    # Buffer受限
    ├── server_buffer_limited/
    └── mismatched/               # 不匹配连接（错误测试）
```

---

## 3. 测试数据准备

### 3.1 PCAP文件生成

**方法1: 使用tcpdump捕获真实流量**
```bash
# TCP正常流量
sudo tcpdump -i eth0 -w tcp_normal.pcap tcp and host 192.168.1.100

# 包含重传的流量（人为制造丢包）
sudo tc qdisc add dev eth0 root netem loss 5%
sudo tcpdump -i eth0 -w tcp_retrans.pcap tcp
sudo tc qdisc del dev eth0 root
```

**方法2: 使用scapy生成合成流量**
```python
from scapy.all import *

# 生成TCP握手失败场景
packets = [
    IP(dst="192.168.1.100")/TCP(dport=80, flags="S"),  # SYN
    IP(src="192.168.1.100")/TCP(sport=80, flags="R")   # RST
]
wrpcap('tcp_handshake_fail.pcap', packets)
```

### 3.2 Socket数据生成

**使用eBPF工具采集**:
```bash
# Client端采集
sudo python3 ebpf-tools/performance/system-network/tcp_connection_analyzer.py \
    --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
    --output test/data/socket/client_normal/

# Server端采集
sudo python3 ebpf-tools/performance/system-network/tcp_connection_analyzer.py \
    --src-ip 192.168.1.20 --dst-ip 192.168.1.10 \
    --output test/data/socket/server_normal/
```

### 3.3 测试数据验证

**数据集质量检查清单**:
- [ ] PCAP文件可被tshark正常解析
- [ ] 至少包含5个完整TCP流
- [ ] Socket数据包含所有必需字段
- [ ] Client和Server端连接五元组匹配
- [ ] 数据时间跨度 >= 10秒

---

## 4. Part 1: PCAP分析工具测试

### 4.1 特性3.1: Summary模式测试

#### 测试用例矩阵

| 用例ID | 需求ID | 测试场景 | 输入 | 预期输出 | 优先级 |
|--------|--------|---------|------|----------|--------|
| **TC-PCAP-SUM-001** | FR-PCAP-SUM-001 | 解析标准PCAP文件 | tcp_normal.pcap | 成功解析，无报错 | P0 |
| **TC-PCAP-SUM-002** | FR-PCAP-SUM-002 | L2/L3/L4协议统计 | mixed_protocols.pcap | 包含Ethernet/IP/TCP统计 | P0 |
| **TC-PCAP-SUM-003** | FR-PCAP-SUM-003 | 按五元组聚合流 | tcp_normal.pcap | 识别出N个独立流 | P0 |
| **TC-PCAP-SUM-004** | FR-PCAP-SUM-004 | 时间维度统计 | tcp_normal.pcap | pps, bps曲线 | P0 |
| **TC-PCAP-SUM-005** | FR-PCAP-SUM-005 | Top N发送方识别 | mixed_protocols.pcap | Top 10 IP列表 | P0 |
| **TC-PCAP-SUM-006** | FR-PCAP-SUM-006 | JSON格式输出 | tcp_normal.pcap | 有效JSON文件 | P0 |
| **TC-PCAP-SUM-007** | FR-PCAP-SUM-007 | 大文件进度显示 | large_file.pcap (>100MB) | 显示进度条 | P1 |

#### 详细测试用例

**TC-PCAP-SUM-001: 解析标准PCAP文件**

```python
def test_parse_standard_pcap():
    """测试解析标准PCAP文件"""
    parser = PcapParser()

    # 执行
    packets = list(parser.parse_file('test/data/pcap/tcp_normal.pcap',
                                     fields=['frame.number', 'ip.src', 'ip.dst']))

    # 验证
    assert len(packets) > 0, "应该解析出至少1个数据包"
    assert 'frame.number' in packets[0], "应包含frame.number字段"
    assert 'ip.src' in packets[0], "应包含ip.src字段"
```

**TC-PCAP-SUM-002: L2/L3/L4协议统计**

```python
def test_protocol_statistics():
    """测试协议统计"""
    parser = PcapParser()
    stats_engine = StatisticsEngine()

    packets = parser.parse_file('test/data/pcap/mixed_protocols.pcap', ...)

    # L2统计
    l2_stats = stats_engine.compute_l2_stats(packets)
    assert 'IPv4' in l2_stats.ethernet_types, "应识别IPv4"
    assert l2_stats.frame_size_distribution is not None

    # L3统计
    l3_stats = stats_engine.compute_l3_stats(packets)
    assert l3_stats.ipv4_count > 0

    # L4统计
    l4_stats = stats_engine.compute_l4_stats(packets)
    assert l4_stats.tcp_count > 0 or l4_stats.udp_count > 0
```

**TC-PCAP-SUM-006: JSON格式输出**

```python
def test_json_output():
    """测试JSON格式输出"""
    formatter = JSONFormatter()

    # 准备测试数据
    result = {
        'total_packets': 100,
        'duration': 10.5,
        'timestamp': datetime.now()
    }

    # 执行
    json_str = formatter.format(result)

    # 验证
    import json
    parsed = json.loads(json_str)  # 不应抛异常
    assert parsed['total_packets'] == 100
    assert 'timestamp' in parsed
```

---

### 4.2 特性3.2: Details模式(TCP)测试

#### 测试用例矩阵

| 用例ID | 需求ID | 测试场景 | 输入 | 预期输出 | 优先级 |
|--------|--------|---------|------|----------|--------|
| **TC-PCAP-DET-001** | FR-PCAP-DET-001 | IP地址过滤 | tcp_normal.pcap + src_ip | 仅包含指定src_ip的包 | P0 |
| **TC-PCAP-DET-002** | FR-PCAP-DET-002 | 端口过滤 | tcp_normal.pcap + dst_port=80 | 仅包含dst_port=80的包 | P0 |
| **TC-PCAP-DET-005** | FR-PCAP-DET-005 | TCP重传分析 | tcp_retrans.pcap | 重传率 > 0 | P0 |
| **TC-PCAP-DET-006** | FR-PCAP-DET-006 | DupACK分析 | tcp_retrans.pcap | DupACK统计 | P0 |
| **TC-PCAP-DET-007** | FR-PCAP-DET-007 | Zero Window分析 | tcp_zero_window.pcap | 检测到Zero Window事件 | P0 |
| **TC-PCAP-DET-008** | FR-PCAP-DET-008 | SACK/D-SACK分析 | tcp_sack.pcap | SACK统计 > 0 | P0 |
| **TC-PCAP-DET-009** | FR-PCAP-DET-009 | 协议特性协商 | tcp_normal.pcap | 识别Window Scaling等 | P0 |

#### 详细测试用例

**TC-PCAP-DET-005: TCP重传分析**

```python
def test_tcp_retransmission_analysis():
    """测试TCP重传分析"""
    parser = PcapParser()
    tcp_analyzer = TCPAnalyzer()

    # 解析含重传的PCAP
    packets = parser.parse_file('test/data/pcap/tcp_retrans.pcap', ...)
    tcp_flow = build_tcp_flow(packets)

    # 执行分析
    retrans_stats = tcp_analyzer.analyze_retransmissions(tcp_flow)

    # 验证
    assert retrans_stats.retrans_packets > 0, "应检测到重传"
    assert 0 < retrans_stats.retrans_rate < 1, "重传率应在0-1之间"
    assert retrans_stats.fast_retrans + retrans_stats.timeout_retrans == retrans_stats.retrans_packets
```

**TC-PCAP-DET-007: Zero Window分析**

```python
def test_zero_window_detection():
    """测试Zero Window检测"""
    tcp_analyzer = TCPAnalyzer()

    # 加载Zero Window场景
    tcp_flow = load_tcp_flow('test/data/pcap/tcp_zero_window.pcap')

    # 执行
    zw_stats = tcp_analyzer.analyze_zero_window(tcp_flow)

    # 验证
    assert zw_stats.zero_window_events > 0, "应检测到Zero Window事件"
    assert zw_stats.total_duration > 0, "应有持续时间"
    assert zw_stats.avg_duration > 0
```

---

### 4.3 特性3.3: Analysis模式测试

#### 测试用例矩阵

| 用例ID | 需求ID | 测试场景 | 输入 | 预期输出 | 优先级 |
|--------|--------|---------|------|----------|--------|
| **TC-PCAP-ANA-001** | FR-PCAP-ANA-001 | 高延迟检测 | high_latency.pcap | 识别HIGH_LATENCY问题 | P0 |
| **TC-PCAP-ANA-002** | FR-PCAP-ANA-002 | 丢包检测 | tcp_retrans.pcap | 识别PACKET_LOSS问题 | P0 |
| **TC-PCAP-ANA-007** | FR-PCAP-ANA-007 | 重传突发检测 | tcp_retrans.pcap | 检测到突发事件 | P0 |
| **TC-PCAP-ANA-008** | FR-PCAP-ANA-008 | 问题原因分析 | tcp_retrans.pcap | 提供可能原因列表 | P0 |
| **TC-PCAP-ANA-009** | FR-PCAP-ANA-009 | 解决建议生成 | tcp_retrans.pcap | 提供优化建议 | P0 |
| **TC-PCAP-ANA-010** | FR-PCAP-ANA-010 | 问题分类排序 | mixed_problems.pcap | 按严重程度排序 | P0 |

#### 详细测试用例

**TC-PCAP-ANA-002: 丢包检测**

```python
def test_packet_loss_detection():
    """测试丢包检测"""
    detector = ProblemDetector()

    tcp_flow = load_tcp_flow('test/data/pcap/tcp_retrans.pcap')

    # 执行
    problem = detector.detect_packet_loss(tcp_flow)

    # 验证
    assert problem is not None, "应检测到丢包问题"
    assert problem.type == 'PACKET_LOSS'
    assert problem.severity in ['HIGH', 'WARNING']
    assert 'retrans_rate' in problem.evidence
```

**TC-PCAP-ANA-008: 问题原因分析**

```python
def test_cause_analysis():
    """测试原因分析"""
    diagnosis_engine = DiagnosisEngine()

    # 准备问题
    problem = Problem(
        type='PACKET_LOSS',
        severity='HIGH',
        description='重传率5%',
        evidence={'retrans_rate': 0.05}
    )

    # 执行
    causes = diagnosis_engine.analyze_causes(problem, tcp_flow)

    # 验证
    assert len(causes) > 0, "应提供至少1个可能原因"
    assert all(0 <= c.confidence <= 1 for c in causes), "置信度应在0-1之间"
    assert all(len(c.evidence) > 0 for c in causes), "应有证据支持"
```

---

## 5. Part 2: TCP Socket分析工具测试

### 5.1 特性3.5: Summary模式测试

#### 测试用例矩阵

| 用例ID | 需求ID | 测试场景 | 输入 | 预期输出 | 优先级 |
|--------|--------|---------|------|----------|--------|
| **TC-SOCKET-SUM-001** | FR-SOCKET-SUM-001 | 解析双端数据 | client_normal/ + server_normal/ | 成功解析双端 | P0 |
| **TC-SOCKET-SUM-002** | FR-SOCKET-SUM-002 | 完整统计计算 | 任意Socket数据 | 包含Min/Max/Mean/P99 | P0 |
| **TC-SOCKET-SUM-003** | FR-SOCKET-SUM-003 | BDP和最优CWND | 正常数据 + 带宽参数 | BDP > 0, optimal_cwnd > 0 | P0 |
| **TC-SOCKET-SUM-004** | FR-SOCKET-SUM-004 | 带宽利用率 | 正常数据 + 带宽 | 0 < utilization < 1 | P0 |
| **TC-SOCKET-SUM-010** | FR-SOCKET-SUM-010 | 性能瓶颈识别 | cwnd_limited数据 | 识别CWND_LIMITED | P0 |
| **TC-SOCKET-SUM-011** | FR-SOCKET-SUM-011 | 配置建议 | cwnd_limited数据 | 提供CWND调优建议 | P0 |
| **TC-SOCKET-SUM-012** | FR-SOCKET-SUM-012 | 带宽参数解析 | "100mbps" | 100000000 bps | P0 |
| **TC-SOCKET-SUM-014** | FR-SOCKET-SUM-014 | 连接验证 | mismatched/ | 抛出ConnectionMismatchError | P0 |

#### 详细测试用例

**TC-SOCKET-SUM-001: 解析双端数据**

```python
def test_parse_dual_side_data():
    """测试双端数据解析"""
    parser = SocketDataParser()

    # 执行
    client_df, server_df, aligned_df = parser.parse_dual_directories(
        'test/data/socket/client_normal/',
        'test/data/socket/server_normal/'
    )

    # 验证
    assert len(client_df) > 0, "Client数据不应为空"
    assert len(server_df) > 0, "Server数据不应为空"
    assert len(aligned_df) > 0, "对齐数据不应为空"
    assert 'cwnd' in client_df.columns, "应包含cwnd字段"
    assert 'rtt' in client_df.columns, "应包含rtt字段"
```

**TC-SOCKET-SUM-003: BDP和最优CWND计算**

```python
def test_bdp_calculation():
    """测试BDP计算"""
    analyzer = SummaryAnalyzer(config)

    # 准备数据
    client_df = load_socket_data('test/data/socket/client_normal/')
    server_df = load_socket_data('test/data/socket/server_normal/')
    bandwidth = 1000000000  # 1Gbps

    # 执行
    window_result = analyzer.analyze_window(client_df, server_df, bandwidth)

    # 验证
    assert window_result.bdp > 0, "BDP应 > 0"
    assert window_result.optimal_cwnd > 0, "最优CWND应 > 0"
    assert window_result.bdp == bandwidth * window_result.client_rtt_stats.mean / 8
```

**TC-SOCKET-SUM-014: 连接验证**

```python
def test_connection_mismatch_detection():
    """测试连接不匹配检测"""
    parser = SocketDataParser()

    # 执行 - 应抛出异常
    with pytest.raises(ConnectionMismatchError) as exc_info:
        parser.parse_dual_directories(
            'test/data/socket/client_normal/',
            'test/data/socket/server_mismatched/'
        )

    # 验证异常信息
    assert 'Connection mismatch' in str(exc_info.value)
```

---

### 5.2 特性3.6: Detailed模式测试

#### 测试用例矩阵

| 用例ID | 需求ID | 测试场景 | 输入 | 预期输出 | 优先级 |
|--------|--------|---------|------|----------|--------|
| **TC-SOCKET-DET-001** | FR-SOCKET-DET-001 | 窗口限制时间占比 | cwnd_limited/ | cwnd_limited_ratio > 0.5 | P0 |
| **TC-SOCKET-DET-002** | FR-SOCKET-DET-002 | CWND变化模式识别 | 正常数据 | 识别慢启动/拥塞避免 | P0 |
| **TC-SOCKET-DET-003** | FR-SOCKET-DET-003 | 速率时序分析 | 正常数据 | pacing/delivery趋势 | P0 |
| **TC-SOCKET-DET-004** | FR-SOCKET-DET-004 | Rate限制类型识别 | pacing_limited/ | 识别Pacing限制 | P0 |
| **TC-SOCKET-DET-005** | FR-SOCKET-DET-005 | 重传突发事件 | retrans_burst/ | 检测到突发事件 | P0 |
| **TC-SOCKET-DET-009** | FR-SOCKET-DET-009 | 时序数据导出 | 正常数据 | 导出5类CSV文件 | P0 |
| **TC-SOCKET-DET-010** | FR-SOCKET-DET-010 | 指标相关性分析 | 正常数据 | 计算4种相关性 | P0 |

#### 详细测试用例

**TC-SOCKET-DET-001: 窗口限制时间占比**

```python
def test_window_limit_time_ratio():
    """测试窗口限制时间占比"""
    detailed_analyzer = DetailedAnalyzer(config)

    # 加载CWND受限数据
    client_df = load_socket_data('test/data/socket/client_cwnd_limited/')
    server_df = load_socket_data('test/data/socket/server_cwnd_limited/')

    # 执行
    window_detailed = detailed_analyzer.analyze_window_detailed(
        client_df, server_df, bandwidth=1e9
    )

    # 验证
    assert window_detailed.cwnd_limited_ratio > 0.5, "CWND限制时间应 > 50%"
    assert 0 <= window_detailed.rwnd_limited_ratio <= 1
    assert 0 <= window_detailed.sndbuf_limited_ratio <= 1
```

**TC-SOCKET-DET-009: 时序数据导出**

```python
def test_timeseries_export():
    """测试时序数据导出"""
    detailed_analyzer = DetailedAnalyzer(config)

    # 准备数据
    aligned_df = load_aligned_data('test/data/socket/aligned_normal.csv')

    # 执行
    timeseries_data = detailed_analyzer.export_timeseries(aligned_df)

    # 验证
    assert 'rtt' in timeseries_data, "应导出RTT时序"
    assert 'cwnd' in timeseries_data, "应导出CWND时序"
    assert 'rate' in timeseries_data, "应导出Rate时序"
    assert 'buffer' in timeseries_data, "应导出Buffer时序"
    assert 'retrans' in timeseries_data, "应导出Retrans时序"

    # 验证数据结构
    rtt_df = timeseries_data['rtt']
    assert 'timestamp' in rtt_df.columns
    assert 'rtt_client' in rtt_df.columns
```

---

### 5.3 特性3.7: Pipeline瓶颈分析测试

#### 测试用例矩阵

| 用例ID | 需求ID | 测试场景 | 输入 | 预期输出 | 优先级 |
|--------|--------|---------|------|----------|--------|
| **TC-SOCKET-PIPE-001** | FR-SOCKET-PIPE-001 | 发送路径瓶颈识别 | cwnd_limited/ | 识别CWND瓶颈 | P0 |
| **TC-SOCKET-PIPE-002** | FR-SOCKET-PIPE-002 | 接收路径瓶颈识别 | rx_buffer_limited/ | 识别RX Buffer瓶颈 | P0 |
| **TC-SOCKET-PIPE-003** | FR-SOCKET-PIPE-003 | 瓶颈压力值计算 | buffer_limited/ | utilization > 0.9 | P0 |
| **TC-SOCKET-PIPE-004** | FR-SOCKET-PIPE-004 | 主要瓶颈判断 | 多瓶颈数据 | 识别CRITICAL瓶颈 | P0 |
| **TC-SOCKET-PIPE-005** | FR-SOCKET-PIPE-005 | Pipeline健康度总览 | 正常数据 | health_score = 100 | P0 |
| **TC-SOCKET-PIPE-006** | FR-SOCKET-PIPE-006 | 瓶颈详细诊断 | cwnd_limited/ | 包含根因/影响/行动项 | P0 |
| **TC-SOCKET-PIPE-007** | FR-SOCKET-PIPE-007 | 优化优先级排序 | 多瓶颈 | CRITICAL在前 | P0 |
| **TC-SOCKET-PIPE-008** | FR-SOCKET-PIPE-008 | 整体评估和建议 | 多瓶颈 | 提供Top 3行动计划 | P0 |

#### 详细测试用例

**TC-SOCKET-PIPE-001: 发送路径瓶颈识别**

```python
def test_send_path_bottleneck_detection():
    """测试发送路径瓶颈识别"""
    bottleneck_finder = BottleneckFinder()

    # 加载CWND受限数据
    df = load_socket_data('test/data/socket/client_cwnd_limited/')

    # 执行
    bottlenecks = bottleneck_finder.find_send_path_bottlenecks(df)

    # 验证
    assert len(bottlenecks) > 0, "应检测到至少1个瓶颈"

    # 验证CWND瓶颈
    cwnd_bottleneck = next((b for b in bottlenecks if 'CWND' in b.point), None)
    assert cwnd_bottleneck is not None, "应检测到CWND瓶颈"
    assert cwnd_bottleneck.severity in ['CRITICAL', 'WARNING']
    assert cwnd_bottleneck.utilization > 0.7
```

**TC-SOCKET-PIPE-005: Pipeline健康度总览**

```python
def test_pipeline_health_overview():
    """测试Pipeline健康度总览"""
    reporter = PipelineReporter()

    # Case 1: 无瓶颈
    health = reporter.generate_health_overview([])
    assert health.overall_health == 'HEALTHY'
    assert health.health_score == 100

    # Case 2: 有WARNING
    bottlenecks = [
        Bottleneck(point='CWND', layer='TCP层', severity='WARNING', utilization=0.8, ...)
    ]
    health = reporter.generate_health_overview(bottlenecks)
    assert health.health_score == 90  # 100 - 10
    assert health.overall_health == 'HEALTHY'

    # Case 3: 有CRITICAL
    bottlenecks = [
        Bottleneck(point='CWND', layer='TCP层', severity='CRITICAL', utilization=0.95, ...)
    ]
    health = reporter.generate_health_overview(bottlenecks)
    assert health.health_score == 70  # 100 - 30
    assert health.overall_health == 'DEGRADED'
```

---

## 6. 性能测试

### 6.1 性能测试场景

| 场景ID | 测试目标 | 测试数据 | 性能指标 | 验收标准 |
|--------|---------|---------|---------|---------|
| **PERF-001** | PCAP文件解析速度 | 100MB PCAP | 处理时间 | < 30秒 |
| **PERF-002** | 大规模流聚合 | 10000条流 | 内存占用 | < 2GB |
| **PERF-003** | Socket数据处理 | 10000个采样点 | 处理时间 | < 5秒 |
| **PERF-004** | 并发分析能力 | 10个并发任务 | 吞吐量 | >= 8个/分钟 |

### 6.2 性能测试用例

**PERF-001: PCAP文件解析速度**

```python
def test_pcap_parsing_performance():
    """测试PCAP解析性能"""
    import time

    parser = PcapParser()

    start_time = time.time()
    packets = list(parser.parse_file('test/data/pcap/large_100mb.pcap', ...))
    elapsed = time.time() - start_time

    # 验收标准
    assert elapsed < 30, f"解析时间{elapsed:.1f}秒 超过30秒限制"

    # 性能报告
    print(f"性能指标: {len(packets)}个包 / {elapsed:.1f}秒 = {len(packets)/elapsed:.0f} pps")
```

### 6.3 内存测试

```python
def test_memory_usage():
    """测试内存占用"""
    import psutil
    import os

    process = psutil.Process(os.getpid())

    # 记录初始内存
    mem_before = process.memory_info().rss / 1024 / 1024  # MB

    # 执行大规模分析
    analyzer = PcapAnalyzer()
    analyzer.analyze('test/data/pcap/large_100mb.pcap', mode='summary')

    # 记录峰值内存
    mem_after = process.memory_info().rss / 1024 / 1024  # MB
    mem_increase = mem_after - mem_before

    # 验收标准
    assert mem_increase < 2048, f"内存增长{mem_increase:.0f}MB 超过2GB限制"
```

---

## 7. 验收标准

### 7.1 功能验收标准

#### 7.1.1 必须通过的测试 (P0)

**PCAP工具**:
- [ ] 所有TC-PCAP-SUM-* 测试通过
- [ ] 所有TC-PCAP-DET-* 测试通过
- [ ] 所有TC-PCAP-ANA-* 测试通过

**Socket工具**:
- [ ] 所有TC-SOCKET-SUM-* 测试通过
- [ ] 所有TC-SOCKET-DET-* 测试通过
- [ ] 所有TC-SOCKET-PIPE-* 测试通过

#### 7.1.2 功能完整性

| 功能模块 | 验收标准 |
|---------|---------|
| **PCAP Summary** | 7/7 需求通过 (100%) |
| **PCAP Details** | 12/12 需求通过 (100%) |
| **PCAP Analysis** | 10/10 需求通过 (100%) |
| **Socket Summary** | 14/14 需求通过 (100%) |
| **Socket Detailed** | 10/10 需求通过 (100%) |
| **Socket Pipeline** | 11/11 需求通过 (100%) |

#### 7.1.3 代码质量标准

- [ ] **代码覆盖率**: >= 80%
- [ ] **单元测试通过率**: 100%
- [ ] **集成测试通过率**: 100%
- [ ] **Pylint评分**: >= 8.0/10
- [ ] **无Critical安全漏洞** (Bandit扫描)

### 7.2 性能验收标准

| 性能指标 | 验收标准 |
|---------|---------|
| PCAP解析速度 (100MB) | < 30秒 |
| Socket分析速度 (10K点) | < 5秒 |
| 内存占用峰值 | < 2GB |
| 并发处理能力 | >= 8任务/分钟 |

### 7.3 兼容性验收标准

- [ ] **Python 3.8** 测试通过
- [ ] **Python 3.9** 测试通过
- [ ] **Python 3.10+** 测试通过
- [ ] **Linux (openEuler)** 测试通过
- [ ] **macOS** 测试通过 (开发环境)

### 7.4 文档验收标准

- [ ] **README.md** 完整且准确
- [ ] **API文档** 生成 (Sphinx/mkdocs)
- [ ] **用户手册** 包含所有功能
- [ ] **示例代码** 可运行且有效

---

## 8. 验收计划

### 8.1 验收阶段

```
阶段1: 单元测试验收 (Week 1-2)
├─ 开发人员自测
├─ Code Review
└─ 单元测试覆盖率检查

阶段2: 集成测试验收 (Week 3)
├─ 组件集成测试
├─ 端到端场景测试
└─ 性能测试

阶段3: 系统测试验收 (Week 4)
├─ 完整功能测试
├─ 兼容性测试
└─ 回归测试

阶段4: 用户验收测试 (Week 5)
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
   pytest tests/unit/ -v --cov=src --cov-report=html
   ```
2. 检查覆盖率报告
   ```bash
   open htmlcov/index.html
   ```
3. 修复失败测试直到100%通过

**退出条件**:
- [x] 所有单元测试通过
- [x] 代码覆盖率 >= 80%

---

#### 阶段2: 集成测试验收

**负责人**: 测试工程师
**时间**: Week 3
**准入条件**:
- 阶段1完成
- 所有组件开发完成

**执行步骤**:
1. 准备测试数据集
2. 运行集成测试套件
   ```bash
   pytest tests/integration/ -v --tb=short
   ```
3. 运行端到端测试
   ```bash
   pytest tests/e2e/ -v
   ```
4. 执行性能测试
   ```bash
   pytest tests/performance/ -v --benchmark-only
   ```

**退出条件**:
- [x] 所有集成测试通过
- [x] 性能测试达标
- [x] 无P0缺陷

---

#### 阶段3: 系统测试验收

**负责人**: QA团队
**时间**: Week 4
**准入条件**:
- 阶段2完成
- 文档齐全

**执行步骤**:
1. 搭建测试环境
2. 执行完整功能测试
3. 执行兼容性测试
   ```bash
   # Python 3.8
   pyenv local 3.8.x
   pytest tests/

   # Python 3.9
   pyenv local 3.9.x
   pytest tests/
   ```
4. 执行回归测试
5. 缺陷跟踪和修复

**退出条件**:
- [x] 所有测试用例执行完成
- [x] 无未关闭的P0/P1缺陷
- [x] 验收标准100%满足

---

#### 阶段4: 用户验收测试 (UAT)

**负责人**: 产品负责人 + 最终用户
**时间**: Week 5
**准入条件**:
- 阶段3完成
- 部署文档完整

**执行步骤**:
1. 在UAT环境部署
2. 用户试用和反馈收集
3. 执行真实场景验证
4. 问题修复和改进

**退出条件**:
- [x] 用户满意度 >= 4/5
- [x] 核心场景验证通过
- [x] 无阻塞性问题

---

### 8.3 验收报告模板

```markdown
# 验收报告 - [阶段X]

## 基本信息
- 测试执行人: XXX
- 测试日期: YYYY-MM-DD
- 测试环境: Python 3.x / Linux

## 测试结果总览
- 总用例数: XXX
- 通过数: XXX
- 失败数: XXX
- 跳过数: XXX
- 通过率: XX%

## 详细结果
### 功能测试
| 模块 | 用例数 | 通过 | 失败 | 通过率 |
|------|--------|------|------|--------|
| PCAP Summary | 7 | 7 | 0 | 100% |
| PCAP Details | 12 | 12 | 0 | 100% |
| ... | ... | ... | ... | ... |

### 性能测试
| 指标 | 标准 | 实际 | 结果 |
|------|------|------|------|
| PCAP解析速度 | <30s | 25s | ✓ |
| 内存占用 | <2GB | 1.5GB | ✓ |

### 缺陷统计
| 严重程度 | 数量 | 已修复 | 遗留 |
|---------|------|--------|------|
| P0 | 0 | 0 | 0 |
| P1 | 2 | 2 | 0 |
| P2 | 5 | 4 | 1 |

## 验收结论
[ ] 通过
[ ] 有条件通过 (遗留问题: XXX)
[ ] 不通过

## 签字
- 测试负责人: _________ 日期: _______
- 开发负责人: _________ 日期: _______
- 产品负责人: _________ 日期: _______
```

---

### 8.4 缺陷管理

**缺陷优先级定义**:

| 优先级 | 定义 | 处理时间 | 验收要求 |
|--------|------|---------|---------|
| **P0** | 核心功能无法使用/数据错误 | 24小时 | 必须修复 |
| **P1** | 重要功能受影响 | 3天 | 必须修复 |
| **P2** | 次要功能/体验问题 | 1周 | 可延后 |
| **P3** | 优化建议 | 下版本 | 可不修复 |

**缺陷跟踪流程**:
1. 发现缺陷 → 提交Issue
2. 评估优先级
3. 分配开发人员
4. 修复并提交PR
5. 回归测试验证
6. 关闭Issue

---

## 附录A: 测试命令速查表

```bash
# 运行所有测试
pytest tests/ -v

# 运行特定模块
pytest tests/unit/test_pcap_parser.py -v

# 生成覆盖率报告
pytest --cov=src --cov-report=html --cov-report=term

# 运行性能测试
pytest tests/performance/ --benchmark-only

# 运行兼容性测试
tox

# 代码质量检查
pylint src/
flake8 src/
mypy src/

# 安全扫描
bandit -r src/
```

---

## 附录B: 测试数据集清单

### PCAP文件

| 文件名 | 大小 | 包数 | 用途 | 状态 |
|--------|------|------|------|------|
| tcp_normal.pcap | 10MB | ~10K | 正常TCP流测试 | ✓ 已准备 |
| tcp_retrans.pcap | 15MB | ~12K | 重传分析测试 | ⏳ 待生成 |
| tcp_zero_window.pcap | 5MB | ~5K | Zero Window测试 | ⏳ 待生成 |
| tcp_sack.pcap | 8MB | ~8K | SACK/D-SACK测试 | ⏳ 待生成 |
| large_100mb.pcap | 100MB | ~100K | 性能测试 | ⏳ 待生成 |

### Socket数据目录

| 目录 | 文件数 | 用途 | 状态 |
|------|--------|------|------|
| client_normal/ | ~100 | 正常场景测试 | ⏳ 待采集 |
| server_normal/ | ~100 | 正常场景测试 | ⏳ 待采集 |
| client_cwnd_limited/ | ~100 | CWND受限测试 | ⏳ 待采集 |
| server_cwnd_limited/ | ~100 | CWND受限测试 | ⏳ 待采集 |

---

**文档结束**
