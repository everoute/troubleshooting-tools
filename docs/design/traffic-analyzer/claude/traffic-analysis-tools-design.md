# 网络流量分析工具设计文档 (SDD)

**Software Design Description**

**文档版本**: 2.0
**创建日期**: 2025-11-17
**状态**: Draft
**作者**: Claude Code
**项目**: Traffic Analyzer - 通用网络分析工具集

---

## 修订历史

| 版本 | 日期 | 作者 | 变更说明 |
|------|------|------|----------|
| 1.0 | 2025-11-17 | Claude | 初始版本 (两个工具混合) |
| 2.0 | 2025-11-17 | Claude | 重构为清晰区隔的两部分，增强需求追溯，补全Detailed模式设计 |

---

## 文档说明

本文档包含**两个独立工具**的完整设计：

**Part 1: PCAP分析工具** (`pcap_analyzer.py`)
- 从数据包层面分析网络行为和问题
- 特性：Summary模式、Details模式、Analysis模式、UDP/ICMP分析

**Part 2: TCP Socket分析工具** (`tcpsocket_analyzer.py`)
- 从内核Socket状态层面分析TCP性能瓶颈
- 特性：Summary模式、Detailed模式、Pipeline瓶颈分析

**文档结构**：每个工具包含独立的引言、需求追溯、概要设计(HLD)、详细设计(LLD)

---

## 目录

### Part 1: PCAP分析工具设计
1. [引言](#part-1-引言)
2. [需求追溯](#part-1-需求追溯)
3. [概要设计 (HLD)](#part-1-概要设计-hld)
4. [详细设计 (LLD)](#part-1-详细设计-lld)

### Part 2: TCP Socket分析工具设计
5. [引言](#part-2-引言)
6. [需求追溯](#part-2-需求追溯)
7. [概要设计 (HLD)](#part-2-概要设计-hld)
8. [详细设计 (LLD)](#part-2-详细设计-lld)

### 附录
9. [设计决策](#附录-设计决策)
10. [数据模型](#附录-数据模型)

---

# Part 1: PCAP分析工具设计

---

## Part 1: 引言

### 1.1 目的

本部分描述PCAP分析工具(`pcap_analyzer.py`)的软件设计，包括：
- 系统架构和组件设计
- 需求到设计的追溯关系
- 核心类、接口和算法的详细设计

**目标读者**：开发工程师、测试工程师、架构师

### 1.2 范围

PCAP分析工具用于离线分析已捕获的网络数据包，支持多层协议统计、TCP深度分析、智能问题识别。

### 1.3 参考文档

- **需求文档**: `docs/req/claude/traffic-analysis-requirements-v3.0.md` (第3.A节)
- **设计标准**: `docs/design/README.md` (IEEE 1016)
- **Wireshark文档**: tshark用户手册

---

## Part 1: 需求追溯

### 需求到特性映射

| 需求特性 | 需求文档章节 | 功能需求ID | 优先级 |
|---------|-------------|-----------|--------|
| **特性3.1**: Summary模式 | 3.1 | FR-PCAP-SUM-001~007 | P0 (高) |
| **特性3.2**: Details模式(TCP) | 3.2 | FR-PCAP-DET-001~012 | P0 (高) |
| **特性3.3**: Analysis模式 | 3.3 | FR-PCAP-ANA-001~010 | P1 (中) |
| **特性3.4**: UDP/ICMP分析 | 3.4 | FR-PCAP-UDP-001~005, FR-PCAP-ICMP-001~005 | P2 (低) |

### 功能需求追溯矩阵

#### 特性3.1: Summary模式

| 需求ID | 需求描述 | 设计组件 | 核心类/方法 | HLD章节 | LLD章节 |
|--------|---------|---------|-----------|---------|---------|
| FR-PCAP-SUM-001 | 解析标准pcap格式文件 | PcapParser | `PcapParser.parse_file()` | 1.3.1 | 1.4.1 |
| FR-PCAP-SUM-002 | 输出L2/L3/L4三层协议统计 | StatisticsEngine | `L2Stats`, `L3Stats`, `L4Stats` | 1.3.2 | 1.4.2 |
| FR-PCAP-SUM-003 | 按五元组聚合TCP/UDP流 | FlowAggregator | `FlowAggregator.aggregate_flows()` | 1.3.3 | 1.4.3 |
| FR-PCAP-SUM-004 | 计算时间维度统计(pps,bps) | TimeSeriesAnalyzer | `TimeSeriesAnalyzer.compute_rates()` | 1.3.4 | 1.4.4 |
| FR-PCAP-SUM-005 | 识别Top N发送/接收方IP | TopTalkersAnalyzer | `TopTalkersAnalyzer.identify_top_talkers()` | 1.3.5 | 1.4.5 |
| FR-PCAP-SUM-006 | 支持JSON格式输出 | JSONFormatter | `JSONFormatter.format()` | 1.3.6 | 1.4.6 |
| FR-PCAP-SUM-007 | 处理大文件时显示进度 | ProgressTracker | `ProgressTracker.update()` | 1.3.7 | 1.4.7 |

#### 特性3.2: Details模式(TCP)

| 需求ID | 需求描述 | 设计组件 | 核心类/方法 | HLD章节 | LLD章节 |
|--------|---------|---------|-----------|---------|---------|
| FR-PCAP-DET-001~004 | 支持各种过滤条件 | FilterEngine | `FilterEngine.apply_*_filter()` | 1.3.8 | 1.4.8 |
| FR-PCAP-DET-005 | 分析TCP重传 | TCPAnalyzer | `TCPAnalyzer.analyze_retransmissions()` | 1.3.9 | 1.4.9 |
| FR-PCAP-DET-006 | 分析DupACK | TCPAnalyzer | `TCPAnalyzer.analyze_dupack()` | 1.3.9 | 1.4.10 |
| FR-PCAP-DET-007 | 分析Zero Window事件 | TCPAnalyzer | `TCPAnalyzer.analyze_zero_window()` | 1.3.9 | 1.4.11 |
| FR-PCAP-DET-008 | 分析SACK和D-SACK | TCPAnalyzer | `TCPAnalyzer.analyze_sack()` | 1.3.9 | 1.4.12 |
| FR-PCAP-DET-009 | 统计协议特性协商结果 | TCPAnalyzer | `TCPAnalyzer.analyze_features()` | 1.3.9 | 1.4.13 |
| FR-PCAP-DET-011 | 检测重传突发事件 | ProblemDetector | `ProblemDetector.detect_retrans_burst()` | 1.3.10 | 1.4.14 |

#### 特性3.3: Analysis模式

| 需求ID | 需求描述 | 设计组件 | 核心类/方法 | HLD章节 | LLD章节 |
|--------|---------|---------|-----------|---------|---------|
| FR-PCAP-ANA-001~007 | 识别7类网络问题 | ProblemDetector | `ProblemDetector.detect_*()` | 1.3.10 | 1.4.15 |
| FR-PCAP-ANA-008 | 提供问题的可能原因分析 | DiagnosisEngine | `DiagnosisEngine.analyze_causes()` | 1.3.11 | 1.4.16 |
| FR-PCAP-ANA-009 | 提供解决建议 | DiagnosisEngine | `DiagnosisEngine.generate_recommendations()` | 1.3.11 | 1.4.17 |
| FR-PCAP-ANA-010 | 按严重程度对问题分类 | ProblemClassifier | `ProblemClassifier.classify()` | 1.3.12 | 1.4.18 |

---

## Part 1: 概要设计 (HLD)

### 1.1 系统上下文

```
┌─────────────────────────────────────────────────────────┐
│               外部数据采集工具                           │
│  tcpdump / tshark / Wireshark                           │
└──────────────────┬──────────────────────────────────────┘
                   │ .pcap files
                   ▼
┌─────────────────────────────────────────────────────────┐
│          PCAP分析工具 (本系统)                           │
│  pcap_analyzer.py                                       │
│  - 输入: PCAP文件                                       │
│  - 引擎: tshark                                         │
│  - 输出: 协议分析报告 (text/json)                       │
└──────────────────┬──────────────────────────────────────┘
                   │ 分析报告
                   ▼
┌─────────────────────────────────────────────────────────┐
│                用户/下游系统                             │
│  - 网络工程师 (故障排查)                                │
│  - 性能分析师 (优化调优)                                │
└─────────────────────────────────────────────────────────┘
```

### 1.2 架构设计

**架构风格**: 管道-过滤器 + 分层架构

**整体架构图**:

```
┌─────────────────────────────────────────────────────────┐
│            PCAP Analyzer Architecture                   │
└─────────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┴─────────────────┐
        ▼                                   ▼
┌──────────────────┐             ┌──────────────────┐
│  CLI Interface   │             │  Reporters       │
│  (Layer 4)       │             │  (Layer 4)       │
└────────┬─────────┘             └──────────────────┘
         │                                 ▲
         ▼                                 │
┌──────────────────┐             ┌──────────────────┐
│  Filter Engine   │             │  Statistics      │
│  (Layer 3)       │────────────>│  Engine          │
└────────┬─────────┘             │  (Layer 2)       │
         │                       └────────┬─────────┘
         ▼                                │
┌──────────────────┐                     │
│  Analyzers       │─────────────────────┘
│  (Layer 3)       │
│  - TCP Analyzer  │
│  - Problem Det.  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  PCAP Parser     │
│  (Layer 1)       │
└──────────────────┘
```

### 1.3 组件设计

#### 1.3.1 PcapParser

**职责**: 使用tshark解析PCAP文件，提取数据包信息

**对外接口**:
```python
class PcapParser:
    def parse_file(self, pcap_path: str, fields: List[str],
                   filters: Optional[str] = None) -> Iterator[Packet]
    def get_file_info(self, pcap_path: str) -> FileInfo
```

**实现需求**: FR-PCAP-SUM-001

#### 1.3.2 StatisticsEngine

**职责**: 计算L2/L3/L4层统计信息

**对外接口**:
```python
class StatisticsEngine:
    def compute_l2_stats(self, packets: Iterator[Packet]) -> L2Stats
    def compute_l3_stats(self, packets: Iterator[Packet]) -> L3Stats
    def compute_l4_stats(self, packets: Iterator[Packet]) -> L4Stats
```

**实现需求**: FR-PCAP-SUM-002

#### 1.3.3 FlowAggregator

**职责**: 按五元组聚合TCP/UDP流

**对外接口**:
```python
class FlowAggregator:
    def aggregate_flows(self, packets: Iterator[Packet]) -> Dict[FiveTuple, Flow]
    def get_flow_statistics(self, flow: Flow) -> FlowStats
```

**实现需求**: FR-PCAP-SUM-003

#### 1.3.4 TimeSeriesAnalyzer

**职责**: 计算时间维度统计（pps, bps）

**对外接口**:
```python
class TimeSeriesAnalyzer:
    def compute_rates(self, packets: Iterator[Packet],
                     interval: float = 1.0) -> TimeSeriesStats
    def get_pps(self, time_window: Tuple[datetime, datetime]) -> float
    def get_bps(self, time_window: Tuple[datetime, datetime]) -> float
```

**实现需求**: FR-PCAP-SUM-004

#### 1.3.5 TopTalkersAnalyzer

**职责**: 识别Top N发送/接收方IP

**对外接口**:
```python
class TopTalkersAnalyzer:
    def identify_top_talkers(self, flows: Dict[FiveTuple, Flow],
                            n: int = 10) -> TopTalkersResult
    def get_top_senders(self, n: int = 10) -> List[Tuple[str, int]]
    def get_top_receivers(self, n: int = 10) -> List[Tuple[str, int]]
```

**实现需求**: FR-PCAP-SUM-005

#### 1.3.6 JSONFormatter

**职责**: JSON格式输出

**对外接口**:
```python
class JSONFormatter:
    def format(self, analysis_result: Any) -> str
    def write_to_file(self, analysis_result: Any, output_path: str) -> None
```

**实现需求**: FR-PCAP-SUM-006

#### 1.3.7 ProgressTracker

**职责**: 进度跟踪和显示

**对外接口**:
```python
class ProgressTracker:
    def update(self, current: int, total: int, message: str = "") -> None
    def finish(self) -> None
    def set_total(self, total: int) -> None
```

**实现需求**: FR-PCAP-SUM-007

#### 1.3.8 FilterEngine

**职责**: 数据包过滤

**对外接口**:
```python
class FilterEngine:
    def apply_ip_filter(self, packets: Iterator[Packet],
                       src_ip: Optional[str], dst_ip: Optional[str]) -> Iterator[Packet]
    def apply_port_filter(self, packets: Iterator[Packet],
                         src_port: Optional[int], dst_port: Optional[int]) -> Iterator[Packet]
    def apply_protocol_filter(self, packets: Iterator[Packet],
                             protocol: str) -> Iterator[Packet]
    def apply_time_filter(self, packets: Iterator[Packet],
                         start_time: datetime, end_time: datetime) -> Iterator[Packet]
```

**实现需求**: FR-PCAP-DET-001~004, FR-PCAP-DET-010

#### 1.3.9 TCPAnalyzer

**职责**: TCP深度分析（重传、窗口、SACK等）

**对外接口**:
```python
class TCPAnalyzer:
    def analyze_retransmissions(self, tcp_flow: TCPFlow) -> RetransStats
    def analyze_dupack(self, tcp_flow: TCPFlow) -> DupACKStats
    def analyze_zero_window(self, tcp_flow: TCPFlow) -> ZeroWindowStats
    def analyze_sack(self, tcp_flow: TCPFlow) -> SACKStats
    def analyze_features(self, tcp_flow: TCPFlow) -> TCPFeatures
```

**实现需求**: FR-PCAP-DET-005~009

#### 1.3.10 ProblemDetector

**职责**: 智能问题识别

**对外接口**:
```python
class ProblemDetector:
    def detect_retrans_burst(self, tcp_flow: TCPFlow) -> List[BurstEvent]
    def detect_high_latency(self, tcp_flow: TCPFlow) -> Optional[Problem]
    def detect_packet_loss(self, tcp_flow: TCPFlow) -> Optional[Problem]
    def detect_out_of_order(self, tcp_flow: TCPFlow) -> Optional[Problem]
    def detect_window_issues(self, tcp_flow: TCPFlow) -> Optional[Problem]
    def detect_handshake_failures(self, flows: List[TCPFlow]) -> List[Problem]
    def detect_connection_resets(self, flows: List[TCPFlow]) -> List[Problem]
    def detect_all(self, tcp_flow: TCPFlow) -> List[Problem]
```

**实现需求**: FR-PCAP-ANA-001~007, FR-PCAP-DET-011~012

#### 1.3.11 DiagnosisEngine

**职责**: 问题诊断和建议生成

**对外接口**:
```python
class DiagnosisEngine:
    def analyze_causes(self, problem: Problem,
                      tcp_flow: TCPFlow) -> List[PossibleCause]
    def generate_recommendations(self, problem: Problem,
                                causes: List[PossibleCause]) -> List[Recommendation]
```

**实现需求**: FR-PCAP-ANA-008~009

#### 1.3.12 ProblemClassifier

**职责**: 问题分类和优先级排序

**对外接口**:
```python
class ProblemClassifier:
    def classify(self, problem: Problem) -> ProblemClass
    def rank_by_severity(self, problems: List[Problem]) -> List[Problem]
    def categorize(self, problems: List[Problem]) -> Dict[str, List[Problem]]
```

**实现需求**: FR-PCAP-ANA-010

---

## Part 1: 详细设计 (LLD)

### 1.4.1 PcapParser类

**实现需求**: FR-PCAP-SUM-001

```python
class PcapParser:
    """PCAP文件解析器 - 使用tshark作为后端"""

    def __init__(self, tshark_path: str = 'tshark'):
        self.tshark_path = tshark_path
        self._validate_tshark()

    def parse_file(self,
                   pcap_path: str,
                   fields: List[str],
                   filters: Optional[str] = None) -> Iterator[Dict]:
        """
        解析PCAP文件，返回数据包迭代器（流式处理）

        设计要点:
        - 使用tshark的JSON输出模式（-T json）
        - 流式解析避免内存溢出
        - 支持显示过滤器（-Y参数）
        """
        cmd = [
            self.tshark_path,
            '-r', pcap_path,
            '-T', 'json',
            '-e', *fields,
        ]

        if filters:
            cmd.extend(['-Y', filters])

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

        # 流式解析JSON
        buffer = ""
        for line in proc.stdout:
            buffer += line
            if line.strip().endswith('},') or line.strip().endswith('}'):
                try:
                    packet_json = buffer.strip().rstrip(',')
                    if packet_json:
                        packet = json.loads(packet_json)
                        yield self._normalize_packet(packet)
                    buffer = ""
                except json.JSONDecodeError:
                    continue
```

**关键设计点**:
- **流式处理**: 避免加载整个文件到内存
- **tshark封装**: 利用tshark的强大解析能力
- **错误处理**: 检测tshark可用性、文件有效性

---

### 1.4.2 StatisticsEngine类

**实现需求**: FR-PCAP-SUM-002

```python
@dataclass
class L2Stats:
    ethernet_types: Dict[str, int]
    frame_size_distribution: Dict[str, int]

class StatisticsEngine:
    def compute_l2_stats(self, packets: Iterator[Packet]) -> L2Stats:
        """
        计算L2层统计

        统计内容:
        1. 以太网类型分布 (IPv4/IPv6/ARP/...)
        2. 帧大小分布 (<64, 64-127, 128-255, ...)

        算法: 单次遍历，使用Counter计数
        """
        ethernet_types = Counter()
        frame_sizes = Counter()

        for packet in packets:
            eth_type = packet.get('eth.type')
            ethernet_types[eth_type] += 1

            frame_len = packet.get('frame.len', 0)
            size_range = self._get_size_range(frame_len)
            frame_sizes[size_range] += 1

        return L2Stats(
            ethernet_types=dict(ethernet_types),
            frame_size_distribution=dict(frame_sizes)
        )
```

---

### 1.4.3 FlowAggregator类

**实现需求**: FR-PCAP-SUM-003

```python
@dataclass
class FiveTuple:
    """TCP/UDP五元组"""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str

@dataclass
class Flow:
    """流统计"""
    five_tuple: FiveTuple
    packets: List[Packet]
    total_bytes: int
    start_time: datetime
    end_time: datetime

@dataclass
class FlowStats:
    """流统计结果"""
    packet_count: int
    byte_count: int
    duration: float  # 秒
    avg_packet_size: float
    pps: float
    bps: float

class FlowAggregator:
    """按五元组聚合TCP/UDP流"""

    def aggregate_flows(self, packets: Iterator[Packet]) -> Dict[FiveTuple, Flow]:
        """
        按五元组聚合流

        算法:
        1. 遍历数据包
        2. 提取五元组
        3. 归类到对应流
        """
        flows = defaultdict(lambda: Flow(
            five_tuple=None,
            packets=[],
            total_bytes=0,
            start_time=None,
            end_time=None
        ))

        for packet in packets:
            # 提取五元组
            ft = FiveTuple(
                src_ip=packet.get('ip.src'),
                src_port=packet.get('tcp.srcport', packet.get('udp.srcport')),
                dst_ip=packet.get('ip.dst'),
                dst_port=packet.get('tcp.dstport', packet.get('udp.dstport')),
                protocol=packet.get('_ws.col.Protocol')
            )

            flow = flows[ft]
            flow.five_tuple = ft
            flow.packets.append(packet)
            flow.total_bytes += packet.get('frame.len', 0)

            # 更新时间范围
            packet_time = packet.get('timestamp')
            if not flow.start_time:
                flow.start_time = packet_time
            flow.end_time = packet_time

        return dict(flows)

    def get_flow_statistics(self, flow: Flow) -> FlowStats:
        """
        计算流统计信息
        """
        duration = (flow.end_time - flow.start_time).total_seconds()
        packet_count = len(flow.packets)

        return FlowStats(
            packet_count=packet_count,
            byte_count=flow.total_bytes,
            duration=duration,
            avg_packet_size=flow.total_bytes / packet_count if packet_count > 0 else 0,
            pps=packet_count / duration if duration > 0 else 0,
            bps=(flow.total_bytes * 8) / duration if duration > 0 else 0
        )
```

---

### 1.4.4 TimeSeriesAnalyzer类

**实现需求**: FR-PCAP-SUM-004

```python
@dataclass
class TimeSeriesStats:
    """时序统计结果"""
    interval: float  # 秒
    timestamps: List[datetime]
    pps_series: List[float]
    bps_series: List[float]
    avg_pps: float
    peak_pps: float
    avg_bps: float
    peak_bps: float

class TimeSeriesAnalyzer:
    """时间维度统计分析器"""

    def compute_rates(self,
                     packets: Iterator[Packet],
                     interval: float = 1.0) -> TimeSeriesStats:
        """
        计算时间维度统计（pps, bps）

        算法:
        1. 按时间间隔分桶
        2. 计算每个时间桶的pps和bps
        3. 计算平均值和峰值
        """
        time_buckets = defaultdict(lambda: {'count': 0, 'bytes': 0})

        for packet in packets:
            timestamp = packet.get('timestamp')
            bucket_key = self._get_bucket_key(timestamp, interval)

            time_buckets[bucket_key]['count'] += 1
            time_buckets[bucket_key]['bytes'] += packet.get('frame.len', 0)

        # 生成时序数据
        sorted_buckets = sorted(time_buckets.items())
        timestamps = [bucket[0] for bucket in sorted_buckets]
        pps_series = [bucket[1]['count'] / interval for bucket in sorted_buckets]
        bps_series = [bucket[1]['bytes'] * 8 / interval for bucket in sorted_buckets]

        return TimeSeriesStats(
            interval=interval,
            timestamps=timestamps,
            pps_series=pps_series,
            bps_series=bps_series,
            avg_pps=sum(pps_series) / len(pps_series) if pps_series else 0,
            peak_pps=max(pps_series) if pps_series else 0,
            avg_bps=sum(bps_series) / len(bps_series) if bps_series else 0,
            peak_bps=max(bps_series) if bps_series else 0
        )

    def _get_bucket_key(self, timestamp: datetime, interval: float) -> datetime:
        """将时间戳归类到时间桶"""
        epoch = timestamp.timestamp()
        bucket_epoch = (epoch // interval) * interval
        return datetime.fromtimestamp(bucket_epoch)
```

---

### 1.4.5 TopTalkersAnalyzer类

**实现需求**: FR-PCAP-SUM-005

```python
@dataclass
class TopTalkersResult:
    """Top Talkers分析结果"""
    top_senders: List[Tuple[str, int]]  # (IP, bytes)
    top_receivers: List[Tuple[str, int]]
    top_conversations: List[Tuple[str, str, int]]  # (src_ip, dst_ip, bytes)

class TopTalkersAnalyzer:
    """Top Talkers识别器"""

    def identify_top_talkers(self,
                            flows: Dict[FiveTuple, Flow],
                            n: int = 10) -> TopTalkersResult:
        """
        识别Top N发送/接收方IP

        算法:
        1. 统计每个IP的发送/接收字节数
        2. 按字节数排序
        3. 返回Top N
        """
        sender_stats = defaultdict(int)
        receiver_stats = defaultdict(int)
        conversation_stats = defaultdict(int)

        for ft, flow in flows.items():
            # 发送方统计
            sender_stats[ft.src_ip] += flow.total_bytes
            # 接收方统计
            receiver_stats[ft.dst_ip] += flow.total_bytes
            # 对话统计
            conversation_stats[(ft.src_ip, ft.dst_ip)] += flow.total_bytes

        top_senders = sorted(sender_stats.items(), key=lambda x: x[1], reverse=True)[:n]
        top_receivers = sorted(receiver_stats.items(), key=lambda x: x[1], reverse=True)[:n]
        top_conversations = [
            (src, dst, bytes_)
            for (src, dst), bytes_ in sorted(
                conversation_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )[:n]
        ]

        return TopTalkersResult(
            top_senders=top_senders,
            top_receivers=top_receivers,
            top_conversations=top_conversations
        )
```

---

### 1.4.6 JSONFormatter类

**实现需求**: FR-PCAP-SUM-006

```python
class JSONFormatter:
    """JSON格式输出器"""

    def format(self, analysis_result: Any) -> str:
        """
        将分析结果转换为JSON字符串

        处理:
        1. dataclass转字典
        2. datetime转ISO格式字符串
        3. JSON序列化
        """
        def default_serializer(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return asdict(obj)
            elif isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, Enum):
                return obj.value
            else:
                return str(obj)

        return json.dumps(
            analysis_result,
            default=default_serializer,
            indent=2,
            ensure_ascii=False
        )

    def write_to_file(self, analysis_result: Any, output_path: str) -> None:
        """写入JSON文件"""
        json_str = self.format(analysis_result)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(json_str)
```

---

### 1.4.7 ProgressTracker类

**实现需求**: FR-PCAP-SUM-007

```python
class ProgressTracker:
    """进度跟踪器"""

    def __init__(self):
        self.total = 0
        self.current = 0
        self.start_time = None

    def set_total(self, total: int) -> None:
        """设置总数"""
        self.total = total
        self.start_time = datetime.now()

    def update(self, current: int, total: int = None, message: str = "") -> None:
        """
        更新进度

        显示:
        [################------------] 55% | 1234/2000 | ETA: 00:23 | Parsing...
        """
        if total:
            self.total = total
        self.current = current

        percentage = (current / self.total * 100) if self.total > 0 else 0

        # 计算ETA
        if self.start_time:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            eta = (elapsed / current * (self.total - current)) if current > 0 else 0
        else:
            eta = 0

        # 进度条
        bar_length = 40
        filled_length = int(bar_length * current // self.total) if self.total > 0 else 0
        bar = '#' * filled_length + '-' * (bar_length - filled_length)

        print(f'\r[{bar}] {percentage:.0f}% | {current}/{self.total} | '
              f'ETA: {int(eta//60):02d}:{int(eta%60):02d} | {message}',
              end='', flush=True)

    def finish(self) -> None:
        """完成进度"""
        print()  # 换行
```

---

### 1.4.8 FilterEngine类

**实现需求**: FR-PCAP-DET-001~004, FR-PCAP-DET-010

```python
class FilterEngine:
    """数据包过滤引擎"""

    def apply_ip_filter(self,
                       packets: Iterator[Packet],
                       src_ip: Optional[str],
                       dst_ip: Optional[str]) -> Iterator[Packet]:
        """IP地址过滤"""
        for packet in packets:
            if src_ip and packet.get('ip.src') != src_ip:
                continue
            if dst_ip and packet.get('ip.dst') != dst_ip:
                continue
            yield packet

    def apply_port_filter(self,
                         packets: Iterator[Packet],
                         src_port: Optional[int],
                         dst_port: Optional[int]) -> Iterator[Packet]:
        """端口过滤"""
        for packet in packets:
            actual_src_port = packet.get('tcp.srcport', packet.get('udp.srcport'))
            actual_dst_port = packet.get('tcp.dstport', packet.get('udp.dstport'))

            if src_port and actual_src_port != src_port:
                continue
            if dst_port and actual_dst_port != dst_port:
                continue
            yield packet

    def apply_protocol_filter(self,
                             packets: Iterator[Packet],
                             protocol: str) -> Iterator[Packet]:
        """协议过滤"""
        for packet in packets:
            if packet.get('_ws.col.Protocol').lower() == protocol.lower():
                yield packet

    def apply_time_filter(self,
                         packets: Iterator[Packet],
                         start_time: datetime,
                         end_time: datetime) -> Iterator[Packet]:
        """时间范围过滤"""
        for packet in packets:
            packet_time = packet.get('timestamp')
            if start_time <= packet_time <= end_time:
                yield packet
```

---

### 1.4.9 TCPAnalyzer - 重传分析

**实现需求**: FR-PCAP-DET-005

```python
class TCPAnalyzer:
    def analyze_retransmissions(self, tcp_flow: TCPFlow) -> RetransStats:
        """
        分析TCP重传

        算法:
        1. 遍历数据包，检查tcp.analysis.retransmission标志
        2. 区分快速重传 vs 超时重传:
           - 快速重传: 重传前收到3个DupACK
           - 超时重传: 重传前无DupACK
        3. 检测虚假重传（D-SACK）
        """
        total_packets = len(tcp_flow.packets)
        retrans_packets = []
        fast_retrans = []
        timeout_retrans = []
        spurious_retrans = []

        for i, packet in enumerate(tcp_flow.packets):
            if packet.get('tcp.analysis.retransmission'):
                retrans_packets.append(packet)

                if self._is_fast_retransmission(tcp_flow.packets, i):
                    fast_retrans.append(packet)
                else:
                    timeout_retrans.append(packet)

            if packet.get('tcp.options.sack.dsack'):
                spurious_retrans.append(packet)

        return RetransStats(
            total_packets=total_packets,
            retrans_packets=len(retrans_packets),
            retrans_rate=len(retrans_packets) / total_packets,
            fast_retrans=len(fast_retrans),
            timeout_retrans=len(timeout_retrans),
            spurious_retrans=len(spurious_retrans)
        )
```

---

### 1.4.10 TCPAnalyzer - DupACK分析

**实现需求**: FR-PCAP-DET-006

```python
@dataclass
class DupACKStats:
    """DupACK统计"""
    total_dupack: int
    dupack_rate: float
    max_consecutive_dupack: int
    avg_dupack_per_flow: float

class TCPAnalyzer:
    def analyze_dupack(self, tcp_flow: TCPFlow) -> DupACKStats:
        """
        分析Duplicate ACK

        算法:
        1. 检测tcp.analysis.duplicate_ack标志
        2. 统计连续DupACK最大值
        """
        dupack_count = 0
        current_consecutive = 0
        max_consecutive = 0

        for packet in tcp_flow.packets:
            if packet.get('tcp.analysis.duplicate_ack'):
                dupack_count += 1
                current_consecutive += 1
                max_consecutive = max(max_consecutive, current_consecutive)
            else:
                current_consecutive = 0

        return DupACKStats(
            total_dupack=dupack_count,
            dupack_rate=dupack_count / len(tcp_flow.packets),
            max_consecutive_dupack=max_consecutive,
            avg_dupack_per_flow=dupack_count
        )
```

---

### 1.4.11 TCPAnalyzer - Zero Window分析

**实现需求**: FR-PCAP-DET-007

```python
@dataclass
class ZeroWindowStats:
    """Zero Window统计"""
    zero_window_events: int
    total_duration: float  # 秒
    avg_duration: float
    max_duration: float

class TCPAnalyzer:
    def analyze_zero_window(self, tcp_flow: TCPFlow) -> ZeroWindowStats:
        """
        分析Zero Window事件

        算法:
        1. 检测tcp.analysis.zero_window标志
        2. 计算Zero Window持续时间
        """
        zero_window_events = []
        in_zero_window = False
        event_start = None

        for packet in tcp_flow.packets:
            if packet.get('tcp.analysis.zero_window'):
                if not in_zero_window:
                    in_zero_window = True
                    event_start = packet.get('timestamp')
            else:
                if in_zero_window:
                    event_end = packet.get('timestamp')
                    duration = (event_end - event_start).total_seconds()
                    zero_window_events.append(duration)
                    in_zero_window = False

        total_duration = sum(zero_window_events)
        event_count = len(zero_window_events)

        return ZeroWindowStats(
            zero_window_events=event_count,
            total_duration=total_duration,
            avg_duration=total_duration / event_count if event_count > 0 else 0,
            max_duration=max(zero_window_events) if zero_window_events else 0
        )
```

---

### 1.4.12 TCPAnalyzer - SACK分析

**实现需求**: FR-PCAP-DET-008

```python
@dataclass
class SACKStats:
    """SACK统计"""
    sack_enabled: bool
    sack_packets: int
    dsack_packets: int
    avg_sack_blocks: float

class TCPAnalyzer:
    def analyze_sack(self, tcp_flow: TCPFlow) -> SACKStats:
        """
        分析SACK和D-SACK

        算法:
        1. 检测tcp.options.sack字段
        2. 检测tcp.options.sack.dsack字段
        3. 统计SACK块数量
        """
        sack_enabled = False
        sack_packets = 0
        dsack_packets = 0
        total_sack_blocks = 0

        for packet in tcp_flow.packets:
            if packet.get('tcp.options.sack'):
                sack_enabled = True
                sack_packets += 1
                # 统计SACK块数量
                sack_blocks = packet.get('tcp.options.sack.count', 0)
                total_sack_blocks += sack_blocks

            if packet.get('tcp.options.sack.dsack'):
                dsack_packets += 1

        return SACKStats(
            sack_enabled=sack_enabled,
            sack_packets=sack_packets,
            dsack_packets=dsack_packets,
            avg_sack_blocks=total_sack_blocks / sack_packets if sack_packets > 0 else 0
        )
```

---

### 1.4.13 TCPAnalyzer - 特性协商分析

**实现需求**: FR-PCAP-DET-009

```python
@dataclass
class TCPFeatures:
    """TCP特性"""
    window_scaling: bool
    window_scale_factor: int
    timestamps: bool
    sack_permitted: bool
    mss: int

class TCPAnalyzer:
    def analyze_features(self, tcp_flow: TCPFlow) -> TCPFeatures:
        """
        统计协议特性协商结果

        算法:
        从SYN包中提取TCP选项
        """
        syn_packet = None
        for packet in tcp_flow.packets:
            if packet.get('tcp.flags.syn') and not packet.get('tcp.flags.ack'):
                syn_packet = packet
                break

        if not syn_packet:
            return TCPFeatures(False, 0, False, False, 1460)

        return TCPFeatures(
            window_scaling=bool(syn_packet.get('tcp.options.wscale')),
            window_scale_factor=syn_packet.get('tcp.options.wscale.shift', 0),
            timestamps=bool(syn_packet.get('tcp.options.timestamp')),
            sack_permitted=bool(syn_packet.get('tcp.options.sack_perm')),
            mss=syn_packet.get('tcp.options.mss_val', 1460)
        )
```

---

### 1.4.14 ProblemDetector - 重传突发检测

**实现需求**: FR-PCAP-DET-011

```python
@dataclass
class BurstEvent:
    """突发事件"""
    start_time: datetime
    end_time: datetime
    packet_count: int
    severity: str  # LOW/MEDIUM/HIGH

class ProblemDetector:
    def detect_retrans_burst(self, tcp_flow: TCPFlow) -> List[BurstEvent]:
        """
        检测重传突发事件

        算法:
        1. 滑动窗口检测(时间窗口1秒)
        2. 窗口内重传>5次为突发
        """
        burst_events = []
        window_size = 1.0  # 1秒
        threshold = 5  # 5次重传

        retrans_packets = [
            p for p in tcp_flow.packets
            if p.get('tcp.analysis.retransmission')
        ]

        i = 0
        while i < len(retrans_packets):
            window_start = retrans_packets[i].get('timestamp')
            window_end = window_start + timedelta(seconds=window_size)

            # 统计窗口内重传
            count = 0
            j = i
            while j < len(retrans_packets) and retrans_packets[j].get('timestamp') < window_end:
                count += 1
                j += 1

            if count >= threshold:
                severity = 'HIGH' if count > 10 else 'MEDIUM'
                burst_events.append(BurstEvent(
                    start_time=window_start,
                    end_time=retrans_packets[j-1].get('timestamp'),
                    packet_count=count,
                    severity=severity
                ))
                i = j
            else:
                i += 1

        return burst_events
```

---

### 1.4.15 ProblemDetector - 7类问题识别

**实现需求**: FR-PCAP-ANA-001~007

```python
@dataclass
class Problem:
    """网络问题"""
    type: str
    severity: str
    description: str
    evidence: Dict[str, Any]

class ProblemDetector:
    def detect_all(self, tcp_flow: TCPFlow) -> List[Problem]:
        """
        识别7类网络问题

        1. 高延迟
        2. 丢包
        3. 乱序
        4. 窗口问题
        5. 握手失败
        6. 连接重置
        7. 重传突发
        """
        problems = []

        # 1. 高延迟检测
        if problem := self.detect_high_latency(tcp_flow):
            problems.append(problem)

        # 2. 丢包检测
        if problem := self.detect_packet_loss(tcp_flow):
            problems.append(problem)

        # 3. 乱序检测
        if problem := self.detect_out_of_order(tcp_flow):
            problems.append(problem)

        # 4. 窗口问题
        if problem := self.detect_window_issues(tcp_flow):
            problems.append(problem)

        # 7. 重传突发
        burst_events = self.detect_retrans_burst(tcp_flow)
        if burst_events:
            problems.append(Problem(
                type='RETRANS_BURST',
                severity='HIGH',
                description=f'检测到{len(burst_events)}个重传突发事件',
                evidence={'events': burst_events}
            ))

        return problems

    def detect_high_latency(self, tcp_flow: TCPFlow) -> Optional[Problem]:
        """高延迟检测 (RTT > 100ms)"""
        rtt_values = [p.get('tcp.analysis.ack_rtt', 0) for p in tcp_flow.packets]
        avg_rtt = sum(rtt_values) / len(rtt_values) if rtt_values else 0

        if avg_rtt > 0.1:  # 100ms
            return Problem(
                type='HIGH_LATENCY',
                severity='WARNING',
                description=f'平均RTT {avg_rtt*1000:.1f}ms 超过阈值',
                evidence={'avg_rtt': avg_rtt}
            )
        return None

    def detect_packet_loss(self, tcp_flow: TCPFlow) -> Optional[Problem]:
        """丢包检测 (重传率 > 1%)"""
        total_packets = len(tcp_flow.packets)
        retrans_packets = sum(
            1 for p in tcp_flow.packets
            if p.get('tcp.analysis.retransmission')
        )
        retrans_rate = retrans_packets / total_packets if total_packets > 0 else 0

        if retrans_rate > 0.01:  # 1%
            return Problem(
                type='PACKET_LOSS',
                severity='HIGH',
                description=f'重传率 {retrans_rate*100:.2f}% 超过阈值',
                evidence={'retrans_rate': retrans_rate}
            )
        return None
```

---

### 1.4.16 DiagnosisEngine - 原因分析

**实现需求**: FR-PCAP-ANA-008

```python
@dataclass
class PossibleCause:
    """可能原因"""
    cause: str
    confidence: float  # 0-1
    evidence: List[str]

class DiagnosisEngine:
    def analyze_causes(self,
                      problem: Problem,
                      tcp_flow: TCPFlow) -> List[PossibleCause]:
        """
        问题原因分析

        根据问题类型和证据推断可能原因
        """
        causes = []

        if problem.type == 'HIGH_LATENCY':
            # 分析高延迟原因
            avg_rtt = problem.evidence.get('avg_rtt', 0)

            if avg_rtt > 0.5:  # >500ms
                causes.append(PossibleCause(
                    cause='地理距离过远或跨域传输',
                    confidence=0.8,
                    evidence=['RTT超过500ms，疑似远距离传输']
                ))

        elif problem.type == 'PACKET_LOSS':
            # 分析丢包原因
            retrans_rate = problem.evidence.get('retrans_rate', 0)

            if retrans_rate > 0.05:  # >5%
                causes.append(PossibleCause(
                    cause='网络拥塞或链路质量差',
                    confidence=0.9,
                    evidence=['重传率超过5%，网络质量严重下降']
                ))

        elif problem.type == 'RETRANS_BURST':
            causes.append(PossibleCause(
                cause='瞬时网络拥塞',
                confidence=0.7,
                evidence=['短时间内大量重传，疑似拥塞']
            ))

        return causes
```

---

### 1.4.17 DiagnosisEngine - 解决建议

**实现需求**: FR-PCAP-ANA-009

```python
@dataclass
class Recommendation:
    """优化建议"""
    action: str
    priority: str  # HIGH/MEDIUM/LOW
    description: str

class DiagnosisEngine:
    def generate_recommendations(self,
                                problem: Problem,
                                causes: List[PossibleCause]) -> List[Recommendation]:
        """
        生成解决建议
        """
        recommendations = []

        if problem.type == 'HIGH_LATENCY':
            recommendations.append(Recommendation(
                action='考虑使用CDN或边缘节点',
                priority='HIGH',
                description='减少地理距离带来的延迟'
            ))
            recommendations.append(Recommendation(
                action='检查路由路径是否最优',
                priority='MEDIUM',
                description='使用traceroute分析路由跳数'
            ))

        elif problem.type == 'PACKET_LOSS':
            recommendations.append(Recommendation(
                action='检查网络设备和链路质量',
                priority='HIGH',
                description='排查交换机、路由器是否存在丢包'
            ))
            recommendations.append(Recommendation(
                action='增大TCP缓冲区',
                priority='MEDIUM',
                description='提高拥塞窗口上限'
            ))

        elif problem.type == 'RETRANS_BURST':
            recommendations.append(Recommendation(
                action='优化TCP拥塞控制算法',
                priority='MEDIUM',
                description='考虑使用BBR等新算法'
            ))

        return recommendations
```

---

### 1.4.18 ProblemClassifier - 问题分类

**实现需求**: FR-PCAP-ANA-010

```python
@dataclass
class ProblemClass:
    """问题分类"""
    category: str
    severity: str
    priority: int

class ProblemClassifier:
    SEVERITY_PRIORITY = {
        'CRITICAL': 1,
        'HIGH': 2,
        'MEDIUM': 3,
        'WARNING': 4,
        'LOW': 5
    }

    def classify(self, problem: Problem) -> ProblemClass:
        """
        问题分类

        分类维度:
        1. 按类型: 延迟/丢包/连接
        2. 按严重程度: CRITICAL/HIGH/MEDIUM/LOW
        """
        if problem.type in ['PACKET_LOSS', 'RETRANS_BURST']:
            category = '数据传输问题'
        elif problem.type == 'HIGH_LATENCY':
            category = '性能问题'
        elif problem.type in ['HANDSHAKE_FAILURE', 'CONNECTION_RESET']:
            category = '连接问题'
        else:
            category = '其他问题'

        return ProblemClass(
            category=category,
            severity=problem.severity,
            priority=self.SEVERITY_PRIORITY.get(problem.severity, 99)
        )

    def rank_by_severity(self, problems: List[Problem]) -> List[Problem]:
        """
        按严重程度排序
        """
        return sorted(
            problems,
            key=lambda p: self.SEVERITY_PRIORITY.get(p.severity, 99)
        )

    def categorize(self, problems: List[Problem]) -> Dict[str, List[Problem]]:
        """
        按类别分组
        """
        categorized = defaultdict(list)
        for problem in problems:
            problem_class = self.classify(problem)
            categorized[problem_class.category].append(problem)
        return dict(categorized)
```

---

# Part 2: TCP Socket分析工具设计

---

## Part 2: 引言

### 2.1 目的

本部分描述TCP Socket分析工具(`tcpsocket_analyzer.py`)的软件设计，包括：
- 系统架构和组件设计
- 需求到设计的追溯关系
- 核心类、接口和算法的详细设计

**目标读者**：开发工程师、测试工程师、架构师

### 2.2 范围

TCP Socket分析工具用于分析eBPF采集的Socket状态数据，识别TCP性能瓶颈。**必须同时提供Client端和Server端数据**。

### 2.3 参考文档

- **需求文档**: `docs/req/claude/traffic-analysis-requirements-v3.0.md` (第3.B节)
- **内核研究**: `docs/req/claude/kernel-tcp-code-research.md`
- **设计标准**: `docs/design/README.md` (IEEE 1016)

---

## Part 2: 需求追溯

### 需求到特性映射

| 需求特性 | 需求文档章节 | 功能需求ID | 优先级 |
|---------|-------------|-----------|--------|
| **特性3.5**: Summary模式 | 3.5 | FR-SOCKET-SUM-001~014 | P0 (高) |
| **特性3.6**: Detailed模式 | 3.6 | FR-SOCKET-DET-001~010 | P1 (中) |
| **特性3.7**: Pipeline瓶颈分析 | 3.7 | FR-SOCKET-PIPE-001~011 | P0 (高) |

### 功能需求追溯矩阵

#### 特性3.5: Summary模式

| 需求ID | 需求描述 | 设计组件 | 核心类/方法 | HLD章节 | LLD章节 |
|--------|---------|---------|-----------|---------|---------|
| FR-SOCKET-SUM-001 | 解析TCP Socket采样数据文件 | SocketDataParser | `parse_dual_directories()` | 2.3.1 | 2.4.1 |
| FR-SOCKET-SUM-002 | 对所有数值型指标进行完整统计 | TimeSeriesStats | `compute_basic_stats()` | 2.3.2 | 2.4.2 |
| FR-SOCKET-SUM-003 | 计算BDP和理论最优CWND | SummaryAnalyzer | `analyze_window()` | 2.3.3 | 2.4.3 |
| FR-SOCKET-SUM-004 | 计算带宽利用率 | SummaryAnalyzer | `analyze_rate()` | 2.3.3 | 2.4.4 |
| FR-SOCKET-SUM-005 | 分析RTT稳定性 | SummaryAnalyzer | `analyze_rtt()` | 2.3.3 | 2.4.5 |
| FR-SOCKET-SUM-006 | 分析窗口利用率 | SummaryAnalyzer | `analyze_window()` | 2.3.3 | 2.4.6 |
| FR-SOCKET-SUM-007 | 分析速率关系 | SummaryAnalyzer | `analyze_rate()` | 2.3.3 | 2.4.7 |
| FR-SOCKET-SUM-008 | 分析重传率 | SummaryAnalyzer | `analyze_retrans()` | 2.3.3 | 2.4.8 |
| FR-SOCKET-SUM-009 | 分析Buffer压力 | SummaryAnalyzer | `analyze_buffer()` | 2.3.3 | 2.4.9 |
| FR-SOCKET-SUM-010 | 识别性能瓶颈 | SummaryAnalyzer | `identify_bottlenecks()` | 2.3.3 | 2.4.10 |
| FR-SOCKET-SUM-011 | 提供配置建议 | RecommendationEngine | `generate()` | 2.3.4 | 2.4.11 |
| FR-SOCKET-SUM-012 | 支持带宽参数 | BandwidthParser | `parse()` | 2.3.5 | 2.4.12 |
| FR-SOCKET-SUM-014 | 验证数据一致性 | SocketDataParser | `_validate_connection_match()` | 2.3.1 | 2.4.13 |

#### 特性3.6: Detailed模式

| 需求ID | 需求描述 | 设计组件 | 核心类/方法 | HLD章节 | LLD章节 |
|--------|---------|---------|-----------|---------|---------|
| FR-SOCKET-DET-001 | 窗口限制时间占比分析 | DetailedAnalyzer | `analyze_window_detailed()` | 2.3.6 | 2.4.14 |
| FR-SOCKET-DET-002 | CWND变化模式 | WindowAnalyzer | `detect_cwnd_patterns()` | 2.3.7 | 2.4.15 |
| FR-SOCKET-DET-003 | 速率时序分析 | DetailedAnalyzer | `analyze_rate_detailed()` | 2.3.6 | 2.4.16 |
| FR-SOCKET-DET-004 | 识别Rate限制类型 | RateAnalyzer | `identify_rate_limits()` | 2.3.8 | 2.4.17 |
| FR-SOCKET-DET-005 | 重传突发事件 | DetailedAnalyzer | `analyze_retrans_detailed()` | 2.3.6 | 2.4.18 |
| FR-SOCKET-DET-006 | 虚假重传分布 | DetailedAnalyzer | `analyze_spurious_retrans()` | 2.3.6 | 2.4.19 |
| FR-SOCKET-DET-007 | Buffer压力时序分析 | DetailedAnalyzer | `analyze_buffer_detailed()` | 2.3.6 | 2.4.20 |
| FR-SOCKET-DET-008 | Buffer配置建议 | RecommendationEngine | `recommend_buffer_size()` | 2.3.4 | 2.4.21 |
| FR-SOCKET-DET-009 | 导出时序数据 | DetailedAnalyzer | `export_timeseries()` | 2.3.6 | 2.4.22 |
| FR-SOCKET-DET-010 | 指标相关性分析 | RateAnalyzer | `compute_correlations()` | 2.3.8 | 2.4.23 |

#### 特性3.7: Pipeline瓶颈分析

| 需求ID | 需求描述 | 设计组件 | 核心类/方法 | HLD章节 | LLD章节 |
|--------|---------|---------|-----------|---------|---------|
| FR-SOCKET-PIPE-001 | 识别发送路径6个瓶颈点 | BottleneckFinder | `find_send_path_bottlenecks()` | 2.3.9 | 2.4.24 |
| FR-SOCKET-PIPE-002 | 识别接收路径4个瓶颈点 | BottleneckFinder | `find_recv_path_bottlenecks()` | 2.3.9 | 2.4.25 |
| FR-SOCKET-PIPE-003 | 计算瓶颈压力值 | BottleneckRule | `detect()` | 2.3.10 | 2.4.26 |
| FR-SOCKET-PIPE-004 | 判断主要/次要瓶颈 | BottleneckFinder | `identify_primary()` | 2.3.9 | 2.4.27 |
| FR-SOCKET-PIPE-005 | Pipeline健康度总览 | PipelineReporter | `generate_health_overview()` | 2.3.11 | 2.4.28 |
| FR-SOCKET-PIPE-006 | 瓶颈点详细诊断 | PipelineReporter | `generate_bottleneck_details()` | 2.3.11 | 2.4.29 |
| FR-SOCKET-PIPE-007 | 优化行动优先级 | BottleneckFinder | `rank_priority()` | 2.3.9 | 2.4.30 |
| FR-SOCKET-PIPE-008 | 整体评估和建议 | DiagnosisEngine | `generate_next_steps()` | 2.3.12 | 2.4.31 |

---

## Part 2: 概要设计 (HLD)

### 2.1 系统上下文

```
┌─────────────────────────────────────────────────────────┐
│            外部数据采集工具                              │
│  tcp_connection_analyzer.py (eBPF采集)                  │
└──────────────────┬──────────────────┬───────────────────┘
    Client端数据   │                  │ Server端数据
                   ▼                  ▼
┌─────────────────────────────────────────────────────────┐
│      TCP Socket分析工具 (本系统)                        │
│  tcpsocket_analyzer.py                                  │
│  - 输入: TCP Socket采样数据（双端）                     │
│  - 引擎: pandas/numpy                                    │
│  - 输出: 性能分析 + Pipeline瓶颈诊断                    │
└──────────────────┬──────────────────────────────────────┘
                   │ 分析报告
                   ▼
┌─────────────────────────────────────────────────────────┐
│                用户/下游系统                             │
│  - 性能分析师 (TCP调优)                                 │
│  - 网络工程师 (瓶颈排查)                                │
└─────────────────────────────────────────────────────────┘
```

**关键特点**:
- **双端数据**: 必须同时提供Client端和Server端数据
- **时间对齐**: 工具自动进行时间对齐

### 2.2 架构设计

**架构风格**: 管道-过滤器 + 分层架构

**整体架构图**:

```
┌─────────────────────────────────────────────────────────┐
│       TCP Socket Analyzer Architecture                  │
└─────────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┴─────────────────┐
        ▼                                   ▼
┌──────────────────┐             ┌──────────────────┐
│  CLI Interface   │             │  Reporters       │
│  (Layer 4)       │             │  (Layer 4)       │
└────────┬─────────┘             └──────────────────┘
         │                                 ▲
         ▼                                 │
┌──────────────────┐             ┌──────────────────┐
│  Mode Selector   │             │  Statistics      │
│  (Layer 3)       │────────────>│  Engine          │
│  - Summary       │             │  (Layer 2)       │
│  - Detailed      │             └──────────────────┘
│  - Pipeline      │                      ▲
└────────┬─────────┘                      │
         │                                │
         ▼                                │
┌──────────────────────────────────────────┘
│  Analyzers (Layer 3)
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│  │ Summary      │ │ Detailed     │ │ Bottleneck   │
│  │ Analyzer     │ │ Analyzer     │ │ Finder       │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
│         └────────────────┼────────────────┘
│                          ▼
│         ┌────────────────────────────────┐
│         │  Window/Rate/Buffer Analyzers │
│         └────────────────┬───────────────┘
└──────────────────────────┼──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│          Socket Data Parser (Layer 1)                   │
│  - Dual-Side Parser                                      │
│  - Time Alignment                                        │
└─────────────────────────────────────────────────────────┘
```

**模式架构对比**:

```
Summary模式:  CLI → Parser → TimeSeriesStats → SummaryAnalyzer → Reporter
Detailed模式: CLI → Parser → DetailedAnalyzer → DetailedReporter
                                ├─→ WindowAnalyzer
                                ├─→ RateAnalyzer
                                └─→ BufferAnalyzer
Pipeline模式: CLI → Parser → BottleneckFinder → PipelineReporter
                               (10个规则)
```

### 2.3 组件设计

#### 2.3.1 SocketDataParser

**职责**: 解析双端数据、时间对齐、连接验证

**对外接口**:
```python
class SocketDataParser:
    def parse_dual_directories(self, client_dir: str, server_dir: str)
        -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]
    def parse_directory(self, dir_path: str, side: str) -> pd.DataFrame
    def parse_file(self, file_path: str, side: str) -> SamplePoint
```

**实现需求**: FR-SOCKET-SUM-001, FR-SOCKET-SUM-014

#### 2.3.2 TimeSeriesStats

**职责**: 时序统计（Min/Max/Mean/Std/CV/P50/P95/P99）

**对外接口**:
```python
class TimeSeriesStats:
    def compute_basic_stats(self, data: pd.Series) -> BasicStats
    def compute_percentiles(self, data: pd.Series,
                          percentiles: List[float]) -> Dict[float, float]
```

**实现需求**: FR-SOCKET-SUM-002

#### 2.3.3 SummaryAnalyzer

**职责**: Summary模式主分析器

**对外接口**:
```python
class SummaryAnalyzer:
    def analyze(self, ...) -> SummaryResult
    def analyze_rtt(self, ...) -> RTTAnalysisResult
    def analyze_window(self, ...) -> WindowAnalysisResult
    def analyze_rate(self, ...) -> RateAnalysisResult
    def analyze_buffer(self, ...) -> BufferAnalysisResult
```

**实现需求**: FR-SOCKET-SUM-003~010

#### 2.3.4 RecommendationEngine

**职责**: 生成优化建议

**对外接口**:
```python
class RecommendationEngine:
    def generate(self, analysis_result: Any) -> List[Recommendation]
    def recommend_buffer_size(self, bdp: float, current_size: int) -> BufferRecommendation
    def recommend_cwnd_tuning(self, cwnd_stats: WindowAnalysisResult) -> List[Recommendation]
```

**实现需求**: FR-SOCKET-SUM-011, FR-SOCKET-DET-008

#### 2.3.5 BandwidthParser

**职责**: 解析带宽参数

**对外接口**:
```python
class BandwidthParser:
    def parse(self, bandwidth_str: str) -> float
    def validate(self, bandwidth_str: str) -> bool
```

**实现需求**: FR-SOCKET-SUM-012

#### 2.3.6 DetailedAnalyzer

**职责**: Detailed模式主分析器

**对外接口**:
```python
class DetailedAnalyzer:
    def analyze(self, ...) -> DetailedResult
    def analyze_window_detailed(self, ...) -> WindowDetailedResult
    def analyze_rate_detailed(self, ...) -> RateDetailedResult
    def analyze_retrans_detailed(self, ...) -> RetransDetailedResult
    def analyze_buffer_detailed(self, ...) -> BufferDetailedResult
    def export_timeseries(self, ...) -> Dict[str, pd.DataFrame]
```

**实现需求**: FR-SOCKET-DET-001, 003, 005, 006, 007, 009

#### 2.3.7 WindowAnalyzer

**职责**: 窗口深度分析（辅助Detailed和Pipeline）

**对外接口**:
```python
class WindowAnalyzer:
    def detect_cwnd_patterns(self, df: pd.DataFrame) -> CWNDPatterns
    def analyze_window_limits(self, df: pd.DataFrame) -> WindowLimits
```

**实现需求**: FR-SOCKET-DET-001, 002

#### 2.3.8 RateAnalyzer

**职责**: 速率深度分析（辅助Detailed）

**对外接口**:
```python
class RateAnalyzer:
    def analyze_trends(self, df: pd.DataFrame) -> RateTrends
    def identify_rate_limits(self, df: pd.DataFrame) -> RateLimits
    def compute_correlations(self, df: pd.DataFrame) -> Correlations
```

**实现需求**: FR-SOCKET-DET-004, 010

#### 2.3.9 BottleneckFinder

**职责**: Pipeline瓶颈识别（仅Pipeline模式）

**对外接口**:
```python
class BottleneckFinder:
    def find_send_path_bottlenecks(self, df: pd.DataFrame) -> List[Bottleneck]
    def find_recv_path_bottlenecks(self, df: pd.DataFrame) -> List[Bottleneck]
    def identify_primary(self, bottlenecks: List[Bottleneck]) -> Bottleneck
    def rank_priority(self, bottlenecks: List[Bottleneck]) -> List[Bottleneck]
```

**实现需求**: FR-SOCKET-PIPE-001, 002, 004, 007

#### 2.3.10 BottleneckRule

**职责**: 瓶颈检测规则（10个规则类）

**对外接口**:
```python
class BottleneckRule(ABC):
    @abstractmethod
    def detect(self, data: pd.DataFrame) -> Optional[Bottleneck]
    def get_rule_id(self) -> str
    def get_description(self) -> str
```

**实现需求**: FR-SOCKET-PIPE-003

#### 2.3.11 PipelineReporter

**职责**: Pipeline报告生成

**对外接口**:
```python
class PipelineReporter:
    def generate_health_overview(self, bottlenecks: List[Bottleneck]) -> HealthOverview
    def generate_bottleneck_details(self, bottleneck: Bottleneck) -> BottleneckReport
    def generate_full_report(self, analysis_result: PipelineResult) -> str
```

**实现需求**: FR-SOCKET-PIPE-005, 006

#### 2.3.12 DiagnosisEngine

**职责**: 瓶颈诊断和优化建议

**对外接口**:
```python
class DiagnosisEngine:
    def diagnose_bottleneck(self, bottleneck: Bottleneck,
                           context: AnalysisContext) -> Diagnosis
    def generate_next_steps(self, bottlenecks: List[Bottleneck]) -> List[ActionPlan]
```

**实现需求**: FR-SOCKET-PIPE-008

---

## Part 2: 详细设计 (LLD)

### 2.4.1 SocketDataParser类

**实现需求**: FR-SOCKET-SUM-001, FR-SOCKET-SUM-014

```python
@dataclass
class FiveTuple:
    """TCP五元组"""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str = 'TCP'

    def reverse(self) -> 'FiveTuple':
        """返回反向的五元组（用于匹配Server端数据）"""
        return FiveTuple(
            src_ip=self.dst_ip,
            src_port=self.dst_port,
            dst_ip=self.src_ip,
            dst_port=self.src_port,
            protocol=self.protocol
        )

@dataclass
class SamplePoint:
    """单个采样点数据"""
    timestamp: datetime
    connection: FiveTuple
    state: str
    side: str  # 'client' 或 'server'
    metrics: Dict[str, float]

class SocketDataParser:
    """Socket数据解析器 - 支持双端数据解析和对齐"""

    def parse_dual_directories(self,
                               client_dir: str,
                               server_dir: str) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        解析Client和Server两端的采样文件，并进行时间对齐

        Returns:
            Tuple of:
            - client_df: Client端DataFrame
            - server_df: Server端DataFrame
            - aligned_df: 对齐后的双端DataFrame

        实现逻辑:
        1. 解析Client端数据
        2. 解析Server端数据
        3. 验证连接匹配（五元组互为反向）
        4. 时间对齐（基于timestamp）
        """
        client_df = self.parse_directory(client_dir, side='client')
        server_df = self.parse_directory(server_dir, side='server')
        self._validate_connection_match(client_df, server_df)
        aligned_df = self._align_dual_side_data(client_df, server_df)

        return client_df, server_df, aligned_df

    def _validate_connection_match(self,
                                   client_df: pd.DataFrame,
                                   server_df: pd.DataFrame) -> None:
        """
        验证Client和Server端的连接五元组是否匹配

        验证逻辑:
        Client的src→dst 应该等于 Server的dst←src
        """
        client_conn = client_df['connection'].iloc[0]
        server_conn = server_df['connection'].iloc[0]

        client_ft = self._parse_connection_str(client_conn)
        server_ft = self._parse_connection_str(server_conn)

        if not self._is_reverse_connection(client_ft, server_ft):
            raise ConnectionMismatchError(
                f"Connection mismatch:\n"
                f"  Client: {client_conn}\n"
                f"  Server: {server_conn}"
            )

    def _align_dual_side_data(self,
                              client_df: pd.DataFrame,
                              server_df: pd.DataFrame,
                              max_offset: float = 1.0) -> pd.DataFrame:
        """
        对齐Client和Server两端的时序数据

        算法:
        使用pandas merge_asof进行基于时间的最近邻匹配
        容差为max_offset秒（默认1秒）
        """
        client_reset = client_df.reset_index()
        server_reset = server_df.reset_index()

        aligned = pd.merge_asof(
            client_reset,
            server_reset,
            on='timestamp',
            direction='nearest',
            tolerance=pd.Timedelta(seconds=max_offset),
            suffixes=('_client', '_server')
        )

        aligned = aligned.dropna()
        aligned.set_index('timestamp', inplace=True)

        return aligned
```

**关键设计点**:
1. **双端数据**: 必须同时提供Client和Server端
2. **连接验证**: 确保两端五元组匹配
3. **时间对齐**: 使用merge_asof最近邻匹配

---

### 2.4.2 TimeSeriesStats类

**实现需求**: FR-SOCKET-SUM-002

```python
@dataclass
class BasicStats:
    """基础统计结果"""
    min: float
    max: float
    mean: float
    std: float
    cv: float  # 变异系数
    p50: float
    p95: float
    p99: float

class TimeSeriesStats:
    def compute_basic_stats(self, data: pd.Series) -> BasicStats:
        """
        计算完整统计（Min/Max/Mean/Std/CV/P50/P95/P99）
        """
        data_clean = data.dropna()

        if len(data_clean) == 0:
            return BasicStats(0, 0, 0, 0, 0, 0, 0, 0)

        min_val = data_clean.min()
        max_val = data_clean.max()
        mean_val = data_clean.mean()
        std_val = data_clean.std()
        cv_val = std_val / mean_val if mean_val != 0 else 0

        percentiles = data_clean.quantile([0.5, 0.95, 0.99])

        return BasicStats(
            min=min_val,
            max=max_val,
            mean=mean_val,
            std=std_val,
            cv=cv_val,
            p50=percentiles[0.5],
            p95=percentiles[0.95],
            p99=percentiles[0.99]
        )
```

---

### 2.4.3 SummaryAnalyzer - 窗口分析

**实现需求**: FR-SOCKET-SUM-003, FR-SOCKET-SUM-006

```python
class SummaryAnalyzer:
    def analyze_window(self,
                      client_df: pd.DataFrame,
                      server_df: pd.DataFrame,
                      bandwidth: float) -> WindowAnalysisResult:
        """
        窗口分析

        分析内容:
        1. BDP计算：BDP = Bandwidth × RTT
        2. 理论最优CWND：Optimal_CWND = BDP / MSS
        3. CWND利用率：actual_cwnd / optimal_cwnd
        """
        # 计算BDP
        avg_rtt = client_df['rtt'].mean() / 1000  # ms -> s
        bdp = bandwidth * avg_rtt / 8  # bits -> bytes
        optimal_cwnd = bdp / 1460  # MSS = 1460 bytes

        # 实际CWND
        actual_cwnd = client_df['cwnd'].mean()
        cwnd_utilization = actual_cwnd / optimal_cwnd if optimal_cwnd > 0 else 0

        return WindowAnalysisResult(
            client_cwnd_stats=self.stats_engine.compute_basic_stats(client_df['cwnd']),
            server_cwnd_stats=self.stats_engine.compute_basic_stats(server_df['cwnd']),
            bdp=bdp,
            optimal_cwnd=optimal_cwnd,
            actual_cwnd=actual_cwnd,
            cwnd_utilization=cwnd_utilization,
            rwnd_analysis=self._analyze_rwnd(client_df),
            ssthresh_analysis=self._analyze_ssthresh(client_df)
        )
```

---

### 2.4.4 SummaryAnalyzer - 速率分析

**实现需求**: FR-SOCKET-SUM-004, FR-SOCKET-SUM-007

```python
@dataclass
class RateAnalysisResult:
    """速率分析结果"""
    # 基础统计
    pacing_rate_stats: BasicStats
    delivery_rate_stats: BasicStats

    # 带宽利用率
    avg_bandwidth_utilization: float
    peak_bandwidth_utilization: float

    # 速率关系
    pacing_delivery_ratio: float  # pacing/delivery比值
    rate_stability: float  # 速率稳定性 (CV)

class SummaryAnalyzer:
    def analyze_rate(self,
                    client_df: pd.DataFrame,
                    server_df: pd.DataFrame,
                    bandwidth: float) -> RateAnalysisResult:
        """
        速率分析

        实现需求: FR-SOCKET-SUM-004, FR-SOCKET-SUM-007

        分析内容:
        1. Pacing Rate和Delivery Rate统计
        2. 带宽利用率计算
        3. 速率比值关系
        """
        # Pacing Rate统计
        pacing_rate_stats = self.stats_engine.compute_basic_stats(client_df['pacing_rate'])

        # Delivery Rate统计
        delivery_rate_stats = self.stats_engine.compute_basic_stats(client_df['delivery_rate'])

        # 带宽利用率
        avg_bw_util = delivery_rate_stats.mean / bandwidth if bandwidth > 0 else 0
        peak_bw_util = delivery_rate_stats.max / bandwidth if bandwidth > 0 else 0

        # Pacing/Delivery比值
        pacing_delivery_ratio = pacing_rate_stats.mean / delivery_rate_stats.mean \
            if delivery_rate_stats.mean > 0 else 0

        # 速率稳定性（使用Delivery Rate的CV）
        rate_stability = 1.0 - delivery_rate_stats.cv  # CV越小越稳定

        return RateAnalysisResult(
            pacing_rate_stats=pacing_rate_stats,
            delivery_rate_stats=delivery_rate_stats,
            avg_bandwidth_utilization=avg_bw_util,
            peak_bandwidth_utilization=peak_bw_util,
            pacing_delivery_ratio=pacing_delivery_ratio,
            rate_stability=rate_stability
        )
```

---

### 2.4.5 SummaryAnalyzer - RTT分析

**实现需求**: FR-SOCKET-SUM-005

```python
@dataclass
class RTTAnalysisResult:
    """RTT分析结果"""
    client_rtt_stats: BasicStats
    server_rtt_stats: BasicStats
    rtt_stability: str  # STABLE/UNSTABLE
    jitter: float  # RTT抖动 (std)

class SummaryAnalyzer:
    def analyze_rtt(self,
                   client_df: pd.DataFrame,
                   server_df: pd.DataFrame) -> RTTAnalysisResult:
        """
        RTT稳定性分析

        实现需求: FR-SOCKET-SUM-005

        稳定性判断:
        - CV < 0.3: STABLE
        - CV >= 0.3: UNSTABLE
        """
        client_rtt_stats = self.stats_engine.compute_basic_stats(client_df['rtt'])
        server_rtt_stats = self.stats_engine.compute_basic_stats(server_df['rtt'])

        # 稳定性判断
        stability = 'STABLE' if client_rtt_stats.cv < 0.3 else 'UNSTABLE'

        # 抖动 = 标准差
        jitter = client_rtt_stats.std

        return RTTAnalysisResult(
            client_rtt_stats=client_rtt_stats,
            server_rtt_stats=server_rtt_stats,
            rtt_stability=stability,
            jitter=jitter
        )
```

---

### 2.4.6 SummaryAnalyzer - 窗口利用率 (补充说明)

**实现需求**: FR-SOCKET-SUM-006

**说明**: 窗口利用率分析已在 2.4.3 的 `analyze_window()` 中实现，通过 `cwnd_utilization` 字段体现。

---

### 2.4.7 SummaryAnalyzer - 速率关系 (补充说明)

**实现需求**: FR-SOCKET-SUM-007

**说明**: 速率关系分析已在 2.4.4 的 `analyze_rate()` 中实现，通过 `pacing_delivery_ratio` 字段体现。

---

### 2.4.8 SummaryAnalyzer - 重传率分析

**实现需求**: FR-SOCKET-SUM-008

```python
@dataclass
class RetransAnalysisResult:
    """重传分析结果"""
    retrans_rate: float
    retrans_bytes_rate: float
    spurious_retrans_count: int
    total_retrans: int

class SummaryAnalyzer:
    def analyze_retrans(self,
                       client_df: pd.DataFrame,
                       server_df: pd.DataFrame) -> RetransAnalysisResult:
        """
        重传率分析

        实现需求: FR-SOCKET-SUM-008

        计算:
        1. 重传率 = retrans增量 / packets_sent增量
        2. 虚假重传统计
        """
        # 总重传次数（累计值的最大值）
        total_retrans = client_df['retrans'].max() if 'retrans' in client_df.columns else 0

        # 总发包数
        total_packets = client_df['packets_sent'].max() if 'packets_sent' in client_df.columns else 0

        # 重传率
        retrans_rate = (total_retrans / total_packets * 100) if total_packets > 0 else 0

        # 重传字节率 (如果有bytes_retrans字段)
        retrans_bytes = client_df['bytes_retrans'].max() if 'bytes_retrans' in client_df.columns else 0
        total_bytes = client_df['bytes_sent'].max() if 'bytes_sent' in client_df.columns else 0
        retrans_bytes_rate = (retrans_bytes / total_bytes * 100) if total_bytes > 0 else 0

        # 虚假重传
        spurious_count = client_df['spurious_retrans'].sum() if 'spurious_retrans' in client_df.columns else 0

        return RetransAnalysisResult(
            retrans_rate=retrans_rate,
            retrans_bytes_rate=retrans_bytes_rate,
            spurious_retrans_count=spurious_count,
            total_retrans=total_retrans
        )
```

---

### 2.4.9 SummaryAnalyzer - Buffer压力分析

**实现需求**: FR-SOCKET-SUM-009

```python
@dataclass
class BufferAnalysisResult:
    """Buffer分析结果"""
    # 发送侧
    send_q_stats: BasicStats
    socket_tx_pressure: float  # 0-1, 平均压力
    # 接收侧
    recv_q_stats: BasicStats
    socket_rx_pressure: float

class SummaryAnalyzer:
    def analyze_buffer(self,
                      client_df: pd.DataFrame,
                      server_df: pd.DataFrame) -> BufferAnalysisResult:
        """
        Buffer压力分析

        实现需求: FR-SOCKET-SUM-009

        压力计算:
        Pressure = socket_queue / socket_buffer
        """
        # 发送侧统计
        send_q_stats = self.stats_engine.compute_basic_stats(client_df['send_q'])

        # 发送侧压力
        if 'socket_tx_queue' in client_df.columns and 'socket_tx_buffer' in client_df.columns:
            tx_pressure = (client_df['socket_tx_queue'] / client_df['socket_tx_buffer']).mean()
        else:
            tx_pressure = 0.0

        # 接收侧统计
        recv_q_stats = self.stats_engine.compute_basic_stats(server_df['recv_q'])

        # 接收侧压力
        if 'socket_rx_queue' in server_df.columns and 'socket_rx_buffer' in server_df.columns:
            rx_pressure = (server_df['socket_rx_queue'] / server_df['socket_rx_buffer']).mean()
        else:
            rx_pressure = 0.0

        return BufferAnalysisResult(
            send_q_stats=send_q_stats,
            socket_tx_pressure=tx_pressure,
            recv_q_stats=recv_q_stats,
            socket_rx_pressure=rx_pressure
        )
```

---

### 2.4.10 SummaryAnalyzer - 瓶颈识别

**实现需求**: FR-SOCKET-SUM-010

```python
@dataclass
class BottleneckIdentification:
    """瓶颈识别结果"""
    primary_bottleneck: str
    confidence: float
    evidence: List[str]

class SummaryAnalyzer:
    def identify_bottlenecks(self,
                            window_result: WindowAnalysisResult,
                            rate_result: RateAnalysisResult,
                            buffer_result: BufferAnalysisResult) -> BottleneckIdentification:
        """
        识别主要性能瓶颈

        实现需求: FR-SOCKET-SUM-010

        瓶颈类型:
        1. CWND受限: cwnd_utilization > 0.9
        2. Buffer受限: buffer_pressure > 0.8
        3. 网络带宽受限: bandwidth_utilization > 0.9
        4. 应用受限: 其他情况
        """
        evidence = []
        scores = {}

        # CWND受限检测
        if window_result.cwnd_utilization > 0.9:
            scores['CWND_LIMITED'] = 0.9
            evidence.append(f'CWND利用率{window_result.cwnd_utilization*100:.1f}%')

        # Buffer受限检测
        if buffer_result.socket_tx_pressure > 0.8:
            scores['BUFFER_LIMITED'] = 0.8
            evidence.append(f'发送Buffer压力{buffer_result.socket_tx_pressure*100:.1f}%')

        # 网络带宽受限
        if rate_result.avg_bandwidth_utilization > 0.9:
            scores['NETWORK_LIMITED'] = 0.85
            evidence.append(f'带宽利用率{rate_result.avg_bandwidth_utilization*100:.1f}%')

        # 确定主要瓶颈
        if scores:
            primary = max(scores, key=scores.get)
            confidence = scores[primary]
        else:
            primary = 'APP_LIMITED'
            confidence = 0.7
            evidence.append('无明显系统瓶颈，可能应用发送速率受限')

        return BottleneckIdentification(
            primary_bottleneck=primary,
            confidence=confidence,
            evidence=evidence
        )
```

---

### 2.4.11 RecommendationEngine - 配置建议

**实现需求**: FR-SOCKET-SUM-011

```python
@dataclass
class Recommendation:
    """优化建议"""
    category: str
    priority: str  # HIGH/MEDIUM/LOW
    action: str
    rationale: str
    command: Optional[str] = None

class RecommendationEngine:
    def generate(self, analysis_result: SummaryResult) -> List[Recommendation]:
        """
        生成配置优化建议

        实现需求: FR-SOCKET-SUM-011

        建议类型:
        1. CWND调优
        2. Buffer扩容
        3. 拥塞控制算法
        """
        recommendations = []

        # CWND调优建议
        if analysis_result.bottleneck.primary_bottleneck == 'CWND_LIMITED':
            recommendations.append(Recommendation(
                category='窗口优化',
                priority='HIGH',
                action='增大初始CWND或ssthresh',
                rationale='CWND成为主要瓶颈',
                command='sysctl -w net.ipv4.tcp_init_cwnd=10'
            ))

        # Buffer扩容建议
        if analysis_result.buffer.socket_tx_pressure > 0.8:
            new_size = int(analysis_result.window.bdp * 1.5)
            recommendations.append(Recommendation(
                category='Buffer优化',
                priority='HIGH',
                action=f'增大发送Buffer至{new_size}字节',
                rationale=f'当前Buffer压力{analysis_result.buffer.socket_tx_pressure*100:.1f}%',
                command=f'sysctl -w net.ipv4.tcp_wmem="4096 16384 {new_size}"'
            ))

        # 拥塞控制算法建议
        if analysis_result.rate.avg_bandwidth_utilization < 0.6:
            recommendations.append(Recommendation(
                category='拥塞控制',
                priority='MEDIUM',
                action='考虑切换到BBR拥塞控制算法',
                rationale='带宽利用率偏低，BBR可能提升吞吐',
                command='sysctl -w net.ipv4.tcp_congestion_control=bbr'
            ))

        return recommendations
```

---

### 2.4.12 BandwidthParser - 带宽解析

**实现需求**: FR-SOCKET-SUM-012

```python
class BandwidthParser:
    """带宽参数解析器"""

    UNITS = {
        'bps': 1,
        'kbps': 1000,
        'mbps': 1000000,
        'gbps': 1000000000,
        'kibps': 1024,
        'mibps': 1024 * 1024,
        'gibps': 1024 * 1024 * 1024,
    }

    def parse(self, bandwidth_str: str) -> float:
        """
        解析带宽字符串到 bps

        实现需求: FR-SOCKET-SUM-012

        支持格式:
        - "100mbps", "100Mbps", "100 Mbps"
        - "1gbps", "1Gbps"
        - "100000000" (默认bps)
        """
        bandwidth_str = bandwidth_str.strip().lower()

        # 提取数字和单位
        import re
        match = re.match(r'^([\d.]+)\s*([a-z]+)?$', bandwidth_str)
        if not match:
            raise ValueError(f'无效的带宽格式: {bandwidth_str}')

        value = float(match.group(1))
        unit = match.group(2) or 'bps'

        if unit not in self.UNITS:
            raise ValueError(f'不支持的带宽单位: {unit}')

        return value * self.UNITS[unit]

    def validate(self, bandwidth_str: str) -> bool:
        """验证带宽字符串格式"""
        try:
            self.parse(bandwidth_str)
            return True
        except ValueError:
            return False
```

---

### 2.4.13 SocketDataParser - 连接验证 (补充说明)

**实现需求**: FR-SOCKET-SUM-014

**说明**: 连接验证逻辑已在 2.4.1 的 `_validate_connection_match()` 方法中实现。

---

### 2.4.14 DetailedAnalyzer - 窗口深度分析

**实现需求**: FR-SOCKET-DET-001

```python
@dataclass
class WindowDetailedResult:
    """窗口深度分析结果"""
    # 基础统计
    basic_stats: WindowAnalysisResult  # 继承自Summary

    # 窗口限制时间占比
    cwnd_limited_ratio: float
    rwnd_limited_ratio: float
    sndbuf_limited_ratio: float

    # CWND变化模式
    cwnd_patterns: CWNDPatterns

    # 窗口恢复事件
    window_recovery_events: List[WindowRecoveryEvent]

@dataclass
class WindowRecoveryEvent:
    """窗口恢复事件"""
    timestamp: datetime
    cwnd_before: int
    cwnd_after: int
    drop_percentage: float
    possible_cause: str

class DetailedAnalyzer:
    def __init__(self, config: AnalyzerConfig):
        self.config = config
        self.summary_analyzer = SummaryAnalyzer(config)
        self.window_analyzer = WindowAnalyzer()
        self.rate_analyzer = RateAnalyzer()

    def analyze(self,
                client_df: pd.DataFrame,
                server_df: pd.DataFrame,
                aligned_df: pd.DataFrame,
                bandwidth: float) -> DetailedResult:
        """
        执行Detailed模式分析

        实现逻辑:
        1. 先执行Summary分析（复用）
        2. 窗口深度分析
        3. 速率深度分析
        4. Buffer深度分析
        5. 可选：导出时序数据
        """
        # 1. Summary分析（复用）
        summary = self.summary_analyzer.analyze(client_df, server_df, aligned_df, bandwidth)

        # 2. 窗口深度分析
        window_detailed = self.analyze_window_detailed(client_df, server_df, bandwidth)

        # 3. 速率深度分析
        rate_detailed = self.analyze_rate_detailed(client_df, server_df, bandwidth)

        # 4. 重传深度分析
        retrans_detailed = self.analyze_retrans_detailed(client_df, server_df)

        # 5. Buffer深度分析
        buffer_detailed = self.analyze_buffer_detailed(client_df, server_df)

        # 6. 时序数据导出（可选）
        timeseries = None
        if self.config.export_timeseries:
            timeseries = self.export_timeseries(aligned_df)

        return DetailedResult(
            summary=summary,
            window_detailed=window_detailed,
            rate_detailed=rate_detailed,
            retrans_detailed=retrans_detailed,
            buffer_detailed=buffer_detailed,
            timeseries_data=timeseries
        )

    def analyze_window_detailed(self,
                                client_df: pd.DataFrame,
                                server_df: pd.DataFrame,
                                bandwidth: float) -> WindowDetailedResult:
        """
        窗口深度分析

        实现需求: FR-SOCKET-DET-001

        分析内容:
        1. 窗口限制时间占比分析
        2. CWND变化模式识别
        3. 窗口恢复事件检测
        """
        # 基础统计（复用Summary）
        basic_stats = self.summary_analyzer.analyze_window(client_df, server_df, bandwidth)

        # 窗口限制时间占比
        window_limits = self.window_analyzer.analyze_window_limits(client_df)

        # CWND变化模式
        cwnd_patterns = self.window_analyzer.detect_cwnd_patterns(client_df)

        # 窗口恢复事件检测
        recovery_events = self._detect_window_recovery_events(client_df)

        return WindowDetailedResult(
            basic_stats=basic_stats,
            cwnd_limited_ratio=window_limits.cwnd_limited_ratio,
            rwnd_limited_ratio=window_limits.rwnd_limited_ratio,
            sndbuf_limited_ratio=window_limits.sndbuf_limited_ratio,
            cwnd_patterns=cwnd_patterns,
            window_recovery_events=recovery_events
        )

    def _detect_window_recovery_events(self, df: pd.DataFrame) -> List[WindowRecoveryEvent]:
        """
        检测窗口恢复事件

        算法:
        1. 检测CWND突然下降（下降>30%）
        2. 记录下降幅度和时间
        3. 分析可能原因（丢包、超时等）
        """
        events = []
        cwnd_values = df['cwnd'].values
        timestamps = df.index

        for i in range(1, len(cwnd_values)):
            cwnd_before = cwnd_values[i-1]
            cwnd_after = cwnd_values[i]

            # 检测CWND下降
            if cwnd_before > 0:
                drop_ratio = (cwnd_before - cwnd_after) / cwnd_before

                if drop_ratio > 0.3:  # 下降超过30%
                    # 分析可能原因
                    possible_cause = self._analyze_window_drop_cause(df, i)

                    events.append(WindowRecoveryEvent(
                        timestamp=timestamps[i],
                        cwnd_before=cwnd_before,
                        cwnd_after=cwnd_after,
                        drop_percentage=drop_ratio * 100,
                        possible_cause=possible_cause
                    ))

        return events

    def _analyze_window_drop_cause(self, df: pd.DataFrame, index: int) -> str:
        """
        分析CWND下降原因

        可能原因:
        1. 丢包触发快速恢复（50%下降）
        2. 超时触发慢启动（更大下降）
        3. 拥塞避免调整
        """
        cwnd_before = df['cwnd'].iloc[index-1]
        cwnd_after = df['cwnd'].iloc[index]
        drop_ratio = (cwnd_before - cwnd_after) / cwnd_before

        if abs(drop_ratio - 0.5) < 0.05:
            return "可能的丢包触发快速恢复（CWND减半）"
        elif drop_ratio > 0.7:
            return "可能的超时触发慢启动（CWND大幅下降）"
        else:
            return "拥塞避免调整"
```

---

### 2.4.15 WindowAnalyzer - CWND模式识别

**实现需求**: FR-SOCKET-DET-002

```python
@dataclass
class CWNDPatterns:
    """CWND变化模式"""
    slow_start_detected: bool
    congestion_avoidance_ratio: float
    fast_recovery_count: int
    cwnd_growth_rate: float  # 平均增长速率

@dataclass
class WindowLimits:
    """窗口限制统计"""
    cwnd_limited_ratio: float
    rwnd_limited_ratio: float
    sndbuf_limited_ratio: float

class WindowAnalyzer:
    """窗口分析器（辅助类）"""

    def detect_cwnd_patterns(self, df: pd.DataFrame) -> CWNDPatterns:
        """
        检测CWND变化模式

        实现需求: FR-SOCKET-DET-002

        识别模式:
        1. 慢启动阶段：CWND指数增长
        2. 拥塞避免阶段：CWND线性增长
        3. 快速恢复：CWND减半事件
        """
        cwnd = df['cwnd']
        ssthresh = df['ssthresh']

        # 检测慢启动
        slow_start_detected = (cwnd < ssthresh).any()

        # 计算拥塞避免时间占比
        congestion_avoidance = (cwnd >= ssthresh).sum() / len(df)

        # 检测快速恢复（CWND减半事件）
        fast_recovery_count = self._count_fast_recovery(df)

        # 计算CWND增长速率
        cwnd_growth_rate = self._compute_cwnd_growth_rate(df)

        return CWNDPatterns(
            slow_start_detected=slow_start_detected,
            congestion_avoidance_ratio=congestion_avoidance,
            fast_recovery_count=fast_recovery_count,
            cwnd_growth_rate=cwnd_growth_rate
        )

    def _count_fast_recovery(self, df: pd.DataFrame) -> int:
        """
        统计快速恢复次数

        快速恢复特征：CWND突然减半
        """
        count = 0
        cwnd_values = df['cwnd'].values

        for i in range(1, len(cwnd_values)):
            if cwnd_values[i-1] > 0:
                ratio = cwnd_values[i] / cwnd_values[i-1]
                if 0.45 < ratio < 0.55:  # 接近减半
                    count += 1

        return count

    def _compute_cwnd_growth_rate(self, df: pd.DataFrame) -> float:
        """
        计算CWND增长速率（线性回归斜率）
        """
        from scipy.stats import linregress

        x = np.arange(len(df))
        y = df['cwnd'].values

        slope, _, _, _, _ = linregress(x, y)

        return slope

    def analyze_window_limits(self, df: pd.DataFrame) -> WindowLimits:
        """
        分析窗口限制时间占比

        实现需求: FR-SOCKET-DET-001

        检测逻辑:
        1. CWND Limited: inflight_data >= CWND × MSS × 95%
        2. RWND Limited: inflight_data >= snd_wnd × 95%
        3. SNDBUF Limited: socket_tx_queue >= socket_tx_buffer × 95%
        """
        # CWND Limited
        if 'packets_out' in df.columns and 'cwnd' in df.columns:
            cwnd_limited = (df['packets_out'] >= df['cwnd'] * 0.95)
            cwnd_limited_ratio = cwnd_limited.sum() / len(df)
        else:
            cwnd_limited_ratio = 0.0

        # RWND Limited
        if 'inflight_data' in df.columns and 'snd_wnd' in df.columns:
            rwnd_limited = (df['inflight_data'] >= df['snd_wnd'] * 0.95)
            rwnd_limited_ratio = rwnd_limited.sum() / len(df)
        else:
            rwnd_limited_ratio = 0.0

        # SNDBUF Limited
        if 'socket_tx_queue' in df.columns and 'socket_tx_buffer' in df.columns:
            sndbuf_limited = (df['socket_tx_queue'] >= df['socket_tx_buffer'] * 0.95)
            sndbuf_limited_ratio = sndbuf_limited.sum() / len(df)
        else:
            sndbuf_limited_ratio = 0.0

        return WindowLimits(
            cwnd_limited_ratio=cwnd_limited_ratio,
            rwnd_limited_ratio=rwnd_limited_ratio,
            sndbuf_limited_ratio=sndbuf_limited_ratio
        )
```

---

### 2.4.16 DetailedAnalyzer - 速率深度分析

**实现需求**: FR-SOCKET-DET-003

```python
@dataclass
class RateDetailedResult:
    """速率深度分析结果"""
    # 时序趋势
    pacing_trends: RateTrends
    delivery_trends: RateTrends

    # Rate限制类型
    rate_limits: RateLimits

    # 指标相关性
    correlations: Correlations

class DetailedAnalyzer:
    def analyze_rate_detailed(self,
                             client_df: pd.DataFrame,
                             server_df: pd.DataFrame,
                             bandwidth: float) -> RateDetailedResult:
        """
        速率深度分析

        实现需求: FR-SOCKET-DET-003

        分析内容:
        1. 时序趋势分析
        2. Rate限制类型识别
        3. 指标相关性分析
        """
        # 时序趋势分析
        pacing_trends = self.rate_analyzer.analyze_trends(
            client_df['pacing_rate'], metric_name='Pacing Rate'
        )
        delivery_trends = self.rate_analyzer.analyze_trends(
            client_df['delivery_rate'], metric_name='Delivery Rate'
        )

        # Rate限制类型
        rate_limits = self.rate_analyzer.identify_rate_limits(client_df, bandwidth)

        # 指标相关性分析
        correlations = self.rate_analyzer.compute_correlations(client_df)

        return RateDetailedResult(
            pacing_trends=pacing_trends,
            delivery_trends=delivery_trends,
            rate_limits=rate_limits,
            correlations=correlations
        )
```

---

### 2.4.17 RateAnalyzer - Rate限制识别

**实现需求**: FR-SOCKET-DET-004

```python
@dataclass
class RateTrends:
    """速率趋势"""
    rising_periods: List[Tuple[datetime, datetime]]
    falling_periods: List[Tuple[datetime, datetime]]
    stable_periods: List[Tuple[datetime, datetime]]
    volatility: float  # 波动性

@dataclass
class RateLimits:
    """Rate限制类型"""
    pacing_limited_ratio: float
    network_limited_ratio: float
    app_limited_ratio: float

class RateAnalyzer:
    """速率分析器（辅助类）"""

    def analyze_trends(self, data: pd.Series, metric_name: str) -> RateTrends:
        """
        分析速率趋势

        实现需求: FR-SOCKET-DET-003

        算法:
        1. 使用滑动窗口计算瞬时斜率
        2. 识别上升/下降/稳定时段
        3. 计算波动性（标准差/均值）
        """
        # 计算滑动窗口斜率
        window_size = 10
        slopes = []

        for i in range(window_size, len(data)):
            window_data = data.iloc[i-window_size:i]
            x = np.arange(len(window_data))
            y = window_data.values

            from scipy.stats import linregress
            slope, _, _, _, _ = linregress(x, y)
            slopes.append((data.index[i], slope))

        # 识别趋势时段
        threshold = data.mean() * 0.01  # 1%阈值

        rising_periods = []
        falling_periods = []
        stable_periods = []

        current_trend = None
        period_start = None

        for timestamp, slope in slopes:
            if slope > threshold:
                trend = 'RISING'
            elif slope < -threshold:
                trend = 'FALLING'
            else:
                trend = 'STABLE'

            if trend != current_trend:
                if current_trend and period_start:
                    # 保存上一个时段
                    if current_trend == 'RISING':
                        rising_periods.append((period_start, timestamp))
                    elif current_trend == 'FALLING':
                        falling_periods.append((period_start, timestamp))
                    else:
                        stable_periods.append((period_start, timestamp))

                current_trend = trend
                period_start = timestamp

        # 计算波动性
        volatility = data.std() / data.mean() if data.mean() > 0 else 0

        return RateTrends(
            rising_periods=rising_periods,
            falling_periods=falling_periods,
            stable_periods=stable_periods,
            volatility=volatility
        )

    def identify_rate_limits(self, df: pd.DataFrame, bandwidth: float) -> RateLimits:
        """
        识别Rate限制类型

        实现需求: FR-SOCKET-DET-004

        限制类型:
        1. Pacing限制: Delivery Rate ≈ Pacing Rate
        2. 网络限制: Delivery Rate << Pacing Rate
        3. 应用限制: 基于app_limited标记
        """
        pacing = df['pacing_rate']
        delivery = df['delivery_rate']

        # Pacing限制
        pacing_limited = (abs(delivery - pacing) / pacing < 0.05)
        pacing_limited_ratio = pacing_limited.sum() / len(df)

        # 网络限制
        network_limited = ((pacing - delivery) / pacing > 0.2)
        network_limited_ratio = network_limited.sum() / len(df)

        # 应用限制
        if 'app_limited' in df.columns:
            app_limited_ratio = df['app_limited'].sum() / len(df)
        else:
            app_limited_ratio = 0.0

        return RateLimits(
            pacing_limited_ratio=pacing_limited_ratio,
            network_limited_ratio=network_limited_ratio,
            app_limited_ratio=app_limited_ratio
        )
```

---

### 2.4.18 DetailedAnalyzer - 重传突发检测

**实现需求**: FR-SOCKET-DET-005

```python
@dataclass
class RetransBurst:
    """重传突发事件"""
    start_time: datetime
    end_time: datetime
    duration: float  # 秒
    retrans_count: int
    avg_retrans_rate: float
    rtt_correlation: Optional[float]  # 与RTT变化的相关性
    cwnd_correlation: Optional[float]  # 与CWND变化的相关性

@dataclass
class RetransDetailedResult:
    """重传深度分析结果"""
    # 逐周期增量分析
    incremental_retrans: pd.DataFrame

    # 重传突发事件
    burst_events: List[RetransBurst]

    # 虚假重传分析
    spurious_retrans_distribution: Dict[datetime, int]

class DetailedAnalyzer:
    def analyze_retrans_detailed(self,
                                client_df: pd.DataFrame,
                                server_df: pd.DataFrame) -> RetransDetailedResult:
        """
        重传深度分析

        实现需求: FR-SOCKET-DET-005, FR-SOCKET-DET-006

        分析内容:
        1. 逐周期增量分析
        2. 重传突发检测
        3. 虚假重传时间分布
        """
        # 逐周期增量分析
        incremental_retrans = self._compute_incremental_retrans(client_df)

        # 重传突发检测
        burst_events = self._detect_retrans_bursts(client_df, incremental_retrans)

        # 虚假重传分布
        spurious_dist = self._analyze_spurious_retrans_distribution(client_df)

        return RetransDetailedResult(
            incremental_retrans=incremental_retrans,
            burst_events=burst_events,
            spurious_retrans_distribution=spurious_dist
        )

    def _compute_incremental_retrans(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        计算逐周期重传增量

        返回DataFrame包含列:
        - timestamp
        - retrans_delta (重传增量)
        - cumulative_retrans (累计重传)
        - instant_retrans_rate (瞬时重传率)
        """
        if 'retrans' not in df.columns:
            return pd.DataFrame()

        incremental = pd.DataFrame()
        incremental['timestamp'] = df.index
        incremental['cumulative_retrans'] = df['retrans'].values

        # 计算增量
        incremental['retrans_delta'] = incremental['cumulative_retrans'].diff().fillna(0)

        # 计算瞬时重传率（需要总发包数）
        if 'packets_sent' in df.columns:
            packets_delta = df['packets_sent'].diff().fillna(0)
            incremental['instant_retrans_rate'] = (
                incremental['retrans_delta'] / packets_delta
            ).fillna(0) * 100  # 百分比

        return incremental

    def _detect_retrans_bursts(self,
                               df: pd.DataFrame,
                               incremental: pd.DataFrame) -> List[RetransBurst]:
        """
        检测重传突发事件

        突发定义:
        - 连续多个周期重传率 > 阈值（如5%）
        - 持续时间 >= 最小时长（如5秒）
        """
        bursts = []

        if incremental.empty or 'instant_retrans_rate' not in incremental.columns:
            return bursts

        threshold = 5.0  # 5%重传率阈值
        min_duration = 5.0  # 最小持续5秒

        high_retrans = incremental['instant_retrans_rate'] > threshold

        in_burst = False
        burst_start = None
        burst_retrans_count = 0

        for i, (idx, row) in enumerate(incremental.iterrows()):
            if high_retrans.iloc[i]:
                if not in_burst:
                    # 开始新突发
                    in_burst = True
                    burst_start = i
                    burst_retrans_count = 0

                burst_retrans_count += row['retrans_delta']
            else:
                if in_burst:
                    # 突发结束
                    burst_end = i - 1
                    start_time = incremental.iloc[burst_start]['timestamp']
                    end_time = incremental.iloc[burst_end]['timestamp']
                    duration = (end_time - start_time).total_seconds()

                    if duration >= min_duration:
                        # 计算与RTT、CWND的相关性
                        rtt_corr = self._compute_burst_rtt_correlation(df, burst_start, burst_end)
                        cwnd_corr = self._compute_burst_cwnd_correlation(df, burst_start, burst_end)

                        bursts.append(RetransBurst(
                            start_time=start_time,
                            end_time=end_time,
                            duration=duration,
                            retrans_count=int(burst_retrans_count),
                            avg_retrans_rate=incremental.iloc[burst_start:burst_end+1]['instant_retrans_rate'].mean(),
                            rtt_correlation=rtt_corr,
                            cwnd_correlation=cwnd_corr
                        ))

                    in_burst = False

        return bursts

    def _compute_burst_rtt_correlation(self,
                                       df: pd.DataFrame,
                                       start_idx: int,
                                       end_idx: int) -> Optional[float]:
        """
        计算突发期间重传与RTT的相关性
        """
        if 'rtt' not in df.columns:
            return None

        # 比较突发前后RTT变化
        if start_idx > 0:
            rtt_before = df['rtt'].iloc[:start_idx].mean()
            rtt_during = df['rtt'].iloc[start_idx:end_idx+1].mean()

            return (rtt_during - rtt_before) / rtt_before if rtt_before > 0 else None

        return None
```

---

### 2.4.19 DetailedAnalyzer - 虚假重传分布

**实现需求**: FR-SOCKET-DET-006

```python
class DetailedAnalyzer:
    def _analyze_spurious_retrans_distribution(self,
                                               df: pd.DataFrame) -> Dict[datetime, int]:
        """
        虚假重传时间分布

        实现需求: FR-SOCKET-DET-006

        返回: 时间戳 -> 虚假重传次数的映射
        """
        if 'spurious_retrans' not in df.columns:
            return {}

        distribution = {}

        for timestamp, row in df.iterrows():
            spurious = row['spurious_retrans']
            if spurious > 0:
                distribution[timestamp] = spurious

        return distribution
```

---

### 2.4.20 DetailedAnalyzer - Buffer压力时序分析

**实现需求**: FR-SOCKET-DET-007

```python
@dataclass
class BufferDetailedResult:
    """Buffer深度分析结果"""
    # 发送侧时序分析
    send_q_timeseries: pd.DataFrame
    socket_tx_pressure_timeseries: pd.DataFrame

    # 接收侧时序分析
    recv_q_timeseries: pd.DataFrame
    socket_rx_pressure_timeseries: pd.DataFrame

    # 压力分级统计
    pressure_distribution: Dict[str, float]  # HIGH/MEDIUM/LOW占比

class DetailedAnalyzer:
    def analyze_buffer_detailed(self,
                                client_df: pd.DataFrame,
                                server_df: pd.DataFrame) -> BufferDetailedResult:
        """
        Buffer压力时序分析

        实现需求: FR-SOCKET-DET-007

        分析内容:
        1. 发送侧压力时序
        2. 接收侧压力时序
        3. 压力分级统计
        """
        # 发送侧时序
        send_q_ts = self._extract_timeseries(client_df, 'send_q')
        socket_tx_pressure = self._compute_buffer_pressure(
            client_df, 'socket_tx_queue', 'socket_tx_buffer'
        )

        # 接收侧时序
        recv_q_ts = self._extract_timeseries(server_df, 'recv_q')
        socket_rx_pressure = self._compute_buffer_pressure(
            server_df, 'socket_rx_queue', 'socket_rx_buffer'
        )

        # 压力分级
        pressure_dist = self._compute_pressure_distribution(socket_tx_pressure)

        return BufferDetailedResult(
            send_q_timeseries=send_q_ts,
            socket_tx_pressure_timeseries=socket_tx_pressure,
            recv_q_timeseries=recv_q_ts,
            socket_rx_pressure_timeseries=socket_rx_pressure,
            pressure_distribution=pressure_dist
        )

    def _compute_buffer_pressure(self,
                                 df: pd.DataFrame,
                                 queue_field: str,
                                 buffer_field: str) -> pd.DataFrame:
        """
        计算Buffer压力时序

        返回DataFrame包含:
        - timestamp
        - utilization (利用率)
        - pressure_level (HIGH/MEDIUM/LOW)
        """
        if queue_field not in df.columns or buffer_field not in df.columns:
            return pd.DataFrame()

        pressure_df = pd.DataFrame()
        pressure_df['timestamp'] = df.index
        pressure_df['utilization'] = df[queue_field] / df[buffer_field]

        # 压力分级
        def classify_pressure(util):
            if util > 0.9:
                return 'HIGH'
            elif util > 0.7:
                return 'MEDIUM'
            else:
                return 'LOW'

        pressure_df['pressure_level'] = pressure_df['utilization'].apply(classify_pressure)

        return pressure_df

    def _compute_pressure_distribution(self, pressure_df: pd.DataFrame) -> Dict[str, float]:
        """计算压力分级分布"""
        if pressure_df.empty:
            return {}

        total = len(pressure_df)
        counts = pressure_df['pressure_level'].value_counts()

        return {
            'HIGH': counts.get('HIGH', 0) / total,
            'MEDIUM': counts.get('MEDIUM', 0) / total,
            'LOW': counts.get('LOW', 0) / total
        }
```

---

### 2.4.21 RecommendationEngine - Buffer配置建议

**实现需求**: FR-SOCKET-DET-008

```python
@dataclass
class BufferRecommendation:
    """Buffer配置建议"""
    recommended_tx_size: int
    recommended_rx_size: int
    current_tx_size: int
    current_rx_size: int
    rationale: str
    commands: List[str]

class RecommendationEngine:
    def recommend_buffer_size(self,
                             bdp: float,
                             current_tx_size: int,
                             current_rx_size: int) -> BufferRecommendation:
        """
        Buffer配置建议

        实现需求: FR-SOCKET-DET-008

        计算公式:
        Recommended_Size = max(BDP * 2, current_size * 1.5)
        """
        # 发送Buffer建议 (基于BDP)
        recommended_tx = max(int(bdp * 2), int(current_tx_size * 1.5))

        # 接收Buffer建议
        recommended_rx = max(int(bdp * 2), int(current_rx_size * 1.5))

        # 生成sysctl命令
        commands = [
            f'sysctl -w net.ipv4.tcp_wmem="4096 16384 {recommended_tx}"',
            f'sysctl -w net.ipv4.tcp_rmem="4096 87380 {recommended_rx}"'
        ]

        rationale = (
            f'基于BDP={bdp:.0f}字节，建议:\n'
            f'  - 发送Buffer: {current_tx_size} → {recommended_tx} ({recommended_tx/current_tx_size:.1f}x)\n'
            f'  - 接收Buffer: {current_rx_size} → {recommended_rx} ({recommended_rx/current_rx_size:.1f}x)'
        )

        return BufferRecommendation(
            recommended_tx_size=recommended_tx,
            recommended_rx_size=recommended_rx,
            current_tx_size=current_tx_size,
            current_rx_size=current_rx_size,
            rationale=rationale,
            commands=commands
        )
```

---

### 2.4.22 DetailedAnalyzer - 时序数据导出

**实现需求**: FR-SOCKET-DET-009

```python
class DetailedAnalyzer:
    def export_timeseries(self, aligned_df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
        """
        导出时序数据用于绘图

        实现需求: FR-SOCKET-DET-009

        导出文件:
        - rtt_timeseries.csv
        - cwnd_timeseries.csv
        - rate_timeseries.csv
        - buffer_timeseries.csv
        - retrans_timeseries.csv

        格式: timestamp, metric1, metric2, ...
        """
        timeseries_data = {}

        # RTT时序
        if 'rtt_client' in aligned_df.columns:
            rtt_df = pd.DataFrame()
            rtt_df['timestamp'] = aligned_df.index
            rtt_df['rtt_client'] = aligned_df['rtt_client']
            rtt_df['rtt_server'] = aligned_df.get('rtt_server', None)
            rtt_df['rttvar_client'] = aligned_df.get('rttvar_client', None)
            timeseries_data['rtt'] = rtt_df

        # CWND时序
        if 'cwnd_client' in aligned_df.columns:
            cwnd_df = pd.DataFrame()
            cwnd_df['timestamp'] = aligned_df.index
            cwnd_df['cwnd_client'] = aligned_df['cwnd_client']
            cwnd_df['cwnd_server'] = aligned_df.get('cwnd_server', None)
            cwnd_df['ssthresh_client'] = aligned_df.get('ssthresh_client', None)
            timeseries_data['cwnd'] = cwnd_df

        # Rate时序
        if 'pacing_rate_client' in aligned_df.columns:
            rate_df = pd.DataFrame()
            rate_df['timestamp'] = aligned_df.index
            rate_df['pacing_rate_client'] = aligned_df['pacing_rate_client']
            rate_df['delivery_rate_client'] = aligned_df['delivery_rate_client']
            timeseries_data['rate'] = rate_df

        # Buffer时序
        if 'socket_tx_queue_client' in aligned_df.columns:
            buffer_df = pd.DataFrame()
            buffer_df['timestamp'] = aligned_df.index
            buffer_df['send_q_client'] = aligned_df['send_q_client']
            buffer_df['recv_q_server'] = aligned_df.get('recv_q_server', None)
            buffer_df['socket_tx_queue_client'] = aligned_df['socket_tx_queue_client']
            buffer_df['socket_rx_queue_server'] = aligned_df.get('socket_rx_queue_server', None)
            timeseries_data['buffer'] = buffer_df

        # 重传时序
        if 'retrans_client' in aligned_df.columns:
            retrans_df = pd.DataFrame()
            retrans_df['timestamp'] = aligned_df.index
            retrans_df['retrans_client'] = aligned_df['retrans_client']
            retrans_df['retrans_server'] = aligned_df.get('retrans_server', None)
            timeseries_data['retrans'] = retrans_df

        return timeseries_data
```

---

### 2.4.23 RateAnalyzer - 相关性分析

**实现需求**: FR-SOCKET-DET-010

```python
@dataclass
class Correlations:
    """指标相关性"""
    pacing_vs_cwnd: float
    pacing_vs_rtt: float
    delivery_vs_pacing: float
    rate_vs_buffer: float

class RateAnalyzer:
    def compute_correlations(self, df: pd.DataFrame) -> Correlations:
        """
        计算指标之间的相关性

        实现需求: FR-SOCKET-DET-010

        相关性分析:
        1. Pacing Rate vs CWND
        2. Pacing Rate vs RTT
        3. Delivery Rate vs Pacing Rate
        4. Rate vs Buffer占用
        """
        correlations = {}

        # Pacing Rate vs CWND
        if 'pacing_rate' in df.columns and 'cwnd' in df.columns:
            correlations['pacing_vs_cwnd'] = df[['pacing_rate', 'cwnd']].corr().iloc[0, 1]
        else:
            correlations['pacing_vs_cwnd'] = None

        # Pacing Rate vs RTT
        if 'pacing_rate' in df.columns and 'rtt' in df.columns:
            correlations['pacing_vs_rtt'] = df[['pacing_rate', 'rtt']].corr().iloc[0, 1]
        else:
            correlations['pacing_vs_rtt'] = None

        # Delivery Rate vs Pacing Rate
        if 'delivery_rate' in df.columns and 'pacing_rate' in df.columns:
            correlations['delivery_vs_pacing'] = df[['delivery_rate', 'pacing_rate']].corr().iloc[0, 1]
        else:
            correlations['delivery_vs_pacing'] = None

        # Rate vs Buffer
        if 'delivery_rate' in df.columns and 'socket_tx_queue' in df.columns:
            correlations['rate_vs_buffer'] = df[['delivery_rate', 'socket_tx_queue']].corr().iloc[0, 1]
        else:
            correlations['rate_vs_buffer'] = None

        return Correlations(
            pacing_vs_cwnd=correlations.get('pacing_vs_cwnd'),
            pacing_vs_rtt=correlations.get('pacing_vs_rtt'),
            delivery_vs_pacing=correlations.get('delivery_vs_pacing'),
            rate_vs_buffer=correlations.get('rate_vs_buffer')
        )
```

---

### 2.4.24 BottleneckFinder - 发送路径瓶颈

**实现需求**: FR-SOCKET-PIPE-001

```python
class BottleneckFinder:
    """Pipeline瓶颈识别器"""

    def __init__(self):
        self.rules = [
            # 发送路径规则（6条）
            AppSendLimitRule(),           # 规则1
            SocketTxBufferRule(),         # 规则2
            TCPWriteQueueRule(),          # 规则3
            CwndLimitRule(),              # 规则4
            RwndLimitRule(),              # 规则5
            NetworkBandwidthRule(),       # 规则6
            # 接收路径规则（4条）
            NetworkRecvRule(),            # 规则7
            TCPRxBufferRule(),            # 规则8
            SocketRxBufferRule(),         # 规则9
            AppReadLimitRule(),           # 规则10
        ]

    def find_send_path_bottlenecks(self, df: pd.DataFrame) -> List[Bottleneck]:
        """
        识别发送路径的6个瓶颈点

        发送路径:
        应用 write() → Socket层 → TCP层 → 网络层
        """
        bottlenecks = []

        # 应用前6个规则（发送路径）
        for rule in self.rules[:6]:
            result = rule.detect(df)
            if result:
                bottlenecks.append(result)

        return bottlenecks
```

---

### 2.4.26 BottleneckRule - 规则设计

**实现需求**: FR-SOCKET-PIPE-003

```python
class SocketTxBufferRule(BottleneckRule):
    """规则2: Socket发送Buffer瓶颈检测"""

    rule_id = "SOCKET_TX_BUFFER"

    def detect(self, data: pd.DataFrame) -> Optional[Bottleneck]:
        """
        检测Socket发送Buffer瓶颈

        检测条件: socket_tx_queue > 90% socket_tx_buffer
        """
        if 'socket_tx_queue' not in data.columns or 'socket_tx_buffer' not in data.columns:
            return None

        avg_queue = data['socket_tx_queue'].mean()
        buffer_limit = data['socket_tx_buffer'].iloc[0]
        utilization = avg_queue / buffer_limit if buffer_limit > 0 else 0

        if utilization < 0.7:
            return None

        severity = 'CRITICAL' if utilization > 0.9 else 'WARNING'

        return Bottleneck(
            point="Socket发送Buffer",
            layer="Socket层",
            severity=severity,
            utilization=utilization,
            diagnosis=f"发送buffer利用率达{utilization*100:.1f}%",
            recommendation=(
                f"建议增大发送buffer:\n"
                f"  sysctl -w net.ipv4.tcp_wmem=\"4096 16384 {int(buffer_limit * 1.5)}\""
            ),
            evidence={
                'avg_queue': avg_queue,
                'buffer_limit': buffer_limit,
                'utilization': utilization
            }
        )
```

---

### 2.4.25 BottleneckFinder - 接收路径瓶颈

**实现需求**: FR-SOCKET-PIPE-002

```python
class BottleneckFinder:
    def find_recv_path_bottlenecks(self, df: pd.DataFrame) -> List[Bottleneck]:
        """
        识别接收路径的4个瓶颈点

        接收路径:
        网络层 → TCP层 → Socket层 → 应用 read()

        规则7-10:
        - NetworkRecvRule: 网络丢包/延迟
        - TCPRxBufferRule: TCP接收队列满
        - SocketRxBufferRule: Socket接收Buffer满
        - AppReadLimitRule: 应用读取慢
        """
        bottlenecks = []

        # 应用后4个规则（接收路径）
        for rule in self.rules[6:10]:
            result = rule.detect(df)
            if result:
                bottlenecks.append(result)

        return bottlenecks
```

---

### 2.4.27 BottleneckFinder - 主要瓶颈识别

**实现需求**: FR-SOCKET-PIPE-004

```python
@dataclass
class Bottleneck:
    """瓶颈点"""
    point: str
    layer: str
    severity: str  # CRITICAL/WARNING/INFO
    utilization: float
    diagnosis: str
    recommendation: str
    evidence: Dict[str, Any]

class BottleneckFinder:
    def identify_primary(self, bottlenecks: List[Bottleneck]) -> Bottleneck:
        """
        从多个瓶颈中识别主要瓶颈

        实现需求: FR-SOCKET-PIPE-004

        判断标准:
        1. CRITICAL > WARNING > INFO
        2. 同级别比较utilization
        """
        if not bottlenecks:
            return None

        # 严重程度权重
        severity_weight = {
            'CRITICAL': 3,
            'WARNING': 2,
            'INFO': 1
        }

        # 排序：先按严重程度，再按utilization
        primary = max(
            bottlenecks,
            key=lambda b: (severity_weight.get(b.severity, 0), b.utilization)
        )

        return primary
```

---

### 2.4.28 PipelineReporter - 健康度总览

**实现需求**: FR-SOCKET-PIPE-005

```python
@dataclass
class HealthOverview:
    """Pipeline健康度总览"""
    overall_health: str  # HEALTHY/DEGRADED/CRITICAL
    health_score: float  # 0-100
    bottleneck_count: int
    critical_issues: int
    warnings: int

class PipelineReporter:
    def generate_health_overview(self, bottlenecks: List[Bottleneck]) -> HealthOverview:
        """
        生成Pipeline健康度总览

        实现需求: FR-SOCKET-PIPE-005

        健康度评分:
        - 无瓶颈: 100分
        - 每个WARNING: -10分
        - 每个CRITICAL: -30分
        """
        critical_count = sum(1 for b in bottlenecks if b.severity == 'CRITICAL')
        warning_count = sum(1 for b in bottlenecks if b.severity == 'WARNING')

        # 计算健康度分数
        health_score = 100
        health_score -= critical_count * 30
        health_score -= warning_count * 10
        health_score = max(0, health_score)

        # 健康等级
        if health_score >= 80:
            overall_health = 'HEALTHY'
        elif health_score >= 50:
            overall_health = 'DEGRADED'
        else:
            overall_health = 'CRITICAL'

        return HealthOverview(
            overall_health=overall_health,
            health_score=health_score,
            bottleneck_count=len(bottlenecks),
            critical_issues=critical_count,
            warnings=warning_count
        )
```

---

### 2.4.29 PipelineReporter - 瓶颈详细诊断

**实现需求**: FR-SOCKET-PIPE-006

```python
@dataclass
class BottleneckReport:
    """瓶颈详细报告"""
    bottleneck: Bottleneck
    root_cause: str
    impact: str
    action_items: List[str]

class PipelineReporter:
    def generate_bottleneck_details(self, bottleneck: Bottleneck) -> BottleneckReport:
        """
        生成瓶颈详细诊断报告

        实现需求: FR-SOCKET-PIPE-006

        包含:
        1. 根因分析
        2. 影响评估
        3. 行动项列表
        """
        # 根因分析
        root_cause = self._analyze_root_cause(bottleneck)

        # 影响评估
        impact = self._assess_impact(bottleneck)

        # 行动项
        action_items = self._generate_action_items(bottleneck)

        return BottleneckReport(
            bottleneck=bottleneck,
            root_cause=root_cause,
            impact=impact,
            action_items=action_items
        )

    def _analyze_root_cause(self, bottleneck: Bottleneck) -> str:
        """根因分析"""
        if bottleneck.point == 'CWND':
            return '拥塞窗口限制了发送速率，可能由于网络拥塞或丢包'
        elif bottleneck.point == 'Socket发送Buffer':
            return 'Socket发送缓冲区满，应用写入速度超过网络发送速度'
        else:
            return bottleneck.diagnosis

    def _assess_impact(self, bottleneck: Bottleneck) -> str:
        """影响评估"""
        if bottleneck.severity == 'CRITICAL':
            return '严重影响吞吐量，可能导致性能下降50%以上'
        elif bottleneck.severity == 'WARNING':
            return '中等影响，可能导致性能下降20-50%'
        else:
            return '轻微影响'

    def _generate_action_items(self, bottleneck: Bottleneck) -> List[str]:
        """生成行动项"""
        items = []
        items.append(f'1. 立即执行: {bottleneck.recommendation}')
        items.append(f'2. 监控指标: 观察 {bottleneck.point} 的利用率变化')
        items.append('3. 验证效果: 重新运行分析确认问题解决')
        return items
```

---

### 2.4.30 BottleneckFinder - 优化优先级排序

**实现需求**: FR-SOCKET-PIPE-007

```python
class BottleneckFinder:
    def rank_priority(self, bottlenecks: List[Bottleneck]) -> List[Bottleneck]:
        """
        按优化优先级排序瓶颈

        实现需求: FR-SOCKET-PIPE-007

        排序标准:
        1. 严重程度 (CRITICAL > WARNING > INFO)
        2. 利用率 (高 > 低)
        3. 层次 (越靠近应用层优先级越高)
        """
        layer_priority = {
            '应用层': 4,
            'Socket层': 3,
            'TCP层': 2,
            '网络层': 1
        }

        severity_priority = {
            'CRITICAL': 3,
            'WARNING': 2,
            'INFO': 1
        }

        ranked = sorted(
            bottlenecks,
            key=lambda b: (
                severity_priority.get(b.severity, 0),
                b.utilization,
                layer_priority.get(b.layer, 0)
            ),
            reverse=True
        )

        return ranked
```

---

### 2.4.31 DiagnosisEngine - 整体评估和建议

**实现需求**: FR-SOCKET-PIPE-008

```python
@dataclass
class ActionPlan:
    """行动计划"""
    priority: int
    action: str
    expected_impact: str
    estimated_effort: str

@dataclass
class Diagnosis:
    """诊断结果"""
    summary: str
    details: str
    severity: str

class DiagnosisEngine:
    def generate_next_steps(self, bottlenecks: List[Bottleneck]) -> List[ActionPlan]:
        """
        生成下一步行动建议

        实现需求: FR-SOCKET-PIPE-008

        优先级排序:
        1. CRITICAL瓶颈优先
        2. 快速见效的优化优先
        3. 低成本优化优先
        """
        action_plans = []

        for i, bottleneck in enumerate(bottlenecks[:3], 1):  # 只显示Top 3
            # 评估影响和工作量
            if bottleneck.severity == 'CRITICAL':
                expected_impact = '高 (预期性能提升30-50%)'
                effort = '中等 (需要系统重启)'
            else:
                expected_impact = '中等 (预期性能提升10-20%)'
                effort = '低 (动态调整，无需重启)'

            action_plans.append(ActionPlan(
                priority=i,
                action=bottleneck.recommendation,
                expected_impact=expected_impact,
                estimated_effort=effort
            ))

        return action_plans

    def diagnose_bottleneck(self,
                           bottleneck: Bottleneck,
                           context: AnalysisContext) -> Diagnosis:
        """
        瓶颈深度诊断

        实现需求: FR-SOCKET-PIPE-008

        结合上下文信息进行根因分析
        """
        summary = f'{bottleneck.layer}的{bottleneck.point}成为瓶颈'

        details = f'''
        诊断详情:
        - 利用率: {bottleneck.utilization*100:.1f}%
        - 证据: {bottleneck.evidence}
        - 诊断: {bottleneck.diagnosis}

        可能原因:
        '''

        # 根据瓶颈类型添加可能原因
        if 'CWND' in bottleneck.point:
            details += '1. 网络存在丢包或延迟\n'
            details += '2. ssthresh设置过小\n'
            details += '3. BBR等算法参数需要调优'

        elif 'Buffer' in bottleneck.point:
            details += '1. 默认Buffer配置过小\n'
            details += '2. 应用发送/接收速率不均衡\n'
            details += f'3. BDP需求: {context.bdp:.0f}字节'

        return Diagnosis(
            summary=summary,
            details=details,
            severity=bottleneck.severity
        )
```

---

# 附录

## 附录: 设计决策

### DD-001: 架构风格选择

**选择**: 管道-过滤器 + 分层架构

**理由**:
1. 数据处理本质是管道：输入 → 解析 → 统计 → 分析 → 输出
2. 分层提供清晰的职责划分
3. 符合UNIX哲学：做一件事并做好

---

### DD-002: 双端数据设计

**背景**: Pipeline分析需要完整的双向视图

**决策**: 强制要求同时提供Client和Server端数据

**理由**:
1. 发送路径分析需要发送方数据
2. 接收路径分析需要接收方数据
3. 双向综合分析才能全面识别瓶颈

---

## 附录: 数据模型

```python
# PCAP工具数据模型
@dataclass
class Packet:
    frame_number: int
    timestamp: datetime
    frame_len: int
    eth_src: str
    eth_dst: str
    ip_src: str
    ip_dst: str
    # ... TCP/UDP字段

# Socket工具数据模型
@dataclass
class SamplePoint:
    timestamp: datetime
    connection: FiveTuple
    state: str
    side: str
    metrics: Dict[str, float]
```

---

**文档结束**
