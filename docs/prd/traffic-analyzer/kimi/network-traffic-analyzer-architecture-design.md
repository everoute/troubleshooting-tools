# 网络流量分析工具 - 架构设计文档

**文档版本**: v1.0
**创建日期**: 2024-11-16
**最后更新**: 2024-11-16

**文档目的**: 本文档基于《网络流量分析工具需求规格说明书》，详细阐述两个分析工具的架构设计、模块划分、数据流、算法设计和实现细节。

---

## 目录

1. [总体架构设计](#1-总体架构设计)
2. [PCAP分析工具设计](#2-pcap分析工具设计)
3. [TCPSocket分析工具设计](#3-tcpsocket分析工具设计)
4. [通用组件设计](#4-通用组件设计)
5. [数据模型设计](#5-数据模型设计)
6. [可视化输出设计](#6-可视化输出设计)
7. [不确定问题记录](#7-不确定问题记录)
8. [附录](#8-附录)

---

## 1. 总体架构设计

### 1.1 系统架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                    网络流量分析工具套件                           │
│                  Network Traffic Analyzer Suite                 │
└─────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
        ┌───────────▼──────┐ ┌─────▼──────┐ ┌──────▼────────┐
        │  PCAP分析工具    │ │ TCPSocket  │ │  通用组件库   │
        │  PCAP Analyzer   │ │  Analyzer  │ │    (Common)   │
        └──────────────────┘ └────────────┘ └───────────────┘
                  │                    │              │
                  │                    │              │
                  ▼                    ▼              ▼
         ┌────────────────┐   ┌──────────────┐  ┌─────────┐
         │  tshark/tcpdump│   │    ss命令    │  │libpcap  │
         │   （输入源）   │   │  采集数据    │  │解析库   │
         └────────────────┘   └──────────────┘  └─────────┘
```

### 1.2 架构风格

- **架构模式**: 模块化分层架构 + 插件化设计
- **设计理念**:
  - 工具独立: 两个主工具可独立运行
  - 组件复用: 通用组件库被两个工具共享
  - 扩展性: 易于添加新的分析模块或输出格式
  - 性能: 支持大文件流式处理，内存可控

### 1.3 技术栈选型

| 层级 | 技术 | 版本要求 | 说明 |
|------|------|----------|------|
| 语言 | Python | 3.6+ | 支持dataclass、typing、async |
| 协议解析 | tshark (Wireshark) | 2.6+ | PCAP解析首选 |
| 系统调用 | ss (iproute2) | 4.9+ | TCPSocket数据采集 |
| 数据分析 | pandas + numpy | 最新 | 统计分析 |
| 可视化 | matplotlib + seaborn | 最新 | 图表生成 |
| 数据结构 | dataclass + pydantic | 最新 | 类型安全和序列化 |
| 进度条 | tqdm | 最新 | 大文件处理进度 |

### 1.4 目录结构

```
traffic-analyzer/
├── README.md                              # 项目说明
├── requirements.txt                       # 依赖列表
├── setup.py                               # 安装脚本
│
├── pcap_analyzer/                         # PCAP分析工具
│   ├── __init__.py
│   ├── main.py                           # 入口脚本
│   ├── parser/                           # 协议解析模块
│   │   ├── __init__.py
│   │   ├── pcap_parser.py               # tshark封装
│   │   └── stream_processor.py          # 流式处理
│   ├── analyzer/                         # 协议分析模块
│   │   ├── __init__.py
│   │   ├── l2_analyzer.py               # L2层分析
│   │   ├── l3_analyzer.py               # L3层分析
│   │   ├── l4_analyzer.py               # L4层分析
│   │   ├── tcp_analyzer.py              # TCP深度分析
│   │   ├── udp_analyzer.py              # UDP分析
│   │   └── icmp_analyzer.py             # ICMP分析
│   ├── stats/                            # 统计计算模块
│   │   ├── __init__.py
│   │   ├── flow_stats.py                # 流统计
│   │   └── distribution.py              # 分布统计
│   └── output/                           # 输出模块
│       ├── __init__.py
│       ├── text_reporter.py             # 文本报告
│       ├── json_reporter.py             # JSON输出
│       └── visualizer.py                # 图表生成
│
├── tcpsocket_analyzer/                   # TCPSocket分析工具
│   ├── __init__.py
│   ├── main.py                           # 入口脚本
│   ├── parser/                           # 数据解析模块
│   │   ├── __init__.py
│   │   ├── ss_parser.py                 # ss输出解析
│   │   └── timeseries_parser.py         # 时序数据解析
│   ├── analyzer/                         # 性能分析模块
│   │   ├── __init__.py
│   │   ├── rtt_analyzer.py              # RTT分析
│   │   ├── window_analyzer.py           # 窗口分析
│   │   ├── rate_analyzer.py             # 速率分析
│   │   ├── buffer_analyzer.py           # Buffer分析（重点）
│   │   ├── retrans_analyzer.py          # 重传分析
│   │   └── bottleneck_detector.py       # 瓶颈识别
│   ├── models/                           # 数据模型
│   │   ├── __init__.py
│   │   ├── connection.py                # 连接模型
│   │   └── timeseries.py                # 时序数据模型
│   └── output/                           # 输出模块
│       ├── __init__.py
│       ├── text_reporter.py             # 文本报告
│       ├── json_reporter.py             # JSON输出
│       └── visualizer.py                # 图表生成
│
├── common/                               # 通用组件库
│   ├── __init__.py
│   ├── utils/                            # 工具函数
│   │   ├── __init__.py
│   │   ├── logger.py                    # 日志
│   │   ├── file_utils.py                # 文件操作
│   │   └── math_utils.py                # 数学计算
│   ├── models/                           # 通用数据模型
│   │   ├── __init__.py
│   │   └── packet.py                    # 通用包模型
│   └── visualization/                    # 通用可视化组件
│       ├── __init__.py
│       ├── chart_base.py                # 图表基类
│       └── plot_utils.py                # 绘图工具
│
└── docs/                                 # 文档
    ├── requirements.md                  # 需求规格
    ├── design.md                        # 本文档（架构设计）
    ├── api.md                           # API文档
    └── examples/                        # 示例
        ├── pcap_examples.md
        └── tcpsocket_examples.md
```

### 1.5 数据流设计

#### 1.5.1 PCAP分析工具数据流

```
┌─────────────┐
│ PCAP文件    │
│ (client/    │
│  server)    │
└──────┬──────┘
       │
       ▼
┌──────────────────────────┐
│ tshark命令行调用         │
│ -T json -x               │
│ 输出原始JSON             │
└──────┬───────────────────┘
       │
       ▼
┌──────────────────────────┐
│ PCAPParser               │
│ - 读取JSON流             │
│ - 协议分层解析            │
│ - 流重组                 │
└──────┬───────────────────┘
       │
       ├─► ┌────────────────────┐
       │   │ Flow Aggregator    │
       │   │ - 按5元组聚合      │
       │   │ - 维护流状态机      │
       │   └─────────┬──────────┘
       │             │
       │             ▼
       │   ┌────────────────────┐
       │   │ Protocol Analyzer  │
       │   │ - L2/L3/L4分析      │
       │   │ - TCP/UDP/ICMP深度  │
       │   └─────────┬──────────┘
       │             │
       │             ▼
       │   ┌────────────────────┐
       └───► Statistics Engine  │
           │ - 计算统计指标      │
           │ - 分布分析          │
           └─────────┬──────────┘
                     │
          ┌──────────┼──────────┐
          │          │          │
          ▼          ▼          ▼
   ┌──────────┐ ┌─────────┐ ┌──────────┐
   │ Text     │ │ JSON    │ │ Visual   │
   │ Reporter │ │ Reporter│ │ Charts   │
   └──────────┘ └─────────┘ └──────────┘
```

#### 1.5.2 TCPSocket分析工具数据流

```
┌──────────────────────┐
│ tcpsocket数据目录     │
│ (client/ or server/) │
│ - 多个采集文件        │
│ - 每个文件有多个时间  │
│  点的ss快照          │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────────┐
│ SSOutputParser           │
│ - 从文件中提取所有采样    │
│ - 解析每行输出           │
│ - 按时间戳排序           │
└──────┬───────────────────┘
       │
       ▼
┌──────────────────────────┐
│ TimeSeriesBuilder        │
│ - 构建时序数据           │
│ - 插值处理               │
│ - 数据对齐               │
└──────┬───────────────────┘
       │
       ├─► ┌────────────────────┐
       │   │ Connection Tracker │
       │   │ - 识别唯一连接      │
       │   │ - 维护连接生命周期   │
       │   └─────────┬──────────┘
       │             │
       │             ▼
       │   ┌────────────────────┐
       │   │ Metrics Analyzer   │
       │   │ - RTT分析          │
       │   │ - 窗口分析          │
       │   │ - 速率分析          │
       │   │ - Buffer分析        │
       │   └─────────┬──────────┘
       │             │
       │             ▼
       │   ┌────────────────────┐
       │   │ Bottleneck Detector│
       │   │ - 自动识别瓶颈      │
       │   │ - 健康度评分        │
       │   │ - 生成调优建议      │
       │   └─────────┬──────────┘
       │             │
       │             ▼
       │   ┌────────────────────┐
       └───► Report Generator   │
           │ - 汇总统计          │
           │ - 生成报告          │
           └─────────┬──────────┘
                     │
          ┌──────────┼──────────┐
          │          │          │
          ▼          ▼          ▼
   ┌──────────┐ ┌─────────┐ ┌──────────┐
   │ Text     │ │ JSON    │ │ Visual   │
   │ Report   │ │ Report  │ │ Charts   │
   └──────────┘ └─────────┘ └──────────┘
```

---

## 2. PCAP分析工具设计

### 2.1 概要设计

#### 2.1.1 设计目标

PCAP分析工具旨在提供对网络抓包文件的多层协议分析能力，支持：
- L2/L3/L4层统计
- TCP/UDP/ICMP协议深度分析
- 智能问题识别
- 大文件流式处理

#### 2.1.2 运行模式

工具提供两种运行模式：

**1. Summary模式（默认）**
- 快速概览统计信息
- 适合初步分析
- 内存占用低

**2. Details模式（配合过滤条件）**
- 协议层深度分析
- 连接/流级别统计
- 智能问题识别
- 支持可视化输出

#### 2.1.3 总体流程

```
开始
  │
  ├─► 解析命令行参数
  │   - input: PCAP文件路径
  │   - mode: summary/details
  │   - filters: 协议/IP/端口过滤
  │   - output: 文本/JSON/图表
  │
  ├─► 模式判断
  │   │
  │   ├─► SUMMARY模式 ──► 快速扫描PCAP
  │   │   - 读取文件头
  │   │   - 统计包数量、字节数
  │   │   - 按协议分层统计
  │   │   - 生成概览报告
  │   │
  │   └─► DETAILS模式 ──► 深度解析
  │       - 逐包解析
  │       - 流重组
  │       - 协议分析
  │       - 问题识别
  │
  └─► 输出结果
      - 文本报告
      - JSON数据
      - 可视化图表
      - 分析报告
```

### 2.2 详细设计

#### 2.2.1 核心模块设计

##### 2.2.1.1 PCAP解析器 (PCAPParser)

**职责**: 封装tshark命令，解析PCAP文件，输出结构化数据

**接口设计**:
```python
class PCAPParser:
    """PCAP文件解析器"""

    def __init__(self, pcap_path: str):
        """
        初始化解析器

        Args:
            pcap_path: PCAP文件路径
        """
        self.pcap_path = pcap_path
        self.total_packets = 0
        self.total_bytes = 0

    def parse_summary(self) -> Dict[str, Any]:
        """
        Summary模式解析

        Returns:
            概览统计信息
            {
                "total_packets": int,
                "total_bytes": int,
                "time_range": {"start": float, "end": float},
                "protocol_distribution": Dict[str, int],
                "layer2_stats": {...},
                "layer3_stats": {...},
                "layer4_stats": {...}
            }
        """
        pass

    def parse_packets_stream(self, filter_expr: str = None) -> Iterator[Dict[str, Any]]:
        """
        流式解析PCAP文件（逐包返回）

        Args:
            filter_expr: 过滤表达式（BPF语法）

        Yields:
            每个包的解析结果（JSON格式）
            {
                "frame_number": int,
                "timestamp": float,
                "layers": {
                    "frame": {...},
                    "eth": {...},
                    "ip": {...},
                    "tcp" | "udp" | "icmp": {...}
                }
            }
        """
        pass

    def get_flows(self, filter_expr: str = None) -> Dict[str, List[Dict]]:
        """
        提取所有数据流（按5元组分组）

        Args:
            filter_expr: 过滤表达式

        Returns:
            流字典，key为流ID（5元组哈希）
        """
        pass

    def close(self):
        """清理资源"""
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
```

**实现细节**:

1. **tshark调用方式**:
   ```bash
   # Summary模式
   tshark -r <pcap_file> -q -z io,stat,0

   # Details模式 - 获取JSON格式
   tshark -r <pcap_file> -T json -x -o tcp.analyze_sequence_numbers:TRUE
   ```

2. **性能优化**:
   - 使用`subprocess.Popen`配合管道流式读取tshark输出
   - 避免一次性加载所有数据到内存
   - 使用`ijson`库流式解析JSON

3. **错误处理**:
   - tshark未安装：抛出ToolNotFoundError
   - PCAP文件损坏：抛出ParseError
   - 内存不足：监控内存使用，分批处理

##### 2.2.1.2 流聚合器 (FlowAggregator)

**职责**: 将数据包按5元组聚合成流，维护流状态

**接口设计**:
```python
@dataclass
class FlowKey:
    """流标识（5元组）"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # 'tcp', 'udp', 'icmp', etc.

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip,
                    self.src_port, self.dst_port, self.protocol))


@dataclass
class FlowStats:
    """流统计信息"""
    flow_key: FlowKey
    start_time: float
    end_time: float
    packet_count: int = 0
    byte_count: int = 0
    src_byte_count: int = 0
    dst_byte_count: int = 0
    # TCP特有
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    retrans_count: int = 0
    # 窗口相关
    min_window: int = None
    max_window: int = None


class FlowAggregator:
    """流聚合器"""

    def __init__(self):
        self.flows: Dict[str, FlowStats] = {}

    def add_packet(self, packet: Dict[str, Any]):
        """
        添加数据包到流统计

        Args:
            packet: 解析后的数据包（来自PCAPParser）
        """
        pass

    def get_flow_stats(self) -> List[FlowStats]:
        """
        获取所有流的统计信息

        Returns:
            流统计列表
        """
        return list(self.flows.values())

    def get_top_flows(self, by: str = 'bytes', top_n: int = 10) -> List[FlowStats]:
        """
        获取Top N流

        Args:
            by: 排序字段（'bytes', 'packets', 'duration'）
            top_n: 返回数量

        Returns:
            Top N流列表
        """
        pass

    def clear(self):
        """清空所有流统计"""
        self.flows.clear()
```

**实现算法**:

1. **流状态机**（针对TCP）:
   ```
   IDLE ──SYN──► SYN_SENT
   SYN_SENT ──SYN-ACK──► ESTABLISHED
   ESTABLISHED ──FIN──► FIN_WAIT
   FIN_WAIT ──ACK──► CLOSED
   ANY ──RST──► CLOSED
   ```

2. **重传检测**:
   - 基于IP ID和序列号的变化
   - 相同序列号出现多次标识为重传
   - 使用字典记录已见的序列号

3. **内存管理**:
   - 长时间运行的流（>24小时）定期清理
   - 使用LRU缓存限制内存占用

##### 2.2.1.3 TCP分析器 (TCPAnalyzer)

**职责**: TCP协议深度分析，包括重传、窗口、延迟等

**接口设计**:
```python
class TCPAnalyzer:
    """TCP协议深度分析器"""

    def __init__(self):
        self.retrans_detector = RetransmissionDetector()
        self.window_analyzer = WindowAnalyzer()
        self.rtt_estimator = RTTEstimator()

    def analyze_flow(self, flow_key: FlowKey,
                    packets: List[Dict]) -> Dict[str, Any]:
        """
        分析TCP流

        Args:
            flow_key: 流标识
            packets: 该流的所有数据包（按时间排序）

        Returns:
            分析结果
            {
                "retrans_stats": {
                    "total_retrans": int,
                    "retrans_rate": float,  # 重传率
                    "fast_retrans": int,
                    "timeout_retrans": int,
                    "tlp_retrans": int
                },
                "window_stats": {
                    "zero_window_events": int,
                    "window_full_events": int,
                    "min_window": int,
                    "max_window": int,
                    "avg_window": float
                },
                "rtt_stats": {
                    "min_rtt": float,
                    "max_rtt": float,
                    "avg_rtt": float,
                    "rtt_variance": float,
                    "p50": float,
                    "p95": float,
                    "p99": float
                },
                "throughput": {
                    "avg_throughput": float,  # bps
                    "peak_throughput": float
                },
                "issues": [
                    {
                        "type": "high_retrans",
                        "severity": "high",
                        "description": "重传率过高 (>1%)",
                        "recommendation": "检查网络质量"
                    },
                    ...
                ]
            }
        """
        pass
```

**重传检测算法**:

```python
class RetransmissionDetector:
    """重传检测器"""

    def __init__(self):
        # 记录已确认的序列号
        self.acked_seqs: Set[int] = set()

    def detect_retransmission(self, packet: Dict,
                            retrans_threshold: int = 3) -> Dict:
        """
        检测重传

        Args:
            packet: 数据包
            retrans_threshold: 重传阈值（重复ACK数）

        Returns:
            {
                "is_retrans": bool,
                "retrans_type": "timeout" | "fast" | "tlp" | "sack",
                "dupack_count": int
            }
        """
        # 实现逻辑:
        # 1. 提取TCP序列号
        seq = packet['layers']['tcp']['tcp_seq']

        # 2. 如果序列号已确认过，则是重传
        if seq in self.acked_seqs:
            # 检查是超时重传还是快速重传
            return {
                "is_retrans": True,
                "retrans_type": self._classify_retrans(packet)
            }

        # 3. 检查重复ACK
        if self._is_dupack(packet, retrans_threshold):
            return {
                "is_retrans": True,
                "retrans_type": "fast",
                "dupack_count": retrans_threshold
            }

        return {"is_retrans": False}

    def _classify_retrans(self, packet: Dict) -> str:
        """分类重传类型"""
        # TLP (Tail Loss Probe)检测
        if self._is_tlp(packet):
            return "tlp"
        # SACK重传
        elif self._has_sack(packet):
            return "sack"
        # 超时重传
        else:
            return "timeout"

    def _is_dupack(self, packet: Dict, threshold: int) -> bool:
        """检测是否为重复ACK触发的快速重传"""
        # 实现: 检查连续threshold个相同的ACK
        pass

    def _is_tlp(self, packet: Dict) -> bool:
        """检测是否为TLP探测"""
        # TLP: 发送新数据而非重传旧数据
        pass

    def _has_sack(self, packet: Dict) -> bool:
        """检测是否使用SACK"""
        return 'tcp_options_sack' in packet['layers']['tcp']
```

**窗口分析算法**:

```python
class WindowAnalyzer:
    """TCP窗口分析器"""

    def analyze_window(self, packets: List[Dict]) -> Dict:
        """
        分析窗口变化

        Returns:
            {
                "zero_window_events": int,     # Zero Window事件数
                "window_full_events": int,     # Window Full事件数
                "min_window": int,
                "max_window": int,
                "avg_window": float,
                "window_changes": List[Dict]  # 窗口变化时间序列
            }
        """
        stats = {
            "zero_window_events": 0,
            "window_full_events": 0,
            "window_values": []
        }

        for packet in packets:
            tcp_layer = packet['layers']['tcp']
            window = int(tcp_layer['tcp_window_size'])

            # 记录窗口值
            stats["window_values"].append(window)

            # 检测Zero Window
            # 发送方窗口满: unacked ≈ cwnd
            # 接收方窗口空: advertised window = 0
            if self._is_zero_window(packet):
                stats["zero_window_events"] += 1

            # 检测Window Full
            if self._is_window_full(packet):
                stats["window_full_events"] += 1

        # 计算统计值
        if stats["window_values"]:
            stats.update({
                "min_window": min(stats["window_values"]),
                "max_window": max(stats["window_values"]),
                "avg_window": statistics.mean(stats["window_values"])
            })

        return stats

    def _is_zero_window(self, packet: Dict) -> bool:
        """检测Zero Window事件"""
        tcp_layer = packet['layers']['tcp']
        # 接收方通告窗口为0
        return int(tcp_layer['tcp_window_size']) == 0

    def _is_window_full(self, packet: Dict) -> bool:
        """检测Window Full事件"""
        # 发送方窗口已满
        # unacked ≈ cwnd
        tcp_layer = packet['layers']['tcp']
        unacked = self._get_unacked_count(packet)
        cwnd = tcp_layer.get('tcp_analysis_cwnd', 0)
        return unacked >= cwnd * 0.9
```

**RTT估算算法**:

```python
class RTTEstimator:
    """RTT估算器（基于TCP Timestamps选项）"""

    def __init__(self):
        self.rtt_samples: List[float] = []

    def estimate_rtt(self, packets: List[Dict]) -> Dict:
        """
        估算RTT

        Returns:
            {
                "min_rtt": float,      # ms
                "max_rtt": float,      # ms
                "avg_rtt": float,      # ms
                "rtt_variance": float, # ms
                "p50": float,
                "p95": float,
                "p99": float,
                "rtt_samples": List[float]
            }
        """
        self.rtt_samples = []

        for i, packet in enumerate(packets):
            rtt = self._extract_rtt(packet)
            if rtt is not None:
                self.rtt_samples.append(rtt)

        if not self.rtt_samples:
            return {"error": "No RTT samples available"}

        return {
            "min_rtt": min(self.rtt_samples),
            "max_rtt": max(self.rtt_samples),
            "avg_rtt": statistics.mean(self.rtt_samples),
            "rtt_variance": statistics.stdev(self.rtt_samples),
            "p50": np.percentile(self.rtt_samples, 50),
            "p95": np.percentile(self.rtt_samples, 95),
            "p99": np.percentile(self.rtt_samples, 99),
            "rtt_samples": self.rtt_samples
        }

    def _extract_rtt(self, packet: Dict) -> Optional[float]:
        """
        从数据包提取RTT值

        方法:
        1. 使用TCP Timestamps选项（如果有）
           RTT = 当前时间 - Echo Reply时间

        2. 通过SYN-ACK对估算
           RTT = ACK时间 - SYN发送时间

        3. 通过数据包-ACK对估算
           RTT = ACK时间 - 数据发送时间
        """
        tcp_layer = packet['layers']['tcp']

        # 检查是否有TCP Timestamps选项
        if 'tcp_options_timestamp' in tcp_layer:
            ts_val = tcp_layer['tcp_options_timestamp_tsval']
            ts_echo = tcp_layer.get('tcp_options_timestamp_tsecr')
            if ts_echo:
                # RTT = 当前时间戳 - Echo的时间戳
                rtt = (ts_val - ts_echo) / 1000  # 转换为ms
                return rtt

        # TODO: 通过SYN-ACK对估算
        # TODO: 通过数据包-ACK对估算

        return None
```

##### 2.2.1.4 智能分析器 (SmartAnalyzer)

**职责**: 自动识别网络问题，生成分析结论和建议

**接口设计**:
```python
class SmartAnalyzer:
    """智能问题识别分析器"""

    def __init__(self):
        self.issue_database = self._load_issue_database()

    def analyze(self, flow_stats: FlowStats,
               tcp_analysis: Dict = None) -> Dict[str, Any]:
        """
        智能分析

        Args:
            flow_stats: 流统计信息
            tcp_analysis: TCP深度分析结果（可选）

        Returns:
            {
                "issues": [
                    {
                        "category": "performance" | "retransmission" | "window",
                        "severity": "high" | "medium" | "low",
                        "title": "问题标题",
                        "description": "详细描述",
                        "evidence": "证据数据",
                        "recommendation": "优化建议"
                    },
                    ...
                ],
                "summary": {
                    "total_issues": int,
                    "high_priority": int,
                    "medium_priority": int,
                    "low_priority": int
                }
            }
        """
        issues = []

        # TCP分析（如果有）
        if tcp_analysis:
            issues.extend(self._analyze_tcp_issues(tcp_analysis))

        # 通用分析
        issues.extend(self._analyze_general_issues(flow_stats))

        # 去重和优先级排序
        issues = self._deduplicate_issues(issues)
        issues = sorted(issues, key=lambda x: self._severity_weight(x['severity']))

        return {
            "issues": issues,
            "summary": {
                "total_issues": len(issues),
                "high_priority": sum(1 for i in issues if i['severity'] == 'high'),
                "medium_priority": sum(1 for i in issues if i['severity'] == 'medium'),
                "low_priority": sum(1 for i in issues if i['severity'] == 'low')
            }
        }

    def _analyze_tcp_issues(self, tcp_analysis: Dict) -> List[Dict]:
        """分析TCP特定问题"""
        issues = []

        # 1. 高重传率
        retrans_rate = tcp_analysis.get('retrans_stats', {}).get('retrans_rate', 0)
        if retrans_rate > 0.05:  # >5% 严重
            issues.append({
                "category": "retransmission",
                "severity": "high",
                "title": "高重传率",
                "description": "检测到重传率过高，表明网络质量较差或存在拥塞",
                "evidence": f"重传率: {retrans_rate:.2%}",
                "recommendation": "检查物理链路质量、减少网络拥塞、调整TCP拥塞控制算法"
            })
        elif retrans_rate > 0.01:  # >1% 中等
            issues.append({
                "category": "retransmission",
                "severity": "medium",
                "title": "重传率偏高",
                "description": "重传率超过正常范围",
                "evidence": f"重传率: {retrans_rate:.2%}",
                "recommendation": "监控网络质量，检查是否有周期性丢包"
            })

        # 2. Zero Window频繁
        zero_win = tcp_analysis.get('window_stats', {}).get('zero_window_events', 0)
        if zero_win > 5:
            issues.append({
                "category": "window",
                "severity": "high",
                "title": "频繁Zero Window事件",
                "description": "多次出现接收窗口为0，表明接收方处理缓慢",
                "evidence": f"Zero Window事件: {zero_win}次",
                "recommendation": "检查接收方应用性能，增大tcp_rmem缓冲区"
            })

        # 3. RTT异常
        rtt_stats = tcp_analysis.get('rtt_stats', {})
        if rtt_stats and rtt_stats.get('avg_rtt'):
            avg_rtt = rtt_stats['avg_rtt']
            if avg_rtt > 1000:  # >1秒 严重
                issues.append({
                    "category": "performance",
                    "severity": "high",
                    "title": "RTT异常高",
                    "description": "平均RTT超过1秒，网络延迟严重",
                    "evidence": f"平均RTT: {avg_rtt:.1f}ms",
                    "recommendation": "检查网络路径、路由、物理链路"
                })
            elif avg_rtt > 200:  # >200ms 中等
                issues.append({
                    "category": "performance",
                    "severity": "medium",
                    "title": "RTT偏高",
                    "description": "网络延迟较高",
                    "evidence": f"平均RTT: {avg_rtt:.1f}ms",
                    "recommendation": "检查网络拓扑、减少跳数"
                })

        return issues

    def _analyze_general_issues(self, flow_stats: FlowStats) -> List[Dict]:
        """分析通用问题"""
        issues = []

        # 包大小异常（大量小包）
        avg_packet_size = flow_stats.byte_count / flow_stats.packet_count
        if avg_packet_size < 200:  # 平均包大小<200 bytes
            issues.append({
                "category": "performance",
                "severity": "medium",
                "title": "小包过多",
                "description": "平均包大小过小，协议效率低",
                "evidence": f"平均包大小: {avg_packet_size:.1f} bytes",
                "recommendation": "考虑应用层合并小包或使用批量接口"
            })

        return issues

    def _load_issue_database(self) -> Dict:
        """加载问题数据库（可扩展）"""
        return {
            "high_retrans": {
                "threshold": 0.01,
                "severity": "high",
                "description": "重传率过高"
            },
            # 可添加更多预定义问题
        }
```

#### 2.2.2 输出模块设计

##### 2.2.2.1 文本报告生成器 (TextReporter)

```python
class TextReporter:
    """文本报告生成器"""

    def __init__(self, output_stream=sys.stdout):
        self.output = output_stream

    def generate_summary(self, stats: Dict[str, Any]):
        """生成概览报告"""
        print("=" * 80, file=self.output)
        print("PCAP流量分析报告", file=self.output)
        print("=" * 80, file=self.output)

        # 基本信息
        print(f\n\n文件信息", file=self.output)
        print(f"  - 总数据包数: {stats['total_packets']:,}", file=self.output)
        print(f"  - 总字节数: {stats['total_bytes'] / (1024**3):.2f} GB", file=self.output)
        print(f"  - 时间范围: {stats['time_range']['start']} - {stats['time_range']['end']}", file=self.output)

        # 协议分布
        print(f"\n协议分布", file=self.output)
        for proto, count in stats['protocol_distribution'].items():
            pct = count / stats['total_packets'] * 100
            print(f"  - {proto}: {count:,} ({pct:.1f}%)", file=self.output)

        # Top流
        if 'top_flows' in stats:
            print(f"\nTop 10流（按字节数）", file=self.output)
            for i, flow in enumerate(stats['top_flows'], 1):
                print(f"  {i}. {flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} "
                      f"({flow['protocol']}) - {flow['byte_count'] / (1024**2):.2f} MB", file=self.output)

        print("=" * 80, file=self.output)

    def generate_detailed_report(self, analysis: Dict[str, Any]):
        """生成详细报告"""
        # L2-L4统计
        if 'layer2_stats' in analysis:
            print(f"\nL2层统计", file=self.output)
            self._print_dict(analysis['layer2_stats'])

        if 'layer3_stats' in analysis:
            print(f"\nL3层统计", file=self.output)
            self._print_dict(analysis['layer3_stats'])

        if 'layer4_stats' in analysis:
            print(f"\nL4层统计", file=self.output)
            self._print_dict(analysis['layer4_stats'])

        # TCP深度分析
        if 'tcp_analysis' in analysis:
            print(f"\nTCP深度分析", file=self.output)
            self._print_tcp_analysis(analysis['tcp_analysis'])

        # 智能分析
        if 'smart_analysis' in analysis:
            print(f"\n问题识别", file=self.output)
            self._print_issues(analysis['smart_analysis'])

    def _print_dict(self, data: Dict, indent: int = 2):
        """打印字典"""
        for key, value in data.items():
            print(f"{' ' * indent}- {key}: {value}", file=self.output)

    def _print_tcp_analysis(self, tcp_analysis: Dict):
        """打印TCP分析结果"""
        # 重传统计
        if 'retrans_stats' in tcp_analysis:
            print(f"  重传统计:", file=self.output)
            self._print_dict(tcp_analysis['retrans_stats'], indent=4)

        # 窗口统计
        if 'window_stats' in tcp_analysis:
            print(f"  窗口统计:", file=self.output)
            self._print_dict(tcp_analysis['window_stats'], indent=4)

        # RTT统计
        if 'rtt_stats' in tcp_analysis:
            print(f"  RTT统计:", file=self.output)
            self._print_dict(tcp_analysis['rtt_stats'], indent=4)

    def _print_issues(self, smart_analysis: Dict):
        """打印问题"""
        issues = smart_analysis.get('issues', [])

        if not issues:
            print(f"  ✓ 未检测到明显问题", file=self.output)
            return

        # 按严重性分组
        high = [i for i in issues if i['severity'] == 'high']
        medium = [i for i in issues if i['severity'] == 'medium']
        low = [i for i in issues if i['severity'] == 'low']

        if high:
            print(f"  严重问题 ({len(high)}):", file=self.output)
            for issue in high:
                print(f"    ✗ {issue['title']}", file=self.output)
                print(f"      描述: {issue['description']}", file=self.output)
                print(f"      证据: {issue.get('evidence', 'N/A')}", file=self.output)
                print(f"      建议: {issue['recommendation']}", file=self.output)

        if medium:
            print(f"  中等问题 ({len(medium)}):", file=self.output)
            for issue in medium:
                print(f"    ! {issue['title']}", file=self.output)
                print(f"      建议: {issue['recommendation']}", file=self.output)

        if low:
            print(f"  轻微问题 ({len(low)}):", file=self.output)
            for issue in low:
                print(f"    - {issue['title']}", file=self.output)
```

##### 2.2.2.2 JSON报告生成器 (JSONReporter)

```python
class JSONReporter:
    """JSON报告生成器"""

    def __init__(self, indent: int = 2):
        self.indent = indent

    def generate(self, data: Dict[str, Any]) -> str:
        """
        生成JSON格式报告

        Args:
            data: 分析数据

        Returns:
            JSON字符串
        """
        return json.dumps(data, indent=self.indent, ensure_ascii=False, default=str)

    def save(self, data: Dict[str, Any], filepath: str):
        """
        保存JSON到文件

        Args:
            data: 分析数据
            filepath: 输出文件路径
        """
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=self.indent, ensure_ascii=False, default=str)
```

##### 2.2.2.3 可视化图表生成器 (Visualizer)

```python
class Visualizer:
    """可视化图表生成器"""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)

    def plot_protocol_distribution(self,
                                 protocol_dist: Dict[str, int],
                                 title: str = "协议分布"):
        """
        绘制协议分布饼图

        Args:
            protocol_dist: 协议分布数据
            title: 图表标题
        """
        labels = list(protocol_dist.keys())
        sizes = list(protocol_dist.values())

        plt.figure(figsize=(10, 8))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        plt.title(title)
        plt.axis('equal')

        # 保存
        output_path = self.output_dir / "protocol_distribution.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()

        return output_path

    def plot_packet_size_distribution(self,
                                    packets: List[Dict],
                                    title: str = "包大小分布"):
        """
        绘制包大小分布直方图
        """
        sizes = [int(p['layers']['frame']['frame_len']) for p in packets]

        plt.figure(figsize=(12, 6))
        plt.hist(sizes, bins=50, edgecolor='black', alpha=0.7)
        plt.title(title)
        plt.xlabel("包大小 (bytes)")
        plt.ylabel("数量")
        plt.grid(True, alpha=0.3)

        # 添加统计信息
        mean_size = statistics.mean(sizes)
        median_size = statistics.median(sizes)
        plt.axvline(mean_size, color='red', linestyle='--', label=f'均值: {mean_size:.0f}')
        plt.axvline(median_size, color='green', linestyle='--', label=f'中位数: {median_size:.0f}')
        plt.legend()

        output_path = self.output_dir / "packet_size_dist.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()

        return output_path

    def plot_tcp_retrans_timeline(self,
                                packets: List[Dict],
                                title: str = "重传时间线"):
        """
        绘制重传时间线
        """
        timestamps = []
        is_retrans = []

        for p in packets:
            if 'tcp' in p['layers']:
                timestamps.append(float(p['timestamp']))
                # 判断是否重传
                retrans = p['layers']['tcp'].get('tcp_analysis_retransmission', False)
                is_retrans.append(1 if retrans else 0)

        if not timestamps:
            return None

        plt.figure(figsize=(14, 6))

        # 绘制正常包
        normal_times = [t for t, r in zip(timestamps, is_retrans) if r == 0]
        plt.scatter(normal_times, [0]*len(normal_times),
                   color='blue', s=10, alpha=0.6, label='正常包')

        # 绘制重传包
        retrans_times = [t for t, r in zip(timestamps, is_retrans) if r == 1]
        if retrans_times:
            plt.scatter(retrans_times, [0]*len(retrans_times),
                       color='red', s=50, label='重传包')

        plt.title(title)
        plt.xlabel("时间")
        plt.yticks([])
        plt.legend()
        plt.grid(True, alpha=0.3)

        output_path = self.output_dir / "retrans_timeline.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()

        return output_path

    def plot_rtt_distribution(self,
                            rtt_samples: List[float],
                            title: str = "RTT分布"):
        """
        绘制RTT分布图
        """
        if not rtt_samples:
            return None

        plt.figure(figsize=(12, 5))

        # 直方图
        plt.subplot(1, 2, 1)
        plt.hist(rtt_samples, bins=30, edgecolor='black', alpha=0.7)
        plt.title("RTT直方图")
        plt.xlabel("RTT (ms)")
        plt.ylabel("频数")
        plt.grid(True, alpha=0.3)

        # 箱线图
        plt.subplot(1, 2, 2)
        plt.boxplot(rtt_samples, vert=True, patch_artist=True)
        plt.title("RTT箱线图")
        plt.ylabel("RTT (ms)")
        plt.grid(True, alpha=0.3)

        # 添加统计信息
        stats_text = f"""
        样本数: {len(rtt_samples)}
        均值: {statistics.mean(rtt_samples):.2f}ms
        中位数: {statistics.median(rtt_samples):.2f}ms
        95分位: {np.percentile(rtt_samples, 95):.2f}ms
        """
        plt.figtext(0.5, 0.95, stats_text, ha='center', va='top',
                   bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

        plt.tight_layout()

        output_path = self.output_dir / "rtt_distribution.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()

        return output_path
```

#### 2.2.3 命令行接口设计

```python
# pcap_analyzer/main.py

import argparse
from pcap_analyzer.parser import PCAPParser
from pcap_analyzer.analyzer import TCPAnalyzer, UDPAnalyzer, ICMPAnalyzer
from pcap_analyzer.stats import FlowAggregator
from pcap_analyzer.output import TextReporter, JSONReporter, Visualizer


def main():
    parser = argparse.ArgumentParser(
        description='PCAP流量分析工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # Summary模式
  python pcap_analyzer.py --input pcap/client

  # Summary模式，显示所有层统计
  python pcap_analyzer.py --input pcap/client --layer all

  # Details模式，TCP深度分析
  python pcap_analyzer.py --input pcap/client --proto tcp

  # 指定连接的TCP分析
  python pcap_analyzer.py --input pcap/client --src-ip 10.0.0.1 --dst-ip 10.0.0.2 --port 5201

  # 智能问题识别
  python pcap_analyzer.py --input pcap/client --proto tcp --analysis

  # JSON输出
  python pcap_analyzer.py --input pcap/client --proto tcp --json > analysis.json
        """
    )

    # 输入参数
    input_group = parser.add_argument_group('输入参数')
    input_group.add_argument('--input', '-i', required=True,
                            help='PCAP文件或目录路径')
    input_group.add_argument('--recursive', '-r', action='store_true',
                            help='递归处理目录下的所有PCAP文件')

    # 模式选择
    mode_group = parser.add_argument_group('分析模式')
    mode_group.add_argument('--summary', action='store_true', default=True,
                           help='Summary模式（默认）')
    mode_group.add_argument('--layer', choices=['all', 'l2', 'l3', 'l4'],
                           help='Summary模式显示的层')
    mode_group.add_argument('--proto', choices=['tcp', 'udp', 'icmp'],
                           help='Details模式协议类型')
    mode_group.add_argument('--analysis', action='store_true',
                           help='启用智能问题识别')

    # 过滤条件
    filter_group = parser.add_argument_group('过滤条件')
    filter_group.add_argument('--src-ip', help='源IP地址')
    filter_group.add_argument('--dst-ip', help='目标IP地址')
    filter_group.add_argument('--ip', help='任意方向IP地址')
    filter_group.add_argument('--src-port', type=int, help='源端口')
    filter_group.add_argument('--dst-port', type=int, help='目标端口')
    filter_group.add_argument('--port', type=int, help='任意方向端口')
    filter_group.add_argument('--bpf', help='BPF过滤表达式')

    # 输出选项
    output_group = parser.add_argument_group('输出选项')
    output_group.add_argument('--json', action='store_true',
                             help='JSON输出格式')
    output_group.add_argument('--output-dir', '-o',
                             help='图表输出目录（Details模式）')
    output_group.add_argument('--quiet', '-q', action='store_true',
                             help='静默模式，减少输出')

    # 性能选项
    perf_group = parser.add_argument_group('性能选项')
    perf_group.add_argument('--batch-size', type=int, default=10000,
                           help='每批处理的包数量')
    perf_group.add_argument('--max-memory', type=int, default=1024,
                           help='最大内存使用（MB）')

    args = parser.parse_args()

    # 主逻辑
    try:
        # 创建解析器
        with PCAPParser(args.input) as parser:
            # Summary模式
            if args.summary and not args.proto:
                summary_stats = parser.parse_summary()

                # 应用过滤
                if args.bpf or any([args.src_ip, args.dst_ip, args.ip,
                                  args.src_port, args.dst_port, args.port]):
                    # 在summary基础上过滤
                    pass

                # 输出
                if args.json:
                    reporter = JSONReporter()
                    print(reporter.generate(summary_stats))
                else:
                    reporter = TextReporter()
                    reporter.generate_summary(summary_stats)

            # Details模式
            elif args.proto:
                # 构建过滤表达式
                filter_expr = args.bpf or ""

                # 流聚合器
                aggregator = FlowAggregator()
                tcp_analyzer = TCPAnalyzer()
                smart_analyzer = SmartAnalyzer()

                # 流式解析
                packet_stream = parser.parse_packets_stream(filter_expr)

                # 批量处理
                batch = []
                for packet in tqdm(packet_stream, desc="解析数据包"):
                    batch.append(packet)
                    aggregator.add_packet(packet)

                    if len(batch) >= args.batch_size:
                        # 分析该批次
                        batch.clear()

                # 生成报告
                flow_stats = aggregator.get_flow_stats()
                top_flows = aggregator.get_top_flows()

                # TCP深度分析
                tcp_analysis = None
                if args.proto == 'tcp' and args.analysis:
                    # 获取Top流的详细信息
                    top_flow = top_flows[0]
                    flow_packets = []  # TODO: 获取该流的所有包

                    if flow_packets:
                        tcp_analysis = tcp_analyzer.analyze_flow(
                            flow_key=top_flow.flow_key,
                            packets=flow_packets
                        )

                # 智能分析
                smart_analysis = None
                if args.analysis:
                    smart_analysis = smart_analyzer.analyze(
                        flow_stats=flow_stats[0],
                        tcp_analysis=tcp_analysis
                    )

                # 输出
                report_data = {
                    "flow_stats": flow_stats,
                    "tcp_analysis": tcp_analysis,
                    "smart_analysis": smart_analysis
                }

                if args.json:
                    reporter = JSONReporter()
                    print(reporter.generate(report_data))
                else:
                    reporter = TextReporter()
                    reporter.generate_detailed_report(report_data)

                    # 可视化
                    if args.output_dir:
                        visualizer = Visualizer(args.output_dir)

                        # 协议分布图
                        if 'protocol_distribution' in summary_stats:
                            visualizer.plot_protocol_distribution(
                                summary_stats['protocol_distribution']
                            )

                        # RTT分布图
                        if tcp_analysis and 'rtt_stats' in tcp_analysis:
                            visualizer.plot_rtt_distribution(
                                tcp_analysis['rtt_stats'].get('rtt_samples', [])
                            )

    except KeyboardInterrupt:
        print("\n操作已取消", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
```

#### 2.2.4 配置管理

```python
# common/utils/config.py

import yaml
from pathlib import Path
from typing import Dict, Any


class Config:
    """配置管理类"""

    def __init__(self, config_path: str = None):
        if config_path:
            self.config = self._load_from_file(config_path)
        else:
            self.config = self._load_default()

    def _load_default(self) -> Dict[str, Any]:
        """加载默认配置"""
        return {
            "pcap": {
                "batch_size": 10000,
                "max_memory_mb": 1024,
                "tshark_path": "tshark",
                "tcp_last_retrans": 3,
                "retrans_threshold": 0.01
            },
            "report": {
                "text": {
                    "width": 80
                },
                "json": {
                    "indent": 2
                },
                "visual": {
                    "dpi": 300,
                    "format": "png"
                }
            }
        }

    def _load_from_file(self, filepath: str) -> Dict[str, Any]:
        """从文件加载配置"""
        with open(filepath, 'r') as f:
            return yaml.safe_load(f)

    def get(self, key: str, default=None):
        """获取配置项"""
        keys = key.split('.')
        value = self.config

        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value):
        """设置配置项"""
        keys = key.split('.')
        config = self.config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def save(self, filepath: str):
        """保存配置到文件"""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False, indent=2)
```

---

## 3. TCPSocket分析工具设计

### 3.1 概要设计

#### 3.1.1 设计目标

TCPSocket分析工具旨在提供对TCP连接性能指标的时序分析，基于`ss -tinopm`采集的数据，提供：
- RTT、窗口、速率趋势分析
- 带宽利用率计算
- Buffer压力识别
- 瓶颈自动定位
- 调优建议生成

#### 3.1.2 核心概念

**关键指标**:
- **RTT**: 往返时间（ms）
- **RTTVar**: RTT方差（ms）
- **CWND**: 拥塞窗口（包数）
- **RWND**: 接收窗口（bytes）
- **SWND**: 发送窗口（bytes）
- **Pacing Rate**: 发送节奏控制速率（bps）
- **Delivery Rate**: 网络交付速率（bps）
- **Send Rate**: 发送缓冲区内存使用量（bytes）
- **BDP**: 带宽延迟积（理论最优窗口）

**Buffer指标** (skmem字段):
- **r**: 接收队列已分配内存
- **rb**: 接收缓冲区上限
- **t**: 发送队列已分配内存
- **tb**: 发送缓冲区上限
- **w**: 写队列排队内存（`w = t - unacked`）
- **d**: 丢包计数（最关键，>0表示有丢包）

#### 3.1.3 运行流程

```
开始
  │
  ├─► 解析命令行参数
  │   - input_dir: tcpsocket数据目录
  │   - bandwidth: 物理链路带宽（必填）
  │   - filter: 连接过滤器
  │   - time_range: 时间范围
  │   - output_format: 输出格式
  │
  ├─► 读取并解析ss数据
  │   - 读取所有采集文件
  │   - 解析每个文件的多行输出
  │   - 提取时间戳和所有指标
  │   - 构建时序数据
  │
  ├─► 连接识别与跟踪
  │   - 识别唯一连接（5元组）
  │   - 维护连接生命周期
  │   - 支持过滤指定连接
  │
  ├─► 时序数据分析
  │   ├─► RTT分析: 计算统计值和趋势
  │   ├─► 窗口分析: CWND/RWND/SWND vs BDP
  │   ├─► 速率分析: pacing vs delivery利用率
  │   ├─► Buffer分析: r/rb, t/tb, w变化
  │   └─► 重传分析: 重传率和趋势
  │
  ├─► 瓶颈识别与诊断
  │   ├─► 计算带宽利用率
  │   ├─► 识别CWND限制、RWND限制、sndbuf限制
  │   ├─► 检测Buffer压力（d>0, r/rb>0.8, t/tb>0.8）
  │   ├─► Buffer健康度评分
  │   └─► 生成调优建议
  │
  └─► 输出报告
      - 文本报告（分级章节）
      - JSON数据（结构化）
      - 时序图（RTT、窗口、Buffer）
      - 堆积图（Send-Q、Buffer、Unacked）
      - 热图（buffer使用率）
```

### 3.2 详细设计

#### 3.2.1 核心模块设计

##### 3.2.1.1 SS输出解析器 (SSOutputParser)

**职责**: 解析`ss -tinopm`采集的原始文本数据

**接口设计**:
```python
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any, Iterator
import re


@dataclass
class SSSample:
    """SS采样本"""
    timestamp: datetime
    state: str
    recv_q: int
    send_q: int
    local_ip: str
    local_port: int
    peer_ip: str
    peer_port: int
    # TCP指标
    rtt: float = None
    rtt_var: float = None
    rto: float = None
    mss: int = None
    cwnd: int = None
    snd_wnd: int = None
    rcv_space: int = None
    rcv_ssthresh: int = None
    # 速率（bps）
    send_rate: float = None
    pacing_rate: float = None
    delivery_rate: float = None
    # 重传
    retrans: int = None
    retrans_total: int = None
    unacked: int = None
    lost: int = None
    sacked: int = None
    dsack_dups: int = None
    # Buffer
    r: int = None
    rb: int = None
    t: int = None
    tb: int = None
    f: int = None
    w: int = None
    o: int = None
    bl: int = None
    d: int = None
    # 限制比例
    rwnd_limited_ms: int = None
    sndbuf_limited_ms: int = None
    cwnd_limited_ms: int = None


### 3.2.1.2 时序数据构建器 (TimeSeriesBuilder)

**职责**: 将多个SS样本构建成时间序列数据，执行数据对齐、插值等处理

**接口设计**:
```python
from typing import Dict, List, Optional
import pandas as pd
from collections import defaultdict


class TimeSeriesBuilder:
    """时序数据构建器"""

    def __init__(self):
        self.connections: Dict[str, List[SSSample]] = defaultdict(list)

    def add_samples(self, samples: List[SSSample]):
        """
        添加样本

        Args:
            samples: SS样本列表
        """
        for sample in samples:
            # 连接标识（5元组）
            conn_id = f"{sample.local_ip}:{sample.local_port}-{sample.peer_ip}:{sample.peer_port}-{sample.state}"
            self.connections[conn_id].append(sample)

    def build_timeseries(self, connection_filter: str = None) -> Dict[str, pd.DataFrame]:
        """
        构建时序数据

        Args:
            connection_filter: 连接过滤器（格式: IP:PORT-IP:PORT）

        Returns:
            时序数据字典，key为连接ID，value为DataFrame
        """
        timeseries = {}

        for conn_id, samples in self.connections.items():
            # 应用过滤器
            if connection_filter and not self._match_filter(conn_id, connection_filter):
                continue

            # 按时间排序
            samples = sorted(samples, key=lambda s: s.timestamp)

            # 转换为DataFrame
            df = self._samples_to_dataframe(samples)

            timeseries[conn_id] = df

        return timeseries

    def _match_filter(self, conn_id: str, filter_expr: str) -> bool:
        """匹配连接过滤器"""
        # filter_expr格式: 10.0.0.1:48270-10.0.0.2:5201
        parts = filter_expr.split('-')
        if len(parts) != 2:
            return True

        src = parts[0]
        dst = parts[1]

        # conn_id格式: 10.0.0.1:48270-10.0.0.2:5201-ESTAB
        return src in conn_id and dst in conn_id

    def _samples_to_dataframe(self, samples: List[SSSample]) -> pd.DataFrame:
        """样本转换为DataFrame"""
        data = []

        for sample in samples:
            data.append({
                'timestamp': sample.timestamp,
                'rtt': sample.rtt,
                'rtt_var': sample.rtt_var,
                'rto': sample.rto,
                'cwnd': sample.cwnd,
                'snd_wnd': sample.snd_wnd,
                'rcv_space': sample.rcv_space,
                'pacing_rate': sample.pacing_rate,
                'delivery_rate': sample.delivery_rate,
                'send_rate': sample.send_rate,
                'unacked': sample.unacked,
                'retrans': sample.retrans_total,
                'r': sample.r,
                'rb': sample.rb,
                't': sample.t,
                'tb': sample.tb,
                'w': sample.w,
                'd': sample.d,
                'rwnd_limited_ms': sample.rwnd_limited_ms,
                'sndbuf_limited_ms': sample.sndbuf_limited_ms,
                'cwnd_limited_ms': sample.cwnd_limited_ms
            })

        df = pd.DataFrame(data)
        df.set_index('timestamp', inplace=True)

        return df

    def interpolate(self, df: pd.DataFrame, freq: str = '1S') -> pd.DataFrame:
        """
        插值处理（可选）

        如果采样间隔不均匀，可以进行插值

        Args:
            df: 原始DataFrame
            freq: 插值频率（默认1秒）

        Returns:
            插值后的DataFrame
        """
        # 重新采样
        resampled = df.asfreq(freq)

        # 线性插值
        interpolated = resampled.interpolate(method='linear')

        return interpolated

    def align_connections(self, timeseries: Dict[str, pd.DataFrame],
                         start_time: Optional[pd.Timestamp] = None,
                         end_time: Optional[pd.Timestamp] = None) -> Dict[str, pd.DataFrame]:
        """
        对齐连接时间范围

        Args:
            timeseries: 时序数据字典
            start_time: 起始时间
            end_time: 结束时间

        Returns:
            对齐后的时序数据
        """
        aligned = {}

        for conn_id, df in timeseries.items():
            # 过滤时间范围
            if start_time:
                df = df[df.index >= start_time]
            if end_time:
                df = df[df.index <= end_time]

            aligned[conn_id] = df

        return aligned


class ConnectionTracker:
    """连接跟踪器"""

    def __init__(self):
        self.connections: Dict[str, Dict[str, Any]] = {}

    def track(self, samples: List[SSSample]):
        """跟踪连接"""
        for sample in samples:
            conn_id = self._make_conn_id(sample)

            if conn_id not in self.connections:
                self.connections[conn_id] = {
                    'local_ip': sample.local_ip,
                    'local_port': sample.local_port,
                    'peer_ip': sample.peer_ip,
                    'peer_port': sample.peer_port,
                    'state': sample.state,
                    'start_time': sample.timestamp,
                    'end_time': sample.timestamp,
                    'sample_count': 0
                }

            # 更新结束时间
            conn = self.connections[conn_id]
            conn['end_time'] = sample.timestamp
            conn['sample_count'] += 1

    def _make_conn_id(self, sample: SSSample) -> str:
        """生成连接ID"""
        return f"{sample.local_ip}:{sample.local_port}-{sample.peer_ip}:{sample.peer_port}-{sample.state}"

    def get_connections(self) -> List[Dict]:
        """获取所有连接"""
        return list(self.connections.values())

    def get_connection_stats(self) -> Dict[str, Any]:
        """获取连接统计"""
        connections = self.get_connections()

        return {
            'total_connections': len(connections),
            'connection_durations': [
                (c['end_time'] - c['start_time']).total_seconds()
                for c in connections
            ]
        }
```

##### 3.2.1.3 RTT分析器 (RTTAnalyzer)

**职责**: 分析RTT指标，计算统计值、分位数和趋势

**接口设计**:
```python
import numpy as np
from scipy import stats


class RTTAnalyzer:
    """RTT分析器"""

    def analyze(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析RTT

        Args:
            df: 时序数据DataFrame

        Returns:
            分析结果
            {
                "basic_stats": {
                    "min": float,        # ms
                    "max": float,        # ms
                    "mean": float,       # ms
                    "std": float,        # 标准差
                    "variance": float    # 方差
                },
                "percentiles": {
                    "p50": float,        # 中位数
                    "p75": float,
                    "p90": float,
                    "p95": float,
                    "p99": float
                },
                "trend": {
                    "direction": "increasing" | "decreasing" | "stable",
                    "slope": float,      # 线性回归斜率
                    "p_value": float,    # 显著性
                    "r_squared": float   # 拟合优度
                },
                "stability": {
                    "jitter": float,     # 抖动（ms）
                    "cv": float          # 变异系数
                },
                "outliers": List[Dict]  # 异常点
            }
        """
        rtt_series = df['rtt'].dropna()

        if rtt_series.empty:
            return {"error": "No RTT data available"}

        # 基本统计
        basic_stats = {
            'min': float(rtt_series.min()),
            'max': float(rtt_series.max()),
            'mean': float(rtt_series.mean()),
            'std': float(rtt_series.std()),
            'variance': float(rtt_series.var())
        }

        # 分位数
        percentiles = {
            'p50': float(np.percentile(rtt_series, 50)),
            'p75': float(np.percentile(rtt_series, 75)),
            'p90': float(np.percentile(rtt_series, 90)),
            'p95': float(np.percentile(rtt_series, 95)),
            'p99': float(np.percentile(rtt_series, 99))
        }

        # 趋势分析（线性回归）
        timestamps = np.arange(len(rtt_series))
        slope, intercept, r_value, p_value, std_err = stats.linregress(
            timestamps, rtt_series
        )

        # 判断趋势方向
        if abs(slope) < 0.1:
            direction = 'stable'
        elif slope > 0:
            direction = 'increasing'
        else:
            direction = 'decreasing'

        trend = {
            'direction': direction,
            'slope': float(slope),
            'p_value': float(p_value),
            'r_squared': float(r_value ** 2)
        }

        # 稳定性
        jitter = rtt_series.diff().abs().mean()
        cv = rtt_series.std() / rtt_series.mean() if rtt_series.mean() != 0 else 0

        stability = {
            'jitter': float(jitter),
            'cv': float(cv)
        }

        # 异常点检测（使用IQR方法）
        outliers = self._detect_outliers(rtt_series, df)

        return {
            'basic_stats': basic_stats,
            'percentiles': percentiles,
            'trend': trend,
            'stability': stability,
            'outliers': outliers
        }

    def _detect_outliers(self, series: pd.Series, df: pd.DataFrame) -> List[Dict]:
        """
        检测RTT异常点（使用IQR方法）

        Args:
            series: RTT序列
            df: 原始DataFrame

        Returns:
            异常点列表
        """
        Q1 = np.percentile(series, 25)
        Q3 = np.percentile(series, 75)
        IQR = Q3 - Q1

        lower_bound = Q1 - 1.5 * IQR
        upper_bound = Q3 + 1.5 * IQR

        outliers = []

        for idx, value in series.iteritems():
            if value < lower_bound or value > upper_bound:
                # 找出原因
                cause = self._analyze_outlier_cause(df, idx)

                outliers.append({
                    'timestamp': idx.isoformat(),
                    'value': float(value),
                    'bound': 'upper' if value > upper_bound else 'lower',
                    'cause': cause
                })

        return outliers

    def _analyze_outlier_cause(self, df: pd.DataFrame, timestamp) -> str:
        """
        分析异常点原因

        Args:
            df: DataFrame
            timestamp: 异常点时间戳

        Returns:
            原因描述
        """
        row = df.loc[timestamp]

        causes = []

        # 检查是否重传
        if 'retrans' in row and row['retrans'] > 0:
            causes.append('重传')

        # 检查是否丢包
        if 'd' in row and row['d'] > 0:
            causes.append('丢包')

        # 检查是否窗口受限
        if 'cwnd_limited_ms' in row and row['cwnd_limited_ms'] > 0:
            causes.append('CWND受限')

        # 检查是否Buffer满
        if 't' in row and 'tb' in row and row['t'] > row['tb'] * 0.9:
            causes.append('发送缓冲区满')

        return ' + '.join(causes) if causes else '未知'

    def generate_time_series_plot(self, df: pd.DataFrame,
                                save_path: str = None) -> Optional[str]:
        """
        生成RTT时序图

        Args:
            df: 时序数据
            save_path: 保存路径

        Returns:
            文件路径或None
        """
        if 'rtt' not in df.columns or df['rtt'].isna().all():
            return None

        plt.figure(figsize=(14, 6))

        # 绘制RTT时序
        plt.plot(df.index, df['rtt'], color='blue', linewidth=1, alpha=0.7, label='RTT')

        # 添加移动平均线
        rtt_ma = df['rtt'].rolling(window=10, min_periods=1).mean()
        plt.plot(df.index, rtt_ma, color='red', linewidth=2, linestyle='--',
                label='移动平均（10样本）')

        # 添加分位数线
        rtt_series = df['rtt'].dropna()
        p50 = np.percentile(rtt_series, 50)
        p95 = np.percentile(rtt_series, 95)

        plt.axhline(y=p50, color='green', linestyle=':', alpha=0.7, label=f'P50={p50:.1f}ms')
        plt.axhline(y=p95, color='orange', linestyle=':', alpha=0.7, label=f'P95={p95:.1f}ms')

        # 标记异常点
        outliers = self._detect_outliers(rtt_series, df)
        if outliers:
            outlier_times = [pd.Timestamp(o['timestamp']) for o in outliers]
            outlier_values = [o['value'] for o in outliers]
            plt.scatter(outlier_times, outlier_values, color='red', s=50, marker='o',
                       zorder=5, label=f'异常点({len(outliers)})')

        plt.title('RTT时序分析')
        plt.xlabel('时间')
        plt.ylabel('RTT (ms)')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.xticks(rotation=45)

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            plt.close()
            return save_path
        else:
            plt.show()
            return None


##### 3.2.1.4 窗口分析器 (WindowAnalyzer)

**职责**: 分析CWND/RWND/SWND，与BDP对比，识别窗口限制

**接口设计**:
```python
from typing import Tuple


class WindowAnalyzer:
    """窗口分析器"""

    def __init__(self, bandwidth_bps: float):
        """
        初始化

        Args:
            bandwidth_bps: 物理链路带宽（bps）
        """
        self.bandwidth_bps = bandwidth_bps

    def analyze(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析窗口

        Args:
            df: 时序数据

        Returns:
            分析结果
        """
        if df.empty:
            return {"error": "No data available"}

        # 计算BDP
        bdp_results = self._calculate_bdp(df)

        # 分析窗口受限
        limitation_results = self._analyze_limitations(df)

        # CWND分析
        cwnd_results = self._analyze_cwnd(df, bdp_results)

        # RWND分析
        rwnd_results = self._analyze_rwnd(df)

        return {
            'bdp': bdp_results,
            'limitations': limitation_results,
            'cwnd': cwnd_results,
            'rwnd': rwnd_results
        }

    def _calculate_bdp(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        计算BDP（带宽延迟积）

        BDP = 带宽 (bytes/s) × RTT (s)

        Returns:
            {
                "avg_rtt": float,        # 平均RTT（秒）
                "bdp_bytes": float,      # BDP（字节）
                "bdp_packets": float,    # BDP（包数）
                "expected_cwnd": float   # 期望CWND（包数）
            }
        """
        # 平均RTT（秒）
        avg_rtt_ms = df['rtt'].mean() if not df['rtt'].isna().all() else 100
        avg_rtt_sec = avg_rtt_ms / 1000

        # BDP（字节）
        bandwidth_bytes_per_sec = self.bandwidth_bps / 8
        bdp_bytes = bandwidth_bytes_per_sec * avg_rtt_sec

        # MSS（默认1460）
        mss = df['mss'].iloc[-1] if 'mss' in df and not df['mss'].isna().all()
        else 1460

        # BDP（包数）
        bdp_packets = bdp_bytes / mss

        # 期望CWND（考虑TCP窗口缩放）
        # 通常BDP × 2作为缓冲区余量
        expected_cwnd = bdp_packets * 2

        return {
            'avg_rtt': avg_rtt_sec,
            'bdp_bytes': bdp_bytes,
            'bdp_packets': bdp_packets,
            'expected_cwnd': expected_cwnd,
            'mss': mss
        }

    def _analyze_limitations(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析窗口限制

        Returns:
            {
                "rwnd_limited_ratio": float,      # RWND限制比例
                "sndbuf_limited_ratio": float,     # sndbuf限制比例
                "cwnd_limited_ratio": float,      # CWND限制比例
                "primary_limitation": str          # 主要限制因素
            }
        """
        total_duration = (df.index[-1] - df.index[0]).total_seconds() * 1000

        # 计算各限制的总时间
        rwnd_time = df['rwnd_limited_ms'].fillna(0).sum() if 'rwnd_limited_ms' in df else 0
        sndbuf_time = df['sndbuf_limited_ms'].fillna(0).sum() if 'sndbuf_limited_ms' in df else 0
        cwnd_time = df['cwnd_limited_ms'].fillna(0).sum() if 'cwnd_limited_ms' in df else 0

        # 计算比例
        rwnd_ratio = rwnd_time / total_duration if total_duration > 0 else 0
        sndbuf_ratio = sndbuf_time / total_duration if total_duration > 0 else 0
        cwnd_ratio = cwnd_time / total_duration if total_duration > 0 else 0

        # 主要限制因素
        ratios = {
            'RWND限制': rwnd_ratio,
            'sndbuf限制': sndbuf_ratio,
            'CWND限制': cwnd_ratio
        }
        primary = max(ratios.items(), key=lambda x: x[1])

        return {
            'rwnd_limited_ratio': rwnd_ratio,
            'sndbuf_limited_ratio': sndbuf_ratio,
            'cwnd_limited_ratio': cwnd_ratio,
            'primary_limitation': primary[0],
            'primary_limitation_ratio': primary[1]
        }

    def _analyze_cwnd(self, df: pd.DataFrame, bdp_results: Dict) -> Dict[str, Any]:
        """
        分析CWND

        Returns:
            {
                "avg_cwnd": float,
                "max_cwnd": float,
                "min_cwnd": float,
                "cwnd_vs_bdp_ratio": float,      # CWND/BDP
                "cwnd_efficiency": float,         # 窗口利用效率
                "underutilized_periods": int      # 窗口不足的时间段数
            }
        """
        if 'cwnd' not in df.columns or df['cwnd'].isna().all():
            return {"error": "No CWND data available"}

        cwnd_series = df['cwnd'].dropna()

        # 基本统计
        avg_cwnd = cwnd_series.mean()
        max_cwnd = cwnd_series.max()
        min_cwnd = cwnd_series.min()

        # 与BDP对比
        expected_cwnd = bdp_results['expected_cwnd']
        cwnd_vs_bdp_ratio = avg_cwnd / expected_cwnd if expected_cwnd > 0 else 0

        # 窗口效率：实际窗口/发送窗口可用量
        if 'unacked' in df:
            actual_wnd = df['unacked'].fillna(0)
            available_wnd = df['cwnd'].fillna(0)
            cwnd_efficiency = (actual_wnd / available_wnd).mean()
        else:
            cwnd_efficiency = 1.0

        return {
            'avg_cwnd': float(avg_cwnd),
            'max_cwnd': float(max_cwnd),
            'min_cwnd': float(min_cwnd),
            'cwnd_vs_bdp_ratio': float(cwnd_vs_bdp_ratio),
            'cwnd_efficiency': float(cwnd_efficiency),
            'expected_cwnd': expected_cwnd,
            'cwnd_underutilized': cwnd_vs_bdp_ratio < 0.8
        }

    def _analyze_rwnd(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析RWND

        Returns:
            {
                "avg_rcv_space": float,
                "rwnd_changes": List,        # RWND变化点
                "window_shrink_events": int  # 窗口收缩事件数
            }
        """
        if 'rcv_space' not in df.columns or df['rcv_space'].isna().all():
            return {"error": "No RWND data available"}

        rwnd_series = df['rcv_space'].dropna()

        # 基本统计
        avg_rcv_space = rwnd_series.mean()

        # 检测窗口变化
        rwnd_changes = []
        prev_rwnd = None

        for idx, rwnd in rwnd_series.iteritems():
            if prev_rwnd is None:
                prev_rwnd = rwnd
                continue

            if abs(rwnd - prev_rwnd) > prev_rwnd * 0.1:  # 变化超过10%
                rwnd_changes.append({
                    'timestamp': idx.isoformat(),
                    'old_value': float(prev_rwnd),
                    'new_value': float(rwnd)
                })

            prev_rwnd = rwnd

        # 窗口收缩事件
        window_shrink_events = sum(
            1 for change in rwnd_changes if change['new_value'] < change['old_value']
        )

        return {
            'avg_rcv_space': float(avg_rcv_space),
            'rwnd_changes': rwnd_changes,
            'window_shrink_events': window_shrink_events
        }

    def generate_cwnd_plot(self, df: pd.DataFrame, save_path: str = None) -> Optional[str]:
        """
        生成CWND时序图（叠加BDP参考线）
        """
        if 'cwnd' not in df.columns or df['cwnd'].isna().all():
            return None

        plt.figure(figsize=(14, 6))

        # 绘制CWND
        plt.plot(df.index, df['cwnd'], color='blue', linewidth=1.5, label='CWND')

        # 计算BDP并绘制参考线
        bdp = self._calculate_bdp(df)
        expected_cwnd = bdp['expected_cwnd']

        plt.axhline(y=expected_cwnd, color='red', linestyle='--', linewidth=2,
                   label=f'期望CWND (BDP={expected_cwnd:.1f})')

        plt.title('CWND时序分析（对比BDP）')
        plt.xlabel('时间')
        plt.ylabel('CWND（包数）')
        plt.legend()
        plt.grid(True, alpha=0.3)

        # 添加说明
        plt.figtext(0.5, 0.02,
                   f"MSS={bdp['mss']}, BDP={bdp['bdp_packets']:.1f} packets",
                   ha='center', va='bottom')

        plt.xticks(rotation=45)
        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            plt.close()
            return save_path
        else:
            plt.show()
            return None


##### 3.2.1.5 Buffer分析器 (BufferAnalyzer)

**职责**: 分析Buffer状态，识别压力点，计算健康度

**接口设计**:
```python
class BufferAnalyzer:
    """Buffer分析器（基于Kernel调研结果）"""

    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化

        Args:
            config: 配置
                - r_threshold: 接收Buffer阈值（0.8）
                - t_threshold: 发送Buffer阈值（0.8）
                - w_threshold: 写队列阈值（0.6）
        """
        self.config = config or {}
        self.r_threshold = self.config.get('r_threshold', 0.8)
        self.t_threshold = self.config.get('t_threshold', 0.8)
        self.w_threshold = self.config.get('w_threshold', 0.6)

    def analyze(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析Buffer

        Args:
            df: 时序数据

        Returns:
            分析结果
        """
        # 接收Buffer分析
        rx_results = self._analyze_rx_buffer(df)

        # 发送Buffer分析
        tx_results = self._analyze_tx_buffer(df)

        # Write Queue分析
        w_results = self._analyze_write_queue(df)

        # 健康度评分
        health_score = self._calculate_health_score(rx_results, tx_results, w_results)

        return {
            'rx_buffer': rx_results,
            'tx_buffer': tx_results,
            'write_queue': w_results,
            'health_score': health_score,
            'pressure_events': self._detect_pressure_events(df)
        }

    def _analyze_rx_buffer(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析接收Buffer

        Returns:
            {
                "r_avg": float,              # r平均值
                "r_max": float,              # r最大值
                "rb_avg": float,             # rb平均值
                "utilization_avg": float,    # 平均使用率
                "utilization_max": float,    # 最大使用率
                "drops": int,                # 丢包计数（d>0）
                "high_pressure_time": float  # 高压时间（秒）
            }
        """
        if df.empty or 'r' not in df.columns:
            return {"error": "No data available"}

        # 基本统计
        r_avg = df['r'].mean()
        r_max = df['r'].max()
        rb_avg = df['rb'].mean() if 'rb' in df else 0

        # 计算使用率
        utilization = df['r'] / df['rb'].replace(0, 1)
        utilization_avg = utilization.mean()
        utilization_max = utilization.max()

        # 丢包（d>0）
        drops = 0
        if 'd' in df:
            drops = (df['d'] > 0).sum()

        # 高压时间（r/rb > threshold）
        high_pressure = utilization > self.r_threshold
        high_pressure_time = high_pressure.sum() * df.index.freq.nanos / 1e9 \
                           if hasattr(df.index, 'freq') else 0

        return {
            'r_avg': float(r_avg),
            'r_max': float(r_max),
            'rb_avg': float(rb_avg),
            'utilization_avg': float(utilization_avg),
            'utilization_max': float(utilization_max),
            'drops': int(drops),
            'high_pressure_time': float(high_pressure_time)
        }

    def _analyze_tx_buffer(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析发送Buffer

        Returns:
            {
                "t_avg": float,              # t平均值
                "t_max": float,              # t最大值
                "tb_avg": float,             # tb平均值
                "utilization_avg": float,    # 平均使用率
                "utilization_max": float     # 最大使用率
            }
        """
        if df.empty or 't' not in df.columns:
            return {"error": "No data available"}

        t_avg = df['t'].mean()
        t_max = df['t'].max()
        tb_avg = df['tb'].mean() if 'tb' in df else 0

        utilization = df['t'] / df['tb'].replace(0, 1)
        utilization_avg = utilization.mean()
        utilization_max = utilization.max()

        return {
            't_avg': float(t_avg),
            't_max': float(t_max),
            'tb_avg': float(tb_avg),
            'utilization_avg': float(utilization_avg),
            'utilization_max': float(utilization_max)
        }

    def _analyze_write_queue(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析写队列w（基于调研：w = t - unacked）

        Returns:
            {
                "w_avg": float,               # w平均值
                "w_max": float,               # w最大值
                "w_rel_t_avg": float,         # w/t平均比例
                "w_rel_unacked_avg": float    # w/unacked平均比例
            }
        """
        if df.empty or 'w' not in df.columns:
            return {"error": "No data available"}

        w_avg = df['w'].mean()
        w_max = df['w'].max()

        # w/t比例
        w_rel_t = df['w'] / df['t'].replace(0, 1)
        w_rel_t_avg = w_rel_t.mean()

        # w/unacked比例（验证w = t - unacked）
        if 'unacked' in df:
            w_rel_unacked = df['w'] / df['unacked'].replace(0, 1)
            w_rel_unacked_avg = w_rel_unacked.mean()
        else:
            w_rel_unacked_avg = None

        return {
            'w_avg': float(w_avg),
            'w_max': float(w_max),
            'w_rel_t_avg': float(w_rel_t_avg),
            'w_rel_unacked_avg': float(w_rel_unacked_avg) if w_rel_unacked_avg else None
        }

    def _calculate_health_score(self, rx_results: Dict,
                               tx_results: Dict,
                               w_results: Dict) -> Dict[str, Any]:
        """
        计算Buffer健康度评分（0-100）

        评分标准（基于调研报告）：
        - sk_drops > 0: -50分（直接扣50）
        - r/rb > 0.9: -20分
        - r/rb > 0.8: -10分
        - r/rb > 0.7: -5分
        - t/tb > 0.9: -15分
        - t/tb > 0.8: -7分
        - w/tb > 0.8: -10分

        返回:
            {
                "score": int,              # 0-100
                "grade": str,              # 等级：优秀/良好/一般/较差/严重
                "reasons": List[str]       # 扣分原因
            }
        """
        score = 100
        reasons = []

        # 丢包（最严重）
        if 'drops' in rx_results and rx_results['drops'] > 0:
            score -= 50
            reasons.append(f"检测到丢包: {rx_results['drops']}次")

        # 接收Buffer压力
        if 'utilization_avg' in rx_results:
            if rx_results['utilization_avg'] > 0.9:
                score -= 20
                reasons.append(f"接收Buffer压力高: {rx_results['utilization_avg']:.1%}")
            elif rx_results['utilization_avg'] > 0.8:
                score -= 10
                reasons.append(f"接收Buffer压力较高: {rx_results['utilization_avg']:.1%}")
            elif rx_results['utilization_avg'] > 0.7:
                score -= 5
                reasons.append(f"接收Buffer压力: {rx_results['utilization_avg']:.1%}")

        # 发送Buffer压力
        if 'utilization_avg' in tx_results:
            if tx_results['utilization_avg'] > 0.9:
                score -= 15
                reasons.append(f"发送Buffer压力高: {tx_results['utilization_avg']:.1%}")
            elif tx_results['utilization_avg'] > 0.8:
                score -= 7
                reasons.append(f"发送Buffer压力: {tx_results['utilization_avg']:.1%}")

        # 写队列堆积
        if 'w_rel_t_avg' in w_results and w_results['w_rel_t_avg']:
            if w_results['w_rel_t_avg'] > 0.8:
                score -= 10
                reasons.append(f"写队列堆积: {w_results['w_rel_t_avg']:.1%}")

        # 确保分数在0-100范围内
        score = max(0, score)

        # 分级
        if score >= 90:
            grade = "优秀"
        elif score >= 70:
            grade = "良好"
        elif score >= 50:
            grade = "一般"
        elif score >= 30:
            grade = "较差"
        else:
            grade = "严重"

        return {
            'score': score,
            'grade': grade,
            'reasons': reasons
        }

    def _detect_pressure_events(self, df: pd.DataFrame) -> List[Dict]:
        """
        检测压力事件

        返回:
            [
                {
                    "timestamp": str,
                    "type": "sk_drops" | "rx_pressure" | "tx_pressure",
                    "severity": "high" | "medium",
                    "value": float
                }
            ]
        """
        events = []

        # 检测丢包事件（d>0）
        if 'd' in df.columns:
            drops = df[df['d'] > 0]
            for timestamp, row in drops.iterrows():
                events.append({
                    'timestamp': timestamp.isoformat(),
                    'type': 'sk_drops',
                    'severity': 'high',
                    'value': int(row['d']),
                    'description': 'Socket层丢包'
                })

        # 检测接收Buffer高压
        if all(col in df.columns for col in ['r', 'rb']):
            rx_pressure = df[df['r'] / df['rb'] > self.r_threshold]
            for timestamp, row in rx_pressure.iterrows():
                events.append({
                    'timestamp': timestamp.isoformat(),
                    'type': 'rx_pressure',
                    'severity': 'medium',
                    'value': float(row['r'] / row['rb']),
                    'description': '接收Buffer压力高'
                })

        # 检测发送Buffer高压
        if all(col in df.columns for col in ['t', 'tb']):
            tx_pressure = df[df['t'] / df['tb'] > self.t_threshold]
            for timestamp, row in tx_pressure.iterrows():
                events.append({
                    'timestamp': timestamp.isoformat(),
                    'type': 'tx_pressure',
                    'severity': 'medium',
                    'value': float(row['t'] / row['tb']),
                    'description': '发送Buffer压力高'
                })

        return events

    def generate_buffer_pressure_plot(self, df: pd.DataFrame,
                                     save_path: str = None) -> Optional[str]:
        """
        生成Buffer压力时序图

        Args:
            df: 时序数据
            save_path: 保存路径

        Returns:
            文件路径或None
        """
        fig, axes = plt.subplots(3, 1, figsize=(14, 12))

        # 接收Buffer
        if all(col in df.columns for col in ['r', 'rb']):
            ax1 = axes[0]
            ax1.fill_between(df.index, 0, df['r'], alpha=0.7, color='blue', label='r (已使用)')
            ax1.plot(df.index, df['rb'], color='red', linestyle='--', linewidth=2, label='rb (上限)')
            ax1.set_title('接收Buffer（r/rb）')
            ax1.set_ylabel('Bytes')
            ax1.legend()
            ax1.grid(True, alpha=0.3)

        # 发送Buffer
        if all(col in df.columns for col in ['t', 'tb']):
            ax2 = axes[1]
            ax2.fill_between(df.index, 0, df['t'], alpha=0.7, color='green', label='t (已使用)')
            ax2.plot(df.index, df['tb'], color='red', linestyle='--', linewidth=2, label='tb (上限)')
            ax2.set_title('发送Buffer（t/tb）')
            ax2.set_ylabel('Bytes')
            ax2.legend()
            ax2.grid(True, alpha=0.3)

        # 写队列
        if 'w' in df.columns:
            ax3 = axes[2]
            ax3.fill_between(df.index, 0, df['w'], alpha=0.7, color='orange', label='w (写队列)')
            ax3.set_title('写队列排队（w）')
            ax3.set_ylabel('Bytes')
            ax3.legend()
            ax3.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.xticks(rotation=45)

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            plt.close()
            return save_path
        else:
            plt.show()
            return None

    def generate_tuning_recommendations(self, analysis_results: Dict) -> List[Dict]:
        """
        生成调优建议（基于调研报告的算法）

        Args:
            analysis_results: 分析结果

        Returns:
            建议列表
        """
        recommendations = []

        rx = analysis_results.get('rx_buffer', {})
        tx = analysis_results.get('tx_buffer', {})
        health = analysis_results.get('health_score', {})

        # 检查丢包
        if rx.get('drops', 0) > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'receive_buffer',
                'issue': 'Socket层丢包',
                'evidence': f"sk_drops={rx['drops']}",
                'recommendation': '立即增大接收缓冲区',
                'commands': [
                    'sysctl -w net.core.rmem_max=134217728',
                    'sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"'
                ]
            })

        # 接收Buffer压力
        if rx.get('utilization_avg', 0) > 0.9:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'receive_buffer',
                'issue': '接收Buffer压力严重',
                'evidence': f"利用率={rx['utilization_avg']:.1%}",
                'recommendation': '增大tcp_rmem上限，并检查应用读取性能',
                'metrics_to_check': ['Recv-Q', '应用CPU使用率', '系统调用延迟']
            })
        elif rx.get('utilization_avg', 0) > 0.8:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'receive_buffer',
                'issue': '接收Buffer压力较高',
                'recommendation': '建议增大tcp_rmem或优化应用读取'
            })

        # 发送Buffer压力
        if tx.get('utilization_avg', 0) > 0.9:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'send_buffer',
                'issue': '发送Buffer压力高',
                'recommendation': '增大tcp_wmem上限',
                'commands': [
                    'sysctl -w net.ipv4.tcp_wmem="4096 16384 4194304"',
                    'sysctl -w net.core.wmem_max=212992'
                ]
            })

        return recommendations

##### 3.2.1.6 速率分析器 (RateAnalyzer)

**职责**: 分析三类Rate（pacing_rate, delivery_rate, send_rate），计算带宽利用率和理想/实际比值

**接口设计**:
```python
class RateAnalyzer:
    """速率分析器（基于Kernel调研）"""

    def __init__(self, bandwidth_bps: float):
        """
        初始化

        Args:
            bandwidth_bps: 物理链路带宽（bps）
        """
        self.bandwidth_bps = bandwidth_bps

    def analyze(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析速率

        Args:
            df: 时序数据

        Returns:
            分析结果
        """
        # Pacing Rate分析
        pacing_results = self._analyze_pacing_rate(df)

        # Delivery Rate分析
        delivery_results = self._analyze_delivery_rate(df)

        # Send Rate分析（注意：send_rate是内存使用量，不是速率）
        send_results = self._analyze_send_rate(df)

        # 带宽利用率
        bandwidth_utilization = self._calculate_bandwidth_utilization(df)

        return {
            'pacing_rate': pacing_results,
            'delivery_rate': delivery_results,
            'send_rate': send_results,
            'bandwidth_utilization': bandwidth_utilization
        }

    def _analyze_pacing_rate(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析pacing_rate

        Returns:
            {
                "avg": float,          # 平均值
                "max": float,          # 最大值
                "percent_of_bw": float  # 占带宽比例
            }
        """
        if 'pacing_rate' not in df.columns or df['pacing_rate'].isna().all():
            return {"error": "No pacing_rate data"}

        pacing = df['pacing_rate'].dropna()

        avg = pacing.mean()
        max_val = pacing.max()
        percent_of_bw = avg / self.bandwidth_bps if self.bandwidth_bps > 0 else 0

        return {
            'avg': float(avg),
            'max': float(max_val),
            'percent_of_bw': float(percent_of_bw)
        }

    def _analyze_delivery_rate(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析delivery_rate

        依据调研：delivery_rate是网络交付能力估算，每个ACK采样

        Returns:
            {
                "avg": float,
                "max": float,
                "percent_of_bw": float,
                "vs_pacing_ratio": float  # delivery/pacing比值
            }
        """
        if 'delivery_rate' not in df.columns or df['delivery_rate'].isna().all():
            return {"error": "No delivery_rate data"}

        delivery = df['delivery_rate'].dropna()

        avg = delivery.mean()
        max_val = delivery.max()
        percent_of_bw = avg / self.bandwidth_bps if self.bandwidth_bps > 0 else 0

        # 与pacing_rate比值（基于调研的理想情况）
        vs_pacing_ratio = (avg / df['pacing_rate'].mean()) if 'pacing_rate' in df else 0

        return {
            'avg': float(avg),
            'max': float(max_val),
            'percent_of_bw': float(percent_of_bw),
            'vs_pacing_ratio': float(vs_pacing_ratio)
        }

    def _analyze_send_rate(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        分析send_rate

        注意：基于调研结果，send_rate不是速率而是发送缓冲区内存使用量（bytes）

        Returns:
            {
                "avg_bytes": float,
                "max_bytes": float,
                "note": "这是发送缓冲区内存使用量，不是发送速率"
            }
        """
        if 'send_rate' not in df.columns or df['send_rate'].isna().all():
            return {"error": "No send_rate data"}

        send = df['send_rate'].dropna()

        avg = send.mean()
        max_val = send.max()

        return {
            'avg_bytes': float(avg),
            'max_bytes': float(max_val),
            'note': '这是发送缓冲区内存使用量（inet_diag_meminfo.idiag_wmem），不是发送速率'
        }

    def _calculate_bandwidth_utilization(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        计算带宽利用率

        带宽利用率 = (平均delivery_rate / 物理链路带宽) × 100%

        判断标准：
        - < 30%: 利用率低，存在CWND/RWND限制或应用受限
        - 30%-70%: 正常范围
        - > 70%: 利用率良好
        - > 90%: 接近上限

        Returns:
            {
                "avg_delivery_rate": float,
                "utilization_percent": float,
                "grade": str,              # 等级：优秀/良好/一般/不足
                "issues": List[str]        # 可能的问题
            }
        """
        if 'delivery_rate' not in df.columns:
            return {"error": "No delivery_rate data"}

        avg_delivery = df['delivery_rate'].mean()
        utilization = avg_delivery / self.bandwidth_bps * 100

        # 评级
        if utilization > 90:
            grade = '饱和度极高'
            issues = ['可能出现排队延迟']
        elif utilization > 70:
            grade = '良好'
            issues = []
        elif utilization > 50:
            grade = '正常'
            issues = []
        elif utilization > 30:
            grade = '一般'
            issues = ['可能存在闲置带宽']
        else:
            grade = '不足'
            issues = ['可能存在CWND限制、RWND限制或应用受限']

        return {
            'avg_delivery_rate': float(avg_delivery),
            'utilization_percent': float(utilization),
            'grade': grade,
            'issues': issues
        }

    def generate_rate_comparison_plot(self, df: pd.DataFrame,
                                     save_path: str = None) -> Optional[str]:
        """
        生成速率对比图

        Args:
            df: 时序数据
            save_path: 保存路径

        Returns:
            文件路径或None
        """
        if df.empty:
            return None

        plt.figure(figsize=(14, 8))

        # 双Y轴
        ax1 = plt.gca()
        ax2 = ax1.twinx()

        # 绘制pacing和delivery（使用左侧Y轴）
        if 'pacing_rate' in df.columns:
            ax1.plot(df.index, df['pacing_rate'], 'blue', linewidth=1.5,
                    label='Pacing Rate', alpha=0.8)

        if 'delivery_rate' in df.columns:
            ax1.plot(df.index, df['delivery_rate'], 'green', linewidth=1.5,
                    label='Delivery Rate', alpha=0.8)

        # 绘制send_rate（使用右侧Y轴，注意这不是速率而是内存使用）
        if 'send_rate' in df.columns:
            ax2.plot(df.index, df['send_rate'], 'orange', linewidth=1,
                    label='Send Buffer (内存使用)', linestyle='--', alpha=0.6)

        ax1.set_xlabel('时间')
        ax1.set_ylabel('速率 (bps)', color='blue')
        ax2.set_ylabel('Send Buffer (bytes)', color='orange')

        # 合并图例
        lines1, labels1 = ax1.get_legend_handles_labels()
        lines2, labels2 = ax2.get_legend_handles_labels()
        ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')

        plt.title('速率对比分析')
        plt.xticks(rotation=45)

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            plt.close()
            return save_path
        else:
            plt.show()
            return None

##### 3.2.1.7 瓶颈识别器 (BottleneckDetector)

**职责**: 综合所有分析结果，识别性能瓶颈

**接口设计**:
```python
class BottleneckDetector:
    """瓶颈识别器"""

    def detect(self,
              rtt_analysis: Dict,
              window_analysis: Dict,
              buffer_analysis: Dict,
              rate_analysis: Dict) -> Dict[str, Any]:
        """
        综合识别瓶颈

        Args:
            rtt_analysis: RTT分析结果
            window_analysis: 窗口分析结果
            buffer_analysis: Buffer分析结果
            rate_analysis: 速率分析结果

        Returns:
            {
                "bottlenecks": List[Dict],   # 识别出的瓶颈
                "root_causes": List[str],    # 根本原因
                "impact": str,                 # 影响程度
                "confidence": float           # 置信度
            }
        """
        bottlenecks = []

        # 1. 网络质量瓶颈（RTT异常）
        if self._has_network_quality_issue(rtt_analysis):
            bottlenecks.append({
                'type': 'network_quality',
                'severity': 'high',
                'description': '网络延迟高或不稳定',
                'evidence': self._extract_rtt_evidence(rtt_analysis)
            })

        # 2. Buffer压力瓶颈
        buffer_bottleneck = self._detect_buffer_bottleneck(buffer_analysis)
        if buffer_bottleneck:
            bottlenecks.append(buffer_bottleneck)

        # 3. 窗口受限瓶颈
        window_bottleneck = self._detect_window_bottleneck(window_analysis)
        if window_bottleneck:
            bottlenecks.append(window_bottleneck)

        # 4. 带宽利用率瓶颈
        rate_bottleneck = self._detect_rate_bottleneck(rate_analysis)
        if rate_bottleneck:
            bottlenecks.append(rate_bottleneck)

        # 按严重性排序
        bottlenecks = sorted(bottlenecks, key=lambda x: x['severity'], reverse=True)

        return {
            'bottlenecks': bottlenecks,
            'primary_bottleneck': bottlenecks[0] if bottlenecks else None,
            'recommendations': self._generate_recommendations(bottlenecks)
        }

    def _has_network_quality_issue(self, rtt_analysis: Dict) -> bool:
        """判断是否有网络质量问题"""
        if 'basic_stats' not in rtt_analysis:
            return False

        # RTT异常高（> 1秒）
        if rtt_analysis['basic_stats']['mean'] > 1000:
            return True

        # RTT不稳定（抖动 > 50ms）
        if rtt_analysis['stability']['jitter'] > 50:
            return True

        return False

    def _detect_buffer_bottleneck(self, buffer_analysis: Dict) -> Optional[Dict]:
        """检测Buffer瓶颈"""
        health = buffer_analysis.get('health_score', {})
        rx = buffer_analysis.get('rx_buffer', {})

        # 丢包是最严重的Buffer瓶颈
        if rx.get('drops', 0) > 0:
            return {
                'type': 'buffer_drops',
                'severity': 'critical',
                'description': 'Socket层丢包导致数据丢失',
                'root_cause': '接收缓冲区不足或应用读取慢'
            }

        # 健康度评分
        if health.get('score', 100) < 30:
            return {
                'type': 'buffer_pressure',
                'severity': 'high',
                'description': f"Buffer压力大（健康度={health['score']}）",
                'root_cause': health.get('reasons', [])
            }

        return None

    def _detect_window_bottleneck(self, window_analysis: Dict) -> Optional[Dict]:
        """检测窗口瓶颈"""
        limitations = window_analysis.get('limitations', {})
        cwnd = window_analysis.get('cwnd', {})

        # 主要限制因素
        primary = limitations.get('primary_limitation')
        ratio = limitations.get('primary_limitation_ratio', 0)

        if ratio > 0.5:  # 超过50%时间受限
            if 'CWND' in primary:
                return {
                    'type': 'cwnd_limitation',
                    'severity': 'high',
                    'description': f"CWND限制导致发送受阻 ({ratio:.1%}时间)",
                    'root_cause': '网络丢包、拥塞、ECN标记'
                }
            elif 'RWND' in primary:
                return {
                    'type': 'rwnd_limitation',
                    'severity': 'medium',
                    'description': f"对端接收窗口限制 ({ratio:.1%}时间)",
                    'root_cause': '对端应用读取慢或接收缓冲区配置小'
                }

        # cwnd < bdp
        if cwnd.get('cwnd_underutilized'):
            return {
                'type': 'cwnd_underutilization',
                'severity': 'medium',
                'description': "CWND未充分利用，存在闲置带宽",
                'root_cause': '有闲置带宽，但CWND未达到BDP'
            }

        return None

    def _detect_rate_bottleneck(self, rate_analysis: Dict) -> Optional[Dict]:
        """检测速率瓶颈"""
        bandwidth_util = rate_analysis.get('bandwidth_utilization', {})

        utilization = bandwidth_util.get('utilization_percent', 100)

        if utilization < 30:
            return {
                'type': 'low_bandwidth_utilization',
                'severity': 'medium',
                'description': f"带宽利用率低 ({utilization:.1f}%)",
                'root_cause': bandwidth_util.get('issues', [])
            }

        return None

    def _generate_recommendations(self, bottlenecks: List[Dict]) -> List[str]:
        """生成优化建议"""
        recommendations = []

        for bottleneck in bottlenecks:
            btype = bottleneck['type']

            if btype == 'network_quality':
                recommendations.append("• 检查物理链路质量")
                recommendations.append("• 检查路由路径，减少跳数")
                recommendations.append("• 检查网络设备负载")

            elif btype == 'buffer_drops':
                recommendations.append("• 立即增大tcp_rmem接收缓冲区")
                recommendations.append("• 优化应用读取性能")

            elif btype == 'buffer_pressure':
                recommendations.append("• 增大发送/接收缓冲区")
                recommendations.append("• 检查应用处理速度")

            elif btype == 'cwnd_limitation':
                recommendations.append("• 检查是否频繁丢包")
                recommendations.append("• 考虑更换拥塞控制算法（如BBR）")

            elif btype == 'rwnd_limitation':
                recommendations.append("• 优化对端应用性能")
                recommendations.append("• 增大对端tcp_rmem")

            elif btype == 'cwnd_underutilization':
                recommendations.append("• 检查应用是否受限")
                recommendations.append("• 增大初始CWND")

            elif btype == 'low_bandwidth_utilization':
                recommendations.append("• 检查CWND大小")
                recommendations.append("• 检查应用发送速率")

        return recommendations
```

#### 3.2.2 输出报告设计

##### 3.2.2.1 TCP文本报告生成器 (TCPSocketReportGenerator)

**职责**: 生成结构化的TCP分析报告（分级章节）

**接口设计**:
```python
        """
        解析目录中的所有采集文件

        Args:
            dir_path: 目录路径

        Yields:
            每个文件的样本列表
        """
        import os

        dir_path = Path(dir_path)

        # 查找所有文件
        files = sorted(dir_path.glob('*'))

        for filepath in files:
            if not filepath.is_file():
                continue

            try:
                samples = self.parse_file(str(filepath))
                yield samples
            except Exception as e:
                logging.warning(f"解析文件失败 {filepath}: {e}")

    def _parse_sample_body(self, timestamp: datetime, body: str) -> Optional[SSSample]:
        """
        解析样本主体

        Args:
            timestamp: 时间戳
            body: 主体内容

        Returns:
            SSSample对象或None
        """
        lines = body.strip().split('\n')

        if not lines:
            return None

        # 第一行是连接信息
        conn_match = self.CONNECTION_PATTERN.search(lines[0])
        if not conn_match:
            return None

        sample = SSSample(
            timestamp=timestamp,
            state=conn_match.group(1),
            recv_q=int(conn_match.group(2)),
            send_q=int(conn_match.group(3)),
            local_ip=conn_match.group(4),
            local_port=int(conn_match.group(5)),
            peer_ip=conn_match.group(6),
            peer_port=int(conn_match.group(7))
        )

        # 后续是指标行（以制表符开头）
        metrics_line = ' '.join(lines[1:]) if len(lines) > 1 else ''

        # 解析TCP选项
        self._parse_tcp_options(sample, metrics_line)

        # 解析速率
        self._parse_rates(sample, metrics_line)

        # 解析重传
        self._parse_retrans(sample, metrics_line)

        # 解析skmem
        self._parse_skmem(sample, metrics_line)

        # 解析限制时间
        self._parse_limited_times(sample, metrics_line)

        return sample

    def _parse_tcp_options(self, sample: SSSample, line: str):
        """解析TCP选项"""
        match = self.TCP_OPTS_PATTERN.search(line)
        if match:
            sample.rtt = float(match.group(1))
            sample.rtt_var = float(match.group(2))
            sample.rto = int(match.group(3))
            sample.mss = int(match.group(4))

        # 解析cwnd, snd_wnd, rcv_space等
        cwnd_match = re.search(r'cwnd:(\d+)', line)
        if cwnd_match:
            sample.cwnd = int(cwnd_match.group(1))

        snd_wnd_match = re.search(r'snd_wnd:(\d+)', line)
        if snd_wnd_match:
            sample.snd_wnd = int(snd_wnd_match.group(1))

        rcv_space_match = re.search(r'rcv_space:(\d+)', line)
        if rcv_space_match:
            sample.rcv_space = int(rcv_space_match.group(1))

        rcv_ssthresh_match = re.search(r'rcv_ssthresh:(\d+)', line)
        if rcv_ssthresh_match:
            sample.rcv_ssthresh = int(rcv_ssthresh_match.group(1))

    def _parse_rates(self, sample: SSSample, line: str):
        """解析速率"""
        match = self.RATE_PATTERN.search(line)
        if match:
            sample.send_rate = float(match.group(1))
            sample.pacing_rate = float(match.group(2))
            sample.delivery_rate = float(match.group(3))

    def _parse_retrans(self, sample: SSSample, line: str):
        """解析重传信息"""
        match = self.RETRANS_PATTERN.search(line)
        if match:
            sample.retrans = int(match.group(1))
            sample.retrans_total = int(match.group(2))
            sample.lost = int(match.group(3))
            sample.unacked = int(match.group(4))

        # 解析sacked, dsack_dups
        sacked_match = re.search(r'sacked:(\d+)', line)
        if sacked_match:
            sample.sacked = int(sacked_match.group(1))

        dsack_match = re.search(r'dsack_dups:(\d+)', line)
        if dsack_match:
            sample.dsack_dups = int(dsack_match.group(1))

    def _parse_skmem(self, sample: SSSample, line: str):
        """解析skmem"""
        match = self.SKMEM_PATTERN.search(line)
        if match:
            sample.r = int(match.group(1))
            sample.rb = int(match.group(2))
            sample.t = int(match.group(3))
            sample.tb = int(match.group(4))
            sample.f = int(match.group(5))
            sample.w = int(match.group(6))
            sample.o = int(match.group(7))
            sample.bl = int(match.group(8))
            sample.d = int(match.group(9))

    def _parse_limited_times(self, sample: SSSample, line: str):
        """解析受限时间"""
        match = self.LIMITED_PATTERN.search(line)
        if match:
            sample.rwnd_limited_ms = int(match.group(1))
            sample.sndbuf_limited_ms = int(match.group(3))
            sample.cwnd_limited_ms = int(match.group(5))
