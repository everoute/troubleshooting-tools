# 网络流量分析工具设计文档 - 关键设计决策与不确定问题记录

## 文档版本
- **版本**: v1.0
- **创建日期**: 2024-11-16
- **设计状态**: 初步完成

---

## 目录

1. [关键设计决策总结](#1-关键设计决策总结)
2. [PCAP分析工具设计](#2-pcap分析工具设计)
3. [TCPSocket分析工具设计](#3-tcpsocket分析工具设计)
4. [不确定问题记录](#4-不确定问题记录)
5. [后续工作](#5-后续工作)

---

## 1. 关键设计决策总结

### 1.1 架构决策

| 决策 | 选择 | 理由 |
|------|------|------|
| **架构模式** | 模块化分层架构 | - 两个工具可独立运行<br>- 组件复用（输出模块、通用工具）<br>- 易于扩展新分析模块 |
| **技术栈** | Python 3.6+ | - 需求规格要求<br>- 支持dataclass、typing、async<br>- 丰富的数据分析生态（pandas、numpy）|
| **PCAP解析** | tshark (Wireshark) | - 解析能力强，支持多层协议<br>- 输出JSON格式易于解析<br>- 流式处理支持 |
| **数据存储** | 内存+流式 | - 大文件支持，避免OOM<br>- 按需加载和丢弃数据 |

### 1.2 TCP分析核心发现

#### w字段精确含义（关键发现）
- **调研结论**: w = `sk_wmem_queued`（写队列排队内存）
- **位置**: `kernel/include/net/sock.h:418`
- **关系**: `w = t - unacked_memory`
- **意义**: 反映应用写入速度 vs 网络发送速度的差异
- **设计影响**: BufferAnalyzer中，w字段用于诊断写队列堆积

#### send_rate真相（重要澄清）
- **传统理解**: 很多人认为是发送速率
- **调研结论**: **不是内核计算值**！ss命令显示的是**发送缓冲区内存使用量**（单位：bytes）
- **来源**: `inet_diag_meminfo.idiag_wmem`
- **与tcpi_bytes_acked的关系**: 无直接关系（tcpi_bytes_acked是累计确认字节数）
- **设计影响**:
  - RateAnalyzer中明确标注"send_rate是内存使用量，不是速率"
  - 重点分析 pacing_rate 和 delivery_rate

#### delivery_rate采样机制
- **采样时机**: 每个ACK到达时触发（约RTT间隔）
- **时间间隔**: `max(send_interval, ack_interval)`（取较长阶段）
- **平滑算法**: 只保留非app_limited或带宽更高的样本
- **最小RTT约束**: 如果采样间隔 < tcp_min_rtt，丢弃异常样本
- **设计影响**: 说明delivery_rate是可靠的估算值，可用于带宽利用率计算

### 1.3 自动分析算法

#### Buffer健康度评分算法（0-100分）
```python
评分标准（基于调研报告）：
- sk_drops > 0: -50分（直接扣50，最高优先级）
- r/rb > 0.9: -20分
- r/rb > 0.8: -10分
- r/rb > 0.7: -5分
- t/tb > 0.9: -15分
- t/tb > 0.8: -7分
- w/tb > 0.8: -10分（写队列堆积）

分数等级：
90-100: 优秀（无压力，配置合理）
70-89: 良好（轻度压力，可接受）
50-69: 一般（中度压力，建议关注）
30-49: 较差（重度压力，需要优化）
0-29: 严重（有丢包或严重堆积，立即处理）
```

#### 带宽利用率评估标准
```python
带宽利用率 = (平均delivery_rate / 物理链路带宽) × 100%

判断标准（基于需求文档）：
< 30%: 利用率低，存在CWND/RWND限制或应用受限
30%-70%: 正常范围
> 70%: 利用率良好
> 90%: 接近带宽上限，可能存在排队和延迟
```

#### 瓶颈识别优先级
```python
1. 丢包（sk_drops > 0）- critical（最严重）
2. Buffer高压（健康度 < 30）- high
3. 网络质量（RTT > 1秒或抖动 > 50ms）- high
4. CWND限制（>50%时间受限）- high
5. RWND限制（>50%时间受限）- medium
6. 带宽利用率低（<30%）- medium
7. CWND未充分利用（cwnd < bdp）- medium
```

### 1.4 可视化图表规划

#### PCAP分析工具
- 协议分布饼图
- 包大小分布直方图
- 重传时间线散点图
- RTT分布（直方图+箱线图）

#### TCPSocket分析工具
- **RTT时序图**：叠加移动平均线和分位数线，标记异常点
- **CWND时序图**：叠加BDP参考线
- **Buffer压力时序图**：
  - 接收Buffer（r vs rb）
  - 发送Buffer（t vs tb）
  - 写队列（w）
- **速率对比图**：双Y轴（pacing/delivery速率 vs send_buffer内存使用）
- **堆积图**（需求未明确，暂不考虑）
- **热图**（按需实现，暂列为低优先级）

---

## 2. PCAP分析工具设计

### 2.1 模块划分

```
pcap_analyzer/
├── main.py                          # 主入口
├── parser/
│   ├── pcap_parser.py              # tshark封装
│   └── stream_processor.py         # 流式处理
├── analyzer/
│   ├── l2_analyzer.py              # L2层分析
│   ├── l3_analyzer.py              # L3层分析
│   ├── l4_analyzer.py              # L4层分析
│   ├── tcp_analyzer.py             # TCP深度分析
│   ├── udp_analyzer.py             # UDP分析
│   ├── icmp_analyzer.py            # ICMP分析
│   └── smart_analyzer.py           # 智能问题识别
├── stats/
│   ├── flow_stats.py               # 流统计
│   └── distribution.py             # 分布统计
└── output/
    ├── text_reporter.py            # 文本报告
    ├── json_reporter.py            # JSON输出
    └── visualizer.py               # 图表生成
```

### 2.2 核心算法

#### 重传检测算法
```python
算法: RetransmissionDetector.detect_retransmission()
输入: 数据包(packet), 重传阈值(retrans_threshold)
输出: {is_retrans: bool, retrans_type: str}

逻辑:
1. 提取TCP序列号(seq)
2. 如果序列号已确认过 → 重传
   * 检查是否TLP探测（发送新数据）→ 'tlp'
   * 检查是否SACK重传 → 'sack'
   * 否则 → 超时重传'timeout'
3. 检查重复ACK数 ≥ threshold → 快速重传'fast'
4. 否则 → 不是重传

性能考虑: 使用字典记录已见序列号，O(1)查找
```

#### 流重组算法
```python
算法: FlowAggregator.add_packet()
输入: 解析后的数据包（包含5元组、序列号、标志位）
输出: 更新流统计

逻辑:
1. 提取5元组（src_ip, dst_ip, src_port, dst_port, protocol）
2. 计算流ID（哈希）
3. 维护流状态机:
   IDLE ──SYN──► SYN_SENT
   SYN_SENT ──SYN-ACK──► ESTABLISHED
   ESTABLISHED ──FIN──► FIN_WAIT
   FIN_WAIT ──ACK──► CLOSED
   ANY ──RST──► CLOSED
4. 更新流统计（包数、字节数、重传数）
5. 维护时间窗口，定期清理过期流

内存管理: 使用LRU缓存，限制最大流数量（如10000条）
```

#### 智能问题识别
```python
预定义问题数据库:
- 高重传率: retrans_rate > 0.01
  * severity: high (>5%)/medium (>1%)
  * 建议: 检查网络质量

- Zero Window: zero_window_events > 5
  * severity: high
  * 建议: 检查接收方应用性能

- RTT异常: avg_rtt > 1000ms
  * severity: high (>1秒)/medium (>200ms)
  * 建议: 检查网络路径

- 小包过多: avg_packet_size < 200 bytes
  * severity: medium
  * 建议: 应用层合并小包

实现: SmartAnalyzer._analyze_tcp_issues()
     SmartAnalyzer._analyze_general_issues()
```

---

## 3. TCPSocket分析工具设计

### 3.1 模块划分

```
tcpsocket_analyzer/
├── main.py                          # 主入口
├── parser/
│   ├── ss_parser.py                # ss输出解析
│   └── timeseries_parser.py        # 时序数据解析
├── analyzer/
│   ├── rtt_analyzer.py             # RTT分析
│   ├── window_analyzer.py          # 窗口分析
│   ├── rate_analyzer.py            # 速率分析
│   ├── buffer_analyzer.py          # Buffer分析
│   ├── retrans_analyzer.py         # 重传分析
│   └── bottleneck_detector.py      # 瓶颈识别
├── models/
│   ├── connection.py               # 连接模型
│   └── timeseries.py               # 时序数据模型
└── output/
    ├── text_reporter.py            # 文本报告
    ├── json_reporter.py            # JSON输出
    └── visualizer.py               # 图表生成
```

### 3.2 核心算法

#### RTT异常检测
```python
算法: RTTAnalyzer._detect_outliers()
方法: IQR（四分位距）

Q1 = np.percentile(series, 25)
Q3 = np.percentile(series, 75)
IQR = Q3 - Q1

lower_bound = Q1 - 1.5 × IQR
upper_bound = Q3 + 1.5 × IQR

异常条件: value < lower_bound or value > upper_bound

特点:
- 非参数方法，不假设分布
- 对异常值敏感
- 适合RTT这类可能有极端值的指标
```

#### RTT趋势分析
```python
算法: 线性回归
方法: scipy.stats.linregress()

输入: timestamps, rtt_values
输出: slope, intercept, r_value, p_value, std_err

判断:
abs(slope) < 0.1 → stable
slope > 0 → increasing (RTT逐渐增大)
slope < 0 → decreasing (RTT逐渐减小)

统计显著性:
- p_value < 0.05 认为趋势显著
- r_squared 表示拟合优度
```

#### BDP计算
```python
算法: BufferAnalyzer._calculate_bdp()

输入: 带宽(bps), RTT(ms), MSS(默认1460)

计算:
avg_rtt_sec = avg_rtt_ms / 1000
bandwidth_bytes_per_sec = bandwidth_bps / 8
bdp_bytes = bandwidth_bytes_per_sec × avg_rtt_sec
bdp_packets = bdp_bytes / mss

# 缓冲区余量（经验值2倍）
expected_cwnd = bdp_packets × 2

实现注意:
- 如果RTT不可用，使用默认值（如100ms）
- MSS优先从数据中读取，否则用1460
```

#### Buffer健康度评分算法
```python
算法: BufferAnalyzer._calculate_health_score()

初始化: score = 100

扣分规则:
1. sk_drops > 0 → score -= 50 （最高优先级）
2. r/rb > 0.9 → score -= 20
3. r/rb > 0.8 → score -= 10
4. r/rb > 0.7 → score -= 5
5. t/tb > 0.9 → score -= 15
6. t/tb > 0.8 → score -= 7
7. w/tb > 0.8 → score -= 10

限制: score = max(0, score)

评级:
90-100: 优秀（excellent）
70-89: 良好（good）
50-69: 一般（fair）
30-49: 较差（poor）
0-29: 严重（critical）

使用场景: 快速评估连接健康状态，识别优化的紧急程度
```

#### 瓶颈识别与根因分析
```python
检测顺序（按严重性）:
1. Buffer丢包（sk_drops > 0）
   * severity: critical
   * 根因: 接收缓冲区不足或应用读取慢
   * 建议: 增大tcp_rmem，优化应用

2. 健康度低（score < 30）
   * severity: high
   * 根因: 列出所有扣分原因
   * 建议: 针对具体压力点调整

3. 网络质量（RTT > 1000ms或抖动 > 50ms）
   * severity: high
   * 根因: 物理链路或路由问题
   * 建议: 检查链路、路由、设备负载

4. CWND限制（>50%时间受限）
   * severity: high
   * 根因: 丢包、拥塞、ECN标记
   * 建议: 检查丢包率，考虑更换拥塞控制算法

5. RWND限制（>50%时间受限）
   * severity: medium
   * 根因: 对端应用读取慢或接收缓冲区小
   * 建议: 优化对端应用，增大对端tcp_rmem

6. 带宽利用率低（<30%）
   * severity: medium
   * 根因: CWND限制、RWND限制或应用受限
   * 建议: 检查CWND大小，应用发送速率

7. CWND未充分利用（cwnd < bdp）
   * severity: medium
   * 根因: 有闲置带宽，但CWND未达到BDP
   * 建议: 检查应用是否受限，增大初始CWND

实现: BottleneckDetector.detect()
     综合rtt_analysis、window_analysis、buffer_analysis、rate_analysis
```

---

## 4. 不确定问题记录

### 4.1 实现细节问题

#### ❓ **问题1**: 时间序列插值策略
**描述**:
ss数据采集间隔可能不均匀（取决于采集脚本），是否需要插值对齐？

**可选方案**:
- **方案A**: 不插值，直接使用原始采样点
  * 优点: 保持数据真实性
  * 缺点: 时序分析可能不准确

- **方案B**: 线性插值到固定频率（如1秒）
  * 优点: 时序分析方便，图表平滑
  * 缺点: 引入人为数据

- **方案C**: 仅当间隔过大时插值（如超过5秒）
  * 优点: 平衡真实性和可用性
  * 缺点: 逻辑复杂

**建议**: 初步采用方案A，保持简单；后期根据用户反馈决定是否需要插值

**影响模块**: TimeSeriesBuilder.interpolate()

#### ❓ **问题2**: 大文件内存管理
**描述**:
tcpsocket采集可能产生大量文件（超过1000个），一次性加载可能OOM。

**可选方案**:
- **方案A**: 流式读取，逐文件处理
  * 优点: 内存可控
  * 缺点: 无法跨文件的时间序列分析

- **方案B**: 批量处理，每批N个文件
  * 优点: 可跨文件分析
  * 缺点: 内存使用和实现复杂度平衡

- **方案C**: 先构建索引，按需加载
  * 优点: 灵活
  * 缺点: 实现复杂

**建议**: 采用方案A，每个文件独立处理，内存占用最低

**影响模块**: SSOutputParser.parse_directory()

#### ❓ **问题3**: 可视化图表库选择
**描述**:
图表需要支持时序、多Y轴、交互式（可选）。

**可选方案**:
- **matplotlib**: 静态图表，成熟稳定
- **plotly**: 交互式图表，功能强大但体积大
- **echarts**: 前端图表，需要导出HTML
- **bokeh**: 交互式，Python原生支持

**建议**: 优先使用matplotlib（最稳定），为交互式场景预留接口

**影响模块**: Visualizer类

### 4.2 SS输出解析问题

#### ❓ **问题4**: 多连接识别的处理
**描述**:
单个文件可能包含多个连接的ss输出，如何关联到同一条连接？

**调研结论**:
- 文件名格式: `{role}.{port}` 或 `role.{pid}`
- 内容格式: 包含多个时间戳，每个时间戳可能有多个连接
- 同一文件内的连接共享采集上下文

**建议**:
- 按时间戳分组
- 在每个时间戳内，按连接ID（5元组）分组
- 跨文件前需要检查连接是否延续（IP:PORT不变）

**影响模块**: TimeSeriesBuilder, ConnectionTracker

#### ❓ **问题5**: 缺失字段的处理
**描述**:
某些ss输出可能缺少部分字段（如老版本ss不包含某些指标）。

**建议**:
- 解析器使用**可选字段**（Optional）
- 分析器检查字段是否存在再计算
- 报告生成时说明哪些指标不可用

**影响模块**: SSSample数据类，所有Analyzer

### 4.3 BDP和带宽计算问题

#### ❓ **问题6**: 物理链路带宽的获取
**描述**:
tcpsocket_analyzer需要`--bandwidth`参数指定物理带宽，但用户可能不知道。

**可选方案**:
- **方案A**: 必填参数，用户必须提供
  * 优点: 精确计算带宽利用率
  * 缺点: 用户体验差

- **方案B**: 可选参数，不提供则跳过带宽分析
  * 优点: 用户体验好
  * 缺点: 缺少重要指标

- **方案C**: 自动检测（如ethtool）
  * 优点: 自动化
  * 缺点: 需要root权限，不一定能检测到

**建议**: 采用方案A（必填），因为这是核心功能，且用户应该知道测试环境的带宽

**影响模块**: TCPSocket命令行参数，RateAnalyzer，WindowAnalyzer

#### ❓ **问题7**: MSS（最大段大小）的取值
**描述**:
BDP计算需要MSS，但MSS可能在连接过程中变化（MTU发现）。

**建议**:
1. 从数据中读取（ss输出包含mss字段）
2. 如果ss中没有，使用默认值（如1460）
3. 在BDP计算结果中注明使用的MSS值

**影响模块**: BufferAnalyzer._calculate_bdp()

### 4.4 Buffer评分阈值调优

#### ❓ **问题8**: Buffer健康度评分阈值是否合理
**描述**:
Buffer评分算法中的阈值是经验值：
- r/rb > 0.9 → -20分
- r/rb > 0.8 → -10分
- r/rb > 0.7 → -5分

**需要验证**:
- 这些阈值是否真实反映压力
- 不同网络环境（1Gbps vs 10Gbps）是否需要不同阈值
- 实际测试数据验证

**建议**:
- 第一期使用这些经验阈值
- 收集实际数据后调优
- 提供配置接口允许用户调整

**影响模块**: BufferAnalyzer配置

---

## 5. 后续工作

### 5.1 Phase 1: MVP实现（优先级1）

**PCAP分析工具MVP**:
- [ ] PCAPParser（tshark封装）
- [ ] FlowAggregator（流聚合）
- [ ] TCPAnalyzer（重传、RTT、窗口分析）
- [ ] TextReporter（文本报告）
- [ ] 命令行接口（--input --proto --analysis）

**TCPSocket分析工具MVP**:
- [ ] SSOutputParser（ss输出解析）
- [ ] TimeSeriesBuilder（时序构建）
- [ ] RTTAnalyzer（RTT统计、异常检测）
- [ ] BufferAnalyzer（健康度评分）
- [ ] TextReporter（文本报告）
- [ ] 命令行接口（--input-dir --bandwidth --connection-filter）

### 5.2 Phase 2: 增强功能（优先级2）

- [ ] 智能问题识别（SmartAnalyzer）
- [ ] 瓶颈识别（BottleneckDetector）
- [ ] 调优建议自动化
- [ ] 可视化图表（matplotlib基础版）
- [ ] JSON输出格式
- [ ] 性能优化（内存使用监控）

### 5.3 Phase 3: 高级功能（优先级3）

- [ ] 交互式可视化（plotly或web界面）
- [ ] 实时分析模式（streaming）
- [ ] 多连接对比分析
- [ ] 历史数据基准对比
- [ ] 与eBPF工具集成

### 5.4 测试验证计划

**单元测试**:
- [ ] SSOutputParser解析各种格式
- [ ] RTTAnalyzer异常检测
- [ ] BufferAnalyzer健康度评分
- [ ] FlowAggregator流状态机

**集成测试**:
- [ ] 端到端PCAP分析
- [ ] 端到端TCPSocket分析
- [ ] 命令行接口测试
- [ ] 大文件性能测试（>1GB PCAP）

**验证指标**:
- [ ] 解析准确率（与人工检查对比）
- [ ] 问题识别召回率和精确率
- [ ] 内存使用（< 1GB for 1GB PCAP）
- [ ] 处理速度（> 100Mbps分析速度）

---

## 附录

### 附录A: 设计文档完整索引

完整的设计文档包含以下内容：
- `network-traffic-analyzer-architecture-design.md`: 完整的设计文档（约3000行）
  - 第1-2部分: 总体架构 + PCAP分析工具设计
  - 第3部分: TCPSocket分析工具详细设计
  - 包含完整的类定义、接口设计、算法实现

### 附录B: Kernel调研成果应用

调研结果应用到设计中的位置：

| 调研成果 | 设计章节 | 应用方式 |
|---------|----------|----------|
| w字段 = sk_wmem_queued | 3.2.1.5 BufferAnalyzer | 验证w = t - unacked，用于写队列分析 |
| send_rate真相 | 3.2.1.6 RateAnalyzer | 明确标注send_rate是内存使用量 |
| delivery_rate采样机制 | 3.2.1.6 RateAnalyzer | 说明每个ACK采样，受tcp_min_rtt约束 |
| pacing_rate计算公式 | 3.2.1.6 RateAnalyzer | 公式计算，对比delivery_rate |
| skmem字段映射 | 2.2.1.4, 3.2.1.5 | 完整映射到SSSample数据结构 |

### 附录C: 关键配置文件

```yaml
# config.yaml 示例
pcap:
  batch_size: 10000          # 每批处理包数
  max_memory_mb: 1024        # 最大内存使用
  tshark_path: "tshark"      # tshark路径
  retrans_threshold: 0.01    # 重传率阈值
tcpsocket:
  bandwidth_bps: 10000000000 # 带宽（10Gbps）
  r_threshold: 0.8           # 接收Buffer阈值
  t_threshold: 0.8           # 发送Buffer阈值
  w_threshold: 0.6           # 写队列阈值
output:
  text_width: 80
  json_indent: 2
  visual_dpi: 300
```

---

**文档结束**

**备注**: 本总结文档基于完整的设计文档，涵盖了所有关键设计决策和不确定问题。
重要设计决策已与Kernel调研结果对齐，不确定问题已记录待后续解决。
