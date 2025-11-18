# Traffic Analyzer - 网络流量分析工具

基于内核调研的高性能网络分析工具集，提供PCAP分析和TCPSocket分析两大功能模块。

## 功能特性

### TCPSocket分析工具
对`ss -tinopm`命令输出进行深度分析，识别网络性能问题和调优机会：

- **Buffer健康度评估**：基于内核skmem字段的自动化评分算法（0-100分）
- **RTT时序分析**：趋势检测、抖动分析、异常点识别（IQR方法）
- **TCP窗口分析**：CWND/RWND分析、BDP计算、Zero Window检测
- **速率分析**：pacing_rate、delivery_rate深度分析、瓶颈检测
- **综合报告**：自动化问题检测、根因分析、调优建议

### PCAP分析工具
基于tshark对PCAP文件进行TCP协议深度分析：

- **流统计聚合**：5元组流识别、双向流量统计
- **TCP深度分析**：重传检测、RTT估算、窗口分析
- **智能问题识别**：自动检测重传、RTT异常、Zero Window等问题
- **性能指标**：吞吐量、包大小分布、协议分布

## 安装

### 前置要求
- Python 3.8+
- tshark（PCAP分析工具需要）
- ss命令（TCPSocket分析工具需要）

### 快速安装
```bash
cd traffic-analyzer
pip install -r requirements.txt

# 使CLI工具可执行
chmod +x bin/tcp_analyzer_cli.py bin/pcap_analyzer_cli.py
```

## 使用指南

### TCPSocket分析工具

#### 准备数据
首先采集ss命令输出：
```bash
# 持续监控特定连接
while true; do
  ss -tinopm "dst 10.0.0.1:8080" >> ss_samples.txt
  sleep 1
done

# 监控所有连接
ss -tinopm > ss_output.txt
```

#### 基础用法
```bash
# 分析单个文件
python3 bin/tcp_analyzer_cli.py -f ss_output.txt -o ./reports

# 分析目录中的所有采集文件
python3 bin/tcp_analyzer_cli.py -d ./ss_samples/ -o ./reports
```

#### 高级过滤
```bash
# 分析特定IP的连接
python3 bin/tcp_analyzer_cli.py -f ss_output.txt --local-ip 192.168.1.100 -o ./reports

# 分析特定端口（本地或对端）
python3 bin/tcp_analyzer_cli.py -f ss_output.txt --conn-port 8080 -o ./reports

# 组合过滤
python3 bin/tcp_analyzer_cli.py -f ss_output.txt \
  --local-ip 10.0.0.1 --peer-ip 10.0.0.2 \
  --local-port 12345 -o ./reports
```

#### 输出格式
```bash
# JSON格式（便于后续处理）
python3 bin/tcp_analyzer_cli.py -f ss_output.txt -o ./reports -j

# 静默模式（只输出统计）
python3 bin/tcp_analyzer_cli.py -f ss_output.txt -q
```

#### 示例输出
```
================================================================================
TCP连接分析报告
================================================================================

【汇总统计】
总连接数     : 5
优秀连接     : 3
良好连接     : 1
一般连接     : 1
问题连接     : 0
平均健康度   : 85.2/100
总吞吐量     : 450.5 Mbps
平均RTT      : 12.3 ms
需关注连接   : 1

【Top 流量连接】
192.168.1.100:12345 → 10.0.0.1:8080
  健康度: ✓ 92/100 (优秀)
  RTT分析: 平均值: 10.20ms | 范围: 8.10ms - 25.30ms | 标准差: 2.10ms
  窗口分析: CWND范围: 20-128 | CWND/BDP: 0.85 | 拥塞状态: normal
  速率分析: 吞吐量: 112.5 Mbps | Pacing Rate: 150.0 Mbps

需关注的连接
  ⚠ 接收Buffer压力较高: 85%
    建议: 建议增大tcp_rmem或优化应用读取
```

### PCAP分析工具

#### 基础用法
```bash
# 分析PCAP文件
python3 bin/pcap_analyzer_cli.py -f capture.pcap -o ./reports

# JSON格式输出
python3 bin/pcap_analyzer_cli.py -f capture.pcap -o ./reports -j
```

#### 高级过滤
```bash
# 分析特定IP和端口的流量
python3 bin/pcap_analyzer_cli.py -f capture.pcap \
  --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \
  --src-port 12345 --dst-port 80 \
  -o ./reports

# 仅分析TCP协议
python3 bin/pcap_analyzer_cli.py -f capture.pcap --protocol tcp -o ./reports

# 限制分析的数据包数量（用于大文件测试）
python3 bin/pcap_analyzer_cli.py -f large.pcap -n 10000 -o ./reports
```

#### 客户端/服务端视角
```bash
# 客户端视角（SYN发起方）
python3 bin/pcap_analyzer_cli.py -f capture.pcap --side client -o ./reports

# 服务端视角（SYN接收方）
python3 bin/pcap_analyzer_cli.py -f capture.pcap --side server -o ./reports
```

## 分析模块详解

### Buffer分析器
基于内核skmem字段的健康度评分算法（0-100分）：

**评分规则**：
- `sk_drops > 0`: -50分（丢包是最严重的问题）
- `r/rb > 0.9`: -20分（接收Buffer压力严重）
- `r/rb > 0.8`: -10分（接收Buffer压力较高）
- `r/rb > 0.7`: -5分（接收Buffer压力一般）
- `t/tb > 0.9`: -15分（发送Buffer压力高）
- `t/tb > 0.8`: -7分（发送Buffer压力）
- `w/tb > 0.8`: -10分（写队列堆积严重）

**健康度等级**：
- 90-100: 优秀（Excellent）
- 70-89: 良好（Good）
- 50-69: 一般（Fair）
- 30-49: 较差（Poor）
- 0-29: 严重（Critical）

### RTT分析器
提供全面的RTT时序分析：
- **基础统计**：min/max/mean/std/p50/p95/p99
- **趋势分析**：线性回归检测RTT趋势（increasing/decreasing/stable）
- **稳定性指标**：抖动（jitter）和变异系数（CV）
- **异常检测**：IQR方法识别异常点并分析原因（重传、丢包、Buffer压力等）

### 窗口分析器
分析TCP窗口机制：
- **BDP计算**：带宽延迟积（bytes和packets）
- **CWND分析**：拥塞窗口大小、增长率、app_limited时间
- **RWND分析**：接收窗口、RWND受限比例、窗口利用不足检测
- **Zero Window检测**：识别接收/发送窗口为0的事件
- **窗口效率**：评估CWND和RWND的效率（0-1）

### 速率分析器
基于内核调研的深度速率分析：

**重要发现**：
- `send_rate`不是传输速率，而是发送缓冲区内存使用量！
- `delivery_rate`使用tcp_rate.c的采样机制，受tcp_min_rtt约束
- `pacing_rate`是TCO的速率限制机制

**分析功能**：
- pacing_rate分析：速率限制、激活时间、用户配置检测
- delivery_rate分析：吞吐量、稳定性、throttle检测
- 瓶颈检测：自动识别瓶颈位置（sender/network/receiver）
- 速率匹配度：pacing_rate和delivery_rate匹配分析

## 技术架构

```
traffic-analyzer/
├── bin/                          # CLI入口
│   ├── tcp_analyzer_cli.py      # TCPSocket分析CLI
│   └── pcap_analyzer_cli.py     # PCAP分析CLI
├── common/                       # 通用组件
│   └── utils/
│       ├── logger.py            # 日志配置
│       ├── config.py            # 配置管理
│       └── file_utils.py        # 文件操作工具
├── tcpsocket_analyzer/          # TCPSocket分析工具
│   ├── parser/
│   │   └── ss_parser.py         # ss输出解析器
│   ├── analyzer/
│   │   ├── buffer_analyzer.py   # Buffer分析器
│   │   ├── rtt_analyzer.py      # RTT分析器
│   │   ├── window_analyzer.py   # 窗口分析器
│   │   └── rate_analyzer.py     # 速率分析器
│   └── report/
│       └── report_generator.py  # 报告生成器
└── pcap_analyzer/               # PCAP分析工具
    ├── parser/
    │   └── pcap_parser.py       # tshark解析器
    ├── analyzer/
    │   └── tcp_analyzer.py      # TCP深度分析器
    └── stats/
        └── flow_stats.py        # 流统计模块
```

## 算法原理

### Buffer健康度评分算法
```python
# 基于内核调研的评分规则
score = 100

# 丢包（最严重）
if drops > 0:
    score -= 50

# 接收Buffer压力
if r/rb > 0.9: score -= 20
elif r/rb > 0.8: score -= 10
elif r/rb > 0.7: score -= 5

# 发送Buffer压力
if t/tb > 0.9: score -= 15
elif t/tb > 0.8: score -= 7

# 写队列堆积
if w/tb > 0.8: score -= 10
```

### RTT异常检测（IQR方法）
```python
Q1 = np.percentile(rtt_series, 25)
Q3 = np.percentile(rtt_series, 75)
IQR = Q3 - Q1

lower_bound = Q1 - 1.5 * IQR
upper_bound = Q3 + 1.5 * IQR

outliers = rtt_series[(rtt_series < lower_bound) | (rtt_series > upper_bound)]
```

### 瓶颈检测算法
```python
# 多维度评分机制
bottleneck_score = {'sender': 0, 'network': 0, 'receiver': 0}

# 发送端瓶颈
if pacing_rate受限: bottleneck_score['sender'] += 2
if app_limited > 30%: bottleneck_score['sender'] += 3

# 网络瓶颈
if pacing高但delivery低: bottleneck_score['network'] += 3
if 重传率高: bottleneck_score['network'] += 2
if 丢包: bottleneck_score['network'] += 3

# 接收端瓶颈
if rwnd_limited > 30%: bottleneck_score['receiver'] += 3
if zero_window: bottleneck_score['receiver'] += 2
```

## 内核调研成果

本工具基于深入的内核网络栈调研，关键发现包括：

1. **w字段验证**：`w = sk_wmem_queued = t - unacked_memory`
2. **send_rate澄清**：是发送缓冲区内存使用量，不是传输速率
3. **delivery_rate机制**：基于tcp_rate.c采样，受tcp_min_rtt约束
4. **Buffer压力阈值**：r/rb > 0.8为高压，> 0.9为严重

详细调研报告见：`docs/req/kimi/appendix-kernel-code-research.md`

## 性能考虑

- **TCPSocket分析**：支持大规模采集文件，流式解析
- **PCAP分析**：tshark原生解析，性能优异，支持max_packets限制
- **内存使用**：采用生成器和迭代器，避免内存爆炸
- **并行化**：各模块独立，可扩展为并行处理

## 扩展性

模块化设计支持轻松扩展：
- 添加新分析器（如延迟分析器、丢包分析器）
- 扩展报告格式（HTML、图表等）
- 集成监控系统（Prometheus、Grafana）
- 支持其他数据源（netlink、sockets API）

## 贡献

欢迎提交Issue和Pull Request！

## 许可证

MIT License

## 联系

如有问题或建议，请联系项目维护者。
