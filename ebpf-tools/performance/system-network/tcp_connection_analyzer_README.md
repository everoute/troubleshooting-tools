# TCP Connection Analyzer

## 概述

TCP Connection Analyzer 是一个用于收集和分析 TCP 连接性能的工具。它可以帮助诊断网络吞吐量问题，识别性能瓶颈，并提供可操作的优化建议。

## 功能特性

1. **连接信息收集**
   - 使用 `ss` 命令收集详细的 TCP 连接指标
   - 支持 client 和 server 两种角色
   - 可以监控单个连接或所有连接

2. **性能指标分析**
   - RTT (往返时延) 和 RTT 方差
   - 拥塞窗口 (cwnd) 和慢启动阈值 (ssthresh)
   - 接收窗口 (rcv_space) 和发送窗口
   - 发送速率、限速速率、实际交付速率
   - 重传统计和丢包统计
   - 队列状态 (Recv-Q, Send-Q)

3. **瓶颈检测**
   - **rwnd_limited**: 接收窗口限制
   - **cwnd_limited**: 拥塞窗口限制
   - **sndbuf_limited**: 发送缓冲区限制
   - 高重传率检测
   - 队列积压检测
   - 速率限制检测

4. **智能建议**
   - 计算带宽延迟积 (BDP)
   - 推荐接收/发送缓冲区大小
   - 提供具体的 sysctl 调整命令
   - 给出进一步排查方向

5. **灵活的监控模式**
   - 单次采样
   - 持续监控（指定间隔）
   - 系统配置查看

## 使用方法

### 基本用法

#### 1. Client 端分析（分析到服务器的连接）

```bash
# 分析到 iperf3 服务器的连接
sudo python3 tcp_connection_analyzer.py \
    --remote-ip 1.1.1.5 \
    --remote-port 5201 \
    --role client

# 分析所有到端口 5201 的连接
sudo python3 tcp_connection_analyzer.py \
    --remote-port 5201 \
    --role client
```

#### 2. Server 端分析（分析从客户端来的连接）

```bash
# 分析 iperf3 服务端的连接
sudo python3 tcp_connection_analyzer.py \
    --local-port 5201 \
    --role server
```

#### 3. 持续监控

```bash
# 每 2 秒采样一次
sudo python3 tcp_connection_analyzer.py \
    --remote-ip 1.1.1.5 \
    --remote-port 5201 \
    --role client \
    --interval 2
```

#### 4. 查看系统 TCP 配置

```bash
# 显示当前系统 TCP 配置
sudo python3 tcp_connection_analyzer.py --show-config --role client
```

### 高级选项

```bash
# 指定目标带宽（用于 BDP 计算，默认 25 Gbps）
--target-bandwidth 25

# 监控所有状态的连接（不只是 ESTABLISHED）
--all

# JSON 格式输出（便于脚本处理）
--json
```

## 输出说明

### 1. 连接基本信息

```
Connection: 1.1.1.2:53858 -> 1.1.1.5:5201
State: ESTAB
```

### 2. 性能指标

```
Metrics:
  recv_q                   : 0
  send_q                   : 0
  rtt                      : 0.078 ms
  rttvar                   : 0.036 ms
  cwnd                     : 10
  ssthresh                 : 285
  rcv_space                : 14480 bytes (14.1 KB)
  mss                      : 1448
  pmtu                     : 1500
  send_rate                : 0.15 Gbps
  pacing_rate              : 0.26 Gbps
  retrans                  : 0/1195
  bdp                      : 243750 bytes (238.0 KB)
  recommended_window       : 975000 bytes (952.1 KB)
```

**关键指标解读：**

- **rtt**: 往返时延，越小越好（局域网通常 < 1ms）
- **cwnd**: 拥塞窗口，太小（<100）说明有问题
- **rcv_space**: 接收窗口，应该远大于 BDP
- **pacing_rate**: 发送速率限制，应该接近目标带宽
- **retrans**: 重传次数，格式为 "未确认/总重传"
- **bdp**: 带宽延迟积，理论最小窗口大小
- **recommended_window**: 推荐窗口大小（BDP × 4）

### 3. 瓶颈检测

```
Bottlenecks Detected:
  🔴 [CRITICAL] rwnd_limited
     Value: 95.6%
     Receive window limited for 95.6% of the time

  ⚠️ [WARNING] small_cwnd
     Value: 10
     Congestion window very small (10), possibly in slow start or recovery

  ⚠️ [WARNING] high_retransmissions
     Value: 1195
     High retransmission count (1195)
```

**瓶颈类型：**

- **rwnd_limited**: 接收窗口限制（最常见的吞吐量瓶颈）
- **cwnd_limited**: 拥塞窗口限制（网络丢包导致）
- **sndbuf_limited**: 发送缓冲区限制
- **small_cwnd**: 拥塞窗口过小
- **high_retransmissions**: 高重传率
- **recv_queue_backlog**: 接收队列积压（应用层慢）
- **low_pacing_rate**: 发送速率远低于目标

### 4. 优化建议

```
Recommendations:
  1. Issue: Receive window too small
     Current: rcv_space = 14480 bytes (14.1 KB)
     Recommended: 975000 bytes (952.1 KB, 0.9 MB)
     Action: Increase tcp_rmem on the receiver side
     Commands:
       sudo sysctl -w net.core.rmem_max=1950000
       sudo sysctl -w net.ipv4.tcp_rmem="4096 131072 1950000"

  2. Issue: High retransmissions detected
     Action: Investigate packet loss
     Commands:
       ethtool -S <interface> | grep drop
       Use eBPF tools to trace packet drops
```

## 典型使用场景

### 场景 1：iperf3 测试吞吐量上不去

**问题：** 25G 网卡，iperf3 只能跑到 6-7 Gbps

**诊断步骤：**

1. **在 iperf3 客户端执行：**
   ```bash
   # 开始 iperf3 测试
   iperf3 -c 1.1.1.5 -t 60 -P 2 &

   # 在另一个终端分析连接
   sudo python3 tcp_connection_analyzer.py \
       --remote-ip 1.1.1.5 \
       --remote-port 5201 \
       --role client
   ```

2. **在 iperf3 服务端执行：**
   ```bash
   sudo python3 tcp_connection_analyzer.py \
       --local-port 5201 \
       --role server
   ```

3. **查看输出，重点关注：**
   - `rwnd_limited` 占比 > 50% → 接收窗口瓶颈
   - `cwnd` < 100 → 拥塞问题
   - `retrans` 很高 → 网络丢包
   - `rcv_space` << BDP × 4 → 窗口太小

4. **根据建议调整系统参数**

5. **重新测试验证**

### 场景 2：持续监控连接状态变化

```bash
# 启动持续监控
sudo python3 tcp_connection_analyzer.py \
    --remote-ip 1.1.1.5 \
    --remote-port 5201 \
    --role client \
    --interval 1 > tcp_analysis.log

# 观察关键指标的变化趋势：
# - rcv_space 是否逐步增长
# - cwnd 是否稳定
# - rwnd_limited 是否下降
# - retrans 是否增加
```

### 场景 3：对比调优前后

```bash
# 调优前
echo "=== Before Tuning ===" > comparison.txt
sudo python3 tcp_connection_analyzer.py \
    --remote-ip 1.1.1.5 \
    --remote-port 5201 \
    --role client >> comparison.txt

# 调整系统参数
sudo sysctl -w net.core.rmem_max=268435456
sudo sysctl -w net.ipv4.tcp_rmem="4096 131072 268435456"

# 重启 iperf3 测试

# 调优后
echo "=== After Tuning ===" >> comparison.txt
sudo python3 tcp_connection_analyzer.py \
    --remote-ip 1.1.1.5 \
    --remote-port 5201 \
    --role client >> comparison.txt

# 对比结果
less comparison.txt
```

## 工作原理

### 数据收集

工具使用 `ss` 命令的以下选项收集信息：

```bash
ss -tinopm <filter>
```

- `-t`: 只显示 TCP
- `-i`: 显示内部 TCP 信息（cwnd, rtt, retrans 等）
- `-n`: 不解析服务名
- `-o`: 显示定时器信息
- `-p`: 显示进程信息
- `-m`: 显示 socket 内存使用

### 瓶颈检测逻辑

#### 1. rwnd_limited 检测

```python
if rwnd_limited_ratio > 50%:
    # 接收窗口是主要瓶颈
    # 计算所需窗口大小 = BDP × 4
    # 提供调整 tcp_rmem 的建议
```

#### 2. cwnd_limited 检测

```python
if cwnd_limited_ratio > 50%:
    # 拥塞窗口限制
    # 建议检查网络丢包
    # 检查 ethtool 统计
```

#### 3. 小 cwnd 检测

```python
if cwnd < 100:
    # 拥塞窗口过小
    # 可能在慢启动或拥塞恢复阶段
    # 通常是丢包的结果
```

#### 4. 高重传检测

```python
if retrans_total > 100:
    # 高重传率
    # 建议排查丢包原因
```

### BDP 计算

```python
BDP (bytes) = 带宽 (bps) × RTT (秒) / 8

推荐窗口 = BDP × 4
```

**示例：**
```
带宽 = 25 Gbps = 25,000,000,000 bps
RTT = 0.1 ms = 0.0001 秒

BDP = 25,000,000,000 × 0.0001 / 8
    = 312,500 bytes
    ≈ 305 KB

推荐窗口 = 305 KB × 4 = 1.2 MB
```

## 常见问题

### Q1: 为什么需要 sudo？

A: `ss` 命令的某些选项（如 `-p` 显示进程信息）需要 root 权限。

### Q2: 如何确定是 client 还是 server 角色？

A:
- **Client**: 发起连接的一方，使用高端口连接到服务器的固定端口
- **Server**: 监听固定端口的一方

例如 iperf3：
- Server: `iperf3 -s` (监听 5201)
- Client: `iperf3 -c <server>` (使用随机高端口)

### Q3: rwnd_limited 95% 一定是接收窗口问题吗？

A: 是的，这个指标直接反映了发送端被接收端窗口限制的时间占比。如果超过 50%，接收窗口肯定是主要瓶颈。

### Q4: 调整了 tcp_rmem 为什么 rcv_space 还是很小？

A: 可能原因：
1. 连接是在调整前建立的 → 需要重新建立连接
2. 窗口自动调整算法需要时间 → 等待几个 RTT 周期
3. 陷入恶性循环 → 需要同时调大 default 值

### Q5: 如何解读 retrans 字段的 "0/1195"？

A: 格式为 "未确认重传/总重传次数"
- 第一个数字：当前未被确认的重传数量
- 第二个数字：连接建立以来的累积重传次数

### Q6: 工具能检测哪些瓶颈？

A: 主要检测：
1. TCP 层瓶颈（rwnd_limited, cwnd_limited, sndbuf_limited）
2. 拥塞问题（小 cwnd, 高重传）
3. 应用层问题（Recv-Q > 0）
4. 速率限制（pacing_rate 远低于目标）

不能直接检测：
- 网卡硬件问题（需要用 ethtool）
- CPU 瓶颈（需要用 mpstat）
- 内存压力（需要查看系统日志）

## 与其他工具的配合

### 1. 配合 ethtool 检查网卡

```bash
# 运行分析工具
sudo python3 tcp_connection_analyzer.py --remote-ip 1.1.1.5 --remote-port 5201 --role client

# 如果提示检查丢包，使用 ethtool
sudo ethtool -S <网卡名> | grep -E "drop|error|miss"
```

### 2. 配合 eBPF 工具深入分析

```bash
# 如果检测到高延迟，使用延迟分析工具
sudo python3 system_network_latency_details.py \
    --src-ip 1.1.1.2 --dst-ip 1.1.1.5 \
    --protocol tcp --direction tx \
    --phy-interface <网卡> \
    --latency-us 100
```

### 3. 配合 netstat 查看系统统计

```bash
# 查看系统级别的重传统计
netstat -s | grep -i retrans

# 查看 TCP 内存使用
cat /proc/net/sockstat
```

## 输出示例

完整的输出示例参见工具执行结果，主要包含：

1. **系统配置部分** (--show-config)
2. **连接信息和指标**
3. **瓶颈检测结果**
4. **优化建议和命令**

## 限制和注意事项

1. **需要 ss 工具**：系统必须安装 iproute2 包
2. **内核版本**：某些指标（如 rwnd_limited）需要较新的内核（4.9+）
3. **连接状态**：只能分析已建立的连接
4. **采样时间点**：单次采样是瞬时值，建议持续监控
5. **不能替代 eBPF**：无法追踪内核内部的详细路径

## 后续计划

- [ ] 添加历史数据记录和趋势分析
- [ ] 支持多连接对比
- [ ] 添加图形化输出
- [ ] 集成 eBPF 工具进行深度分析
- [ ] 添加自动化测试脚本

## 参考资料

- ss(8) man page
- TCP RFC 793, 1323, 5681
- Linux kernel TCP implementation
- BCC/eBPF performance tools
