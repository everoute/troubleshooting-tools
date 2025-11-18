# 最大 RTT 27.5 秒计算详解

## 问题：tshark 是如何计算 RTT 的？

### RTT (Round-Trip Time) 定义
RTT 是指从**发送数据包**到**收到该数据包的 ACK 确认**之间的时间间隔。

### tshark 的 `tcp.analysis.ack_rtt` 字段
tshark 自动追踪每个 TCP 流，计算每个 ACK 对应的原始数据包发送时间，从而得出 RTT。

---

## 27.5 秒 RTT 的具体案例

### 涉及的数据包

| Frame | 时间 (秒) | 方向 | 描述 | 重传 |
|-------|----------|------|------|------|
| 1779 | 17.305 | 服务器→客户端 | seq=398473, len=1310 首次发送 | ❌ |
| 1788 | 18.182 | 服务器→客户端 | seq=398473, len=1310 第1次重传 | ✅ |
| 2054 | 30.734 | 服务器→客户端 | seq=398473, len=1310 第2次重传 | ✅ |
| 2805 | 44.804 | 服务器→客户端 | seq=398473, len=1310 第3次重传 | ✅ |
| **2806** | **44.855** | **客户端→服务器** | **ack=399783 确认** | ❌ |

### 计算过程

```
RTT = ACK 确认时间 - 首次数据发送时间
RTT = 44.855204 - 17.304519
RTT = 27.550685 秒
RTT = 27,550.685 毫秒
```

### 验证

```bash
# 查看 Frame 1779 (首次发送)
tshark -r 02.pcap -Y "frame.number == 1779" -T fields \
  -e frame.number -e frame.time_relative -e ip.src -e tcp.seq -e tcp.len

# 输出: 1779	17.304519000	10.10.216.21	398473	1310

# 查看 Frame 2806 (ACK 确认)
tshark -r 02.pcap -Y "frame.number == 2806" -T fields \
  -e frame.number -e frame.time_relative -e ip.src -e tcp.ack

# 输出: 2806	44.855204000	10.10.64.28	399783

# 确认 ACK 号匹配
# seq + len = ack
# 398473 + 1310 = 399783 ✅
```

---

## 为什么 RTT 这么长？

### 重传时间线

```
17.305s ━━━━┓ 首次发送 (Frame 1779)
            │
18.182s ━━━━┫ 0.88秒后，第1次重传 (Frame 1788)
            │   ↓ TCP 指数退避
30.734s ━━━━┫ 12.55秒后，第2次重传 (Frame 2054)
            │   ↓ 继续指数退避
44.804s ━━━━┫ 14.07秒后，第3次重传 (Frame 2805)
            │
44.855s ━━━━┛ 客户端终于发送 ACK (Frame 2806)
```

### 根本原因

1. **严重丢包**：前 3 次发送的数据包全部丢失或未被确认
2. **TCP 重传机制**：
   - 第1次重传：正常超时重传（~1秒）
   - 第2次重传：指数退避（~12秒）
   - 第3次重传：继续指数退避（~14秒）
3. **网络问题**：
   - 可能是中间设备拥塞
   - 可能是客户端接收缓冲区满
   - 可能是客户端处理延迟

---

## 其他高 RTT 案例

在同一个抓包文件中，还有其他高 RTT 的例子：

```bash
tshark -r 02.pcap -Y "ip.addr==10.10.216.21 and tcp.port==443 and tcp.analysis.ack_rtt > 10" \
  -T fields -e frame.number -e tcp.analysis.ack_rtt | head -5
```

输出：
```
2806    27.550685000    # 最严重的案例
2835    21.669688000    # 也很严重
2838    21.670184000    # 也很严重
```

所有这些高 RTT 都是由于**多次重传失败**导致的。

---

## 总结

### tshark RTT 计算公式

```
tcp.analysis.ack_rtt = ACK_time - Original_Data_Send_time
```

### 注意事项

1. **RTT ≠ 网络延迟**
   - 正常情况下，RTT 反映网络延迟
   - 但有重传时，RTT 反映的是"首次发送到最终确认"的总时长

2. **重传会导致 RTT 虚高**
   - 本案例中，真实网络延迟可能只有几毫秒
   - 但由于 3 次重传，RTT 被计算为 27.5 秒

3. **如何查看真实网络延迟**
   - 查看 `tcp.analysis.initial_rtt`（3次握手的 RTT）
   - 查看没有重传的数据包的 RTT
   - 在本案例中，初始 RTT 只有 0.143 ms

### 诊断命令

```bash
# 查看 TCP 流的统计信息
tshark -r 02.pcap -Y "tcp.stream == 6" -q -z conv,tcp

# 查看重传统计
tshark -r 02.pcap -Y "tcp.stream == 6 and tcp.analysis.retransmission" | wc -l

# 查看 RTT 分布
tshark -r 02.pcap -Y "tcp.stream == 6 and tcp.analysis.ack_rtt" \
  -T fields -e tcp.analysis.ack_rtt | \
  awk '{sum+=$1; sumsq+=$1*$1; n++} END {print "Avg:", sum/n, "StdDev:", sqrt(sumsq/n - (sum/n)^2)}'
```

---

## 结论

**27.5 秒的 RTT 并不是网络延迟，而是由于严重的丢包和多次重传导致的总耗时。**

这个指标清楚地表明：
- ❌ 网络存在严重问题（8.99% 重传率）
- ❌ 需要立即排查网络路径
- ❌ 可能需要检查中间设备和服务器配置

真实的网络延迟（基础 RTT）可能只有不到 1 毫秒。
