# Linux Kernel TCP代码研究任务清单

**目的**：为TCP Socket分析工具提供理论基础
**目标Kernel版本**：openEuler 4.19.90（基于Linux 4.19）
**创建日期**：2025-11-13

---

## 研究总览

本文档列出了实现TCP Socket分析工具所需的kernel代码研究任务。每个任务需要：
1. 找到相关的kernel代码位置
2. 理解计算逻辑和数据结构
3. 明确与采集数据的对应关系
4. 验证理论与实际的一致性

**研究方法**：
- 阅读kernel源代码
- 参考kernel文档和注释
- 使用bpftrace动态追踪（可选）
- 对比实际采集数据验证理解

---

## 任务1：Rate计算方式研究

### 1.1 send_rate研究

**研究目标**：确定send_rate在kernel中的定义和计算方式

**研究问题**：
- [ ] send_rate是kernel计算还是用户空间估算？
- [ ] 如果是kernel计算：
  - 存储在哪个数据结构？（`struct tcp_sock` or `struct sock`？）
  - 计算函数是什么？
  - 计算公式？
  - 更新频率和触发条件？
- [ ] 如果是用户空间估算：
  - ss命令如何计算？
  - 基于哪些kernel提供的原始数据？

**代码位置参考**：
- `net/ipv4/tcp.c`
- `net/ipv4/tcp_output.c`
- `include/net/tcp.h`
- `include/linux/tcp.h`

**搜索关键字**：
- `send_rate`
- `sk_rate`
- `TCP_INFO`（用户空间获取TCP信息的接口）

**记录格式**：
```
## send_rate研究结果

### 定义来源
- [ ] Kernel计算  / [ ] 用户空间估算

### Kernel层实现（如果适用）
**存储位置**：
- 文件：
- 结构体：
- 字段名：

**计算函数**：
- 函数名：
- 文件位置：
- 行号：

**计算公式**：
```c
// 粘贴关键代码
```

**更新时机**：
- 触发条件：
- 更新频率：

### 用户空间实现（如果适用）
**ss命令中的实现**：
- iproute2源码位置：
- 计算方法：

### 实际意义
（用自己的话描述这个rate表示什么）

### 与采集数据的对应
（采集数据中的哪个字段对应这个值）
```

---

### 1.2 pacing_rate研究

**研究目标**：理解pacing_rate的计算机制和作用

**研究问题**：
- [ ] pacing_rate存储在哪里？（预期：`sk->sk_pacing_rate`）
- [ ] 计算函数是什么？（预期：`tcp_update_pacing_rate()`）
- [ ] 计算公式中涉及哪些因素？（CWND、RTT、MSS、pacing_gain等）
- [ ] 慢启动和拥塞避免阶段的pacing_rate有何不同？
- [ ] 不同拥塞控制算法（Cubic vs BBR）的pacing_rate计算有何差异？
- [ ] Pacing机制如何实际控制发送速率？（与FQ qdisc的关系）

**代码位置参考**：
- `net/ipv4/tcp_input.c` - `tcp_update_pacing_rate()`
- `net/ipv4/tcp_cong.c`
- `net/ipv4/tcp_bbr.c` - BBR算法特定实现
- `include/net/sock.h` - `sk_pacing_rate`定义
- `net/sched/sch_fq.c` - FQ qdisc与pacing的配合

**搜索关键字**：
- `tcp_update_pacing_rate`
- `sk_pacing_rate`
- `pacing_gain`
- `tcp_pacing_ss_ratio`
- `tcp_pacing_ca_ratio`

**记录格式**：
```
## pacing_rate研究结果

### 存储位置
**数据结构**：
- 文件：include/net/sock.h
- 结构体：struct sock
- 字段名：sk_pacing_rate
- 类型：

### 计算函数
**函数名**：tcp_update_pacing_rate
**文件位置**：net/ipv4/tcp_input.c
**行号**：

**完整代码**：
```c
// 粘贴tcp_update_pacing_rate函数代码
```

### 计算公式

**Cubic算法（默认）**：
- 慢启动阶段：
  ```
  pacing_rate = ?
  ```
- 拥塞避免阶段：
  ```
  pacing_rate = ?
  ```

**BBR算法**：
```
pacing_rate = ?
```

**相关sysctl参数**：
- `net.ipv4.tcp_pacing_ss_ratio` = ? （默认值）
- `net.ipv4.tcp_pacing_ca_ratio` = ? （默认值）

### 更新时机
（什么时候调用tcp_update_pacing_rate？）

### Pacing机制
（pacing_rate如何实际限制发送速率？）

**与qdisc的关系**：
（FQ qdisc如何读取和使用sk_pacing_rate？）

### 实际意义
（用自己的话描述）

### 与采集数据的对应
- 采集数据字段：pacing_rate
- 单位转换：
```

---

### 1.3 delivery_rate研究

**研究目标**：理解delivery_rate的测量机制

**研究问题**：
- [ ] delivery_rate基于什么机制计算？（ACK采样）
- [ ] 涉及哪些函数？（`tcp_rate_skb_sent`, `tcp_rate_skb_delivered`, `tcp_rate_gen`）
- [ ] 采样窗口是如何确定的？
- [ ] interval_us是如何计算的？（snd_interval vs ack_interval）
- [ ] 如何处理重传的影响？
- [ ] BBR如何使用delivery_rate？
- [ ] 用户空间如何从kernel获取这个值？

**代码位置参考**：
- `net/ipv4/tcp_rate.c` - 主要实现文件
- `include/net/tcp.h` - rate_sample结构定义
- `net/ipv4/tcp_input.c` - 调用tcp_rate相关函数
- `net/ipv4/tcp_output.c` - 发送时标记

**搜索关键字**：
- `tcp_rate_gen`
- `tcp_rate_skb_sent`
- `tcp_rate_skb_delivered`
- `rate_delivered`
- `rate_interval_us`
- `delivery_rate`

**记录格式**：
```
## delivery_rate研究结果

### 核心数据结构
**rate_sample结构**：
```c
// 粘贴struct rate_sample定义
```

**tcp_sock中的相关字段**：
- `rate_delivered`
- `rate_interval_us`
- `rate_app_limited`
- 其他...

### 计算流程

**1. 发送时标记（tcp_rate_skb_sent）**：
```c
// 粘贴关键代码
```
（记录什么信息？）

**2. ACK时更新（tcp_rate_skb_delivered）**：
```c
// 粘贴关键代码
```
（计算什么？）

**3. 生成rate估算（tcp_rate_gen）**：
```c
// 粘贴tcp_rate_gen函数代码
```

### 计算公式
```
delivered = ?
interval_us = max(snd_us, ack_us)
delivery_rate = ?
```

**为什么取max(snd_us, ack_us)？**
（理解并解释）

### 处理特殊情况
- 重传如何处理？
- app_limited如何标记和影响？

### 采样频率
（多久更新一次delivery_rate？）

### 用户空间获取
（ss命令如何从kernel获取delivery_rate？）
- getsockopt调用？
- TCP_INFO结构？

### 与BBR的关系
（BBR如何使用delivery_rate？）

### 实际意义
（用自己的话描述）

### 与采集数据的对应
- 采集数据字段：delivery_rate
- 单位转换：
```

---

### 1.4 三种Rate关系总结

完成上述三个rate的研究后，总结：

**记录格式**：
```
## 三种Rate的关系

### 定义对比
| Rate | 类型 | 来源 | 更新频率 |
|------|------|------|----------|
| send_rate | ? | ? | ? |
| pacing_rate | ? | ? | ? |
| delivery_rate | ? | ? | ? |

### 在TCP发送流程中的位置
```
应用层
  ↓
[send_rate 相关]
  ↓
TCP层
  ↓
[pacing_rate 控制]
  ↓
网络层
  ↓
网络物理传输
  ↓
[delivery_rate 测量]
  ↓
ACK返回
```

### 正常情况下的关系
```
理论关系：
pacing_rate >= send_rate >= delivery_rate （是否正确？）

实际观察：
（基于采集数据的观察）
```

### 异常模式识别
**模式1：delivery_rate << pacing_rate**
- 含义：
- 可能原因：
- 诊断方法：

**模式2：send_rate << pacing_rate**
- 含义：
- 可能原因：
- 诊断方法：

### 分析建议
（基于三种rate的对比，如何诊断性能问题？）
```

---

## 任务2：Socket Memory字段研究

### 2.1 字段定义研究

**研究目标**：明确采集数据中每个buffer/queue字段在kernel中的定义

**采集数据中的字段列表**：
1. recv_q
2. send_q
3. socket_rx_queue
4. socket_rx_buffer
5. socket_tx_queue
6. socket_tx_buffer
7. socket_forward_alloc
8. socket_write_queue
9. socket_opt_mem
10. socket_backlog
11. socket_dropped
12. inflight_data
13. unacked

**对每个字段，需要研究**：
- [ ] Kernel中的对应结构体和字段名
- [ ] 字段定义所在文件和行号
- [ ] 数据类型和单位
- [ ] 何时增加、何时减少（代码位置）
- [ ] 与其他字段的关系

**代码位置参考**：
- `include/net/sock.h` - struct sock定义
- `include/linux/tcp.h` - struct tcp_sock定义
- `net/ipv4/tcp.c` - TCP相关操作
- `net/ipv4/tcp_input.c` - 接收路径
- `net/ipv4/tcp_output.c` - 发送路径

**记录格式模板**（为每个字段创建一节）：

```
### recv_q

**采集数据字段名**：recv_q

**Kernel对应**：
- 结构体：struct sock / struct tcp_sock （哪个？）
- 字段名：？
- 文件位置：include/net/sock.h:行号
- 数据类型：

**定义代码**：
```c
// 粘贴字段定义
```

**实际意义**：
（这个字段表示什么？在哪个位置的数据？）

**增加时机**：
- 函数名：
- 文件位置：
- 代码片段：
```c
// 粘贴增加此字段的代码
```

**减少时机**：
- 函数名：
- 文件位置：
- 代码片段：
```c
// 粘贴减少此字段的代码
```

**与其他字段的关系**：
（数学关系或包含关系）

**在pipeline中的位置**：
（见2.2节的pipeline图）
```

---

### 2.2 Pipeline梳理

**研究目标**：梳理数据包从应用层到网络、从网络到应用层的完整路径，标注每个buffer的位置

#### 2.2.1 发送路径追踪

**研究方法**：
1. 从 `write()` 系统调用入口开始
2. 追踪到 `tcp_sendmsg()`
3. 追踪到 `tcp_write_xmit()` 和 `tcp_transmit_skb()`
4. 追踪到 `ip_queue_xmit()`
5. 标注每个阶段的buffer/queue

**需要确定的问题**：
- [ ] send_q在哪个阶段？
- [ ] socket_write_queue在哪个阶段？
- [ ] socket_tx_queue在哪个阶段？
- [ ] socket_tx_buffer的限制在哪里生效？
- [ ] inflight_data在哪个阶段？
- [ ] unacked如何计算？

**记录格式**：
```
## 发送路径Pipeline

### 完整流程图
```
应用程序
  |
  | write()/send() 系统调用
  ↓
[用户空间 → 内核空间边界]
  |
  | sys_sendmsg() / sock_write_iter()
  ↓
Socket层
  |
  | 函数：？
  | Buffer：send_q (?)
  ↓
TCP层 - 消息处理
  |
  | 函数：tcp_sendmsg()
  | Buffer：socket_write_queue (?)
  ↓
TCP层 - 分段和排队
  |
  | 函数：tcp_write_xmit()
  | Buffer：socket_tx_queue (?)
  | 限制：socket_tx_buffer (?)
  ↓
TCP层 - 发送
  |
  | 函数：tcp_transmit_skb()
  | 状态：inflight_data (?)
  ↓
IP层
  |
  | 函数：ip_queue_xmit()
  ↓
设备层（qdisc, driver）
  ↓
网络物理层
  |
  ↓
网络传输中
  |
  | 状态：unacked (?)
  ↓
ACK返回
  |
  | 函数：tcp_ack(), tcp_clean_rtx_queue()
  ↓
释放buffer
```

### 关键函数详细分析

#### write()/send() 系统调用
**入口函数**：
```c
// 粘贴相关代码
```

**send_q位置**：
（确定send_q是否在这里，如果不是，在哪里？）

#### tcp_sendmsg()
**文件**：net/ipv4/tcp.c
**关键代码**：
```c
// 粘贴关键代码片段
```

**socket_write_queue位置**：
（确定socket_write_queue是否对应这里）

#### tcp_write_xmit()
**文件**：net/ipv4/tcp_output.c
**关键代码**：
```c
// 粘贴关键代码片段
```

**socket_tx_queue位置**：
（确定socket_tx_queue是否对应这里）

#### tcp_transmit_skb()
**文件**：net/ipv4/tcp_output.c
**关键代码**：
```c
// 粘贴关键代码片段
```

**inflight_data统计**：
（inflight_data是否在这里增加？）

### Buffer数量关系
（基于pipeline理解，推导各buffer的数量关系）

例如：
```
socket_tx_buffer >= socket_write_queue + socket_tx_queue (?)
inflight_data = unacked × MSS (?)
```
```

---

#### 2.2.2 接收路径追踪

**研究方法**：
1. 从网络层 `ip_rcv()` 开始
2. 追踪到 `tcp_v4_rcv()` 和 `tcp_rcv_established()`
3. 追踪到 `tcp_data_queue()`
4. 追踪到 `tcp_recvmsg()`
5. 标注每个阶段的buffer/queue

**需要确定的问题**：
- [ ] socket_rx_queue在哪个阶段？
- [ ] socket_rx_buffer的限制在哪里生效？
- [ ] recv_q在哪个阶段？
- [ ] socket_backlog在哪里？
- [ ] socket_dropped在哪里增加？

**记录格式**：
```
## 接收路径Pipeline

### 完整流程图
```
网络物理层
  ↓
设备层（NIC, driver）
  ↓
IP层
  |
  | 函数：ip_rcv(), ip_local_deliver()
  ↓
TCP层 - 接收处理
  |
  | 函数：tcp_v4_rcv(), tcp_rcv_established()
  | Buffer：socket_backlog (?)
  ↓
TCP层 - 数据排队
  |
  | 函数：tcp_data_queue()
  | Buffer：socket_rx_queue (?)
  | 限制：socket_rx_buffer (?)
  | 丢包点：socket_dropped (?)
  ↓
Socket接收队列
  |
  | Buffer：recv_q (?)
  ↓
[内核空间 → 用户空间边界]
  |
  | 函数：tcp_recvmsg()
  ↓
应用程序
  |
  | read()/recv() 系统调用
  ↓
用户buffer
```

### 关键函数详细分析

#### tcp_v4_rcv()
**文件**：net/ipv4/tcp_ipv4.c
**关键代码**：
```c
// 粘贴关键代码片段
```

#### tcp_rcv_established()
**文件**：net/ipv4/tcp_input.c
**关键代码**：
```c
// 粘贴关键代码片段
```

#### tcp_data_queue()
**文件**：net/ipv4/tcp_input.c
**关键代码**：
```c
// 粘贴关键代码片段
```

**socket_rx_queue位置**：
（确定socket_rx_queue是否对应这里）

**socket_dropped增加位置**：
```c
// 粘贴socket_dropped++的代码
```

**条件**：
（什么条件下增加socket_dropped？）

#### tcp_recvmsg()
**文件**：net/ipv4/tcp.c
**关键代码**：
```c
// 粘贴关键代码片段
```

**recv_q位置**：
（确定recv_q是否对应这里）

### Buffer数量关系
（基于pipeline理解，推导各buffer的数量关系）
```

---

### 2.3 字段关系验证

**研究目标**：基于代码理解推导buffer之间的数学关系，并用实际数据验证

**研究方法**：
1. 基于代码理解，推导理论关系式
2. 从采集数据中提取实际值
3. 计算和验证关系式
4. 如果不匹配，重新检查理解

**记录格式**：
```
## Buffer字段关系验证

### 理论关系推导

**关系1：发送侧buffer关系**
```
推导：基于发送pipeline，
socket_tx_buffer应该限制：
socket_tx_buffer >= socket_write_queue + socket_tx_queue

或者：
socket_tx_buffer >= inflight_data + send_q

（写出你推导的关系）
```

**关系2：接收侧buffer关系**
```
推导：
socket_rx_buffer >= socket_rx_queue + recv_q

（写出你推导的关系）
```

**关系3：inflight_data与unacked**
```
推导：
inflight_data = unacked × MSS (?)

（写出你推导的关系）
```

**关系4：其他关系**
（补充其他推导的关系）

### 实际数据验证

**数据来源**：
- 文件：traffic-analyzer/tcp-perf/1112/tcpsocket/client/client.1
- 时间点：选择几个时间点采样

**验证关系1**：
```
时间点1：2025-11-12 14:19:47.320
- socket_tx_buffer = 16777216 bytes
- socket_write_queue = 16821248 bytes
- socket_tx_queue = 0 bytes
- 计算：socket_write_queue + socket_tx_queue = 16821248
- 关系：16777216 >= 16821248 ? 不成立！

结论：关系1的推导可能有误，需要重新理解。
```

**验证关系2**：
```
（类似的验证其他关系）
```

### 修正后的关系

（基于验证结果，修正理论关系）

### 最终确认的关系

（列出验证通过的关系式）
```

---

## 任务3：Window字段研究

### 3.1 CWND研究

**研究目标**：明确cwnd的定义、单位、更新机制

**研究问题**：
- [ ] cwnd存储在哪里？（`tp->snd_cwnd`）
- [ ] cwnd的单位是什么？（packets还是bytes？）
- [ ] 不同拥塞控制算法如何更新cwnd？
  - Cubic算法
  - BBR算法
  - Reno算法
- [ ] 慢启动、拥塞避免、快速恢复中cwnd的变化
- [ ] ssthresh的作用和更新时机

**代码位置参考**：
- `include/linux/tcp.h` - tcp_sock结构
- `net/ipv4/tcp_input.c` - cwnd更新逻辑
- `net/ipv4/tcp_cong.c` - 拥塞控制框架
- `net/ipv4/tcp_cubic.c` - Cubic算法
- `net/ipv4/tcp_bbr.c` - BBR算法

**记录格式**：
```
## CWND研究结果

### 存储位置
**结构体**：struct tcp_sock
**字段名**：snd_cwnd
**文件**：include/linux/tcp.h
**定义**：
```c
// 粘贴定义
```

### 单位
**单位**：packets (MSS-sized segments) 还是 bytes？
（通过代码确认）

### 初始值
**初始cwnd**：
- 函数：tcp_init_cwnd()
- 文件：net/ipv4/tcp_input.c
- 代码：
```c
// 粘贴tcp_init_cwnd代码
```
- 计算：initial cwnd = ?

### 慢启动阶段

**慢启动更新逻辑**：
```c
// 粘贴慢启动cwnd更新代码
```

**更新公式**：
```
cwnd_new = cwnd_old + acked (?)
```

**何时结束慢启动**：
```
当 cwnd >= ssthresh 时
```

### 拥塞避免阶段

**拥塞避免更新逻辑**：
```c
// 粘贴拥塞避免cwnd更新代码
```

**更新公式**：
```
（Cubic算法）
W_cubic = ?
cwnd = ?
```

### 快速恢复

**进入快速恢复的条件**：
- 触发：3个duplicate ACK

**cwnd变化**：
```
cwnd = ssthresh + 3 (?)
```

### ssthresh更新

**更新时机**：
- 检测到丢包时

**更新公式**：
```
ssthresh = max(cwnd / 2, 2) (?)
```

### 与采集数据的对应
- 采集字段：cwnd
- 单位：packets
- 采集字段：ssthresh
```

---

### 3.2 RWND研究

**研究目标**：明确接收窗口的表示和更新机制

**研究问题**：
- [ ] RWND存储在哪里？
- [ ] 采集数据中的rcv_space是否就是RWND？
- [ ] rcv_ssthresh的作用？
- [ ] 接收窗口如何通告给发送方？
- [ ] 接收窗口自动调整（auto-tuning）机制？

**代码位置参考**：
- `include/linux/tcp.h` - tcp_sock中的相关字段
- `net/ipv4/tcp_input.c` - 接收窗口计算
- `net/ipv4/tcp_output.c` - 窗口通告

**记录格式**：
```
## RWND研究结果

### 相关字段
**tcp_sock结构中的接收窗口相关字段**：
- `rcv_wnd`：?
- `rcv_ssthresh`：?
- `rcvq_space`：?

**定义**：
```c
// 粘贴相关字段定义
```

### 窗口计算
**函数**：tcp_select_window()
**文件**：net/ipv4/tcp_output.c
**代码**：
```c
// 粘贴tcp_select_window代码
```

**计算逻辑**：
（解释计算过程）

### 窗口通告
**如何通告**：
（通过TCP header中的window字段）

**Window Scale**：
（window scale选项的作用）

### 接收窗口自动调整
**函数**：tcp_rcv_space_adjust()
**文件**：net/ipv4/tcp_input.c
**代码**：
```c
// 粘贴代码
```

**调整机制**：
（解释auto-tuning机制）

### 与采集数据的对应
- 采集字段：rcv_space
- 对应kernel字段：?
- 采集字段：rcv_ssthresh
- 对应kernel字段：?
```

---

### 3.3 SWND研究

**研究目标**：明确发送窗口的计算方法

**研究问题**：
- [ ] SWND是如何计算的？（min(CWND, RWND)?）
- [ ] 采集数据中的snd_wnd对应什么？
- [ ] 实际发送时如何使用这个值？

**代码位置参考**：
- `net/ipv4/tcp_output.c`

**记录格式**：
```
## SWND研究结果

### 定义
**发送窗口的概念**：
（用自己的话解释）

### 计算方法
**代码位置**：
```c
// 查找发送窗口计算代码
```

**计算公式**：
```
snd_wnd = min(cwnd, advertised_rwnd) (?)
```

### 与发送限制的关系
**发送条件检查**：
```c
// 粘贴检查是否可以发送的代码
```

### 与采集数据的对应
- 采集字段：snd_wnd
- 对应kernel字段：tp->snd_wnd
- 单位：
```

---

### 3.4 窗口限制状态研究

**研究目标**：理解如何判断连接受哪种窗口限制

**研究问题**：
- [ ] 如何判断CWND Limited？
- [ ] 如何判断RWND Limited？
- [ ] 如何判断SNDBUF Limited？
- [ ] kernel是否有现成的统计？

**代码位置参考**：
- `net/ipv4/tcp_output.c` - 发送限制检查

**记录格式**：
```
## 窗口限制状态研究

### CWND Limited判断
**条件**：
```
inflight >= cwnd 且 cwnd < rwnd
```

**代码位置**：
```c
// 查找相关判断代码
```

### RWND Limited判断
**条件**：
```
inflight >= rwnd 且 rwnd < cwnd
```

### SNDBUF Limited判断
**条件**：
```
sk_wmem_alloc >= sk_sndbuf
```

### Kernel统计
**是否有现成统计**：
（查找tcp_info结构或其他统计）

**采集数据中的相关字段**：
- rwnd_limited时间占比
- cwnd_limited时间占比
- sndbuf_limited时间占比

**如何计算这些占比**：
（kernel代码中的计算方法）
```

---

## 任务4：数据格式确认

**研究目标**：确认tcp_connection_analyzer.py的输出与kernel数据的对应关系

**研究方法**：
1. 阅读tcp_connection_analyzer.py源码
2. 确认它使用的数据来源（ss命令？netlink？getsockopt?）
3. 确认字段映射关系

**记录格式**：
```
## 采集工具分析

### tcp_connection_analyzer.py数据来源
**使用的工具/接口**：
- [ ] ss命令
- [ ] netlink socket
- [ ] getsockopt(TCP_INFO)
- [ ] /proc/net/tcp
- [ ] 其他：

### 字段映射表
| 采集数据字段 | Kernel结构体 | Kernel字段名 | 单位 | 备注 |
|-------------|-------------|-------------|------|------|
| recv_q | ? | ? | bytes | |
| send_q | ? | ? | bytes | |
| rtt | tcp_sock | srtt_us | microseconds | 需要转换 |
| rttvar | tcp_sock | mdev_us | microseconds | 需要转换 |
| cwnd | tcp_sock | snd_cwnd | packets | |
| ... | ... | ... | ... | |

### 单位转换
**RTT**：
- Kernel存储：srtt_us (微秒)
- 采集输出：ms (毫秒)
- 转换：srtt_us / 1000

**其他转换**：
（列出所有需要注意的单位转换）
```

---

## 任务5：综合验证

**研究目标**：使用实际采集数据验证所有研究结果

**验证方法**：
1. 选择一些采样点的数据
2. 根据研究结果验证各种关系
3. 确认理论与实际的一致性

**记录格式**：
```
## 综合验证

### 验证用数据
**数据文件**：traffic-analyzer/tcp-perf/1112/tcpsocket/client/client.1
**选择的采样点**：
- 时间点1：2025-11-12 14:19:47.320
- 时间点2：...

### 验证项1：BDP计算
**物理带宽**：10 Gbps (假设)
**RTT**：5.349 ms
**计算BDP**：
```
BDP = 10 Gbps × 5.349 ms / 8
    = 10 × 10^9 × 5.349 × 10^-3 / 8
    = 6686250 bytes
    ≈ 6.5 MB
```

**理论最优cwnd**：
```
optimal_cwnd = BDP / MSS
             = 6686250 / 1448
             ≈ 4617 packets
```

**实际cwnd**：5846 packets

**对比**：实际cwnd > 理论cwnd，合理（有余量）

### 验证项2：Rate关系
**pacing_rate**：15.19 Gbps
**delivery_rate**：1.64 Gbps
**send_rate**：12.66 Gbps

**分析**：
- delivery_rate << pacing_rate：网络传输存在瓶颈
- send_rate < pacing_rate：发送受pacing控制

### 验证项3：Buffer关系
**socket_tx_buffer**：16777216 bytes
**socket_write_queue**：16821248 bytes

**分析**：
- socket_write_queue > socket_tx_buffer ？
- 这不合理，需要重新理解这两个字段的含义

（继续验证其他项...）

### 发现的问题
（列出验证中发现的不一致或疑问）

### 需要进一步研究的点
（列出需要深入研究的问题）
```

---

## 研究输出

完成所有任务后，需要产出：

### 1. 研究报告
- 每个任务的详细研究结果
- 代码片段和说明
- 数据结构图
- Pipeline流程图

### 2. 字段映射表
- 采集数据字段与kernel字段的完整映射
- 单位转换说明

### 3. 关系公式汇总
- 所有验证通过的数学关系
- 使用条件和适用范围

### 4. 分析方法指南
- 基于研究结果，如何分析各种性能指标
- 问题识别的判断依据
- 优化建议的生成方法

### 5. 更新需求规格
- 将研究结果反馈到需求规格书
- 完善详细分析部分的说明
- 明确实现中需要注意的细节

---

## 附录：研究工具

### 代码浏览工具
- **LXR/Elixir**：在线浏览kernel源码，带索引
- **VS Code + C/C++扩展**：本地浏览，支持跳转
- **cscope/ctags**：命令行代码索引工具

### 动态追踪工具（可选）
- **bpftrace**：编写脚本追踪kernel函数
- **perf**：性能分析工具
- **systemtap**：kernel动态追踪

### 参考资料
- Linux Kernel文档：https://www.kernel.org/doc/
- LWN.net文章：https://lwn.net/
- TCP RFC：RFC 793, 5681, 6298等
- BBR论文和文档

---

**文档结束**

**下一步**：开始执行各个研究任务，并将结果填写到本文档中。