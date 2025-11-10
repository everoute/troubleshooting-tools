# Kernel 代码调研报告

**调研日期**：2024-11-13
**调研目标**：
1. TCPSocket 分析工具中各类 Rate 的计算方式
2. skmem 各字段的详细意义和位置
3. 数据包收发 pipeline 中 buffer 的完整路径

---

## 1. Rate 相关计算调研

### 1.1 delivery_rate（传输速率）

**源代码**：`net/ipv4/tcp_rate.c`

**计算函数**：`tcp_rate_gen()`

**核心逻辑**：
```c
// 在 tcp_rate_gen() 中
rs->delivered = tp->delivered - rs->prior_delivered;
snd_us = rs->interval_us;  // 发送阶段时间
ack_us = tcp_stamp_us_delta(tp->tcp_mstamp, rs->prior_mstamp);  // ACK阶段时间
rs->interval_us = max(snd_us, ack_us);  // 取较长阶段

// 存储到 tp
tp->rate_delivered = rs->delivered;
tp->rate_interval_us = rs->interval_us;
```

**关键发现**：
- **delivery_rate 不会直接存储在 tcp_sock 结构中**
- 它是 **临时计算值**，通过 `rate_delivered / rate_interval_us` 计算
- **ss 命令输出**的 delivery_rate 是在用户空间计算的：
  ```
  delivery_rate = tp->rate_delivered * MSS * 8 / tp->rate_interval_us
  ```
- **采样区间**：每个 ACK 触发一次计算
- **interval_us**：取发送阶段和 ACK 阶段的较大值
- **目的**：估算网络的**有效吞吐量能力**

**数据路径**：
```
send (tcp_rate_skb_sent)
    ↓
  skb 发送时记录时间戳和 delivered 计数
    ↓
ack (tcp_rate_skb_delivered)
    ↓
  比较 delivered 计数，计算差值
    ↓
tcp_rate_gen
    ↓
  计算 interval_us = max(send_interval, ack_interval)
    ↓
  存储到 tp->rate_delivered 和 tp->rate_interval_us
```

---

### 1.2 pacing_rate（Pacing 速率）

**源代码**：`net/ipv4/tcp_input.c`, `tcp_update_pacing_rate()`

**计算公式**：
```c
// 计算基础：mss * cwnd / srtt (bytes per second)
rate = (u64)tp->mss_cache * ((USEC_PER_SEC / 100) << 3);

// 根据拥塞控制阶段乘以系数
if (tp->snd_cwnd < tp->snd_ssthresh / 2)
    // 慢启动前期：200% (sysctl_tcp_pacing_ss_ratio 默认值 200)
    rate *= sysctl_tcp_pacing_ss_ratio;
else
    // 拥塞避免或慢启动后期：120% (sysctl_tcp_pacing_ca_ratio 默认值 120)
    rate *= sysctl_tcp_pacing_ca_ratio;

rate *= max(tp->snd_cwnd, tp->packets_out);

do_div(rate, tp->srtt_us);  // 除以 RTT

// 最终 pacing_rate
sk->sk_pacing_rate = min(rate, sk->sk_max_pacing_rate);
```

**关键公式总结**：
```
pacing_rate =
  ├─ 慢启动 (cwnd < ssthresh/2):
  │   pacing_rate = 200% × (mss × cwnd / srtt)
  │
  └─ 拥塞避免/慢启动后期:
      pacing_rate = 120% × (mss × cwnd / srtt)
```

**关键发现**：
- **存储位置**：`sk->sk_pacing_rate`（struct sock 中）
- **单位**：bytes per second
- **更新时机**：每个 ACK 到达时（tcp_ack() → tcp_update_pacing_rate）
- **目的**：控制数据包发送节奏，**减少突发，平滑流量**
- **机制**：与 FQ（Fair Queue）调度器配合，限制队列长度
- **默认值**：
  - `sysctl_tcp_pacing_ss_ratio` = 200（慢启动系数）
  - `sysctl_tcp_pacing_ca_ratio` = 120（拥塞避免系数）

**sysctl 参数位置**：
```bash
net.ipv4.tcp_pacing_ss_ratio = 200
net.ipv4.tcp_pacing_ca_ratio = 120
```

---

### 1.3 send_rate（发送速率）

**调研结果**：**没有找到明确的 send_rate 计算代码**

**分析**：
- `ss` 命令显示的 send_rate 应该是
- **用户空间估算值**，不是内核直接提供的指标
- 可能计算方式：**最近时间窗口内的实际发送速率**
- 计算公式推测：
  ```
  send_rate = (最近发送字节数) / (时间窗口) * 8
  ```

**建议**：在 TCPSocket 工具中，send_rate 作为**参考值**，重点分析 pacing_rate 和 delivery_rate

---

### 1.4 三类 Rate 的关系总结

```
                pacing_rate              delivery_rate
                    |                         |
                    ↓ (上限)                  ↑ (实际能力)
              ┌─────┴─────┐            ┌──────┴──────┐
              ↓           ↓            ↓             ↓
           发送队列 → 网络排队 → 网络传输 → 到达对端 → ACK
              ↑                                               ↑
              └─────────────────────────────────────────────┘
                                    |
                                send_rate (估算)
```

**	pacing_rate**：**计划发送速率**
- 由拥塞控制算法计算
- 用于控制发送节奏
- 防止突发填满缓冲区

**	delivery_rate**：**网络交付速率**
- 测量网络实际能传输的速率
- 基于 ACK 反馈计算
- 反映**网络瓶颈**的真实能力

**	send_rate**：实际观测到的发送速率（用户空间估算）
- 可能略低于 pacing_rate
- 可能受应用层发送限制

**理想情况**：
```
delivery_rate ≈ pacing_rate*0.8-1.0  # 网络充分利用
send_rate ≈ pacing_rate              # 应用发送能力足够
```

**异常情况**：
```
delivery_rate << pacing_rate  # 网络瓶颈（丢包、拥塞、对端接收慢）
send_rate << pacing_rate      # 应用限制（app_limited）
```

---

## 2. skmem 字段详细调研

### 2.1 skmem 字段在内核中的定义

**源代码**：`include/net/sock.h`

**ss 命令输出格式**：
```
skmem:(r<r>,rb<rb>,t<t>,tb<tb>,f<f>,w<w>,o<o>,bl<bl>,d<d>)
```

### 2.2 各字段详细说明

#### r - sk_rmem_alloc

**定义**：`include/net/sock.h:394`
```c
#define sk_rmem_alloc sk_backlog.rmem_alloc
```

**类型**：`atomic_t`

**含义**：Receive Queue 中已分配内存
- 已通过校验和验证、TCP 序列号检查、放入 socket 接收队列的数据
- 单位：bytes

**访问路径**：`tcp_v4_rcv()` → `tcp_v4_do_rcv()` → `tcp_rcv_established()`
在 `tcp_data_queue()` 中分配：
```c
// net/ipv4/tcp_input.c:tcp_data_queue()
if (!eaten) {
    __skb_queue_tail(&sk->sk_receive_queue, skb);  // 加入接收队列
    atomic_add(skb->truesize, &sk->sk_rmem_alloc);  // 增加计数
}
```

**减少位置**：应用程序读取数据时
```c
// net/ipv4/tcp.c:tcp_recvmsg()
__skb_unlink(skb, &sk->sk_receive_queue);
atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
```

---

#### rb - sk_rcvbuf

**定义**：`struct sock` 中的字段

**类型**：`int`

**含义**：Receive Buffer 大小上限

**设置来源**：
1. 系统默认值：`net.core.rmem_default`
2. TCP 默认值：`tcp_rmem[1]`
3. 用户设置：`setsockopt(SO_RCVBUF)`

**读取路径**：`tcp_select_window()` 用于计算通告窗口

**内核设置位置**：
```c
// net/ipv4/tcp_input.c:tcp_rcv_space_adjust()
if (sk->sk_rcvbuf < new_clamp) {
    sk->sk_rcvbuf = new_clamp;
    tp->rcvq_space.space = new_clamp;
}
```

**sysctl 参数**：
```bash
net.ipv4.tcp_rmem = 4096 87380 6291456  # min default max
net.core.rmem_max = 212992
```

---

#### t - sk_wmem_alloc

**定义**：`include/net/sock.h:419`

**类型**：`refcount_t`

**含义**：Transmit Queue 中已分配内存

**注意**：初始值为 1（占位符），所以实际使用值为 `sk_wmem_alloc_get() - 1`

**增加位置**：发送数据包时
```c
// net/ipv4/tcp_output.c:tcp_transmit_skb()
skb_set_owner_w(skb, sk);  // 内部调用 refcount_add(skb->truesize, &sk->sk_wmem_alloc)
```

**减少位置**：数据包确认后
```c
// net/ipv4/tcp_input.c:tcp_clean_rtx_queue()
tcp_free_skb(sk, skb);  // 内部调用 refcount_sub(skb->truesize, &sk->sk_wmem_alloc)
```

**表示内容**：待发送 + 已发送未确认的数据

---

#### tb - sk_sndbuf

**定义**：`struct sock` 中的字段

**类型**：`int`

**含义**：Send Buffer 大小上限

**设置来源**：
1. 系统默认值：`net.core.wmem_default`
2. TCP 默认值：`tcp_wmem[1]`
3. 用户设置：`setsockopt(SO_SNDBUF)`

**sysctl 参数**：
```bash
net.ipv4.tcp_wmem = 4096 16384 4194304  # min default max
net.core.wmem_max = 212992
```

---

#### f - sk_forward_alloc

**定义**：`include/net/sock.h:396`

**类型**：`int`

**含义**：**预分配内存（Forward Allocation）**

**作用**：为提高内存分配效率，TCP 协议栈会为 socket **预分配**一块内存池

**详细机制**：
- 当 socket 需要内存时（分配 skb），优先从 `sk_forward_alloc` 扣除
- 当 `sk_forward_alloc` 不足时，再从系统申请大块内存（`sk_mem_reclaim()`）
- 避免每分配一个 skb 都要调用 `kmalloc()`，提高性能

**API**：
```c
// 分配内存
void sk_mem_charge(struct sock *sk, int size)  // size 从 sk_forward_alloc 扣除

// 释放内存
void sk_mem_uncharge(struct sock *sk, int size)  // size 加回 sk_forward_alloc
```

**典型值**：几百 KB 到几 MB

---

#### w - 写队列排队内存

**需要进一步调研**：在 struct sock 中未找到明确对应字段

**推测**：可能是 `sk_write_queue` 相关的统计，或是 `tcp_mem` 的一部分

**建议**：在源码中搜索 ss 命令的实现（`iproute2` 包），确认该字段来源

---

#### o - sk_omem_alloc

**类型**：`atomic_t`

**含义**：Options Memory Allocation（选项内存分配）

**用途**：存储 TCP 选项相关的内存

**典型值**：很小（几十到几百 bytes）

---

#### bl - sk_ack_backlog

**定义**：`struct sock` 中的字段

**类型**：`u32`

**含义**：**ACK Backlog 队列长度**

**应用场景**：**仅用于监听 socket（Listen Socket）**

**详细说明**：
- 表示已完成三次握手（ESTABLISHED），但**尚未被 accept()** 的连接数量
- 对应 TCP 握手队列：
  ```
  SYN Queue ← 半连接队列
  ↓ syn+ack
  ESTABLISHED
  ↓
  Accept Queue ← bl 计数（由 accept queue 大小限制）
  ↓ accept()
  Application
  ```

**重要参数**：
```bash
net.core.somaxconn = 4096  # accept queue 最大长度
```

**检查方法**：
```bash
ss -ltm | grep -A1 backlog
```

**对于已连接 socket**：该值始终为 0（因为不是监听 socket）

---

#### d - sk_drops

**定义**：`struct sock` 中的字段

**类型**：`unsigned long`

**含义**：**Dropped Packets Count（丢包计数）**

**发生位置**：数据包从网络层传递到传输层时

**原因**：
1. **接收队列满**（`r >= rb`）
```c
// net/ipv4/tcp_input.c:tcp_data_queue()
if (atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf) {
    sk->sk_drops++;  // 增加丢包计数
    goto drop;       // 丢弃数据包
}
```

2. **内存分配失败**（罕见）

3. **socket locked**（罕见）

**影响**：
- **d > 0**：**确定有数据丢失**！
- 需要立即增大接收缓冲区：
  ```bash
  sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"
  ```

**与其他指标的关系**：
- 与 `TCPBacklogDrop` 不同：
  - `sk_drops`：在 socket 层丢弃
  - `TCPBacklogDrop`：在网络层（TCP 协议栈）丢弃

---

### 2.3 Recv-Q 与 r 的关系深度分析

**	Recv-Q** 的定义：
```bash
$ ss -n
State    Recv-Q Send-Q    Local:Port  Peer:Port
ESTAB    0      0         10.0.0.1:22 10.0.0.2:12345
```

**内核代码**：`net/ipv4/tcp_diag.c:tcp_diag_get_info()`

**Recv-Q 含义**：**接收队列中未被应用程序读取的字节数**

**vs r（sk_rmem_alloc）**：
- **r**：已分配给该 socket 的内存（包括已读取和未读取的）
- **Recv-Q：只包含未读取的**

**数值关系**：
r >= Recv-Q

**数据流**：
```
网络层 → tcp_rcv_established() → tcp_data_queue()
    ↓
(skb 放入 sk_receive_queue)
atomic_add(skb->truesize, &sk->sk_rmem_alloc)  // r 增加
    ↓
(等待应用程序读取)
    ↓
tcp_recvmsg()
    ↓
__skb_unlink(skb, &sk->sk_receive_queue)
atomic_sub(skb->truesize, &sk->sk_rmem_alloc)  // r 减少
(skb 复制到用户空间)
    ↓
(应用程序)
```

**压力分析**：
- **Recv-Q 很大**：应用程序读取慢
  ```bash
  # 检查应用状态
  pidstat -p <pid> -r 1  # 查看内存使用
  strace -p <pid> -T    # 查看系统调用延迟
  ```

- **r 接近 rb**：接收缓冲区配置不足
  ```bash
  # 增大接收缓冲区
  sudo sysctl -w net.ipv4.tcp_rmem="4096 131072 16777216"
  ```

- **sk_drops > 0**：必定有数据丢失，优先处理

---

### 2.4 Send-Q 与 t 的关系深度分析

**	Send-Q ** 的定义：
```bash
$ ss -n
State    Recv-Q Send-Q    Local:Port  Peer:Port
ESTAB    0      16384      10.0.0.1:22 10.0.0.2:12345
```

** Send-Q 含义**：** **应用程序已发送但内核 TCP 未读取的字节数**

**** 位置**：用户空间 → 内核空间的边界**

** vs t（sk_wmem_alloc） **：
- ** t **：内核发送队列中已分配内存（待发送 + 已发送未确认）
- ** Send-Q **：用户空间发送缓冲区到内核的排队

** 数值关系 **：无直接关系（t 包含 Send-Q，还包含已发送未确认）

** 数据流 **：
```
应用程序
    ↓
send()/write()  数据放入 socket 缓冲区
    ↓
tcp_sendmsg()  TCP 从 socket 缓冲区读取数据
    ↓ (数据包构建)
tcp_transmit_skb()
sk_set_owner_w(skb, sk)  // t 增加
    ↓
(数据进入 Qdisc/NIC)
    ↓
ACK 返回
tcp_clean_rtx_queue()  // t 减少 (已确认的数据包)
```

** Send-Q 很大的原因 **：
1. ** 应用程序写入过快 **，超过 TCP 处理能力
2. ** 内核 TCP 处理慢 **（罕见，通常发生在 CWND 很小、网络很慢时）

** 排查方法 **：
```bash
# 查看 Send-Q
ss -tm  # 查看 Send-Q 值

# 检查 CWND
tcp_connection_analyzer.py --show | grep cwnd

# 如果 CWND 很小（< 10），说明网络或拥塞控制限制
```

---

## 3. 数据包收发 Pipeline 完整分析

### 3.1 接收路径（Receive Path）

```
NIC 收到数据包
    ↓
硬件中断 → NAPI/softirq
    ↓
napi_poll() → netif_receive_skb()  # 网络层入口
    ↓
ip_rcv()  # IP 层处理
    ↓
tcp_v4_rcv()  # TCP 层入口
    ↓
tcp_v4_do_rcv()
    ↓
tcp_rcv_established()  # 已连接状态处理
    ↓
extensive TCP checks (校验和、序列号、窗口检查)
    ↓
tcp_data_queue()  # 数据包排队
    ↓
atomic_add(skb->truesize, &sk->sk_rmem_alloc)  // r 增加
    ↓
__skb_queue_tail(&sk->sk_receive_queue, skb)  // 放入接收队列
    ↓
socket 层
    ↓
tcp_recvmsg()  # 应用层读取
    ↓
__skb_unlink(skb, &sk->sk_receive_queue)  // 从队列移除
    ↓
atomic_sub(skb->truesize, &sk->sk_rmem_alloc)  // r 减少
    ↓
copy_to_user()  # 复制到用户空间
    ↓
应用程序缓冲区
```

**关键压力点分析**：

**压力点 1：sk_drops（socket 层丢包）**
- **位置**：`tcp_data_queue()` 函数
- **条件**：
  ```c
  if (atomic_read(&sk->sk_rmem_alloc) >= sk->sk_rcvbuf) {
      sk->sk_drops++;
      goto drop;
  }
  ```
- **本质**：接收缓冲区不足（r >= rb）
- **解决方法**：增大接收缓冲区

**压力点 2：TCPBacklogDrop（协议栈丢包）**
- **位置**：`tcp_v4_rcv()` 之前的网络层
- **条件**：半连接队列（SYN Queue）或全连接队列（Accept Queue）满
- **查看方法**：
  ```bash
  netstat -s | grep TCPBacklogDrop
  ```

**压力点 3：NIC 丢包**
- **位置**：网卡层、Ring Buffer
- **查看方法**：
  ```bash
  ethtool -S eth0 | grep -E "drop|miss|error|fault"
  ```

**压力点 4：应用读取慢**
- **现象**：Recv-Q 堆积、r 堆积
- **查看方法**：
  ```bash
  ss -tm  # 查看 Recv-Q
  ps aux | grep <pid>  # 查看进程状态
  ```

### 3.2 发送路径（Send Path）

```
应用程序 send()/write()
    ↓
socket 层（write 系统调用）
    ↓
tcp_sendmsg()  # TCP 发送入口
    ↓
数据放入 sk_send_queue
    ↓
tcp_push_one/tcp_push_pending_frames
    ↓
tcp_write_xmit()  # 构建数据包
    ↓
tcp_transmit_skb()  # 发送 skb
    ↓
skb_set_owner_w(skb, sk)  // t 增加 (sk_wmem_alloc++ )
    ↓
ip_queue_xmit()  # 网络层
    ↓
邻居子系统
    ↓
Qdisc（流量控制）sch_fq / sch_htb
    ↓ (pacing_rate 在此生效)
NIC 发送 Ring Buffer
    ↓
网卡硬件队列
    ↓
网络物理链路
    ↓
对端接收
    ↓
对端发送 ACK
    ↓
数据返回
    ↓
tcp_ack()  # 处理 ACK
    ↓
tcp_clean_rtx_queue()  # 清理重传队列
    ↓
tcp_free_skb()  // t 减少 (sk_wmem_alloc--)
    ↓
重传定时器更新
```

**关键压力点分析**：

**压力点 1：Send-Q 堆积**
- **条件**：Send-Q > 0 且持续增长
- **本质**：应用发送快于内核 TCP 处理速度
- **排查**：
  ```bash
  ss -tm  # 查看 Send-Q
  # 通常小于 100KB 正常
  # 大于 1MB 可能有问题
  ```

**压力点 2：窗口限制**
- **CWND 限制**：`unacked ≈ cwnd`
  - 现象：发送停止，等待 ACK
  - 解决：网络优化、减少丢包

- **RWND 限制**：对端通告窗口很小
  - 现象：`snd_wnd` 很小
  - 解决：对端增大接收缓冲区

- **sndbuf 限制**：`t >= tb`
  - 现象：send_rate 下降
  - 解决：增大发送缓冲区 `tcp_wmem`

**压力点 3：内存不足**
- **条件**：分配 skb 失败
- **查看**：
  ```bash
  dmesg | grep -i "tcp.*oom\|tcp.*memory"
  ```

**压力点 4：Qdisc/NIC 队列满**
- **现象**：pacing_rate 受限，发送延迟
- **查看**：
  ```bash
  tc -s qdisc show  # 查看 Qdisc 统计
  ethtool -S eth0   # 查看网卡队列
  ```

---

## 4. 调研总结与需求调整建议

### 4.1 Rate 分析部分的调整

根据调研，ss 输出的三个 rate 的来源和意义如下：

**	delivery_rate**：
- ✅ 是估算的网络有效吞吐量能力
- ✅ 重点分析指标
- ✅ 与 BDP 对比，判断网络利用率

**	pacing_rate **：
- ✅ 是发送节奏控制值
- ✅ 计算公式明确（200% 或 120% × mss × cwnd / srtt）
- ✅ 可用于判断拥塞控制阶段（通过 pacing_ca_ratio 调整）

**	send_rate **：
- ⚠️ 没有找到明确的内核计算代码
- ⚠️ 可能是用户空间估算值
- ℹ️ 建议作为**参考指标 **，不用于核心分析

** 建议调整 **：
1. 重点分析 ** delivery_rate ** 和 ** pacing_rate **
2. send_rate 作为观察值，了解即可
3. 增加** 带宽利用率 **的计算和判断
4. 增加 ** pacing_rate vs delivery_rate ** 的对比分析

---

### 4.2 Buffer 分析部分的调整

** skmem 字段优先级 **：

** 高优先级 **：
- ** d **（sk_drops）—— ** 最重要！**>0 表示确定有丢包
- ** r **（sk_rmem_alloc）—— 接收队列内存
- ** rb **（sk_rcvbuf）—— 接收缓冲区上限
- ** t **（sk_wmem_alloc）—— 发送队列内存
- ** tb **（sk_sndbuf）—— 发送缓冲区上限

** 中优先级 **：
- ** Recv-Q **—— 应用层影响
- ** Send-Q **—— 应用层影响

** 低优先级（暂时可忽略）**：
- f（forward_alloc）—— 内部优化机制
- o（omem_alloc）—— 选项内存，很小
- bl（ack_backlog）—— 仅监听 socket
- w（未知字段，需要进一步调研）

**需要补充调研的字段**：
- w 字段的明确含义和来源

**Buffer 压力分析重点**：
```bash
if sk_drops > 0:
    → 立即告警！socket 层有丢包
    → 建议增大 tcp_rmem

if r >= rb * 0.8:
    → 接收缓冲区压力高
    → 建议增大 tcp_rmem 或加快应用读取

if recv_q > rb * 0.5:
    → 应用读取慢
    → 检查应用性能

if t >= tb * 0.8:
    → 发送缓冲区压力高
    → 建议增大 tcp_wmem

if send_q > tb * 0.5:
    → 应用发送过快
    → 正常现象，除非持续非常高
```

---

### 4.3 数据格式确认

根据调研，tcpsocket 数据文件中的字段可以直接映射到内核数据结构：

```python
# ss -tinopm 输出解析示例

# rtt:78.4/36.2
# → tp->srtt_us = 78.4ms
# → tp->mdev_us = 36.2ms (RTT variance)

# cwnd:10
# → tp->snd_cwnd = 10

# retrans:0/1195
# → tp->retrans_out = 0 (当前重传)
# → total retransmissions = 1195 (历史累计)

# send 148512820bps
# → send_rate (用户空间计算)

# pacing_rate 257809520bps
# → sk->sk_pacing_rate (内核直接存储)

# delivery_rate 3200000000bps
# → 用户空间计算: tp->rate_delivered * MSS * 8 / tp->rate_interval_us

# skmem:(r0,rb87380,t0,tb87040,f0,w0,o0,bl0,d0)
# → r  = sk_rmem_alloc
# → rb = sk_rcvbuf
# → t  = sk_wmem_alloc
# → tb = sk_sndbuf
# → f  = sk_forward_alloc
# → w  = ???
# → o  = sk_omem_alloc
# → bl = sk_ack_backlog
# → d  = sk_drops

# unacked:675
# → tp->packets_out = 675

# rcv_space:14480
# → tp->rcv_space = 14480

# rcv_ssthresh:65535
# → tp->rcvq_space.space = 65535
# → tp->rcvq_space.copied = ... (非公开字段)
```

---

### 4.4 建议补充的调研（下一步）

**需要进一步确认**：
1. ** w 字段的精确含义 **
   - 在 ss 源码中查找（iproute2 包）
   - grep -r "w\>" iproute2/misc/ss.c

2. ** send_rate 的确切计算方式 **
   - 查看 ss 源码中的计算逻辑

3. ** delivery_rate 的采样窗口大小 **
   - 是否可调？
   - tcp_min_rtt 的影响？

4. ** skmem 各字段的时间序列变化 **
   - 采集一些实际数据，观察 r/rb/t/tb 的变化模式
   - 建立正常流量和异常流量的基准

5. ** ss 命令的实现细节 **
   - `getsockopt(TCP_INFO)` 返回的 tcp_info 结构
   - 与 `ss` 输出字段的对应关系

---

## 5. 结论

### 已确认的信息 ✅

1. ** delivery_rate **：基于 RTT 采样，估算网络有效吞吐量
2. ** pacing_rate**：计算公式明确，用于控制发送节奏
3. **skmem 主要字段**：r/t/rb/tb/d 的含义和位置已确认
4. **Recv-Q 与 r 的关系**：r = 接收队列总量，Recv-Q = 未读部分
5. **数据包 pipeline**：收发路径已梳理清晰

### 需要补充的信息 ⚠️

1. **w 字段**：需要查看 ss 源码确认
2. **send_rate**：确认是否是用户空间估算值
3. **实际测试数据**：采集 tcpsocket 数据，验证理论分析

### 调研结果对需求的调整建议

**Rate 分析部分**：
- 重点分析 delivery_rate 和 pacing_rate
- send_rate 作为参考值
- 引入带宽利用率分析
- 对比 pacing_rate vs delivery_rate

**Buffer 分析部分**：
- d（sk_drops）作为最高优先级
- 重点分析 r/rb、Recv-Q
- 重点分析 t/tb、Send-Q
- 其他字段（f/o/bl）作为低优先级

**数据解析部分**：
- 确认 ss 输出到内核字段的映射关系
- 确保数值单位转换正确
- 建立时间序列分析框架

---

## 6. 参考文件列表

### 核心源码文件
- `net/ipv4/tcp_rate.c` - delivery_rate 计算
- `net/ipv4/tcp_input.c` - pacing_rate 计算
- `include/net/sock.h` - skmem 字段定义
- `net/ipv4/tcp_input.c:tcp_data_queue()` - 接收队列处理
- `net/ipv4/tcp_output.c:tcp_transmit_skb()` - 发送处理
- `net/ipv4/tcp.c:tcp_recvmsg()` - 应用层接收

### 系统参数
- `net.ipv4.tcp_pacing_ss_ratio = 200`
- `net.ipv4.tcp_pacing_ca_ratio = 120`
- `net.ipv4.tcp_rmem = "4096 87380 6291456"`
- `net.ipv4.tcp_wmem = "4096 16384 4194304"`
- `net.core.rmem_max = 212992`
- `net.core.wmem_max = 212992`

### 用户空间工具
- `iproute2/misc/ss.c` - ss 命令实现（需要查看）
- `iproute2/include/linux/tcp.h` - TCP_INFO 结构
