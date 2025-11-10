下面把你的两个问题拆开讲，并给出可量化、可复现实验的办法。

一、你看到的 cache-misses 到底是什么

* perf stat 的通用事件 cache-misses 在 x86 上通常映射为“最后一级缓存（LLC/L3）未命中”的次数，统计的是该被观测对象（这里是 iperf3 进程）在该时间片内发生的 LLC 未命中总数。它既包含读的未命中，也包含写入导致的写分配（write-allocate/RFO）未命中。
* -p  的语义是“跟着这个进程计数（user+sys）”。也就是说：
  * 计到了 iperf3 在线程上下文里执行的用户态代码，以及该线程进入内核执行 recvmsg/tcp_recvmsg/copy_to_user 一类系统调用时的内核态代码；
  * 计不到独立于进程上下文的软中断（NET_RX softirq/ksoftirqd）里干的 RX/GRO/TCP 入栈工作。
* 因为 iperf3 是一个“吞吐拷贝器”，这些 miss 主要来自：
  * TCP 把数据从内核接收队列拷到用户缓冲区时，用户缓冲区对应的 cache line 首次触达引发的写分配（按 64B 一行，理论上大约每 64B 至少 1 次）；
  * 少量来自读 skb 数据（在进程上下文补拷时）以及 iperf3 的控制逻辑。
* 把它换成“每字节未命中”更直观，也避免不同微架构 PMU 定义细节差异的干扰：
  * Intel（16 Gbps ≈ 2.0 GB/s）：
    * cycles/s ≈ 2.30e9 → 约 1.15 cycles/Byte；
    * cache-misses/s ≈ 43e6 → 约 0.0215 miss/Byte ≈ 每 46B 1 次，量级接近“每 64B 一次写分配+少量额外 miss”的直觉。
  * Hygon（12 Gbps ≈ 1.5 GB/s）：
    * cycles/s ≈ 1.16e9 → 约 0.77 cycles/Byte；
    * cache-misses/s ≈ 18.5e6 → 约 0.012 miss/Byte ≈ 每 80B 1 次。
* 结论：这些数刻画的是“用户态收数据（含进程上下文内核代码）”的内存行为；它不是 RX 软中断路径的“每包 miss”，因此不能直接解释“收包瓶颈”。要分析收包瓶颈，应该在承载 NET_RX 的 CPU 上测（见后文量化项 C）。

二、用“流水线”视角重新梳理“为什么 CPU 平均不满却上不去”

先把两个容易混淆的点对齐：

* “CPU cycle 时间 vs 包间隔时间”的对比并不能用于推导是否能“持续满速”。2.5 GHz 的 1 个 cycle ≈ 0.4 ns，而 1 Mpps 的包间隔 ≈ 1 μs（= 2500 cycles）。收包栈靠批处理（NAPI+合并）工作：不是“每来一包就立刻处理”，而是一波一波地处理 ring/GRO 里攒出来的批次。这就天然产生“忙窗（NAPI 在跑）”+“空窗（等待下一次触发）”的锯齿。
* 能否跑满，取决于两个条件同时满足：
  1. 平均预算：λ · C ≤ F。λ 是到达的 PPS，C 是每包消耗的 cycles，F 是该核每秒能提供的 cycles（“有效 GHz×10^9”）。这决定了理论占空比 D≈λC/F 和理想上限 PPS_max=F/C。
  2. 触发/调度：批处理的触发频率足以把“平均预算”兑现（合并门限、NAPI 预算/时间片、调度/唤醒延迟不制造太多“空窗”）。

你现在的现象正是“平均预算”还没花完，但“触发/调度”把工作切成了明显的忙窗+空窗：

* 之前我们在 RX 核上算过：C≈1.2–1.4k cycles/包，F≈2.49e9 cycles/s，λ≈1.0 Mpps → D≈λC/F≈0.5。也就是说，数学上就只需要“忙 0.5 秒、闲 0.5 秒”，吞吐就稳定在 ~1 Mpps（≈11–12 Gbps@1500B），这和你看到的 softirq ≈45–55% 完全一致。
* “剩下那一半 cycles 去哪了？”答案是：它们处于“没有工作可做”的空窗里（要么 ring/GRO 尚未到合并门限、要么 NAPI 上一轮没打满预算已退出、要么用户态线程在等数据/被调度、要么 CPU 进了浅/深 C-state）。空窗不是“丢了算力”，而是“此刻无活可干”的时间占比。

Intel 看起来“90% 忙”的直接原因是两点叠加：

* 它的 C 更低（每包更省 cycles），F（有效 GHz）更高，所以λC/F 更接近 1（忙窗更容易黏在一起）。
* 由于更省/更快，同样的合并门限与 NAPI 预算下，平均每窗能吃更多包、空窗更短（触发/调度侧也更“紧凑”）。

三、把“本质”量化出来（一眼看懂“为什么不满却上不去”）

以下 6 组指标，建议在“RX 核”（软中断落在的 CPU）和“iperf 线程”分别测，合起来就能把根因数字化：

A) 每包周期 C（RX 核）

* perf stat -C <rx_cpu> -e cycles,instructions,cache-misses,ref-cycles -I 1000
* sar -n DEV 1 或 ethtool -S 拿 PPS。
* 算 C = cycles/s ÷ PPS。把 C 带入 PPS_max=F/C（F≈ref-cycles/s），得到“理想 100% 忙时的上限”。你现在的 C≈1.3k → PPS_max≈2.49e9/1.3k≈1.9 Mpps（22–23 Gbps@1500B）。

B) 占空比 D 与“空窗”大小（RX 核）

* 用 perf 同一条输出里的 cycles 与 ref-cycles：D≈cycles/ref-cycles。
* 再看软中断时间：bcc/bpftrace 的 softirqs 工具或 perf timechart，可以看到 NET_RX 在这核里每秒跑了多少毫秒。它与 D 高度一致。
* 若把 rx-usecs/frames、netdev_budget_usecs 拉大，你会看到 D↑、软中断累计时间↑、pps/bps 随之小涨——这就是“压缩空窗”的直接证据。

C) 每包 LLC miss（RX 核）

* 仍然在 RX 核：miss/pkt = cache-misses/s ÷ PPS。你之前在 RX 核观测过 ~15–17 miss/包，这说明大量时间在等内存（每个 L3 miss 100–200+ cycles 的序列化代价，部分被并行度掩蔽）。
* 这项在 Intel 往往更低（DDIO/LLC 组织/预取器差异），从而直接拉低 C。

D) 触发与批量化的“节拍”（反映空窗生成机制）

* 中断与批量：从 ethtool -S 和 /proc/interrupts 抽两列，算 pkts_per_irq 和 irq/s，再推 batch 周期（gap≈1/irq/s）。过小会抖、过大就空窗长。
* NAPI 预算触顶率：打开 tracepoint 采样 10–20 秒：
  * echo 1 > /sys/kernel/debug/tracing/events/napi/napi_poll/enable
  * cat /sys/kernel/debug/tracing/trace_pipe | ts | awk … 统计每次 poll 的 work_done 与 budget_exhausted 比例
  * 看到大量“没打满预算就退出”的 poll，说明触发频率偏低（中断合并过强）；大量“打满预算”说明预算偏紧（应该加大 budget 或 usecs）。
* 这两项加起来就能把“为什么有空窗”变成可量化的时间线。

E) 用户态拷贝“每字节周期/未命中”（iperf 线程）

* 你已经测了：cycles/Byte、miss/Byte。两平台都在 1 cyc/B 左右的量级，说明用户态 copy 不是你当前吞吐差距的主因（反而 Hygon 的 cyc/B 更低）。
* 再配合 off-CPU 时间看“等数据”的比重：
  * perf sched timehist -p $(pidof iperf3) -I 1000 -w
  * bcc/offcputime -p $(pidof iperf3) 10
  * 如果大量时间栈顶在 tcp_recvmsg→schedule，说明用户线程在等内核把数据喂上来（又一次印证“空窗”）。

F) 有效 GHz 与 C-state（RX 核）

* turbostat --Summary --interval 1 观察 Bzy_MHz/Busy% 与 C-state 驻留。
* Hygon 若频率更稳定但 Busy% 低，进一步指向“触发不够紧凑”；Intel 若 Bzy_MHz 高、Busy% 高，说明它把“忙窗”连得更密。

四、用你的现有数再“算一次”直观闭环

* 现状（Hygon）：
  * RX 核：C≈1.3k cycles/包，F≈2.49e9，λ≈1.0 Mpps → D≈0.52，Gbps≈11–12。
  * iperf 线程：≈0.77 cyc/B、≈0.012 miss/B，说明用户态 copy 很轻，瓶颈不在这里。
  * 把 rx-usecs 从 3 稍加、netdev_budget_usecs 提到 24000 后，D↑，λ 随之小涨（你已经观测到了）。
* 对比（Intel）：
  * 由于 C 更低、F（有效 GHz）更高 → D 接近 0.9；看起来“CPU 很忙”，但本质上只是 λC/F 更靠近 1，忙窗之间几乎无空档。

五、回答你的两个具体问题

1. 对“流水线”抽象是否正确？

* 正确的部分：把收包看成分阶段的流水线+缓冲（ring/GRO/SK 队列）是对的；最大可持续 PPS 的上界由 F/C 给出（当触发/调度完全不限制时）。
* 需修正的部分：不需要“每个包在到达间隔内立刻完成处理”。系统依靠批处理与缓冲实现“平均意义上的达标”。因此会自然出现“忙窗+空窗”的锯齿，平均 CPU 使用率等于 λC/F，而不是必须“100%”。只有当 λC/F→1 且触发足够紧凑时，使用率才会贴近 100%。

2. “这些阶段的 CPU 为什么没打满？多出来的 cycles 去哪了？”

* 它们以“空窗时间”的形式存在：中断合并/预算/调度/唤醒/C-state 共同决定 NAPI 何时被触发、跑多久、何时让步。空窗里没有可处理的工作，CPU 自然不会“为了忙而忙”。这不是算力丢失，而是节拍安排。
* 如何证明？按第三节的 D/E/F 采样 1–2 分钟，你会得到：
  * pkts_per_irq 与 irq/s → 反推出每次忙窗之间的平均间隔（空窗长度）；
  * napi_poll 的 budget_exhausted 比例 → 是“预算太紧”还是“触发太疏”；
  * iperf off-CPU → 用户线程是否在“等数据”；
  * turbostat → 空窗内 CPU 是否在浅/深 C-state。

    把这些时间加总，你会发现“忙窗总时长/秒”≈ D×1s，和前面 λC/F 的算式严丝合缝。

六、下一步最小代价的验证与提升路线

* 验证“空窗假说”（强烈推荐先做）：
  * 记录 60 秒：
    * RX 核：perf stat -C <rx_cpu> -e cycles,ref-cycles,cache-misses -I 1000
    * 中断/批量：每秒采 /proc/interrupts 与 ethtool -S（算 pkts/irq、irq/s）
    * NAPI：tracepoint 采集 napi_poll，统计 budget_exhausted 比率与每次 poll 耗时直方图
    * 用户线程：perf sched timehist -p $(pidof iperf3) -I 1000 -w
    * 频率与 C-state：turbostat --interval 1
  * 期望看到：irq 间隔 + 非 budget-exhausted 的 poll 较多 → 空窗显著；iperf 线程 off-CPU 时间与这些空窗对齐。
* 在不改业务的前提下“压缩空窗”的两招：
  * 略增 rx-usecs（如 6–8）与 rx-frames（如 64），并把 netdev_budget_usecs 提到 30000 左右；观察 D、pps、RTT 抖动三者的折中。
  * 若追求更极致，可以小范围验证 busy_poll/busy_read（例如 25–50 μs）：让用户线程主动在 sys_recvmsg 里自旋，牺牲更多 CPU 换更紧凑的节拍（通常只在低延迟场景使用）。
* 从根上降 C（每包周期）才是大幅提升的关键：
  * 栈与驱动版本（≥5.15 的 mlx5e + page_pool + 新 GRO 路径更省）；
  * NUMA 粘性/IRQ 亲和/IOMMU passthrough；
  * 若允许，增大 MTU 至 9000，把 λ 直接降为 ~1/6，D 与 C 不变时 Gbps 会显著上升，这是“瓶颈在每包成本”的最有说服力对照。

一句话总结

* 你看到的“CPU 没打满却上不去”并非矛盾：λC/F 给出了平均占空比 D；当 C 偏大、触发节拍又偏疏时，自然形成“忙窗+空窗”，平均 CPU 看起来不忙，但“忙的时候已满”。Intel 因为 C 更低、F 更高，D→1，忙窗几乎连成一片，于是“看起来 90% 忙”。用四个数字就能把本质钉死：C（cycles/包）、D（cycles/ref-cycles）、miss/包（RX 核）、以及 pkts/irq+irq/s（节拍），再辅以 iperf 的 cycles/Byte 与 off-CPU 时间，答案就完全量化了。
