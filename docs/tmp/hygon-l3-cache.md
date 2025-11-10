                                                                                                                                                                                                                       
• L3 关键特性                                                                                                                                                                                                          
                                                                                                                                                                                                                       
  - 海光 7 系列沿袭 Zen1：每颗封装含 4 个 die，每个 die 内有 2 个 CCX，每个 CCX 的 4 个物理核心共享 8 MB L3，总计 32 MB/CCD，NUMA 结构呈 8 个节点的对称布局。(blog.51cto.com (https://blog.51cto.com/                  
    u_11529070/9218654?utm_source=openai))                                                                                                                                                                             
  - L3 设计为 16 路组相联的 victim cache，按低位地址交错成 4 份切片（约 2 MB/核）；数据在 L1/L2 溢出后再进入 L3，因此对热点工作集容量变化十分敏感。(en.wikichip.org (https://en.wikichip.org/wiki/amd/                 
    microarchitectures/zen?utm_source=openai))                                                                                                                                                                         
  - 实测延迟：L1≈4 周期，L2≈12 周期，L3 平均 37–40 周期，而落到 DDR4 内存需 284–307 周期；L3 命中率直接决定是否触发数百周期的远程访存。(anandtech.com (https://www.anandtech.com/show/15493/hygon-dhyana-reviewed-     
    chinese-x86-cpus-amd/3?utm_source=openai))                                                                                                                                                                         
                                                                                                                                                                                                                       
  性能影响路径                                                                                                                                                                                                         
                                                                                                                                                                                                                       
  - 同一 CCX 内核心访问本地 L3 切片约 37 周期，最远切片约 43 周期；一旦跨 CCX/跨 die，经 Infinity Fabric 传输会额外增加 60–200 周期，接近一次远程内存访问的开销。(7-cpu.com (https://www.7-cpu.com/cpu/Zen.html?       
    utm_source=openai))                                                                                                                                                                                                
  - NUMA 节点内的 L3 容量有限，当网络报文描述符、环形队列和应用工作集同时占用 LLC 时，容易造成 L3 淘汰、回退到高延迟的内存访问，表现为带宽下降或抖动。此结论由上列延迟差异推断，需结合实际监控验证。(anandtech.com     
    (https://www.anandtech.com/show/15493/hygon-dhyana-reviewed-chinese-x86-cpus-amd/3?utm_source=openai))                                                                                                             
  - 多 socket 部署时，调度若把线程迁移到远端节点，即使仍在同一 NUMA node，也可能跨越不同 CCX，增加 L3 miss 和互连拥塞，对网络 I/O 延迟尤其敏感。该结论基于架构拓扑推断，建议通过 perf 等工具确认。(blog.51cto.com      
    (https://blog.51cto.com/u_11529070/9218654?utm_source=openai))                                                                                                                                                     
                                                                                                                                                                                                                       
  优化思路                                                                                                                                                                                                             
                                                                                                                                                                                                                       
  - 尽量把核心、内存、网卡 IRQ 绑定在同一 NUMA node/CCX，避免跨 CCX 访问；可结合先前脚本与 taskset/numactl 调整，降低 L3 远端命中率。此策略依据上述拓扑与延迟差，需用实际测试确认收益。(blog.51cto.com (https://       
    blog.51cto.com/u_11529070/9218654?utm_source=openai))                                                                                                                                                              
  - 监控 L3 行为：perf stat -e LLC-loads,LLC-load-misses 或 BCC cachetop 可快速判断当前工作负载是否受 L3 限制，再配合配置调优。(en.wikichip.org (https://en.wikichip.org/wiki/amd/microarchitectures/zen?              
    utm_source=openai))                                                                                                                                                                                                
  - 控制工作集：在网络处理链路中采用批处理、减少共享数据结构尺寸或引入 per-core ring/queue，将热点数据留在同一 CCX 的 L2/L3，降低跨切片竞争。(en.wikichip.org (https://en.wikichip.org/wiki/amd/microarchitectures/    
    zen?utm_source=openai))                                                                                                                                                                                            
  - 调优内存子系统：适当提升内存频率、优化内存通道均衡，可缩短必要时的回退延迟，尤其在跨 CCX 情况下对整体带宽有帮补。该建议结合 Infinity Fabric 与内存延迟模型推断，落地前需压测验证。(7-cpu.com (https://www.7-       
    cpu.com/cpu/Zen.html?utm_source=openai)) 