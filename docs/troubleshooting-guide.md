# eBPF 网络故障排查指南

## 1. 常见问题诊断流程

### 1.1 网络延迟问题诊断

**问题现象**: 网络访问反应慢、延迟高

**诊断步骤**:
1. **系统级延迟分析**
   ```bash
   # 整体网络延迟测量
   sudo python3 ebpf-tools/performance/system-network/system_network_latency_details.py \
     --src-ip SOURCE_IP --dst-ip DEST_IP --protocol tcp --direction both
   ```

2. **虚拟机网络延迟分解**
   ```bash
   # 虚拟机网络栈延迟分析
   sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_details.py \
     --vm-interface vnet0 --phy-interface eth0 \
     --src-ip VM_IP --dst-ip TARGET_IP --protocol tcp
   ```

3. **OVS 延迟分析**
   ```bash
   # OVS upcall 延迟监控
   sudo python3 ebpf-tools/ovs/ovs_upcall_latency_summary.py \
     --src-ip SOURCE_IP --dst-ip DEST_IP --protocol tcp
   ```

**延迟分析指标**:
- 正常范围: < 50us (局域网)
- 需要关注: 50-100us
- 异常情况: > 100us

### 1.2 网络丢包问题诊断

**问题现象**: 数据包丢失、连接中断、吞吐量下降

**诊断步骤**:
1. **基本丢包检测**
   ```bash
   # 以太网层丢包监控
   sudo python3 ebpf-tools/linux-network-stack/packet-drop/eth_drop.py \
     --src-ip SOURCE_IP --dst-ip DEST_IP --l4-protocol tcp --verbose
   ```

2. **内核丢包栈分析**
   ```bash
   # 详细内核丢包栈统计
   sudo python3 ebpf-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats_summary_all.py \
     --src-ip SOURCE_IP --dst-ip DEST_IP --interval 5 --duration 60
   ```

3. **OVS 丢包监控**
   ```bash
   # OVS 数据路径丢包监控
   sudo python3 ebpf-tools/ovs/ovs-kernel-module-drop-monitor.py \
     --src-ip SOURCE_IP --dst-ip DEST_IP --protocol tcp
   ```

**常见丢包原因及解决方案**:
- `NO_BUFFER`: 缓冲区不足 → 调整 ring buffer 大小
- `SOCKET_FILTER`: 过滤器拦截 → 检查防火墙规则
- `CHECKSUM_ERROR`: 校验和错误 → 检查网卡卸载配置

### 1.3 虚拟化网络问题诊断

**问题现象**: 虚拟机网络性能下降、中断延迟高

**诊断步骤**:
1. **vhost-net 性能分析**
   ```bash
   # vhost 队列关联分析
   sudo python3 ebpf-tools/kvm-virt-network/vhost-net/vhost_queue_correlation_details.py \
     --device vhost-1 --interval 2

   # vhost eventfd 监控
   sudo python3 ebpf-tools/kvm-virt-network/vhost-net/vhost_eventfd_count.py \
     --interval 5
   ```

2. **virtio-net 驱动分析**
   ```bash
   # virtio-net 轮询效率监控
   sudo python3 ebpf-tools/kvm-virt-network/virtio-net/virtnet_poll_monitor.py

   # virtio-net 中断监控
   sudo python3 ebpf-tools/kvm-virt-network/virtio-net/virtnet_irq_monitor.py
   ```

3. **TUN/TAP 设备分析**
   ```bash
   # TUN 环形缓冲区监控
   sudo python3 ebpf-tools/kvm-virt-network/tun/tun_ring_monitor.py \
     --device tun0
   ```

## 2. 数据分析工作流

**数据收集**:
```bash
# 将输出保存到文件
sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_details.py \
  --vm-interface vnet0 --phy-interface eth0 \
  --src-ip 172.21.153.114 --dst-ip 172.21.153.113 \
  --duration 300 > latency_analysis_$(date +%Y%m%d_%H%M%S).log
```

**数据关联分析**:
1. 将性能数据与系统负载关联
2. 将丢包事件与网络流量关联
3. 将虚拟化指标与客户机性能关联

## 3. 故障排查检查单

### 3.1 网络延迟高检查单

□ **基础检查**
- [ ] 检查系统 CPU 利用率
- [ ] 检查网卡队列状态
- [ ] 检查内存使用情况

□ **网络栈分析**
- [ ] 使用 system_network_latency_details.py 分析各阶段延迟
- [ ] 检查 OVS upcall 延迟
- [ ] 分析 virtio-net 中断处理，vring 信息统计

□ **虚拟化检查**
- [ ] 检查 vhost-net 线程详情，关联 tun 队列 && virtio-net 队列详情
- [ ] 分析 virtio-net 中断合并
- [ ] 检查 TUN/TAP 环形缓冲区

### 3.2 网络丢包检查单

□ **丢包检测**
- [ ] 使用 eth_drop.py 检测丢包详情全量信息
- [ ] 使用 kernel_drop_stack_stats_summary_all.py 分析详细丢包栈, 分层按流量/dev 等聚合的丢包 rootcause 统计
- [ ] 检查 qdisc 队列丢包

□ **丢包原因分析**
- [ ] 缓冲区不足 (NO_BUFFER)
- [ ] 过滤器拦截 (SOCKET_FILTER)
- [ ] 校验和错误 (CHECKSUM_ERROR)
- [ ] 其他原因分析

□ **OVS 相关检查**
- [ ] 检查 OVS 数据路径丢包
- [ ] 分析 megaflow 生命周期
- [ ] 检查 kernel megaflow table 表项状态更新

### 3.3 虚拟化性能检查单

□ **vhost-net 检查**
- [ ] 检查 vhost worker 线程 CPU 亲和性
- [ ] 分析 eventfd 通知频率
- [ ] 检查队列对关联性

□ **virtio-net 检查**
- [ ] 检查 NAPI 轮询效率
- [ ] 分析中断合并效果
- [ ] 检查多队列配置

□ **TUN/TAP 检查**
- [ ] 检查环形缓冲区利用率
- [ ] 分析 GSO/TSO 卸载状态
- [ ] 检查设备队列映射