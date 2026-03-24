# 一线操作手册：VM 间 ICMP 完整收发分段延迟

适用场景：
- 两台 VM 之间 `ping` 延迟高/抖动。
- 需要在宿主机上拿到“virtio 网卡到 virtio 网卡”的完整收发分段。

输出目标：
- 每包一行 CSV 表格。
- 列包含：主路径分段 + vhost 分段 + irq 分段 + `total_us`。

## 0. 前提

- 具备宿主机 `root`/`sudo` 权限。
- 宿主机安装 `python3` 和 `python3-bcc`（或 `python3-bpfcc`）。
- 已拿到本工具包并解压。

检查命令：

```bash
python3 -V
python3 - <<'PY'
import importlib.util
print("bcc:", bool(importlib.util.find_spec("bcc")))
print("bpfcc:", bool(importlib.util.find_spec("bpfcc")))
PY
```

## 1. 识别流量经过的两个 virtio 接口

目标是找出源 VM 和目的 VM 在宿主机上的接口名（通常是 `vnet*`）。

```bash
sudo timeout 10 tcpdump -ni any icmp and host <SRC_VM_IP> and host <DST_VM_IP>
```

观察四条关键事件：
- 请求入：`<src-vnet> P IP <SRC> > <DST>`
- 请求出：`<dst-vnet> Out IP <SRC> > <DST>`
- 回包入：`<dst-vnet> P IP <DST> > <SRC>`
- 回包出：`<src-vnet> Out IP <DST> > <SRC>`

如果看到的是物理口和 vnet 混合，优先再确认是否同宿主机 VM 到 VM；同宿主机应尽量使用两侧 `vnet*`。

## 2. 运行完整分段采样

进入工具目录后执行：

```bash
cd /tmp/vm-icmp-e2e-tools-<VERSION>
sudo ./run_vm_icmp_e2e.sh \
  --src-ip <SRC_VM_IP> --dst-ip <DST_VM_IP> \
  --src-iface <SRC_VNET> --dst-iface <DST_VNET> \
  --packet-table --packet-table-limit 200 \
  --interval 10 --duration 60
```

建议采样时长：
- 快速定位：`--duration 30`
- 抖动问题：`--duration 120` 以上

## 3. 每包表格字段说明

每包一行（CSV）主要列：
- `idx,id,seq`：包序号、ICMP id、ICMP seq
- `req_internal_us`：请求在宿主机内部转发耗时
- `req_vhost_s0/s1/s2/total_us`：请求方向 vhost 三段
- `req_irq_s2/s3/s4/s5/total_ms`：请求方向 irq 注入链
- `external_us`：请求发出到回包到达的中间段
- `rep_irq_*`：回包方向 irq 注入链
- `rep_vhost_*`：回包方向 vhost 三段
- `rep_internal_us`：回包在宿主机内部转发耗时
- `total_us`：本工具主路径总延迟

说明：
- 某些列为空，表示该包在对应子工具里未匹配到可关联事件。
- `total_us` 不等于各子列简单求和（存在重叠与采样口径差异）。

## 4. 导出结果

推荐保留原始终端输出：

```bash
sudo ./run_vm_icmp_e2e.sh ... | tee vm_icmp_e2e_$(date +%Y%m%d_%H%M%S).log
```

提取每包 CSV 行：

```bash
grep -E '^[0-9]+,[0-9]+' vm_icmp_e2e_*.log > per_packet_latency.csv
```

## 5. 常见问题

1. `Error: Neither bcc nor bpfcc module found`
- 安装 bcc：`python3-bcc`

2. `unrecognized arguments`
- 使用包内最新脚本，先跑：`./run_vm_icmp_e2e.sh --help`

3. 只有主路径有数据，vhost/irq 为空
- 检查接口是否真的是 `vnet*`。
- 检查是否为同宿主机 VM<->VM 流量。

4. `rep->src` 长期 `n=0`
- 可能接口方向设置反了，回到第 1 步重新抓包确认。
