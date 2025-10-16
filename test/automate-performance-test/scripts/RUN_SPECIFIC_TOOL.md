# 运行特定工具测试指南

## 快速开始

### 只运行 system_network_performance 测试

```bash
cd scripts
python3 run_automation.py \
    --config-dir ../config \
    --tools system_network_performance \
    --environments host
```

这会：
- ✅ 自动过滤并生成只包含 `system_network_performance` 的 workflow
- ✅ 只在 `host` 环境执行
- ✅ 包含 **11 test cycles**: 1 baseline + 10 cases
- ✅ 立即执行测试
- 📊 预计执行时间: ~10 分钟

---

## 详细用法

### 参数说明

```bash
python3 run_automation.py [options]
```

#### 必选参数
无（所有参数都有默认值）

#### 可选参数

| 参数 | 说明 | 默认值 | 示例 |
|------|------|--------|------|
| `--config-dir` | 配置文件目录 | `../config` | `--config-dir /path/to/config` |
| `--tools` | 指定要测试的工具（可多个） | 所有工具 | `--tools system_network_performance` |
| `--environments` | 指定测试环境（可多个） | 所有环境 | `--environments host` |
| `--dry-run` | 只生成 workflow 不执行 | false | `--dry-run` |
| `--workflow-output` | workflow 输出文件名 | `generated_workflow.json` | `--workflow-output my_workflow.json` |
| `--log-level` | 日志级别 | `INFO` | `--log-level DEBUG` |

---

## 使用场景

### 场景 1：只测试单个工具（推荐）

```bash
# 只测试 system_network_performance (host 环境)
python3 run_automation.py \
    --tools system_network_performance \
    --environments host
```

**结果**: 11 cycles (1 baseline + 10 cases)

---

### 场景 2：测试多个特定工具

```bash
# 测试两个工具
python3 run_automation.py \
    --tools system_network_performance linux_network_stack \
    --environments host
```

**结果**: 32 cycles (1 baseline + 10 + 21 cases)

---

### 场景 3：只生成 workflow，不立即执行

```bash
# 生成 workflow 文件，检查后再决定是否执行
python3 run_automation.py \
    --tools system_network_performance \
    --environments host \
    --dry-run \
    --workflow-output workflow_system_network.json
```

**后续执行**:
```bash
# 检查 workflow 内容
cat workflow_system_network.json | jq '.metadata'

# 如果确认无误，使用其他方式执行
# (注意：当前 run_automation.py 不支持直接读取 workflow 文件执行)
```

---

### 场景 4：测试所有工具的 host 环境

```bash
# 不指定 --tools，只指定环境
python3 run_automation.py \
    --environments host
```

**结果**: 32 cycles (1 baseline + 31 host cases)

---

### 场景 5：测试所有工具的 vm 环境

```bash
python3 run_automation.py \
    --environments vm
```

**结果**: 69 cycles (1 baseline + 68 vm cases)

---

### 场景 6：运行完整测试（所有工具 + 所有环境）

```bash
# 不指定任何过滤参数
python3 run_automation.py
```

**结果**: 101 cycles (2 baseline + 99 cases)
**预计时间**: ~85 分钟

---

## 可用的工具列表

| 工具 ID | 环境 | Cases 数量 | 说明 |
|---------|------|-----------|------|
| `system_network_performance` | host | 10 | 主机系统网络性能 |
| `vm_network_performance` | vm | 18 | 虚拟机网络性能 |
| `linux_network_stack` | host | 21 | Linux 网络栈监控 |
| `ovs_monitoring` | vm | 18 | OVS 监控 |
| `kvm_virt_network` | vm | 32 | KVM 虚拟化网络 |

---

## 可用的环境列表

| 环境 | 说明 | SSH 配置 |
|------|------|----------|
| `host` | 物理主机环境 | host-server, host-client |
| `vm` | 虚拟机环境 | vm-server, vm-client |

---

## 输出文件

### 自动生成的文件

1. **Workflow 文件** (默认: `generated_workflow.json`)
   - 包含完整的测试执行计划
   - 可以用于检查测试配置

2. **日志文件** (`automation_YYYYMMDD_HHMMSS.log`)
   - 详细的执行日志
   - 包含所有测试步骤和结果

### 远程测试结果

测试结果保存在远程主机的 `$workdir/performance-test-results/` 目录下：

```
$workdir/performance-test-results/
├── baseline/
│   └── host/                          # baseline 测试结果
│       ├── server_results/
│       └── client_results/
└── ebpf/
    └── system_network_performance_case_1_tcp_rx_*/
        └── host/                       # eBPF case 测试结果
            ├── server_results/
            ├── client_results/
            └── ebpf_monitoring/        # eBPF 程序资源监控
```

---

## 验证生成的 Workflow

### 查看 metadata

```bash
cat workflow_system_network.json | jq '.metadata'
```

输出示例:
```json
{
  "generation_time": "2025-10-16T17:50:39.981671",
  "total_test_cycles": 11,
  "environments": ["host"]
}
```

### 查看包含的工具

```bash
cat workflow_system_network.json | jq '[.test_sequence[].ebpf_case.tool_id] | unique'
```

输出示例:
```json
[
  null,                              # baseline
  "system_network_performance"       # 目标工具
]
```

### 查看性能测试配置

```bash
cat workflow_system_network.json | jq '.global_config.performance_specs.throughput'
```

---

## 故障排查

### 问题 1：连接失败

**错误**: `SSH connection failed`

**解决**:
1. 检查 `config/ssh-config.yaml` 中的 SSH 配置
2. 确认远程主机可访问：`ssh user@host`
3. 检查 SSH key 配置

### 问题 2：工具名称错误

**错误**: `Filtered to tools: []` 或 生成 0 test cycles

**解决**:
1. 检查工具名称拼写是否正确
2. 查看可用工具: `cat config/ebpf-tools-config.yaml | grep "id:"`
3. 确保工具 ID 与配置文件中的 `id` 字段匹配

### 问题 3：环境名称错误

**错误**: `Filtered to environments: {}`

**解决**:
1. 检查环境名称：只能是 `host` 或 `vm`
2. 查看配置: `cat config/test-env-config.yaml`

---

## 高级用法

### 调试模式

```bash
# 启用详细日志
python3 run_automation.py \
    --tools system_network_performance \
    --environments host \
    --log-level DEBUG
```

### 检查配置而不执行

```bash
# 先生成 workflow 检查
python3 run_automation.py \
    --tools system_network_performance \
    --environments host \
    --dry-run

# 检查生成的 workflow
cat generated_workflow.json | jq '.test_sequence[].cycle_id'

# 确认无误后实际执行
python3 run_automation.py \
    --tools system_network_performance \
    --environments host
```

---

## 执行时间估算

### 每个 test cycle 包含的测试

| 测试类型 | 配置 | 持续时间 |
|---------|------|---------|
| Throughput | single_stream | 10s |
| Throughput | multi_stream | 10s |
| Latency | tcp_rr | 10s |
| Latency | udp_rr | 10s |
| PPS | single_stream | 5s |
| PPS | multi_stream_4 | 5s |
| **总计** | - | **~50s** |

### 工具执行时间

| 工具 | Cycles | 预计时间 |
|------|--------|---------|
| system_network_performance | 11 | ~10 min |
| linux_network_stack | 22 | ~20 min |
| vm_network_performance | 19 | ~17 min |
| ovs_monitoring | 19 | ~17 min |
| kvm_virt_network | 33 | ~30 min |
| **全部 (host + vm)** | 101 | **~85 min** |

注: 实际时间包含 setup/teardown 开销，可能略长。

---

## 常见命令速查

```bash
# 只测试 system_network_performance
python3 run_automation.py --tools system_network_performance --environments host

# 测试所有 host 工具
python3 run_automation.py --environments host

# 测试所有 vm 工具
python3 run_automation.py --environments vm

# 完整测试（默认）
python3 run_automation.py

# 仅生成 workflow 不执行
python3 run_automation.py --tools system_network_performance --dry-run

# 调试模式
python3 run_automation.py --tools system_network_performance --log-level DEBUG
```

---

## 更新日期
2025-10-16
