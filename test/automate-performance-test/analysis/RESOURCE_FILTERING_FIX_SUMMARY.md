# 资源监控时间过滤修复总结

## 问题回顾

### 发现的问题

以 `system_network_performance_case_1_tcp_rx_e5620a` 的 TP Single 测试为例：

**Client Timing (UTC)**:
```
Start: 2025-10-22 10:25:57.762
End:   2025-10-22 10:26:00.904
```

**Resource Monitor Records**:
```
Epoch       UTC时间    CPU%    统计时段       说明
1761128757  10:25:57  16.50   55-57秒    ← 修复前包含，主要在测试前
1761128759  10:25:59   0.00   57-59秒    ← 应该包含
1761128761  10:26:01   0.50   59-61秒    ← 应该包含，修复前未包含
```

**修复前的错误结果**:
- 包含记录: epoch=1761128757 (CPU=16.5%), epoch=1761128759 (CPU=0.0%)
- CPU Avg: 8.25%
- CPU Max: 16.5%

**问题**: 16.5% 的高CPU来自进程启动阶段（55-57秒），不代表测试运行期间的资源使用。

## 根本原因

### 1. pidstat 采样语义

pidstat 输出的时间戳是**采样结束时刻**，但统计的 CPU 使用率是**过去 interval 秒（2秒）的平均值**。

```
时间轴:
     55      57      59      61      63
     |-------|-------|-------|-------|
     ← 1 → ← 2 → ← 3 → ← 4 →

记录 epoch=1761128757: 统计 55-57秒的CPU (主要在测试开始前)
记录 epoch=1761128759: 统计 57-59秒的CPU (包含测试开始)
记录 epoch=1761128761: 统计 59-61秒的CPU (包含测试结束)
```

### 2. 错误的过滤逻辑

**修复前**的代码：
```python
filtered = [r for r in records
           if start_epoch <= r["timestamp"] <= end_epoch]
```

这会包含 `timestamp = start_epoch` 的记录，但该记录统计的是 **测试开始前的数据**。

## 解决方案

### 修复的代码

**文件**: `src/parsers/resource_parser.py`

#### 1. 添加 metadata 解析

```python
@staticmethod
def _parse_monitor_metadata(log_path: str) -> Dict:
    """Parse monitor metadata from log header

    Extracts INTERVAL from header line:
        # START_DATETIME: ... INTERVAL: 2s PID: ...
    """
    metadata = {"interval": 2}  # Default

    try:
        with open(log_path, 'r') as f:
            for line in f:
                if "INTERVAL:" in line:
                    match = re.search(r'INTERVAL:\s*(\d+)s', line)
                    if match:
                        metadata["interval"] = int(match.group(1))
    except Exception as e:
        logger.warning(f"Failed to parse metadata: {e}")

    return metadata
```

#### 2. 修复过滤逻辑

```python
# Parse monitor metadata
metadata = ResourceParser._parse_monitor_metadata(log_path)
interval = metadata.get("interval", 2)

# Adjust filtering to account for pidstat sampling semantics
# A record at timestamp T contains stats for [T-interval, T]
# We want records that fully cover the test period [start, end]
# So we filter: start + interval <= T <= end + interval
filtered = [r for r in records
           if start_epoch + interval <= r["timestamp"] <= end_epoch + interval]
```

### 修复逻辑说明

对于测试时段 `[start, end]` 和采样间隔 `interval`：

**包含条件**: `start + interval <= timestamp <= end + interval`

**原因**:
- `timestamp = start + interval` 的记录统计 `[start, start + interval]`，完全在测试期间
- `timestamp = end + interval` 的记录统计 `[end, end + interval]`，包含测试结束时刻
- 排除 `timestamp = start` 的记录，因为它统计 `[start - interval, start]`，主要在测试前

## 时间转换机制

### UTC to Epoch 转换

**Client timing** 文件中的时间是 **UTC 时间**。

**转换代码** (`src/utils.py`):
```python
def datetime_to_epoch(datetime_str: str) -> int:
    """Convert UTC datetime string to Unix timestamp"""
    dt = parse_datetime(datetime_str)  # "2025-10-22 10:25:57.762"
    dt_with_tz = dt.replace(tzinfo=timezone.utc)
    return int(dt_with_tz.timestamp())  # 1761128757
```

**Resource monitor** 日志中的时间戳是 **Unix epoch（秒）**，可以直接对比。

### 时间对照验证

Monitor 文件头部：
```
# START_DATETIME: 2025-10-22 18:25:53.333063770  (CST, UTC+8)
# START_EPOCH: 1761128753
```

验证:
```
CST: 2025-10-22 18:25:53 (北京时间)
UTC: 2025-10-22 10:25:53 (减8小时)
Epoch: 1761128753 ✓ 正确
```

**结论**: UTC 时间字符串可以直接转为 epoch 与 resource monitor 的时间戳对比。

## 修复效果

### Case 1 TP Single

**修复前**:
```
过滤: 1761128757 <= timestamp <= 1761128760
包含: epoch=1761128757 (CPU=16.5%), epoch=1761128759 (CPU=0.0%)
结果: CPU Avg=8.25%, CPU Max=16.5%, Mem Max=147600KB
```

**修复后**:
```
过滤: 1761128759 <= timestamp <= 1761128762 (调整 +2秒)
包含: epoch=1761128759 (CPU=0.0%), epoch=1761128761 (CPU=0.5%)
结果: CPU Avg=0.25%, CPU Max=0.5%, Mem Max=147600KB
```

**改善**:
- CPU Avg: 8.25% → 0.25% (降低 **97.0%**)
- CPU Max: 16.5% → 0.5% (降低 **97.0%**)
- 去除了进程启动阶段的高CPU，更准确反映测试运行期间的资源使用

### Case 1 TP Multi

**验证数据**:
```
Client timing: 10:26:05.498 ~ 10:26:10.676
修复后过滤: 1761128767 <= timestamp <= 1761128772

包含记录:
  epoch=1761128767 (CPU=5.5%, 统计 65-67秒)
  epoch=1761128769 (CPU=2.5%, 统计 67-69秒)
  epoch=1761128771 (CPU=0.0%, 统计 69-71秒)

结果: CPU Avg=2.67%, CPU Max=5.5%
```

**验证**: 完整覆盖测试期间（65.498-70.676秒）✓

## 影响范围

### 所有5个topic都已修复

1. `system_network_performance` (10 cases)
2. `linux_network_stack` (20 cases)
3. `kvm_virt_network` (20 cases)
4. `ovs_monitoring` (19 cases)
5. `vm_network_performance` (20 cases)

### 预期影响

1. **CPU Avg 显著降低**: 去除启动阶段的高CPU
2. **CPU Max 降低**: 去除启动峰值
3. **更准确的资源统计**: 只统计测试运行期间
4. **短时间测试影响最大**: PPS/TP Single (~3秒) 比 PPS/TP Multi (~5秒) 受启动影响更大

## 相关文档

- `TIME_CONVERSION_AND_FIX.md`: 详细的时间转换机制和修复方案
- `TIME_RANGE_FILTERING_ANALYSIS.md`: 原始问题分析
- `CPU_AVG_CALCULATION.md`: CPU 平均值计算方法

## 文件修改

**修改的文件**:
- `src/parsers/resource_parser.py`
  - 添加 `_parse_monitor_metadata()` 方法
  - 修改 `parse()` 方法，调整过滤逻辑

**修改行数**: ~40行（新增 + 修改）

## 验证命令

```bash
# 运行完整分析
python3 analyze_performance.py --config config_iteration001.yaml

# 查看 case_1 的资源报告
grep "system_network_performance_case_1" \
  output_iteration_001/system_network_performance_resources_iteration_001.csv
```

## 总结

1. ✅ **问题根源**: 没有考虑 pidstat 采样语义（时间戳T统计的是 [T-interval, T] 的数据）
2. ✅ **修复方案**: 调整过滤逻辑为 `start + interval <= timestamp <= end + interval`
3. ✅ **修复效果**: CPU 统计显著降低（~97%），更准确反映测试运行期间的资源使用
4. ✅ **时间转换**: UTC 字符串 → epoch 的转换机制正确，可以直接对比
5. ✅ **全面修复**: 所有5个topic的89个test case都已使用修复后的逻辑重新分析

**修复成功！资源监控数据现在准确反映测试运行期间的实际资源使用情况。**
