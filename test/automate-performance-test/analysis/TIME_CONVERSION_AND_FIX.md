# 时间转换与资源过滤修复方案

## 时间转换机制

### 1. Client Timing 时间格式

Client timing 文件中的时间是 **UTC 时间**：
```
Start: 2025-10-22 10:25:57.762
End:   2025-10-22 10:26:00.904
```

### 2. Resource Monitor 时间格式

Resource monitor 日志中的时间戳是 **Unix epoch（秒）**：
```
# START_DATETIME: 2025-10-22 18:25:53.333063770  START_EPOCH: 1761128753
#      Time   UID       PID
 1761128757     0     57202    # 这是 Unix timestamp
```

### 3. 转换过程

**步骤1**: 将 UTC 时间字符串转换为 epoch

`src/utils.py` line 59-78:
```python
def datetime_to_epoch(datetime_str: str) -> int:
    """Convert datetime string to Unix timestamp

    IMPORTANT: Assumes the input datetime string is in UTC timezone.
    """
    # Parse the datetime string (returns naive datetime object)
    dt = parse_datetime(datetime_str)  # "2025-10-22 10:25:57.762"

    # Treat the naive datetime as UTC
    dt_with_tz = dt.replace(tzinfo=timezone.utc)

    # Convert to Unix timestamp
    return int(dt_with_tz.timestamp())
```

**示例**：
```python
"2025-10-22 10:25:57.762" (UTC)
→ datetime(2025, 10, 22, 10, 25, 57, 762000, tzinfo=UTC)
→ Unix timestamp: 1761128757 (精确到秒)
```

### 4. 时间对照验证

**Resource monitor 文件中**：
```
# START_DATETIME: 2025-10-22 18:25:53.333063770
# START_EPOCH: 1761128753
```

这里 `18:25:53` 是 **CST（中国标准时间，UTC+8）**

验证：
```
CST: 2025-10-22 18:25:53 (北京时间)
UTC: 2025-10-22 10:25:53 (减8小时)
Epoch: 1761128753 ✓ 正确
```

**结论**：转换方式正确，UTC 时间字符串可以直接转为 epoch 与 resource monitor 的时间戳对比。

## 当前问题分析

### Case 1 TP Single 示例

**Client Timing (UTC)**:
```
Start: 10:25:57.762 → epoch 1761128757
End:   10:26:00.904 → epoch 1761128760
```

**Resource Monitor Records**:
```
时间戳      CST时间    UTC时间    CPU%    说明
1761128755  18:25:55  10:25:55  89.50   启动阶段 (统计53-55秒)
1761128757  18:25:57  10:25:57  16.50   ← 当前包含，但统计55-57秒(主要在测试前)
1761128759  18:25:59  10:25:59   0.00   ← 当前包含，统计57-59秒
1761128761  18:26:01  10:26:01   0.50   ← 当前未包含，但统计59-61秒(包含测试)
1761128763  18:26:03  10:26:03   0.00   测试后
```

### pidstat 采样语义

**关键理解**：pidstat 输出的时间戳是**采样结束时刻**，但统计的是**过去 interval 秒的数据**。

```
时间轴（UTC）:
     53      55      57      59      61      63
     |-------|-------|-------|-------|-------|
     ← 1 → ← 2 → ← 3 → ← 4 → ← 5 →

记录1 (epoch=1761128755): 统计 53-55秒 的CPU
记录2 (epoch=1761128757): 统计 55-57秒 的CPU ← 主要在测试前！
记录3 (epoch=1761128759): 统计 57-59秒 的CPU ← 包含测试开始
记录4 (epoch=1761128761): 统计 59-61秒 的CPU ← 包含测试结束
记录5 (epoch=1761128763): 统计 61-63秒 的CPU

测试时间: 57.762 - 60.904秒
应该使用: 记录3 和 记录4
```

### Case 1 TP Multi 验证

按您的推算，第7、8、9条记录对应 TP Multi：

```
第7条: 1761128767  18:26:07  10:26:07  5.50  (统计 65-67秒)
第8条: 1761128769  18:26:09  10:26:09  2.50  (统计 67-69秒)
第9条: 1761128771  18:26:11  10:26:11  0.00  (统计 69-71秒)
```

如果 TP Multi 的时间是 `10:26:05 ~ 10:26:10` (UTC):
- 测试期间: 65-70秒
- 应该包含: 记录7 (统计65-67)、记录8 (统计67-69)、记录9 (统计69-71) ✓

这与您的推算一致！

## 修复方案

### 问题根源

当前过滤逻辑：
```python
filtered = [r for r in records
           if start_epoch <= r["timestamp"] <= end_epoch]
```

这会包含 `timestamp = start_epoch` 的记录，但该记录统计的是 `[start_epoch - interval, start_epoch]` 的数据，主要在测试开始之前。

### 修复逻辑

**方案**：考虑采样间隔，过滤应该包含那些**统计时段与测试时段有交集**的记录。

对于 pidstat 记录：
- 时间戳为 `T` 的记录统计的是 `[T - interval, T]` 的CPU使用率
- 测试时段为 `[start, end]`

记录应该被包含的条件：
```
统计时段 [T - interval, T] 与测试时段 [start, end] 有交集
⟺ T - interval < end AND T > start
⟺ T > start AND T < end + interval
```

但为了避免包含测试开始前的启动数据，我们应该：
```
T >= start + interval AND T <= end + interval
```

这确保：
- `T = start + interval` 的记录统计 `[start, start + interval]`，完全在测试期间
- `T = end + interval` 的记录统计 `[end, end + interval]`，包含测试结束时刻

### 代码修复

**文件**: `src/parsers/resource_parser.py`

**当前代码** (line 44-51):
```python
time_range_stats = {}
if time_ranges:
    for name, (start_epoch, end_epoch) in time_ranges.items():
        filtered = [r for r in records
                   if start_epoch <= r["timestamp"] <= end_epoch]
        if filtered:
            time_range_stats[name] = ResourceParser._calculate_stats(filtered)
```

**修复后**:
```python
time_range_stats = {}
if time_ranges:
    # Get interval from monitor metadata (default 2s)
    interval = metadata.get("interval", 2) if metadata else 2

    for name, (start_epoch, end_epoch) in time_ranges.items():
        # Adjust filtering to account for pidstat sampling semantics
        # A record at timestamp T contains stats for [T-interval, T]
        # We want records that cover the test period [start, end]
        filtered = [r for r in records
                   if start_epoch + interval <= r["timestamp"] <= end_epoch + interval]
        if filtered:
            time_range_stats[name] = ResourceParser._calculate_stats(filtered)
```

但这需要传入 `interval` 参数，需要修改接口。

**更简单的方案**：从日志文件中读取 interval

```python
@staticmethod
def _parse_monitor_metadata(log_path: str) -> Dict:
    """Parse monitor metadata from log header

    Returns:
        Dict with start_epoch, interval, etc.
    """
    metadata = {"interval": 2}  # Default

    try:
        with open(log_path, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    # Parse: # START_DATETIME: ... INTERVAL: 2s PID: ...
                    if "INTERVAL:" in line:
                        match = re.search(r'INTERVAL:\s*(\d+)s', line)
                        if match:
                            metadata["interval"] = int(match.group(1))
                    # Could also parse START_EPOCH, PID if needed
                else:
                    break  # Stop at first data line
    except Exception as e:
        logger.warning(f"Failed to parse monitor metadata: {e}")

    return metadata
```

## 修复效果预测

### Case 1 TP Single

**修复前**:
```
过滤条件: 1761128757 <= timestamp <= 1761128760
包含记录: epoch=1761128757 (CPU=16.5%), epoch=1761128759 (CPU=0.0%)
CPU Avg: 8.25%
CPU Max: 16.5%
```

**修复后**:
```
过滤条件: 1761128757 + 2 <= timestamp <= 1761128760 + 2
即: 1761128759 <= timestamp <= 1761128762
包含记录: epoch=1761128759 (CPU=0.0%), epoch=1761128761 (CPU=0.5%)
CPU Avg: 0.25%  ← 降低了 97%
CPU Max: 0.5%   ← 降低了 97%
```

### Case 1 TP Multi

假设 TP Multi timing 是 `10:26:05.498 ~ 10:26:10.676`:

**修复前**:
```
过滤条件: 1761128765 <= timestamp <= 1761128770
可能包含: epoch=1761128765 (统计63-65秒，测试前), ...
```

**修复后**:
```
过滤条件: 1761128767 <= timestamp <= 1761128772
包含记录: epoch=1761128767, 1761128769, 1761128771
统计时段: 65-67, 67-69, 69-71秒
完整覆盖测试期间 65.498-70.676秒 ✓
```

## 影响评估

### 受影响的测试

所有5个topic的所有test case都受影响，特别是：
1. **短时间测试**（PPS/TP Single，~3秒）：影响最大，启动阶段占比高
2. **长时间测试**（PPS/TP Multi，~5秒）：影响相对较小

### 预期变化

1. **CPU Avg 将显著降低**：去除启动阶段的高CPU
2. **CPU Max 可能降低**：去除启动峰值
3. **更准确反映实际运行状态**：只统计测试运行期间的资源使用

## 总结

1. **时间转换机制**：UTC 字符串 → epoch 的转换是正确的，可以直接与 resource monitor 对比
2. **问题根源**：没有考虑 pidstat 采样语义（时间戳T统计的是过去interval秒的数据）
3. **修复方案**：调整过滤逻辑为 `start + interval <= timestamp <= end + interval`
4. **您的推算正确**：TP Single 应该用记录3、4；TP Multi 应该用记录7、8、9
