# Resource Report Format Fix

## 问题描述

之前的实现中，资源报告的时间范围是从第一个test case提取的，然后用于所有case的header。这导致了以下问题：

- 每个case的每个测试类型都有不同的时间范围
- Header中显示的时间范围与实际的资源监控时间不匹配
- 无法准确验证资源统计数据

**示例问题**：
```
# case_1 的 TP Single 实际时间（从 client timing）：
Start: 2025-10-22 10:25:57.762
End: 2025-10-22 10:26:00.904

# 但报告中显示的是 case_10 的时间：
10:34:39.280 ~ 10:34:42.418
```

## 解决方案

修改资源报告格式，在每一行数据中包含该case对应测试类型的时间范围，而不是在header中显示统一的时间范围。

### 修改的文件

`src/report_generator.py` - `generate_resources_report()` 和 `_extract_resources_row()` 方法

### 新的报告格式

**Header结构**：
```csv
Row 1: Tool Case, Protocol, Direction, PPS Single,,,,PPS Multi,,,,TP Single,,,,TP Multi,,,,Full Cycle,,,Log Size,
Row 2: ,,, Time Range, CPU Avg (%), CPU Max (%), Mem Max (KB), Time Range, CPU Avg (%), CPU Max (%), Mem Max (KB), ...
```

**数据行示例**：
```csv
system_network_performance_case_1_tcp_rx_e5620a,tcp,rx,
2025-10-22 10:26:28.240 ~ 2025-10-22 10:26:33.439,0.0,0.0,147836,  # PPS Single
2025-10-22 10:26:38.021 ~ 2025-10-22 10:26:43.187,0.0,0.0,147836,  # PPS Multi
2025-10-22 10:25:57.762 ~ 2025-10-22 10:26:00.904,8.25,16.5,147600, # TP Single
2025-10-22 10:26:05.498 ~ 2025-10-22 10:26:10.676,2.67,5.5,147836,  # TP Multi
...
```

### 关键改进

1. **每行都有独立的时间范围**：每个测试类型（PPS Single/Multi, TP Single/Multi）都显示该case的实际时间范围

2. **时间来源明确**：时间范围直接从client端的performance data中的`start_time`和`end_time`提取

3. **格式统一**：时间格式为 `YYYY-MM-DD HH:MM:SS.fff ~ YYYY-MM-DD HH:MM:SS.fff`

4. **易于验证**：可以直接使用报告中的时间范围去原始资源监控文件中验证数据

## 代码变更

### 1. Header 定义

```python
# Row 1: Main categories (each row will have its own time ranges)
header_row1 = [
    "Tool Case", "Protocol", "Direction",
    "PPS Single", "", "", "",  # Time Range, CPU Avg, CPU Max, Mem Max
    "PPS Multi", "", "", "",
    "TP Single", "", "", "",
    "TP Multi", "", "", "",
    "Full Cycle", "", "",
    "Log Size", ""
]

# Row 2: Sub-column headers
header_row2 = [
    "", "", "",  # Tool Case, Protocol, Direction
    "Time Range", "CPU Avg (%)", "CPU Max (%)", "Mem Max (KB)",  # PPS Single
    "Time Range", "CPU Avg (%)", "CPU Max (%)", "Mem Max (KB)",  # PPS Multi
    "Time Range", "CPU Avg (%)", "CPU Max (%)", "Mem Max (KB)",  # TP Single
    "Time Range", "CPU Avg (%)", "CPU Max (%)", "Mem Max (KB)",  # TP Multi
    "Max RSS (KB)", "Max VSZ (KB)", "Total Samples",
    "Size (Bytes)", "Size (Human)"
]
```

### 2. 数据行提取

```python
def _extract_resources_row(self, result: Dict) -> List:
    # ... 省略 safe_get 和 format_time_range 函数定义 ...

    # Extract time ranges from client performance data
    client = perf.get("client", {})

    # PPS Single time range
    pps_single_start = safe_get(client, "pps", "single", "start_time")
    pps_single_end = safe_get(client, "pps", "single", "end_time")
    pps_single_time = format_time_range(pps_single_start, pps_single_end)

    # ... 同样方式提取其他时间范围 ...

    return [
        result.get("tool_case", "N/A"),
        metadata.get("protocol", "N/A"),
        metadata.get("direction", "N/A"),
        # PPS Single: Time Range + metrics
        pps_single_time,
        safe_get(time_range_stats, "pps_single", "cpu", "avg_percent"),
        safe_get(time_range_stats, "pps_single", "cpu", "max_percent"),
        safe_get(time_range_stats, "pps_single", "memory", "max_rss_kb"),
        # ... 其他测试类型 ...
    ]
```

### 3. 删除不再使用的方法

删除了 `_extract_time_ranges_from_results()` 方法，因为不再需要从第一个case提取统一的时间范围。

## 验证

运行完整分析后验证：

```bash
# 查看 case_1 的资源报告
grep "system_network_performance_case_1_tcp_rx_e5620a" \
  output_iteration_001/system_network_performance_resources_iteration_001.csv

# 输出显示每个测试类型都有正确的时间范围：
# TP Single: 2025-10-22 10:25:57.762 ~ 2025-10-22 10:26:00.904
# 这与 client timing 文件中的时间完全匹配
```

## 生成的报告

成功生成所有5个topic的报告：
- system_network_performance (10 cases)
- linux_network_stack (20 cases)
- kvm_virt_network (20 cases)
- ovs_monitoring (19 cases)
- vm_network_performance (20 cases)

每个topic生成5个文件：
1. `{topic}_latency_iteration_001.csv`
2. `{topic}_throughput_iteration_001.csv`
3. `{topic}_pps_iteration_001.csv`
4. `{topic}_resources_iteration_001.csv` ✨ (新格式)
5. `{topic}_overview_iteration_001.md`

## 总结

通过将时间范围从header移到数据行，现在每个test case的每个测试类型都有准确的时间范围显示，便于验证和分析资源使用情况。
