# 如何分析所有Topics

## 方法1: 使用Python命令直接分析（推荐）

这是最简单的方法，**不指定 `--topic` 参数**即可分析所有topics：

```bash
cd /Users/echken/workspace/troubleshooting-tools/test/automate-performance-test/analysis

# 分析所有topics（使用config.yaml中的默认iteration）
python3 analyze_performance.py

# 或指定iteration
python3 analyze_performance.py --iteration iteration_001

# 启用详细日志
python3 analyze_performance.py --iteration iteration_001 --verbose
```

### 原理

当**不指定** `--topic` 参数时，程序会自动分析`config.yaml`中定义的所有topics：

```yaml
topics:
  host:
    - system_network_performance
    - linux_network_stack
  vm:
    - kvm_virt_network
    - ovs_monitoring
    - vm_network_performance
```

代码位置: `analyze_performance.py:310-314`
```python
if args.topic:
    topics = [args.topic]
else:
    topics = get_all_topics(iteration_path, config)  # 获取所有topics
```

---

## 方法2: 使用Shell脚本（交互式）

如果您想要更清晰的进度显示和错误处理：

```bash
cd /Users/echken/workspace/troubleshooting-tools/test/automate-performance-test/analysis

# 使用默认iteration（iteration_001）
./analyze_all_topics.sh

# 或指定iteration
./analyze_all_topics.sh iteration_002
```

脚本会：
- 逐个分析每个topic
- 显示进度（1/5, 2/5, ...）
- 统计成功/失败数量
- 显示总耗时

---

## 方法3: 使用快捷启动脚本

```bash
cd /Users/echken/workspace/troubleshooting-tools/test/automate-performance-test/analysis

# 运行交互式菜单，选择"6) all"
./QUICK_START.sh
```

---

## 当前数据中可用的Topics

基于 `results/1021/iteration_001/` 的数据，包含以下5个topics：

| Topic | 类型 | 测试用例数 | 说明 |
|-------|------|-----------|------|
| `system_network_performance` | host | 10 | 系统网络性能测试 |
| `linux_network_stack` | host | ~15 | Linux网络栈跟踪 |
| `kvm_virt_network` | vm | ~20 | KVM虚拟化网络 |
| `ovs_monitoring` | vm | ~10 | OVS监控 |
| `vm_network_performance` | vm | ~15 | VM网络性能 |

---

## 输出结果

分析完成后，所有报告会保存在 `output/` 目录下：

```
output/
├── system_network_performance/
│   ├── system_network_performance_overview_iteration_001.md
│   ├── system_network_performance_summary_iteration_001.csv
│   ├── system_network_performance_summary_iteration_001.md
│   ├── system_network_performance_latency_iteration_001.csv
│   ├── system_network_performance_throughput_iteration_001.csv
│   ├── system_network_performance_pps_iteration_001.csv
│   └── system_network_performance_resources_iteration_001.csv
├── linux_network_stack/
│   └── ...
├── kvm_virt_network/
│   └── ...
├── ovs_monitoring/
│   └── ...
└── vm_network_performance/
    └── ...
```

### 快速查看结果

```bash
# 查看所有生成的文件
ls -lh output/*/*.md

# 查看特定topic的概览
cat output/system_network_performance/system_network_performance_overview_iteration_001.md

# 查看所有overview文件
cat output/*/​*_overview_*.md

# 统计生成的报告数量
find output/ -name "*.csv" | wc -l
find output/ -name "*.md" | wc -l
```

---

## 预期运行时间

根据数据量大小，分析所有topics大约需要：

- **小数据集** (~50个测试用例): 5-10秒
- **中等数据集** (~100个测试用例): 15-30秒
- **大数据集** (~200个测试用例): 30-60秒

实时进度会在控制台显示：
```
Processing topic: system_network_performance
Found 10 tool cases
[1/10] Processing: system_network_performance_case_1_tcp_rx_e5620a
[2/10] Processing: system_network_performance_case_2_tcp_tx_8dc4aa
...
Successfully processed 10/10 tool cases
```

---

## 常见问题

### Q1: 某个topic失败了怎么办？

查看日志文件了解详情：
```bash
tail -50 analysis.log
```

或使用`--verbose`重新运行该topic：
```bash
python3 analyze_performance.py --topic kvm_virt_network --verbose
```

### Q2: 如何只分析特定的几个topics？

手动逐个运行：
```bash
python3 analyze_performance.py --topic system_network_performance
python3 analyze_performance.py --topic linux_network_stack
```

或修改`config.yaml`，注释掉不需要的topics：
```yaml
topics:
  host:
    - system_network_performance
    # - linux_network_stack  # 临时不分析
  vm:
    - kvm_virt_network
    # - ovs_monitoring
    # - vm_network_performance
```

### Q3: 如何指定输出目录？

```bash
python3 analyze_performance.py --output-dir ./results_20251022
```

### Q4: 如何只生成CSV或Markdown格式？

```bash
# 只生成CSV
python3 analyze_performance.py --format csv

# 只生成Markdown
python3 analyze_performance.py --format markdown

# 同时生成两种格式（默认）
python3 analyze_performance.py --format csv,markdown
```

### Q5: 分析时如何跳过baseline对比？

目前版本不支持跳过baseline，如果没有baseline数据，对比列会显示为N/A。

---

## 完整示例

```bash
# 进入分析目录
cd /Users/echken/workspace/troubleshooting-tools/test/automate-performance-test/analysis

# 清理之前的输出（可选）
rm -rf output/*

# 分析所有topics（详细日志）
python3 analyze_performance.py --iteration iteration_001 --verbose 2>&1 | tee full_analysis.log

# 查看结果概览
echo "=== 生成的报告 ==="
find output/ -name "*.md" -o -name "*.csv" | sort

echo ""
echo "=== 快速预览 ==="
for overview in output/*_overview_*.md; do
    echo "====== $(basename $overview) ======"
    head -20 "$overview"
    echo ""
done
```

---

## 批量分析多个iterations

如果您有多个iterations需要分析：

```bash
#!/bin/bash
for iter in iteration_001 iteration_002 iteration_003; do
    echo "分析 $iter ..."
    python3 analyze_performance.py \
        --iteration "$iter" \
        --output-dir "./output_$iter"
done
```

---

## 性能优化建议

1. **使用SSD存储**: 可以显著提升文件读取速度
2. **减少日志级别**: 生产环境使用`INFO`而不是`DEBUG`
3. **并行分析**: 对于独立的iterations，可以并行运行多个分析进程

---

## 相关文档

- `USAGE_GUIDE.md` - 完整使用指南
- `CPU_AVG_CALCULATION.md` - CPU指标计算说明
- `QUICK_START.sh` - 交互式快速启动脚本
- `analyze_all_topics.sh` - 批量分析脚本
