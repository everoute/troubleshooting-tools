#!/bin/bash
# 分析所有topics的脚本
# 用法: ./analyze_all_topics.sh [iteration_name]

set -e

# 进入脚本所在目录
cd "$(dirname "$0")"

# 默认使用config.yaml中的iteration，或使用命令行参数
ITERATION="${1:-iteration_001}"

echo "============================================================"
echo "Performance Test Analysis - All Topics"
echo "============================================================"
echo "Iteration: $ITERATION"
echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"
echo ""

# 定义所有topics
TOPICS=(
    "system_network_performance"
    "linux_network_stack"
    "kvm_virt_network"
    "ovs_monitoring"
    "vm_network_performance"
)

# 统计
TOTAL=${#TOPICS[@]}
SUCCESS=0
FAILED=0

# 开始时间
START_TIME=$(date +%s)

echo "将分析以下 $TOTAL 个topics:"
for topic in "${TOPICS[@]}"; do
    echo "  - $topic"
done
echo ""
echo "============================================================"
echo ""

# 分析每个topic
for i in "${!TOPICS[@]}"; do
    topic="${TOPICS[$i]}"
    num=$((i + 1))

    echo "[$num/$TOTAL] 正在分析: $topic"
    echo "------------------------------------------------------------"

    # 运行分析
    if python3 analyze_performance.py \
        --topic "$topic" \
        --iteration "$ITERATION" \
        --report-style both 2>&1 | tail -20; then

        SUCCESS=$((SUCCESS + 1))
        echo "✓ 成功完成: $topic"
    else
        FAILED=$((FAILED + 1))
        echo "✗ 失败: $topic"
    fi

    echo ""
done

# 结束时间
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo "============================================================"
echo "分析完成！"
echo "============================================================"
echo "总计: $TOTAL topics"
echo "成功: $SUCCESS"
echo "失败: $FAILED"
echo "耗时: ${DURATION}秒"
echo ""
echo "报告位置: ./output/"
echo ""
echo "查看结果:"
echo "  ls -la output/"
echo ""
echo "查看特定topic的报告:"
echo "  cat output/system_network_performance_overview_${ITERATION}.md"
echo "============================================================"
