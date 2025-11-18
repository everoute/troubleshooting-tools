# 需求文档说明

## IEEE 830 标准

**IEEE 830-1998**: IEEE Recommended Practice for Software Requirements Specifications

这是一个软件需求规格书（SRS）的国际标准，定义了如何编写高质量的需求文档。

### 核心原则

1. **正确性 (Correct)**: 每条需求必须准确描述系统功能
2. **无歧义 (Unambiguous)**: 每条需求只有一种解释
3. **完整性 (Complete)**: 涵盖所有必要的需求
4. **一致性 (Consistent)**: 需求之间无冲突
5. **可验证性 (Verifiable)**: 每条需求可以测试验证
6. **可追溯性 (Traceable)**: 每条需求可以追溯到来源和实现

### 推荐的SRS结构

```
1. Introduction (引言)
   1.1 Purpose
   1.2 Scope
   1.3 Definitions, Acronyms, and Abbreviations
   1.4 References

2. Overall Description (总体描述)
   2.1 Product Perspective
   2.2 Product Functions
   2.3 User Characteristics
   2.4 Constraints
   2.5 Assumptions and Dependencies

3. Specific Requirements (详细需求)
   3.1 External Interfaces
   3.2 Functions
   3.3 Performance Requirements
   3.4 Design Constraints
   ...
```

**注意**: IEEE 830-1998 在2011年被 **IEEE 29148-2011** 取代，但830的结构仍广泛使用。

---

## 需求编号系统

### FR - Functional Requirement (功能需求)

功能需求描述系统**必须做什么**（系统的行为和功能）。

**编号规则**: `FR-<工具>-<模块>-<序号>`

示例：
- `FR-PCAP-SUM-001`: PCAP工具 - Summary模式 - 第1条功能需求
- `FR-SOCKET-DET-003`: Socket工具 - Detailed模式 - 第3条功能需求

### NFR - Non-Functional Requirement (非功能需求)

非功能需求描述系统**如何做**（系统的质量属性）。

**编号规则**: `NFR-<类别>-<序号>`

示例：
- `NFR-PERF-001`: 性能需求 - 第1条
- `NFR-REL-005`: 可靠性需求 - 第5条

**非功能需求类别**:
- **PERF**: Performance (性能)
- **REL**: Reliability (可靠性)
- **USA**: Usability (可用性)
- **MAIN**: Maintainability (可维护性)
- **PORT**: Portability (可移植性)

### MUST / SHOULD / MAY

基于 **RFC 2119** 的关键词约定：

| 关键词 | 含义 | 强制性 |
|--------|------|--------|
| **MUST / SHALL** | 必须实现，强制性需求 | ✓✓✓ |
| **SHOULD** | 应该实现，强烈推荐 | ✓✓ |
| **MAY** | 可以实现，可选 | ✓ |
| **MUST NOT** | 禁止 | - |

---

## 需求追溯矩阵 (RTM)

需求追溯矩阵用于跟踪需求从定义到实现、测试的全过程：

| 需求ID | 需求描述 | 优先级 | 设计文档 | 实现代码 | 测试用例 | 状态 |
|--------|---------|--------|----------|----------|----------|------|
| FR-PCAP-SUM-001 | 解析pcap文件 | P0 | design.md#3.1 | parser.py:45 | test_parser.py:12 | ✓ |
| FR-PCAP-SUM-002 | L2/L3/L4统计 | P0 | design.md#3.2 | stats.py:89 | test_stats.py:23 | ⏳ |

---

## 需求优先级

| 级别 | 标记 | 说明 | 实施阶段 |
|------|------|------|----------|
| **P0** | 高 | 核心功能，必须实现 | MVP / 第一阶段 |
| **P1** | 中 | 重要功能，强烈建议 | 第二阶段 |
| **P2** | 低 | 增强功能，资源允许时 | 第三阶段 |

---

## 需求变更管理

### 变更流程

1. **提出变更**: 创建变更请求（CR - Change Request）
2. **影响分析**: 评估对现有需求、设计、代码的影响
3. **评审批准**: 团队评审变更必要性
4. **更新文档**: 修改需求文档，记录变更历史
5. **追溯更新**: 更新RTM，追溯到设计和测试

### 变更记录

每个变更应记录：
- 变更日期
- 变更原因
- 影响范围
- 变更内容
- 审批人

---

## 最佳实践

### 编写功能需求

**好的示例**:
```
FR-PCAP-SUM-001: 工具必须能够解析标准libpcap格式的PCAP文件
验证方法: 使用标准PCAP测试文件，验证解析成功且无错误
```

**不好的示例**:
```
工具应该能处理文件
(问题: 不明确、不可验证、无编号)
```

### 编写非功能需求

**好的示例**:
```
NFR-PERF-001: PCAP工具必须能在10分钟内处理10GB的PCAP文件
测试条件: Intel Xeon E5-2680 v4, 16GB RAM, SSD
验证方法: 使用10GB标准测试文件，测量处理时间
```

**不好的示例**:
```
工具应该很快
(问题: 无法量化、无法验证)
```

---

## 参考资料

- **IEEE 830-1998**: IEEE Recommended Practice for Software Requirements Specifications
- **IEEE 29148-2011**: Systems and software engineering - Life cycle processes - Requirements engineering
- **RFC 2119**: Key words for use in RFCs to Indicate Requirement Levels
- **ISO/IEC/IEEE 29148**: Requirements Engineering standard

---

## 工具推荐

- **需求管理**: DOORS, Jama Connect, ReqIF
- **追溯管理**: Confluence + Jira
- **文档编写**: Markdown + Git (当前使用)
