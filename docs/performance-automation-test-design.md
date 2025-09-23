# 简化版自动化性能测试 Workflow 设计文档

## 1. 项目概述

### 1.1 设计目标
构建一个简化的自动化eBPF网络性能测试框架，专注于：
1. **数据收集**: 收集eBPF工具运行时的性能数据和资源监控数据
2. **基线对比**: 为每个eBPF工具测试提供对应的基线测试（无eBPF程序运行）
3. **远端存储**: 所有测试结果、日志、监控数据均存储在远端测试环境

### 1.2 核心原则
- **仅做数据收集，暂不做数据分析**
- **支持host和vm两种测试环境**
- **复用现有的testcase定义，避免重复配置**
- **独立的代码目录，不与现有测试工具混淆**
- **所有数据存储在远端，本地不保存测试结果**
- **所有Hook在远端执行，结果带时间戳保存**
- **eBPF工具与性能测试完全解耦**：性能测试不依赖具体eBPF工具实现，任何eBPF case都可以配合任意性能测试类型执行

## 2. eBPF与性能测试解耦架构

### 2.1 解耦设计理念
系统采用完全解耦的设计，将eBPF工具执行与性能测试执行分离为两个独立的阶段：

```
[eBPF Case定义] + [性能测试定义] = [组合测试用例]
        ↓                ↓                    ↓
   独立的case配置    独立的测试类型        Hook协调执行
```

### 2.2 以eBPF为核心的测试循环流程
```yaml
# 执行流程以eBPF程序为核心，每个case都是一个完整的测试循环
workflow_execution:
  test_cycle_sequence:
    # 每个测试循环围绕一个eBPF case展开
    - cycle: "eBPF case循环"
      structure: "一个eBPF case + 其关联的所有性能测试"
      flow: |
        1. Case级Init: 启动eBPF程序 + 开始监控
        2. 执行所有关联的性能测试 (throughput/latency/pps)
        3. Case级Post: 停止监控 + 停止eBPF程序
      result: "ebpf/{tool_id}_case_{case_id}_{params}/{test_env}/"

    # 基线测试作为特殊的eBPF case（无eBPF程序）
    - cycle: "基线测试循环"
      structure: "无eBPF程序 + 性能测试"
      flow: |
        1. Case级Init: 准备环境（不启动eBPF程序）
        2. 执行性能测试 (throughput/latency/pps)
        3. Case级Post: 环境清理
      result: "baseline/{test_env}/"

# 关键点：
# 1. 每个测试循环都是围绕eBPF case展开的
# 2. Hook执行时只需要知道case_id，不需要了解eBPF工具的具体细节
# 3. 性能测试在每个case的生命周期内执行
```

### 2.3 以eBPF为核心的架构优势
1. **测试循环完整性**：每个eBPF case都有完整的生命周期管理，包含启动、监控、测试、停止
2. **灵活组合**：任意eBPF case可以与任意性能测试类型组合
3. **易于扩展**：新增eBPF工具只需添加case配置，不影响测试流程架构
4. **复用性强**：同一个测试循环框架可用于所有eBPF工具
5. **监控同步**：Custom Hook与eBPF case生命周期完全同步，确保监控数据完整
6. **维护简单**：修改eBPF工具不影响测试循环逻辑

## 3. 远端存储目录结构设计

### 3.1 远端结果存储位置
```bash
# Host环境 (server: 172.21.152.82, client: 172.21.152.85)
/home/smartx/lcc/performance-test-results/

# VM环境 (server: 172.21.153.114, client: 172.21.153.113)
/root/lcc/performance-test-results/
```

### 3.2 远端目录结构编码
```
{workdir}/performance-test-results/
├── baseline/                                           # 基线测试结果
│   ├── {test_env}/                                    # host 或 vm
│   │   ├── {perf_test_type}/                          # throughput, latency, pps
│   │   │   ├── {conn_type}_{timestamp}/               # single_20241201_143022, multi_4_20241201_143022
│   │   │   │   ├── client_results/
│   │   │   │   │   ├── stream_1.json
│   │   │   │   │   ├── stream_2.json
│   │   │   │   │   └── ...
│   │   │   │   ├── server_results/
│   │   │   │   │   └── server.log
│   │   │   │   ├── monitoring/
│   │   │   │   │   ├── cpu_mem_{timestamp}.log        # CPU和内存监控，带时间戳
│   │   │   │   │   ├── network_stats_{timestamp}.log  # 网络统计，带时间戳
│   │   │   │   │   └── hook_results_{timestamp}.json  # Hook执行结果，带时间戳
│   │   │   │   └── metadata_{timestamp}.json          # 元数据，带时间戳
└── ebpf/                                              # eBPF工具测试结果
    ├── {tool_id}_{case_id}_{test_params_hash}/        # tool_001_case_5_tcp_rx_a1b2c3
    │   ├── {test_env}/                                # host 或 vm
    │   │   ├── {perf_test_type}/                      # throughput, latency, pps
    │   │   │   ├── {conn_type}_{timestamp}/           # single_20241201_143022, multi_4_20241201_143022
    │   │   │   │   ├── client_results/
    │   │   │   │   ├── server_results/
    │   │   │   │   ├── monitoring/
    │   │   │   │   ├── ebpf_monitoring/                    # eBPF工具特定监控
    │   │   │   │   │   ├── tool_cpu_usage_{timestamp}.log  # eBPF工具CPU使用率
    │   │   │   │   │   ├── tool_memory_{timestamp}.log     # eBPF工具内存使用（virt, rss）
    │   │   │   │   │   ├── tool_output_{timestamp}.log     # eBPF工具标准输出
    │   │   │   │   │   ├── tool_error_{timestamp}.log      # eBPF工具错误输出
    │   │   │   │   │   ├── tool_logsize_{timestamp}.log    # eBPF工具日志大小变化
    │   │   │   │   │   └── hook_custom_{timestamp}.json    # 自定义Hook结果
    │   │   │   │   └── metadata_{timestamp}.json           # 元数据，带时间戳
```

### 3.3 目录编码规则
```yaml
# 目录名称编码规则
encoding_rules:
  tool_id: "tool_{3_digit_number}"                     # tool_001, tool_002, ...
  case_id: "case_{testcase_id}"                        # case_5, case_12, ...
  test_params_hash: "{protocol}_{direction}_{hash}"    # tcp_rx_a1b2c3, udp_tx_b2c3d4
  test_env: "host|vm"                                   # 测试环境
  perf_test_type: "throughput|latency|pps"             # 性能测试类型
  conn_type:                                           # 连接类型编码
    single: "single"                                   # 单连接
    multi: "multi_{count}"                             # 多连接，如 multi_4, multi_8
  timestamp: "YYYYMMDD_HHMMSS"                         # 时间戳

# 参数哈希生成
params_hash_generation:
  input: "protocol + direction + other_params"
  algorithm: "md5[:6]"                                 # 取MD5的前6位
  example: "tcp_rx_detailed" -> "a1b2c3"
```

## 3. 四类Spec定义

### 3.1 SSH连接配置 (ssh-config.yaml)
```yaml
# SSH连接配置
ssh_hosts:
  host-server:
    host: "172.21.152.82"
    user: "smartx"
    workdir: "/home/smartx/lcc"

  host-client:
    host: "172.21.152.85"
    user: "smartx"
    workdir: "/home/smartx/lcc"

  vm-server:
    host: "172.21.153.114"
    user: "root"
    workdir: "/root/lcc"

  vm-client:
    host: "172.21.153.113"
    user: "root"
    workdir: "/root/lcc"
```

### 3.2 测试环境配置 (test-env-config.yaml)
```yaml
# 测试环境配置
test_environments:
  host:
    name: "Host Network Environment"
    description: "系统网络性能测试环境"
    server:
      ssh_ref: "host-server"
      test_ip: "10.132.114.11"
      interface: "port-storage"
    client:
      ssh_ref: "host-client"
      test_ip: "10.132.114.12"
      interface: "port-storage"

  vm:
    name: "VM Network Environment"
    description: "虚拟机网络性能测试环境"
    server:
      ssh_ref: "vm-server"
      test_ip: "172.21.153.114"
      interface: "ens4"
    client:
      ssh_ref: "vm-client"
      test_ip: "172.21.153.113"
      interface: "ens4"
```

### 3.3 性能测试规格 (performance-test-spec.yaml)
```yaml
# 性能测试规格配置
performance_tests:
  throughput:
    single_stream:
      server_cmd: "iperf3 -s -p {port} -B {server_ip}"
      client_cmd_tcp: "iperf3 -c {server_ip} -B {client_ip} -p {port} -t {duration} -b {target_bw} -l 65520 -J > {result_file}"
      client_cmd_udp: "iperf3 -c {server_ip} -B {client_ip} -p {port} -t {duration} -b {target_bw} -u -J > {result_file}"
      duration: 30
      target_bw: ["1G", "10G"]
      ports: [5001]

    multi_stream:
      streams: [2, 4, 8]
      base_port: 5001
      duration: 30

  latency:
    server_cmd: "netserver -L {server_ip} -p {port} -D"
    client_cmd_tcp: "netperf -H {server_ip} -p {port} -t TCP_RR -l 20 -- -o min_latency,mean_latency,max_latency,p99_latency,p90_latency > {result_file}"
    client_cmd_udp: "netperf -H {server_ip} -p {port} -t UDP_RR -l 20 -- -o min_latency,mean_latency,max_latency,p99_latency,p90_latency > {result_file}"
    duration: 20
    ports: [12865]

  pps:
    multi_stream_only: true
    server_cmd: "iperf3 -s -p {port} -B {server_ip}"
    client_cmd_tcp: "iperf3 -c {server_ip} -B {client_ip} -p {port} -t {duration} -b {target_bw} -l 64 -J > {result_file}"
    client_cmd_udp: "iperf3 -c {server_ip} -B {client_ip} -p {port} -t {duration} -b {target_bw} -l 64 -u -J > {result_file}"
    sar_cmd: "sar -n DEV 1 {duration} | grep {interface} > {result_file}"
    streams: [4, 8]
    duration: 30
```

### 3.4 eBPF工具配置 (ebpf-tools-config.yaml) - 解耦设计
```yaml
# eBPF工具配置 - 完全基于case引用，与性能测试解耦
# 关键：这里只定义eBPF case和它适用的测试场景，不包含任何性能测试的具体实现
ebpf_tools:
  tool_001:
    id: "system_network_perfomance_metrics"
    name: "System Network Performance Metrics"

    # 引用现有testcase文件中的case
    testcase_source:
      file: "test/workflow/case/performance-test-cases.json"
      case_ids: [1, 2, 3, 4]  # 只需要case_id，执行时从文件读取完整命令

    # 定义这个工具可以配合哪些性能测试
    test_associations:
      applicable_environments: ["host"]  # 可在哪些环境运行
      performance_test_types: ["throughput", "latency", "pps"]  # 可配合哪些性能测试

    # 监控配置 - 独立于性能测试
    resource_monitoring:
      enabled: true
      cpu: true
      memory: true
      memory_types: ["virt", "rss"]
      log_size: true
      cpu_stats: ["avg", "peak"]

  tool_002:
    id: "system_network_latency_details"
    name: "System Network Latency Details"
    testcase_file: "test/workflow/case/performance-test-cases.json"
    case_ids: [5, 6, 7, 8]
    applicable_environments: ["host"]
    performance_test_types: ["throughput", "latency", "pps"]
    resource_monitoring:
      enabled: true
      cpu: true
      memory: true
      memory_types: ["virt", "rss"]
      log_size: true
      cpu_stats: ["avg", "peak"]

  tool_003:
    id: "vm_network_latency_summary"
    name: "VM Network Latency Summary"
    testcase_file: "test/workflow/case/performance-test-cases.json"
    case_ids: [15, 16, 17, 18, 19, 20]
    applicable_environments: ["vm"]
    performance_test_types: ["throughput", "latency", "pps"]
    resource_monitoring:
      enabled: true
      cpu: true
      memory: true
      memory_types: ["virt", "rss"]
      log_size: true
      cpu_stats: ["avg", "peak"]
```

## 4. Workflow生成（以eBPF程序为核心的测试序列）

### 4.1 Workflow总spec生成器
```python
class EBPFCentricWorkflowGenerator:
    def generate_workflow_spec(self, ssh_config, env_config, perf_spec, ebpf_config):
        """
        生成以eBPF程序为核心的完整测试序列
        输出：包含时序信息的完整workflow spec
        """
        workflow_spec = {
            "metadata": {
                "generation_time": datetime.now().isoformat(),
                "total_test_cycles": 0,
                "environments": list(env_config.test_environments.keys())
            },
            "test_sequence": [],  # 按时序排列的测试循环
            "global_config": {
                "ssh_hosts": ssh_config.ssh_hosts,
                "performance_specs": perf_spec.performance_tests
            }
        }

        # 1. 首先生成基线测试循环（特殊的eBPF case）
        for env_name in env_config.test_environments.keys():
            baseline_cycle = self._generate_baseline_test_cycle(env_name, env_config, perf_spec)
            workflow_spec["test_sequence"].append(baseline_cycle)

        # 2. 生成所有eBPF case的测试循环
        for tool_id, tool_config in ebpf_config.ebpf_tools.items():
            for case_id in tool_config.testcase_source.case_ids:
                for env_name in tool_config.test_associations.applicable_environments:
                    ebpf_cycle = self._generate_ebpf_test_cycle(
                        tool_id, case_id, env_name, tool_config, env_config, perf_spec
                    )
                    workflow_spec["test_sequence"].append(ebpf_cycle)

        workflow_spec["metadata"]["total_test_cycles"] = len(workflow_spec["test_sequence"])
        return workflow_spec

    def _generate_baseline_test_cycle(self, env_name, env_config, perf_spec):
        """生成基线测试循环（无eBPF程序的特殊case）"""
        return {
            "cycle_id": f"baseline_{env_name}",
            "cycle_type": "baseline",
            "environment": env_name,
            "ebpf_case": {
                "case_id": "baseline",
                "program": None,  # 基线测试无eBPF程序
                "command": None,
                "duration": None
            },
            "test_cycle": {
                "init_hook": {
                    "tasks": [
                        "prepare_test_environment",
                        "start_performance_servers",
                        "prepare_monitoring_tools"
                        # 注意：基线测试不启动eBPF程序
                    ],
                    "custom_monitoring": False  # 基线测试不启动custom monitoring
                },
                "performance_tests": self._get_performance_tests_for_env(env_name, perf_spec),
                "post_hook": {
                    "tasks": [
                        "collect_baseline_results",
                        "stop_performance_servers",
                        "cleanup_environment"
                    ]
                }
            },
            "expected_duration": self._calculate_cycle_duration(perf_spec),
            "result_path": f"baseline/{env_name}"
        }

    def _generate_ebpf_test_cycle(self, tool_id, case_id, env_name, tool_config, env_config, perf_spec):
        """生成eBPF工具测试循环"""
        # 从testcase文件读取case详情
        case_details = self._load_case_details(tool_config.testcase_source.file, case_id)

        return {
            "cycle_id": f"{tool_id}_case_{case_id}_{env_name}",
            "cycle_type": "ebpf_test",
            "environment": env_name,
            "ebpf_case": {
                "case_id": case_id,
                "tool_id": tool_id,
                "program": case_details["name"],
                "command": case_details["command"],  # 从testcase文件读取的完整命令
                "duration": case_details["duration"]
            },
            "test_cycle": {
                "init_hook": {
                    "tasks": [
                        "prepare_test_environment",
                        "start_performance_servers",
                        f"start_ebpf_case_{case_id}",  # 启动特定的eBPF程序
                        "start_custom_monitoring"  # 启动监控
                    ],
                    "custom_monitoring": True,
                    "ebpf_startup_command": case_details["command"]
                },
                "performance_tests": self._get_applicable_performance_tests(
                    tool_config.test_associations.performance_test_types, perf_spec
                ),
                "post_hook": {
                    "tasks": [
                        "stop_custom_monitoring",  # 停止监控
                        f"stop_ebpf_case_{case_id}",  # 停止eBPF程序
                        f"collect_ebpf_results_{tool_id}_{case_id}",
                        "cleanup_environment"
                    ]
                }
            },
            "monitoring_config": tool_config.resource_monitoring,
            "expected_duration": self._calculate_cycle_duration(perf_spec) + case_details["duration"],
            "result_path": f"ebpf/{tool_id}_case_{case_id}/{env_name}"
        }

    def _get_performance_tests_for_env(self, env_name, perf_spec):
        """获取环境对应的性能测试配置"""
        return [
            {
                "type": "throughput",
                "configs": ["single_stream", "multi_stream"]
            },
            {
                "type": "latency",
                "configs": ["tcp_rr", "udp_rr"]
            },
            {
                "type": "pps",
                "configs": ["multi_stream_4", "multi_stream_8"]
            }
        ]
```

### 4.2 分层Hook设计

Hook系统采用分层设计，根据处理阶段和输入参数决定具体执行的操作。

**分层Hook架构**
```yaml
hook_layers:
  global_level:
    scope: "整个测试会话"
    execution: "一次性"
    purpose: "全局环境准备和清理"

  tool_level:
    scope: "每个eBPF工具的所有case"
    execution: "每个工具开始前/结束后"
    purpose: "工具级别的环境配置"

  case_level:
    scope: "每个具体的eBPF case"
    execution: "每个case开始前/结束后"
    purpose: "case特定的初始化和清理"

  test_level:
    scope: "每项性能测试"
    execution: "每项测试开始前/结束后"
    purpose: "性能测试特定的操作"
```

**Hook参数化执行**
```yaml
hook_execution_model:
  input_parameters:
    - stage: "global|tool|case|test"
    - action: "init|post"
    - context:
        tool_id: "当前工具ID"
        case_id: "当前case ID"
        test_type: "当前测试类型"
        environment: "测试环境"
        ebpf_command: "eBPF命令"

  execution_logic: |
    def execute_hook(stage, action, context):
        if stage == "global" and action == "init":
            # 全局初始化：创建基础目录、检查SSH连接等
        elif stage == "tool" and action == "init":
            # 工具级初始化：工具特定的环境准备
        elif stage == "case" and action == "init":
            # Case级初始化：启动具体eBPF程序、开始监控
        elif stage == "test" and action == "init":
            # 测试级初始化：启动性能测试服务
```

#### A. 分层Init Hook配置
```yaml
layered_init_hooks:
  # 全局级别初始化（整个测试会话开始时执行一次）
  global_init:
    stage: "global"
    execution: "once_per_session"
    targets: ["server", "client"]
    tasks:
      - name: "create_base_directories"
        cmd: "mkdir -p {workdir}/performance-test-results/{baseline,ebpf}"
        output: "{workdir}/performance-test-results/global_init_{timestamp}.log"

      - name: "check_system_requirements"
        cmd: |
          echo "Checking system requirements at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {workdir}/performance-test-results/system_check_{timestamp}.log
          which iperf3 netperf python3 >> {workdir}/performance-test-results/system_check_{timestamp}.log

      - name: "cleanup_previous_processes"
        cmd: |
          pkill -f "iperf3.*-s" || true
          pkill -f "netserver" || true
          echo "Previous processes cleaned at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {workdir}/performance-test-results/cleanup_{timestamp}.log

  # 工具级别初始化（每个eBPF工具开始前执行）
  tool_init:
    stage: "tool"
    execution: "per_tool"
    context_required: ["tool_id", "environment"]
    tasks:
      - name: "create_tool_directories"
        cmd: "mkdir -p {workdir}/performance-test-results/ebpf/{tool_id}"
        output: "{workdir}/performance-test-results/ebpf/{tool_id}/tool_init_{timestamp}.log"

      - name: "tool_specific_setup"
        cmd: |
          echo "Starting tool {tool_id} in environment {environment} at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {workdir}/performance-test-results/ebpf/{tool_id}/tool_start_{timestamp}.log
          # 工具特定的环境配置可以在这里添加

  # Case级别初始化（每个eBPF case开始前执行）
  case_init:
    stage: "case"
    execution: "per_case"
    context_required: ["tool_id", "case_id", "ebpf_command", "environment"]
    tasks:
      - name: "create_case_directories"
        cmd: "mkdir -p {workdir}/performance-test-results/ebpf/{tool_id}_case_{case_id}/{environment}"
        output: "{result_path}/case_init_{timestamp}.log"

      - name: "start_ebpf_program"
        condition: "ebpf_command is not None"  # 基线测试跳过
        cmd: |
          echo "Starting eBPF case {case_id}: {ebpf_command}" > {result_path}/ebpf_start_{timestamp}.log
          cd {workdir} && {ebpf_command} > {result_path}/ebpf_output_{timestamp}.log 2>&1 &
          EBPF_PID=$!
          echo $EBPF_PID > {result_path}/ebpf_pid_{timestamp}.txt
          echo "eBPF program started with PID: $EBPF_PID at $(date '+%Y-%m-%d %H:%M:%S.%N')" >> {result_path}/ebpf_start_{timestamp}.log

      - name: "start_case_monitoring"
        condition: "ebpf_command is not None"
        cmd: |
          EBPF_PID=$(cat {result_path}/ebpf_pid_{timestamp}.txt)
          # 启动case特定的监控
          nohup bash -c 'while kill -0 $EBPF_PID 2>/dev/null; do date "+%Y-%m-%d %H:%M:%S.%N" && top -b -n 1 -p $EBPF_PID | tail -1 | awk "{print $9}"; sleep 1; done' > {result_path}/ebpf_cpu_{timestamp}.log &
          nohup bash -c 'while kill -0 $EBPF_PID 2>/dev/null; do date "+%Y-%m-%d %H:%M:%S.%N" && ps -p $EBPF_PID -o vsz,rss --no-headers; sleep 1; done' > {result_path}/ebpf_memory_{timestamp}.log &
          echo "Case monitoring started for PID: $EBPF_PID" > {result_path}/monitoring_start_{timestamp}.log

  # 测试级别初始化（每项性能测试开始前执行）
  test_init:
    stage: "test"
    execution: "per_performance_test"
    context_required: ["test_type", "test_config"]
    tasks:
      - name: "start_performance_servers"
        cmd: |
          # 根据测试类型启动相应的服务
          if [ "{test_type}" = "throughput" ] || [ "{test_type}" = "pps" ]; then
            nohup iperf3 -s -p 5001 -B {server_ip} > {result_path}/iperf3_server_{test_type}_{timestamp}.log 2>&1 &
          fi
          if [ "{test_type}" = "latency" ]; then
            nohup netserver -L {server_ip} -p 12865 -D > {result_path}/netserver_{test_type}_{timestamp}.log 2>&1 &
          fi
          sleep 2
          echo "Performance servers for {test_type} started at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_path}/perf_servers_{test_type}_{timestamp}.log
```

#### B. 分层Post Hook配置
```yaml
layered_post_hooks:
  # 测试级别清理（每项性能测试结束后执行）
  test_post:
    stage: "test"
    execution: "per_performance_test"
    context_required: ["test_type"]
    tasks:
      - name: "stop_performance_servers"
        cmd: |
          # 根据测试类型停止相应的服务
          if [ "{test_type}" = "throughput" ] || [ "{test_type}" = "pps" ]; then
            pkill -f "iperf3.*-s.*{server_ip}" || true
          fi
          if [ "{test_type}" = "latency" ]; then
            pkill -f "netserver.*{server_ip}" || true
          fi
          echo "Performance servers for {test_type} stopped at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_path}/perf_servers_stop_{test_type}_{timestamp}.log

      - name: "collect_test_results"
        cmd: |
          echo "Test {test_type} completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_path}/test_complete_{test_type}_{timestamp}.log
          # 同步数据到磁盘
          sync

  # Case级别清理（每个eBPF case结束后执行）
  case_post:
    stage: "case"
    execution: "per_case"
    context_required: ["tool_id", "case_id", "environment"]
    tasks:
      - name: "stop_case_monitoring"
        condition: "ebpf_command is not None"
        cmd: |
          # 停止case特定的监控进程
          pkill -f "ebpf_cpu.*{case_id}" || true
          pkill -f "ebpf_memory.*{case_id}" || true
          echo "Case monitoring stopped at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_path}/monitoring_stop_{timestamp}.log

      - name: "stop_ebpf_program"
        condition: "ebpf_command is not None"
        cmd: |
          if [ -f {result_path}/ebpf_pid_{timestamp}.txt ]; then
            EBPF_PID=$(cat {result_path}/ebpf_pid_{timestamp}.txt)
            if kill -0 $EBPF_PID 2>/dev/null; then
              kill $EBPF_PID
              echo "eBPF program (PID: $EBPF_PID) stopped at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_path}/ebpf_stop_{timestamp}.log
            else
              echo "eBPF program already stopped at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_path}/ebpf_stop_{timestamp}.log
            fi
          fi

      - name: "collect_case_data"
        cmd: |
          # 收集本case的所有数据
          echo "Case {case_id} data collection completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_path}/case_complete_{timestamp}.log
          du -sh {result_path}/* > {result_path}/case_data_size_{timestamp}.log
          sync

  # 工具级别清理（每个eBPF工具的所有case结束后执行）
  tool_post:
    stage: "tool"
    execution: "per_tool"
    context_required: ["tool_id", "environment"]
    tasks:
      - name: "collect_tool_summary"
        cmd: |
          echo "Tool {tool_id} testing completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {workdir}/performance-test-results/ebpf/{tool_id}/tool_complete_{timestamp}.log
          find {workdir}/performance-test-results/ebpf/{tool_id}* -name "*.log" | wc -l > {workdir}/performance-test-results/ebpf/{tool_id}/total_files_{timestamp}.txt

      - name: "tool_specific_cleanup"
        cmd: |
          # 工具特定的清理操作
          echo "Tool {tool_id} cleanup completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {workdir}/performance-test-results/ebpf/{tool_id}/tool_cleanup_{timestamp}.log

  # 全局级别清理（整个测试会话结束时执行一次）
  global_post:
    stage: "global"
    execution: "once_per_session"
    targets: ["server", "client"]
    tasks:
      - name: "final_cleanup"
        cmd: |
          # 确保所有测试相关进程都已停止
          pkill -f "iperf3.*-s" || true
          pkill -f "netserver" || true
          pkill -f "python.*ebpf" || true
          echo "All test processes cleaned at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {workdir}/performance-test-results/final_cleanup_{timestamp}.log

      - name: "generate_session_summary"
        cmd: |
          echo "Test session completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {workdir}/performance-test-results/session_summary_{timestamp}.json
          echo "Total result files: $(find {workdir}/performance-test-results -name "*.log" -o -name "*.json" | wc -l)" >> {workdir}/performance-test-results/session_summary_{timestamp}.json
          echo "Total disk usage: $(du -sh {workdir}/performance-test-results | cut -f1)" >> {workdir}/performance-test-results/session_summary_{timestamp}.json
          sync
```

#### C. Custom Hook配置（分层监控）
```yaml
layered_custom_hooks:
  # Case级别的custom monitoring（与case生命周期同步）
  case_level_monitoring:
    stage: "case"
    execution: "per_case"
    lifecycle: "from_case_init_to_case_post"
    trigger_conditions:
      start: "after case_init hook"
      stop: "before case_post hook"
    context_required: ["tool_id", "case_id", "ebpf_pid", "environment"]

    monitoring_tasks:
      ebpf_cpu_monitoring:
        purpose: "监控eBPF程序CPU使用率"
        condition: "ebpf_pid is not None"
        cmd: |
          # 在后台持续监控，直到进程结束或被kill
          nohup bash -c '
            while kill -0 {ebpf_pid} 2>/dev/null; do
              echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "$(top -b -n 1 -p {ebpf_pid} | tail -1 | awk "{print \$9}")"
              sleep 1
            done
          ' > {result_path}/ebpf_cpu_monitor_{timestamp}.log &
          echo $! > {result_path}/cpu_monitor_pid_{timestamp}.txt

      ebpf_memory_monitoring:
        purpose: "监控eBPF程序内存使用（virt, rss）"
        condition: "ebpf_pid is not None"
        cmd: |
          nohup bash -c '
            while kill -0 {ebpf_pid} 2>/dev/null; do
              echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "$(ps -p {ebpf_pid} -o vsz,rss,pmem --no-headers)"
              sleep 1
            done
          ' > {result_path}/ebpf_memory_monitor_{timestamp}.log &
          echo $! > {result_path}/memory_monitor_pid_{timestamp}.txt

      ebpf_log_size_monitoring:
        purpose: "监控eBPF工具日志大小变化"
        condition: "ebpf_pid is not None"
        cmd: |
          LOG_FILE="{result_path}/ebpf_output_{timestamp}.log"
          nohup bash -c '
            while kill -0 {ebpf_pid} 2>/dev/null; do
              SIZE=$(stat -c %s "$LOG_FILE" 2>/dev/null || echo 0)
              echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "$SIZE"
              sleep 1
            done
          ' > {result_path}/ebpf_logsize_monitor_{timestamp}.log &
          echo $! > {result_path}/logsize_monitor_pid_{timestamp}.txt

  # 测试级别的performance monitoring（在每个性能测试期间）
  test_level_monitoring:
    stage: "test"
    execution: "per_performance_test"
    lifecycle: "during_performance_test"
    context_required: ["test_type", "test_duration", "interface"]

    monitoring_tasks:
      network_performance:
        purpose: "监控网络性能指标"
        cmd: |
          # 监控网络接口统计信息
          timeout {test_duration} sar -n DEV 1 | grep {interface} | while read line; do
            echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "$line"
          done > {result_path}/network_perf_monitor_{test_type}_{timestamp}.log &

      system_performance:
        purpose: "监控系统整体性能"
        cmd: |
          # 监控系统CPU和内存
          timeout {test_duration} bash -c '
            while true; do
              echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "CPU:" "$(top -bn1 | grep "Cpu(s)" | awk "{print \$2}")"
              echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "MEM:" "$(free | grep Mem | awk "{print \$3/\$2*100}")"
              sleep 1
            done
          ' > {result_path}/system_perf_monitor_{test_type}_{timestamp}.log &

# Custom Hook停止机制
custom_hook_termination:
  automatic_termination:
    ebpf_monitoring: "当eBPF程序进程结束时自动停止"
    performance_monitoring: "当性能测试完成时通过timeout自动停止"

  manual_termination:
    method: "通过case_post和test_post hook停止相关监控进程"
    commands:
      - "kill $(cat {result_path}/cpu_monitor_pid_{timestamp}.txt) 2>/dev/null || true"
      - "kill $(cat {result_path}/memory_monitor_pid_{timestamp}.txt) 2>/dev/null || true"
      - "kill $(cat {result_path}/logsize_monitor_pid_{timestamp}.txt) 2>/dev/null || true"
```

## 5. 本地项目目录结构（仅代码和配置）

```
test/automate-performance-test/
├── config/
│   ├── ssh-config.yaml                 # SSH连接配置
│   ├── test-env-config.yaml            # 测试环境配置
│   ├── performance-test-spec.yaml      # 性能测试规格
│   └── ebpf-tools-config.yaml          # eBPF工具配置
├── src/
│   ├── core/
│   │   ├── workflow_generator.py       # Workflow生成器
│   │   ├── test_executor.py            # 测试执行引擎（远端执行）
│   │   ├── ssh_manager.py              # SSH连接管理器
│   │   └── remote_path_manager.py      # 远端路径管理器
│   ├── hooks/
│   │   ├── init_hooks.py               # 初始化Hook（远端执行）
│   │   ├── post_hooks.py               # 后处理Hook（远端执行）
│   │   └── custom_hooks.py             # 自定义Hook（远端执行）
│   ├── monitoring/
│   │   ├── remote_cpu_monitor.py       # 远端CPU监控
│   │   ├── remote_memory_monitor.py    # 远端内存监控
│   │   ├── remote_network_monitor.py   # 远端网络监控
│   │   └── remote_ebpf_monitor.py      # 远端eBPF工具监控
│   └── utils/
│       ├── config_loader.py            # 配置加载器
│       ├── remote_command.py           # 远端命令执行器
│       ├── testcase_loader.py          # 现有testcase加载器
│       └── timestamp_manager.py        # 时间戳管理器
├── scripts/
│   ├── run_automation.py               # 主执行脚本
│   ├── generate_workflow.py            # Workflow生成脚本
│   └── fetch_remote_results.py         # 远端结果获取脚本（可选）
└── docs/
    └── workflow_examples/              # Workflow示例
```

**注意**:
- 本地不存储任何测试结果
- 所有测试数据、日志、监控结果都保存在远端workdir
- 如需分析，可通过`fetch_remote_results.py`脚本从远端拉取

## 6. 正确的执行流程（以eBPF程序为核心）

### 6.1 测试循环单元结构
```
每个测试循环单元 = 一个eBPF case + 其关联的所有性能测试
```

### 6.2 完整执行流程
```
1. 配置加载 → 2. Workflow生成（生成完整测试序列）
                        ↓
3. 执行测试循环序列：
   对每个eBPF case（包括基线case）:
   ┌─────────────────────────────────────────┐
   │ a. Init Hook:                          │
   │    - 准备测试环境                       │
   │    - 启动eBPF程序（如果不是基线）        │
   │    - 启动Custom Hook监控                │
   │                ↓                        │
   │ b. 执行性能测试:                        │
   │    - Throughput测试                     │
   │    - Latency测试                        │
   │    - PPS测试                           │
   │                ↓                        │
   │ c. Post Hook:                          │
   │    - 停止Custom Hook监控                │
   │    - 停止eBPF程序                      │
   │    - 收集本轮数据                       │
   │    - 清理环境                          │
   └─────────────────────────────────────────┘
                        ↓
4. 所有测试完成，数据已收集在远端
```

### 6.3 测试循环示例
```yaml
# 生成的Workflow总spec示例
workflow_spec:
  test_sequence:
    # 基线测试（特殊的eBPF case，没有eBPF程序）
    - case_id: "baseline"
      ebpf_program: null
      environment: "host"
      init_hook: "prepare_baseline_test"
      performance_tests:
        - type: "throughput"
          config: "single_stream"
        - type: "latency"
          config: "tcp_rr"
        - type: "pps"
          config: "multi_stream_4"
      post_hook: "cleanup_baseline_test"

    # eBPF case 1
    - case_id: "case_1"
      ebpf_program: "system_network_perfomance_metrics_rx_tcp"
      environment: "host"
      init_hook:
        - "prepare_environment"
        - "start_ebpf_case_1"  # 启动eBPF程序
        - "start_custom_monitoring"  # 开始监控
      performance_tests:
        - type: "throughput"
        - type: "latency"
        - type: "pps"
      post_hook:
        - "stop_custom_monitoring"  # 停止监控
        - "stop_ebpf_program"
        - "collect_case_1_data"
        - "cleanup_environment"

    # eBPF case 2
    - case_id: "case_2"
      # ... 类似结构
```

### 6.4 Hook的正确定义和作用域

**Init Hook**（每个测试循环的初始化）:
- 准备当前测试循环的环境
- **关键：启动当前eBPF case对应的程序**
- 启动Custom Hook监控

**Custom Hook**（监控期间）:
- 在Init Hook最后启动
- 在整个性能测试期间持续运行
- 在Post Hook开始时停止

**Post Hook**（每个测试循环的清理）:
- 停止Custom Hook监控
- 停止eBPF程序
- 收集本轮测试数据
- 清理环境，为下一个循环准备

## 7. 远端监控数据收集详情

### 7.1 eBPF工具监控（远端执行）
```yaml
ebpf_monitoring_details:
  execution_location: "remote"  # 所有监控在远端执行
  base_path: "{workdir}/performance-test-results/ebpf/{tool_id}_{case_id}/ebpf_monitoring"

  cpu_usage:
    command: "top -b -d 1 -p {ebpf_pid} | awk 'NR>7{print strftime(\"%Y-%m-%d %H:%M:%S\"), $9}'"
    output: "{base_path}/tool_cpu_usage_{timestamp}.log"
    format: "timestamp cpu_percent"

  memory_usage:
    command: "ps -p {ebpf_pid} -o pid,vsz,rss,pmem --no-headers | awk '{print strftime(\"%Y-%m-%d %H:%M:%S\"), $0}'"
    output: "{base_path}/tool_memory_{timestamp}.log"
    format: "timestamp pid virt_kb rss_kb mem_percent"
    frequency: 1  # 每秒

  log_size:
    target: "{tool_output_log}"
    command: "stat -c '%Y %s' {log_file} | awk '{print strftime(\"%Y-%m-%d %H:%M:%S\", $1), $2}'"
    output: "{base_path}/tool_logsize_{timestamp}.log"
    format: "timestamp size_bytes"

  tool_output:
    stdout: "{base_path}/tool_output_{timestamp}.log"
    stderr: "{base_path}/tool_error_{timestamp}.log"
    redirect: true
    timestamp_in_filename: true  # 文件名包含时间戳
```

### 7.2 性能测试监控（远端执行）
```yaml
performance_monitoring_details:
  execution_location: "remote"
  base_path: "{workdir}/performance-test-results/{test_type}/monitoring"

  network_stats:
    command: "sar -n DEV 1 {duration} | grep {interface} | awk '{print strftime(\"%Y-%m-%d %H:%M:%S\"), $0}'"
    output: "{base_path}/network_stats_{timestamp}.log"

  system_resources:
    cpu:
      command: "top -b -d 1 -n {duration} | grep -E '^%Cpu' | awk '{print strftime(\"%Y-%m-%d %H:%M:%S\"), $0}'"
      output: "{base_path}/cpu_usage_{timestamp}.log"
    memory:
      command: "free -s 1 -c {duration} | grep Mem | awk '{print strftime(\"%Y-%m-%d %H:%M:%S\"), $0}'"
      output: "{base_path}/memory_usage_{timestamp}.log"
    disk_io:
      command: "iostat -x 1 {duration} | awk '/^[a-z]/{print strftime(\"%Y-%m-%d %H:%M:%S\"), $0}'"
      output: "{base_path}/disk_io_{timestamp}.log"
```

### 7.3 时间戳格式统一
```yaml
timestamp_formats:
  file_naming: "%Y%m%d_%H%M%S"         # 文件名时间戳: 20241201_143022
  log_content: "%Y-%m-%d %H:%M:%S"     # 日志内容时间戳: 2024-12-01 14:30:22
  precise: "%Y-%m-%d %H:%M:%S.%N"      # 精确时间戳（含纳秒）: 2024-12-01 14:30:22.123456789

# 所有Hook和监控输出都包含时间戳，便于后续分析时关联和对齐数据
```

## 8. 关键特性总结

1. **以eBPF程序为核心的测试循环**:
   - 每个测试循环 = 一个eBPF case + 其关联的所有性能测试
   - 基线测试作为特殊的eBPF case（无eBPF程序）
   - 每个测试循环有完整的生命周期：init → 性能测试 → post
   - 围绕eBPF程序组织整个测试流程

2. **分层Hook设计**:
   - **全局级别**: 整个测试会话的一次性初始化和清理
   - **工具级别**: 每个eBPF工具的环境配置
   - **Case级别**: 每个eBPF case的启动、监控和停止
   - **测试级别**: 每项性能测试的服务管理
   - Hook执行根据阶段和输入参数决定具体操作

3. **Custom Hook与case生命周期同步**:
   - 在case init时启动监控
   - 在整个性能测试期间持续运行
   - 在case post时停止监控
   - eBPF程序资源监控（CPU、内存、日志大小）

4. **eBPF与性能测试完全解耦**:
   - 性能测试执行不依赖eBPF工具的具体实现
   - Hook只需要case_id，不需要理解eBPF工具细节
   - 任意eBPF case可以与任意性能测试类型自由组合
   - 新增eBPF工具只需添加case配置，无需修改测试流程

5. **完全远端存储和执行**:
   - 所有测试结果、监控数据、Hook输出都保存在远端workdir
   - 所有Hook和监控命令都在远端执行
   - 本地只保留代码和配置，不存储测试结果

6. **精确时间戳管理**:
   - 所有文件名和日志内容都包含精确时间戳
   - 支持纳秒级精度，便于数据关联和分析
   - 每个层级的Hook输出都有时间戳标识

7. **结构化存储**:
   - 清晰的目录编码，便于识别和查找特定测试结果
   - 支持基线和eBPF测试结果的分离存储
   - 复用现有testcase配置，避免重复定义

## 9. 正确的执行流程总结

```
配置加载 → Workflow生成（测试序列） → 全局初始化

然后对每个eBPF case执行测试循环：
┌─────────────────────────────────────────┐
│ 1. 工具级Init（如果是新工具）             │
│ 2. Case级Init：启动eBPF程序 + 开始监控    │
│ 3. 对每项性能测试：                      │
│    ├─ 测试级Init：启动性能服务           │
│    ├─ 执行性能测试                      │
│    └─ 测试级Post：停止性能服务           │
│ 4. Case级Post：停止监控 + 停止eBPF程序   │
│ 5. 工具级Post（如果工具测试完成）         │
└─────────────────────────────────────────┘

所有测试完成 → 全局清理 → 数据收集完成
```

这个设计完全满足您的需求：
- ✅ 以eBPF程序为核心的测试循环
- ✅ 分层Hook设计，根据阶段执行不同操作
- ✅ Custom Hook与case生命周期同步
- ✅ 所有数据保存在远端workdir
- ✅ Hook远端执行，结果带时间戳
- ✅ 便于后续远程分析或拉取数据