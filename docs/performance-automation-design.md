# 自动化性能测试 Workflow 设计文档

## 1. 项目概述

### 1.1 目标
构建一个自动化的eBPF网络性能测试框架，用于：
1. 量化eBPF工具部署时的性能开销（吞吐量、延迟、PPS）
2. 分析eBPF程序本身的资源消耗（CPU、内存、存储）
3. 提供基线测试与eBPF工具测试的自动化对比分析

### 1.2 核心原则
- **基线对比**: 每个eBPF工具测试都有对应的基线测试（无eBPF程序运行）
- **结果隔离**: 基线测试和eBPF工具测试结果保存在不同目录结构中
- **通用框架**: 支持任意eBPF工具的集成，不限定特定工具
- **环境分离**: SSH连接配置与测试环境定义分离

## 2. 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                    测试控制中心 (Test Controller)                    │
├─────────────────────────────────────────────────────────────────┤
│  - 测试套件调度器 (Test Suite Scheduler)                           │
│  - 环境配置管理器 (Environment Manager)                            │
│  - 数据收集引擎 (Data Collection Engine)                          │
│  - 结果分析器 (Result Analyzer)                                   │
└─────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┼───────────┐
                    │           │           │
        ┌───────────▼─┐    ┌────▼────┐    ┌─▼──────────┐
        │ System Net  │    │ VM Net  │    │ eBPF Tools │
        │ Test Env    │    │Test Env │    │ Manager    │
        └─────────────┘    └─────────┘    └────────────┘
```

## 3. 核心组件设计

### 3.1 测试配置层

#### A. SSH连接配置 (SSH Config)
```yaml
# 只包含SSH连接信息和工作目录
ssh_hosts:
  system-host-server:
    host: "172.21.152.82"
    user: "smartx"
    workdir: "/home/smartx/lcc"

  system-host-client:
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

#### B. 测试环境定义 (Test Environment Spec)
```yaml
# 测试环境配置，包含网络配置和测试规格
test_environments:
  system-network:
    name: "System Network Performance Testing"
    description: "Host-level network performance testing"
    server:
      ssh_ref: "system-host-server"      # 引用SSH配置
      test_ip: "10.132.114.11"
      interface: "port-storage"
    client:
      ssh_ref: "system-host-client"
      test_ip: "10.132.114.12"
      interface: "port-storage"

  vm-network:
    name: "VM Network Performance Testing"
    description: "Virtual machine network performance testing"
    server:
      ssh_ref: "vm-server"
      test_ip: "172.21.153.114"
      interface: "ens4"
    client:
      ssh_ref: "vm-client"
      test_ip: "172.21.153.113"
      interface: "ens4"
```

#### C. 性能测试规格 (Performance Test Spec)
```yaml
test_types:
  throughput:
    single_stream:
      server_cmd: "iperf3 -s -p {port} -B {server_ip}"
      client_cmd_tcp: "iperf3 -c {server_ip} -B {client_ip} -p {port} -t {duration} -b {target_bw} -l 65520"
      client_cmd_udp: "iperf3 -c {server_ip} -B {client_ip} -p {port} -t {duration} -b {target_bw} -u"
      ports: [5001]
      durations: [30]
      target_bw: ["1G", "10G"]

    multi_stream:
      streams: [2, 4, 8]
      base_port: 5001

  latency:
    server_cmd: "netserver -L {server_ip} -p {port} -D"
    client_cmd_tcp: "netperf -H {server_ip} -p {port} -t TCP_RR -l 20 -- -o min_latency,mean_latency,max_latency,p99_latency,p90_latency"
    client_cmd_udp: "netperf -H {server_ip} -p {port} -t UDP_RR -l 20 -- -o min_latency,mean_latency,max_latency,p99_latency,p90_latency"
    ports: [12865]

  pps:
    server_cmd: "iperf3 -s -p {port} -B {server_ip}"
    client_cmd_tcp: "iperf3 -c {server_ip} -B {client_ip} -p {port} -t {duration} -b {target_bw} -l 64"
    client_cmd_udp: "iperf3 -c {server_ip} -B {client_ip} -p {port} -t {duration} -b {target_bw} -l 64 -u"
    sar_cmd: "sar -n DEV 1 | grep {interface}"
    streams: [4, 8]
```

#### D. eBPF工具测试规格 (eBPF Tools Spec)
```yaml
# 通用eBPF工具规格框架，支持任意工具
ebpf_tools:
  # 每个工具定义一个唯一ID和配置
  tool_001:
    id: "system_network_perfomance_metrics"
    name: "System Network Performance Metrics"
    path: "ebpf-tools/performance/system-network/system_network_perfomance_metrics.py"
    executable: "python3"
    parameters:
      # 工具参数模板，支持变量替换
      template: "--internal-interface {INTERNAL_INTERFACE} --phy-interface {PHY_INTERFACE} --src-ip {SRC_IP} --dst-ip {DST_IP} --direction {direction} --protocol {protocol}"
      required_vars: ["INTERNAL_INTERFACE", "PHY_INTERFACE", "SRC_IP", "DST_IP"]
    applicable_environments: ["system-network"]  # 适用的测试环境
    test_scope:
      test_types: ["throughput", "latency", "pps"]
      protocols: ["tcp", "udp"]
    resource_monitoring:
      enabled: true
      cpu: true
      memory: true
      disk_io: true

  tool_002:
    id: "vm_network_latency_summary"
    name: "VM Network Latency Summary"
    path: "ebpf-tools/performance/vm-network/vm_network_latency_summary.py"
    executable: "python3"
    parameters:
      template: "--vm-interface {VM_INTERFACE} --phy-interface {PHY_INTERFACE} --direction {direction} --src-ip {SRC_IP} --dst-ip {DST_IP} --protocol {protocol}"
      required_vars: ["VM_INTERFACE", "PHY_INTERFACE", "SRC_IP", "DST_IP"]
    applicable_environments: ["vm-network"]
    test_scope:
      test_types: ["throughput", "latency", "pps"]
      protocols: ["tcp", "udp", "icmp"]
    resource_monitoring:
      enabled: true
      cpu: true
      memory: true
      disk_io: true

# 工具发现配置 - 支持自动发现eBPF工具
tool_discovery:
  enabled: true
  scan_directories:
    - "ebpf-tools/performance/system-network"
    - "ebpf-tools/performance/vm-network"
    - "ebpf-tools/linux-network-stack"
    - "ebpf-tools/ovs"
  file_patterns:
    - "*.py"
    - "*.bt"
  auto_generate_config:
    enabled: true
    default_test_types: ["throughput", "latency", "pps"]
    default_protocols: ["tcp", "udp"]
```

### 3.2 目录结构编码设计

#### A. 结果目录结构
```
test/workflow/result/
├── baseline/                                    # 基线测试结果（无eBPF程序）
│   ├── {test_env_id}/                          # 测试环境ID (如system-network, vm-network)
│   │   ├── {test_type}/                        # 测试类型 (throughput, latency, pps)
│   │   │   ├── {protocol}/                     # 协议类型 (tcp, udp, icmp)
│   │   │   │   ├── {test_params_hash}/         # 测试参数哈希 (如streams_4_30s, single_1G_30s)
│   │   │   │   │   ├── run_{timestamp}/        # 单次测试运行，时间戳标识
│   │   │   │   │   │   ├── client_results/     # 客户端测试结果
│   │   │   │   │   │   │   ├── stream_1.json
│   │   │   │   │   │   │   ├── stream_2.json
│   │   │   │   │   │   │   └── ...
│   │   │   │   │   │   ├── server_results/     # 服务端测试结果
│   │   │   │   │   │   │   └── server.log
│   │   │   │   │   │   ├── monitoring/         # 监控数据
│   │   │   │   │   │   │   ├── cpu_mem_server.log
│   │   │   │   │   │   │   ├── cpu_mem_client.log
│   │   │   │   │   │   │   ├── network_server.log
│   │   │   │   │   │   │   ├── network_client.log
│   │   │   │   │   │   │   └── disk_io.log
│   │   │   │   │   │   └── metadata.json       # 测试元数据
│   │   │   │   │   └── summary.json            # 该参数组合的汇总结果
│   │   │   │   └── test_type_summary.json      # 该协议下的测试类型汇总
│   │   │   └── protocol_summary.json           # 该测试类型下的协议汇总
│   │   └── environment_summary.json            # 该环境下的完整汇总
│   └── baseline_summary.json                   # 所有基线测试汇总
└── ebpf/                                       # eBPF工具测试结果
    ├── {ebpf_tool_id}/                         # eBPF工具唯一标识
    │   ├── {test_env_id}/                      # 测试环境ID
    │   │   ├── {test_type}/                    # 测试类型
    │   │   │   ├── {protocol}/                 # 协议类型
    │   │   │   │   ├── {test_params_hash}/     # 测试参数哈希
    │   │   │   │   │   ├── run_{timestamp}/    # 单次测试运行
    │   │   │   │   │   │   ├── client_results/ # 客户端测试结果
    │   │   │   │   │   │   ├── server_results/ # 服务端测试结果
    │   │   │   │   │   │   ├── monitoring/     # 监控数据
    │   │   │   │   │   │   ├── ebpf_output/    # eBPF工具输出
    │   │   │   │   │   │   │   ├── tool_stdout.log
    │   │   │   │   │   │   │   ├── tool_stderr.log
    │   │   │   │   │   │   │   └── tool_data.json
    │   │   │   │   │   │   └── metadata.json
    │   │   │   │   │   └── summary.json
    │   │   │   │   └── test_type_summary.json
    │   │   │   └── protocol_summary.json
    │   │   └── environment_summary.json
    │   └── tool_summary.json                   # 该工具的完整测试汇总
    └── ebpf_comparison.json                    # eBPF工具与基线对比分析
```

#### B. 目录编码规则
```yaml
# 目录名称编码规则
encoding_rules:
  test_params_hash:
    # 根据测试参数生成唯一标识
    throughput_single: "single_{bandwidth}_{duration}s"     # 如: single_1G_30s
    throughput_multi: "streams_{stream_count}_{duration}s"  # 如: streams_4_30s
    latency: "latency_{duration}s"                          # 如: latency_20s
    pps: "pps_streams_{stream_count}_{duration}s"           # 如: pps_streams_8_30s

  timestamp: "YYYYMMDD_HHMMSS"                              # 如: 20241201_143022

  ebpf_tool_id:
    # eBPF工具ID生成规则
    format: "{tool_name}_{version_hash}"                    # 如: system_network_perf_a1b2c3
    fallback: "{tool_filename}_{md5_short}"                 # 备用方案

# 元数据结构
metadata_schema:
  metadata.json:
    test_case:
      environment: "string"
      test_type: "string"
      protocol: "string"
      parameters: "object"
      ebpf_tool: "string|null"
    execution:
      start_time: "ISO8601"
      end_time: "ISO8601"
      duration: "number"
      status: "success|failed|timeout"
    hosts:
      server: "object"
      client: "object"
    commands:
      server_cmd: "string"
      client_cmd: "array"
      ebpf_cmd: "string|null"
```

#### C. 结果标识和匹配
```python
class ResultIdentifier:
    """结果目录标识和匹配工具"""

    def generate_result_path(self, test_case):
        """生成结果存储路径"""
        base_path = "baseline" if not test_case.ebpf_tool else f"ebpf/{test_case.ebpf_tool.id}"

        params_hash = self._generate_params_hash(test_case)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        return f"{base_path}/{test_case.environment}/{test_case.test_type}/{test_case.protocol}/{params_hash}/run_{timestamp}"

    def find_matching_baseline(self, ebpf_result_path):
        """为eBPF测试结果找到对应的基线测试结果"""
        # 解析eBPF测试路径
        parts = ebpf_result_path.split('/')
        env_id = parts[2]
        test_type = parts[3]
        protocol = parts[4]
        params_hash = parts[5]

        # 构建对应的基线测试路径
        baseline_pattern = f"baseline/{env_id}/{test_type}/{protocol}/{params_hash}/run_*"
        return self._find_latest_run(baseline_pattern)

    def compare_test_conditions(self, baseline_metadata, ebpf_metadata):
        """比较测试条件是否一致"""
        return (
            baseline_metadata['test_case']['environment'] == ebpf_metadata['test_case']['environment'] and
            baseline_metadata['test_case']['test_type'] == ebpf_metadata['test_case']['test_type'] and
            baseline_metadata['test_case']['protocol'] == ebpf_metadata['test_case']['protocol'] and
            baseline_metadata['test_case']['parameters'] == ebpf_metadata['test_case']['parameters']
        )
```

### 3.3 Hook系统设计

#### A. Init Hook
```python
def init_hook(test_suite_config):
    """测试套件初始化"""
    # 1. 环境准备
    setup_test_environment()

    # 2. 启动服务端
    start_servers(test_suite_config)

    # 3. 创建结果目录
    create_result_directories()

    # 4. 启动监控任务
    start_monitoring_tasks()

    # 5. 预热测试环境
    warmup_environment()
```

#### B. Post Hook
```python
def post_hook(test_suite_config, results):
    """测试套件后处理"""
    # 1. 停止监控任务
    stop_monitoring_tasks()

    # 2. 收集测试数据
    collect_test_data()

    # 3. 结构化保存结果
    save_structured_results(results)

    # 4. 生成性能报告
    generate_performance_report()

    # 5. 环境清理
    cleanup_environment()
```

#### C. Custom Hook
```python
def custom_monitoring_hook(test_case, monitoring_config):
    """自定义监控Hook"""
    # 1. 进程监控
    monitor_processes(monitoring_config.target_processes)

    # 2. 资源监控
    monitor_resources(
        cpu=True,
        memory=True,
        storage=True,
        frequency=monitoring_config.frequency
    )

    # 3. 日志收集
    collect_logs(monitoring_config.log_targets)
```

### 3.4 测试用例生成器

```python
class TestCaseGenerator:
    def generate_test_matrix(self, env_config, test_spec, ebpf_spec):
        """生成完整测试矩阵"""
        test_cases = []

        for env_name, env_config in environments.items():
            for test_type in test_spec.test_types:
                # 基线测试 (无eBPF)
                baseline_cases = self._generate_baseline_cases(
                    env_name, env_config, test_type
                )
                test_cases.extend(baseline_cases)

                # eBPF工具测试
                for tool in ebpf_spec.get_tools_for_env(env_name):
                    if test_type in tool.test_types:
                        ebpf_cases = self._generate_ebpf_cases(
                            env_name, env_config, test_type, tool
                        )
                        test_cases.extend(ebpf_cases)

        return test_cases

    def _generate_baseline_cases(self, env_name, env_config, test_type):
        """生成基线测试用例"""
        cases = []

        if test_type == "throughput":
            # 单流测试
            for protocol in ["tcp", "udp"]:
                for bandwidth in ["1G", "10G"]:
                    cases.append(TestCase(
                        env=env_name,
                        type="throughput_single",
                        protocol=protocol,
                        bandwidth=bandwidth,
                        ebpf_tool=None
                    ))

            # 多流测试
            for streams in [2, 4, 8]:
                for protocol in ["tcp", "udp"]:
                    cases.append(TestCase(
                        env=env_name,
                        type="throughput_multi",
                        protocol=protocol,
                        streams=streams,
                        ebpf_tool=None
                    ))

        elif test_type == "latency":
            for protocol in ["tcp", "udp"]:
                cases.append(TestCase(
                    env=env_name,
                    type="latency",
                    protocol=protocol,
                    ebpf_tool=None
                ))

        elif test_type == "pps":
            for streams in [4, 8]:
                for protocol in ["tcp", "udp"]:
                    cases.append(TestCase(
                        env=env_name,
                        type="pps",
                        protocol=protocol,
                        streams=streams,
                        ebpf_tool=None
                    ))

        return cases
```

### 3.5 测试执行引擎

```python
class TestExecutor:
    def __init__(self, ssh_manager, monitoring_manager):
        self.ssh_manager = ssh_manager
        self.monitoring_manager = monitoring_manager

    def execute_test_case(self, test_case):
        """执行单个测试用例"""
        result_dir = self._create_result_directory(test_case)

        try:
            # 1. 启动eBPF工具 (如果需要)
            if test_case.ebpf_tool:
                self._start_ebpf_tool(test_case.ebpf_tool)

            # 2. 启动监控
            monitoring_tasks = self._start_monitoring(test_case)

            # 3. 执行性能测试
            test_result = self._execute_performance_test(test_case)

            # 4. 收集监控数据
            monitoring_data = self._collect_monitoring_data(monitoring_tasks)

            # 5. 保存结果
            self._save_test_result(result_dir, test_result, monitoring_data)

            return TestResult(
                test_case=test_case,
                performance_data=test_result,
                monitoring_data=monitoring_data,
                success=True
            )

        except Exception as e:
            return TestResult(
                test_case=test_case,
                error=str(e),
                success=False
            )

        finally:
            # 清理资源
            if test_case.ebpf_tool:
                self._stop_ebpf_tool(test_case.ebpf_tool)
            self._stop_monitoring(monitoring_tasks)

    def _execute_performance_test(self, test_case):
        """执行具体的性能测试"""
        if test_case.type.startswith("throughput"):
            return self._execute_throughput_test(test_case)
        elif test_case.type == "latency":
            return self._execute_latency_test(test_case)
        elif test_case.type == "pps":
            return self._execute_pps_test(test_case)

    def _execute_throughput_test(self, test_case):
        """执行吞吐量测试"""
        # 启动服务端
        server_cmd = self._build_server_command(test_case)
        server_process = self.ssh_manager.start_remote_process(
            test_case.env_config.server, server_cmd
        )

        # 等待服务端就绪
        time.sleep(2)

        # 启动客户端
        client_results = []
        if test_case.type == "throughput_single":
            client_cmd = self._build_client_command(test_case)
            result = self.ssh_manager.execute_remote_command(
                test_case.env_config.client, client_cmd
            )
            client_results.append(result)

        elif test_case.type == "throughput_multi":
            # 多流并发测试
            client_processes = []
            for i in range(test_case.streams):
                port = test_case.base_port + i
                client_cmd = self._build_client_command(test_case, port=port)
                process = self.ssh_manager.start_remote_process(
                    test_case.env_config.client, client_cmd
                )
                client_processes.append(process)

            # 等待所有客户端完成
            for process in client_processes:
                result = process.wait()
                client_results.append(result)

        # 停止服务端
        server_process.terminate()

        return {
            "type": "throughput",
            "client_results": client_results,
            "total_throughput": self._calculate_total_throughput(client_results)
        }
```

### 3.6 监控数据收集

```python
class MonitoringManager:
    def start_resource_monitoring(self, target_hosts, processes):
        """启动资源监控"""
        monitoring_tasks = {}

        for host in target_hosts:
            # CPU & Memory监控
            cpu_mem_cmd = f"top -b -d 1 -p {','.join(processes)} | tee cpu_mem_monitor.log"
            monitoring_tasks[f"{host}_cpu_mem"] = self.ssh_manager.start_remote_process(
                host, cpu_mem_cmd
            )

            # 磁盘IO监控
            io_cmd = "iostat -x 1 | tee disk_io_monitor.log"
            monitoring_tasks[f"{host}_io"] = self.ssh_manager.start_remote_process(
                host, io_cmd
            )

            # 网络监控
            if host in target_hosts:
                interface = host.interface
                net_cmd = f"sar -n DEV 1 | grep {interface} | tee network_monitor.log"
                monitoring_tasks[f"{host}_network"] = self.ssh_manager.start_remote_process(
                    host, net_cmd
                )

        return monitoring_tasks

    def collect_monitoring_data(self, monitoring_tasks):
        """收集监控数据"""
        monitoring_data = {}

        for task_name, process in monitoring_tasks.items():
            try:
                output = process.get_output()
                monitoring_data[task_name] = self._parse_monitoring_output(
                    task_name, output
                )
            except Exception as e:
                monitoring_data[task_name] = {"error": str(e)}

        return monitoring_data

    def _parse_monitoring_output(self, task_name, output):
        """解析监控输出"""
        if "cpu_mem" in task_name:
            return self._parse_top_output(output)
        elif "io" in task_name:
            return self._parse_iostat_output(output)
        elif "network" in task_name:
            return self._parse_sar_output(output)
```

### 3.7 结果分析和报告

```python
class ResultAnalyzer:
    def analyze_test_results(self, test_results):
        """分析测试结果"""
        analysis = {
            "baseline_performance": {},
            "ebpf_overhead": {},
            "performance_comparison": {}
        }

        # 按环境和测试类型分组
        grouped_results = self._group_results(test_results)

        for env_name, env_results in grouped_results.items():
            analysis["baseline_performance"][env_name] = self._analyze_baseline(
                env_results["baseline"]
            )

            analysis["ebpf_overhead"][env_name] = self._analyze_ebpf_overhead(
                env_results["baseline"], env_results["ebpf"]
            )

        return analysis

    def _analyze_ebpf_overhead(self, baseline_results, ebpf_results):
        """分析eBPF工具性能开销"""
        overhead_analysis = {}

        for tool_name, tool_results in ebpf_results.items():
            tool_overhead = {}

            for test_type, results in tool_results.items():
                baseline_perf = baseline_results[test_type]
                ebpf_perf = results["performance"]

                if test_type == "throughput":
                    overhead = (baseline_perf["throughput"] - ebpf_perf["throughput"]) / baseline_perf["throughput"] * 100
                    tool_overhead[test_type] = {
                        "throughput_loss_percent": overhead,
                        "baseline_throughput": baseline_perf["throughput"],
                        "ebpf_throughput": ebpf_perf["throughput"]
                    }

                elif test_type == "latency":
                    overhead = (ebpf_perf["mean_latency"] - baseline_perf["mean_latency"]) / baseline_perf["mean_latency"] * 100
                    tool_overhead[test_type] = {
                        "latency_increase_percent": overhead,
                        "baseline_latency": baseline_perf["mean_latency"],
                        "ebpf_latency": ebpf_perf["mean_latency"]
                    }

                elif test_type == "pps":
                    overhead = (baseline_perf["pps"] - ebpf_perf["pps"]) / baseline_perf["pps"] * 100
                    tool_overhead[test_type] = {
                        "pps_loss_percent": overhead,
                        "baseline_pps": baseline_perf["pps"],
                        "ebpf_pps": ebpf_perf["pps"]
                    }

                # 资源开销分析
                tool_overhead[f"{test_type}_resource_overhead"] = {
                    "cpu_usage": results["monitoring"]["cpu_usage"],
                    "memory_usage": results["monitoring"]["memory_usage"],
                    "disk_io": results["monitoring"]["disk_io"]
                }

            overhead_analysis[tool_name] = tool_overhead

        return overhead_analysis

    def generate_performance_report(self, analysis):
        """生成性能报告"""
        report = {
            "summary": self._generate_summary(analysis),
            "detailed_analysis": analysis,
            "recommendations": self._generate_recommendations(analysis)
        }

        return report
```

## 4. 项目目录结构

```
test/workflow/
├── config/
│   ├── ssh-hosts.yaml                        # SSH连接配置
│   ├── test-environments.yaml                # 测试环境定义
│   ├── performance-test-spec.yaml            # 性能测试规格
│   ├── ebpf-tools-spec.yaml                  # eBPF工具规格
│   └── monitoring-config.yaml                # 监控配置
├── automation/
│   ├── core/
│   │   ├── test_executor.py                  # 测试执行引擎
│   │   ├── test_case_generator.py            # 测试用例生成器
│   │   ├── monitoring_manager.py             # 监控管理器
│   │   ├── ssh_manager.py                    # SSH连接管理器
│   │   ├── result_analyzer.py                # 结果分析器
│   │   └── result_identifier.py              # 结果标识和匹配
│   ├── hooks/
│   │   ├── init_hook.py                      # 初始化Hook
│   │   ├── post_hook.py                      # 后处理Hook
│   │   └── custom_hook.py                    # 自定义Hook
│   └── utils/
│       ├── config_parser.py                  # 配置解析器
│       ├── command_builder.py                # 命令构建器
│       ├── data_parser.py                    # 数据解析器
│       └── tool_discovery.py                 # eBPF工具自动发现
├── result/                                   # 详细目录结构见3.2节
│   ├── baseline/                             # 基线测试结果
│   │   ├── {test_env_id}/
│   │   │   ├── {test_type}/
│   │   │   │   ├── {protocol}/
│   │   │   │   │   └── {test_params_hash}/
│   │   │   │   │       └── run_{timestamp}/
│   │   │   │   └── ...
│   │   │   └── ...
│   │   └── baseline_summary.json
│   ├── ebpf/                                 # eBPF工具测试结果
│   │   ├── {ebpf_tool_id}/
│   │   │   ├── {test_env_id}/
│   │   │   │   ├── {test_type}/
│   │   │   │   │   ├── {protocol}/
│   │   │   │   │   │   └── {test_params_hash}/
│   │   │   │   │   │       └── run_{timestamp}/
│   │   │   │   │   └── ...
│   │   │   │   └── ...
│   │   │   └── tool_summary.json
│   │   └── ebpf_comparison.json
│   └── analysis/                             # 分析报告
│       ├── performance_comparison.json       # 性能对比报告
│       ├── overhead_analysis.json            # 开销分析报告
│       └── recommendations.json              # 优化建议
└── scripts/
    ├── run_performance_automation.py         # 主执行脚本
    ├── generate_test_matrix.py               # 测试矩阵生成脚本
    ├── generate_report.py                    # 报告生成脚本
    └── tool_scanner.py                       # eBPF工具扫描脚本
```

## 5. 执行流程

```
1. 配置解析 → 2. 测试矩阵生成 → 3. 环境初始化
                     ↓
8. 报告生成 ← 7. 结果分析 ← 6. 数据收集 ← 5. 测试执行 ← 4. 监控启动
```

### 5.1 具体执行步骤

1. **配置解析**: 读取所有配置文件，构建测试环境和规格
2. **测试矩阵生成**: 根据配置生成完整的测试用例矩阵
3. **环境初始化**: 执行init hook，准备测试环境
4. **监控启动**: 启动资源监控和自定义监控
5. **测试执行**: 按序执行所有测试用例（基线测试 + eBPF工具测试）
6. **数据收集**: 收集性能数据和监控数据
7. **结果分析**: 分析性能开销和对比
8. **报告生成**: 生成结构化性能报告

## 6. 关键特性与优势

### 6.1 基线对比保证
- **强制基线测试**: 每个eBPF工具测试都必须有对应的基线测试
- **结果隔离存储**: 基线和eBPF测试结果分别存储在不同目录结构中
- **自动匹配机制**: 系统自动匹配相同测试条件的基线和eBPF测试结果
- **条件一致性验证**: 确保对比测试的环境、参数完全一致

### 6.2 通用框架设计
- **工具无关性**: 不硬编码特定eBPF工具，支持任意工具集成
- **自动发现机制**: 支持扫描目录自动发现新eBPF工具
- **灵活配置**: 通过配置文件定义工具参数和适用环境
- **参数模板化**: 支持变量替换的命令模板，适应不同工具需求

### 6.3 环境配置分离
- **SSH配置独立**: SSH连接信息与测试环境定义完全分离
- **环境引用机制**: 测试环境通过引用方式使用SSH配置
- **配置复用**: SSH配置可被多个测试环境复用
- **维护简化**: 修改连接信息不影响测试环境定义

### 6.4 目录结构编码
- **层次化组织**: 多层目录结构清晰区分不同测试维度
- **唯一标识**: 每个测试结果都有唯一的目录路径标识
- **参数编码**: 测试参数自动编码为目录名，便于识别和查找
- **时间戳隔离**: 多次运行结果通过时间戳区分，避免覆盖

### 6.5 全面监控
- **性能数据**: 吞吐量、延迟、PPS等网络性能指标
- **资源监控**: CPU、内存、磁盘IO等系统资源使用
- **eBPF特定**: eBPF工具自身的输出和资源消耗
- **多主机支持**: 同时监控服务端和客户端的资源使用

## 7. 实施计划

### 阶段1: 核心框架
- 实现基础的配置解析和测试用例生成
- 开发SSH连接管理和远程执行能力
- 构建基本的监控和数据收集机制

### 阶段2: 测试执行
- 实现三类性能测试的自动化执行
- 集成eBPF工具的启动和停止管理
- 开发结果数据的解析和存储

### 阶段3: 分析报告
- 构建性能开销分析算法
- 实现自动化报告生成
- 开发可视化的结果展示

### 阶段4: 优化完善
- 性能优化和并发执行
- 增强错误处理和容错能力
- 完善文档和使用指南

这个设计提供了完整的自动化性能测试框架，能够满足您提出的所有需求，并具备良好的扩展性和维护性。