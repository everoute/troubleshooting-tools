#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析 1113 高延迟 ICMP ping 测试结果（正确版本）
测试场景：host2 (192.168.10.212) ping host1 (192.168.10.211)

时间窗口定义：
- 窗口1: 15:22:25 + 559s (在 host2 交换机端口 eth2-1 抓包)
- 窗口2: 15:32:30 + 559s (在 host1 交换机端口 eth1-1 抓包)

延迟分段逻辑：
- 窗口1: 使用 host2 switch port 分割
  - Seg_A: Host2 ↔ Host2_Switch_Port 往返延迟
  - Seg_B: Host2_Switch_Port ↔ Host1 往返延迟
- 窗口2: 使用 host1 switch port 分割
  - Seg_A: Host2 ↔ Host1_Switch_Port 往返延迟
  - Seg_B: Host1_Switch_Port ↔ Host1 往返延迟
"""

import re
import subprocess
from datetime import datetime, timedelta
import json

# 时间窗口定义
WINDOW1_START = datetime.strptime("2025-11-13 15:22:25", "%Y-%m-%d %H:%M:%S")
WINDOW1_END = WINDOW1_START + timedelta(seconds=559)
WINDOW1_PCAP = "ce6885-eth2-1-1113.cap"  # Host2 交换机端口
WINDOW1_PCAP_START = datetime.strptime("2025-11-13 15:17:00.000757", "%Y-%m-%d %H:%M:%S.%f")

WINDOW2_START = datetime.strptime("2025-11-13 15:32:30", "%Y-%m-%d %H:%M:%S")
WINDOW2_END = WINDOW2_START + timedelta(seconds=559)
WINDOW2_PCAP = "ce6885-eth1-1-1113.cap"  # Host1 交换机端口
WINDOW2_PCAP_START = datetime.strptime("2025-11-13 15:27:06.000219", "%Y-%m-%d %H:%M:%S.%f")

# 时间偏差（host时间 vs 交换机时间）
TIME_OFFSET_W1 = (WINDOW1_START - WINDOW1_PCAP_START).total_seconds()
TIME_OFFSET_W2 = (WINDOW2_START - WINDOW2_PCAP_START).total_seconds()

print("=" * 80)
print("时间窗口配置:")
print(f"  窗口1: {WINDOW1_START} - {WINDOW1_END}")
print(f"    交换机抓包: {WINDOW1_PCAP} (Host2端口 eth2-1)")
print(f"    抓包开始时间: {WINDOW1_PCAP_START}")
print(f"    时间偏差: {TIME_OFFSET_W1:.3f} 秒")
print()
print(f"  窗口2: {WINDOW2_START} - {WINDOW2_END}")
print(f"    交换机抓包: {WINDOW2_PCAP} (Host1端口 eth1-1)")
print(f"    抓包开始时间: {WINDOW2_PCAP_START}")
print(f"    时间偏差: {TIME_OFFSET_W2:.3f} 秒")
print("=" * 80)
print()

class LatencyRecord:
    def __init__(self):
        self.timestamp = None
        self.icmp_id = None
        self.icmp_seq = None
        self.src_ip = None
        self.dst_ip = None

        # Host2 TX 测量
        self.host2_tx_stack = None
        self.host2_rx_stack = None
        self.inter_path_latency = None
        self.total_rtt = None

        # 交换机抓包
        self.switch_request_ts = None
        self.switch_reply_ts = None
        self.switch_rtt = None
        self.ip_id_request = None
        self.ip_id_reply = None

        self.window = None

def parse_tx_log(filepath, window_start, window_end, window_num):
    """解析 Host2 TX 测量日志，找出指定时间窗口内的高延迟记录"""
    records = []

    with open(filepath, 'r') as f:
        content = f.read()

    blocks = re.split(r'={50,}', content)

    for block in blocks:
        if '=== ICMP RTT Trace:' not in block:
            continue

        rec = LatencyRecord()

        # 提取时间戳
        ts_match = re.search(r'=== ICMP RTT Trace: ([\d\-: .]+) \(', block)
        if not ts_match:
            continue

        rec.timestamp = datetime.strptime(ts_match.group(1).strip(), "%Y-%m-%d %H:%M:%S.%f")

        # 检查是否在时间窗口内
        if not (window_start <= rec.timestamp <= window_end):
            continue

        # 提取 ICMP ID 和 Seq
        session_match = re.search(r'Session:.*\(ID: (\d+), Seq: (\d+)\)', block)
        if session_match:
            rec.icmp_id = int(session_match.group(1))
            rec.icmp_seq = int(session_match.group(2))

        # 提取 IP
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+) \([^)]+\) -> (\d+\.\d+\.\d+\.\d+)', block)
        if ip_match:
            rec.src_ip = ip_match.group(1)
            rec.dst_ip = ip_match.group(2)

        # 提取延迟
        path1_match = re.search(r'Total Path 1:\s+([\d.]+) us', block)
        if path1_match:
            rec.host2_tx_stack = float(path1_match.group(1))

        path2_match = re.search(r'Total Path 2:\s+([\d.]+) us', block)
        if path2_match:
            rec.host2_rx_stack = float(path2_match.group(1))

        inter_match = re.search(r'Inter-Path Latency.*:\s+([\d.]+) us', block)
        if inter_match:
            rec.inter_path_latency = float(inter_match.group(1))

        rtt_match = re.search(r'Total RTT.*:\s+([\d.]+) us', block)
        if rtt_match:
            rec.total_rtt = float(rtt_match.group(1))

        # 验证必需字段
        if rec.icmp_id and rec.icmp_seq and rec.inter_path_latency:
            rec.window = window_num
            records.append(rec)

    return records

def find_packet_in_switch_pcap(pcap_file, icmp_id, icmp_seq, host_timestamp, pcap_start_time, time_offset):
    """在交换机抓包中查找匹配的 ICMP request 和 reply"""
    # 计算期望的相对时间
    expected_offset = (host_timestamp - pcap_start_time - timedelta(seconds=time_offset)).total_seconds()
    search_start = max(0, expected_offset - 3.0)
    search_end = expected_offset + 3.0

    cmd = [
        'tshark', '-r', pcap_file,
        '-Y', f'icmp && icmp.ident == {icmp_id} && icmp.seq == {icmp_seq}',
        '-T', 'fields',
        '-e', 'frame.time_relative',
        '-e', 'icmp.type',
        '-e', 'ip.id',
        '-e', 'ip.src',
        '-e', 'ip.dst'
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return None

        candidates = []
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue

            parts = line.split('\t')
            if len(parts) < 5:
                continue

            rel_time = float(parts[0])
            icmp_type = parts[1]
            ip_id = parts[2]
            src_ip = parts[3]
            dst_ip = parts[4]

            if search_start <= rel_time <= search_end:
                candidates.append({
                    'rel_time': rel_time,
                    'icmp_type': icmp_type,
                    'ip_id': ip_id,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip
                })

        # 查找 request-reply 对
        for i, pkt in enumerate(candidates):
            if pkt['icmp_type'] == '8':  # Request
                for reply in candidates[i:]:
                    if (reply['icmp_type'] == '0' and
                        reply['src_ip'] == pkt['dst_ip'] and
                        reply['dst_ip'] == pkt['src_ip']):

                        switch_rtt_s = reply['rel_time'] - pkt['rel_time']
                        if 0 <= switch_rtt_s <= 0.5:  # 合理性检查
                            return (
                                pkt['rel_time'],
                                reply['rel_time'],
                                switch_rtt_s * 1000000,  # 转为微秒
                                pkt['ip_id'],
                                reply['ip_id']
                            )
    except Exception as e:
        print(f"  警告: 搜索失败 - {e}")

    return None

def analyze_and_report():
    """主分析函数"""
    base_dir = "/Users/echken/workspace/troubleshooting-tools/traffic-analyzer/latency/1113-highlatency"
    tx_log = f"{base_dir}/host/212-1113/212-211-tx.log"

    print("步骤1: 解析 Host2 TX 测量日志\n")

    print("  窗口1: 查找高延迟记录...")
    window1_records = parse_tx_log(tx_log, WINDOW1_START, WINDOW1_END, 1)
    print(f"    找到 {len(window1_records)} 个高延迟数据包")

    print("\n  窗口2: 查找高延迟记录...")
    window2_records = parse_tx_log(tx_log, WINDOW2_START, WINDOW2_END, 2)
    print(f"    找到 {len(window2_records)} 个高延迟数据包")

    all_records = window1_records + window2_records

    print(f"\n步骤2: 在交换机抓包中匹配数据包\n")

    results = []

    for rec in all_records:
        if rec.window == 1:
            pcap_file = f"{base_dir}/switch/{WINDOW1_PCAP}"
            pcap_start = WINDOW1_PCAP_START
            time_offset = TIME_OFFSET_W1
            port_desc = "Host2 交换机端口"
        else:
            pcap_file = f"{base_dir}/switch/{WINDOW2_PCAP}"
            pcap_start = WINDOW2_PCAP_START
            time_offset = TIME_OFFSET_W2
            port_desc = "Host1 交换机端口"

        print(f"  [窗口{rec.window}] 搜索 ID={rec.icmp_id}, Seq={rec.icmp_seq}...")

        switch_result = find_packet_in_switch_pcap(
            pcap_file, rec.icmp_id, rec.icmp_seq,
            rec.timestamp, pcap_start, time_offset
        )

        if switch_result:
            req_ts, rep_ts, switch_rtt_us, ip_id_req, ip_id_rep = switch_result
            rec.switch_request_ts = req_ts
            rec.switch_reply_ts = rep_ts
            rec.switch_rtt = switch_rtt_us
            rec.ip_id_request = ip_id_req
            rec.ip_id_reply = ip_id_rep
            print(f"    ✓ 找到! 交换机RTT={switch_rtt_us/1000:.3f}ms, IP_ID: {ip_id_req} -> {ip_id_rep}")
        else:
            print(f"    ✗ 未找到")

        results.append(rec)

    print(f"\n步骤3: 生成延迟分段报告\n")
    generate_report(results)

    # 保存 JSON
    output_file = f"{base_dir}/latency_analysis_1113_v2.json"
    save_json(results, output_file)
    print(f"\n✓ 分析结果已保存: {output_file}")

def generate_report(records):
    """生成详细报告"""
    print("=" * 120)
    print("ICMP 高延迟分段分析报告 (Host2 -> Host1)")
    print("=" * 120)

    for window_num in [1, 2]:
        window_records = [r for r in records if r.window == window_num]
        if not window_records:
            continue

        print(f"\n{'='*120}")
        if window_num == 1:
            print(f"时间窗口1: {WINDOW1_START} - {WINDOW1_END}")
            print(f"交换机抓包位置: Host2 端口 (eth2-1)")
            print(f"延迟分段点: Host2 Switch Port")
        else:
            print(f"时间窗口2: {WINDOW2_START} - {WINDOW2_END}")
            print(f"交换机抓包位置: Host1 端口 (eth1-1)")
            print(f"延迟分段点: Host1 Switch Port")
        print(f"{'='*120}\n")

        # 表格
        print(f"{'时间戳':<24} {'ID':<7} {'Seq':<5} {'总RTT':<9} {'InterPath':<11} {'Switch_RTT':<12} {'Seg_A':<11} {'Seg_B':<11}")
        print(f"{'':24} {'':7} {'':5} {'(ms)':<9} {'(ms)':<11} {'(ms)':<12} {'(ms)':<11} {'(ms)':<11}")
        print("-" * 120)

        for rec in sorted(window_records, key=lambda x: x.timestamp):
            ts_str = rec.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            total_rtt_ms = rec.total_rtt / 1000 if rec.total_rtt else 0
            inter_path_ms = rec.inter_path_latency / 1000 if rec.inter_path_latency else 0

            if rec.switch_rtt:
                switch_rtt_ms = rec.switch_rtt / 1000
                seg_a_ms = inter_path_ms - switch_rtt_ms
                seg_b_ms = switch_rtt_ms

                print(f"{ts_str:<24} {rec.icmp_id:<7} {rec.icmp_seq:<5} "
                      f"{total_rtt_ms:<9.3f} {inter_path_ms:<11.3f} "
                      f"{switch_rtt_ms:<12.3f} {seg_a_ms:<11.3f} {seg_b_ms:<11.3f}")
            else:
                print(f"{ts_str:<24} {rec.icmp_id:<7} {rec.icmp_seq:<5} "
                      f"{total_rtt_ms:<9.3f} {inter_path_ms:<11.3f} "
                      f"{'N/A':<12} {'N/A':<11} {'N/A':<11}")

        # 详细分段
        print(f"\n详细延迟分段分析:")
        print("-" * 120)

        for rec in sorted(window_records, key=lambda x: x.timestamp):
            ts_str = rec.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            ip_id_str = ""
            if rec.ip_id_request and rec.ip_id_reply:
                ip_id_str = f" [IP_ID: {rec.ip_id_request} -> {rec.ip_id_reply}]"

            print(f"\n[{ts_str}] ICMP_ID={rec.icmp_id}, Seq={rec.icmp_seq}{ip_id_str}")
            print(f"  总 RTT: {rec.total_rtt/1000:.3f} ms")
            print(f"    ├─ Host2 TX 协议栈: {rec.host2_tx_stack:.1f} us")
            print(f"    ├─ 中间路径延迟 (InterPath): {rec.inter_path_latency/1000:.3f} ms")

            if rec.switch_rtt:
                seg_a_ms = rec.inter_path_latency / 1000 - rec.switch_rtt / 1000
                seg_b_ms = rec.switch_rtt / 1000

                if window_num == 1:
                    # 窗口1: Host2 交换机端口分割
                    print(f"    │    ├─ Seg_A: Host2 ↔ Host2_Switch_Port 往返: {seg_a_ms:.3f} ms")
                    print(f"    │    └─ Seg_B: Host2_Switch_Port ↔ Host1 往返: {seg_b_ms:.3f} ms")
                else:
                    # 窗口2: Host1 交换机端口分割
                    print(f"    │    ├─ Seg_A: Host2 ↔ Host1_Switch_Port 往返: {seg_a_ms:.3f} ms")
                    print(f"    │    └─ Seg_B: Host1_Switch_Port ↔ Host1 往返: {seg_b_ms:.3f} ms")

                if seg_a_ms > 10:
                    print(f"    │         ⚠️  Seg_A 高延迟: {seg_a_ms:.1f} ms")

            print(f"    └─ Host2 RX 协议栈: {rec.host2_rx_stack:.1f} us")

def save_json(records, output_file):
    """保存为 JSON"""
    data = []
    for rec in records:
        item = {
            'timestamp': rec.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            'window': rec.window,
            'icmp_id': rec.icmp_id,
            'icmp_seq': rec.icmp_seq,
            'src_ip': rec.src_ip,
            'dst_ip': rec.dst_ip,
            'host2_tx_stack_us': rec.host2_tx_stack,
            'host2_rx_stack_us': rec.host2_rx_stack,
            'inter_path_latency_us': rec.inter_path_latency,
            'total_rtt_us': rec.total_rtt,
            'switch_rtt_us': rec.switch_rtt,
            'ip_id_request': rec.ip_id_request,
            'ip_id_reply': rec.ip_id_reply,
        }

        if rec.switch_rtt and rec.inter_path_latency:
            item['seg_a_us'] = rec.inter_path_latency - rec.switch_rtt
            item['seg_b_us'] = rec.switch_rtt

            if rec.window == 1:
                item['seg_a_desc'] = 'Host2 ↔ Host2_Switch_Port'
                item['seg_b_desc'] = 'Host2_Switch_Port ↔ Host1'
            else:
                item['seg_a_desc'] = 'Host2 ↔ Host1_Switch_Port'
                item['seg_b_desc'] = 'Host1_Switch_Port ↔ Host1'

        data.append(item)

    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

if __name__ == "__main__":
    analyze_and_report()
