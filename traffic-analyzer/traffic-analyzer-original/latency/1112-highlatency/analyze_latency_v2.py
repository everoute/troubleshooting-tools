#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重新分析高延迟ICMP ping测试结果，使用正确的时间窗口：
- 时间窗口1: 16:54:30 - 16:55:30 (在host1连接的交换机端口抓包)
- 时间窗口2: 16:55:45 - 16:56:45 (在host2连接的交换机端口抓包)
"""

import re
import subprocess
import sys
from datetime import datetime, timedelta
from collections import defaultdict
import json

# 正确的时间窗口定义
WINDOW1_START = datetime.strptime("2025-11-12 16:54:30", "%Y-%m-%d %H:%M:%S")
WINDOW1_END = WINDOW1_START + timedelta(seconds=60)
WINDOW1_PCAP = "ce6885-eth1-1.pcap"  # 交换机在host1端口抓包

WINDOW2_START = datetime.strptime("2025-11-12 16:55:45", "%Y-%m-%d %H:%M:%S")
WINDOW2_END = WINDOW2_START + timedelta(seconds=60)
WINDOW2_PCAP = "ce6885-eth2-1.pcap"  # 交换机在host2端口抓包

# PCAP文件的实际时间戳（与host测量时间有5分24秒偏差）
WINDOW1_PCAP_ACTUAL_START = datetime.strptime("2025-11-12 16:49:06.000814", "%Y-%m-%d %H:%M:%S.%f")
WINDOW2_PCAP_ACTUAL_START = datetime.strptime("2025-11-12 16:50:21.000561", "%Y-%m-%d %H:%M:%S.%f")

# 时间偏差
TIME_OFFSET = (WINDOW1_START - WINDOW1_PCAP_ACTUAL_START).total_seconds()  # 应该是 324秒

print(f"检测到的时间偏差: {TIME_OFFSET} 秒")
print(f"时间窗口1: {WINDOW1_START} - {WINDOW1_END}")
print(f"时间窗口2: {WINDOW2_START} - {WINDOW2_END}")
print(f"PCAP1实际时间: {WINDOW1_PCAP_ACTUAL_START}")
print(f"PCAP2实际时间: {WINDOW2_PCAP_ACTUAL_START}")
print()

class PacketRecord:
    """表示单个高延迟数据包观测"""
    def __init__(self):
        self.timestamp = None
        self.icmp_id = None
        self.icmp_seq = None
        self.src_ip = None
        self.dst_ip = None

        # TX侧测量（来自host1）
        self.tx_path1_latency = None  # host1协议栈处理（请求路径）
        self.tx_inter_path_latency = None  # 网络传输
        self.tx_path2_latency = None  # host1协议栈处理（应答路径）
        self.tx_total_rtt = None

        # RX侧测量（来自host2）
        self.rx_path1_latency = None  # host2协议栈处理（请求路径）
        self.rx_inter_path_latency = None  # 网络传输
        self.rx_path2_latency = None  # host2协议栈处理（应答路径）
        self.rx_total_rtt = None

        # 交换机抓包分析
        self.switch_request_ts = None
        self.switch_reply_ts = None
        self.switch_rtt = None

        self.time_window = None  # 1 or 2

def parse_tx_log(filepath, window_start, window_end, window_num):
    """解析TX侧延迟测量日志"""
    packets = []

    with open(filepath, 'r') as f:
        content = f.read()

    # 按块分割
    blocks = re.split(r'={50,}', content)

    for block in blocks:
        if '=== ICMP RTT Trace:' not in block:
            continue

        pkt = PacketRecord()

        # 提取时间戳
        ts_match = re.search(r'=== ICMP RTT Trace: ([\d\-: .]+) \(', block)
        if not ts_match:
            continue
        
        pkt.timestamp = datetime.strptime(ts_match.group(1).strip(), "%Y-%m-%d %H:%M:%S.%f")

        # 检查是否在指定时间窗口内
        if not (window_start <= pkt.timestamp <= window_end):
            continue

        # 提取会话信息（ID和Seq）
        session_match = re.search(r'Session:.*\(ID: (\d+), Seq: (\d+)\)', block)
        if session_match:
            pkt.icmp_id = int(session_match.group(1))
            pkt.icmp_seq = int(session_match.group(2))

        # 提取IP
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+) \([^)]+\) -> (\d+\.\d+\.\d+\.\d+)', block)
        if ip_match:
            pkt.src_ip = ip_match.group(1)
            pkt.dst_ip = ip_match.group(2)

        # 提取延迟
        path1_match = re.search(r'Total Path 1:\s+([\d.]+) us', block)
        if path1_match:
            pkt.tx_path1_latency = float(path1_match.group(1))

        path2_match = re.search(r'Total Path 2:\s+([\d.]+) us', block)
        if path2_match:
            pkt.tx_path2_latency = float(path2_match.group(1))

        inter_match = re.search(r'Inter-Path Latency.*:\s+([\d.]+) us', block)
        if inter_match:
            pkt.tx_inter_path_latency = float(inter_match.group(1))

        rtt_match = re.search(r'Total RTT.*:\s+([\d.]+) us', block)
        if rtt_match:
            pkt.tx_total_rtt = float(rtt_match.group(1))

        pkt.time_window = window_num
        packets.append(pkt)

    return packets

def parse_rx_log(filepath, window_start, window_end):
    """解析RX侧延迟测量日志"""
    packets = {}  # 键为(icmp_id, icmp_seq)

    try:
        with open(filepath, 'r') as f:
            content = f.read()
    except Exception as e:
        print(f"警告：无法读取RX日志: {e}")
        return packets

    blocks = re.split(r'={50,}', content)

    for block in blocks:
        if '=== ICMP RTT Trace:' not in block:
            continue

        # 提取时间戳
        ts_match = re.search(r'=== ICMP RTT Trace: ([\d\-: .]+) \(', block)
        if not ts_match:
            continue
        timestamp = datetime.strptime(ts_match.group(1).strip(), "%Y-%m-%d %H:%M:%S.%f")

        # 只处理在我们的时间窗口内的数据包
        if not (window_start <= timestamp <= window_end):
            continue

        # 提取会话信息
        session_match = re.search(r'Session:.*\(ID: (\d+), Seq: (\d+)\)', block)
        if not session_match:
            continue

        icmp_id = int(session_match.group(1))
        icmp_seq = int(session_match.group(2))

        # 提取延迟
        path1_latency = None
        path2_latency = None
        inter_latency = None
        total_rtt = None

        path1_match = re.search(r'Total Path 1:\s+([\d.]+) us', block)
        if path1_match:
            path1_latency = float(path1_match.group(1))

        path2_match = re.search(r'Total Path 2:\s+([\d.]+) us', block)
        if path2_match:
            path2_latency = float(path2_match.group(1))

        inter_match = re.search(r'Inter-Path Latency.*:\s+([\d.]+) us', block)
        if inter_match:
            inter_latency = float(inter_match.group(1))

        rtt_match = re.search(r'Total RTT.*:\s+([\d.]+) us', block)
        if rtt_match:
            total_rtt = float(rtt_match.group(1))

        packets[(icmp_id, icmp_seq)] = {
            'timestamp': timestamp,
            'path1_latency': path1_latency,
            'path2_latency': path2_latency,
            'inter_latency': inter_latency,
            'total_rtt': total_rtt
        }

    return packets

def find_packet_in_pcap(pcap_file, icmp_id, icmp_seq, host_timestamp, pcap_start_time):
    """
    在交换机抓包中查找匹配的ICMP请求和应答数据包
    使用ICMP ID + Seq精确匹配，并验证时间合理性
    """
    # 计算期望的相对时间（使用时间偏移）
    expected_offset = (host_timestamp - pcap_start_time - timedelta(seconds=TIME_OFFSET)).total_seconds()
    search_start = max(0, expected_offset - 2.0)  # 搜索窗口 +/- 2秒
    search_end = expected_offset + 2.0

    # 使用ICMP ID + Seq精确查找
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

        # 收集候选数据包
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

            # 检查是否在搜索窗口内
            if not (search_start <= rel_time <= search_end):
                continue

            candidates.append({
                'rel_time': rel_time,
                'icmp_type': icmp_type,
                'ip_id': ip_id,
                'src_ip': src_ip,
                'dst_ip': dst_ip
            })

        # 查找请求-应答对
        best_match = None
        best_time_diff = float('inf')

        for i, pkt in enumerate(candidates):
            if pkt['icmp_type'] == '8':  # 请求
                # 查找对应的应答
                for reply in candidates[i:]:
                    if (reply['icmp_type'] == '0' and
                        reply['src_ip'] == pkt['dst_ip'] and
                        reply['dst_ip'] == pkt['src_ip']):

                        # 计算RTT
                        switch_rtt_s = reply['rel_time'] - pkt['rel_time']

                        # 验证RTT合理性：应该在几微秒到几百毫秒之间
                        if switch_rtt_s < 0 or switch_rtt_s > 0.5:  # 超过500ms认为不合理
                            continue

                        # 计算与期望时间的差异
                        time_diff = abs(pkt['rel_time'] - expected_offset)

                        if time_diff < best_time_diff:
                            best_time_diff = time_diff
                            request_ts = pkt['rel_time']
                            reply_ts = reply['rel_time']
                            switch_rtt_us = switch_rtt_s * 1000000
                            best_match = (request_ts, reply_ts, switch_rtt_us, pkt['ip_id'], reply['ip_id'])
                        break

        return best_match

    except Exception as e:
        print(f"警告：搜索pcap出错 ID={icmp_id}, Seq={icmp_seq}: {e}")

    return None

def analyze_latency_breakdown(pkt, switch_result):
    """
    计算详细的延迟分段
    """
    breakdown = {
        'timestamp': pkt.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        'icmp_id': pkt.icmp_id,
        'icmp_seq': pkt.icmp_seq,
        'time_window': pkt.time_window,

        # TX测量
        'host1_tx_stack': pkt.tx_path1_latency,
        'host1_rx_stack': pkt.tx_path2_latency,
        'tx_inter_path': pkt.tx_inter_path_latency,
        'tx_total_rtt': pkt.tx_total_rtt,

        # RX测量（如果有）
        'host2_rx_stack': pkt.rx_path1_latency,
        'host2_tx_stack': pkt.rx_path2_latency,
        'rx_inter_path': pkt.rx_inter_path_latency,
        'rx_total_rtt': pkt.rx_total_rtt,

        # 交换机抓包
        'switch_rtt': None,
        'switch_request_offset': None,
        'switch_reply_offset': None,
        'ip_id_request': None,
        'ip_id_reply': None,
    }

    if switch_result:
        request_ts, reply_ts, switch_rtt_us, ip_id_req, ip_id_rep = switch_result
        breakdown['switch_request_offset'] = request_ts
        breakdown['switch_reply_offset'] = reply_ts
        breakdown['switch_rtt'] = switch_rtt_us
        breakdown['ip_id_request'] = ip_id_req
        breakdown['ip_id_reply'] = ip_id_rep

        # 计算分段延迟
        # 对于窗口1（交换机在host1端口）：
        #   Seg_A: host1 TX stack -> 交换机看到request
        #   Seg_B: 交换机request -> 交换机reply (switch_rtt，包含到host2的往返)
        #   Seg_C: 交换机reply -> host1 RX stack
        #
        # 有：Seg_A + Seg_B + Seg_C = tx_inter_path_latency
        #     Seg_B = switch_rtt
        # 所以：Seg_A + Seg_C = tx_inter_path_latency - switch_rtt

        network_overhead = pkt.tx_inter_path_latency - switch_rtt_us
        breakdown['host1_to_switch_overhead'] = network_overhead  # Seg_A + Seg_C

        # 如果有RX测量，可以进一步分解
        if pkt.rx_path1_latency is not None:
            # switch_rtt 包含：
            #   - 交换机->host2传输
            #   - host2 RX stack处理
            #   - host2 TX stack处理
            #   - host2->交换机传输
            # 
            # 如果RX侧测量显示host2处理时间，可以估算网络段
            host2_processing = (pkt.rx_path1_latency or 0) + (pkt.rx_path2_latency or 0)
            host2_network_segments = switch_rtt_us - host2_processing
            breakdown['host2_network_overhead'] = max(0, host2_network_segments)
            breakdown['host2_processing'] = host2_processing

    return breakdown

def generate_report(packets_data):
    """生成详细分析报告"""
    print("=" * 120)
    print("ICMP高延迟分析报告")
    print("=" * 120)
    print()

    # 按时间窗口分组
    for window_num in [1, 2]:
        window_packets = [p for p in packets_data if p['time_window'] == window_num]
        if not window_packets:
            continue

        if window_num == 1:
            print(f"\n{'='*120}")
            print(f"时间窗口1: {WINDOW1_START} - {WINDOW1_END}")
            print(f"交换机抓包: {WINDOW1_PCAP} (在host1端口)")
            print(f"{'='*120}\n")
        else:
            print(f"\n{'='*120}")
            print(f"时间窗口2: {WINDOW2_START} - {WINDOW2_END}")
            print(f"交换机抓包: {WINDOW2_PCAP} (在host2端口)")
            print(f"{'='*120}\n")

        # 打印表格头
        print(f"{'时间戳':<24} {'ICMP_ID':<8} {'Seq':<5} "
              f"{'H1-TX':<8} {'中间段':<10} {'H1-RX':<8} {'总RTT':<9} "
              f"{'交换机RTT':<10} {'网络开销':<10}")
        print(f"{'':24} {'':8} {'':5} "
              f"{'(us)':<8} {'(us)':<10} {'(us)':<8} {'(ms)':<9} "
              f"{'(us)':<10} {'(us)':<10}")
        print("-" * 110)

        for pkt in sorted(window_packets, key=lambda x: x['timestamp']):
            switch_rtt_str = f"{pkt['switch_rtt']:.1f}" if pkt['switch_rtt'] else 'N/A'
            network_oh_str = f"{pkt['host1_to_switch_overhead']:.1f}" if pkt.get('host1_to_switch_overhead') else 'N/A'

            print(f"{pkt['timestamp']:<24} "
                  f"{pkt['icmp_id']:<8} {pkt['icmp_seq']:<5} "
                  f"{pkt['host1_tx_stack']:<8.1f} "
                  f"{pkt['tx_inter_path']:<10.1f} "
                  f"{pkt['host1_rx_stack']:<8.1f} "
                  f"{pkt['tx_total_rtt']/1000:<9.1f} "
                  f"{switch_rtt_str:<10} "
                  f"{network_oh_str:<10}")

        print("\n")

        # 详细延迟分解
        print("详细延迟分段:")
        print("-" * 110)

        for pkt in sorted(window_packets, key=lambda x: x['timestamp']):
            ip_id_info = ""
            if pkt.get('ip_id_request') and pkt.get('ip_id_reply'):
                ip_id_info = f" [IP_ID: {pkt['ip_id_request']} -> {pkt['ip_id_reply']}]"

            print(f"\n[{pkt['timestamp']}] ICMP_ID={pkt['icmp_id']}, Seq={pkt['icmp_seq']}{ip_id_info}")
            print(f"  总RTT: {pkt['tx_total_rtt']/1000:.3f} ms")
            print(f"    ├─ Host1 TX协议栈处理: {pkt['host1_tx_stack']:.1f} us")
            print(f"    ├─ 中间段网络延迟: {pkt['tx_inter_path']/1000:.3f} ms")

            if pkt['switch_rtt']:
                print(f"    │    ├─ Host1↔交换机网络开销: {pkt.get('host1_to_switch_overhead', 0)/1000:.3f} ms")
                print(f"    │    └─ 交换机RTT (包含Host2处理): {pkt['switch_rtt']/1000:.3f} ms")

                if pkt.get('host2_processing'):
                    print(f"    │         ├─ Host2 RX协议栈: {pkt.get('host2_rx_stack', 0):.1f} us")
                    print(f"    │         ├─ Host2 TX协议栈: {pkt.get('host2_tx_stack', 0):.1f} us")
                    print(f"    │         └─ Host2↔交换机网络段: {pkt.get('host2_network_overhead', 0)/1000:.3f} ms")

            print(f"    └─ Host1 RX协议栈处理: {pkt['host1_rx_stack']:.1f} us")

            if pkt['tx_inter_path'] > 50000:
                print(f"  ⚠️  高延迟警告: 中间段延迟 = {pkt['tx_inter_path']/1000:.1f} ms")

def main():
    base_dir = "/Users/admin/workspace/troubleshooting-tools/test/pcap-analyzer/1112-highlatency"
    tx_log = f"{base_dir}/211-1112/211-212-tx.log"
    rx_log = f"{base_dir}/212-1112/211-212-rx.log"

    print("=" * 80)
    print("步骤1: 解析时间窗口1的TX侧测量...")
    window1_packets = parse_tx_log(tx_log, WINDOW1_START, WINDOW1_END, 1)
    print(f"  找到 {len(window1_packets)} 个高延迟数据包")

    print("\n步骤2: 解析时间窗口2的TX侧测量...")
    window2_packets = parse_tx_log(tx_log, WINDOW2_START, WINDOW2_END, 2)
    print(f"  找到 {len(window2_packets)} 个高延迟数据包")

    all_packets = window1_packets + window2_packets

    print(f"\n步骤3: 解析RX侧测量...")
    # 合并两个窗口来搜索RX数据
    combined_start = min(WINDOW1_START, WINDOW2_START)
    combined_end = max(WINDOW1_END, WINDOW2_END)
    rx_packets_dict = parse_rx_log(rx_log, combined_start, combined_end)
    print(f"  找到 {len(rx_packets_dict)} 个RX侧高延迟数据包")

    print("\n步骤4: 匹配TX和RX测量...")
    for pkt in all_packets:
        key = (pkt.icmp_id, pkt.icmp_seq)
        if key in rx_packets_dict:
            rx_data = rx_packets_dict[key]
            pkt.rx_path1_latency = rx_data['path1_latency']
            pkt.rx_path2_latency = rx_data['path2_latency']
            pkt.rx_inter_path_latency = rx_data['inter_latency']
            pkt.rx_total_rtt = rx_data['total_rtt']
            print(f"  ✓ 匹配到 ID={pkt.icmp_id}, Seq={pkt.icmp_seq}")

    print("\n步骤5: 分析交换机抓包...")
    packets_data = []
    for pkt in all_packets:
        # 确定使用哪个pcap文件
        if pkt.time_window == 1:
            pcap_file = f"{base_dir}/{WINDOW1_PCAP}"
            pcap_start = WINDOW1_PCAP_ACTUAL_START
        else:
            pcap_file = f"{base_dir}/{WINDOW2_PCAP}"
            pcap_start = WINDOW2_PCAP_ACTUAL_START

        print(f"  搜索 ID={pkt.icmp_id}, Seq={pkt.icmp_seq} (窗口{pkt.time_window})...")
        switch_result = find_packet_in_pcap(pcap_file, pkt.icmp_id, pkt.icmp_seq, pkt.timestamp, pcap_start)

        if switch_result:
            print(f"    ✓ 找到! 交换机RTT={switch_result[2]/1000:.3f}ms, IP_ID: {switch_result[3]} -> {switch_result[4]}")

        breakdown = analyze_latency_breakdown(pkt, switch_result)
        packets_data.append(breakdown)

    print("\n步骤6: 生成报告...\n")
    generate_report(packets_data)

    # 保存JSON
    output_file = f"{base_dir}/latency_analysis_results_v2.json"
    with open(output_file, 'w') as f:
        json.dump(packets_data, f, indent=2, default=str)
    print(f"\n✓ 分析结果已保存到: {output_file}")

if __name__ == "__main__":
    main()
