#!/usr/bin/env python3
"""
Comprehensive analysis of tshark exported packet data
"""

import csv
from collections import defaultdict
import statistics

def analyze_csv(csv_file):
    """Analyze tshark CSV export"""

    connections = defaultdict(lambda: {
        'packets': [],
        'retrans': 0,
        'fast_retrans': 0,
        'dup_acks': 0,
        'rtts': [],
        'window_sizes': [],
        'syn_time': None,
        'fin_time': None,
        'bytes_sent': 0,
        'bytes_recv': 0,
        'client_ip': '10.10.64.28',
        'server_ip': '10.10.216.21'
    })

    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)

        for row in reader:
            src_ip = row['ip.src']
            dst_ip = row['ip.dst']
            src_port = row['tcp.srcport']
            dst_port = row['tcp.dstport']

            # Determine connection key and direction
            if src_ip == '10.10.64.28' and dst_ip == '10.10.216.21':
                conn_key = int(src_port)
                direction = 'outbound'
            elif src_ip == '10.10.216.21' and dst_ip == '10.10.64.28':
                conn_key = int(dst_port)
                direction = 'inbound'
            else:
                continue

            conn = connections[conn_key]

            # Parse fields
            timestamp = float(row['frame.time_epoch']) if row['frame.time_epoch'] else 0
            tcp_len = int(row['tcp.len']) if row['tcp.len'] else 0
            tcp_flags = row['tcp.flags']

            # Track bytes
            if direction == 'outbound':
                conn['bytes_sent'] += tcp_len
            else:
                conn['bytes_recv'] += tcp_len

            # Track connection timing
            if not conn['syn_time'] and tcp_flags:
                try:
                    flags_int = int(tcp_flags, 16)
                    if flags_int & 0x02:  # SYN flag
                        conn['syn_time'] = timestamp
                except:
                    pass

            # Track retransmissions
            if row['tcp.analysis.retransmission']:
                conn['retrans'] += 1
            if row['tcp.analysis.fast_retransmission']:
                conn['fast_retrans'] += 1
            if row['tcp.analysis.duplicate_ack']:
                conn['dup_acks'] += 1

            # Track RTT
            if row['tcp.analysis.ack_rtt']:
                try:
                    rtt = float(row['tcp.analysis.ack_rtt']) * 1000  # Convert to ms
                    conn['rtts'].append(rtt)
                except:
                    pass

            # Track window size
            if row['tcp.window_size']:
                try:
                    win_size = int(row['tcp.window_size'])
                    conn['window_sizes'].append(win_size)
                except:
                    pass

            conn['packets'].append({
                'time': timestamp,
                'direction': direction,
                'length': tcp_len,
                'flags': tcp_flags
            })

    return connections

def print_analysis(connections):
    """Print comprehensive analysis"""

    print("\n" + "="*100)
    print("COMPREHENSIVE PCAP ANALYSIS REPORT - 10.10.216.21:443 访问分析")
    print("="*100)

    total_retrans = sum(c['retrans'] for c in connections.values())
    total_fast_retrans = sum(c['fast_retrans'] for c in connections.values())
    total_dup_acks = sum(c['dup_acks'] for c in connections.values())
    total_packets = sum(len(c['packets']) for c in connections.values())

    print(f"\n### 整体统计 ###")
    print(f"总连接数: {len(connections)}")
    print(f"总数据包: {total_packets:,}")
    print(f"重传数据包: {total_retrans:,}")
    print(f"快速重传: {total_fast_retrans:,}")
    print(f"重复ACK: {total_dup_acks:,}")
    if total_packets > 0:
        print(f"重传率: {(total_retrans/total_packets)*100:.2f}%")

    # Collect all RTTs
    all_rtts = []
    for conn in connections.values():
        all_rtts.extend(conn['rtts'])

    if all_rtts:
        print(f"\n### RTT延迟统计 (ms) ###")
        print(f"样本数: {len(all_rtts):,}")
        print(f"最小值: {min(all_rtts):.3f} ms")
        print(f"最大值: {max(all_rtts):.3f} ms")
        print(f"平均值: {statistics.mean(all_rtts):.3f} ms")
        print(f"中位数: {statistics.median(all_rtts):.3f} ms")
        sorted_rtts = sorted(all_rtts)
        print(f"95分位: {sorted_rtts[int(len(sorted_rtts)*0.95)]:.3f} ms")
        print(f"99分位: {sorted_rtts[int(len(sorted_rtts)*0.99)]:.3f} ms")

    # Print per-connection details
    print(f"\n{'='*100}")
    print("各连接详细分析")
    print(f"{'='*100}")

    # Sort connections by packet count (most active first)
    sorted_conns = sorted(connections.items(), key=lambda x: len(x[1]['packets']), reverse=True)

    for port, conn in sorted_conns:
        packets = conn['packets']
        if not packets:
            continue

        duration = packets[-1]['time'] - packets[0]['time']

        print(f"\n### 连接端口 {port} ###")
        print(f"  数据包数: {len(packets):,}")
        print(f"  持续时间: {duration:.3f} 秒")
        print(f"  发送字节: {conn['bytes_sent']:,} bytes ({conn['bytes_sent']/1024:.1f} KB)")
        print(f"  接收字节: {conn['bytes_recv']:,} bytes ({conn['bytes_recv']/1024:.1f} KB)")

        if duration > 0:
            throughput_kbps = (conn['bytes_recv'] * 8) / duration / 1000
            print(f"  下载吞吐量: {throughput_kbps:.2f} Kbps ({throughput_kbps/1000:.2f} Mbps)")

        # RTT stats for this connection
        if conn['rtts']:
            print(f"  RTT统计:")
            print(f"    最小: {min(conn['rtts']):.3f} ms")
            print(f"    最大: {max(conn['rtts']):.3f} ms")
            print(f"    平均: {statistics.mean(conn['rtts']):.3f} ms")
            print(f"    中位数: {statistics.median(conn['rtts']):.3f} ms")

        # Window size stats
        if conn['window_sizes']:
            print(f"  窗口大小统计:")
            print(f"    最小: {min(conn['window_sizes']):,} bytes")
            print(f"    最大: {max(conn['window_sizes']):,} bytes")
            print(f"    平均: {int(statistics.mean(conn['window_sizes'])):,} bytes")

        # Anomalies
        anomalies = []
        if conn['retrans'] > 0:
            anomalies.append(f"重传: {conn['retrans']} 次")
        if conn['fast_retrans'] > 0:
            anomalies.append(f"快速重传: {conn['fast_retrans']} 次")
        if conn['dup_acks'] > 0:
            anomalies.append(f"重复ACK: {conn['dup_acks']} 次")

        if conn['rtts']:
            max_rtt = max(conn['rtts'])
            avg_rtt = statistics.mean(conn['rtts'])
            if max_rtt > 1000:  # > 1 second
                anomalies.append(f"检测到极高延迟: {max_rtt:.0f} ms")
            if max_rtt > avg_rtt * 10:
                anomalies.append(f"RTT波动大: 最大/平均 = {max_rtt/avg_rtt:.1f}x")

        if duration > 0 and len(packets) > 100:
            retrans_rate = conn['retrans'] / len(packets) * 100
            if retrans_rate > 5:
                anomalies.append(f"高重传率: {retrans_rate:.1f}%")

        if anomalies:
            print(f"  ⚠️  异常情况:")
            for anomaly in anomalies:
                print(f"    - {anomaly}")

    # Summary of issues
    print(f"\n{'='*100}")
    print("问题总结")
    print(f"{'='*100}")

    issues = []

    if total_retrans > 0:
        issues.append(f"1. 存在大量重传 ({total_retrans:,} 个重传包，重传率 {(total_retrans/total_packets)*100:.2f}%)")
        issues.append(f"   说明: 网络存在丢包，可能是网络拥塞、路由问题或硬件故障")

    if total_dup_acks > total_retrans * 2:
        issues.append(f"2. 重复ACK数量异常 ({total_dup_acks:,} 个)")
        issues.append(f"   说明: 接收端频繁收到乱序的包")

    if all_rtts:
        max_rtt = max(all_rtts)
        avg_rtt = statistics.mean(all_rtts)
        if max_rtt > 1000:
            issues.append(f"3. 检测到极高延迟 (最大 RTT: {max_rtt:.0f} ms)")
            issues.append(f"   说明: 网络路径上存在严重的延迟或阻塞")

        p95_rtt = sorted(all_rtts)[int(len(all_rtts)*0.95)]
        if p95_rtt > 100:
            issues.append(f"4. 95分位RTT过高 ({p95_rtt:.1f} ms)")
            issues.append(f"   说明: 大部分请求都受到延迟影响")

    # Check for slow connections
    slow_conns = []
    for port, conn in connections.items():
        if len(conn['packets']) > 100:
            duration = conn['packets'][-1]['time'] - conn['packets'][0]['time']
            if duration > 0:
                throughput_mbps = (conn['bytes_recv'] * 8) / duration / 1000000
                if throughput_mbps < 1:  # Less than 1 Mbps
                    slow_conns.append((port, throughput_mbps))

    if slow_conns:
        issues.append(f"5. 存在慢速连接 ({len(slow_conns)} 个连接吞吐量 < 1 Mbps)")
        for port, mbps in slow_conns[:3]:
            issues.append(f"   - 端口 {port}: {mbps:.3f} Mbps")

    if issues:
        for issue in issues:
            print(issue)
    else:
        print("✓ 未检测到明显问题")

    print(f"\n{'='*100}")
    print("分析完成！")
    print(f"{'='*100}\n")

if __name__ == "__main__":
    csv_file = "/Users/admin/workspace/troubleshooting-tools/tmp/packets.csv"

    print("正在分析数据...")
    connections = analyze_csv(csv_file)
    print_analysis(connections)
