#!/usr/bin/env python3
"""
Compare all four TCP connections from iperf test
"""

import sys
import os
sys.path.append('/Users/admin/workspace/troubleshooting-tools/test/pcap-analyzer')
from parse_tcp_analyzer_data import parse_connection_file, extract_numeric_value, extract_ratio_value

def get_final_metrics(connections):
    """Get metrics from the final sample"""
    if not connections:
        return {}

    final = connections[-1]
    metrics = final.get('metrics', {})

    result = {
        'send_q': extract_numeric_value(metrics.get('send_q', '')),
        'recv_q': extract_numeric_value(metrics.get('recv_q', '')),
        'rtt': extract_numeric_value(metrics.get('rtt', '')),
        'cwnd': extract_numeric_value(metrics.get('cwnd', '')),
        'ssthresh': extract_numeric_value(metrics.get('ssthresh', '')),
        'retrans': metrics.get('retrans', ''),
        'unacked': extract_numeric_value(metrics.get('unacked', '')),
        'inflight_data': extract_numeric_value(metrics.get('inflight_data', '')),
        'socket_tx_queue': extract_numeric_value(metrics.get('socket_tx_queue', '')),
        'socket_write_queue': extract_numeric_value(metrics.get('socket_write_queue', '')),
        'socket_tx_buffer': extract_numeric_value(metrics.get('socket_tx_buffer', '')),
        'spurious_retrans_rate': extract_ratio_value(metrics.get('spurious_retrans_rate', '')),
        'delivery_rate': extract_numeric_value(metrics.get('delivery_rate', '')),
        'send_rate': extract_numeric_value(metrics.get('send_rate', '')),
        'dsack_dups': extract_numeric_value(metrics.get('dsack_dups', '')),
    }

    # Parse retrans ratio
    retrans_str = metrics.get('retrans', '')
    if '/' in retrans_str:
        parts = retrans_str.split('/')
        if len(parts) == 2:
            result['retrans_current'] = int(parts[0])
            result['retrans_total'] = int(parts[1])

    return result

def print_comparison_table(client_data, server_data):
    """Print comparison table"""

    print("\n" + "="*120)
    print("四连接对比分析 - 最终采样数据")
    print("="*120)
    print()

    # Header
    print(f"{'指标':<30} {'客户端1':<15} {'客户端2':<15} {'客户端3':<15} {'客户端4':<15}")
    print("-" * 120)

    metrics = [
        ('拥塞窗口 (cwnd)', 'cwnd', ''),
        ('慢启动阈值 (ssthresh)', 'ssthresh', ''),
        ('RTT (ms)', 'rtt', 'ms'),
        ('发送队列 (send_q)', 'send_q', 'bytes'),
        ('未确认段数 (unacked)', 'unacked', ''),
        ('飞行中数据 (inflight_data)', 'inflight_data', 'KB'),
        ('', '', ''),
        ('socket_tx_queue', 'socket_tx_queue', 'KB'),
        ('socket_write_queue', 'socket_write_queue', 'KB'),
        ('socket_tx_buffer', 'socket_tx_buffer', 'KB'),
        ('', '', ''),
        ('当前重传', 'retrans_current', ''),
        ('总重传', 'retrans_total', ''),
        ('DSACK dups', 'dsack_dups', ''),
        ('虚假重传率', 'spurious_retrans_rate', '%'),
        ('', '', ''),
        ('发送速率 (send_rate)', 'send_rate', 'Gbps'),
        ('交付速率 (delivery_rate)', 'delivery_rate', 'Gbps'),
    ]

    for label, key, unit in metrics:
        if not label:
            print()
            continue

        row = [label]
        for i in range(1, 5):
            data = client_data.get(i, {})
            value = data.get(key)
            if value is not None:
                if unit == 'KB' and value > 1000:
                    row.append(f"{value/1024:.1f} MB")
                elif unit == '%':
                    row.append(f"{value:.1f}%")
                elif unit == 'Gbps':
                    row.append(f"{value:.2f} Gbps")
                elif unit == 'ms':
                    row.append(f"{value:.3f} ms")
                elif unit == 'bytes' and value > 10000:
                    row.append(f"{value/1024:.1f} KB")
                else:
                    row.append(f"{value:.0f}")
            else:
                row.append("-")

        print(f"{row[0]:<30} {row[1]:<15} {row[2]:<15} {row[3]:<15} {row[4]:<15}")

    print()
    print("="*120)
    print("服务器端对比")
    print("="*120)
    print()

    print(f"{'指标':<30} {'服务器1':<15} {'服务器2':<15} {'服务器3':<15} {'服务器4':<15}")
    print("-" * 120)

    for label, key, unit in metrics:
        if not label:
            print()
            continue

        row = [label]
        for i in range(1, 5):
            data = server_data.get(i, {})
            value = data.get(key)
            if value is not None:
                if unit == 'KB' and value > 1000:
                    row.append(f"{value/1024:.1f} MB")
                elif unit == '%':
                    row.append(f"{value:.1f}%")
                elif unit == 'Gbps':
                    row.append(f"{value:.2f} Gbps")
                elif unit == 'ms':
                    row.append(f"{value:.3f} ms")
                elif unit == 'bytes' and value > 10000:
                    row.append(f"{value/1024:.1f} KB")
                else:
                    row.append(f"{value:.0f}")
            else:
                row.append("-")

        print(f"{row[0]:<30} {row[1]:<15} {row[2]:<15} {row[3]:<15} {row[4]:<15}")

def main():
    base_dir = "/Users/admin/workspace/troubleshooting-tools/test/pcap-analyzer/1112/iperf1112"

    client_data = {}
    server_data = {}

    # Parse all connections
    for i in range(1, 5):
        client_file = f"{base_dir}/client/client.{i}"
        server_file = f"{base_dir}/server/server.{i}"

        print(f"解析客户端连接 {i}...")
        client_conns = parse_connection_file(client_file)
        client_data[i] = get_final_metrics(client_conns)

        print(f"解析服务器端连接 {i}...")
        server_conns = parse_connection_file(server_file)
        server_data[i] = get_final_metrics(server_conns)

    print_comparison_table(client_data, server_data)

    # Additional analysis
    print("\n" + "="*120)
    print("关键发现")
    print("="*120)
    print()

    # Compare socket queues
    print("### Socket 队列分析 ###")
    print()
    for side, data in [('客户端', client_data), ('服务器', server_data)]:
        print(f"{side}:")
        for i in range(1, 5):
            metrics = data.get(i, {})
            tx_queue = metrics.get('socket_tx_queue', 0)
            write_queue = metrics.get('socket_write_queue', 0)
            if write_queue > 0:
                ratio = tx_queue / write_queue if write_queue > 0 else 0
                print(f"  连接{i}: socket_tx_queue={tx_queue/1024:.1f} KB, "
                      f"socket_write_queue={write_queue/1024:.1f} KB, "
                      f"比率={ratio:.3f}")
        print()

    # Retransmission analysis
    print("### 重传分析 ###")
    print()
    for side, data in [('客户端', client_data), ('服务器', server_data)]:
        print(f"{side}:")
        total_retrans = 0
        for i in range(1, 5):
            metrics = data.get(i, {})
            retrans_total = metrics.get('retrans_total', 0)
            spurious_rate = metrics.get('spurious_retrans_rate')
            total_retrans += retrans_total if retrans_total else 0
            if spurious_rate is not None:
                print(f"  连接{i}: 总重传={retrans_total}, 虚假重传率={spurious_rate:.1f}%")
            else:
                print(f"  连接{i}: 总重传={retrans_total}, 虚假重传率=N/A")
        print(f"  总计: {total_retrans} 次重传")
        print()

if __name__ == "__main__":
    main()
