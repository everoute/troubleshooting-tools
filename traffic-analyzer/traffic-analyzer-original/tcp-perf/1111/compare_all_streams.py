#!/usr/bin/env python3
"""
Compare all 4 client and server streams
"""

import sys

# Data extracted from parsing results
client_streams = {
    '48270': {
        'samples': 78,
        'time_range': '19:04:21 -> 19:07:01',
        'duration_min': 2.7,
        'send_rate_avg': 246.67,
        'delivery_rate_avg': 10.89,
        'pacing_rate_avg': 14.67,
        'cwnd_avg': 5559.8,
        'retrans_increase': 1696,
        'retrans_ratio_avg': 0.003,
        'spurious_retrans_avg': 87.9,
    },
    '48272': {
        'samples': 104,
        'time_range': '19:07:39 -> 19:11:13',
        'duration_min': 3.6,
        'send_rate_avg': 237.35,
        'delivery_rate_avg': 9.93,
        'pacing_rate_avg': 15.10,
        'cwnd_avg': 5795.0,
        'retrans_increase': 2104,
        'retrans_ratio_avg': 0.004,
        'spurious_retrans_avg': 72.1,
    },
    '48274': {
        'samples': 95,
        'time_range': '19:11:54 -> 19:15:09',
        'duration_min': 3.3,
        'send_rate_avg': 199.39,
        'delivery_rate_avg': 9.66,
        'pacing_rate_avg': 14.14,
        'cwnd_avg': 5231.5,
        'retrans_increase': 3985,
        'retrans_ratio_avg': 0.004,
        'spurious_retrans_avg': 69.5,
    },
    '48276': {
        'samples': 128,
        'time_range': '19:15:47 -> 19:20:11',
        'duration_min': 4.4,
        'send_rate_avg': 234.57,
        'delivery_rate_avg': 9.89,
        'pacing_rate_avg': 13.94,
        'cwnd_avg': 5487.0,
        'retrans_increase': 3121,
        'retrans_ratio_avg': 0.003,
        'spurious_retrans_avg': 98.0,
    }
}

server_streams = {
    '48270': {
        'samples': 105,
        'time_range': '19:03:14 -> 19:07:04',
        'send_rate': 2.76,
        'pacing_rate': 5.52,
        'cwnd': 10,
        'retrans': 0,
    },
    '48272': {
        'samples': 108,
        'time_range': '19:07:22 -> 19:11:19',
        'send_rate': 2.76,
        'pacing_rate': 5.52,
        'cwnd': 10,
        'retrans': 0,
    },
    '48274': {
        'samples': 99,
        'time_range': '19:11:38 -> 19:15:16',
        'send_rate': 3.41,
        'pacing_rate': 6.81,
        'cwnd': 10,
        'retrans': 0,
    },
    '48276': {
        'samples': 121,
        'time_range': '19:15:34 -> 19:20:00',
        'send_rate': 2.97,
        'pacing_rate': 5.94,
        'cwnd': 10,
        'retrans': 0,
    }
}

print("="*120)
print("4-STREAM PERFORMANCE COMPARISON - CLIENT SIDE")
print("="*120)
print()
print(f"{'Stream':<10} {'Time Range':<25} {'Samples':<10} {'Delivery':<12} {'Pacing':<12} {'Cwnd':<10} {'Retrans+':<12} {'Spurious%':<12}")
print(f"{'Port':<10} {'(Duration)':<25} {'Count':<10} {'Rate(Gbps)':<12} {'Rate(Gbps)':<12} {'(avg)':<10} {'Increase':<12} {'(avg)':<12}")
print("-"*120)

total_delivery = 0
total_pacing = 0
total_retrans = 0
total_spurious_weighted = 0
total_samples = 0

for port in ['48270', '48272', '48274', '48276']:
    s = client_streams[port]
    total_delivery += s['delivery_rate_avg']
    total_pacing += s['pacing_rate_avg']
    total_retrans += s['retrans_increase']
    total_spurious_weighted += s['spurious_retrans_avg'] * s['retrans_increase']
    total_samples += s['samples']

    print(f"{port:<10} {s['time_range']:<25} {s['samples']:<10} {s['delivery_rate_avg']:<12.2f} {s['pacing_rate_avg']:<12.2f} {s['cwnd_avg']:<10.0f} {s['retrans_increase']:<12} {s['spurious_retrans_avg']:<12.1f}")

print("-"*120)
avg_spurious = total_spurious_weighted / total_retrans if total_retrans > 0 else 0
print(f"{'TOTAL':<10} {'All Streams':<25} {total_samples:<10} {total_delivery:<12.2f} {total_pacing:<12.2f} {'N/A':<10} {total_retrans:<12} {avg_spurious:<12.1f}")
print()

print("="*120)
print("4-STREAM PERFORMANCE COMPARISON - SERVER SIDE")
print("="*120)
print()
print(f"{'Stream':<10} {'Time Range':<25} {'Samples':<10} {'Send Rate':<15} {'Pacing Rate':<15} {'Cwnd':<10} {'Retrans':<10}")
print(f"{'Port':<10} {'(Duration)':<25} {'Count':<10} {'(Gbps)':<15} {'(Gbps)':<15} {'':<10} {'':<10}")
print("-"*120)

for port in ['48270', '48272', '48274', '48276']:
    s = server_streams[port]
    print(f"{port:<10} {s['time_range']:<25} {s['samples']:<10} {s['send_rate']:<15.2f} {s['pacing_rate']:<15.2f} {s['cwnd']:<10} {s['retrans']:<10}")

print("-"*120)
print()

print("="*120)
print("KEY FINDINGS")
print("="*120)
print()
print(f"1. Total Aggregate Throughput (Client Side):")
print(f"   - Total Delivery Rate: {total_delivery:.2f} Gbps")
print(f"   - Total Pacing Rate Limit: {total_pacing:.2f} Gbps")
print(f"   - Utilization: {(total_delivery/total_pacing)*100:.1f}%")
print()
print(f"2. Retransmission Analysis:")
print(f"   - Total Retrans Increase: {total_retrans:,}")
print(f"   - Weighted Avg Spurious Rate: {avg_spurious:.1f}%")
print(f"   - Estimated True Retrans: {int(total_retrans * (1 - avg_spurious/100)):,}")
print()
print(f"3. Per-Stream Performance Variance:")
streams_data = [(port, client_streams[port]['delivery_rate_avg'], client_streams[port]['spurious_retrans_avg'])
                for port in ['48270', '48272', '48274', '48276']]
streams_data.sort(key=lambda x: x[1], reverse=True)
print(f"   Best Performer: Port {streams_data[0][0]} - {streams_data[0][1]:.2f} Gbps (Spurious: {streams_data[0][2]:.1f}%)")
print(f"   Worst Performer: Port {streams_data[-1][0]} - {streams_data[-1][1]:.2f} Gbps (Spurious: {streams_data[-1][2]:.1f}%)")
print()
print(f"4. Critical Issues:")
print(f"   ⚠️  Stream 48276 has CRITICAL spurious retransmission rate: {client_streams['48276']['spurious_retrans_avg']:.1f}%")
print(f"   ⚠️  All streams show spurious retrans > 65%")
print(f"   ⚠️  Bandwidth utilization below 70% on all streams")
print()

# Calculate efficiency
avg_send_rate = sum([client_streams[p]['send_rate_avg'] for p in ['48270', '48272', '48274', '48276']]) / 4
print(f"5. Bandwidth Efficiency:")
print(f"   - Average Send Rate: {avg_send_rate:.2f} Gbps (includes retrans)")
print(f"   - Average Delivery Rate: {total_delivery/4:.2f} Gbps")
print(f"   - Efficiency: {(total_delivery/4 / avg_send_rate)*100:.1f}%")
print()

print("="*120)
