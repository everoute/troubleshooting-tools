# Ovs Monitoring - Analysis Overview

**Iteration:** iteration_001
**Date:** 2025-10-22 23:39:53
**Total Cases:** 18

## Summary Statistics

- Total test cases: 18
- Cases with latency data: 18
- Cases with throughput data: 18
- Cases with PPS data: 18
- Cases with resource data: 18

## Performance Summary

| Tool Case | Protocol | Dir | Latency Diff (%) | Throughput Diff (%) | PPS Diff (%) |
|-----------|----------|-----|------------------|---------------------|---------------|
| ovs_monitoring_case_10_udp_... | udp | tx | 6.28 | -27.0 | 3.61 |
| ovs_monitoring_case_11_tcp_... | tcp | rx | -5.16 | 5.58 | -5.4 |
| ovs_monitoring_case_12_tcp_... | tcp | tx | 8.63 | -7.27 | -6.2 |
| ovs_monitoring_case_13_tcp_... | tcp | rx | 1.89 | -30.89 | -6.91 |
| ovs_monitoring_case_14_tcp_... | tcp | tx | 0.06 | -11.75 | 4.92 |
| ovs_monitoring_case_15_udp_... | udp | rx | -5.78 | -29.92 | -8.85 |
| ovs_monitoring_case_16_udp_... | udp | tx | 1.6 | -2.4 | -0.2 |
| ovs_monitoring_case_17_tcp_... | tcp | rx | -11.07 | 12.78 | -1.24 |
| ovs_monitoring_case_18_tcp_... | tcp | tx | -4.8 | -6.16 | -0.99 |
| ovs_monitoring_case_1_tcp_r... | tcp | rx | 2.17 | -26.02 | -7.49 |
| ovs_monitoring_case_2_tcp_t... | tcp | tx | -4.9 | -16.87 | -13.69 |
| ovs_monitoring_case_3_udp_r... | udp | rx | 6.84 | 0.97 | -7.71 |
| ovs_monitoring_case_4_udp_t... | udp | tx | 0.97 | 18.56 | -4.74 |
| ovs_monitoring_case_5_tcp_r... | tcp | rx | 0.32 | -31.8 | -5.8 |
| ovs_monitoring_case_6_tcp_t... | tcp | tx | -9.36 | -3.89 | -10.17 |
| ovs_monitoring_case_7_tcp_r... | tcp | rx | -1.87 | 0.45 | -8.58 |
| ovs_monitoring_case_8_tcp_t... | tcp | tx | 11.03 | -38.03 | -0.22 |
| ovs_monitoring_case_9_udp_r... | udp | rx | -3.66 | -13.89 | -2.07 |

## Notes

- Positive diff% for latency indicates performance degradation (higher latency)
- Negative diff% for throughput/PPS indicates performance degradation
- N/A indicates missing data

## Detailed Reports

1. **Latency Report**: `ovs_monitoring_latency_iteration_001.csv`
2. **Throughput Report**: `ovs_monitoring_throughput_iteration_001.csv`
3. **PPS Report**: `ovs_monitoring_pps_iteration_001.csv`
4. **Resources Report**: `ovs_monitoring_resources_iteration_001.csv`
