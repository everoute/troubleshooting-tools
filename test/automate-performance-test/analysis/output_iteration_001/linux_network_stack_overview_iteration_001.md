# Linux Network Stack - Analysis Overview

**Iteration:** iteration_001
**Date:** 2025-10-22 23:39:53
**Total Cases:** 21

## Summary Statistics

- Total test cases: 21
- Cases with latency data: 21
- Cases with throughput data: 21
- Cases with PPS data: 21
- Cases with resource data: 21

## Performance Summary

| Tool Case | Protocol | Dir | Latency Diff (%) | Throughput Diff (%) | PPS Diff (%) |
|-----------|----------|-----|------------------|---------------------|---------------|
| linux_network_stack_case_10... | udp | tx | 40.43 | -48.45 | -7.27 |
| linux_network_stack_case_11... | tcp | rx | 41.74 | -35.66 | 1.42 |
| linux_network_stack_case_12... | tcp | tx | 1.84 | -15.34 | -11.43 |
| linux_network_stack_case_13... | tcp | rx | 18.9 | -19.49 | -27.89 |
| linux_network_stack_case_14... | tcp | rx | 50.42 | -32.62 | -42.84 |
| linux_network_stack_case_15... | tcp | tx | 59.23 | -23.98 | -20.75 |
| linux_network_stack_case_16... | udp | rx | 34.25 | -21.01 | -5.15 |
| linux_network_stack_case_17... | udp | tx | 23.0 | -23.29 | -6.46 |
| linux_network_stack_case_18... | tcp | rx | 48.01 | -18.24 | -13.19 |
| linux_network_stack_case_19... | tcp | tx | 161.7 | -15.27 | -22.5 |
| linux_network_stack_case_1_... | tcp | rx | 27.71 | -42.92 | -11.45 |
| linux_network_stack_case_20... | udp | rx | 20.7 | -11.75 | -2.57 |
| linux_network_stack_case_21... | udp | tx | 40.32 | -18.18 | -2.25 |
| linux_network_stack_case_2_... | tcp | tx | 17.06 | -33.45 | -9.06 |
| linux_network_stack_case_3_... | udp | rx | 12.22 | -25.78 | -11.7 |
| linux_network_stack_case_4_... | udp | tx | 16.05 | -18.45 | -7.76 |
| linux_network_stack_case_5_... | tcp | rx | 10.36 | -4.77 | -23.41 |
| linux_network_stack_case_6_... | tcp | tx | 35.83 | -15.2 | 0.46 |
| linux_network_stack_case_7_... | tcp | rx | 24.97 | -7.88 | 4.63 |
| linux_network_stack_case_8_... | tcp | tx | 22.05 | -1.52 | -6.1 |
| linux_network_stack_case_9_... | udp | rx | 13.19 | -10.71 | -10.17 |

## Notes

- Positive diff% for latency indicates performance degradation (higher latency)
- Negative diff% for throughput/PPS indicates performance degradation
- N/A indicates missing data

## Detailed Reports

1. **Latency Report**: `linux_network_stack_latency_iteration_001.csv`
2. **Throughput Report**: `linux_network_stack_throughput_iteration_001.csv`
3. **PPS Report**: `linux_network_stack_pps_iteration_001.csv`
4. **Resources Report**: `linux_network_stack_resources_iteration_001.csv`
