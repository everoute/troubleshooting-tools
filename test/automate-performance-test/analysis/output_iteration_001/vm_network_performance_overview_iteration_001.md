# Vm Network Performance - Analysis Overview

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
| vm_network_performance_case... | tcp | tx | 8.87 | -0.84 | -10.36 |
| vm_network_performance_case... | tcp | rx | -10.89 | -20.7 | 4.44 |
| vm_network_performance_case... | udp | tx | -6.79 | -10.71 | -3.02 |
| vm_network_performance_case... | udp | rx | 2.53 | -17.2 | -12.0 |
| vm_network_performance_case... | tcp | tx | -7.09 | -7.98 | -2.4 |
| vm_network_performance_case... | tcp | rx | -3.97 | -14.02 | -2.14 |
| vm_network_performance_case... | tcp | tx | 11.88 | -15.51 | -5.37 |
| vm_network_performance_case... | tcp | rx | 22.12 | -30.37 | -3.38 |
| vm_network_performance_case... | udp | tx | 7.64 | -14.93 | -0.35 |
| vm_network_performance_case... | udp | rx | 6.67 | -20.12 | -4.24 |
| vm_network_performance_case... | tcp | tx | 2.68 | -25.89 | -7.19 |
| vm_network_performance_case... | tcp | rx | 6.79 | 16.74 | -6.07 |
| vm_network_performance_case... | tcp | tx | 10.27 | -26.15 | -11.78 |
| vm_network_performance_case... | tcp | rx | 11.94 | -11.68 | -7.82 |
| vm_network_performance_case... | udp | tx | 14.2 | 9.02 | -11.41 |
| vm_network_performance_case... | udp | rx | 14.14 | -18.69 | -3.81 |
| vm_network_performance_case... | tcp | tx | 11.32 | -18.3 | -4.86 |
| vm_network_performance_case... | tcp | rx | 2.46 | -36.66 | -5.83 |

## Notes

- Positive diff% for latency indicates performance degradation (higher latency)
- Negative diff% for throughput/PPS indicates performance degradation
- N/A indicates missing data

## Detailed Reports

1. **Latency Report**: `vm_network_performance_latency_iteration_001.csv`
2. **Throughput Report**: `vm_network_performance_throughput_iteration_001.csv`
3. **PPS Report**: `vm_network_performance_pps_iteration_001.csv`
4. **Resources Report**: `vm_network_performance_resources_iteration_001.csv`
